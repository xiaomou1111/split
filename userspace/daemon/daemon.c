/* SPDX-License-Identifier: GPL-2.0
 * daemon.c — splitd 守护进程
 *
 * 生命周期：
 *   读配置 → 加载 BPF → 设 tun/rules/uid/cnip → 挂物理网卡 → 循环(poll)：
 *     网络变化 → 重挂
 *     控制命令 → 回复
 */
#define _GNU_SOURCE /* struct ucred / SO_PEERCRED 需要；必须置于任何头文件之前 */
#include "daemon.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>       /* open/O_CREAT（单实例锁文件） */
#include <limits.h>      /* PATH_MAX（锁文件路径） */
#include <sys/file.h>    /* flock（单实例锁） */
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h> /* chmod（ctl socket 0600） */
#include <linux/if_arp.h> /* ARPHRD_NONE（tun_find_drift 的 L3 TUN 类型兜底） */

#include "../common/log.h"
#include "../common/config.h"
#include "../common/paths.h"
#include "../common/netlink.h"
#include "../loader/loader.h"
#include "../loader/iface.h"
#include "../rule/rule.h"
#include "../cni/cnip.h"
#include "../dns/dns.h"

/* v1.2.4：map_tun=0（utun 缺失）降级期间的心跳收紧间隔（毫秒）——
 * utun 重建回来后恢复代理的最长等待；正常状态心跳仍为 1s。 */
#define TUN_SYNC_DEGRADED_MS 300

static volatile sig_atomic_t g_stop = 0;
static int g_hijack_last = 0; /* v1.1.3 路由接管状态（变化才打日志） */
/* v1.2.8（审查修复）：最近一次 route_tun_hijacked 的原始结果（含 -1=检测失败）。
 * 主循环每 10s 更新；ctl_status 读它而非同步重跑 netlink dump——status 命令不再
 * 在 ctl_serve 里阻塞主循环最多 4×2s（同步 2~4 次 dump 会让 ctl/网络事件/CNIP 调度
 * 全部停摆）。至多 10s 陈旧，对状态展示可接受。 */
static int g_hijack_now = 0;
/* tun_sync 前向声明：ctl_serve（reload 分支）与主循环事件分支都要在定义前调用 */
static int tun_sync(struct split_bpf_ctx *ctx, const struct split_config *cfg,
                    const struct iface_list *snap);
/* CNIP 写锁（H2 显式化）：
 * CNIP map（map_cnip4/6）的写入方只有两个，且必须互斥——
 *   A. 定时/补拉 auto-update：fork 出子进程后由子进程灌入；
 *   B. 用户 `reload-cnip`：主线程同步灌入。
 * g_cnip_busy 在 fork 前置位、子进程回收后清位；reload-cnip 见位即拒绝，
 * 从而保证"任一时刻只有一个写入方在清空+写 CNIP map"。
 * 注意：`reload`（rule_apply_all）只碰 rule/dns map、不碰 CNIP map，
 * 与子进程的 CNIP 灌入天然无交集——若未来给 reload 增加 CNIP 重灌，
 * 必须在此处同步加 g_cnip_busy 检查，否则破坏该不变式。 */
static volatile sig_atomic_t g_cnip_busy = 0;

/* v1.2.5：最近一次确认有效的 tun ifindex（名字漂移兜底的基准）。
 * mihomo 重建的新 TUN 一定是新建接口（ifindex 单调递增），用它排除
 * 系统 VPN 等"早于旧 utun 就存在"的无关 tunN 接口。 */
static int g_tun_last_good = 0;

/* v1.2.8（审查修复，漂移保持）：最近一次**漂移对齐**的 ifindex（非精确匹配所得）。
 * 背景：漂移对齐后 g_tun_last_good 会被设为该 ifindex，而 tun_find_drift 的
 * "ifindex > last_good" 严格检查会让同一设备下一心跳被排除 → map_tun 回退置 0
 * （漂移对齐只存活一轮就失效）。g_tun_drift_idx 记录该设备，tun_find_drift 对
 * "== g_tun_drift_idx" 的设备放行（既存的漂移设备保持有效；mihomo 再次重建出
 * 更高 ifindex 的新设备仍会被优先选中）。精确匹配命中 / 设备彻底缺失（置 0）时清零，
 * 恢复对新漂移的重新搜寻。 */
static int g_tun_drift_idx = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* 启动时钟毫秒（用于 CNIP 定时刷新/DNS 清理，含 suspend、不受系统时间调整影响） */
static long long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

/* ---------- 单实例锁 ---------- */

/*
 * 单实例锁（v1.1.4）：在控制 socket 路径旁建 "<path>.lock" 文件并 flock。
 * 背景：二次 `splitctl start` 时，新 daemon 的 ctl_listen 会 unlink 旧 socket
 * 并重新 bind——第一个实例从此失联（无法 stop/status），且两个 daemon 同时
 * 加载 BPF/挂 tc 互相踩踏。
 * 实现：flock(LOCK_EX|LOCK_NB)，进程退出/fd 关闭时内核自动释放；锁文件
 * 本身不删除（下次 O_CREAT 复用，删除反而有竞态）。
 * 返回：>=0=持锁 fd；-1=锁被占用（另一实例存活，调用方应退出）；
 *      -2=锁不可用（只读目录等，调用方降级为无锁运行）。
 */
static int instance_lock(const char *lock_path)
{
    int fd = open(lock_path, O_CREAT | O_RDWR, 0600);

    if (fd < 0) {
        LOG_WARNF("打开锁文件 %s 失败(%s)，单实例保护降级", lock_path,
                  strerror(errno));
        return -2;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            LOG_ERRORF("已有 splitd 在运行（锁 %s 被占用），拒绝启动", lock_path);
            close(fd);
            return -1;
        }
        LOG_WARNF("flock %s 失败(%s)，单实例保护降级", lock_path, strerror(errno));
        close(fd);
        return -2;
    }
    return fd;
}

/* ---------- 控制 socket ---------- */

static int ctl_listen(void)
{
    int fd;
    struct sockaddr_un sa;
    const char *path = split_socket_path();

    unlink(path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        listen(fd, 4) < 0) {
        LOG_ERRORF("ctl socket bind %s 失败(%s)", path, strerror(errno));
        close(fd);
        return -1;
    }
    /* v1.1.4：bind 后收紧 socket 文件权限（默认受 umask 影响，可能 755）。
     * 非 root 直接连不上；ctl_serve 的 SO_PEERCRED 校验是第二道闸。 */
    chmod(path, 0600);
    return fd;
}

/* 返回 0=已完整写出；-1=客户端断开/写失败（v1.2.7 审查加固：调用方可据此中止
 * list-rules 等长流程的枚举，避免对已断开连接继续无谓耗时）。 */
static int ctl_reply(int c, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    size_t len;
    ssize_t off = 0;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    len = strlen(buf);
    /* vsnprintf 保证 len ≤ 511；+'\n' 写入 buf[511]，buf[512] 不溢出。
     * 此时 buf 不再是 C 字符串（无 NUL 终止），write 按长度写不依赖 NUL。 */
    buf[len] = '\n';
    len++;
    /* 循环写防部分写入：unix stream socket 对 >PIPE_BUF 的 write 不保证原子 */
    while (off < (ssize_t)len) {
        ssize_t w = write(c, buf + off, len - (size_t)off);

        if (w <= 0)
            return -1;        /* 客户端断开/错误：丢弃剩余回复 */
        off += w;
    }
    return 0;
}

static void ctl_status(int c, struct split_bpf_ctx *ctx)
{
    uint32_t n4 = 0, n6 = 0;
    uint32_t tun_u = 0;
    int tun = 0, hijack = 0;

    if (map_get_tun(ctx, &tun_u) == 0)
        tun = (int)tun_u;
    map_cnip_count(ctx, &n4, &n6);
    /* v1.2.8：读主循环 10s 节流缓存的路由接管检测结果，不在 ctl 路径同步重跑
     * netlink dump（最多 4×2s 阻塞）。hijack_now 含 -1=检测失败（如实显示）。 */
    hijack = g_hijack_now;
    ctl_reply(c, "OK prog_fd=%d attached=%d tun=%d cnip4=%u cnip6=%u hijack=%d",
              ctx->prog_fd, ctx->nattached, tun, n4, n6, hijack);
    if (n4 == 0 && n6 == 0)
        ctl_reply(c, "WARN CNIP 未导入（0 条）：检查 config/cn_cidr_v4.txt 或 reload-cnip");
    if (hijack == 1)
        ctl_reply(c, "WARN 路由被 mihomo auto-route 接管：eBPF 分流失效，请把 mihomo tun.auto-route 改为 false");
    /* v1.2.7（审查 H2）：map_tun=0（utun 缺失）降级要可见——"代理流量被放行直连"
     * 与"分流失效"不同，属静默降级，status 显式提示便于排障。 */
    if (tun == 0)
        ctl_reply(c, "WARN tun 设备缺失（map_tun=0）：代理流量被放行直连，请确认 mihomo 已启动");
    ctl_reply(c, "END");
}

static void ctl_stats(int c, struct split_bpf_ctx *ctx)
{
    static const char *names[] = {
        "total", "direct_cn", "direct_rule", "proxy",
        "skip_uid", "parse_err", "redirect_err", "dropped",
        "miss_tun", "dom_proxy", "dom_direct", "direct_v6",
    };
    uint64_t stats[STAT_MAX] = {0};
    int k;

    if (map_stats_dump(ctx, stats) < 0) {
        ctl_reply(c, "ERR 读取统计失败");
        ctl_reply(c, "END");
        return;
    }
    ctl_reply(c, "OK");
    /* v1.1.9：以 names[] 元素数（此处 13=STAT_DIRECT_V6+1）为上界，与 STAT_MAX
     * 取小——新增统计段时加 names 项即可自动扩展，避免硬编码 10 不同步。 */
    for (k = 0; k < STAT_MAX &&
                k < (int)(sizeof(names) / sizeof(names[0])); k++)
        ctl_reply(c, "%s %llu", names[k], (unsigned long long)stats[k]);
    ctl_reply(c, "END");
}

/* v1.1.0：DNS 学习器状态（真机排查"域名分流是否在学习"的关键命令） */
static void ctl_dns(int c, struct split_bpf_ctx *ctx, struct dns_learn *dl)
{
    uint32_t n4 = 0, n6 = 0;

    map_dns_count(ctx, &n4, &n6);
    ctl_reply(c, "OK fd=%d learned=%llu skipped=%llu entries4=%u entries6=%u",
              dl->fd, (unsigned long long)dl->learned,
              (unsigned long long)dl->skipped, n4, n6);
    ctl_reply(c, "END");
}

/* 整词匹配：命令名后必须紧跟空白或结尾（v1.1.4 审查加固：此前
 * strncmp(cmd,"stop",4) 会让 "stopx"/"stop anything" 误触发 stop） */
static int cmd_is(const char *cmd, const char *name)
{
    size_t n = strlen(name);

    return strncmp(cmd, name, n) == 0 &&
           (cmd[n] == '\0' || cmd[n] == ' ' || cmd[n] == '\t');
}

/* 命令参数拆词（v1.1.9）：把 "<arg1> <arg2>" 拆成两 token，容忍 space/tab
 * 任意组合及多余空白。`s` 指向首参数首字符（已跳前导空白）。
 * 返回: 0=仅一个 token；1=拆出两个 token（*which 指向第二个，已跳前导空白）；
 *       -1=无 token / 第二个 token 为空。
 * 用 `find_token` 扫描空白分隔，不用 strchr(' ')，否则 Tab 分隔会漏拆。 */
static int split_two(char *s, char **tok1, char **tok2)
{
    char *p = s;
    char *second;
    char *start;
    char save;

    if (!*p)
        return -1;                /* 无首参数 */
    start = p;
    while (*p && *p != ' ' && *p != '\t') p++;
    save = *p;
    *p = '\0';
    *tok1 = start;
    if (save == '\0')
        return 0;                 /* 只有一个 token */
    second = p + 1;
    while (*second == ' ' || *second == '\t') second++;
    if (!*second)
        return -1;                /* 第二个 token 为空 */
    *tok2 = second;
    return 1;
}

/* list-rules：枚举 proxy/direct 四个规则 map，逐行回 "proxy <cidr>" / "direct <cidr>" */
struct ctl_rule_priv { int c; };

static int ctl_rule_line(int which, const char *cidr, void *priv)
{
    /* v1.2.7（审查 H4）：客户端断开时 ctl_reply 返回 -1，此处向上中止枚举
     * （map_rule_foreach 收到回调非 0 即返回），避免对已断开连接继续耗时。 */
    if (ctl_reply(((struct ctl_rule_priv *)priv)->c, "%s %s",
                  which == RULE_PROXY ? "proxy" : "direct", cidr) != 0)
        return -1;
    return 0;
}

static int ctl_serve(struct split_bpf_ctx *ctx,
                     const char *cfg_path,
                     struct split_config *cfg,
                     long long *cnip_next_ms,
                     struct dns_learn *dl,
                     struct rule_overrides *rov,
                     int *tun_degraded,
                     int c)
{
    char cmd[512];
    ssize_t n;

    /* 权限校验：splitd 以 root 运行，只允许 root（uid 0）下发控制命令，
     * 防止任意本地用户 stop / 改规则。*/
    {
        struct ucred cred;
        socklen_t len = sizeof(cred);
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0 ||
            cred.uid != 0) {
            ctl_reply(c, "ERR 仅 root 可控制 splitd");
            ctl_reply(c, "END");
            return 0;
        }
    }

    /* 带整体超时读命令（<=1500ms）：SOCK_STREAM 不保证消息边界，命令可能被拆成
     * 多次 read 到达——以 '\n' 为命令结束符循环读取，直到收齐换行、缓冲满
     * 或超时。客户端挂住时不能让整个 daemon 主循环停摆（poll 主循环还要
     * 处理网络事件/CNIP 定时）——因此把阻塞上限压到 1.5s，避免 H1：
     * ctl_serve 是主循环同步调用，过长 read 会顺延 1s tun_sync / 5s
     * reconcile / CNIP fork，放宽 mihomo 重建 utun 时 map_tun stale 的
     * 静默丢包窗口。超时按命令超时关闭连接。 */
    {
        long long deadline = now_ms() + 1500;
        size_t got = 0;
        int truncated = 0;

        for (;;) {
            struct pollfd p = { .fd = c, .events = POLLIN };
            long long remain = deadline - now_ms();
            int pr;

            if (remain <= 0) {
                ctl_reply(c, "ERR 命令超时");
                ctl_reply(c, "END");
                return 0;
            }
            pr = poll(&p, 1, (int)remain);
            if (pr <= 0) {
                if (pr < 0 && errno == EINTR)
                    continue;
                ctl_reply(c, "ERR 命令超时");
                ctl_reply(c, "END");
                return 0;
            }
            n = read(c, cmd + got, sizeof(cmd) - 1 - got);
            if (n <= 0)
                return 0;             /* 客户端断开 */
            got += (size_t)n;
            if (memchr(cmd, '\n', got))
                break;                /* 收齐命令（尾随 '\n' 由下方清理） */
            if (got >= sizeof(cmd) - 1) {
                truncated = 1;        /* 缓冲满仍未收到 '\n'：按超长命令拒绝 */
                break;
            }
        }
        if (truncated) {
            /* 命令超过缓冲（512B）。此前会按截断串解析——靠后续参数校验兜住
             * 不会误写/误删，但更清晰的做法是显式拒绝，避免"收到半截规则"的歧义。 */
            ctl_reply(c, "ERR 命令过长");
            ctl_reply(c, "END");
            return 0;
        }
        n = (ssize_t)got;
    }
    cmd[n] = '\0';

    /* 清理末尾换行与空格 */
    while (n > 0 && (cmd[n - 1] == '\n' || cmd[n - 1] == '\r' ||
                     cmd[n - 1] == ' ' || cmd[n - 1] == '\t')) {
        cmd[--n] = '\0';
    }

    if (cmd_is(cmd, "stats")) {
        ctl_stats(c, ctx);
    } else if (cmd_is(cmd, "dns")) {
        ctl_dns(c, ctx, dl);
    } else if (cmd_is(cmd, "status")) {
        ctl_status(c, ctx);
    } else if (cmd_is(cmd, "list-rules")) {
        /* v1.2.2：当前在线规则（配置基线 + 运行时 add-rule/del-rule 的 map 实况），
         * 逐行 "proxy <cidr>" / "direct <cidr>"，供 WebUI 规则列表展示/删除。 */
        struct ctl_rule_priv priv = { .c = c };

        ctl_reply(c, "OK");
        map_rule_foreach(ctx, RULE_PROXY, ctl_rule_line, &priv);
        map_rule_foreach(ctx, RULE_DIRECT, ctl_rule_line, &priv);
        ctl_reply(c, "END");
    } else if (cmd_is(cmd, "reload-cnip")) {
        /* v1.1.6：CNIP 更新子进程运行中时拒绝并发重灌，避免两进程同时
         * "清空→写入"同一组 LPM_TRIE map 产生瞬时缺失/交错。 */
        if (g_cnip_busy) {
            ctl_reply(c, "ERR CNIP 更新进行中，请稍后重试");
            ctl_reply(c, "END");
        } else if (cnip_apply(ctx, cfg) == 0) {
            ctl_reply(c, "OK");
            ctl_reply(c, "END");
        } else {
            ctl_reply(c, "ERR");
            ctl_reply(c, "END");
        }
    } else if (cmd_is(cmd, "reload")) {
        /* v1.0.6：真正重读配置文件（docs/04 契约：reload = 读配置 → 重写 map）。
         * 重读失败则沿用内存配置继续重放（避免"改了配置但规则没同步"）。 */
        if (config_load(cfg_path, cfg) == 0) {
            if (cfg->cnip_auto_update_hours > 0)
                *cnip_next_ms = now_ms() +
                    (long long)cfg->cnip_auto_update_hours * 3600000LL;
            /* v1.2.8（审查修复）：debug 从 true 改 false 时恢复 INFO——旧实现只
             * 在 debug=true 时升到 DEBUG、永不降回，误配排查时日志一直刷屏。 */
            g_log_level = cfg->debug ? LOG_DEBUG : LOG_INFO;
            LOG_INFOF("reload: 已重读 %s", cfg_path);
        } else {
            LOG_ERRORF("reload: 重读 %s 失败，沿用内存配置", cfg_path);
        }
        rule_apply_all(ctx, cfg);
        /* v1.2.0（H1）：重放运行时 add-rule/del-rule 偏差——否则 CLI 增删的
         * 规则在 reload 后丢失（rule_apply_all 先 clear 再写配置基线）。 */
        rule_overrides_replay(ctx, rov);
        iface_reconcile(ctx, cfg, NULL);
        /* v1.2.1：reload 后立即对齐 map_tun（不等 1s 心跳）。若 mihomo 也已
         * 重载配置重建 utun，ifindex 漂移在此处第一时间修正，缩小静默丢包窗口。
         * v1.2.4：返回值同步 tun_degraded（utun 缺失时心跳收紧快重试）。 */
        {
            int r = tun_sync(ctx, cfg, NULL);

            if (r >= 0)
                *tun_degraded = (r == 1);
        }
        ctl_reply(c, "OK");
        ctl_reply(c, "END");
    } else if (cmd_is(cmd, "add-rule")) {
        char *arg = cmd + strlen("add-rule");
        char *cidr, *which_str;
        int which = RULE_PROXY;
        int sp;

        while (*arg && (*arg == ' ' || *arg == '\t')) arg++;
        sp = split_two(arg, &cidr, &which_str);
        if (sp < 0) {
            ctl_reply(c, "ERR 用法: add-rule <cidr> [proxy|direct]");
            ctl_reply(c, "END");
        } else {
            if (sp == 1) {
                if (strcmp(which_str, "direct") == 0)
                    which = RULE_DIRECT;
                else if (strcmp(which_str, "proxy") != 0)
                    which = -1; /* 非法 */
            }
            if (which < 0) {
                ctl_reply(c, "ERR which 只能是 proxy 或 direct");
                ctl_reply(c, "END");
            } else if (rule_add(ctx, cidr, which) != 0) {
                ctl_reply(c, "ERR");
                ctl_reply(c, "END");
            } else if (rule_override_record(rov, cidr, which, 1) != 0) {
                /* 规则已入 map，但记录失败（已满）：本次生效，reload 后将丢失。
                 * 属容量耗尽的可接受降级，如实告知而非假装成功。 */
                ctl_reply(c, "ERR 已入 map 但运行时追踪满，规则不跨 reload");
                ctl_reply(c, "END");
            } else {
                ctl_reply(c, "OK");
                ctl_reply(c, "END");
            }
        }
    } else if (cmd_is(cmd, "del-rule")) {
        char *arg = cmd + strlen("del-rule");
        char *cidr, *which_str;
        int which = RULE_PROXY;
        int sp;

        while (*arg && (*arg == ' ' || *arg == '\t')) arg++;
        sp = split_two(arg, &cidr, &which_str);
        if (sp < 0) {
            ctl_reply(c, "ERR 用法: del-rule <cidr> [proxy|direct]");
            ctl_reply(c, "END");
        } else {
            if (sp == 1) {
                if (strcmp(which_str, "direct") == 0)
                    which = RULE_DIRECT;
                else if (strcmp(which_str, "proxy") != 0)
                    which = -1;
            }
            if (which < 0) {
                ctl_reply(c, "ERR which 只能是 proxy 或 direct");
                ctl_reply(c, "END");
            } else if (rule_del(ctx, cidr, which) != 0) {
                ctl_reply(c, "ERR");
                ctl_reply(c, "END");
            } else if (rule_override_record(rov, cidr, which, 0) != 0) {
                ctl_reply(c, "ERR 已删但运行时追踪满，跨 reload 会复活");
                ctl_reply(c, "END");
            } else {
                ctl_reply(c, "OK");
                ctl_reply(c, "END");
            }
        }
    } else if (cmd_is(cmd, "stop")) {
        ctl_reply(c, "OK");
        ctl_reply(c, "END");
        g_stop = 1;
    } else {
        ctl_reply(c, "ERR 未知命令");
        ctl_reply(c, "END");
    }
    return 0; /* 单命令一连接：回复后关闭（避免双方阻塞等待 EOF） */
}

/* ---------- tun 存活同步 ---------- */

/* ---------- v1.2.5/v1.2.6：tun 名字漂移兜底 ---------- */
/* 该接口名是否可能是"mihomo 的 TUN"（精确匹配失败后的候选识别）：
 *   - 与配置名同前缀且后跟数字（utun → utun0/utun1）；
 *   - v1.2.6：mihomo 源码核实（listener/sing_tun/sing_tun.go）——
 *     `InterfaceName` 默认就是 **"Meta"**，`CalculateInterfaceName()` 在 Linux
 *     且 `device==""` 时直接返回该名（`utunN` 只在 darwin）。重载后新 TUN
 *     若落回 "Meta"，按名必须认出来。
 *   - 审查修正（v1.2.8）：**移除"配置名以 utun 开头则接受 tunN"的启发式**——
 *     它是 Android **系统 VPN（VpnService）** 的默认设备名（tun0），且 mihomo
 *     Linux 回退名经源码核实是 "Meta" 而非 "tunN"；接受 tunN 会让"mihomo 之后
 *     建立的系统 VPN"被误认为漂移的新 TUN（map_tun 被改写进错误设备，代理流量
 *     被 redirect 到 VPN 内）。tunN 只能经 ARPHRD_NONE 类型兜底再认，且该兜底
 *     现亦排除 tunN 前缀（见 tun_l3_known_other），系统 VPN 完全不在候选内。
 */
static int tun_name_like(const char *name, const char *cfg_name)
{
    size_t base = strlen(cfg_name);
    unsigned char c;

    /* v1.2.7（审查 M4）：空 tun_device 属配置错误，不做名字匹配——否则
     * strncmp(name,"",0)==0 恒真，任何以数字开头的接口都会被误认作 TUN 候选。 */
    if (!cfg_name[0])
        return 0;
    if (strcmp(name, "Meta") == 0)
        return 1;
    if (strncmp(name, cfg_name, base) == 0) {
        c = (unsigned char)name[base];
        if (c >= '0' && c <= '9')
            return 1;
    }
    return 0;
}

/* ARPHRD_NONE（L3 无 L2 头）接口里，明确不是 mihomo TUN 的常见名。
 * wireguard / tailscale 等 L3 VPN 也是 ARPHRD_NONE，若不加排除，
 * "按类型兜底"会把这些设备误当新 TUN（代理流量被重定向进错误设备）。
 * 审查修正（v1.2.8）：**追加 "tun" 前缀排除**——Android 系统 VPN
 * （VpnService）的设备名正是 tunN，且同为 ARPHRD_NONE；mihomo 的
 * 名字识别已由 "Meta"/同前缀+数字 覆盖，类型兜底无须再认 tunN
 * （mihomo InterfaceName 为空的回退名是 "Meta"，非 tunN）。 */
static int tun_l3_known_other(const char *name)
{
    static const char *exclude[] = { "wg", "tailscale", "tun", NULL };
    int k;

    for (k = 0; exclude[k]; k++) {
        if (strncmp(name, exclude[k], strlen(exclude[k])) == 0)
            return 1;
    }
    return 0;
}

/* 在扫描结果里找名字漂移后的新 TUN（返回最佳候选 ifindex，0=无）：
 *   1. 名字 TUN 类（tun_name_like，含 mihomo Linux 默认回退名 "Meta"）；
 *   2. IFF_UP（mihomo 建好并启用后才认，避免把 DOWN 的残留当候选）；
 *   3. ifindex 严格大于 g_tun_last_good——mihomo 重建的新 TUN 是新建接口、
 *      ifindex 单调递增；早于旧 utun 的 tun0/tun1（系统 VPN）被排除。
 * 多个候选取 ifindex 最大者（最可能是刚重建的）。
 *
 * v1.2.6 追加"按类型兜底"：名字匹配（含 Meta）仍缺时，任何 ARPHRD_NONE
 * （IFF_TUN 的 L3 设备，mihomo 任意 device 名 / 回退名都落在该类）+ IFF_UP +
 * 新于 last_good 且不是已知非-tun（wg/tailscale/tunN——v1.2.8 排除系统 VPN）的
 * 接口也视为候选——覆盖 mihomo 重载后落到任意名字（如配置 device 被 WebUI 改空
 * 时的 "Meta"）。名字匹配优先于类型匹配（类型兜底会把 wireguard 等误判为候选的
 * 风险已用排除表压住，但仍是低置信兜底，能不用就不用）。 */
static int tun_find_drift(const struct iface_list *list, const char *cfg_name,
                          int last_good)
{
    int best = 0, best_type = 0, k;

    for (k = 0; k < list->count; k++) {
        const struct iface *i = &list->items[k];

        if (!(i->flags & 0x1)) /* IFF_UP */
            continue;
        /* v1.2.8（审查修复）：`== g_tun_drift_idx` 放行——漂移对齐后 last_good 被设为
         * 该设备，严格 "ifindex > last_good" 会让它下一心跳被排除（漂移对齐只活一轮
         * 就回退置 0）。既存的漂移设备据此保持有效；mihomo 再次重建出更高 ifindex 的
         * 新设备仍会被优先选中。 */
        if (i->ifindex <= last_good && i->ifindex != g_tun_drift_idx)
            continue;
        if (tun_name_like(i->name, cfg_name)) {
            if (i->ifindex > best)
                best = i->ifindex;
            continue;
        }
        if (i->type == ARPHRD_NONE && !tun_l3_known_other(i->name)) {
            if (i->ifindex > best_type)
                best_type = i->ifindex;
        }
    }
    if (best > 0)
        return best;
    return best_type;
}

/* 汇总扫描里所有 TUN 类接口（含被 ifindex 基准排除的），附到"不存在"日志，
 * 用于区分"utun 真没了" vs "名字漂移成 utunN/tunN/Meta"。
 * v1.2.6：同时列出 ARPHRD_NONE 的 L3 接口（不排除 wg 等——诊断就是要看全）。 */
static void tun_list_like(const struct iface_list *list, const char *cfg_name,
                          char *buf, size_t bufsz)
{
    size_t off = 0;
    int k;

    buf[0] = '\0';
    for (k = 0; k < list->count && off + 32 < bufsz; k++) {
        const struct iface *i = &list->items[k];

        if (!tun_name_like(i->name, cfg_name) && i->type != ARPHRD_NONE)
            continue;
        off += (size_t)snprintf(buf + off, bufsz - off, "%s%s=%d%s",
                                off ? ", " : "", i->name, i->ifindex,
                                i->type == ARPHRD_NONE ? "(tun)" : "");
    }
}

/*
 * tun_sync — 让 map_tun 与 tun_device 实际 ifindex 保持一致（v1.0.6）。
 *
 * 背景：mihomo 崩溃被 Android 杀/重启、gso 切换、升级、**重载配置文件**时都会
 * 重建 utun，ifindex 必然变化。若不刷新，map_tun 残留旧 ifindex，而 bpf_redirect
 * 对无效 ifindex 是在 __skb_do_redirect 里 kfree_skb 直接丢包（helper 本身
 * 恒返回 TC_ACT_REDIRECT，split.bpf.c 的失败检查救不回）→ 海外流量全挂。
 *
 * 策略（"绝不丢包"铁律）：
 *   - tun_device 接口不存在 → map_tun 置 0（BPF 侧走 STAT_MISS_TUN + TC_ACT_OK 放行）；
 *   - tun_device 若隐若现（ifindex 漂移）→ 重新对齐写入新值；
 *   - 接口扫描失败（临时 netlink 错误）→ 不动 map_tun（避免误置 0）。
 * 调用点（v1.2.1 起三处）：
 *   A. poll 心跳周期兜底（1s 节流，无条件，防事件漏收）；
 *   B. netlink 接口变化事件（v1.2.1 新增：复用 iface_watch_poll 已扫快照，
 *      不等 1s 心跳，缩小 mihomo 重建 utun 后 map_tun stale 的静默丢包窗口）；
 *   C. reload 命令（v1.2.1 新增：重读配置后立即对齐 map_tun）。
 * snap 非 NULL 复用调用方快照（免重复 scan），NULL 自扫——与 iface_reconcile 同款约定。
 *
 * v1.2.4（真机修复）：
 *   - 快照权威复核：事件路径传入的快照是"排空 netlink 事件后再扫"的时点快照——
 *     若恰拍在 mihomo 重载重建 utun 的 DELLINK 与 NEWLINK 之间（utun 已删未建），
 *     快照里没有 utun，但 utun 此刻可能已重建回来。此前直接按快照结论把 map_tun
 *     置 0，造成"ip link 能看到 utun 但 split 报 tun 不存在、代理完全失效"的假象。
 *     现当快照缺 utun 时强制重新 iface_scan 权威复核，只有复核仍缺才置 0。
 *   - 降级快重试：返回 1=降级（map_tun=0）时，daemon 心跳从 1s 收紧到 300ms，
 *     utun 重建回来后恢复代理的最长等待 ≤300ms（NEWLINK 事件漏收时不再等 1s+）。
 *   - 返回契约：0=已对齐/保持有效；1=降级（map_tun=0，utun 缺失）；-1=扫描失败（未动 map）。
 *
 * v1.2.5（名字漂移兜底）：
 *   mihomo 重载后新 TUN 可能不再叫配置名。精确匹配（+v1.2.4 复核）仍缺时，
 *   用 g_tun_last_good 基准找"比旧 utun 更新、IFF_UP、TUN 类名字"的候选自动
 *   对齐（tun_find_drift），并打 WARN 提示；"不存在"日志附带扫描中的 TUN 类
 *   接口清单（tun_list_like），便于区分"真没了" vs "改名了"。
 * v1.2.6（按类型兜底 + 修正回退名假设）：
 *   - 源码核实（mihomo Alpha listener/sing_tun/sing_tun.go）：`InterfaceName`
 *     默认即 "Meta"，`device==""` 时 Linux 回退名是 **"Meta"** 而非 "tunN"
 *     （"tunN" 仅 InterfaceName 为空、"utunN" 仅 darwin）。tun_name_like 现
 *     直接认 "Meta"。
 *   - tun_find_drift 增加 ARPHRD_NONE（L3 TUN 类型）兜底：重载后新 TUN 落到
 *     任意名字（含 WebUI 把 device 改空的 "Meta"）都能被找到，排除 wg/tailscale
 *     等同样是 ARPHRD_NONE 的 L3 VPN，避免误把代理流量重定向进错误设备。
 */
static int tun_sync(struct split_bpf_ctx *ctx, const struct split_config *cfg,
                    const struct iface_list *snap)
{
    struct iface_list owned;
    const struct iface_list *list;
    uint32_t cur = 0;
    int idx = 0, k;

    if (snap) {
        list = snap;
    } else {
        if (iface_scan(&owned) < 0) {
            LOG_WARNF("tun 同步：接口扫描失败，跳过（map_tun 保持原值）");
            return -1;
        }
        list = &owned;
    }
    for (k = 0; k < list->count; k++) {
        if (strcmp(list->items[k].name, cfg->tun_device) == 0) {
            idx = list->items[k].ifindex;
            break;
        }
    }
    /* v1.2.4 快照权威复核：事件路径传入的快照可能拍在 mihomo 重建 utun 的间隙
     * （DELLINK 已消费、NEWLINK 未到）——快照缺 utun 不等于 utun 此刻不存在，
     * 若直接按快照置 0 会出现"ip link 可见 utun 但 map_tun=0、代理完全失效"。
     * 此时强制重扫一次、以最新扫描为准；自扫路径（snap==NULL）本身就是最新
     * 扫描，无需复核。复核失败按"跳过不动 map"处理（与主扫描失败同语义）。 */
    if (idx <= 0 && snap) {
        if (iface_scan(&owned) < 0) {
            LOG_WARNF("tun 同步：复核扫描失败，跳过（map_tun 保持原值）");
            return -1;
        }
        list = &owned; /* 后续漂移兜底/诊断用最新扫描 */
        for (k = 0; k < owned.count; k++) {
            if (strcmp(owned.items[k].name, cfg->tun_device) == 0) {
                idx = owned.items[k].ifindex;
                break;
            }
        }
    }
    /* v1.2.5/1.2.6 名字漂移兜底：mihomo 重载后新 TUN 可能不再叫配置名（Linux
     * 回退名是 "Meta"；"tunN" 已被 v1.2.8 排除——系统 VPN 专用名）。精确匹配
     * （含复核）失败时，找"晚于旧 utun、IFF_UP、TUN 类名字或 ARPHRD_NONE"的
     * 候选自动对齐（tun_find_drift，v1.2.6 含按类型兜底）。 */
    if (idx <= 0) {
        int drift = tun_find_drift(list, cfg->tun_device, g_tun_last_good);

        if (drift > 0) {
            int first_time = (g_tun_drift_idx != drift);

            idx = drift;
            /* v1.2.8：记录漂移对齐的设备——否则下一心跳"ifindex > last_good"
             * 会把刚对齐的设备排除、map_tun 回退置 0（漂移对齐只活一轮）。 */
            g_tun_drift_idx = drift;
            if (first_time)
                LOG_WARNF("tun 设备 %s 未找到，检测到名字漂移的新 TUN 接口 ifindex=%d，"
                          "自动对齐（若持续出现，请把 mihomo tun.device 改为实际名字）",
                          cfg->tun_device, drift);
        }
    }
    /* v1.2.8：漂移记忆只在"漂移设备仍有效"时保留——精确匹配命中（设备改回配置名）
     * 或设备彻底缺失（下面置 0）都清零，恢复对未来漂移的重新搜寻。 */
    if (g_tun_drift_idx != 0 && !(idx > 0 && idx == g_tun_drift_idx))
        g_tun_drift_idx = 0;
    if (map_get_tun(ctx, &cur) != 0)
        return -1;

    if (idx <= 0) {
        if (cur != 0) {
            if (map_set_tun(ctx, 0) != 0) {
                LOG_ERRORF("map_tun 置 0 失败(%s)", strerror(errno));
                return -1;
            }
            {
                char tunlike[160] = "";
                tun_list_like(list, cfg->tun_device, tunlike, sizeof(tunlike));
                LOG_WARNF("tun 设备 %s 不存在，map_tun 置 0（代理流量放行保联网）"
                          "；扫描中 TUN 类接口: %s", cfg->tun_device,
                          tunlike[0] ? tunlike : "(无)");
            }
        }
        return 1; /* 降级中：utun 缺失，map_tun=0（心跳据此收紧快重试） */
    }
    g_tun_last_good = idx; /* 名字漂移兜底的"最新有效 ifindex"基准 */
    if (cur != (uint32_t)idx) {
        if (map_set_tun(ctx, idx) != 0) {
            LOG_ERRORF("map_tun 更新 %d 失败(%s)", idx, strerror(errno));
            return -1;
        }
        LOG_INFOF("tun 设备 %s ifindex=%d 已重新对齐", cfg->tun_device, idx);
    }
    return 0;
}

void daemon_loop(const char *cfg_path, const char *bpf_obj, int debug)
{
    struct split_config cfg;
    struct split_bpf_ctx ctx;
    struct dns_learn dl;
    int tun_index, lfd = -1, evfd = -1, lock_fd = 0;
    long long cnip_next_ms = 0;
    long long tun_sync_last_ms = 0;
    long long reconcile_last_ms = 0;
    long long dns_prune_last_ms = 0;
    long long hijack_last_ms = 0; /* 路由接管检测节流（10s） */
    int tun_degraded = 0; /* v1.2.4：map_tun=0（utun 缺失）降级中 → 心跳收紧到 300ms 快重试 */
    struct rule_overrides rov;   /* v1.2.0：运行时规则偏差（add-rule/del-rule，reload 后保留） */
    int cnip_boot_once = 0;       /* v1.1.3：CNIP 缺失补拉（一次） */
    pid_t cnip_pid = 0; /* CNIP 更新子进程（见主循环 fork 注释） */

    if (debug)
        g_log_level = LOG_DEBUG;

    if (config_load(cfg_path, &cfg) < 0)
        exit(1);
    config_dump(&cfg);
    if (cfg.debug)
        g_log_level = LOG_DEBUG;
    rule_overrides_init(&rov);

    /* 1.5 单实例锁：防二次 start 顶掉首个实例的 ctl socket。
     * 锁被占用（另一实例存活）→ 退出；锁不可用（只读目录等）→ 降级继续。 */
    {
        char lock_path[PATH_MAX];
        const char *sp = split_socket_path();

        snprintf(lock_path, sizeof(lock_path), "%s.lock", sp);
        lock_fd = instance_lock(lock_path);
        if (lock_fd == -1)
            exit(4); /* 已有 splitd 在运行 */
        if (lock_fd == -2)
            lock_fd = 0; /* 降级：无锁运行 */
    }

    /* 1. BPF —— 加载失败直接退出（无 eBPF 的 splitd 没有意义）。
     *    注意：不是"降级纯 TUN"——若 mihomo auto-route:false（本项目推荐配置），
     *    splitd 退出后无人接管分流，须由 service.sh 检测退出并提示。 */
    if (split_load(&ctx, bpf_obj) < 0) {
        LOG_ERRORF("eBPF 加载失败，退出（mihomo 若 auto-route:false 则无兜底，请查 dmesg/sepolicy）");
        exit(2);
    }

    /* 2. tun */
    tun_index = iface_resolve_tun(cfg.tun_device);
    if (tun_index <= 0) {
        LOG_ERRORF("找不到代理 tun 设备 %s（请先启动 mihomo）", cfg.tun_device);
        split_unload(&ctx);
        exit(3);
    }
    if (map_set_tun(&ctx, tun_index) != 0)
        LOG_WARNF("map_tun 写入 %d 失败(%s)", tun_index, strerror(errno));
    LOG_INFOF("tun 设备 %s ifindex=%d", cfg.tun_device, tun_index);
    g_tun_last_good = tun_index; /* v1.2.5：名字漂移兜底的 ifindex 基准 */

    /* 3. 规则 + uid + cnip */
    rule_apply_all(&ctx, &cfg);
    if (cfg.cnip4_path[0] || cfg.cnip6_path[0])
        cnip_apply(&ctx, &cfg);
    if (cfg.cnip_auto_update_hours > 0)
        cnip_next_ms = now_ms() + (long long)cfg.cnip_auto_update_hours * 3600000LL;

    /* 3.5 CNIP 缺失自愈（v1.1.3）：启动后本地 CNIP 文件若未导入成功（0 条）
     * 但配置了 url 数据源，立即安排一次自动更新（不等到 auto_update_hours），
     * 避免"装了框架但 CNIP 静默缺失、直连分流一直不生效"的问题（真机教训：
     * 设备上只有 split.yaml 没有 cn_cidr_v4.txt，direct_cn 恒 0 却无报错）。
     * 仅补拉一次：成功/失败后 cnip_boot_once 清零，周期行为仍由
     * cnip_auto_update_hours 决定（0=不周期更新）。 */
    {
        uint32_t n4 = 0, n6 = 0;

        map_cnip_count(&ctx, &n4, &n6);
        if (n4 == 0 && n6 == 0) {
            if (cfg.cnip4_url[0] || cfg.cnip6_url[0]) {
                LOG_WARNF("CNIP 0 条且配置了 url，5 秒后自动补拉（url_v4=%s）",
                          cfg.cnip4_url[0] ? cfg.cnip4_url : "(无)");
                cnip_boot_once = 1;
                cnip_next_ms = now_ms() + 5000LL;
            } else {
                LOG_WARNF("CNIP 0 条且未配置 url：请放置 cn_cidr_v4.txt/v6.txt 后 reload-cnip");
            }
        }
    }

    /* 4. 挂载 */
    iface_reconcile(&ctx, &cfg, NULL);

    /* 4.5 DNS 学习器（v1.1.0 域名分流）。
     * 打开失败只 WARN 不退出：主分流（CNIP/规则）不受影响，仅域名功能不生效。 */
    dns_learn_open(&dl, &ctx);

    /* 5. 控制/监听 */
    lfd = ctl_listen();
    evfd = iface_watch_open();
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    /* 忽略 SIGPIPE（审查加固）：ctl_reply 用 write 回 unix stream socket，
     * 若客户端在回复期间断开（如 splitctl 途中被杀），write 触发 SIGPIPE，默认
     * 动作会直接杀死 splitd —— 网卡上残留 tc filter + map 即失守。必须忽略，
     * 让 write 返回 EPIPE 走 ctl_reply 的 `w <= 0` 放行路径。 */
    signal(SIGPIPE, SIG_IGN);

    while (!g_stop) {
        struct pollfd fds[3];
        int nfds = 0, rc;
        int lfd_idx = -1, evfd_idx = -1, dns_idx = -1;

        /* CNIP 定时自动更新（auto_update_hours，0=关闭；v1.1.3：cnip_boot_once
         * 时即使 hours=0 也补拉一次）。
         * 配置了 url_v4/v6 则先下载刷新本地文件，再全量重灌。
         * 下载可能耗时数分钟（curl --max-time 60 ×2），必须 fork 子进程执行，
         * 否则 poll 主循环被阻塞：网络事件/ctl 命令都会停摆。
         * 子进程继承 ctx 的 map fd，可直接灌入；父进程 waitpid 回收。 */
        if ((cfg.cnip_auto_update_hours > 0 || cnip_boot_once) &&
            now_ms() >= cnip_next_ms && cnip_pid == 0) {
            if (cnip_boot_once)
                LOG_INFOF("CNIP 缺失补拉启动（一次）");
            else
                LOG_INFOF("CNIP 定时自动更新（每 %d 小时）", cfg.cnip_auto_update_hours);
            g_cnip_busy = 1; /* 置忙：fork 期间与灌入期间拒绝 reload-cnip（防双写） */
            cnip_pid = fork();
            if (cnip_pid == 0) {
                int r;

                /* 子进程只做 CNIP 更新：关闭与更新无关的父进程 fd——
                 * ctl listen / netlink watch / DNS AF_PACKET / 单实例锁，
                 * 避免它们被内层 fork+execlp 派生的 curl（v1.2.8 起不再走
                 * system/sh）继承泄漏，也避免与父进程 poll 主循环的 fd 语义
                 * 纠缠。map fd 必须保留（子进程要经 bpf 系统调用灌 CNIP，见下）。 */
                if (lfd >= 0) close(lfd);
                if (evfd >= 0) close(evfd);
                if (dl.fd >= 0) close(dl.fd);
                if (lock_fd > 0) close(lock_fd);
                r = cnip_auto_update(&ctx, &cfg);
                _exit(r == 0 ? 0 : 1);
            }
            if (cnip_pid < 0) {
                LOG_ERRORF("fork 失败，1 分钟后再试");
                cnip_pid = 0;
                g_cnip_busy = 0; /* fork 失败：从未进入子进程，解除忙标志 */
                /* boot_once 不清零：保证 hours=0 时补拉仍会重试（否则
                 * 条件 (hours>0 || boot_once) 恒 false，补拉被永久吞掉） */
                cnip_next_ms = now_ms() + 60000LL;
            } else {
                LOG_INFOF("CNIP 更新已派生子进程 pid=%d", cnip_pid);
            }
        }
        /* 回收 CNIP 更新子进程（不阻塞） */
        if (cnip_pid > 0) {
            int st = 0;
            pid_t r = waitpid(cnip_pid, &st, WNOHANG);

            if (r == cnip_pid) {
                cnip_pid = 0;
                g_cnip_busy = 0; /* 子进程已回收：解除 reload-cnip 拒绝 */
                if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
                    cnip_boot_once = 0;
                    cnip_next_ms = now_ms() +
                        (long long)cfg.cnip_auto_update_hours * 3600000LL;
                } else {
                    /* 失败保留 boot_once（仅成功才清零）：hours=0（仅补拉一次）
                     * 时若清零，调度条件 (hours>0 || boot_once) 恒 false，
                     * "5 分钟后再试"永远不会发生——与 fork 失败分支语义一致。 */
                    LOG_ERRORF("CNIP 更新失败，5 分钟后再试");
                    cnip_next_ms = now_ms() + 300000LL;
                }
            } else if (r < 0) {
                /* v1.2.8（审查修复）：waitpid 失败（如 ECHILD——子进程已被系统回收）
                 * 时若不清除 cnip_pid，会永久卡死：定时更新不再触发、g_cnip_busy
                 * 恒 1 导致 reload-cnip 永久被拒。按 fork 失败同语义清理并稍后重试。 */
                LOG_WARNF("waitpid CNIP 子进程失败(%s)，清除更新状态，1 分钟后再试",
                          strerror(errno));
                cnip_pid = 0;
                g_cnip_busy = 0;
                cnip_next_ms = now_ms() + 60000LL;
            }
        }

        /* 记录各自在 fds[] 中的实际下标，避免 fd 为 -1 时错位读到未初始化槽位 */
        if (lfd >= 0) { fds[nfds].fd = lfd; fds[nfds].events = POLLIN; lfd_idx = nfds; nfds++; }
        if (evfd >= 0) { fds[nfds].fd = evfd; fds[nfds].events = POLLIN; evfd_idx = nfds; nfds++; }
        if (dl.fd >= 0) { fds[nfds].fd = dl.fd; fds[nfds].events = POLLIN; dns_idx = nfds; nfds++; }

        rc = poll(fds, nfds, 2000);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (rc > 0) {
            /* v1.2.7（审查 H3）：poll 只消费 POLLIN，而 POLLERR/POLLHUP/POLLNVAL
             * 若出现却无人处理，poll 会立即返回 → daemon 100% CPU 忙循环。对三个
             * fd 的错误事件显式处理：ctl listen / netlink watch 重建，DNS 学习器
             * 关闭降级（非致命，reload 重开）。 */
            if (lfd_idx >= 0 &&
                (fds[lfd_idx].revents & (POLLERR | POLLHUP | POLLNVAL))) {
                LOG_WARNF("ctl listen fd 异常(0x%x)，重建监听 socket",
                          fds[lfd_idx].revents);
                close(lfd);
                lfd = ctl_listen();   /* 内部 unlink+bind+chmod */
            }
            if (evfd_idx >= 0 &&
                (fds[evfd_idx].revents & (POLLERR | POLLHUP | POLLNVAL))) {
                LOG_WARNF("netlink watch fd 异常(0x%x)，重建 watch socket",
                          fds[evfd_idx].revents);
                close(evfd);
                evfd = iface_watch_open();
            }
            if (dns_idx >= 0 &&
                (fds[dns_idx].revents & (POLLERR | POLLHUP | POLLNVAL))) {
                LOG_WARNF("dns 学习器 fd 异常(0x%x)，关闭学习器（reload 后重开）",
                          fds[dns_idx].revents);
                dns_learn_close(&dl);
            }

            if (lfd_idx >= 0 && (fds[lfd_idx].revents & POLLIN)) {
                int c = accept(lfd, NULL, NULL);
                if (c >= 0) {
                    ctl_serve(&ctx, cfg_path, &cfg, &cnip_next_ms, &dl, &rov,
                              &tun_degraded, c);
                    close(c);
                }
                if (g_stop)
                    break;
            }
            if (evfd_idx >= 0 && (fds[evfd_idx].revents & POLLIN)) {
                struct iface_list snap;
                if (iface_watch_poll(evfd, &snap) > 0) {
                    LOG_INFOF("检测到网络变化，重新同步挂载");
                    /* v1.1.9：复用 iface_watch_poll 已拿到的快照，避免 reconcile 再全量 scan */
                    iface_reconcile(&ctx, &cfg, &snap);
                    /* v1.2.1：mihomo 重载配置重建 utun 时 ifindex 漂移，立即用同一
                     * 快照对齐 map_tun——否则要等 1s 心跳，期间 bpf_redirect 指向
                     * 陈旧 ifindex 被 __skb_do_redirect 静默丢包（海外全挂）。
                     * v1.2.4：tun_sync 内会对缺 utun 的快照做权威复核（见函数注释），
                     * 返回值同步维护 tun_degraded 供心跳降级快重试。 */
                    {
                        int r = tun_sync(&ctx, &cfg, &snap);

                        if (r >= 0)
                            tun_degraded = (r == 1);
                    }
                    tun_sync_last_ms = now_ms();
                }
            }
            if (dns_idx >= 0 && (fds[dns_idx].revents & POLLIN)) {
                dns_learn_poll(&dl);
            }
        }

        /* 心跳兜底：tun 存活同步不依赖 poll 超时。持续 DNS 流量下 dl.fd 恒可读、
         * poll 几乎不超时——若只放 rc==0 分支则兜底形同虚设：mihomo 重建 utun 且
         * netlink 事件漏收时 map_tun 残留旧 ifindex，代理流量被内核 __skb_do_redirect
         * kfree_skb 静默丢弃（v1.0.6 故障面）。代价：每秒一次 rtnetlink 全量 dump
         * （<1ms）。事件路径（见上）已第一时间复用快照对齐，此处是事件漏收时的兜底。
         * v1.2.4：utun 缺失降级期间（tun_degraded=1）把间隔从 1s 收紧到 300ms——
         * mihomo 重载重建 utun 时若 NEWLINK 事件漏收，恢复代理的等待从 ≤1s 缩到
         * ≤300ms，缩小"代理完全失效"的窗口；正常状态仍 1s。 */
        {
            long long now = now_ms();
            int r;

            if (now - tun_sync_last_ms >=
                (tun_degraded ? TUN_SYNC_DEGRADED_MS : 1000)) {
                r = tun_sync(&ctx, &cfg, NULL);
                if (r >= 0)
                    tun_degraded = (r == 1);
                tun_sync_last_ms = now;
            }
        }

        /* 接口挂载自愈心跳（v1.1.7，5s 节流）：iface_reconcile 原先只在 netlink
         * 事件（iface_watch_poll>0）时执行——熄屏 doze / 弱网下事件可能被内核
         * 丢进 watch socket 缓冲溢出、或整个进程被冻结错过事件，导致 eBPF 永久
         * 挂在旧 ifindex（attached=n 仍显示正常）→ 分流静默失效（真机症状：
         * 长时间熄屏后无法代理，mihomo 只剩自身 DNS 连接）。
         * 与 tun_sync 同源思路（v1.1.2）：改为周期兜底自愈（幂等，无变化零开销；
         * iface_scan 全程 <1ms，5s 一次可忽略）。netlink 事件路径保留（触达更快），
         * 此心跳保证事件漏收时最多 5s 内自愈。 */
        if (now_ms() - reconcile_last_ms >= 5000) {
            iface_reconcile(&ctx, &cfg, NULL);
            reconcile_last_ms = now_ms();
        }

        /* 路由接管检测（v1.1.3，10s 节流）：mihomo 若被改回 auto-route:true
         * 或用户手动加路由把 default 指向 tun，物理网卡 egress 的 eBPF 立刻
         * 失明（direct_cn/proxy 停涨但无报错）。检测到变化立即打 WARN，
         * 让"静默失效"变成可查日志；splitctl status 也会带出 hijack 标记。 */
        if (now_ms() - hijack_last_ms >= 10000) {
            uint32_t tun_u = 0;
            int tun = 0, h;

            if (map_get_tun(&ctx, &tun_u) == 0)
                tun = (int)tun_u;
            h = route_tun_hijacked(tun);
            /* v1.2.8：原始结果（含 -1）存入 g_hijack_now 供 ctl_status 读取——
             * status 的 hijack 字段不再由 ctl 路径重跑 netlink dump。 */
            g_hijack_now = h;
            /* -1=检测失败（netlink 错误/超时）：跳过本轮，不更新状态不告警，
             * 避免误报"接管/解除"；status 的 hijack 字段如实显示 -1。 */
            if (h >= 0 && h != g_hijack_last) {
                if (h == 1)
                    LOG_WARNF("检测到路由被接管（default 指向 tun）：eBPF 分流失效，请将 mihomo tun.auto-route 改为 false");
                else if (g_hijack_last == 1)
                    LOG_INFOF("路由接管已解除，eBPF 分流恢复");
                g_hijack_last = h;
            }
            hijack_last_ms = now_ms();
        }

        /* DNS 学习条目过期清理（30s 节流；内核查到过期条目会跳过，
         * 这里只负责回收 map 空间，频率低一点无碍） */
        if (dl.fd >= 0 && now_ms() - dns_prune_last_ms >= 30000) {
            int pruned = map_dns_prune(&ctx, (uint64_t)now_ms() * 1000000ULL);

            if (pruned > 0)
                LOG_DEBUGF("dns 学习: 清理过期条目 %d", pruned);
            dns_prune_last_ms = now_ms();
        }
    }

    LOG_INFOF("splitd 退出");
    if (cnip_pid > 0) {
        /* 不阻塞退出：子进程仍持有 map fd，让其自然完成/回收；已结束则收尸防僵尸 */
        int st = 0;

        waitpid(cnip_pid, &st, WNOHANG);
    }
    dns_learn_close(&dl);
    split_unload(&ctx);
    if (lfd >= 0) {
        close(lfd);
        unlink(split_socket_path());
    }
    if (evfd >= 0)
        close(evfd);
    if (lock_fd > 0)
        close(lock_fd); /* 释放单实例锁（进程退出时也会自动释放） */
}

int main(int argc, char **argv)
{
    const char *cfg_path = "/etc/split/split.yaml";
    const char *bpf_path = SPLIT_BPF_OBJ_DEFAULT;
    int opt, debug = 0;

    while ((opt = getopt(argc, argv, "c:b:d")) != -1) {
        switch (opt) {
        case 'c': cfg_path = optarg; break;
        case 'b': bpf_path = optarg; break;
        case 'd': debug = 1; break;
        default:
            fprintf(stderr, "用法: %s [-d] [-c cfg] [-b obj]\n", argv[0]);
            return 1;
        }
    }
    daemon_loop(cfg_path, bpf_path, debug);
    return 0;
}