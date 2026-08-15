/* SPDX-License-Identifier: GPL-2.0
 * cnip.c — CNIP 数据导入
 *
 * 依赖：loader 的 map_cnip_add_cidr（用户态 → LPM_TRIE map）
 * 数据格式：每行一条 "A.B.C.D/N" 或 "IPv6/N"，支持 # 注释与空行。
 */
#include "cnip.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>        /* PATH_MAX（path_lookup 回落查找用） */
#include <time.h>          /* clock_gettime/CLOCK_MONOTONIC（下载耗时统计） */
#include <unistd.h>        /* fork/execl/_exit */
#include <fcntl.h>         /* FD_CLOEXEC（exec 下载器前防 fd 泄漏） */
#include <sys/socket.h>   /* AF_INET */
#include <sys/wait.h>      /* WEXITSTATUS / waitpid */
#include <arpa/inet.h>

#include "../common/log.h"

/* 单行地址族探测：返回 AF_INET / AF_INET6，非法（或超长）返回 0。
 * v1.4.3：混合 v4+v6 数据源（Loyalsoldier/geoip cn.txt）按目标族加载时，
 * 用此在进入 map_cnip_add_cidr 前跳过另一族行——否则会因 inet_pton 族不符
 * 被计入"失败"行数（其实不是失败，是另一族）。裸 IP 无斜杠也能探测（对应
 * 自动补 /32 或 /128 的既有逻辑）。 */
static int cnip_line_family(const char *line)
{
    char ip[256];
    const char *slash = strchr(line, '/');
    size_t n = slash ? (size_t)(slash - line) : strlen(line);
    struct in_addr a4;
    struct in6_addr a6;

    if (n == 0 || n >= sizeof(ip))
        return 0;
    memcpy(ip, line, n);
    ip[n] = '\0';
    if (inet_pton(AF_INET, ip, &a4) == 1)
        return AF_INET;
    if (inet_pton(AF_INET6, ip, &a6) == 1)
        return AF_INET6;
    return 0;
}

/* dry_run=1：只解析计 ok/bad、不写 CNIP map（下载校验阶段用，见 cnip_try_url）——
 * 校验期若直接写 map，rename 失败且全配置族失败跳过 cnip_apply 时，map 会残留
 * 本地旧文件里没有的条目（map≠file）。dry_run 走 map_cnip_cidr_ok 判定，与
 * 真正加载（map_cnip_add_cidr）的 ok/bad 口径一致。 */
static int cnip_load_fd(struct split_bpf_ctx *ctx, FILE *fp, int family,
                        unsigned int *p_ok, unsigned int *p_bad, int dry_run)
{
    char line[256];
    unsigned int ok = 0, bad = 0, skip = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *p, *slash = NULL;
        char one[256];
        size_t n;

        /* 去行尾（\n \r 及尾随空白；Windows/CRLF/手工编辑过的数据文件常见） */
        n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r' ||
                         line[n - 1] == ' ' || line[n - 1] == '\t'))
            line[--n] = '\0';

        p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '#')
            continue;

        /* 审查（2026-08）：行内 `#` 注释——"1.2.3.4/24 # 说明"这类行此前只剥了整行
         * 注释（上面的 continue），行内注释会带着 " # 说明" 一路进 snprintf/parse_pfix，
         * 合法行被计 bad 并丢弃（MEMORY"支持 # 注释"契约只实现了一半）。IPv6 地址不含
         * #，从首个 # 截断安全；截断后需再去尾随空白（可能紧贴 # 或注释后）。 */
        {
            char *hash = strchr(p, '#');

            if (hash)
                *hash = '\0';
            n = strlen(p);
            while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t'))
                p[--n] = '\0';
        }
        if (*p == '\0')
            continue;

        /* v1.4.3（混合源按族加载）：异族行跳过、不计 bad（Loyalsoldier cn.txt 同时含
         * v4+v6，加载 v4 map 时跳过 v6 行）；非法行仍计 bad（ok/bad 语义不变）。
         * v1.4.5：skip 计数仅供 DEBUG 诊断——混合文件按族加载后想确认"该族之外
         * 到底被跳过了多少行"，或排查"文件全为另一族导致 0 条"时，不用再猜。 */
        {
            int lfam = cnip_line_family(p);
            if (lfam == 0) {
                bad++;
                continue;
            }
            if (lfam != family) {
                skip++;
                continue;
            }
        }

        slash = strchr(p, '/');
        {
            int one_len;
            if (slash)
                one_len = snprintf(one, sizeof(one), "%s", p);
            else
                one_len = snprintf(one, sizeof(one), "%s/%d", p,
                                   family == AF_INET ? 32 : 128);
            if (one_len < 0 || one_len >= (int)sizeof(one)) {
                /* 超缓冲的畸形行（snprintf 返回所需长度）：整行放弃，
                 * 避免写入被截断的 cidr 造成误分流 */
                LOG_DEBUGF("跳过超长行: %s", p);
                bad++;
                continue;
            }
        }

        if ((dry_run ? map_cnip_cidr_ok(one, family)
                     : map_cnip_add_cidr(ctx, one, family)) == 0)
            ok++;
        else
            bad++;
    }
    if (skip > 0)
        LOG_DEBUGF("跳过异族行 %u 条（混合源按族加载，family=%d）", skip, family);
    *p_ok = ok;
    *p_bad = bad;
    return 0;
}

static int cnip_from_path(struct split_bpf_ctx *ctx, const char *path, int family)
{
    FILE *fp;
    unsigned int ok = 0, bad = 0;

    fp = fopen(path, "r");
    if (!fp) {
        LOG_ERRORF("打开 %s 失败", path);
        return -1;
    }
    cnip_load_fd(ctx, fp, family, &ok, &bad, 0); /* 真正加载：写 map */
    fclose(fp);
    LOG_INFOF("CNIP(%s) 导入完成: %u 条, 失败 %u 条 (%s)",
              family == AF_INET ? "v4" : "v6", ok, bad, path);
    /* v1.4.4（审查修复）：加载 0 条时显式告警——文件空/全为另一族/全非法。
     * 族过滤把异族行跳过不计 bad，故 v4-only 文件配到 v6 等错配会 ok=bad=0，
     * 仅靠上面的 INFO 不易察觉。 */
    if (ok == 0)
        LOG_WARNF("CNIP(%s) 加载 0 条：文件为空/全为另一地址族/全非法，请检查 %s",
                  family == AF_INET ? "v4" : "v6", path);
    return 0;
}

int cnip_load_file(struct split_bpf_ctx *ctx, const char *path, int family)
{
    return cnip_from_path(ctx, path, family);
}

/* 在 PATH 中按名字查找可执行文件（回落场景）；返回静态缓冲里的完整路径，失败 NULL。 */
static const char *path_lookup(const char *name)
{
    const char *path = getenv("PATH");
    static char buf[PATH_MAX];
    const char *d;
    size_t n;

    if (!path || !path[0])
        return NULL;
    d = path;
    for (;;) {
        const char *e = strchr(d, ':');

        n = e ? (size_t)(e - d) : strlen(d);
        if (n > 0 && n + strlen(name) + 2 < sizeof(buf)) {
            memcpy(buf, d, n);
            buf[n] = '\0';
            snprintf(buf + n, sizeof(buf) - n, "/%s", name);
            if (access(buf, X_OK) == 0)
                return buf;
        }
        if (!e)
            break;
        d = e + 1;
    }
    return NULL;
}

/* 审查修复（2026-08 全库审查批次）：CNIP 下载子进程以 root 运行，依赖 PATH 查找
 * 可执行文件存在被预置同名二进制替换成 root 代码执行的风险——优先探测常见绝对路径。
 * v1.4.1（CNIP 更新失败修复）：Android Magisk 环境通常没有 curl（cnip_find_curl 探测
 * 全部落空 → exec 失败 exit 127 → 下载必失败，每 5 分钟重试死循环），补齐 wget/busybox
 * 探测与 PATH 回落；全部缺失返回 NULL，由调用方明确报错而非 exec 后 exit 127 的模糊失败。
 * 须在 fork 前（父进程）调用一次，结果由子进程继承 exec。 */
static const char *cnip_find_downloader(int *is_curl)
{
    static const char *const curls[] = {
        "/system/bin/curl", "/system/xbin/curl",
        "/data/adb/split/bin/curl", "/usr/bin/curl", "/bin/curl",
    };
    static const char *const wgets[] = {
        "/system/bin/wget", "/system/xbin/wget",
        "/data/adb/split/bin/wget",
        "/system/bin/busybox", "/system/xbin/busybox",
        "/data/adb/split/bin/busybox",
        "/usr/bin/wget", "/usr/bin/busybox",
        "/bin/wget", "/bin/busybox",
    };
    const char *p;

    for (size_t i = 0; i < sizeof(curls) / sizeof(curls[0]); i++)
        if (access(curls[i], X_OK) == 0) { *is_curl = 1; return curls[i]; }
    for (size_t i = 0; i < sizeof(wgets) / sizeof(wgets[0]); i++)
        if (access(wgets[i], X_OK) == 0) { *is_curl = 0; return wgets[i]; }
    p = path_lookup("curl");
    if (p) { *is_curl = 1; return p; }
    p = path_lookup("wget");
    if (p) { *is_curl = 0; return p; }
    p = path_lookup("busybox");
    if (p) { *is_curl = 0; return p; }
    LOG_WARNF("未找到 curl/wget/busybox（常见路径与 PATH 均无），无法自动更新 CNIP");
    return NULL;
}

/* 单源尝试：fork+exec 下载 url 到 tmp_path 并解析校验（ok>0 才认成功）。
 * 供 cnip_load_url 的多源 fallback 逐个调用；下载器（tool/is_curl）由调用方
 * 在循环外探测一次（候选源之间下载器不变）。返回 0 成功 / -1 失败。 */
static int cnip_try_url(struct split_bpf_ctx *ctx, const char *url,
                        const char *tmp_path, int family,
                        const char *tool, int is_curl)
{
    pid_t pid;
    int st = 0;
    struct timespec t0, t1;

    if (strchr(url, '\'') || strchr(tmp_path, '\'')) {
        LOG_ERRORF("拒绝含单引号的 URL: %s", url);
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t0); /* 下载耗时起点（含 fork+wait+解析校验） */
    pid = fork();
    if (pid < 0) {
        LOG_ERRORF("下载 fork 失败(%s)", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* v1.2.9（审查加固）：exec 前把继承的全部非标准 fd 置 CLOEXEC——
         * 本进程（daemon 派生的 CNIP 更新子进程）持有 BPF map fd、ctl listen、
         * netlink watch 等；下载器 exec 后若继承它们，会成为"不可控进程持着
         * 系统 fd"的脏现场（下载器短暂运行，危害小但应杜绝）。CLOEXEC 只在
         * exec 时生效，不影响本进程 exec 前/后续灌 CNIP 对 map fd 的使用。 */
        for (int fd = 3; fd < 256; fd++)
            fcntl(fd, F_SETFD, FD_CLOEXEC);
        if (is_curl) {
            /* -f：HTTP >= 400 视为失败。旧实现缺 -f，404/502 会以 0 退出码把
             * 错误页存进文件当成功 → rename 覆盖好文件 → cnip_apply 全量清空
             * 重灌 0 条（CNIP 静默归零、直连分流失效的根因之一）。 */
            execl(tool, "curl", "-f", "-L", "--max-time", "60", "-s",
                  "-o", tmp_path, url, (char *)NULL);
        } else if (strstr(tool, "busybox") != NULL) {
            execl(tool, "busybox", "wget", "-q", "-T", "60", "-O",
                  tmp_path, url, (char *)NULL);
        } else {
            execl(tool, "wget", "-q", "-T", "60", "-O",
                  tmp_path, url, (char *)NULL);
        }
        /* 只有 exec 失败才到这里（下载器不存在/不可执行） */
        _exit(127);
    }
    /* EINTR 重试：daemon 的信号处理只置 g_stop，SIGINT/SIGTERM 会中断 waitpid
     * 导致误报"下载失败"（system() 内部同样会被打断，这里显式重试更稳）。 */
    for (;;) {
        if (waitpid(pid, &st, 0) >= 0)
            break;
        if (errno == EINTR)
            continue;
        LOG_ERRORF("下载 waitpid 失败(%s)", strerror(errno));
        return -1;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        LOG_ERRORF("下载失败(exit=%d): %s",
                   WIFEXITED(st) ? WEXITSTATUS(st) : -1, url);
        return -1;
    }

    /* 解析下载内容并校验非空：0 条有效 CIDR = 拿到错误页/空文件（如镜像返回 200 的
     * HTML），直接弃用并 return -1，避免 cnip_fetch_to_path 把坏文件 rename 覆盖好
     * 文件。若此处放行，坏文件会经 cnip_apply 全量清空重灌 → CNIP 归零。真正的 map
     * 灌入仍由 cnip_apply 完成（fetch 成功 rename 到正式 path 后统一重灌）。
     * v1.4.6（审查 P2）：此校验为 dry-run（cnip_load_fd dry_run=1，不写 map）——
     * 校验期写 map 会在 rename 失败（磁盘满/权限）且全配置族失败跳过 apply 时，
     * 让 map 残留只存在于新下载文件、本地旧文件里没有的条目（map≠file）。 */
    {
        FILE *fp = fopen(tmp_path, "r");
        unsigned int ok = 0, bad = 0;

        if (!fp) {
            LOG_ERRORF("打开下载文件失败: %s (%s)", tmp_path, strerror(errno));
            return -1;
        }
        cnip_load_fd(ctx, fp, family, &ok, &bad, 1); /* 校验：dry-run 不写 map */
        fclose(fp);
        LOG_INFOF("CNIP(%s) 下载并解析: %u 条, 失败 %u 条 (%s)",
                  family == AF_INET ? "v4" : "v6", ok, bad, url);
        if (ok == 0) {
            /* v1.4.4（审查修复）：区分失败形态——bad>0 是真非法行（错误页/垃圾内容）；
             * bad==0 是空文件或"全为另一地址族行"（如 v4 源配到 v6、源换格式，族过滤
             * 把异族行跳过不计 bad）。两者都弃用（沿用本地旧文件），仅日志更可诊断。 */
            if (bad > 0)
                LOG_ERRORF("下载内容无有效 CIDR（%u 行非法，疑似错误页/垃圾），弃用: %s",
                           bad, tmp_path);
            else
                LOG_ERRORF("下载内容为空或全为另一地址族行（检查 url 是否配错族），弃用: %s",
                           tmp_path);
            return -1;
        }
    }
    /* v1.4.5：下载耗时——多源 fallback 逐个尝试时，能看出"首选源到底卡了多久才
     * 回落下一候选"（curl --max-time 60 内超时的源会拖慢整个更新）。 */
    clock_gettime(CLOCK_MONOTONIC, &t1);
    LOG_DEBUGF("下载成功，耗时 %lldms: %s",
               (long long)(t1.tv_sec - t0.tv_sec) * 1000LL +
                   (long long)(t1.tv_nsec - t0.tv_nsec) / 1000000LL,
               url);
    return 0;
}

int cnip_load_url(struct split_bpf_ctx *ctx, const char *url,
                  const char *tmp_path, int family)
{
    char buf[CFG_STRLEN];
    char *p;
    int is_curl = 1;
    const char *tool;

    /* v1.2.8（审查修复）：弃用 system()（shell 拼接注入面），改 fork + exec 直接跑
     * 下载器——参数原样传给 execve，无 shell 解释，URL 中任何元字符（`;` `$()` 反引号等）
     * 都只是普通参数。exec 优先绝对路径（2026-08 审查批次），消除对可写 PATH 的依赖。
     * v1.4.1（CNIP 更新失败修复）：Android Magisk 环境通常没有 curl，探测回落
     * wget/busybox wget；全部缺失由 cnip_find_downloader 返回 NULL，此处明确报错。 */
    tool = cnip_find_downloader(&is_curl);
    if (!tool) {
        LOG_ERRORF("未找到 curl/wget/busybox，无法自动更新 CNIP"
                   "（请安装其一，或放置本地 CNIP 文件后 reload-cnip）");
        return -1;
    }
    LOG_DEBUGF("CNIP 下载器: %s (%s)", tool, is_curl ? "curl" : "wget 系");

    /* 多源 fallback（v1.4.2）：url 支持逗号分隔多个候选，按序尝试、任一成功即用。
     * 默认 jsDelivr（大陆可达）优先、raw.githubusercontent（全球更稳）兜底，互为备份；
     * 全部失败返回 -1（沿用本地旧文件，见 cnip_fetch_to_path 调用方）。逗号做分隔符，
     * URL 内如需字面逗号请用 %2C（CNIP 源为简单路径，实际不会出现）。 */
    snprintf(buf, sizeof(buf), "%s", url);
    p = buf;
    while (p && *p) {
        char *comma = strchr(p, ',');
        char *cand;
        size_t n;

        if (comma)
            *comma = '\0';
        cand = p;
        while (*cand == ' ' || *cand == '\t')
            cand++;
        n = strlen(cand);
        while (n > 0 && (cand[n - 1] == ' ' || cand[n - 1] == '\t'))
            cand[--n] = '\0';
        if (cand[0]) {
            if (cnip_try_url(ctx, cand, tmp_path, family, tool, is_curl) == 0)
                return 0;
            LOG_WARNF("CNIP 源不可用，尝试下一候选: %s", cand);
        }
        p = comma ? comma + 1 : NULL;
    }
    return -1;
}

int cnip_apply(struct split_bpf_ctx *ctx, const struct split_config *cfg)
{
    int r4 = 0, r6 = 0;

    /* 未配置任何数据文件：不做任何改动（避免 reload-cnip 在无 path 配置时
     * 把已有 CNIP 全清空——低危但语义误导，清空应只发生在"全量替换"里）。 */
    if (!cfg->cnip4_path[0] && !cfg->cnip6_path[0])
        return 0;

    /* 先清空 v4+v6，保证每次 cnip_apply 都是"全量替换"而非追加，
     * 上游列表收缩时旧前缀不会残留（原追加语义的 bug）。
     * 审查（2026-08 P2）：清空失败必须显式报错——残留旧前缀会让"上游已移除"的
     * 段继续直连（静默误判）。不中止（保住可用性），下次 reload 重试。 */
    if (map_cnip_clear_all(ctx) < 0)
        LOG_ERRORF("清空 CNIP map 失败，本次重灌可能残留旧前缀（全量替换契约被破坏）");
    /* v1.1.9：仅配置单族的路径会把未配置的一族清空（"全量替换"契约语义）。
     * 显式点明，避免配置不完整时误以为另一族仍生效。 */
    if (cfg->cnip4_path[0] && !cfg->cnip6_path[0])
        LOG_WARNF("仅配置 cnip4：本次 reload 将清空 CNIP v6（无 v6 数据源）");
    else if (!cfg->cnip4_path[0] && cfg->cnip6_path[0])
        LOG_WARNF("仅配置 cnip6：本次 reload 将清空 CNIP v4（无 v4 数据源）");
    if (cfg->cnip4_path[0])
        r4 = cnip_from_path(ctx, cfg->cnip4_path, AF_INET);
    if (cfg->cnip6_path[0])
        r6 = cnip_from_path(ctx, cfg->cnip6_path, AF_INET6);
    return (r4 || r6) ? -1 : 0;
}

/* 下载 URL 到"本地文件"，避免写到一半被 load 读到不完整数据：
 * 先下到 <path>.tmp，成功后原子 rename 到 path，再统一 cnip_apply。 */
static int cnip_fetch_to_path(struct split_bpf_ctx *ctx,
                              const char *url, const char *path, int family)
{
    char tmp[CFG_STRLEN + 8];

    if (!url || !url[0] || !path || !path[0])
        return 0;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (cnip_load_url(ctx, url, tmp, family) < 0) {
        LOG_ERRORF("自动更新下载失败: %s -> %s", url, tmp);
        return -1;
    }
    if (rename(tmp, path) < 0) {
        LOG_ERRORF("自动更新保存失败: %s (errno=%d)", path, errno);
        return -1;
    }
    LOG_INFOF("CNIP 已刷新本地文件: %s", path);
    return 0;
}

int cnip_auto_update(struct split_bpf_ctx *ctx, const struct split_config *cfg)
{
    int v4_cfg, v6_cfg;
    int r4 = 0, r6 = 0;

    /* "配置" = url 与本地落盘 path 都给了：cnip_fetch_to_path 对空 url/path 是
     * no-op 返回 0——若直接把它当"成功"，单族配置的族下载失败时 r_other==0 会让
     * "全部失败"判定失效（v1.4.1 修复：失败被静默吞掉、不重试、还误报未配置族
     * 失败）。故先显式区分"配置族 vs 未配置族"。 */
    v4_cfg = cfg->cnip4_url[0] && cfg->cnip4_path[0];
    v6_cfg = cfg->cnip6_url[0] && cfg->cnip6_path[0];

    if (!v4_cfg && !v6_cfg)
        return 0; /* 未配置任何可更新数据源（url 有但缺 path 的族不可能落盘，同 v1.3.1 判定） */

    if (v4_cfg)
        r4 = cnip_fetch_to_path(ctx, cfg->cnip4_url, cfg->cnip4_path, AF_INET);
    if (v6_cfg)
        r6 = cnip_fetch_to_path(ctx, cfg->cnip6_url, cfg->cnip6_path, AF_INET6);

    /* 只对"配置了的族"判定成败；未配置族既不是成功也不是失败。
     * 至少一个配置族成功才落 map；但因 apply 是全量清空重灌，失败族会按
     * "本地旧文件"重写（用旧数据），在此显式点明，避免误以为该族已更新。 */
    if (v4_cfg && r4 != 0)
        LOG_WARNF("CNIP v4 下载失败，将沿用本地旧文件重灌");
    if (v6_cfg && r6 != 0)
        LOG_WARNF("CNIP v6 下载失败，将沿用本地旧文件重灌");
    if ((!v4_cfg || r4 != 0) && (!v6_cfg || r6 != 0))
        return -1; /* 全部配置族失败 → 让上层稍后重试 */
    return cnip_apply(ctx, cfg);
}