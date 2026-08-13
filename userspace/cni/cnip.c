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
#include <unistd.h>       /* fork/execlp/_exit */
#include <fcntl.h>         /* FD_CLOEXEC（exec curl 前防 fd 泄漏） */
#include <sys/socket.h>   /* AF_INET */
#include <sys/wait.h>      /* WEXITSTATUS / waitpid */
#include <arpa/inet.h>

#include "../common/log.h"

static int cnip_load_fd(struct split_bpf_ctx *ctx, FILE *fp, int family,
                        unsigned int *p_ok, unsigned int *p_bad)
{
    char line[256];
    unsigned int ok = 0, bad = 0;

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

        if (map_cnip_add_cidr(ctx, one, family) == 0)
            ok++;
        else
            bad++;
    }
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
    cnip_load_fd(ctx, fp, family, &ok, &bad);
    fclose(fp);
    LOG_INFOF("CNIP(%s) 导入完成: %u 条, 失败 %u 条 (%s)",
              family == AF_INET ? "v4" : "v6", ok, bad, path);
    return 0;
}

int cnip_load_file(struct split_bpf_ctx *ctx, const char *path, int family)
{
    return cnip_from_path(ctx, path, family);
}

/* 审查修复（2026-08 全库审查批次）：CNIP 下载子进程以 root 运行，旧实现 execlp("curl")
 * 依赖 PATH 查找可执行文件——若 daemon 启动环境（Magisk service / WSL2 / systemd）的
 * PATH 含用户可写目录（如 Android /data/local/tmp），可被预置同名二进制替换成 root 代码
 * 执行。改为优先探测常见绝对路径，全部缺失才回落 PATH（并告警，提示把 curl 放到
 * /data/adb/split/bin/curl）。须在 fork 前（父进程）调用一次，结果由子进程继承 exec。 */
static const char *cnip_find_curl(void)
{
    static const char *const cand[] = {
        "/system/bin/curl",
        "/system/xbin/curl",
        "/data/adb/split/bin/curl",
        "/usr/bin/curl",
        "/bin/curl",
    };
    for (size_t i = 0; i < sizeof(cand) / sizeof(cand[0]); i++) {
        if (access(cand[i], X_OK) == 0)
            return cand[i];
    }
    LOG_WARNF("未找到常见路径下的 curl，回落 PATH 查找（PATH 可写时存在被替换风险）");
    return "curl";
}

int cnip_load_url(struct split_bpf_ctx *ctx, const char *url,
                  const char *tmp_path, int family)
{
    pid_t pid;
    int st = 0;

    /* v1.2.8（审查修复）：弃用 system()（shell 拼接注入面），改 fork + exec 直接跑
     * curl——参数原样传给 execve，无 shell 解释，URL 中任何元字符（`;` `$()` 反引号等）
     * 都只是 curl 的普通参数。curl 不存在/不可执行时子进程 _exit(127)，由 waitpid 收回
     * 并报错。审查修复（2026-08 全库审查批次）：exec 用绝对路径（见 cnip_find_curl），
     * 消除对可写 PATH 的依赖。 */
    const char *curl_path = cnip_find_curl();
    if (strchr(url, '\'') || strchr(tmp_path, '\'')) {
        LOG_ERRORF("拒绝含单引号的 URL: %s", url);
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        LOG_ERRORF("下载 fork 失败(%s)", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* v1.2.9（审查加固）：exec 前把继承的全部非标准 fd 置 CLOEXEC——
         * 本进程（daemon 派生的 CNIP 更新子进程）持有 BPF map fd、ctl listen、
         * netlink watch 等；curl exec 后若继承它们，会成为"不可控进程持着
         * 系统 fd"的脏现场（curl 短暂运行，危害小但应杜绝）。CLOEXEC 只在
         * exec 时生效，不影响本进程 exec 前/后续灌 CNIP 对 map fd 的使用。 */
        for (int fd = 3; fd < 256; fd++)
            fcntl(fd, F_SETFD, FD_CLOEXEC);
        execl(curl_path, "curl", "-L", "--max-time", "60", "-s",
              "-o", tmp_path, url, (char *)NULL);
        /* 只有 exec 失败才到这里（curl 不存在/不可执行） */
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
    return cnip_from_path(ctx, tmp_path, family);
}

int cnip_apply(struct split_bpf_ctx *ctx, const struct split_config *cfg)
{
    int r4 = 0, r6 = 0;

    /* 未配置任何数据文件：不做任何改动（避免 reload-cnip 在无 path 配置时
     * 把已有 CNIP 全清空——低危但语义误导，清空应只发生在"全量替换"里）。 */
    if (!cfg->cnip4_path[0] && !cfg->cnip6_path[0])
        return 0;

    /* 先清空 v4+v6，保证每次 cnip_apply 都是"全量替换"而非追加，
     * 上游列表收缩时旧前缀不会残留（原追加语义的 bug）。 */
    map_cnip_clear_all(ctx);
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
    int r4, r6;

    if (!cfg->cnip4_url[0] && !cfg->cnip6_url[0])
        return 0; /* 未配置数据源，无可用更新 */

    r4 = cnip_fetch_to_path(ctx, cfg->cnip4_url, cfg->cnip4_path, AF_INET);
    r6 = cnip_fetch_to_path(ctx, cfg->cnip6_url, cfg->cnip6_path, AF_INET6);

    /* 至少一个成功下到本地才落 map；但因 apply 是全量清空重灌，部分失败族
     * 会按"本地旧文件"重写（用旧数据），在此显式点明，避免误以为该族已更新。 */
    if (r4 != 0 && r6 != 0)
        return -1; /* 全部失败返回 -1，让上层下次再试 */
    if (r4 != 0)
        LOG_WARNF("CNIP v4 下载失败，将沿用本地旧文件重灌；v6 已更新");
    if (r6 != 0)
        LOG_WARNF("CNIP v6 下载失败，将沿用本地旧文件重灌；v4 已更新");
    return cnip_apply(ctx, cfg);
}