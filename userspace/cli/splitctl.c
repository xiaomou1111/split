/* SPDX-License-Identifier: GPL-2.0
 * splitctl.c — 命令行控制工具
 *
 * 与 splitd 通过 unix socket 通信（status/stats/reload/reload-cnip/stop），
 * 或直接派生 splitd（start/stop 由 daemon socket 的 stop 完成）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>  /* waitpid（start 的 execv 失败检测） */
#include <fcntl.h>
#include <errno.h>
#include <limits.h>   /* PATH_MAX（停止闸路径） */
#include <poll.h>     /* send_cmd 读回复超时（v1.2.8） */

#include "../../kernel/include/split_bpf.h"
#include "../common/config.h"
#include "../common/paths.h"

/* ---------- watchdog 停止闸（v1.1.7） ----------
 *
 * 背景：android/scripts/split-watchdog.sh 探活到 splitd 死亡会按同参数拉起。
 * 为防"用户刚 stop 又被拉起"，watchdog 检查 run/splitd.disabled 停止闸——
 * 显式停止路径必须先 touch 它。此前只有 stop-split.sh / WebUI stop 会 touch，
 * 直接 `splitctl stop` 会绕过闸：watchdog（仍存活时）15s 后把 splitd 拉活。
 * 此处把闸放进 splitctl 本身作为唯一收敛点（所有脚本的 stop/start 都经
 * splitctl），任意 stop 路径都生效；start 对称清闸。
 */
static const char *gate_path(void)
{
    /* tmp 最长 PATH_MAX-1，再加 "/splitd.disabled"(16) 可能超 PATH_MAX——按
     * -Wformat-truncation 提示留足余量（GCC15 对 snprintf 截断按 Werror 拒编）。 */
    static char buf[PATH_MAX + 64];
    char tmp[PATH_MAX];
    const char *sock = split_socket_path();
    char *slash;

    snprintf(tmp, sizeof(tmp), "%s", sock);
    slash = strrchr(tmp, '/');
    if (slash) {
        *slash = '\0';
        snprintf(buf, sizeof(buf), "%s/splitd.disabled", tmp);
    } else {
        snprintf(buf, sizeof(buf), "splitd.disabled");
    }
    return buf;
}

/* splitctl stop：置停止闸（watchdog 见之不再拉起）。文件留底不删——
 * 与 daemon 单实例锁文件的"不删除"约定一致，避免 touch/unlink 竞态。 */
static void gate_set(void)
{
    int fd = open(gate_path(), O_CREAT | O_WRONLY, 0600);

    if (fd >= 0)
        close(fd);
}

/* splitctl start：清停止闸（启动后 watchdog 应恢复守护）。 */
static void gate_clear(void)
{
    unlink(gate_path());
}

static int ctl_connect(void)
{
    struct sockaddr_un sa;
    const char *path = split_socket_path();
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_cmd(const char *cmd)
{
    char buf[512];
    char send[512];
    int fd = ctl_connect();
    ssize_t n;
    size_t len;
    ssize_t off = 0;

    if (fd < 0) {
        fprintf(stderr, "splitd 未运行（%s）\n", split_socket_path());
        return 1;
    }
    /* v1.1.4：daemon 以 '\n' 为命令结束符循环读取（SOCK_STREAM 不保消息边界），
     * 发送必须带换行终止，否则 daemon 会一直等 '\n' 直到 5s 超时回 ERR。 */
    len = (size_t)snprintf(send, sizeof(send), "%s\n", cmd);
    if (len >= sizeof(send)) {
        fprintf(stderr, "命令过长\n");
        close(fd);
        return 1;
    }
    /* 循环写防部分写入（与 daemon ctl_reply 同策略） */
    while (off < (ssize_t)len) {
        n = write(fd, send + off, len - (size_t)off);
        if (n <= 0) {
            fprintf(stderr, "发送命令失败（%s）\n", strerror(errno));
            close(fd);
            return 1;
        }
        off += n;
    }

    /* v1.2.8（审查修复）：读回复加整体超时（10s）——此前 read 阻塞到 EOF，
     * daemon 若卡在长 ctl_serve（如 netlink 扫描异常拖满超时）splitctl 会无限
     * 挂死。daemon 单命令即断协议，正常回复远小于 10s。 */
    for (;;) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int pr = poll(&p, 1, 10000);

        if (pr <= 0) {
            fprintf(stderr, "等待回复超时（daemon 无响应，可能正忙于 netlink）\n");
            close(fd);
            return 1;
        }
        n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            fputs(buf, stdout);
            continue;
        }
        if (n < 0) {
            fprintf(stderr, "读取回复失败（%s）\n", strerror(errno));
            close(fd);
            return 1;
        }
        break; /* EOF：daemon 已回复完毕并关闭连接 */
    }
    close(fd);
    return 0;
}

static int cmd_start(const char *cfg, const char *splitd, const char *bpf_obj,
                     int debug)
{
    char *argv[8];
    pid_t pid;
    int n = 0;

    /* 简单方式：fork+exec */
    pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        int nullfd = open("/dev/null", O_RDWR);
        int logfd;

        if (nullfd >= 0)
            dup2(nullfd, 0);   /* stdin：守护进程不应读终端 */
        /* stdout/stderr 落日志文件而非 /dev/null（v1.1.4 审查加固）：
         * splitctl start 派生的 splitd 排障要有日志可查。Android 上由
         * service.sh 直接启动（logs/splitd.log），不走本路径。 */
        logfd = open(split_log_path(), O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (logfd < 0)
            logfd = nullfd;    /* 打不开日志文件则退回 /dev/null */
        if (logfd >= 0) {
            dup2(logfd, 1);
            dup2(logfd, 2);
        }
        argv[n++] = (char *)splitd;
        argv[n++] = "-c";
        argv[n++] = (char *)cfg;
        if (bpf_obj && bpf_obj[0]) {
            argv[n++] = "-b";
            argv[n++] = (char *)bpf_obj;
        }
        if (debug)
            argv[n++] = "-d";   /* v1.1.9：-d 转给派生 splitd（daemon 的 -d 即 debug） */
        argv[n] = NULL;
        execv(splitd, argv);
        _exit(127);
    }
    /* v1.1.8：启动失败检测（消除"execv 失败静默"已知缺口，cli/MEMORY 坑 3）。
     * exec 失败时子进程 _exit(127)，父进程在短窗口内 waitpid(WNOHANG) 收回即可
     * 报错；splitd 正常运行则窗口耗尽按启动成功处理。对早期因配置/权限立即退出的
     * 情况也能如实报告（此前一律打印"已启动"）。 */
    {
        int tries;
        int st = 0;

        for (tries = 0; tries < 20; tries++) {
            pid_t r = waitpid(pid, &st, WNOHANG);

            if (r == pid) {
                if (WIFEXITED(st) && WEXITSTATUS(st) == 127) {
                    fprintf(stderr, "启动失败：无法执行 %s（路径不存在或不可执行）\n",
                            splitd);
                } else {
                    fprintf(stderr, "splitd 立即退出（status=%d）\n",
                            WIFEXITED(st) ? WEXITSTATUS(st) : -1);
                }
                return 1;
            }
            usleep(50000); /* 50ms × 20 = 1s 等待窗口，慢设备也够 */
        }
    }
    printf("splitd 已启动 (pid=%d)\n", pid);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "用法: %s <command> [args]\n"
        "  start  [-c cfg] [-s path] [-b bpfobj] [-d]   启动 splitd\n"
        "  stop                        停止（经 daemon）\n"
        "  status                      状态\n"
        "  stats                       内核计数\n"
        "  list-rules                  当前在线规则（proxy/direct，v1.2.2）\n"
        "  reload                      重读配置并应用\n"
        "  reload-cnip                 只刷新 CNIP\n"
        "  add-rule  <cidr> [direct|proxy]\n"
        "  del-rule  <cidr> [direct|proxy]\n"
        "  validate -c cfg             仅校验配置\n", prog);
}

/* 组装 ctl 命令；超长参数显式拒绝（截断会让 daemon 解析到半截规则） */
static int build_cmd(char *cmd, size_t cap, const char *prefix,
                     const char *a1, const char *a2)
{
    int need = snprintf(cmd, cap, "%s %s", prefix, a1);

    if (need < 0 || (size_t)need >= cap)
        return -1;
    if (a2) {
        int need2 = snprintf(cmd + need, cap - (size_t)need, " %s", a2);

        if (need2 < 0 || (size_t)need2 >= cap - (size_t)need)
            return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *cfg = "/etc/split/split.yaml";
    const char *splitd = "/usr/local/bin/splitd";
    const char *bpf_obj = NULL;
    int opt, debug = 0;

    /* 统一解析公共参数（v1.1.9：-s 指定 splitd 路径，-d 保留为 debug 并转给派生 splitd，
     * 与 daemon 的 -d 语义对齐，消除此前"-d 在 splitctl 是路径、在 daemon 是 debug"的歧义） */
    while ((opt = getopt(argc, argv, "c:s:b:d")) != -1) {
        switch (opt) {
        case 'c': cfg = optarg; break;
        case 's': splitd = optarg; break;
        case 'b': bpf_obj = optarg; break;
        case 'd': debug = 1; break;
        default: break;
        }
    }
    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[optind], "start") == 0) {
        gate_clear();   /* v1.1.7：直接 splitctl start 也要清停止闸，否则 watchdog 持续停摆 */
        return cmd_start(cfg, splitd, bpf_obj, debug);
    }
    if (strcmp(argv[optind], "stop") == 0) {
        gate_set();     /* v1.1.7：停止闸收敛到 splitctl 本身——直接 stop 不再绕过 watchdog */
        return send_cmd("stop");
    }
    if (strcmp(argv[optind], "status") == 0)
        return send_cmd("status");
    if (strcmp(argv[optind], "stats") == 0)
        return send_cmd("stats");
    if (strcmp(argv[optind], "list-rules") == 0)
        return send_cmd("list-rules");
    if (strcmp(argv[optind], "reload") == 0)
        return send_cmd("reload");
    if (strcmp(argv[optind], "reload-cnip") == 0)
        return send_cmd("reload-cnip");
    if (strcmp(argv[optind], "add-rule") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "add-rule <cidr> [proxy|direct]\n");
            return 1;
        }
        char cmd[512];
        const char *which = NULL;

        if (optind + 2 < argc) {
            if (strcmp(argv[optind + 2], "proxy") == 0 || strcmp(argv[optind + 2], "direct") == 0) {
                which = argv[optind + 2];
            } else {
                fprintf(stderr, "add-rule: which 只能是 proxy 或 direct（收到 %s）\n", argv[optind + 2]);
                return 1;
            }
        }
        if (build_cmd(cmd, sizeof(cmd), "add-rule", argv[optind + 1], which) < 0) {
            fprintf(stderr, "add-rule: 参数过长\n");
            return 1;
        }
        return send_cmd(cmd);
    }
    if (strcmp(argv[optind], "del-rule") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "del-rule <cidr> [proxy|direct]\n");
            return 1;
        }
        char cmd[512];
        const char *which = NULL;

        if (optind + 2 < argc) {
            if (strcmp(argv[optind + 2], "proxy") == 0 || strcmp(argv[optind + 2], "direct") == 0) {
                which = argv[optind + 2];
            } else {
                fprintf(stderr, "del-rule: which 只能是 proxy 或 direct（收到 %s）\n", argv[optind + 2]);
                return 1;
            }
        }
        if (build_cmd(cmd, sizeof(cmd), "del-rule", argv[optind + 1], which) < 0) {
            fprintf(stderr, "del-rule: 参数过长\n");
            return 1;
        }
        return send_cmd(cmd);
    }
    if (strcmp(argv[optind], "validate") == 0) {
        struct split_config cfg2;
        if (config_load(cfg, &cfg2) == 0) {
            printf("配置合法\n");
            config_dump(&cfg2);
            return 0;
        }
        return 1;
    }
    usage(argv[0]);
    return 1;
}