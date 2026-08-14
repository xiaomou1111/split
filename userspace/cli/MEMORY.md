# userspace/cli — 记忆文档（改本目录代码前必读）

> 覆盖：`cli/splitctl.c`。二进制 `splitctl`；与 daemon 经 unix socket 通信。

## 命令集（usage 即契约）
- `start [-c cfg] [-s splitd路径] [-b bpfobj] [-d]`：fork+exec 派生 splitd。**v1.0.5 新增 `-b`**：Android 上
  默认 `SPLIT_BPF_OBJ_DEFAULT=/etc/split/split.bpf.o` 不存在，WebUI/脚本启动必须显式传
  `-b /data/adb/split/bin/split.bpf.o`（webuiapi.sh 已带）。**v1.1.9：`-d`（零参）从"splitd 路径"
  改为 debug，路径改由 `-s` 指定**——与 daemon 的 `-d` 语义对齐；splitctl 收到 `-d` 会把它转发给
  派生 splitd（`splitd -d` 即 debug）。无脚本依赖旧 `-d=路径`（grep 已核实）。
- `stop` / `status` / `stats` / `reload` / `reload-cnip` / `update-cnip`：经 socket 单命令发送。
  `update-cnip`（v1.4.1）：手动触发 CNIP 更新（daemon 走"下载 url_v4/v6 + 重灌"后台路径，ctl 立即回
  "已安排"，进度看 splitd.log）——区别于 `reload-cnip`（只重读本地文件）。
- `list-rules`（v1.2.2）：经 socket 发送，逐行输出当前在线规则（`proxy <cidr>` / `direct <cidr>`，map 实况）——WebUI 规则列表展示/删除用。
- `add-rule <cidr> [proxy|direct]` / `del-rule <cidr> [proxy|direct]`：经 socket 发送到 daemon（v1.0.1 已实现）。
- `validate -c cfg`：本地 `config_load` + `config_dump`，不碰 daemon。

## 关键实现与坑
1. **getopt 公共参数解析在子命令之前**：`-c/-s/-b/-d` 对 start/validate 生效；`optind` 之后才是子命令。
   **v1.1.9 语义统一**：`-s` = splitd 可执行路径，`-d` = debug（转发给派生 splitd）——两二进制 `-d` 语义一致，
   消除了旧版"`-d` 在 splitctl 是路径、在 daemon 是 debug"的歧义。
2. `send_cmd`：写命令后 `read` 到 EOF 才返回——**依赖 daemon 的单命令即断协议**（daemon.c:132）。若 daemon 改为长连接，这里会阻塞到超时。
   **v1.2.8（审查修复）：读回复加 10s poll 超时**——此前 `read` 无限阻塞，daemon 若卡在长
   `ctl_serve`（netlink 扫描异常拖满超时）splitctl 会永久挂死。正常回复远小于 10s。
   **v1.4.6（审查 P2）：ERR 映射非零退出码**——`send_cmd` 检查回复首行前缀，`ERR` → 返回 1
   （正文仍打到 stdout）。此前 daemon 回 `ERR`（规则非法/非 root/未配源）时退出码恒 0，
   `webuiapi.sh run()` 与脚本 `$?` 把失败当成功。依赖 daemon"回复首行 OK/ERR"契约，
   改 daemon 回复格式时必须同步这里。
   **v1.1.4：发送必须带 `'\n'` 终止符**——daemon 命令读取已改为"换行终止循环读"（SOCK_STREAM 不保消息边界），
   不带 '\n' 会让 daemon 等满 5s 超时回 `ERR 命令超时`，命令全部失效。命令长度上限因此为 510 字节（`"cmd\n"` ≤ 511）。
3. `cmd_start`：`fork` + `execv`，**不 setsid/不 daemonize**（子进程继承终端，close stdin 到 /dev/null）。
   **v1.1.4：stdout/stderr 重定向到 `/var/log/splitd.log`（O_APPEND）**——此前丢 /dev/null，
   splitctl start 派生的 splitd 排障无日志可查；打不开日志文件时回退 /dev/null。
   **v1.1.9：日志路径收敛到 `split_log_path()`**（`$SPLIT_LOG` 覆盖，默认 `/var/log/splitd.log`），
   不再 hardcode 在 splitctl 里。
   **v1.1.8：启动失败检测补齐**——exec 后父进程 `waitpid(WNOHANG)` 轮询最长 1s：execv 失败
   （路径不存在/不可执行）子进程 `_exit(127)` 即刻被收回并报错返回非 0；splitd 因配置/权限
   立即退出也会如实报告（此前一律打印"已启动"，静默失败难排查）。已知缺口只剩：无 pid 文件
   （`pgrep splitd` 兜底）。
4. socket 路径、`/etc/split/split.yaml`、`/usr/local/bin/splitd` 默认值与 daemon.h/daemon.c 的默认值**必须一致**（目前硬编码三处）。

## 验证
- Linux 冒烟：`splitctl start` → `splitctl status/stats` → `splitctl stop`；`splitctl validate -c configs/split.yaml`。