# userspace/cni — 记忆文档（改本目录代码前必读）

> 覆盖：`cnip.{c,h}`。职责：把 CNIP 数据源灌进 `map_cnip4/6`（LPM_TRIE）。

## 接口契约
- `cnip_load_file(ctx, path, family)`：本地文本 → 灌 map。family = AF_INET / AF_INET6。
- `cnip_load_url(ctx, url, tmp_path, family)`：下载后转交 cnip_load_file。
- `cnip_apply(ctx, cfg)`：按 cfg.cnip4_path/cnip6_path 全量（两族），任一失败 return -1。
- `cnip_auto_update(ctx, cfg)`：有 `url_v4/v6` 时下载到 `<path>.tmp` 再原子 rename 到 `path_v4/v6`，成功后 `cnip_apply`；全失败 return -1，未配 url return 0。**依赖 curl/wget/busybox**（下载器回落见第 3 条）。

## 数据格式（与 fetch-cnip.sh 的输出对齐）
- 每行一条 `A.B.C.D/N` 或 `IPv6/N`；裸 IP 自动补 /32 或 /128；支持 `#` 注释与空行。
- 行尾处理：`\n`/`\r`/尾随空白统一清除（cnip.c 逐字符 trim）——**CRLF 文件已兼容**，
  fetch-cnip 输出为 LF。

## 关键决策与坑
1. **幂等=全量替换（v1.0.5 修复）**：`cnip_apply` 会先调 `loader.map_cnip_clear`（或别名 `map_cnip_clear_all`）清空 v4+v6 再灌。此前是"追加"语义（`BPF_ANY` update，重复 reload 不退旧段），上游列表收缩时旧前缀残留 → 误判直连。daemon 的 `reload-cnip` 与定时刷新都走此"先清空再全量"路径。
   **v1.4.1 新增调用方 `update-cnip`（手动更新）**：daemon ctl 命令，复用 `cnip_auto_update` 的
   "下载 url→原子落盘→cnip_apply"路径（下载在 fork 子进程后台执行，ctl 立即回"已安排"），
   与定时/补拉/`reload-cnip` 共享 `g_cnip_busy` 并发闸——详见 daemon/MEMORY.md。
   **v1.1.3 补漏：双 path 皆空时 `cnip_apply` 直接 return 0 不动 map**——否则 `reload-cnip`
   在未配置 path 的设备上会把已有 CNIP 全清空（低危但语义误导，清空只应发生在"全量替换"里）。
   **v1.1.9：仅配置单族 path 时显式 `LOG_WARNF` 点明另一族将被清空**——"全量替换"契约
   语义下单族配置会让未配置族清零，配置不完整时不再静默。
2. **清 map 的实现注意**：`map_cnip_clear` 走 loader 的 `map_clear_by_keys`，用"反复取首键（key=NULL）+ delete"直到 `-ENOENT`；**不能沿用前一个键继续迭代**——被删键在 LPM_TRIE 里已不存在，`get_next_key` 会提前 -ENOENT（见 loader/MEMORY.md）。
3. **无网络库**：`cnip_load_url` 用 `fork + exec`（**v1.2.8 由 `system()` 改造**——
   参数原样传给 execve 无 shell 解释，URL 中 `;`/`$()`/反引号等元字符不再有注入面；下载器缺失时
   子进程 _exit(127) 由 waitpid 收回报错。安卓上**未必有 curl**（Magisk 环境一般不装）——
   **2026-08 审查批次改为 `cnip_find_downloader()`**：先探测 curl 常见绝对路径，再回落
   wget/busybox 常见绝对路径，最后 PATH 查找（curl → wget → busybox），**全缺失返回 NULL 由
   调用方明确报错**（不再 exec 后 exit 127 的模糊失败）。curl 用 `-f`（HTTP>=400 失败）+
   `-L --max-time 60 -s -o`；wget/busybox 用 `-q -T 60 -O`。**在 fork 前（父进程）调用一次**，
   子进程继承结果 `execl`；残余 TOCTOU 可忽略（能写 /usr/bin 等位置者本已控设备）。
   **下载内容校验**：exec 成功后解析并校验 `ok>0`，0 条有效 CIDR 视为失败弃用——否则 curl 缺
   `-f` 时 404/502 错误页会以 0 退出码被当成成功、rename 覆盖好文件、cnip_apply 全量清空重灌
   0 条（CNIP 静默归零、直连分流失效的根因）。
   **v1.2.9（审查加固）：exec curl 前对继承的全部非标准 fd 置 `FD_CLOEXEC`**——本进程（daemon
   派生的 CNIP 更新子进程）持有 BPF map fd / ctl listen / netlink watch，curl exec 后继承即脏现场。
   循环 `for (fd=3; fd<256; fd++) fcntl(fd, F_SETFD, FD_CLOEXEC)`（对不存在的 fd F_SETFD 返回 -1 无害；
   CLOEXEC 只在 exec 时生效，不影响 exec 后本进程继续灌 CNIP 用 map fd）。
4. 行缓冲 `char line[256]`、`one[256]`（v1.1.6 加大）：CNIP 行远小于 256，超 255 字节畸形行
   （`snprintf` 返回所需长度 ≥ 缓冲）整行放弃并按 bad 计数，**不写被截断的 cidr**，
   避免截断导致误分流。旧 `line[128]/one[64]` 会让超长行静默截断成坏 cidr。
5. `cnip_apply` 对 `r4||r6` 返回 -1：任一失败整体报错；daemon 仅做日志不退出。
6. **部分失败语义（审查加固 + CNIP 更新失败修复）**：`cnip_auto_update` 先显式区分
   "配置族"（`url` 与 `path` 都非空）——**只有配置族才参与成败判定**，未配置族既不是成功
   也不是失败（旧实现把 `cnip_fetch_to_path` 对空 url/path 的 no-op 返回 0 当成功，导致
   单族配置时该族下载失败不 return -1：不重试、失败被静默吞掉、还误报未配置族失败）。
   全部**配置族**失败才 return -1（下次再试）；至少一族成功则落 map，失败族因 `cnip_apply`
   是"全量清空重灌"，会按本地旧文件重写（沿用旧数据），已对失败族显式 `LOG_WARNF` 点明。
6. map 容量 65536：CNIP 全量约 3900 条 v4（chnroutes2 聚合，2026-08 起默认源）+ 约 1200 条
   v6（gaoyifan），余量足。若未来换非聚合源或加全量 v6 需留意不超过 65536。

## 验证
- fetch-cnip 下载后 daemon 启动/`reload-cnip`；统计 `direct_cn` 增长即为生效。
- 格式回归：`cnip_load_file` 单测见 tests/unit（骨架）。