# userspace/daemon — 记忆文档（改本目录代码前必读）

> 覆盖：`daemon.{c,h}`。`main()` 在 daemon.c（splitd 二进制入口）。`daemon.h` 定义 `SPLIT_BPF_OBJ_DEFAULT="/etc/split/split.bpf.o"`。

## 生命周期（顺序即契约，改时序=改行为）
1. 解析参数 `-c cfg -b obj -d` → `config_load`（失败 exit 1）。
1.5. **单实例锁（v1.1.4）**：config_load 后对 `<socket路径>.lock`（如 /run/splitd.sock.lock）
   做 `flock(LOCK_EX|LOCK_NB)`（`instance_lock`，daemon.c）。**被占用 → exit 4**（已有 splitd
   在运行，拒绝启动——防止二次 `splitctl start` 时新 daemon unlink 旧 socket 让原实例失联、
   双 daemon 同时加载 BPF/挂 tc 互相踩踏）；锁文件不可用（只读目录等）→ 降级无锁运行。
   锁文件不删除（进程退出/fd 关闭自动释放，删除反而有竞态）。**service.sh 用 `splitctl
   status` 检测存活、不依赖 exit code**（改 exit code 须同步 android 脚本，见下文 exit(2) 条）。
2. `split_load`（失败 exit 2，**直接退出**——没有 eBPF 的 splitd 无意义，不是降级；mihomo 若
   `auto-route:false`（本项目推荐配置）则无兜底，由 `android/magisk/service.sh` 检测
   `splitctl status` 失败并打日志提示）。
3. `iface_resolve_tun(tun_device)`（默认 `utun`）；**<=0 → exit 3**（mihomo 必须先启动）。
4. `map_set_tun`（失败仅 warn 不退出，后续由 tun_sync 兜底）→ `rule_apply_all` → `cnip_apply`（仅配置了路径时）。
5. `iface_reconcile`（首次挂载）。
6. `ctl_listen`（unix socket）+ `iface_watch_open`（netlink）→ poll 循环（超时自适应到最近定时器，上限 2s，见"主循环调度"节）。
7. **CNIP 定时自动更新（v1.0.6 fork 化）**：`cnip_auto_update_hours>0`（默认 24=每天）且到
   `cnip_next_ms` 时 **fork 子进程**执行 `cnip_auto_update`（下载 url→覆盖本地文件→全量重灌 map；
   子进程继承 map fd，直接灌入），父进程 `waitpid(WNOHANG)` 回收不阻塞 poll 主循环。
   成功→按原间隔续期；失败→5 分钟后再试（fork 失败→1 分钟）。
8. **tun 存活同步（v1.0.6）**：`tun_sync` 负责让 map_tun 与 tun_device 实际 ifindex 对齐。
   **v1.2.1 起三个调用点**（原只有心跳）：netlink 接口事件（复用快照，立即对齐）、reload
   命令（重读配置后立即对齐）、poll 循环末 1s 节流无条件兜底（v1.1.2 起不依赖 poll 超时/
   事件，弱网加固）——详见下方专节。
9. SIGINT/SIGTERM → `g_stop` → `split_unload`（含 detach_all）→ 清理 socket 文件。

## 控制协议（与 cli 的硬契约，改必同步 splitctl.c）
- Unix stream socket，路径 `split_socket_path()`（优先 `$SPLIT_SOCKET`，默认 `/run/splitd.sock`；Android 需 `export SPLIT_SOCKET=/data/adb/split/run/splitd.sock`，见 userspace/common/paths.c）。
- **单命令一连接**：accept 后只 `ctl_serve` 一次，回复完 return 0 即 close（`daemon.c`）——这是为了避开"客户端读 EOF 与服务器等待 EOF 的死锁"，**不要改回多命令循环**。
- **读命令前先 `poll(c, POLLIN, 1500)`（v1.0.6；**v1.2.0（H1）收紧 5s→1.5s**）**：客户端挂住不发数据时 1.5s 超时断开，避免阻塞读卡死整个 daemon 主循环（poll 还负责网络事件/CNIP fork 回收）。
  **H1 背景**：`ctl_serve` 是主循环同步调用，过长 read 会顺延 1s tun_sync / 5s reconcile / CNIP fork 调度，放大 mihomo 重建 utun 时 map_tun stale 的静默丢包窗口。1.5s 是"够收完正常命令"与"不拖心跳"的折中。
- **命令读取（v1.1.4 改为"换行终止循环读"）**：`SOCK_STREAM` 不保消息边界，命令可能被拆成多次 `read` 到达。
   现以 `'\n'` 为结束符循环读取（整体 1.5s 超时，`now_ms` 单调时钟；v1.2.0 由 5s 收紧，见上），收齐换行或缓冲满（`cmd[511]`）停止；
   命令协议不变（单命令一连接、回复后 close）。v1.0.6 起的"poll 一次 + read 一次"实现只对单次小 write 有效，
   勿回退。**发送方必须带 `'\n'` 终止**（splitctl send_cmd 已同步；协议契约，新增发送方必看）。
   **v1.1.6 加固：缓冲满仍未收到 '\n'（`truncated`）→ 直接回 `ERR 命令过长\nEND` 并 return**，不再按截断串解析——避免"收到半截规则"的歧义。
- 命令：`stats` / `status` / `reload-cnip` / **`update-cnip`（v1.4.1）** / `reload` / `add-rule <cidr> [proxy|direct]` / `del-rule <cidr> [proxy|direct]` / `stop` / **`list-rules`（v1.2.2）**；未知 → `ERR 未知命令`。
- **`reload-cnip`（v1.4.1 起后台执行；v1.1.6 起防并发双写）**：只重读本地文件全量重灌
  （`cnip_apply`，"清空→写入"）。**v1.4.1（G1 统一调度）**：与 `update-cnip`/定时更新
  一样走 fork 子进程——ctl 分支校验（`g_cnip_busy` 忙拒绝 / 无 path 直接 OK）后置
  `g_cnip_req=CNIP_REQ_RELOAD` + 提前 `cnip_next_ms`，主循环下一轮 fork 子进程跑
  `cnip_apply`，ctl 立即回 `OK 已安排 CNIP 重灌`。**不再主线程同步重灌**（~6.5 万条 LPM
  写入数秒，会阻塞 poll 主循环）。成功与否看 splitd.log / status 的 cnip4/6 计数。
  忙标志在 fork 前置 1、fork 失败/waitpid 回收后清 0。`reload` 不写 CNIP map
  （只重放 rule/uid 与接口），无需此闸。
  **v1.2.0（H2）显式化不变式**：CNIP map 的写入方只有 fork 子进程一个（定时/补拉/
  update-cnip/reload-cnip 四触发源共用），`g_cnip_busy` 保证互斥；若未来给 `reload`
  增加 CNIP 重灌，必须同步加 `g_cnip_busy` 检查，否则破坏该单写方不变式。
- **`update-cnip`（v1.4.1，手动更新 CNIP）**：触发一次与定时自动更新相同的
  "下载 url_v4/v6 → 原子落盘 → 全量重灌"（`cnip_auto_update`），**不阻塞主线程**——
  ctl 分支校验（`g_cnip_busy` 忙拒绝 / 无 url 拒绝）后只置 `g_cnip_req=CNIP_REQ_UPDATE` +
  把 `cnip_next_ms` 提前到 now，主循环下一轮 poll 迭代走 fork 子进程路径（**fire 成功才清
  `g_cnip_req`，F4——fork 失败保留请求，60s 后按原类型重试**）。**手动更新失败不自动重试**（与 boot_once"成功才清零、失败 5 分钟
  再试"不同——用户可再点）；cnip_next_ms 在成功分支被重设为"now+hours"，hours=0 时因
  条件 `hours>0||boot_once||g_cnip_req!=NONE` 全 false 不会重复 fire。改调度条件时四个
  触发源（定时/补拉/update-cnip/reload-cnip）必须一起维护。
- **`status`（v1.1.3 扩展 / v1.2.7 补 tun 缺失 WARN / v1.2.8 hijack 改缓存）**：`OK prog_fd=<n> attached=<n> tun=<ifindex> cnip4=<n> cnip6=<n> hijack=<0|1|-1>`；
  随后可能跟 `WARN ...` 行（CNIP 0 条未导入 / 路由被 mihomo auto-route 接管 / **tun 缺失
  （map_tun=0，v1.2.7 审查 H2：代理流量被放行直连的静默降级要可见）**）——机器可解析，
  人类一眼看出"分流是否真的生效"。WebUI app.js 解析这些字段（改格式必须同步 app.js）。
  **v1.2.8（审查修复）**：`hijack` 字段改读主循环节流缓存的 `g_hijack_now`（含 -1=检测
  失败）——此前 `ctl_status` 在 ctl 路径同步重跑 `route_tun_hijacked`（2~4 次 netlink dump、
  最坏 4×2s），阻塞主循环的 ctl/网络事件/CNIP 调度。现 status 至多 30s（P2：10s→30s）
  陈旧，不再阻塞。
- **`list-rules`（v1.2.2 新增，WebUI 规则列表）**：枚举 proxy/direct 四个规则 map（LPM_TRIE），逐行回 `proxy <cidr>` / `direct <cidr>`（v4 在前、v6 在后）；先 `OK` 后数据行再 `END`，无规则则只有 OK/END 两行。实现走 loader 的 `map_rule_foreach`（prev-key 顺序迭代，不删键）。**展示的是 map 实况**（配置基线 + 运行时 add-rule/del-rule 的结果），改输出格式必须同步 app.js 的 loadRules。
- **`reload`（v1.0.6 起）是"重读配置文件再全量应用"**：`config_load(cfg_path)` 成功后把结果写回
  daemon 的活配置（`cnip_next_ms` 只提前不推后地按新 `cnip_auto_update_hours` 校准——F3，防覆盖
  挂起的补拉/重试，见"主循环调度"节；`debug:true` 同步日志级别，
  **v1.2.8：`debug:false` 也恢复 INFO——旧实现只升不降**），
  失败则**沿用内存配置继续重放规则**（记 ERROR 不丢现有规则）。随后 `rule_apply_all` +
   `rule_overrides_replay`（**v1.2.0，见下**）+ `iface_reconcile`。此前（≤1.0.5）reload 只重放内存 cfg，不读文件——改前必看。
   **v1.2.1 追加：`iface_reconcile` 后调 `tun_sync(ctx,cfg,NULL)` 立即对齐 map_tun**（reload 重读
   配置后 tun_device 可能变化，且常伴随 mihomo 重建 utun，若只靠 1s 心跳会有 stale 丢包窗口）。
- **运行时规则偏差（v1.2.0，H1）**：reload 的 `rule_apply_all` 会先 `map_rule_clear` 清掉全部
  rule map，故在此之后必须 `rule_overrides_replay(ctx, &rov)` 重放 CLI `add-rule/del-rule` 记录
  的运行时偏差，否则在线增删的规则在 reload 后丢失。`rov` 在 daemon_loop 初始化、随 ctl_serve
  的 add-rule/del-rule 更新（**先写 map、成功后再记录**，失败不记录防幻影覆盖）。上限
  `RULE_OVERRIDE_MAX=64`；追踪满时 add/del 仍立即生效但**不跨 reload**，ctl 回 ERR 如实告知。
  跨 reload 保留、daemon 重启即丢（不落盘，见 USAGE.md）。
- **`stop` 与 watchdog 停止闸（v1.1.7）**：daemon 的 `stop` 命令本身只置 `g_stop` 退出；
  **停止闸（`<run>/splitd.disabled`，防 watchdog 拉起）由 splitctl 侧负责**——`splitctl
  stop` 先 `touch` 再发命令、`splitctl start` 对称 `unlink`（详见 cli/splitctl.c
  `gate_set/gate_clear`）。daemon 不碰闸文件。改 stop 语义时闸的读写仍归 cli，勿移到 daemon。
- **读命令后先 trim 尾部换行/空格（v1.0.5）**：`read` 进 `cmd[512]`（v1.1.3 由 128 扩大，
  防长 cidr 被截断成半截规则）可能带 `\n`/`\r`/空白，
  直接 `strncmp` 会让 `add-rule ... proxy\n` 的 `which_str` 比较失败回 `ERR which 只能是 proxy 或 direct`。
  `cmd[n]='\0'` 后必须循环去掉尾部空白（daemon.c `ctl_serve` 开头）。
- **命令整词匹配（v1.1.4 加固）**：用 `cmd_is()`（前缀 + 下一字符必须是空白/结尾）——
  此前 `strncmp(cmd,"stop",4)` 让 `stopx`/`stop anything` 误触发 stop；`reload-cnip` 判断在
  `reload` 之前，次序保持。命令集不变（usage 即契约）。
- **权限（v1.0.5）：`ctl_serve` 先用 `SO_PEERCRED` 校验 peer uid==0，非 root 直接回 `ERR 仅 root 可控制 splitd`**。splitd 以 root 运行，防止任意本地用户 stop/改规则。Magisk 脚本以 root 调用 splitctl 不受影响；若需让普通 uid 控制，须显式改此校验。
  **v1.1.4：`ctl_listen` bind 后 `chmod(path, 0600)`**——非 root 直接连不上（此前依赖 umask，可能 755）；
  SO_PEERCRED 是第二道闸，两层都别删。
- 回复格式：首行 `OK/ERR ...`，数据行，末行 `END`（stop 也回 `OK` + `END`）。`ctl_reply` 每次自动追加 `\n`。
  **v1.1.8（审查加固）：所有分支统一写成 `ctl_reply("正文"); ctl_reply("END");` 两步收尾**——不再有
  内嵌 `\nEND` 的手写 fmt（此前 reload/reload-cnip/add-rule/del-rule/stop 等分支写法不一）。
  **新增命令分支一律照此两行写，勿再拼 `"\nEND"`。
  **`ctl_reply` 循环 write 防部分写入（v1.1.3 加固）**：unix stream 对 >PIPE_BUF 的写不保证原子。
  **必须无视 SIGPIPE（审查加固）**：`ctl_reply` 用 `write` 回 socket，客户端在回复期间断开会触发
  SIGPIPE、默认动作直接杀死 splitd（残留 tc filter+map 失守）。启动时 `signal(SIGPIPE, SIG_IGN)`（daemon_loop），
  让 write 返回 EPIPE 走 `w <= 0` 放行路径。**别删，也别改成依赖临时捕获**。
- `ctl_stats` 的名字数组**下标对应 STAT_* 枚举**（**0..9**，v6 未分类直连项 `direct_v6`=9；v1.4.0 随域名统计 dom_proxy/dom_direct 删除后自 11 重排为 9——仅运行时统计 map，无持久 ABI），追加新统计要同时扩展两个数组。
  **v1.1.9：循环上界由 `names[]` 元素数与 `STAT_MAX` 取小**（不再硬编码 10），新增段只加 names 项即可自动扩展。
- **add-rule/del-rule 拆词（v1.1.9）**：改用 `split_two()` 按 space/tab 任意组合拆分 cidr 与
  `which`——旧 `strchr(arg,' ')` 只认空格，`<cidr><TAB>direct` 会让 which 含 tab 前缀比较失败回 ERR。
  `split_two` 容忍多余空白、第二个 token 为空即报用法错误。
- **add-rule/del-rule 运行时追踪（v1.2.0，H1）**：`ctl_serve` 增加 `struct rule_overrides *rov`
  参数（daemon_loop 传入）。add-rule/del-rule 先写 map、成功后再 `rule_override_record` 记录
  偏差（满/非法回 ERR 与说明）；reload 后由 `rule_overrides_replay` 重放——CLI 在线规则跨
  reload 保留。**重启即丢、不落盘**。详见 rule/MEMORY 第 7 条。

## 主循环调度（2026-08 调度审查批次，F1-F4）
> 主循环每轮顺序：CNIP 调度（fork）→ CNIP 回收（waitpid WNOHANG）→ 自适应 poll →
> 事件处理 → 心跳节流（tun 1s~30s 退避 P1 / reconcile 15s P3 / hijack 30s P2）。
> 定时器全部 `now_ms()`（CLOCK_BOOTTIME）节流。
- **F1 自适应 poll 超时**：poll 超时不再固定 2000ms，改为"最近定时器截止时刻 − now"、上限
  2000ms——截止取 tun_sync（`tun_sync_interval`，P1 退避 300ms~30s）、reconcile
  `RECONCILE_MS`=15000（P3）、hijack `HIJACK_CHECK_MS`=30000（P2）、
  cnip_next_ms（**仅当会 fire 且 `cnip_pid==0`** 才纳入：fork 条件门开时才可能 fire，子进程
  运行中纳入会让 poll(0) 空转忙循环）。到期即 poll(0) 立刻返回、由下方节流块执行。
  修掉旧问题：固定 2s poll 把降级 300ms / 1s 心跳在"事件漏收（心跳兜底的目标场景）"下钉死成
  2s 步长，`TUN_SYNC_DEGRADED_MS` 注释承诺的"恢复代理最长等待 ≤300ms"无法成立。
  **改 poll 超时语义时保持"截止=min(各定时器)"，勿回退固定 2000。三个兜底心跳的截止
  必须与其节流条件同源（RECONCILE_MS / HIJACK_CHECK_MS / tun_sync_interval），
  否则 poll 提前空醒或把心跳延迟到截止——v1.0.6 旧病。**
- **F2 netlink recv 超时 2s → 300ms**（netlink.c，route_tun_hijacked + iface_scan 两处）：
  两者都是主循环同步 dump（正常 <1ms）。旧 2s `SO_RCVTIMEO` 在 netlink 异常时最坏停摆
  8s（hijack 4×2s）/ 每轮 2s（iface_scan，每 1s 心跳都调）。300ms 余量充足，异常时停摆压到
  ~1.2s。**"防永久阻塞"意图不变：超时按失败处理，调用方保持 map 原值不误清。**
- **F3 reload 只提前不推后 cnip_next_ms**：reload 重读配置后旧实现把 cnip_next_ms 重置为
  now+hours——若 boot_once 补拉已排期（now+5s）或补拉失败在 5 分钟重试窗口，一次 reload
  会把 CNIP 缺失自愈/重试静默推迟最多 24h。现改为 `if (t < *cnip_next_ms) *cnip_next_ms = t`
  （只提前，永不推后）。**改调度条件时四个触发源（定时/补拉/update-cnip/reload-cnip）一起维护。**
- **F4 fork 失败保留手动请求**：g_cnip_req 清空从"fork 前"移到"fork 成功后"——fork 失败时
  保留 update-cnip / reload-cnip 请求，60s 重试分支仍按原请求类型 fire（否则 hours==0 时
  手动请求被静默吞掉，用户已收到"已安排"却永不执行）。**"一次请求 fire 一次"语义不变**
  （fire 成功即清；子进程继承的副本无意义，_exit 不触碰）。

## 主循环 CPU（2026-08 CPU 审查批次，P1-P3）
> 静态结论：稳态无忙循环（三个心跳都在进入时无条件刷新 last_ms；iface_watch 用
> MSG_DONTWAIT 排空事件到 EAGAIN；poll 有界）。稳态 CPU 已 ~0.02%（主成分：1Hz
> RTM_GETLINK dump + 路由/规则 dump——P2 后由 10s 周期变 30s）。P1 处理唯一
> 持续活跃场景；P2/P3 削周期 dump。
- **P1 降级退避（唯一实质收益）**：utun 长期缺失时（mihomo 未起/崩溃/错名）旧实现以
  300ms（3.3Hz）无限重试——瞬时抖动（mihomo 重载重建）才值得 300ms 快重试，持续缺失是
  耗电/唤醒损耗。现 `tun_sync_interval(fail_cnt)` 按连续失败 300ms→1s→5s→30s 封顶递退，
  任一成功立即回正常 1s。间隔是**心跳节流条件与 F1 poll 截止的唯一来源**（二者同源，
  否则 poll 提前空醒/延迟心跳）。fail_cnt 由 `tun_sync_record(r, &fail_cnt)` 在**全部三处**
  tun_sync 调用点维护（reload 分支 / 事件分支 / 心跳），r<0（netlink 失败）不改状态——
  一次网络抖动不算 utun 缺失。**fail_cnt>0 即"降级中"，替代原 tun_degraded 布尔
  （v1.2.4 的 300ms 收紧语义已并入 stages[0]）。**
- **P2 路由接管检测 10s → HIJACK_CHECK_MS=30s**：route_tun_hijacked 是最重 netlink 单点
  （最多 4 次路由/规则 dump），纯 WARN 诊断 + status 读缓存 g_hijack_now，检测延迟
  10s→30s 可接受，3 倍更少周期 dump。
- **P3 接口挂载自愈 5s → RECONCILE_MS=15s**：仅事件漏收时的兜底（事件路径已即时对齐），
  doze 冻结本身以分钟计，15s 延迟相对可忽略，3 倍更少周期 dump。
- **已否决**：tun_sync 定向 RTM_GETLINK 快路径（省 ~80µs/s，不值新 netlink helper +
  drift 检测正确性风险）；F1 的 2000ms poll 空闲回落上限不动（退避后空闲仍 0.5Hz 空醒，
  属可接受的微损耗，改动引入 SIGCHLD 回收延迟权衡）。

## 网络切换
- `iface_watch_poll>0` → `LOG_INFOF` + `iface_reconcile`（增量对齐挂载）。WiFi↔蜂窝切换走此路径。
  **v1.1.9：事件分支把 `iface_watch_poll` 已填好的快照直接传给把 `iface_reconcile`（快照透传），
  避免 reconcile 再次全量 scan；RECONCILE_MS 心跳（P3：5s→15s）/reload/首次挂载仍传 NULL（自扫一次）。**
- **接口挂载自愈心跳（v1.1.7，P3：5s→15s）**：主循环末尾另加 **RECONCILE_MS=15s 节流**的
  `iface_reconcile` 无条件兜底（`reconcile_last_ms`），与 tun_sync(v1.1.2) 同源思路——netlink
  watch socket 缓冲可能溢出、进程在 doze 期间被冻结错过事件，**原"只在事件时 reconcile"会在
  事件漏收后把 eBPF 永久挂在旧 ifindex**（attached=n 仍显示正常，分流静默失效；真机症状=
  长时间熄屏后无法代理）。此心跳保证事件漏收时最多 15s 内自愈（doze 冻结本身以分钟计，
  15s 兜底延迟可忽略，换取 3 倍更少周期 dump）。幂等（无变化零开销，iface_scan <1ms）。
  **附加核验**：`split_attach_iface` 的幂等去重在 v1.1.7 不再只信 `ctx->attached[]`，而是用
  `bpf_tc_query` 对照内核真实 filter（`split_filter_exists`，loader/MEMORY）——attached[] 是
  内存自认为状态，网卡上 filter 被外部清除（ifindex 不变）时只有这条路径能发现。
  iface_plan 的"待挂接口数"日志已降为 DEBUG，避免每轮刷日志。
- **tun 对齐（v1.1.2 起从事件分支移到心跳；v1.2.1 起事件分支恢复即时对齐）**：v1.1.2 曾统一走
  每轮循环末的 1s 节流心跳（见下节）、事件分支只做 `iface_reconcile` 以避免重复逻辑——但该方案
  让 mihomo 重载配置重建 utun 的 ifindex 漂移要等最多 1s+ 才被 map_tun 吸收，期间有静默丢包窗口。
  **v1.2.1 起事件分支在 `iface_reconcile` 后立即 `tun_sync(&ctx,&cfg,&snap)`（复用已扫快照，
  免额外 scan），心跳保留作事件漏收兜底**——两处逻辑共用同一个 tun_sync 函数，无重复维护。

## tun 存活同步（v1.0.6，map_tun 唯一动态维护方）
- **背景（真机场景）**：mihomo 崩溃被 Android 杀/重启、gso 切换、升级时都会重建 utun，
  ifindex 必然变化。map_tun 残留旧 ifindex 时，`bpf_redirect(旧idx, 0)` 的 helper 本身**恒返回
  `TC_ACT_REDIRECT`**（只是把目标写进 bpf_redirect_info），真正的解析在
  `__skb_do_redirect()`（net/core/dev.c）：`dev_get_by_index_rcu` 失败 → `kfree_skb` **直接丢包**——
  split.bpf.c 的 `!= TC_ACT_REDIRECT` 检查救不回，`STAT_REDIRECT_ERR` 不涨，代理流量静默全挂且无从排查。
- **机制（v1.1.2 重构 / v1.2.1 三触发 / v1.2.4 复核+快重试 / v1.2.5 名字漂移兜底 / v1.2.6 按类型兜底）**：`tun_sync(ctx, cfg[, snap])`
  接受可选快照（非 NULL 复用、NULL 自扫，与 iface_reconcile 同款约定）。触发点：
  - **心跳兜底**：每轮 poll 循环末按 1s 节流无条件执行（`tun_sync_last_ms`），
    **不再依赖 poll 超时（rc==0）**——v1.1.2 起即如此（当时 poll 会因 DNS 学习器 fd 恒可读
    几乎不超时，旧"心跳只在超时分支"的方案兜底形同虚设；v1.4.0 移除学习器后 poll 常规 2s
    超时，但"事件漏收时的静默丢包窗口"依然存在，兜底语义不变）。代价：正常态每秒一次
    rtnetlink 全量 dump（<1ms，可忽略）；降级期按 P1 退避降至最多 30s 一次。
    **v1.2.4 降级快重试 / P1（2026-08）退避**：`tun_sync` 返回 1（map_tun=0 降级中）时，
    心跳间隔收紧（`tun_sync_interval` 由 `tun_fail_cnt` 驱动，300ms→1s→5s→30s 封顶
    递退，见"主循环 CPU"节）——瞬时抖动（重建 utun）恢复代理最长等待 ≤300ms；
    持续缺失（mihomo 未运行）不再无限 3.3Hz 唤醒。fail_cnt>0 即降级中（v1.2.4 的
    `tun_degraded` 布尔已并入，三处调用点统一走 `tun_sync_record`）；正常状态 1s。
  - **网络事件（v1.2.1 新增）**：`iface_watch_poll>0` 分支在 `iface_reconcile` 之后立即
    `tun_sync(ctx, cfg, &snap)` 复用已扫快照对齐 map_tun——mihomo **重载配置文件**重建
    utun（ifindex 漂移）正是走这条路径，原先要等下一轮 1s 心跳才对齐，期间 bpf_redirect
    指向陈旧 ifindex 被 `__skb_do_redirect` 静默丢包（海外全挂、STAT_REDIRECT_ERR 不涨）。
    顺带把 `tun_sync_last_ms = now_ms()` 归位，避免同一轮再触发心跳重复 scan。
    **v1.2.4 快照权威复核（真机修复）**：该快照是"排空 netlink 事件后再扫"的时点快照，
    若恰拍在 mihomo 重建 utun 的 DELLINK/NEWLINK 间隙（utun 已删未建），快照缺 utun
    但 utun 此刻可能已重建——此前直接按快照把 map_tun 置 0，造成"ip link 可见 utun
    但 split 报 tun 不存在、map_tun=0、代理完全失效"的假象。现在 `tun_sync` 在"快照缺
    utun"时强制 `iface_scan` 权威复核，只有复核仍缺才置 0。
  - **reload 命令（v1.2.1 新增）**：`rule_overrides_replay` + `iface_reconcile` 之后
    `tun_sync(ctx, cfg, NULL)` 立即对齐（重读配置后 tun_device 可能变化、mihomo 可能已重建 utun）。
  行为：
  - tun_device 接口不存在 → map_tun 置 0（BPF 侧 `tun_ifindex()==0` → `STAT_MISS_TUN` + `TC_ACT_OK` 放行保联网）；
  - ifindex 漂移 → 重写为新值并打日志；
  - **接口扫描失败（临时 netlink 错误）→ 跳过不动 map_tun**（避免误置 0 造成全量放行）。
  - **返回契约（v1.2.4 / P1 退避）**：0=已对齐/保持有效；1=降级（map_tun=0，utun 缺失）；
    -1=扫描/写 map 失败（未动 map）。调用方（事件/reload/心跳）统一走 `tun_sync_record`：
    `r==1` 递增 `tun_fail_cnt` 驱动降级退避（300ms→30s，见上）；`r<0` 不改变降级状态
    （一次网络抖动不算 utun 缺失）。
   - **名字漂移兜底（v1.2.5/v1.2.6，真机修复 + 源码修正 / v1.2.8 收紧）**：mihomo 重载后新 TUN 可能不再叫配置名。
     v1.2.5 曾假设"sing-tun Linux 自动/回退名是 tunN"，但 **mihomo Alpha 源码核实（listener/sing_tun/
     sing_tun.go）**：`InterfaceName` 默认即 `"Meta"`，`device==""` 时 Linux 回退名是 **"Meta"**（`tunN`
     仅 InterfaceName 为空、`utunN` 仅 darwin），device 非空则用 device 名。精确匹配（含 v1.2.4 复核）
     仍缺时，`tun_find_drift` 找候选自动对齐并打 WARN：候选 = IFF_UP + ifindex > `g_tun_last_good` +
     （TUN 类名字（同前缀+数字 / **直接认 "Meta"，v1.2.6**）或
     **`type==ARPHRD_NONE`（L3 TUN）且非 wg/tailscale，v1.2.6 按类型兜底**）。
     **v1.2.8（审查修正）**：① 移除"配置名以 utun 开头则接受 tunN"的启发式——Android **系统 VPN
     （VpnService）默认设备名正是 tunN**，与 mihomo 回退名（源码核实为 "Meta"）无关，接受 tunN 会把
     "mihomo 之后建立的系统 VPN"误认成漂移的新 TUN（map_tun 改写进错误设备，代理流量被 redirect 进 VPN）。
     ② 类型兜底排除表追加 `"tun"` 前缀（`tun_l3_known_other`），系统 VPN 完全不在候选内。
     `tun_name_like` 现只认"Meta + 同前缀+数字"。防误挂三重条件（ifindex 单调基准 + IFF_UP +
     ARPHRD_NONE 排除表 wg/tailscale/tun）保持；"不存在"日志附带扫描中 TUN 类接口清单
     （`tun_list_like`，v1.2.6 起含 ARPHRD_NONE 接口），区分"真没了" vs "改名了"。
     **v1.2.8 补充（漂移保持，验证发现）**：漂移对齐后 `g_tun_last_good` 被设为该 ifindex，
     旧逻辑的"ifindex > last_good"严格检查会让同一设备下一心跳被排除 → map_tun 回退置 0
     （漂移对齐只活一轮）。新增 `g_tun_drift_idx` 记录漂移对齐的设备，`tun_find_drift` 对
     `== g_tun_drift_idx` 放行（既存漂移设备保持有效，mihomo 再次重建更高 ifindex 的新设备
     仍优先选中）；精确匹配命中/设备缺失时清零恢复重新搜寻。漂移 WARN 仅首次对齐时打一次
     （`first_time` 守卫），避免每心跳刷屏。
- **坑**：`iface_index_by_name` 把"scan 失败"与"接口不存在"都返回 -1，无法区分——tun_sync
  **不用它**，直接 `iface_scan` + 遍历名字，只有 scan 真正失败才跳过。
- **保持语义**：daemon 启动时 tun 不存在仍 exit 3（mihomo 必须先启动）；`tun_sync` 只管运行期漂移。

## CNIP 定时刷新（v1.0.6 fork 化）
- `cfg.cnip_auto_update_hours>0` 时，poll 循环每 2s 用 `now_ms()`（CLOCK_BOOTTIME）检查到点即
  **fork 子进程**执行"下载（若有 url）→ 全量重灌 map"；父进程 `waitpid(WNOHANG)` 回收，**不阻塞
  poll 主循环**（下载最长 2×60s，同步执行会让 ctl/网络事件停摆）。0=关闭。
- **CNIP 缺失补拉（v1.1.3）**：启动时（3.5 步）若 CNIP map 为 0 条且配置了 url → `cnip_boot_once=1`
  并 5 秒后触发一次 fork 补拉（即使 hours=0 也会跑这一次）；**成功后才清零 boot_once，
  失败保留（v1.1.3 修正）**——hours=0 时若失败即清零，调度条件 `(hours>0 || boot_once)` 恒
  false，"5 分钟后再试"永远不会发生（与 fork 失败分支保持 boot_once 的语义一致）。
  **v1.3.1（审查修复）：补拉条件收紧为"某族 url 与 path 必须同时配"**——cnip_auto_update
  对空 path 是 no-op（cnip_fetch_to_path 直接返回 0），旧实现只查 url 会让补拉 fork 空转、
  静默"成功"但 CNIP 保持 0 条（用户以为已补拉）；url 有 path 无的族不可能落盘。
  未配 url → 打 WARN 提示放 cn_cidr_v4.txt 后 reload-cnip。
- 子进程退出码：0=成功（按原间隔续期）；非 0=失败（5 分钟后再试，避免离线时每小时刷日志）。
  **v1.2.8（审查修复）**：`waitpid` 失败（如 ECHILD——子进程已被系统回收）时显式清除
  `cnip_pid`/`g_cnip_busy` 并按 fork 失败同语义 1 分钟后再试——旧实现不清会永久卡死：
  定时更新不再触发、`reload-cnip` 被 `g_cnip_busy` 永久拒绝。
- 语义是"重读配置里 path_v4/path_v6 指向的本地文件"；文件由用户侧定时更新（如 cron + fetch-cnip.sh）。不内置网络下载。
- `cnip_apply` 内部已"先清 map 再全量"，重复调用安全（见 cni/MEMORY.md）。
- 注意：fork 子进程继承 ctx 的 map fd，可直接灌入；子进程里不要调用会阻塞主循环的东西（它只跑 cnip_auto_update 就 `_exit`）。
- **子进程 fd 清理**：子进程 fork 后立即关闭与更新无关的父进程 fd（ctl listen `lfd` / netlink watch `evfd` / 单实例锁 `lock_fd`），避免它们被下载器（v1.2.8 起 `cnip_load_url` 内层 `fork+exec` 派生的 curl/wget，v1.4.1 起支持回落）继承泄漏、也避免与父进程 poll fd 语义纠缠；map fd 保留供灌入。

## 路由接管检测（v1.1.3，防"分流失效静默无报错"）
- **背景（真机教训）**：mihomo 配置若是 box 原样（auto-route:true），mihomo 会在 tun 挂
  default 路由并把 ip rule 指向其路由表 → **物理网卡 egress 的 eBPF 完全看不到流量**，
  direct_cn/proxy 停涨但 daemon 无任何报错——比"丢包"更难排查。
- **机制**：主循环每 `HIJACK_CHECK_MS`=30s（P2：10s→30s）节流 `route_tun_hijacked(tun_ifindex)`
  （netlink.c，最重 netlink 单点，减 3 倍）；状态变化才打日志（接管→WARN，解除→INFO）。
  `ctl_status` 同时带出 `hijack` 字段 + WARN 行。
  **检测失败（netlink 错误/超时）返回 -1：daemon 本轮跳过不更新状态**（不误报、不误
  解除），status 的 hijack 字段如实显示 -1。
- **v1.1.8 路由表感知（netlink.c）**：不再把任意 `default dev tun` 当接管。main 表 default 恒被
  隐式 `from all lookup main` 命中 → 直接判接管；非 main 表（如 mihomo 的 table 2022）需再 dump
  RTM_GETRULE，存在"无条件把全部流量导向该表"的规则才判接管——私有表残留 default-via-tun 不再
  误报；规则 dump 失败按 -1（跳过本轮）。注意：mihomo 新版 sing-tun auto-route（仅 fwmark 精确
  匹配、不劫持普通主机流量）不算接管；传统 `from all lookup 2022` 仍会识别。详见 common/MEMORY.md 坑 6。
- **另一道闸（Android 侧）**：`android/scripts/fix-mihomo-tun.sh` 在 service.sh/WebUI start
  前幂等修复 mihomo tun 段（auto-route:false / strict-route:false / stack:gvisor / gso:false /
  mtu:1500 / auto-detect-interface:false）——见 android/MEMORY.md。

## 坑与边界
- `poll` 2s 超时只是"无事件时唤醒心跳"的下界；lfd/evfd 在 `fds[]` 里的**下标由 `lfd_idx/evfd_idx` 记录**（任一 fd 为 -1 时不会错位读未初始化槽位），新增 fd 必须同步。
- **poll 错误事件必须显式消费（v1.2.7 审查 H3，勿回退）**：两个 fd 只处理 `POLLIN`，若出现
  `POLLERR/POLLHUP/POLLNVAL` 而无分支消费，poll 会立即返回 → daemon 100% CPU 忙循环。
  现对两个 fd 的错误位显式处理：ctl listen / netlink watch **重建**（`ctl_listen()` /
  `iface_watch_open()`，内部各自 unlink/bind）。勿把"只查 POLLIN"改回去。
- `ctl_reply` 返回 int（v1.2.7 审查 H4）：0=完整写出，-1=客户端断开/写失败。list-rules 的
  `ctl_rule_line` 回调收到 -1 即返回非 0，`map_rule_foreach` 提前中止——避免对已断开连接继续
  枚举数千条规则耗时。其它调用方按语句使用忽略返回值，无行为变化。
- `g_stop` 在 `ctl_serve` 里被置位后 accept 循环检查 break——`stop` 命令即时生效。
- 退出路径（v1.0.6）：`stop` 时若 CNIP 更新子进程还在跑，先 `waitpid(WNOHANG)` 收尸不阻塞，
  子进程持有 map fd 让其自然完成（孤儿化后由 init 接管，maps 在最后一个 fd 关闭时释放）。
- `tun_sync_last_ms` 初始 0 → 首轮循环即做首次兜底同步（v1.1.2 起不再依赖 2s poll 超时）。
- `exit(2)`（BPF 加载失败）是**真实退出**不是降级——mihomo 若 auto-route:false 则无分流兜底；
  `android/magisk/service.sh` 通过 `splitctl status` 检测并打日志提示（改 exit code 必同步该脚本）。

## 验证
- Linux: `splitd -c configs/split.yaml -d` → `splitctl status/stats` → `stop` 干净退出。
- `strace` 观察 unix socket / netlink 行为。