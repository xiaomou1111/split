# android — 记忆文档（改本目录代码前必读）

> 覆盖：`magisk/`（模块骨架）、`scripts/`（起停/能力探测）、`app/`（预留）。
> 目标：Magisk 23+ / KernelSU 兼容；**eBPF 可用 → 内核分流；不可用 → mihomo 纯 TUN**。

## 模块骨架（magisk/）
- `module.prop`：`id=ebpf-split`，version 与 SPLIT_VERSION 保持同源——**v1.1.0 起由 gen-magisk.sh
  打包时自动改写**（唯一真源 split_bpf.h），module.prop 内数值仅作手工打包兜底。
- `post-fs-data.sh`：早启动阶段挂载 bpffs（容错，无则跳过）。
- `service.sh`：late_start 主胶水，**顺序不可乱**（文件头注释即真相）：
  1. 探测（splitd 缺失 → 跳过 eBPF，**mihomo 仍会尝试启动**）；
  2. SELinux：`magiskpolicy --live` 放行 bpf/socket/tun（**magiskpolicy 不存在则静默跳过**——KernelSU 环境可能无此工具，此时依赖 sepolicy.rule）；
  3. 起随包 mihomo（独立于 splitd，缺 splitd 不影响 mihomo；晚启动网络未就绪时有限重试 3 次）；
  4. 等 `utun` 出现（**30s 超时** → 降级纯 TUN）；
  5. `splitctl status` 自检。
  6. **v1.1.7：清 `run/splitd.disabled` 停止闸 + 后台拉起 `scripts/split-watchdog.sh`（15s 探活）**。
  - **坑 6（v1.0.2 修复）**：旧版把 mihomo 启动嵌在 `if [ ! -x splitd ]` 的 else 里，
    一旦 splitd 缺失就"注释说纯 TUN 由 mihomo 负责、实际 mihomo 根本没起"→ 重启后全挂。
    现在 mihomo 启动解耦到 splitd 判断之外。
- `sepolicy.rule`：magiskpolicy 不可用时的静态补充（rules 与 service.sh 的 `--live` 放行保持一致，改一处必改另一处）。
  **v1.0.5 扩 domain**：KernelSU→`ksu`/`su`、APatch→`ap`，与 `magisk` 一并放行 bpf/tun/unix_stream/netlink
  （各 root 方案进程 domain 不同，只放行 magisk 会在 KSU/APatch 上"能力对但 domain 不匹配"）。
- 坑 1：**utun 的 ifindex 由 map_tun 动态写入**，splitd 用 `iface_index_by_name` 解析——设备名写死 `utun`，改 mihomo 的 tun.device 必须同步 split.yaml 的 `tun_device`。
- 坑 2：splitd 是后台 `&` 起，退出 code 不传回；降级判断靠"30s 无 utun"而非 splitd exit code（daemon exit 2 的降级提示在日志里）。
- 坑 3：`service.sh` 用 `$MODDIR` 但 INSTALL_DIR 是 `/data/adb/split`（gen-magisk.sh 会把二进制解包到该目录）——**不要假设二进制在模块目录**。
- **零重复（v1.1.x 约定）**：`/data/adb/modules/split/` 只做"安装源 + Magisk 必需文件"，`/data/adb/split/`
  是**唯一运行真源**。customize.sh 铺完 bin/config/scripts/mihomo 到运行目录后 `rm -rf` 模块预留副本；
  升级时 Magisk 整包重跑 customize.sh 重新铺入。运行时脚本一律引用 `/data/adb/split`，禁止从 `$MODPATH` 读执行内容。
  **审查修复（2026-08）：`config/split.yaml` 加 `[ ! -f ]` 升级保护**——只在首次安装铺默认配置，
  用户改过的自定义规则不再被升级包无条件 `cp` 覆盖（P0 数据丢失；口径与 mihomo config 的
  `[ ! -f ]` 保护一致）。改此守卫时必须与 mihomo 配置拷贝（mihomo/config.yaml）同查同改。
- 坑 4（v1.0.2 实测）：**`export SPLIT_SOCKET="$INSTALL_DIR/run/splitd.sock"`** 必须在起 splitd 前设置
  （Android 无 /run，不设则 ctl socket 绑不上）。service.sh / start-split.sh / stop-split.sh 都已加。
- 坑 5（v1.0.2 实测）：**BPF 必须 `-mcpu=v1`**，否则真机 5.x GKI verifier 报 `BPF_STX uses reserved fields` 拒载（见 docs/03 §8.5）。

## scripts/
- `start-split.sh`：手动 debug 启动（`splitd -d`，输出到终端）。
- `stop-split.sh`：`splitctl stop`（经 socket）。
- **`split-watchdog.sh`（v1.1.7 新增）**：splitd 存活守护，见下方专节。
- `check-kernel.sh`：启动前能力探测（bpf syscall/verifier/版本），结果影响降级分支。

## split-watchdog.sh（v1.1.7，熄屏后代理失效修复核心）
- **背景（真机症状）**：长时间熄屏后无法代理，mihomo 只剩自身 DNS 连接。根因=splitd 只由
  service.sh 在 boot 拉一次，之后无任何守护：doze/LMK 杀 splitd 后（tc filter 残留持引用保
  旧 prog+旧 maps），map_tun 不再更新，mihomo 重建 utun 后重定向到陈旧 ifindex → 静默丢包。
  另：kernel 侧 v1.1.7 已加接口挂载 5s 自愈心跳（daemon/MEMORY「网络切换」），watchdog 补的是
  **进程死亡**这条路径。
- **机制**：周期（默认 15s）探活 `splitctl status`（连 ctl socket；比 pidfile 可靠，覆盖
  service.sh / splitctl start / WebUI start 各路派生实例），失败且 utun 存在+SELinux 放行则
  按同参数（`-c config -b bpf.o`）重新拉起 splitd，日志写 `logs/splitd.log`（`[wd]` 前缀）。
- **停止闸（防"刚 stop 又被拉起"）**：显式停止路径必须先 `touch run/splitd.disabled` 再杀
  watchdog——已接入 `stop-split.sh` 与 WebUI `stop`；启动路径（service.sh / WebUI `start`）
  清闸并按需重新拉起 watchdog。
  **v1.1.7 收紧：闸收敛到 splitctl 本身**——`splitctl stop` 先 `touch` 同目录
  `splitd.disabled`（路径由 `split_socket_path()` 的 dirname 推出）再发 stop 命令、
  `splitctl start` 对称 `unlink`。所有脚本的 stop/start 都经 splitctl，因此**任意 stop
  路径（含直连 `splitctl stop`）都生效**，不再遗漏。脚本里的显式 `touch`/`rm -f` 保留
  （watchdog 探活性的 shell 上下文仍需，且与 splitctl 幂等）。改闸逻辑唯一定点 = daemon
  目录下 cli/splitctl.c 的 `gate_set/gate_clear` + 本处 shell 声明，改一处必查另一处。
- **防 crash-loop**：utun 不存在（mihomo 未起）直接跳过（splitd 没 tun 拉起也是 exit 3）；
  连续失败指数退避（15s→...→最长 5 分钟），防 BPF 加载失败等死循环刷日志。
  **v1.1.7**：utun 缺失 / splitd 二进制缺失这两个"本次不拉起"分支会 `fails=0`——它们不
  是失败计数，不清会拿陈旧退避拖慢 mihomo 恢复后的首次拉起。
- **mihomo TUN 自愈（v1.2.9，真机问题修复）**：原 watchdog 只在 **splitd 死亡**路径做动作，
  "splitd 活着但 mihomo TUN 中途消失（map_tun=0）"是静默降级——代理流量被放行直连
  （真机症状：`miss_tun` 持续增长、proxy 停滞却无报错；根因如 mihomo 外部控制器
  （9090 无 secret + allow-lan）把 `tun.enable` 改成 false、或 utun 被系统/外部清理）。
  现探活成功分支额外解析 `splitctl status` 的 `tun=` 字段：连续 2 轮（默认 15s×2=30s）
  均为 0 且 `bin/mihomo` 存在 → 先经 mihomo API（`PATCH /configs {"tun":{"enable":true}}`）
  无感恢复（不丢连接）；API 不可达/失败 → 重启 mihomo（先 fix-mihomo-tun.sh 对齐契约）。
  恢复后 5 分钟冷却（`mihomo_recover_ts`），防"API 拉起又被外部关掉"导致的循环重启。
  **v1.3.1（审查修复）：冷却时钟改用 `/proc/uptime` 单调秒**——旧 `date +%s` 在部分设备
  缺失（回退 echo 0 旁路冷却）且墙钟跳时会失效/误延长；uptime 不随系统时间调整。
  **注意**：`curl` 在 Android 上未必存在——API 分支失败会自然落到重启分支，重启是保底。
  **审查修复（2026-08）：自愈 PATCH 支持 mihomo secret 鉴权**——mihomo config 配了
  `external-controller` 密码时，不带 `Authorization: Bearer` 会 401 被误判为"API 不可达"而
  多余重启（断连）。现从 config.yaml 简单 sed 提取 secret（去引号/行内注释），非空则带鉴权头，
  读不到/为空按旧逻辑不带。提取失败只会 401 → 自然落 `restart_mihomo`（该函数即原重启块，
  已抽出复用，两路径共用）；`curl` 缺失同样落重启兜底。重启块改动唯一定点 = `restart_mihomo()`。
  **v1.4.6（审查 P2）：curl 必须带 `-f`**——此前两处 `curl -s -m 3 -X PATCH` 无 `--fail`，
  401/4xx 是"HTTP 成功"（curl 退出 0），`|| restart_mihomo` 不触发，冷却 300s 后重试同一
  失败 PATCH，TUN 自愈永久卡死（与上面"401 → 自然落重启"自述矛盾）。加 `-f` 后非 2xx 走重启兜底。
  注意：此改动让"API 可达但 PATCH 因鉴权/参数被拒"也从原来的静默跳过改为重启 mihomo——符合
  自愈兜底语义，但 401 不再有"多余重启"顾虑（Bearer 正确时本就不会 401）。
  **配套（同一批次）**：配置模板 `configs/mihomo/mihomo-package.yaml` 的 `external-controller`
  由 `0.0.0.0:9090` 改绑 `127.0.0.1:9090`——封掉"9090 无 secret + allow-lan"这个 LAN 操控面
  （旧故障模式见上）；全库对 9090 的调用方本就只走 127.0.0.1（watchdog / 状态栏磁贴），无破坏。
- **单实例**：脚本自身启动时 kill 旧的自身进程（`pgrep -f split-watchdog.sh`，排除 `$$`）。
- 与 boot 自启关系：service.sh 在 splitd 起来后拉起；WebUI `start` 也会拉。手动前台
  `start-split.sh`（-d 调试）不拉 watchdog，适合一轮排障。
- `setup-box-tun.sh`：**一键端到端接入 box mihomo（TUN 模式）**——复制 box 配置、改 tun 段（auto-route:false）、复用 CNIP、起 mihomo+splitd。真机验证可复现（CN 直连 39ms / 海外代理 219ms）。
- `fix-mihomo-tun.sh`（v1.1.3 新增，v1.2.6 加 `device`）：**幂等修复 mihomo tun 段，对齐 eBPF-Split 契约**——
  device:utun / auto-route:false / strict-route:false / stack:gvisor / gso:false / mtu:1500 / auto-detect-interface:false，
  全部整行重写 sed；tun 段缺某项用 `a` 追加（**Android toybox sed 不支持 `0,/re/` 地址**，实测报
  "no previous regex"，严禁使用）。service.sh 启动 mihomo 前 + WebUI start 前都会调用；setup-box-tun.sh
  step2 也委托它（**tun 段 sed 只允许这一处维护**，改契约两处文档同步）。
  **v1.2.6 补 `device:utun`**：mihomo WebUI 重载可能把 tun.device 改空/改名 → 新 TUN 落回
  mihomo Linux 默认名 "Meta" 漂移（split 侧已有名字+类型漂移兜底，**v1.2.8 起排除系统 VPN
  的 tunN**，这里启动前强制回 utun 双保险，与 split.yaml tun_device 保持字节一致）。
  - **坑（v1.1.3 真机教训，本脚本存在的意义）**：box 原样配置常带 `auto-route:true` +
    `strict-route:true`——mihomo 会接管路由（ip rule 9002 → table 2022 `default dev utun`），
    物理网卡 egress 的 eBPF 完全看不到流量 → **CNIP/规则分流静默失效**（`direct_cn` 恒 0、
    proxy 计数停滞，却无任何报错）。症状：splitctl stats 无增长 + `ip rule` 有 9002/2022。
  - **验证**：`splitctl status` 的 `hijack=0`（daemon 每 10s 自检路由接管）+ `cnip4/6` 非 0。

## 目录规范（v1.0.3 重新整理，运行时分层）
`/data/adb/split/` 运行时分层，避免根级散落：
```
bin/      二进制 + split.bpf.o + mihomo（若随包）
config/   split.yaml + cnip 数据
scripts/  辅助脚本
logs/     splitd.log / mihomo.log
run/      splitd.sock
mihomo/   mihomo 配置目录（box 复制或随包）
```
- 脚本统一用变量：`BIN_DIR/CONFIG_DIR/LOG_DIR/RUN_DIR`（改一处即可）。
- `SPLIT_SOCKET` 指向 `$RUN_DIR/splitd.sock`。
- 该目录是唯一运行真源；模块目录（`/data/adb/modules/split/`）的 `bin/config/scripts/mihomo`
  在安装后被 customize.sh 清理，不再持有执行副本（详见下方"零重复"约定）。
- **测试时不要往 /data/adb/split 根级丢配置文件/日志**——用 logs/ 或临时目录，测完清掉。

## mihomo 放哪（v1.0.3 权限结论，重要）
**mihomo 二进制放运行目录 `bin/`（或复用 box 的 `/data/adb/box/bin/`），不放 modules 目录**：
- **权限**：`/data/adb/modules/` 目录对非 root 进程不可读（实测 `su 2000 ls` → Permission denied），且受 Magisk overlay 管理（升级/卸载会丢配置）。
- **box 的经验**：box 把 mihomo 放 `/data/adb/box/bin/`（运行目录，root:net_admin 700），从运行目录跑。
- **SELinux**：magiskpolicy 只对 `magisk` domain 放行；mihomo 放运行目录后用 root 跑，走 ksu/magisk domain。
- customize.sh 随包 mihomo 解包到 `bin/mihomo`（二进制）+ `mihomo/`（配置目录），service.sh 用 `-d $INSTALL_DIR/mihomo` 启动。
- **随包 mihomo（v1.0.3）**：build/arm64/mihomo + configs/mihomo/mihomo-package.yaml（脱敏）打包进 zip。
  脱敏项：订阅 token → `YOUR_TOKEN_1..4`、hysteria2 `server` → `YOUR_HY2_SERVER_IP`、
  `port` → `YOUR_HY2_PORT`、密码 → `YOUR_HYSTERIA2_PASSWORD`、sni → `YOUR_SNI_DOMAIN`。
  用户安装后编辑 `/data/adb/split/mihomo/config.yaml` 填入自己的订阅即可。
  **打包时绝不带真机真实 token/密码/节点 IP**。**原始敏感配置（config.yaml.real）不保留在
  项目/构建区**，只留脱敏模板。

## box 集成经验（v1.0.2 真机实测，小米 diting + KernelSU）
- 设备上若有 box 代理模块（`/data/adb/box`），其 mihomo 二进制（`/data/adb/box/bin/mihomo`）可复用。
- **不要改 box 原配置**：复制其 mihomo 目录到 `/data/adb/split/mihomo/`（含 proxies/ rules/ cache.db），再改 tun 段。
- **关键改动（tun 段，v1.1.3 起由 fix-mihomo-tun.sh 幂等执行，唯一真源）**：`enable:true, device:utun,
  auto-route:false, strict-route:false, stack:gvisor, gso:false, mtu:1500, auto-detect-interface:false`。
  `auto-route:false` 是必须的——让 mihomo 只建 tun 设备不接管路由，路由和分流全交给 eBPF。
- 启动：`mihomo -t -d <dir>` 先测配置，再 `nohup mihomo -d <dir> &`（root 跑，uid=0 已在 skip_uid 防回环）。
- **坑（v1.0.3 实机踩坑）**：改 tun 段必须用"**整行重写**" sed（`s/^  stack:.*$/  stack: gvisor/`），
  **不要**用局部替换（`s/^\(  stack:\) [a-zA-Z]*/\1 gvisor/`）。局部替换多次执行会把
  `stack: gvisor #system/minxd` 切成 `stack: gvisor#system/minxd`（丢空格）或
  `system#system/minxd` → mihomo `invalid tun stack` fatal → utun 不建 → splitd 降级。
  **症状**：mihomo.log `Parse config error: invalid tun stack`；splitd.log `30s 内未发现 utun`。
  **恢复**：`sed -i 's/^  stack:.*$/  stack: gvisor #system\/minxd/' config.yaml` 后重启。
- **CNIP 数据**：box 的 `/data/adb/box/run/cn.zone`（v4）和 `cn_ipv6.zone`（v6）就是"每行 CIDR"格式，可直接复制给 splitd 用（命名 cn_cidr_v4.txt / cn_cidr_v6.txt）；行数随 box 数据源而定（本仓库默认源 Loyalsoldier 全量 v4=4145 / v6=1235）。
- **split.yaml 的 cnip 路径建议用绝对路径**（`/data/adb/split/config/cn_cidr_v4.txt`），避免 splitd 工作目录歧义。
- 端到端验证结论：CN 直连（direct_cn 增长、不经过 mihomo）、海外 redirect 进 utun（proxy 增长、utun rx 增长）、skip_uid 防回环、无 dropped/redirect_err。
- 节点 alive 但访问超时 → 是 mihomo 节点自身连通性问题，不是框架问题。
- **验证方法论陷阱（v1.0.2 真机教训）**：
  1. `skip_uid` 默认含 `[0,2000]`，而 adb shell 跑 curl/ping 的 uid 正好是 0/2000 → **用 root/shell 测试流量验证代理路径是无效的**（全被白名单跳过，看到的都是直连）。要验证海外流量进 mihomo，必须临时把 skip_uid 置空（并给 mihomo 的 DNS/代理服务器 IP 加 direct 规则防回环）。
  2. 看 mihomo 是否真收到流量：`curl 127.0.0.1:9090/connections`（连接列表）+ `utun rx_packets` 计数 + `ss -tnp | grep mihomo`（SYN-SENT 到代理节点 = 正在代理）。
  3. **utun 必须排除**：`attach_auto` 时若 utun 被误挂（前缀匹配陷阱），mihomo 回写流量再次进 eBPF → 回环 + `parse_err` 暴涨。已修 netlink.c exclude。
  4. **eBPF redirect 到 mihomo TUN 的坑（v1.0.4 源码核实）**：mihomo 用 sing-tun 库，直接从 `/dev/tun` fd `read()` 收包。bpf_redirect 从物理网卡 egress 进 tun 前必须设 `skb->queue_mapping=0`，否则 tun_net_xmit 用物理网卡继承的 queue_mapping 索引 tfiles[] 越界→drop（真机 curl 000）。mihomo 源码在 `github.com/MetaCubeX/mihomo/tree/Alpha`，核心在 `listener/sing_tun/`（用 sing-tun 库）。

## app/（预留）
- 仅 README；无 UI 无启动器（roadmap：原生 app / shell 快捷方式）。

## KernelSU WebUI（webroot/ + webuiapi.sh）
- **前端**：`magisk/webroot/`（`index.html` + `app.js` + `style.css` + `kernelsu.js`）。
  KernelSU 识别模块含 `webroot/index.html` 即启用 WebUI（KernelSU Manager 的 WebView 提供）。
- **自动刷新（v1.1.5）**：`startPolling` 每 5s 在**状态面板激活时**刷新 status/stats/mihomo，面板未激活不轮询（省电/省 WebView）；`init()` 首屏手动全量拉一次。
- **日志页（v1.1.5）**：新增 `日志` tab，select 切换 splitd.log/mihomo.log，`get-log <which> 200` 拉尾 200 行；
  勾选"每 5 秒自动刷新"→ 仅日志面板激活时轮询；进面板先手拉一次。仅做展示、不停留可执行输出。
  `kernelsu.js` 是 **npm `kernelsu` v3.0.2 原样 vendored**（ESM，免打包步骤）；升级 manager 基线时整文件替换。
- **后端**：`scripts/webuiapi.sh`（经 `ksu.exec` 以 root 调 `/data/adb/split/scripts/webuiapi.sh <action>`）。
  为什么放 scripts/ 而非 webroot/：webroot 由 KernelSU 设定为网页服务上下文，脚本放运行期目录
  `/data/adb/split/scripts/` 与既有 start/stop 一致，也避开执行权限歧义。
- **动作白名单**：status/stats/**list-rules（v1.2.2）**/**version（v1.2.2）**/start/stop/reload/reload-cnip/**update-cnip（v1.4.1）**/add-rule/del-rule/get-config/save-config/validate-config/**get-log <splitd|mihomo> [n]**（v1.1.5）/mihomo-status/mihomo-start/mihomo-stop/**env（WebUI 完善）**。
  行数 n 走整型白名单（非纯数字回退 200），`tail` → `busybox tail` → `cat` 兜底；日志尾按行截断避免打爆 WebView。
  action 由 case 分支映射，**不透传任意 shell **；参数经 shell 引号包裹（单引号 CIDR）防注入。
- **env 动作（WebUI 完善）**：环境信息 `key=value` 行——kernel/arch（uname）、android/sdk/device（getprop）、
  selinux（getenforce）、uptime（/proc/uptime，格式 hNm）、splitd_pid（`pgrep -f "$SPLITD"` 全路径匹配，
  webuiapi.sh 自身命令行不含该路径不自匹配）、watchdog（1/0，split-watchdog.sh 是否存活）。
  全走只读命令、不经 ctl socket——splitd 未运行时仍可展示，供对照 docs/03-ANDROID.md 排障。
- **mihomo 控制（v1.1.x，WebUI 完善补字段）**：WebUI 新增 mihomo 启动状态 + 开关。
  `mihomo-status` 输出 `status=running|stopped|no-binary` + `pid` + **`ver`（v1.18.x 之类，
  `mihomo -v` 冷启动 ~百 ms，结果缓存到 `run/mihomo.version` 文件，模块重装清 run/ 即失效）** + `log` 路径
  （app.js 按 `key=value` 正则解析）；
  `mihomo-start` 与 service.sh 同源逻辑（先调 fix-mihomo-tun.sh 对齐 auto-route:false，再 `-d $MIHOMO_DIR` 起，3 次重试）；
  `mihomo-stop` 用 `pkill -f "$MIHOMO_BIN"`（注意 `pgrep -f` 匹配 /data/adb/split/bin/mihomo 全路径，避免误杀其它）。
- **update-cnip（v1.4.1，WebUI"更新 CNIP"按钮）**：与 `reload-cnip`（只重读本地文件重灌）不同，走
  `splitctl update-cnip` → daemon 触发一次与定时自动更新相同的"下载 url_v4/v6 → 原子落盘 → 全量重灌"
  （cnip.c 的 `cnip_auto_update`）。**下载耗时所以是后台执行**（v1.4.1 起 `reload-cnip` 同样
  后台执行，与 update-cnip 共用 `g_cnip_req` 统一 fork 调度）：daemon ctl 分支只置
  `g_cnip_req=CNIP_REQ_UPDATE` + 提前 `cnip_next_ms`，主循环下一轮 poll 迭代 fork 子进程下载，ctl 立即回
  `OK 已安排 CNIP 更新`——前端 app.js 点按钮只收到"已安排"，进度看 splitd.log、CNIP 计数靠状态面板
  5s 轮询刷新。未配 `url_v4/url_v6` → `ERR 未配置 CNIP 数据源`；更新进行中（`g_cnip_busy`）→
  `ERR CNIP 更新进行中`。Android 无任何下载器（curl/wget/busybox，v1.4.1 起有回落）时下载失败
  会落本地旧文件重灌（cni/MEMORY 既有语义）。
- **前端（WebUI 完善，v1.2.x）**：状态面板 5s 轮询补 `env`；运行状态卡新增 TUN ifindex（0=缺失放行标黄）、
  splitd PID、存活守护、运行时长；新增"环境信息"卡（内核/架构/Android/SDK/设备/SELinux）；stats 计数做
  增量速率 `+N/s`（与上一轮对比，daemon 重启计数回退显示 ↻）并着色——直连/代理增长绿色、parse_err/
  redirect_err/dropped/miss_tun 非 0 红色；参数页新增 get-config 解析的"当前生效配置摘要"卡（parseMiniYaml，
  注意与 config.c 的极简 YAML 子集保持同理解，改配置语法两侧同步）；规则页按 proxy/direct 计数；守护进程
  开关动作执行后自动刷新状态面板，mihomo 卡提供"查看日志/开关"快捷跳转。
- **配置摘要 CNIP url 语义（v1.4.2/1.4.3 跟进）**：摘要卡对 `cnip.url_v4/v6`（逗号分隔多源 fallback）只显示
  "已配置 v4/v6/未配置"，`自动更新` 行按 `hours`+url 区分 `N 小时（下载）` / `N 小时（无下载源）` / `关闭`——
  cnip_auto_update 对无 url 的族是 no-op（hours>0 也空转，本地重读只走 reload-cnip），摘要文本须与
  daemon 行为一致，改一侧同步另一侧。
- **版本显示（v1.2.2）**：顶栏 `#renderer` 显示 `v<版本>`，数据来自 `version` 动作——webuiapi.sh 内
  `SPLIT_VERSION` 由 **gen-magisk.sh 打包时注入**（唯一真源 split_bpf.h，替换 `@SPLIT_VERSION@` 占位符）；
  直接运行仓库副本时占位符未替换自动回退 `dev`。改版本号只需动 split_bpf.h，打包脚本同步，不另行同步 webuiapi.sh。
- **写配置安全**：`save-config` 传 base64 → 先 `splitctl validate -c` 校验，通过才落盘 + `reload`；
  `validate-config` 仅校验不落盘。base64 无 shell 危险字符，作单引号参数即安全。
  **v1.0.5**：base64 解码按 `base64` → `toybox base64 -d` → `busybox base64 -d` 依次尝试（原 grep `--help` 探测不可靠）；
  解码结果空（`[ -s ]` 失败）即报错不落盘。
- **start 动作（v1.0.5 修复）**：必须带 `-b "$BIN_DIR/split.bpf.o"`。splitctl 新增 `-b` 选项（splitd 默认
  `SPLIT_BPF_OBJ_DEFAULT=/etc/split/split.bpf.o` 在 Android 不存在），否则 WebUI 的"启动"会
  `bpf_object__open_file` 失败 → daemon exit(2) → 看起来"起了马上没"。
  **v1.2.2 修复**：splitd 路径必须传 `-s "$SPLITD"`——v1.1.9 把 `-d` 改成零参 debug 后，旧写法
  `-d "$SPLITD"`（把路径当 `-d` 参数）会导致派生到默认 `/usr/local/bin/splitd`，Android 上
  启动必失败（execv 127）。webuiapi.sh 已改 `-s`。
- **路径恒定**：INSTALL_DIR=/data/adb/split，`export SPLIT_SOCKET=$RUN_DIR/splitd.sock`（Android 无 /run）。
- **SPLIT_LOG（2026-08 跟进）**：webuiapi.sh 与 SPLIT_SOCKET 并列全局 `export SPLIT_LOG=$LOG_DIR/splitd.log`。
  `splitctl start` 派生 splitd 的 stdout/stderr 走 `split_log_path()`（$SPLIT_LOG 优先，默认
  /var/log/splitd.log）；不设则 WebUI『启动』起的 splitd 日志落在日志页读不到的地方（/var/log
  不可写时 splitctl 回退 /dev/null）。service.sh / watchdog 直接 `>> logs/splitd.log`，不受影响。
- 打包：`gen-magisk.sh` 会把 `webroot/` 拷贝进 zip 根；`customize.sh` 现有逻辑把 scripts/*.sh 铺到运行目录。
- 坑：app.js 里 `encodeToB64` 用 TextEncoder→base64，避免中文注释乱码；stats 解析用 `key value` 行。
- customize.sh：BOOTMODE!=true 不 `abort`（KernelSU/APatch 可能不导出该变量），mkdir 失败才真失败。

## 交叉编译注意（android 特有）
- libbpf 需 NDK 版（或静态编译），userspace/Makefile 顶部注释有示例；**不要引入 libpthread 之外的动态依赖**。
- 二进制放 `android/magisk/` 由 gen-magisk.sh 打包（需 `zip` 命令）。
- **版本**：唯一真源是 split_bpf.h 的 `SPLIT_VERSION`；gen-magisk.sh 打包时自动改写 module.prop
  的 version/versionCode（v1.1.0），手工打包才需手动同步。
