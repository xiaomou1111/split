# userspace/common — 记忆文档（改本目录代码前必读）

> 覆盖：`log.{c,h}`、`config.{c,h}`、`netlink.{c,h}`、`paths.{c,h}`。
> 约束：**无第三方依赖，仅 libc**（Android NDK 交叉编译保持简便）。

## paths — 运行时路径（v1.0.2 新增，Android 兼容）
- `split_socket_path()`：返回控制 socket 路径；优先 `$SPLIT_SOCKET` 环境变量，默认 `/run/splitd.sock`。
- **背景**：Android 没有 `/run` 目录（只读根），splitd 的 ctl socket bind 失败但核心 BPF 正常。真机需 `export SPLIT_SOCKET=/data/adb/split/run/splitd.sock`（分层目录 run/ 下）。
- 被 daemon（bind/unlink）与 cli（connect）共用，改路径逻辑必须两处同步。

## config — 极简 YAML 子集解析器
- 支持语法仅：`#` 注释、`section:`、`key: value`、`- list-item`。**无缩进语义、无引号、无嵌套、无多行**。
- section 有 `ifaces:` / `default:` / `rules:` / `cnip:`；顶部 `debug:` / `tun_device:` / `attach_auto:` 只在 `S_NONE` 段。
- 坑 1（覆盖语义）：`proxy_cidr4:`、`direct_cidr4:`、`skip_uid:` 等**列表声明行会先清零默认计数**——声明某组即"="而非"+="。**v1.0.2 修复**：清零逻辑原先在 `handle_scalar`（只被 S_DEFAULT 调用，rules 段是死代码），现已移到 S_RULES 分支里（`cfg->nproxy4=0` 等）。
- 坑 2：列表项必须先有声明行，`cur_list` 决定落入哪一组（**1..7 的魔法编号**：
  attach/exclude/proxy4/proxy6/direct4/direct6/skip_uid，改映射必须同步。
  v1.4.0 移除原 8=proxy_domains、9=direct_domains 两个域名列表）。
- 坑 3：**值/列表项的尾空白已由 `str_trim_tail()` 统一清理**（v1.0.2 修复：此前 `fgets` 的 `\n` 残留导致 `tun_device` 变 `"tun0\n"`、`strcmp` 匹配失败，WSL2 实测发现）。
- 坑 4（v1.0.2 真机修复）：**布尔字段必须用 `parse_bool()` 而非 `atoi()`**。配置写 `attach_auto: true`（YAML 布尔），`atoi("true")=0` 导致 attach_auto 恒为 0 → 真机 `attach_auto:true` 却挂 0 个接口。现支持 `true/false/yes/no/on/off/1/0`（`parse_bool`，大小写不敏感）。涉及 debug/attach_auto/ipv6。
  - **v1.1.9 加固**：`parse_bool` 先清首尾空白再比对（容忍 `"TRUE "` 尾空白），输入进 16B 栈缓冲防原串不可修改。
- 默认值（config_defaults）：`utun`、`attach_auto=1`、`default_verdict=tun`、`ipv6_classify=1`、`proxy_cidr4=["198.18.0.0/15"]`（对齐 mihomo fake-ip-range）、direct4 五个内网段、skip_uid=[0(root),2000(shell)]、cnip4_url/cnip6_url 默认指向 fetch-cnip.sh 的源、auto_update_hours=24（每天）。
- 坑 5（v1.1.3 加固）：**skip_uid 列表项用 `strtoul+endptr` 严格校验**——旧 `strtoul(item,NULL,0)` 会把 `"abc"` 解析成 0（=root，被跳过判定），非法/溢出/超上限值忽略并 WARN。
  **v1.1.8：基数固定为 10**（`strtoul(...,0)` 会把 `"010"` 当八进制解析成 8）——UID 一律十进制。
- 坑 6（v1.1.3）：**section 行内联值会静默丢失**（如 `default: tun`——该行被当作节头，`tun` 被吞）。
   已加 `section_inline_warn`：节名冒号后存在非空白内容即 WARN 提示改写成 `default:` 节下的
  `key: value` 形式，防静默误配。
   **v1.2.8（审查修复）：列表 key 的内联值同样静默丢失**（如 `proxy_cidr4: 1.2.3.0/24`——冒号后的
   值被当列表头吞掉、`cur_list` 置位，值不落入任何规则）。新增 `list_key_inline_warn`：列表声明
   key（attach_list/exclude/各 *_cidr4|6/skip_uid）冒号后非空即 WARN，
   提示改为逐行 `- item`。防"以为加了一条规则实际没有"的静默误配。
- 坑 7（v1.1.8）：**未知 key / 无冒号行打 WARN**——顶层（S_NONE）、各 section（ifaces/default/
  rules/cnip）里的未知 `key: value`，以及 S_NONE 下缺少 ':' 的行，一律 `LOG_WARNF`。此前静默
  忽略，拼错 `tun_device` 之类会被吞掉只剩默认值，排障困难。`handle_scalar` 因此改返回 int。
- 坑 11（v1.2.9）：**列表 key 声明但无列表项会静默清空默认规则**——`rules:` 节写 `proxy_cidr4:`
  后没有任何 `- item`（空列表/仅注释）时，覆盖式清零把默认 fake-ip 段 `198.18.0.0/15` 干掉，
  若 `default:` 节同时 `verdict: direct` 则 fake-ip 流量直连断网。修复：解析结束后对"声明过但
  结果为 0 项"的四个 CIDR 列表（proxy/direct × v4/v6）打 WARN 点明默认段已清空。空列表仍有意义
  （用户主动清空某族），只告警不阻断。
- 坑 8（v1.1.9）：**`cnip` 节 `auto_update_hours` 改 `strtol+endptr` 严格校验**——旧 `atoi`
  对 `"24abc"`/负值/空串静默吞掉（`atoi("abc")=0`=关闭自动更新，拼错即静默失效）。现对
  非法/溢出/负值 WARN 并忽略，合法范围 `0..INT_MAX`。
- 坑 9（v1.2.0，L3）：**`default` 节 `verdict:` 改为白名单严格校验**——仅 `direct`→直连、
  `tun`→代理；其它任何值（含 `"directx"`/`"tun "` 拼写错误）打 WARN 并按默认 tun 处理。
  此前非 "direct" 一律当 tun，误配无告警。
- 坑 10（v1.2.0，真机排查）：**`is_section` 必须接受行尾 `\n` 作为合法终止符**——
  `fgets` 保留行尾 `\n`，标准 YAML 配置 `ifaces:\n` 的 `p[n+1]` 是 `\n` 而非 `\0`/空格/tab，
  旧判据（`=='\0'||==' '||=='\t'`）对该行返回 0 → **所有 section 全部识别失败**，全部回落到
  S_NONE 被报"未知顶层配置 key"，`cnip:`/`rules:` 等段整段失效 → CNIP 0 条、规则全不生效。
  （症状：splitd.log 每个合法 section 都 `config_load:227 未知顶层配置 key`；config_dump 显示
  `cnip4=(未配置)`。可能 v1.1.5 收紧 is_section 判据时漏了 `\n`。）**修复：`p[n+1]` 增加
  `=='\n'` 分支。** `section_inline_warn` 本就排除 `\n`，无连带误报。
  **坑 10 续（v1.4.6 审查 P2）**：补 `'\r'`——`str_trim_tail` 只清 value 不清节头行，Windows
  编辑器（CRLF）写的 split.yaml 节头 `p[n+1]=='\r'` 同样不被识别，四个 section 整段失效。
  仓库 shipped 配置为 LF，本机未实测 CRLF；修复与坑 10 同源同形，无连带。
- `config_dump` 是 debug 用，输出格式被 cli `validate` 复用——改格式同步 cli。
- 坑 12（v1.4.1 功能冲突审查）：**跨字段静默失效告警**——两处配置叠加时旧实现静默吞掉
  一方，现解析结束补 WARN：
  (a) `attach_auto=true`（含默认值）时 `iface_plan` 走物理网卡分支，**attach_list 被完全忽略**
  （iface.c 两分支互斥）——`attach_auto && nattach>0` 即 WARN，提示设 `attach_auto: false` 才生效；
  (b) `default: ipv6=false` 时 policy 第 2 步短路，proxy_cidr6/direct_cidr6/CNIP6 全不生效——
  `!ipv6_classify && nproxy6>0` 即 WARN（proxy6 是"意图相反"的真冲突；direct6/CNIP6 结果仍直连、
  属冗余不告警）。两处均为解析期提示，不改裁决语义。

## netlink — 接口发现/监听（不依赖 iproute2）
- `iface_scan`：RTM_GETLINK + NLM_F_DUMP，解析 IFLA_IFNAME；**只取名字+ifindex+type+flags**，无 mac/addr。
- 坑 1：`iface_is_physical` 用**名字黑名单 + IFF_UP(0x1)** 判断，不是 ARPHRD 白名单（保守策略：宁可多挂不可漏挂？实际是宁可漏挂虚拟接口）。
- 坑 2：`iface_watch_poll` 用 `MSG_DONTWAIT` + EAGAIN 收拢；只把 `RTM_NEWLINK/RTM_DELLINK` 计为"变化"。
   **v1.1.9：检测到变化才填 `snapshot`（内部 `iface_scan` 一次）；无变化（返回 0）不填不扫。**
   此前该参数被忽略——调用方拿到未初始化栈内存（潜在 UB）。现在事件路径可直接复用快照给
   `iface_reconcile`，配合 loader 侧快照透传，一次网络事件只 scan 一次。
   **v1.2.8（审查修复）：改用 `recvmsg` 并检查 `MSG_TRUNC`**——旧 `recv` 对超缓冲的单条 netlink
   消息返回截断长度且无迹象，`NLMSG_OK` 会按半截数据解析（可能漏判/错判事件）。截断时保守视为
   "有变化"（reconcile 幂等，多一次对齐无害）并丢弃本条继续收拢。
   **v1.4.5（首次真编译修复）：消息循环从 `NLMSG_OK(nlh,len)` 改手工边界循环**——宏内
   `nlh->nlmsg_len <= (len)` 是 `__u32` 与 `int` 比较，`-Werror -Wsign-compare` 下是硬错误；
   arm64 交叉 CFLAGS 无 `-Werror` 只降为警告，故此前各提交"静态审查+交叉构建"都没暴露，直到
   v1.4.5 首次原生 `make userspace` 实编。改与本文件 `iface_scan`/`rule_dump` 同款
   `off += NLMSG_ALIGN(nlmsg_len)` + 越界 break，语义不变。
- 坑 3：**`iface_scan` 必须先 `bind()` 再 `send`/`recv`**（v1.0.2 修复：此前缺 bind，内核不投递应答，`iface_index_by_name` 恒失败 → splitd 报"找不到 tun 设备"）。
- 坑 4（v1.0.2 真机修复）：**exclude 列表必须含 `"utun"`**——mihomo 的 tun 设备常叫 `utun`，而 `utun` 不以 `"tun"` 开头（前缀 `utu`），只匹配 `"tun"` 会导致 utun 被当物理接口挂载 → mihomo 回写流量再次进 eBPF → **回环 + parse_err 暴涨**。exclude 现含 lo/tun/utun/tap/dummy/sit/ip6tnl/gre/ifb/tunl/wifi-aware/p2p/r_rmnet 等。
- 坑 8（v1.1.5 真机修复）：**exclude 必须含 `"rmnet_ipa"`**——rmnet_ipa0 是 Qualcomm IPA 聚合口（ARPHRD_RAWIP 519），帧带 RMNET MAP 封装头（非裸 IP，tcpdump filter 都匹配不上），且数据面实际走 rmnet_data* 子接口。此前它被当物理接口挂载 → 其 MAP 帧全部 parse 失败 → parse_err 持续暴涨（蜂窝断海外流量排查的噪音源）。
- 坑 5（v1.1.3 加固）：**`iface_scan` 必须先设 `SO_RCVTIMEO`（2s）再 recv**——与
  `route_tun_hijacked` 同一防线：netlink dump 正常以 NLMSG_DONE 收尾，但内核异常/命名空间
  损坏时可能收不到；`iface_scan` 被 daemon `tun_sync` 每秒调用 + 每次网络事件调用，
  无超时的 recv 永久阻塞 = 整个 splitd 停摆。超时按失败返回（-1），调用方保持 map 原值。
- 坑 6（v1.1.3 设计 / v1.1.4 落实）：**`route_tun_hijacked` 的 recv 超时/错误返回 -1**
  （v1.1.3 曾写进文档但实现缺失：recv 出错走 `goto out` 返回 0，超时被当成"未接管"漏报；
  v1.1.4 补上 `goto out_err` 返回 -1）——daemon 对 -1 跳过本轮状态更新（不误报"接管/解除"），
  status 的 hijack 字段如实显示 -1。send 失败/畸形消息同样计 -1。
  **v1.1.6：`nlh->nlmsg_len < sizeof(struct nlmsghdr)` 的畸形报文也走 `goto out_err` 返回 -1**，
  不再 `goto out`（否则与"失败区分未接管"语义不一致）；`iface_scan` 达 `IFACE_MAX` 上限提前
  终止时补 `LOG_WARNF` 提示列表可能被截断（否则"成功但不完整"静默无痕）。
  **v1.2.0（L1）：路由 dump 遇 `NLMSG_ERROR` 从 `continue` 改为 `goto out_err` 返回 -1**——此前
  内核报错被静默吞掉，仅靠 2s SO_RCVTIMEO 兜底，误判"未接管"或拖慢本轮检测；与 iface_scan
  口径统一。
  **v1.1.8（审查加固）：路由表感知判定**——不再把"任意 `default dev tun`"一律当接管：
  main 表 default 恒被隐式 `from all lookup main`(pref 32766) 命中 → 直接判接管；非 main 表
  只记录表 id，再 dump RTM_GETRULE 查"无条件把全部流量导向该表"的规则（action==FR_ACT_TO_TBL
  且无 dst/src 前缀、fwmark/fwmask、iif/oif、goto、uid/端口、suppress_prefixlength 等选择条件）
   才判接管——避免私有表里残留无人引用的 default-via-tun 被误报。规则 dump 失败返回 -1。
   mihomo 传统 `from all lookup 2022` 仍会被识别；仅 fwmark 精确匹配（sing-tun 新版 auto-route
   已不劫持普通主机流量）不算接管。
   **v1.2.8（审查修复）：`rule_dump_targets_any` 遇 `NLMSG_ERROR` 从 `return 0` 改为 `return -1`**——
   此前真错误（EPERM/命名空间损坏）被吞成"未接管"（hijack=0 假阴性、静默漏报接管）。调用方只传
   合法 family（AF_INET/AF_INET6），旧的"非法 family 只回 ERROR 不发 DONE 故按 0"顾虑不成立；
   与路由侧/iface_scan 口径统一，daemon 对 -1 跳过本轮（不误报）。
   **v1.2.7（审查 M2）**：`tables[]` 容量 16→64；default-via-tun 私有表 id 集合写满时
   无法完整校验"全部流量是否被导进某表"——按检测失败返回 -1（daemon 跳过本轮、status
   显示 -1），避免漏报接管（假阴性）。此前超 16 张被静默忽略。
   **v1.2.3（真机修复，WSL 内核实测）三个子 bug，全部命中"hijack 误判/漏判"**：
  1. **payload 残值**：第一趟 RTA_OIF 的遍历用 `RTA_NEXT` 会把 `payload` 递减到 0，再把残值
     传给 `default_route_table` → RTA_OK 立即 false → **读不到 RTA_TABLE，非 main 表的
     default-via-tun 恒被误判成 main 表**（`default dev utun table 2022` → hijack=1 假报）。
     修复：RTA_OIF 遍历用独立 `attrlen`，`default_route_table` 传原始 payload。
  2. **`rule_steals_table` 把"内核恒带的占位属性"当选择条件**：内核 dump 每条规则**恒带**
     `FRA_SUPPRESS_PREFIXLEN`（值 0xFFFFFFFF=-1 表示"未设置"）与 `FRA_PROTOCOL`（来源元数据）、
     `FRA_PRIORITY`（优先级）——此前一律 return 0 → **真正的无条件劫持 `from all lookup 2022`
     被漏判 hijack=0**。修复：suppress 类只有值 **!= -1**（真设置抑制）才算选择条件；
     PROTOCOL/PRIORITY/FLOW/PAD 忽略；dst/src/iif/oif/fwmark/uid/端口/l3mdev/dscp/flowlabel 才算。
  3. **`default_route_table` 读不到 RTA_TABLE 时**补 `rtm_table` 字段兜底（u8，兼容部分内核只写
     该字段的小表；>255 大表内核必须走 RTA_TABLE 属性，先读属性）。
  验证（WSL2 + dummy utun）：基线 hijack=0；`oif utun`+私有表路由=0（不误报）；无条件
  `from all lookup 2022`→含 default 的表=1（正确识别）。
- 坑 9（v1.4.5 首次真编译修复）：**`rule_steals_table` 引用的 `FRA_DSCP`/`FRA_FLOWLABEL`/
  `FRA_FLOWLABEL_MASK` 依赖内核 6.9 头**——这三个常量 6.9 才进 `linux/fib_rules.h`，Ubuntu
  24.04（6.8）等旧工具链直接引用编译失败。修复：缺失时 `#ifndef` 补 mainline 枚举值
  （DSCP=25/FLOWLABEL=26/FLOWLABEL_MASK=27，落在 6.8 的 `__FRA_MAX` 之后不与旧枚举冲突）。
  旧内核运行时不会发出这些属性，命中分支等价"不可能"，行为与新头完全一致。**勿改回 `#ifdef`
  版本号判断**——`#ifdef` 对枚举常量恒假，只能走宏兜底。
- 坑 7（v1.1.4）：**`config_load` 先 fopen 再 `config_defaults`**——此前 defaults 在 fopen 前执行，
  文件打不开时调用方 cfg 已被重置成默认值，daemon reload 的"失败沿用内存配置"实际变成
  "重放默认规则"（自定义 proxy/direct/skip_uid 全丢）。修复后打开失败 cfg 保持原样。
- `IFACE_MAX=128` 是 loader `attached[]` 的容量约定，改此处必须同步 `loader.h` 的依赖（loader.h include 本头获得 IFACE_MAX）。
- 仅在 start-split/daemon 用到 `iface_index_by_name`（tun 解析）。

## log
- `g_log_level` 全局；宏带 `__func__/__LINE__`；daemon 启动后由 `cfg.debug`/`-d` 覆盖。
- 无 syslog/ring buffer——logcat/终端直接消费。
- 格式：`YYYY-MM-DD HH:MM:SS.mmm [LV] func:line  msg`（`localtime_r`+`strftime`，毫秒来自 `CLOCK_REALTIME` 的 `tv_nsec`）。
- 坑：不要退回 `tv_sec % 100000` 的 epoch 秒显示（v1.0.3 前），人类不可读；Android bionic 同样支持 `localtime_r`。

## 验证
- `make -C userspace`（Linux）。config 的解析逻辑可在宿主上用 `splitctl validate -c xxx` 冒烟。
- **v1.2.0（L4）：`userspace/Makefile` 的 CFLAGS 追加 `-Werror`**（与 kernel/Makefile 对齐）——任何
  新增告警即编译失败，防脏告警累积。在 Linux 上 `make userspace` 如有既有告警暴露需先修（本轮
  已静态审查，若构建仍报碍则就地解决再提交）。
- **v1.4.5（首次真编译）**：本仓库用户态在 WSL2 Ubuntu 24.04（6.8 内核头）首次 `make userspace`
  实编，暴露并修复两处潜伏错误（`FRA_*` 6.9 头缺失 + `NLMSG_OK` 符号比较，见上坑 2/坑 9）。
  此后任何涉及 common 的改动必须 `make userspace`（-Werror）实编验证，勿再以"静态审查代替编译"。