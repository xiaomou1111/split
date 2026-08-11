# 02-模块说明书（MODULES）

> 每个模块都要自问：**它只做一件事吗？它和谁依赖？使用者怎么调它？坏了怎么测？**
> 下面按“目录 → 模块 → 职责 / 对外契约 / 实现要点 / 测试”组织。

## 0. 模块分级

```
L0 公共         include/split_bpf.h, common/, maps.h      <- 唯一被到处 include 的一层
L1 核心内核     parse / radix / policy / classify(bpf)
L2 用户态驱动   loader / iface / cni / rule
L3 生命周期     daemon / cli
L4 平台胶水     android/magisk
```

## 1. 内核侧（kernel/bpf/）

### 1.1 maps.h — 单一真相源（Global）

- **职责**：定义这一切 eBPF map（类型/key/value/容量）。
- **对外契约**：
  | map  | 类型 | key | value | 用途 |
  |------|-----|-----|-------|------|
  | map_cnip4 | LPM_TRIE | u32 pfix + u8[4] | u8 used | 中国 IPv4 |
  | map_cnip6 | LPM_TRIE | u32 pfix + u8[16] | u8 used | 中国 IPv6 |
  | map_rule_proxy4/6 | LPM_TRIE | 同 | u8 | 强制代理段（如 fake-ip, 失败只段）|
  | map_rule_direct4/6 | LPM_TRIE | 同 | u8 | 强制直连段 |
  | map_dns4 | HASH | u32 ip4 | dns_entry | IP→域名（用户态 AF_PACKET 学习）|
  | map_dns6 | HASH | u8[16] ip6 | dns_entry | 同上（IPv6 地址）|
  | map_dom_proxy | LPM_TRIE | dom_key | dom_rule | 代理域名后缀规则（反转存储）|
  | map_dom_direct | LPM_TRIE | dom_key | dom_rule | 直连域名后缀规则 |
  | map_skip_uid | HASH | u32 uid | u8 allow | uid 白名单（mihomo/root） |
  | map_tun | ARRAY(1) | u32 idx | u32 ifindex | 代理 tun 设备 ifindex（daemon 动态同步：mihomo 重建 utun 时 ifindex 漂移自动对齐；接口消失置 0 → BPF 侧放行保联网） |
  | map_cfg | ARRAY(1) | u32 idx | struct split_cfg | 默认行为/IPv6/UID/域名短路开关（v1.2.0：skip_uid_enabled、dom_enabled） |
  | map_rawip | HASH | u32 ifindex | u8 used | RAWIP 接口集合（v1.1.5：Android 蜂窝 rmnet_data*，ARPHRD_RAWIP=519，无以太网头；用户态挂载/网络事件时同步，内核据此跳过 L2 解析） |
  | map_stats | PERCPU_ARRAY | u32 类型 | u64 计数 | 观测 |

> v1.1.0 域名分流编码契约（字节级，split_bpf.h「域名分流」一节为真相）：
> `dns_entry.name` / `dom_key.data` 一律存**反转 + 小写**的域名
> （"example.com" → "moc.elpmaxe"），后缀匹配借 LPM 前缀匹配实现；
> `dom_rule.len` 是规则字节数（LPM lookup 不返回命中长度，边界检查要用）。
- **实现要点**：所有 map 在文件头部集中声明，改端口只需动这一个文件。
- **测试**：`tests/unit/maps_test.c` 验证加载正确大小、类型、max_entries。

### 1.2 parse.h — 报文解析
- **职责**：给定 `__sk_buff*`，安全读出 以太→IP→(TCP/UDP) 的 dst_ip、proto、dport、
  family、以及 skb uid。
- **对外契约**：
  ```c
  struct split_pkt {
      __u16 family;      /* SPLIT_FAMILY_IPV4 / IPV6 */
      __u8  proto;       /* IPPROTO_* */
      __be16 dport;
      union { __be32 ip4; __u8 ip6[16]; } dst;   /* 网络字节序 */
  };
  int parse_skb(struct __sk_buff *skb, struct split_pkt *p);  /* 1=成功 0=不可判(放行) */
  ```
- **实现要点**：所有读写带 `if (data + N > data_end) return 0` 守卫；支持 vlan(0x8100/0x88a8) 跳过外层头。
- **测试**：BPF 单测用 `tests/bpf/`（patterns + verifier 判定）会构造最小以太网/IP 包。

### 1.3 radix.h — LPM_TRIE 匹配
- **职责**：对给定地址做最长前缀匹配（用于 cnip/proxy/direct 三套树，四/六族统一）。
- **对外契约**：`radix_match4(map, be32)` / `radix_match6(map, ip6_ptr)`（宏，返回命中 bool）
- **实现要点**：构造 key 时 prefixlen 固定为 32/128（即"查最具体"）；LPM 自动回溯。
- **测试**：unit：向 trie 插入 `10.0.0.0/8` 查询 `10.1.2.3/32` 命中与 `8.8.8.8/32` 不命中。

### 1.4 policy.h — 判定
- **职责**：把 parse 输出 + UID → Verdict{直连,代理}。
- **对外契约**：
  ```c
  enum split_verdict policy_judge(const struct split_pkt *p, __u32 uid, const struct split_cfg *cfg);
  ```
- **判定顺序（重要，写入注释，v1.1.1 起 8 步；未变，v1.2.0 仅加短路）**：
  1. uid 白名单 → 直连（跳过一切，防 mihomo 环；`cfg.skip_uid_enabled==0` 时整段短路，split.bpf.c 亦不调 bpf_get_socket_uid）
  2. v6 且 `default.ipv6=false` → 直连（v6 不参与任何分类，docs/04 契约；
     必须置于域名/规则/CNIP 之前，否则 proxy6/direct6 仍会命中）
  3. 内部/链路本地/多播(dst) → 直连
  4. 域名规则（IP→域名反查 + proxy/direct 域名后缀） → 按规则（v1.1.0；`cfg.dom_enabled==0` 时整段短路，省下 map_dns 查表+ktime_get_boot_ns）
  5. policy_proxy 命中 → 代理
  6. policy_direct 命中 → 直连
  7. CNIP(v4/v6) 命中 → 直连
  8. 其余 → cfg.default_verdict（默认=代理）
- **实现要点**：顺序即优先级，可配；为可观测性，每次裁决写相邻 stats key。
- **域名匹配（dom.h）**：LPM 只回最长前缀 → 可能被"非标签边界"的更长规则遮蔽
  （如规则 `xample.com` 遮蔽 `com` 匹配 `www.example.com`），故命中后做
  "下一字节必须是 `.`"边界检查，失败则**逐字节递减 prefixlen 再查**（≤64 步
  线性查询，v1.1.1 起无层数限制；旧"跳标签 8 层"方案已废弃，见 kernel/bpf/MEMORY）。

### 1.5 split.bpf.c (classify) — 唯一 BPF 入口
- **职责**：`SEC("classifier") int split_classify(struct __sk_buff*)` 流程编排：
  parse → policy → 若代理→ tun map→发现→`bpf_redirect(tun, 0)`; 否则 `return TC_ACT_OK`。
- **对外契约**：一个 BPF OBJECT 文件 `split.bpf.o` 一个程序段，加载端通过 maps 交互。
- **实现要点**：
  - tun map 未填充时放行（不阻塞网络）。
  - 不丢包原则（parse 失败等于放行）。
  - stats 的 per-cpu 递增。
- **测试**：`tests/integration.sh` 全链路。

---

## 2. 用户态（userspace/）

### 2.1 loader/
- `loader.c`：`bpf_object__open_file` 加载 split.bpf.o，赋 map fd，开全局；tc 挂载（`bpf_tc_*`）
  也在 loader.c（`split_attach_iface`，handle=1 priority=10 固定契约），不存在独立 attach.c。
- 域名分流 map 操作（v1.1.0）：`map_dom_add/del/clear`（域名 → 反转+小写 → LPM key）、
  `map_dns_set/prune/count`（学习器写入 / 过期清理 / 计数）。
- `iface.c`：通过 common/netlink.c 枚举 iface、判断物理性（exclude 名单含 lo/tun/**utun**/tap...），
  订阅 `RTMGRP_LINK`（link 事件），网络切换触发重 attach。

### 2.2 cni/
- `cnip.c`：从 URL/文件拉 CNIP 文本（`A.B.C.D/N` 每行）→ inet_pton → 组装 lpm key → 批量 update。
- `loader` 里对两族各一个。cidr 数量多时用并区/裁剪（v4 段数约 ~7k、v3 ~3k）。
- **对外契约**：`int cnip_apply(struct split_bpf_ctx *ctx, const struct split_config *cfg);`（按
  `cfg->cnip4_path/cnip6_path` 导入）；`int cnip_load_file(ctx, path, family);` / `int cnip_load_url(ctx, url, tmp_path, family);`

### 2.3 rule/
- 维护 `map_rule_proxy* / direct* / skip_uid`：add/del/reload 子命令，配合配置文件字段。
- 域名规则（v1.1.0）：`map_dom_proxy/direct` 由 `rule_apply_all` 一并"先清空再全量"灌入
  （配置字段 `rules: proxy_domains:/direct_domains:`，上限 CFG_DOM_MAX=64 条）。
- 入口：`rule_apply_all(ctx, cfg)`；在线增删：`rule_add(ctx, cidr, which)` / `rule_del(ctx, cidr, which)`。

### 2.4 daemon/
- 生命周期：start (fork daemon 化) / 状态机(init → attach → serving → stop)。
- 网络切换监听，重挂载；config 热重载。BPF 加载失败 **exit(2) 直接退出**（无 eBPF 的 splitd 无意义；
  若 mihomo auto-route:false 则无分流兜底，Android 侧由 service.sh 检测 `splitctl status` 失败打日志提示）。
- **单实例锁（v1.1.4）**：启动时对 `<ctl socket>.lock` flock(LOCK_EX|LOCK_NB)；被另一实例占用 →
  **exit(4)** 拒绝启动（防二次 start 顶掉原实例 socket）；锁不可用（只读目录）→ 降级无锁运行。
- CNIP 定时自动更新 **fork 子进程**执行（下载+重灌），`waitpid(WNOHANG)` 回收，不阻塞 poll 主循环。
- **tun 存活同步（v1.0.6）**：`tun_sync()` 让 map_tun 与 tun_device 当前 ifindex 对齐——mihomo 重建
  utun 导致 ifindex 漂移时自动重写，接口消失时置 0（BPF 侧 `STAT_MISS_TUN` + `TC_ACT_OK` 放行保联网）。
  背景：`bpf_redirect` 对无效 ifindex 在 `__skb_do_redirect` 里 `kfree_skb` 直接丢包（helper 恒返回
  TC_ACT_REDIRECT），旧 ifindex 残留 = 海外全挂。
  **v1.1.2 起每轮 poll 循环末按 1s 节流无条件执行**（不依赖 poll 超时——持续 DNS 流量下 poll
  几乎不超时，旧"心跳只在超时分支"会失效）。**v1.2.1 起新增两处即时触发**：netlink 接口变化
  事件分支（`iface_watch_poll>0` 时复用已扫快照立即对齐——mihomo **重载配置文件**重建 utun 走此
  路径，原先要等下一轮 1s 心跳，期间有 stale 丢包窗口）与 `reload` 命令（重读配置后立即对齐）。
  **v1.2.4（真机修复）**：事件快照缺 utun 时先强制 `iface_scan` 权威复核再定论——快照可能
  拍在 mihomo 重建 utun 的 DELLINK/NEWLINK 间隙，直接按快照置 0 会出现"ip link 可见 utun 但
  map_tun=0、代理完全失效"的假象；utun 缺失降级期间（`tun_sync` 返回 1）心跳从 1s 收紧到
  300ms，事件漏收时恢复代理最长等待 ≤300ms。
  **v1.2.5（名字漂移兜底）**：mihomo 重载后新 TUN 可能不再叫配置名。精确匹配（含复核）仍缺时，
  按"比最近一次有效 ifindex 更新 + IFF_UP + TUN 类名字"找候选自动对齐并打 WARN（`tun_find_drift`，
  `g_tun_last_good` 基准防误挂系统 VPN）；"不存在"日志附带扫描中的 TUN 类接口清单（`tun_list_like`）
  供区分"真没了" vs "改名了"。
  **v1.2.6（源码修正 + 按类型兜底）**：mihomo Alpha `listener/sing_tun/sing_tun.go` 核实——
  Linux 回退名是 `InterfaceName` 默认值 **`"Meta"`**（`device==""` 时），并非 v1.2.5 假设的 `tunN`
  （`tunN` 仅 InterfaceName 为空、`utunN` 仅 darwin）。因此：`tun_name_like` 直接认 "Meta"；
  `tun_find_drift` 追加 **`type==ARPHRD_NONE`（L3 TUN）** 兜底，覆盖重载后落到任意 device 名
  （含 WebUI 把 device 改空的情况），并排除同为 ARPHRD_NONE 的 wg/tailscale 防误挂。
  **v1.2.8（审查收紧）**：移除"配置名以 utun 开头则接受 tunN"的启发式，且类型兜底排除表
  追加 `"tun"` 前缀——Android **系统 VPN（VpnService）默认设备名正是 tunN**，此前"mihomo
  之后建立的系统 VPN"会被误认成漂移的新 TUN（map_tun 改写进错误设备）。mihomo 名字识别由
  "Meta + 同前缀+数字"覆盖，系统 VPN 完全不在候选内。
  **v1.2.8 补充（漂移保持）**：漂移对齐的设备经 `g_tun_drift_idx` 记录并在后续心跳保持有效
  （此前"ifindex > last_good"严格检查会让刚对齐的设备下一轮被排除、map_tun 回退置 0）；
  精确匹配命中/设备缺失时清零恢复重新搜寻，漂移 WARN 仅首次对齐打一次。
- **DNS 学习器（v1.1.0）**：`dns_learn_open` 起 AF_PACKET fd 入 poll（失败仅 WARN，主分流不受影响），
  事件驱动 `dns_learn_poll`；30s 节流 `map_dns_prune` 清理过期学习条目；退出 `dns_learn_close`。
  新 ctl 命令 `dns`（学习器状态：fd/learned/entries4/entries6，真机排查入口）。

### 2.5 cli/ splitctl
- 子命令：`start stop status stats dns list-rules reload reload-cnip add-rule del-rule validate`（`start`/`validate` 本地执行，其余经 socket 与 daemon 通信）。
- `list-rules`（v1.2.2）：逐行输出当前在线规则（`proxy <cidr>` / `direct <cidr>`，map 实况）——WebUI 规则列表用。
- `status` 输出（v1.1.3 扩展 / v1.2.8 hijack 改缓存）：`OK prog_fd=.. attached=.. tun=<ifindex> cnip4=<n> cnip6=<n> hijack=<0|1|-1>` + 可选的 `WARN` 行（CNIP 0 条 / 路由被 mihomo auto-route 接管 / **tun 缺失（v1.2.7）**）。daemon 每 10s 自检路由接管，变化即打日志。
  **v1.2.8（审查修复）**：`hijack` 字段读主循环 10s 节流缓存的 `g_hijack_now`（含 -1=检测失败），
  不再在 ctl 路径同步重跑 netlink dump（最坏 4×2s 阻塞主循环的 ctl/网络事件/CNIP 调度）；
  status 至多 10s 陈旧。
- 通过 unix socket (`/run/splitd.sock`，或 `$SPLIT_SOCKET`) 与 daemon 通信；纯输出。

### 2.6 dns/（v1.1.0 新增）
- **职责**：AF_PACKET 抓 UDP/53 的 DNS 响应（IPv4 传输，PACKET_HOST），解析 A/AAAA
  （支持压缩指针/0x20 大小写/TTL），把 `IP→域名` 写进 map_dns4/6。
- 为什么用户态：DNS 解析在 eBPF 里做有 verifier/真机风险，且**免去新增 ingress hook**
  （kernel/bpf/MEMORY 既定取舍"不做 ingress"保持不变）。
- **限制（已知缺口）**：只学 IPv4 传输；TCP/53 与 IP 分片不学；**VLAN 标签帧不学**（socket 只绑
  `ETH_P_IP`，802.1Q 外层 ethertype 不命中，v1.2.8 文档化）；CNAME 链中每条 A/AAAA
  按**自身 owner name** 学习（v1.2.0 起支持链、v1.2.7 修正归属，不跨响应/不额外学别名
  自身）；TTL=0 不学；TTL 上限 7 天（v1.1.2 clamp，防占满学习 map）；**>SPLIT_DOM_MAX 域名
  截断点非标签边界不学（v1.2.8 防假阳性）**。
  **v1.2.7**：移除 cBPF 内核预过滤（对 RAWIP 蜂窝接口偏移错位致静默漏学），改由
  `dns_process_ip4` 用户态全过滤，Ethernet 与 RAWIP 两种布局均正确。
- **失败语义**：任何解析失败 = 漏判该域名，不影响联网（内核回落 IP 判定）。

### 2.7 common/
- `log.c`：级别化的 log（`g_log_level` 全局，宏带 `__func__/__LINE__`）。
- `config.c`：极简 YAML 子集解析（`section:`/`key: value`/`- item`/`# 注释`）；布尔字段必须走
  `parse_bool()`（支持 true/false/yes/no/on/off/1/0，勿用 atoi）；值/列表项尾空白由 `str_trim_tail()` 清理。
  节头与**列表声明 key 的内联值**（如 `default: tun`、`proxy_cidr4: 1.2.3.0/24`）都会告警提醒
  （v1.2.8 补列表 key 的 `list_key_inline_warn`，防"以为加了规则实际没有"）。
- `netlink.c`：接口枚举（`iface_scan` **必须先 bind()** 再 send/recv）+ `iface_is_physical`
  （名字黑名单 + IFF_UP，exclude 含 lo/tun/**utun**/tap/dummy...），物理判定防回环。
- `paths.c`：`split_socket_path()` — 优先 `$SPLIT_SOCKET` 环境变量，默认 `/run/splitd.sock`（Android 用 run/splitd.sock）；`split_log_path()`（v1.1.9）— 优先 `$SPLIT_LOG`，默认 `/var/log/splitd.log`。
- **实现要求**：无第三方依赖（C + libbpf + kernel headers），便于跨编译到 Android。

---

## 3. 平台胶水（android/）

- `android/magisk/*`：Magisk 模块结构。启动 `service.sh` → root 下依次：
  1. mount bpffs、权限检查
  2. 调用 `magiskpolicy --live` 打开 bpf/tc 权限（sepolicy）
  3. 起 mihomo（或要求已装）→ 起 splitd -c config → 拉起 split-watchdog.sh 守护（v1.1.7）
- `android/scripts/check-kernel.sh`：`uname -r`，尝试 `bpf()` 系统调用探活，输出支持度矩阵。
- `android/scripts/split-watchdog.sh`（v1.1.7）：splitd 存活守护——15s 探活 `splitctl status`，
  失控则按原参数拉起。**停止闸 `run/splitd.disabled` 由 `splitctl stop/start` 直接读写**
  （v1.1.7 起收敛于此，任意 stop 路径都生效，防"刚 stop 又被拉起"；见 android/MEMORY.md）。
- `android/app/`：预留 binder/service 纯 bone 说明，`start/stop` 由 root shell 完成。

---

## 4. 契约（修改一个模块如何不波及别的）

| 想改 | 只需动 | 不需动 |
|---|---|---|
| 换 CNIP 源头 | `userspace/cni/cnip.c` 的 URL 常量 + config | 内核、loader |
| 增加一条同优先级规则 | `userspace/rule/` + config | 内核 |
| 调整判定顺序 | `kernel/bpf/policy.h`（+ 文档），重新编译 BPF | userspace 无感知 |
| 改 map 上限/类型 | `kernel/bpf/maps.h`（+ loader 的期望） | 其余不变 |
| 新增 1 个 hook(如 ingress) | `split.bpf.c` 加 SEC + attach.c | 其余不变，说明连通 |
| 加域名规则 | `configs` + `reload`（rule_apply_all 自动灌入） | 内核 |
| 改域名匹配深度/回溯 | `kernel/bpf/dom.h`（v1.1.1 起逐字节递减 prefixlen 查询，无层数限制） | userspace 无感知 |

统一规则：**涉及 map 的改动，唯一牵一而动是 `maps.h` + `loader` 的 map-fd 表**，
其余模块通过“map 名”解码接口进化。

---
下一份：`docs/03-ANDROID.md`（重点）。