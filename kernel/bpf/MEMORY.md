# kernel/bpf — 记忆文档（改本目录代码前必读）

> 覆盖：`maps.h`、`parse.h`、`radix.h`、`policy.h`、`split.bpf.c`
> 一句话架构：`split.bpf.c`(唯一入口) → `parse.h`(解析) → `policy.h`(裁决) → `radix.h`/`maps.h`(数据)

## 接口契约
- `split_classify()`：唯一 `SEC("classifier")` 程序，tc clsact **egress** 挂载。
- `parse_skb(skb, &pkt)`：返回 1=成功 0=不可判（调用方必须放行）。
- `policy_judge(&pkt, uid, cfg)`：返回 `SPLIT_VERDICT_PASS=0` / `SPLIT_VERDICT_TUN=1`。
- 所有 helper 均为 `static __always_inline`（verifier 纪律）。

## 关键决策与坑（踩过/必须保持的）
1. **绝不丢包**：任何解析失败、异常、无 tun 分支一律 `return TC_ACT_OK`（CONTRIBUTING §3）。`STAT_*` 只做计数不改行为。
2. **判定顺序固定（v1.1.1 起 8 步，policy.h 注释即真相）**：uid 白名单 → **v6 且 ipv6_classify=false → 直连**（第 2 步，须在域名/规则前，否则 proxy6/direct6 仍命中，v1.1.1 修正）→ 内置本地段 → 域名规则（DNS 学习）→ proxy 规则 → direct 规则 → CNIP → default_verdict。**改顺序 = 改分流语义，必须同步 docs/01、docs/02、README。** 域名规则置于 IP 段规则之前：域名是应用层意图（如"此域名强制代理"），优先级高于"IP 属于某段"。
3. **端序**：
   - parse.h 的 case 标签用 `__bswap_constant_16(ETH_P_IP)`（网络序常量），不要用 `htons()`（非常量）。
   - policy.h 内置段判定用 `bpf_ntohl` 转主机序再与 `0x7F000000` 等常量比较（跨 CPU endian 一致）。
4. **`SEC("classifier")` 旧式 section 名（保留）**：libbpf>=1.0 不再按裸 `classifier` 推断
   SCHED_CLS，报 `failed to guess program type from ELF section 'classifier'`。因此
   `bpftool prog load ... type sched_cls`、`make kernel validate` 在现代 libbpf 下会失败
   （非阻塞）。生产路径由 loader 显式 `bpf_program__set_type(..., BPF_PROG_TYPE_SCHED_CLS)`
   处理（loader.c）。**不改 section 名**（AGENTS 硬契约），验证走 splitd（BUILD.md §4.1）。
5. **`-mcpu=v1` 必须保留（Android 兼容关键，v1.0.2 实测发现）**：新 clang 默认编出 `BPF_ATOMIC`（`atomic_fetch_add`，opcode `0xdb`），但小米 5.10/5.15 GKI 的 verifier 只认老 `BPF_XADD`，报 `BPF_STX uses reserved fields` 拒载。**kernel/Makefile 必须 `-mcpu=v1`**（生成 `BPF_XADD`），否则真机加载失败。WSL2(6.18) 能过但真机 5.x 过不了——这就是"宿主能跑真机不能"的经典差异。
6. **map 单一真相源在 maps.h**：改 map 类型/容量/大小必须同步 `userspace/loader/loader.c` 的 map 期望表与 docs/02 map 表。map 名称（`map_` 前缀）被用户态按名字查找，**改名即破坏契约**。
7. **stats_inc 用 `key & (STAT_MAX - 1)` 防越界**：`STAT_MAX=16` 必须是 2 的幂。key 编号被 `daemon.c ctl_stats` 的名字数组引用，**不能重排/插入**（可追加）。v1.1.0 追加 `STAT_DOM_PROXY=9` / `STAT_DOM_DIRECT=10`；追加 `STAT_DIRECT_V6=11`（v6 且 `ipv6_classify=false` 的"配置性直连"，与 CNIP 直连 `STAT_DIRECT_CN=1` 分开计，见 policy.h 第 2 步）——**追加 key 必须同步 daemon.c names 数组**。
8. **LPM_TRIE 语义**：radix.h 查询时 prefixlen 填 128/32（查最具体），内核自动最长前缀回溯；key 必须整体清零（`{ .prefixlen = 32 }` 其余零）。值统一 `__u8 =1`（成员标记，不承载意义）。
   - **域名 trie（dom.h）例外**：`map_dom_*` 的 value 是 `struct dom_rule{len}`——LPM lookup **不返回命中前缀长度**，内核靠 value 自记长度做"下一字节必须是 `.`"的标签边界检查（见 19）。
9. **parse 边界**：VLAN 支持至双标签 QinQ（`VLAN_MAX_TAGS=2`，0x8100/0x88a8，常量上界 + 全展开保证 verifier 可证；此前单层扩展为双标签）；IPv6 扩展头链式解析（HOPOPTS/ROUTING/DSTOPTS 相同布局 `(hdrlen+1)*8`，FRAGMENT 固定 8 字节）：无扩展头直取端口、单一 OPT* → L4、OPT*→FRAGMENT→L4 均可穿越；更深（OPT*→OPT*→L4、隧道/ESP/AH）不穿越，dport 留 0 仍 parse 成功；**fragment 头：取其 nexthdr，仅首片（offset=0）提取 dport，非首片无 L4 留 0**；非 TCP/UDP 时 `dport=0`。
   - **v1.0.6：IPv6 无扩展头时也提取 dport**（此前只从扩展头分支取，普通 v6 TCP/UDP dport 恒 0——
     与 IPv4 分支契约不一致的潜伏 bug；当前 policy 不用 dport 故无实际影响，勿回退到旧版）。
   - **IPv4 分片（v1.1.4 审查加固）**：非首片（offset≠0）无 L4 头，dport 留 0 直接返回
     （与 IPv6 fragment 分支语义对齐）；此前会把分片数据偏移处误当 L4 头读（dport 当前
     未被 policy 使用，无实际影响，属防御性对齐）。
   - **IPv6 fragment offset 掩码必须 0xFFF8（v1.1.4 修正）**：IPv6 frag_off 布局是 offset 占
     高 13 位（bits 3-15）、M 标志是 bit 0。旧 `& 0x1FFF`（IPv4 的 IP_OFFMASK）会把 M=1 的
     首片（0x0001）漏判 dport，且 offset≥8192 的非首片（0x2000）误判为首片（越界检查兜底、
     parse 失败放行，无丢包）。v1.1.4 起 v6 的 TCP/UDP 分头读取 dport（与 IPv4 分支一致）。
10. **split.bpf.c 的 tun 读取**：`tun_ifindex()` 每次取 map（数组槽 0），无 tun 时 `TC_ACT_OK` 并计 `STAT_MISS_TUN`——mihomo 未就绪时保联网。
11. **cfg 为 NULL 的兜底**：policy.h 最后一步 `cfg ? cfg->default_verdict : SPLIT_VERDICT_TUN`——map 未初始化时按"默认代理"处理（docs/06 设计取舍：未知→代理是安全默认）。
    - **v1.2.0 热路径短路（性能）**：`map_cfg` 新增 `skip_uid_enabled`/`dom_enabled` 两个 flag，
      由用户态在 `rule_apply_all` 按 `cfg->nskip_uid>0` / `cfg->ndom_proxy+ndom_direct>0` 写入。
      运行时：
      - `skip_uid_enabled==0` → policy.h 第 1 步整段短路，且 split.bpf.c **不再调用
        `bpf_get_socket_uid`**（这 helper 相对昂贵，是热路径大头）。
      - `dom_enabled==0` → policy.h 第 4 步整段短路，省下 `map_dns4/6` HASH 查表 +
        `bpf_ktime_get_boot_ns()` 两次 helper/查顶。
      - **语义不变**：flag 仅短路"map 为空必然 miss"的分支；会命中的唯一条目恰恰在
        map 非空时，故短路等价。**agent 已验证：合并 proxy/direct 单循环会破坏优先级
        （proxy 需整段判定完才轮到 direct，LPM 遮蔽回溯下不可合并），故回退保持两遍**
        （见 dom.h 头注释）。
12. **TUN redirect 关键：`skb->queue_mapping=0`（v1.0.4 源码核实+真机验证，最重要）**：
    **从物理网卡 egress 用 bpf_redirect 进 tun 前，必须先设 `skb->queue_mapping = 0`。**
    - 根因：`tun_net_xmit()` 用 `tun->tfiles[skb->queue_mapping]` 找读队列（内核 `drivers/net/tun.c`）。
      Android 物理网卡（wlan0/rmnet）多队列，从它 egress redirect 来的 skb 继承其 queue_mapping
      （0~N-1），而单队列 tun 只有 `tfiles[0]`。queue_mapping>0 → `tfile=NULL` → **包被 drop**
      （tun tx_dropped 增长，mihomo read 读不到，utun_rx 不涨）。
    - WSL2 eth0 单队列（queue_mapping 恒 0）所以此前能读到，Android 多队列暴露此 bug。
    - **修复**：redirect 前 `skb->queue_mapping = 0`。真机验证：curl google 200、Play 可用、
      mihomo connections 出现 google 域名、proxy 数千计数。
    - 这即"补齐网络栈上下文"的确切含义——tun 设备需要的 queue_mapping 上下文。
    - **历史**：v1.0.3 曾误判"mihomo 无法接受 bpf_redirect 注入"，实为缺 queue_mapping。
      BPF_F_INGRESS 不可用（包不进 tun 读队列），必须 flags=0(egress) + queue_mapping=0。
13. **mihomo gso 与 eBPF redirect 不兼容（v1.0.4 实测）**：mihomo `gso:true` 使 tun 用
    `IFF_VNET_HDR`（flags 0x5001 = IFF_TUN|IFF_NO_PI|IFF_VNET_HDR；**无** IFF_MULTI_QUEUE，
    Alpha 源码核实 sing-tun `tun_linux.go` `open(name, vnetHdr)`，vnetHdr=options.GSO），
    读侧期望带 virtio_net_hdr 的包；eBPF 注入的
    裸 IP 包不兼容 → 连接失败（curl 000）。**必须保持 `gso:false`**（IFF_TUN|IFF_NO_PI, flags 0x1001）。
    gso 开/关切换时 mihomo 重建 utun，ifindex 变化，**必须重启 splitd 让 map_tun 重新对齐**。
14. **推荐 `stack: gvisor`（v1.0.5 实测结论）**：
    - system/mixed 栈在 eBPF 注入下**能工作**（源码核实：`processIPv4TCP` 把包 NAT 成
      `源=198.18.0.2 → 目标=198.18.0.1:tcpPort`，写回 tun → 内核路由 → mihomo 监听 198.18.0.1
      响应。抓包确认 NAT+SYN-ACK+代理节点 ESTAB 完整）。但**首连慢**（~1.4s），且之前"000 失败"
      是测试超时太短（8s）导致的误判。
    - gvisor 栈（纯用户态 netstack）**更稳定**：首连快（0.55s）、抖动小。实测吞吐受代理节点波动
      主导（gvisor 4.7MB/s vs mixed 1.6-6.9MB/s 不定），栈类型非决定性因素。
    - **结论：用 gvisor**（稳定优先）。若追求极端吞吐可试 mixed，但需接受首连 1.4s + 不稳定风险。
    - 必须 `gso:false`（vnetHdr 与 eBPF 裸 IP 注入不兼容）。
    - **mihomo 源码位置**：`github.com/MetaCubeX/mihomo/tree/Alpha`，TUN 核心在
      `listener/sing_tun/`（用 `github.com/metacubex/sing-tun` 库），system 栈 NAT 在
      sing-tun `stack_system.go` 的 `processIPv4TCP`。
15. **mihomo 默认 tun MTU=9000，必须显式 `mtu: 1500`（v1.0.6 源码核实）**：`server.go`
    `tunMTU == 0 → 9000`，sing-tun `configure()` 把 tun 链路 MTU 设 9000，gvisor 栈按此生成报文
    （MSS≈8960），但出站走物理网卡 1500 → 大包 GSO 分段 / DF 黑洞。样例配置与
    `setup-box-tun.sh` 已统一 `mtu: 1500`（或按实际 1480）。
16. **`auto-detect-interface: false`（eBPF 接管出口后）**：开着会强制 `NetworkUpdateMonitor`+
    `DefaultInterfaceMonitor`（netlink 依赖），Android 上是可避免的故障面；且 serve.go 会因此
    `New` 失败。eBPF 已管路由，样例配置/脚本已关。
17. **tun RX checksum offload + `CHECKSUM_PARTIAL` 注入（待真机核实）**：sing-tun `configure()`
    对 tun 无条件开 `ETHTOOL_SRXCSUM`。物理网卡 egress skb 常 `ip_summed=CHECKSUM_PARTIAL`（L4 校验
    留给网卡），`bpf_redirect` 到软件 tun（无 csum offload）后，主线上 `validate_xmit_skb` 会补算，
    但 Android 厂商内核行为不一，gvisor 收坏校验和会静默丢 → 间歇性建连失败。排查：`splitctl stats`
    + ethtool 对照；BPF 侧无 helper 可强制补算，只能靠真机验证。
18. **tun 地址默认 `198.18.0.1/30`（由 fake-ip 段派生，config/config.go）落在 `proxy_cidr4`
    `198.18.0.0/15` 内** —— 恰好把 DNS（`198.18.0.2`）送进 mihomo。**契约：改 mihomo
    `inet4-address` 时其网段绝不能落在 builtin local / CNIP / direct 规则内，否则 DNS 被内核直连断网。**
19. **域名分流（v1.1.0，dom.h + maps.h 的新 4 map）——编码与匹配契约**：
    - **编码**：`dns_entry.name` / `dom_key.data` 存**反转 + 小写**域名（"example.com" → "moc.elpmaxe"），
      后缀匹配因此变成 LPM 前缀匹配。用户态（loader.c `domain_to_rev`、dns.c `dns_learn_one`）
      负责反转+小写，内核**零反转逻辑**。规则支持 `*.` 通配（去通配存）与 FQDN 尾点。
    - **value 必须自记长度**：`map_dom_*` 的 LPM lookup 不返回命中前缀长度，`dom_rule.len`
      用于标签边界检查：命中后若 `len < remain` 则要求 `data[len] == '.'`（防 `xample.com`
      误匹配 `example.com`）。
    - **遮蔽与回溯（v1.1.1 重构，防 verifier 爆炸）**：LPM 只回最长前缀，边界检查失败
      时必须缩短再查。v1.1.0 用"找最后一个 '.' 跳标签"（`DOM_MAX_DEPTH=8` 循环），
      v1.1.1 实测发现该模式在 `-mcpu=v1` + clang 21 下触发 **verifier 状态爆炸**：
      - 内层"找点"循环（运行时边界 remain + 循环体内读栈数组）→ verifier 状态不收敛；
      - break 提前退出使循环变量终值未约束，嵌套回溯下更糟；
      - 显式 64 条线性分支（pos 状态机）也爆（每步 pos 值分叉）；
      - 逐字节拷贝循环（`for j<SPLIT_DOM_MAX: data[j]=...`）展开后每字节一个
        unknown 分支（`j < remain`），64 分支点组合爆炸；
      - 实测中间态：processed 1000001 insn / total_states 23k~112k 全超限 -E2BIG。
      - **最终方案**：① `__builtin_memcpy` 64B 无分支全量拷贝（LPM 只按 prefixlen
        位匹配，`key->data` 尾部字节不参与匹配、无需清零）；② 回溯改为**逐字节
        递减 prefixlen 再查**（`unroll(full)` 展开 64 份线性块，无回边无状态机）：
        LPM 只匹配前缀位、data 零拷贝，任何合法后缀规则必在 `prefixlen == 规则
        字节数` 的查询步以最长前缀命中。**副作用：>8 层标签的域名也能完整回溯
        （旧 8 层限制解除）**。WSL2 6.18 verifier 通过，且 veth 端到端实测
        （遮蔽规则 xample.com + com 规则）正确命中 com。**铁律：域名处理代码
        不得再引入"运行时边界循环 + 读栈数组"或"展开后带 unknown 分支"的模式。**
      - **无命中提前返回（v1.1.2 优化）**：规则要命中必先是"反转域名"的字节前缀，
        LPM 全长查询返回最长前缀——**任何一次 lookup miss 即 return 0**。常见
        "学得到 IP 但无规则命中"路径从 ≤64 次查询降为 1 次（热路径防放大）；
        遮蔽路径不受影响（miss 只可能在没有任何规则是当前前缀时出现，此时更短
        remain 也不可能命中）。
    - 层间只改 `prefixlen`，data 零拷贝；命中判定（标签边界）：
      `v->len == remain && remain == name_len`（规则=整个域名）或
      `v->len == remain && remain < SPLIT_DOM_MAX && data[remain]=='.'` 或
      `v->len < remain && v->len < SPLIT_DOM_MAX && data[v->len]=='.'`。
    - **expire 时钟同源（v1.1.9 改 BOOTTIME）**：`bpf_ktime_get_boot_ns()`（=CLOCK_BOOTTIME）
      与用户态 `clock_gettime(CLOCK_BOOTTIME)` 严格同源（含 suspend、熄屏/doze 时也推进）；
      内核查到过期条目视为未命中（不删，删除由 daemon 30s 节流 `map_dns_prune` 负责）。
      helper 需 **Linux ≥5.8**（GKI 5.10+ 满足；此前 ≤5.7 无承诺支持）。
    - **verifier**：`dom_rule.len` 是未约束标量，索引 `key->data[len]` 前必须显式
      `len < SPLIT_DOM_MAX`；`dns_entry` 指针跨后续 lookup 使用安全（只读）。
    - **真机 5.x GKI verifier 拒载"变量偏移读"（v1.2.0 实测两版演化）**：边界检查下标
      `v->len`/`remain` 是 map value 未约束标量（umax 255）。① 读栈数组
      `key->data[v->len]` → `invalid variable-offset read from stack var_off=0xff`；
      ② 改读 map value `de->name[v->len]` → `invalid access to map value off=264>80`。
      两版 WSL2 6.18 都过、5.10 GKI 都拒——旧 verifier 不把 `X < SPLIT_DOM_MAX` 条件
      限定传导到寻址寄存器 umax。**铁律：读 map value 必须显式掩码下标到
      `< SPLIT_DOM_MAX`**（`idx = X & (SPLIT_DOM_MAX-1)`；合法输入本就在 [0,63]，
       掩码不改语义，且让 verifier 确信 off+63 < value_size）。对"栈数组 + 未约束
       下标"一律改读**同内容的 map value** + 掩码，勿直接读栈数组。
       **关键（clang 折叠坑，v1.2.0 实测）**：掩码必须放在**循环顶无条件执行**
       （`idx = v->len & (SPLIT_DOM_MAX-1)`，不参与 v->len 后续上界比较）。若把掩码
       放进 `if (v->len < SPLIT_DOM_MAX) { idx = v->len & 63; ... }` 守卫内，clang 会据
       `v->len < 64` 判 `&63` 恒等并**折叠成无操作**，verifier 看不到掩码指令，仍按
       0-255 判越界拒载（反汇编验证：守卫内掩码 0 条 `& 0x3f`，无条件前置后 128 条）。
       铁律：**map value 变量索引的掩码，必须与上界守卫解耦、无条件前置**。
    - **统计**：命中记 `STAT_DOM_PROXY/STAT_DOM_DIRECT`；`splitctl dns` 看学习器状态。
    - **性能**：域名判定只在"IP 已被学习"的包上执行（一次 HASH 查 + 1 次 LPM；
       v1.1.2 起无命中即提前返回，此前为 ≤64 次 LPM），学习 map 空/未命中时开销 ≈ 一次查表。
20. **DNS 学习为什么在用户态（v1.1.0 架构决策，勿回退到内核 ingress 方案）**：
    DNS 响应解析（压缩指针跳转/多记录/0x20 大小写/分片）在 eBPF 里做有 verifier 与
    真机兼容风险；用户态 AF_PACKET（SOCK_DGRAM, ETH_P_IP, PACKET_HOST）无约束且
    splitd 本就 root 运行。**收益：内核侧无需新增 ingress hook**（下文"无 ingress 钩子"
    决策继续成立），学习器失败只是域名功能不生效，主分流（CNIP/规则）完全不受影响。
    - 学习器只收**入站**帧（PACKET_HOST）→ 物理网卡进来的 DNS 响应自然覆盖"查询直连"
      与"查询经 mihomo 转发"两条路径；fake-ip 响应（mihomo 写 tun 发出）不在入站侧，
      学不到（也不需要——fake-ip 段已走 proxy 规则）。
    - **不要对 AF_PACKET 做 blocking read**：fd 非阻塞 + daemon poll 驱动（fds[3]）。
21. **域名判定的正确性边界（已知缺口，文档同步）**：学习有滞后（首次连接走 IP 判定，
    DNS 学习后才生效）；CNAME 链中每条 A/AAAA 按**自身 owner name** 学习（v1.2.7 修正：
    旧方案全部归属到"查询名/CNAME 目标"，多 owner 应答会错配，见 userspace/dns/MEMORY
    第 12 条）；CDN 轮询 IP 与域名间映射可能短暂错配（TTL 过期自愈）；同 IP 多域名时
    后写入者胜出。
    - **超长域名截断边界（v1.2.8）**：>SPLIT_DOM_MAX 的域名只保留"最后 64 字节"后缀。
      用户态仅在截断点前一字节是 `.`（保留串为标签对齐后缀）时才学习，截断点落在标签
      中间时跳过——否则内核 dom.h 对"规则==整个存储名"（`len==name_len`，首检查不做边界
      校验）会把非对齐后缀规则误判为合法后缀（假阳性）。见 userspace/dns/MEMORY 坑 6。
22. **RAWIP 接口（蜂窝）解析（v1.1.5 真机修复，最重要之一）**：
    - **背景**：Android 蜂窝网卡 `rmnet_data*`/`rmnet_ipa0` 是 `ARPHRD_RAWIP`(519)，
      **tc egress 的 skb 没有以太网头，`skb->data` 直接就是 IP 头**（`dev->hard_header_len=0`）。
      旧 parse.h 硬按 `ethhdr` 读 `h_proto` → 把 IP 头前 2 字节（version/ihl，0x45xx）
      当 ethertype → 全部 parse 失败放行直连 → **蜂窝海外流量无法进代理**（WiFi 有以太网头
      所以正常）→ 用户症状"蜂窝数据无法上网"。真机诊断特征：`splitctl stats` 的
      `parse_err` 暴涨（1748/2763≈63%）、`proxy` 几乎不涨、WiFi 一切正常。
    - **机制**：新增 `map_rawip`（HASH, key=ifindex, value=__u8=1），用户态
      `map_rawip_sync` 在挂载/卸载/网络事件时把 **RAWIP(519) 且 IFF_UP** 的接口写入。
      parse.h 开头 `rawip_lookup(skb->ifindex)` 命中 → 按 `data[0]>>4`（4=IPv4, 6=IPv6）
      定 ethertype、`off=0` 直接解析 IP 头；未命中 → 走原以太网/VLAN 路径。
    - **边界**：RAWIP 分支读 `data[0]` 前先 `data+1 > data_end` 检查（铁律：先查再读）。
      非 IPv4/IPv6 的裸帧（如 ARP）→ ethertype=0 → 返回 0 放行不可判（不丢包）。
    - **坑**：`rmnet_ipa0`（Qualcomm IPA 聚合口）虽也是 519，但帧带 **RMNET MAP 封装头
      （非裸 IP）**，且数据面实际走 `rmnet_data*` 子接口——已加入 netlink.c 的
      exclude 列表（`"rmnet_ipa"`），不挂载（真机 tcpdump filter 都无法匹配其帧）。
    - **验证**：真机蜂窝下 `parse_err` 归零、`proxy` 计数增长、utun RX 涨、
      mihomo connections 出现 `type=Tun` 的应用连接（如 gms → android.googleapis.com）。

## 已知缺口（roadmap 对齐）
- VLAN 支持单层与双标签 QinQ（`VLAN_MAX_TAGS=2`）；三标签以上不剥为已知缺口；GRE/ESP 等隧道封装不识别（按外层 dst 判定）。
- 无 ingress 钩子（刻意不做，见 docs/06 取舍；域名学习的 DNS 响应解析在用户态 AF_PACKET 完成，见 20）。
- 域名：学习器只学 IPv4 传输的 UDP/53 响应（IPv6 传输/TCP/53/IP 分片不学）；**VLAN 标签帧不学
  （socket 只绑 ETH_P_IP，v1.2.8 文档化，见 userspace/dns/MEMORY）**；>SPLIT_DOM_MAX 域名截断点
  非标签边界不学（v1.2.8 防假阳性）；回溯 v1.1.1 起逐字节递减 prefixlen 查询（≤64B，无层数限制，旧 8 层限制已解除）。
- 无 tail call / 多程序。
- TUN 剥头问题已在 WSL2 实测验证为"自动剥头"，无需处理；Android 真机仍需最终确认。
- **tproxy 模式（v1.0.2 研究+实测，已否定）**：`tproxy` 目标内核只允许挂在 `NF_INET_PRE_ROUTING` 链（小米 GKI `nft_tproxy.c:301` `nft_chain_validate_hooks(ctx->chain, 1 << NF_INET_PRE_ROUTING)`），**不支持 OUTPUT/本机出站方向**。WSL2 6.18 实测 output hook 添加 tproxy → `Operation not supported`。即使 eBPF 在 egress 打 mark，也没有 netfilter 目标能把本机出站流量转给 mihomo。**结论：tproxy 模式不可行，保持 TUN 主线。** 详见 docs/06 "tproxy 模式"节。

## 验证
- 编译：`make -C kernel bpf`（需 Linux + clang>=12）。
- 冒烟：`make -C kernel validate`（需 root/bpffs）。
- 单测：tests/unit 仅骨架，无 BPF 端到端单测。
