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
2. **判定顺序固定（v1.4.0 起 7 步，policy.h 注释即真相）**：uid 白名单 → **v6 且 ipv6_classify=false → 直连**（第 2 步，须在规则前，否则 proxy6/direct6 仍命中，v1.1.1 修正）→ 内置本地段 → proxy 规则 → direct 规则 → CNIP → default_verdict。**改顺序 = 改分流语义，必须同步 docs/01、docs/02、README。**（v1.4.0 移除原第 4 步域名规则，见 19。）
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
7. **stats_inc 用 `key & (STAT_MAX - 1)` 防越界**：`STAT_MAX=16` 必须是 2 的幂。key 编号被 `daemon.c ctl_stats` 的名字数组引用，**不能重排/插入**（可追加）。`STAT_DIRECT_V6=9`（v6 且 `ipv6_classify=false` 的"配置性直连"，与 CNIP 直连 `STAT_DIRECT_CN=1` 分开计，见 policy.h 第 2 步；v1.4.0 随域名统计删除后自 11 重排为 9——**仅运行时统计 map，无持久 ABI，重排安全**）——**追加 key 必须同步 daemon.c names 数组**。
8. **LPM_TRIE 语义**：radix.h 查询时 prefixlen 填 128/32（查最具体），内核自动最长前缀回溯；key 必须整体清零（`{ .prefixlen = 32 }` 其余零）。值统一 `__u8 =1`（成员标记，不承载意义）。
9. **parse 边界（v1.4.0 起仅 L3）**：VLAN 支持至双标签 QinQ（`VLAN_MAX_TAGS=2`，0x8100/0x88a8，
   常量上界 + 全展开保证 verifier 可证）；rawip 蜂窝无 L2 路径（见 20）。parse 只提取
   `family + dst`（policy 判定的全部输入）；任何越界/未知返回 0（不可判，上层放行）。IPv4
   ihl 校验保留：`ihl<20` 或 `off+ihl>data_end` → parse 失败直连（畸形头边界维持不变）。
   - **L4 dport/proto 解析已随 v1.4.0 删除（性能审查 R1）**：policy 纯 L3/UID 判定，L4 解析
     （IPv4 分片检查、IPv6 扩展头链 HOPOPTS/ROUTING/DSTOPTS/FRAGMENT、`split_ipv6_frag_l4`）
     是无消费者的热路径死代码，已整段删除。`struct split_pkt` 的 proto/dport 字段保留
     （ABI 稳定）但不再填充，勿假定含有效值。
   - **历史（坑不复存在，勿回退旧解析）**：v1.0.6 曾修"IPv6 无扩展头时不提取 dport"、
     v1.1.4 曾加固 IPv4 分片（非首片无 L4）与 IPv6 fragment 掩码（必须 0xFFF8）——均属当时
     "防御性对齐"，policy 从未消费 dport。删除后边缘包（L4 越界/IPv4 非首片/深层扩展头）
     从"parse 失败→直连"改为"按 L3 正常裁决"（两者都不丢包，L3 判定更正确）；
     parse_err 计数相应下降。
10. **split.bpf.c 的 tun 读取**：`tun_ifindex()` 每次取 map（数组槽 0），无 tun 时 `TC_ACT_OK` 并计 `STAT_MISS_TUN`——mihomo 未就绪时保联网。
11. **cfg 未初始化的兜底（v1.3.1 修正契约）**：map_cfg 是 **ARRAY map，lookup 永不返回
    NULL**（未写入时返回全零元素，default_verdict=0=直连）——旧注释"map 未初始化时按默认
    代理（未知→代理是安全默认）"并不成立。现以 loader `map_set_cfg` 写入的
    `bpf_trace_enabled==1` 作为"已初始化"哨兵：policy.h 对 `!cfg || cfg->bpf_trace_enabled==0`
    一律回落 `default_cfg`（TUN 安全默认）。map_set_cfg 失败时 rule.c 显式 LOG_ERROR。
    - **热路径短路（性能）**：`map_cfg` 的 `skip_uid_enabled` flag，由用户态在
      `rule_apply_all` 按 `cfg->nskip_uid>0` 写入。运行时：
      `skip_uid_enabled==0` → policy.h 第 1 步整段短路，且 split.bpf.c **不再调用
      `bpf_get_socket_uid`**（这 helper 相对昂贵，是热路径大头）。
      - **语义不变**：flag 仅短路"map 为空必然 miss"的分支；会命中的唯一条目恰恰在
        map 非空时，故短路等价。**agent 已验证：合并 proxy/direct 单循环会破坏优先级
        （proxy 需整段判定完才轮到 direct，LPM 遮蔽回溯下不可合并），故回退保持两遍**。
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
19. **域名分流（v1.1.0 引入）——随 v1.4.0 整模块移除**：内核 `map_dns4/6` + `map_dom_proxy/direct`
    4 map、`dom.h`、policy 第 4 步、用户态 `userspace/dns/` 学习器与 `dns` ctl 命令全部删除，
    policy 判定回到 8 步前身（现 7 步，见 2）。**勿回退**：域名分流与 mihomo 域名规则体系重叠，
    且 AF_PACKET 学习器是最大用户态开销与安全面。其沉淀的 verifier 教训仍适用于任何
    "读 map value 变量下标"的代码，保留如下：
    - **读 map value 变量下标必须显式掩码到 `< 2 的幂`**：`X < LIMIT` 上界比较不会传导到
      寻址寄存器 umax，真机 5.x GKI verifier 报 `invalid access to map value` 拒载；
      合法输入本就在 [0, LIMIT-1]，掩码不改语义。
    - **掩码必须无条件前置（clang 折叠坑）**：`idx = X & 63` 放进 `if (X < 64)` 守卫内会被
      clang 判恒等折叠成无操作（反汇编 0 条 `& 0x3f`，无条件前置后 128 条），verifier 看不到
      掩码仍按 0-255 判越界拒载。铁律：**掩码与上界守卫解耦、无条件前置**。
    - **勿对栈数组做变量偏移读**（`key->data[X]` → `invalid variable-offset read from stack`）；
      改读同内容的 map value + 掩码。
20. **RAWIP 接口（蜂窝）解析（v1.1.5 真机修复，最重要之一）**：
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
- 无 ingress 钩子（刻意不做，见 docs/06 取舍）。
- 无 tail call / 多程序。
- TUN 剥头问题已在 WSL2 实测验证为"自动剥头"，无需处理；Android 真机仍需最终确认。
- **tproxy 模式（v1.0.2 研究+实测，已否定）**：`tproxy` 目标内核只允许挂在 `NF_INET_PRE_ROUTING` 链（小米 GKI `nft_tproxy.c:301` `nft_chain_validate_hooks(ctx->chain, 1 << NF_INET_PRE_ROUTING)`），**不支持 OUTPUT/本机出站方向**。WSL2 6.18 实测 output hook 添加 tproxy → `Operation not supported`。即使 eBPF 在 egress 打 mark，也没有 netfilter 目标能把本机出站流量转给 mihomo。**结论：tproxy 模式不可行，保持 TUN 主线。** 详见 docs/06 "tproxy 模式"节。

## 验证
- 编译：`make -C kernel bpf`（需 Linux + clang>=12）。
- 冒烟：`make -C kernel validate`（需 root/bpffs）。
- 单测：tests/unit 仅骨架，无 BPF 端到端单测。
