# 01-ARCHITECTURE（总体架构）

> 本文回答三个问题：**谁在什么时候把流量带去哪儿**、**为什么这么设计**、**有什么已知边界**。

## 1. 网络拓扑

```
                 +----------------------------------------------------+
                 |               Android / Linux 主机                  |
                 |                                                    |
 应用(App)        |        +----------+ 路由(Linux)     +---------+     |
 socket ────────►|──────► | 协议栈   ├─────────────────►│ 物理网卡 │────► 互联网
                 |        +----------+                 │ wlan0   │     |   ▲
                 |            │                        +----┬----+     |   |
                 |            │ egress 进入 BPF             │ direct(CN) │  |
                 |            ▼                             │             |  |
                 |    +--------split.bpf.o (tc egress) ─────┘             |
                 |    │ 判定: CNIP→直连 / 其它→代理                       |
                 |    │ 需要代理: bpf_redirect(tun0)                     |
                 |    └───────────────▲────────────────┐                  |
                 |                              │                        |
                 |                    +─────────┴─────+       (mihomo 读) |
                 |                    │  tun0 (TUN）   │       (mihomo 写) |
                 |                    +────────────────+                  |
                 |                          ▲                            |
                 |                    需要代理的流量                       |
                 |                    -----------------> mihomo (代理内核)  ◄─► 海外服务器
                 +----------------------------------------------------+
```

只画了一条物理链路的简单形态；真机上有 **wlan0 / rmnet_data0 / eth0** 等多出口，
框架会自动给所有可用出口挂同一份 BPF 程序（见 `userspace/loader/iface.c`）。

## 2. 数据流逐包拆解（一个浏览器的 youtube 请求）

```
客户端 SYN → dst 172.217.* (Google, 非 CNIP)
  1. 内核路由: 默认路由 → wlan0  egress
  2. tc-egress filter 命中 split 程序:
       parse:  以太网/IP 头、L3 dst、uid
       policy:  非 CNIP、非直连白名单 → 代理
       skip:    uid 非 mihomo 自身
       exec:    bpf_redirect(tun0_ifindex, 0)  // 引导报文“从 tun0 发出”
  3. tun0 作为字符设备，mihomo 从 fd 读到此 SYN
  4. mihomo 规则解析 → 该节点走代理 → 自身套接字连海外服务器(uid 已在白名单,
     再经 wlan0 egress 时被 skip → 直连可出，不回环)
  5. 远端回包 → mihomo 写入 tun0 → 内核按“本地投递”交付应用
```

CN 流量（如百度）路径：
```
包头 dst = 220.181.*(百度, CNIP) → `cnip=on` 时 tc egress 判定 DIRECT → TC_ACT_OK

> `splitctl cnip off` 会临时跳过 CNIP 这一步，百度等地址随后按 `default.verdict` 裁决；CNIP map 仍继续更新，重启 splitd 恢复开启。
→ 原样从 wlan0 发出，从头到尾没有经过 mihomo，延迟=直连。
```

## 3. 为什么要“转发到 TUN”而不是“socks5/端口转发”

| 方案 | 优势 | 劣势 | 结论 |
|---|---|---|---|
| bpf_redirect(tun0) | 保丢重、支持 TCP/UDP/ICMP 全协议、无端口冲突、代理内核无需改造 | 需要 mihomo 开启 TUN 模式 | ✅ 主线方案 |
| 改 dst IP+端口，让流量拐入本机 socks5 端口 | 实现简单 | 只能 TCP/UDP、四层改写复杂、UDP 关联性差、NAT 麻烦 | 备选 |
| fwmark + ip rule + iptables REDIRECT | 成熟 | 依赖 iptables/netfilter，安卓厂商定制多 | 不选 |

## 4. 为什么不用 XDP

- XDP 在 egress 侧一般靠驱动或 `attaches to` / tc 前 drv，真机网卡驱动不在你不用。
- tc (sched_cls) 挂载方式 Android 内核直至 GKI 都有（netd 已使用），确定性强。
- XDP 只支持 egress 定向、且偏 ＤＲＶ 前，不适合"看全局 egress 后采取动作"。

## 5. 安全（BPF verifier）边界的自检清单

- 所有读包都先 `data + offset + len <= data_end`（parse.h 内联守卫，见 parse.h:66/97/101/109；不存在独立的 `skb_dlen` 函数）。
- LPM trie key 构造用栈上结构、大小合法。
- 单个程序不超过逻辑复杂度上限（回归验证器规则：不取未定义值、无循环、栈≤512B）。
- 出错一律 `return TC_ACT_OK`（放行），**绝不在不明确时丢包**——避免断网打不开。
- 只在 uid、cidr 命中后 redirect。

## 6. 已知边界 / 限制（诚实清单）

1. **fake-ip 模式无法内核 IP 分流**：fake-ip 下应用收到的目标 ip 是 198.18.x，分类器
   无法知道域名。解决：a) 用 `redir-host`（推荐）b) fake-ip + 在“always proxy”中加
   fake-ip 段（海内外全进 mihomo，等于没分流, 仅兜底）。
   详见 docs/03-ANDROID.md 的“fake-ip 冲突”章节。
2. **ICMP**：mihomo 的 gvisor/system 栈对部分 ICMP 报文处理有限；`ping` 到非 CNIP 可能
   不通属于可预期行为。
3. **本地回环**：`lo` 不受影响。
4. **vlan/多标头**：parse 支持单层与双标签 QinQ VLAN（0x8100/0x88a8，`VLAN_MAX_TAGS=2`）
   跳过外层头；三标签以上不再剥，ethertype 不匹配 IP/IPv6 → 解析失败 return 0，按默认放行。
5. **TUN 设备命名冲突**：若 mihomo 自带 utun 名称冲突请改 config（同步 split.yaml `tun_device`）。
6. **TUN 以太网头（已实测）**：tc egress 的 skb 带 L2 头，但 `bpf_redirect(tun,0)` 到
   /IFF_TUN 设备时，tun xmit 会**自动剥掉以太网头**，mihomo 读到的是裸 IP（WSL2 实测验证：
   收到的包首字节为 `45`=IPv4，无 MAC 头）。**不要**再用 `bpf_skb_adjust_room` 手动剥头——
   部分驱动 `skb_mac_header_len` 元数据为 0/错位，会把 IP 头前 14 字节吃掉，损坏报文（已回滚）。

## 7. 调试图：内核计数 map（map_stats）

> 编号对应 `split_bpf.h` 的 `enum split_stats_key`（只可尾部追加，不可重排）。

| key | 含义 | 期望速查 |
|-----|------|----------|
| 0 STAT_TOTAL | 进入 eBPF 的包总数 | >0 |
| 1 STAT_DIRECT_CN | CNIP 命中直连（仅 `cnip=on`） | curl 百度后 +1 |
| 2 STAT_DIRECT_RULE | 直连判定类（内置本地∪direct 规则∪默认直连共用，v1.4.6 语义澄清） | 内网/本地流量 +1 |
| 3 STAT_PROXY | 进代理（proxy 规则/默认） | curl 海外后 +1 |
| 4 STAT_SKIP_UID | 白名单跳过 | mihomo 自己发包 |
| 5 STAT_PARSE_ERR | 解析失败（放行） | 应为 0 但允许少量 |
| 6 STAT_REDIRECT_ERR | 重定向失败 | 恒 0 为佳 |
| 7 STAT_DROPPED | 丢弃（不应发生） | 恒 0 |
| 8 STAT_MISS_TUN | 想代理但 tun 未就绪（放行） | 启动初期可出现；**持续增长 = mihomo TUN 消失，v1.2.9 watchdog 自愈（见 USAGE.md Q8）** |
| 9 STAT_DIRECT_V6 | v6 且 ipv6_classify=false 的配置性直连 | 关闭 v6 分类后 +1 |

`splitctl stats` 按 per-CPU 汇总打印。

> 下一步：阅读 `docs/02-MODULES.md`，然后按模块逐文件查看内核代码 `kernel/bpf/`。