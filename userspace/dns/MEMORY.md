# userspace/dns — 记忆文档（改本目录代码前必读）

> 覆盖：`dns.{c,h}`。职责：AF_PACKET 抓 DNS 响应 → 解析 → 把 `IP→域名` 写进
> `map_dns4/6`（内核 egress 域名判定 + 域名规则表的前置数据）。
> v1.1.0 新增。内核侧对应 `kernel/bpf/dom.h`，编码契约见 `kernel/include/split_bpf.h`「域名分流」。

## 接口契约（dns.h）
- `dns_learn_open(dl, ctx)`：AF_PACKET `SOCK_DGRAM` + `htons(ETH_P_IP)`，bind 所有接口
  （ifindex 0）+ PACKET_HOST（默认只收发给本机 MAC 的帧）。**失败返回 -1 不致命**
  （主分流不受影响，daemon 只 WARN）——调用方必须容忍 dl.fd = -1。
- `dns_learn_poll(dl)`：非阻塞读尽（EAGAIN 停），返回处理包数；由 daemon poll 驱动，
  **绝不能阻塞**（O_NONBLOCK 已设）。
- `dns_learn_close(dl)`：close fd 并置 -1。

## 关键实现与坑
1. **为什么在用户态**：DNS 解析（压缩指针/多记录/0x20 大小写）在 eBPF 里做有 verifier 与
   真机兼容风险；用户态 AF_PACKET 无约束。**换来内核侧零新增 hook**（kernel/bpf/MEMORY 20）。
2. **只学"入站"的响应**：PACKET_HOST 只收物理网卡进来的帧——覆盖两条路径：查询直连
   （响应从网卡进）与查询经 mihomo 转发（mihomo 从网卡发出的查询，响应同样从网卡进）。
   fake-ip 响应（mihomo 写 tun 发出的包）不在入站侧，学不到——也不需要（fake-ip 段已走
   proxy 规则）。**别为了"覆盖更多"去开 PACKET_OUTGOING/混杂**。
3. **响应判定**：UDP + `sport==53` + DNS flags `QR=1`；不校验 checksum（内核已验）。
   宽松条件是"源端口 53"——本机自建 DNS（dnsmasq 等）的响应同样能学（也合理）。
4. **解析纪律（用户态也要防恶意包）**：所有指针/长度带界检查；压缩指针跳转 ≤ DNS_MAX_JUMPS(8)
   防环、跳转目标必须落在消息内；answer 记录 ≤ DNS_MAX_RR(64)；名字超缓冲即放弃该包。
   - **question 区同样有上限（v1.1.4 加固）**：`qd` 最大 65535 且此前无循环上限，恶意 64KB
     UDP/53 响应单包可触发约 1.3 万次 `dns_parse_name` 拖慢 daemon；`qd > DNS_MAX_QUESTIONS(16)`
     **整包放弃**（不能只跳过前 16 条——游标错位会解析出垃圾映射）。
   - **消费位置只在"名字字段内"更新（v1.1.1 修复）**：`dns_parse_name` 的返回位置是字段结束处
     （指针后/根后），**跳转目标上的标签/根读取不得覆盖它**——此前指针跳转后 `consumed` 被目标
     链上的读取覆盖，answer name 为压缩指针（最常见）时错位解析，A/AAAA 几乎全漏学。
5. **分片**：`frag_off & 0x3FFF != 0`（offset≠0 或 MF=1）的包直接跳过（不做重组，已知缺口）——
   大响应（EDNS0 大 RRset 或 TCP 才能装下的响应）漏判属预期。v1.1.1 起连 MF=1 的首片也跳过
   （首片虽有 L4，但后续片无法拼合，漏判更安全）。
6. **编码契约（字节级，勿改）**：
   - 名字**正序组装时转小写**（0x20 随机化），学进 map 前取**后缀**（最后 SPLIT_DOM_MAX
     字节）并**反转**（`rev[i] = name[nlen-1-i]`）——与 loader 的 `domain_to_rev`、内核
     dom.h 完全一致。
   - **v1.2.8（审查修复）超长域名截断的边界**：仅当截断点前一字节是 `.`（保留后缀是
     标签对齐后缀）才学习；截断点落在标签中间（保留段前一字节非 `.`）时**跳过该条目**
     ——内核 dom.h 对"规则==整个存储名"（`len==name_len`）的命中不做首边界检查，截断串
     首边界含混时会把非对齐后缀规则误判为合法后缀（假阳性）。跳过只是漏判该域名（回落
     IP 判定），绝不写入边界含混的条目。
- TTL=0 不学；expire_ns = `now_ns()` + TTL×1e9（**CLOCK_BOOTTIME，与内核
      `bpf_ktime_get_boot_ns` 同源**）；**TTL 上限 7 天（v1.1.2 clamp）**：防恶意/异常
     TTL（如 0xFFFFFFFF ≈ 136 年）长期占满 4096 容量的学习 map 导致新学习 skipped。
   - A → family=AF_INET，key=RDATA 前 4 字节（网络序直接拷贝）；AAAA → AF_INET6，16 字节。
7. **只学 IPv4 传输**（socket 只绑 ETH_P_IP）：IPv6 传输的 DNS 响应不学（已知缺口；
   AAAA 记录在 IPv4 传输的响应里正常返回，覆盖绝大多数场景）。
8. **失败语义**：`map_dns_set` 失败（HASH 满等）→ `skipped++` 静默；解析失败 → 直接 return
   该包。**任何失败都不影响联网**（内核域名未学到 → 回落 IP/CNIP 判定）。
9. **禁止把字节数组强转为 struct 指针（v1.1.3 加固）**：`dns_process_ip4` 的 `buf` 是
   `read` 所得的字节数组（对齐只有 1），`(const struct iphdr *)buf` 是未对齐访问 = C UB
   （x86/aarch64 实测无害，但 ARM32 会 SIGBUS）。IP/UDP 头一律 `memcpy` 到本地对齐副本再读字段。
   同样地：读 `buf+i` 处的整数字段（如 DNS 头的 qd/an）用字节拼接，不要强转。
10. **读缓冲改堆分配（v1.1.9）**：`dns_learn_poll` 的 `uint8_t buf[65536]` 改 `malloc(65536)`
    （读后 `free`）——64KB 不上 daemon 主线程栈（Android 若用较小栈空间线程承载有风险）。
    只读一次性包，临时 malloc 开销可忽略，换栈安全。
    - **v1.2.0（H3 优化）**：改为 `dns_learn_open` 里一次性分配、存 `dl->rbuf`，`poll` 复用、
      `close` 释放——不再每轮 malloc/free 64KB（高频 DNS 下省分配开销）。分配失败与 socket 失败
      同语义：不致命、域名功能不生效。
11. **cBPF socket filter 已移除（v1.2.7 审查 M1，勿回退）**：此前用 cBPF 在内核侧预过滤
    UDP/53 以"减少用户态唤醒"，但它按【固定 14B 以太网头偏移】读字段，对 Android 蜂窝
    接口（rmnet_data*，ARPHRD_RAWIP 无 L2 头）偏移错位——加载成功却把蜂窝 DNS 响应在
    内核侧**静默滤掉**，域名学习在蜂窝上长期失效（真机目标平台）。cBPF 无法同时兼容
    Ethernet 与 RAWIP 两种布局。**现放弃内核预过滤**，全部过滤交给 dns_process_ip4
    （version==4 && protocol==UDP && sport==53 && 非分片），两种布局都正确。
    代价：AF_PACKET socket（bind 时已按 ETH_P_IP 协议过滤到 IPv4 帧）每收 IPv4 入站帧
    唤醒 daemon 一次。DNS 学习非关键路径，代价可接受；若需再省 CPU，改为按接口分别
    bind socket 过滤。移除后**不再依赖 `<linux/filter.h>` 与 cBPF 兜底定义**（此前
    v1.1.9 的跳转偏移修正、v1.2.0 的 libbpf 头遮蔽兜底均随之失效，勿再引回）。
    - 历史（勿回退的理由参考）：v1.1.9 曾修正 cBPF 跳转偏移（jt/jf 按"相对下一条指令"
      计数），v1.2.0 曾补 libbpf 内部 filter.h 遮蔽下的 cBPF 定义——这些只服务于已移除
      的 filter，新代码一律用户态过滤。
12. **CNAME 链支持（v1.2.0 引入 / v1.2.7 归属修正）**：answer 区的 A/AAAA 记录按其
    **自身 owner name**（dns_process_ip4 每轮解析出的 `name`）学习——规范 CNAME 链里
    A 记录的 owner 本就是最终规范名，链上每个名字都拿到自己该拿的映射，无需追踪
    "查询名→规范名"（旧 cur_name 方案）。**修正原因（v1.2.7 审查 H1）**：旧方案把
    answer 区所有 A/AAAA 都归属到 cur_name（查询名或 CNAME 目标），当应答含多个不同
    owner（CDN 多域名混答等）时错误归属，域名规则误命中/漏命中。CNAME 记录本身只推进
    游标（p = rdata + rdlen，兼容 rdlen 与名字编码长度不一致的畸形应答）。仅支持单次
    响应内的链（不查外部）；超 `DNS_MAX_RR` 截断。

## 已知缺口（roadmap）
- IPv6 传输 / TCP(53) / IP 分片不学；同 IP 多域名 → 后写入者胜出（HASH 覆盖）；DNS 服务器
  自定义端口（非 53）不学。
- **VLAN 标签帧不学（v1.2.8 显式文档化）**：socket 只绑 `ETH_P_IP`，802.1Q/802.1AD 帧外层
  ethertype 是 0x8100/0x88a8 不命中 → VLAN 内 DNS 响应漏学。目标平台（Android 蜂窝 RAWIP +
  常规 WiFi）无 802.1Q 场景，属预期；修需要加第二路 ETH_P_8021Q socket（无法在此平台实测，
  故以文档化替代，勿未经真机验证引入）。
- 超长域名（>SPLIT_DOM_MAX）若截断点非标签边界不学（v1.2.8，防假阳性，见坑 6）。
- CNAME 链的别名自身（无 A 记录）不学 IP；链上每个 A/AAAA 记录按自己 owner 学（跨响应/多级
  无外部跟查）——覆盖绝大多数 "CDN 别名"场景；无 SNI 学习（HTTPS 未预解析域名首连走 IP
  判定——TTL 内第二次连接起才生效）。

## 验证
- Linux：daemon 起来后 `splitctl dns` 看 `learned` 是否随 `nslookup` 增长；
  `splitctl stats` 看 `dom_proxy/dom_direct` 计数。
- 单元级：可在宿主上把构造好的 DNS 响应包直接喂给 `dns_learn_poll`（读函数非阻塞，
  可用 UDP socket + AF_PACKET 对打验证，tests/unit 骨架）。
