# 06-ROADMAP — 路线图与已知缺口

> 这里如实记录"尚未实现 / 计划中的部分"，避免使用者误以为已经完备。

## 已实现（本版）

- [x] 内核：tc egress 分类 + `bpf_redirect(tun0)` 转发
- [x] CNIP(IPv4/IPv6) LPM_TRIE 分流
- [x] proxy/direct 规则段 + UID 白名单
- [x] 内置本地段（回环/链路本地/组播）
- [x] 用户态：splitd 守护 + splitctl 命令 + netlink 网络跟随
- [x] CNIP 文本导入（文件/URL）
- [x] 配置解析与示例（redir-host / fake-ip 两套 mihomo 配置）
- [x] Android：Magisk 模块骨架 + sepolicy + 降级路径
- [x] **域名分流（v1.1.0）**：用户态 AF_PACKET 学 DNS 响应（IP→域名）+ 内核
  `map_dom_proxy/direct` 域名后缀规则（反转 LPM 匹配，优先级高于 IP 段规则）
- [x] **熄屏/doze 自愈（v1.1.7）**：daemon 主循环 5s 节流 `iface_reconcile`（netlink 事件漏收
  时自动重建挂载，且 `split_attach_iface` 经 `bpf_tc_query` 核验 filter 真实存在、丢失即重挂）
  + `scripts/split-watchdog.sh`（splitd 进程死亡后按同参数拉起，配停止闸）
- [x] **文档：架构 / 模块说明书 / 安卓兼容 / 配置 / 术语**
- [x] **v1.1.9 审查收敛**：DNS 过期时钟改 BOOTTIME（熄屏也推进，`bpf_ktime_get_boot_ns`，需内核 ≥5.8）；
  `iface_reconcile` 全程快照复用去重复 scan；`splitctl` 的 `-d` 语义改为 debug、splitd 路径改 `-s`；
  日志路径收敛 `split_log_path()`；补 `.gitignore`（构建产物/敏感配置不入库）

## 缺口（诚实清单）

| 项 | 状态 | 说明 |
|---|---|---|
| `del-rule`（在线删规则） | 已实现 | `bpf_map__delete_elem` 走 LPM_TRIE delete；cli → daemon 协议已支持 |
| TUN 以太网头 | 无需处理 | WSL2 实测：`bpf_redirect` 到 /IFF_TUN 时 tun xmit 自动剥 L2，mihomo 读到裸 IP；手动 `bpf_skb_adjust_room` 反而会损坏 IP 头（已回滚） |
| rule map 全量重建 | 已实现（v1.0.5） | `reload` 用 `map_rule_clear` 先清空再全量写（幂等），删减配置无需重启；CNIP 的 `reload-cnip` 同理（`map_cnip_clear`） |
| VLAN 双层/多标签 | 双层（v1.1.x）| parse 跳至双标签 QinQ（`VLAN_MAX_TAGS=2`）；三标签以上等 roadmap |
| ICMP 进 mihomo | 内核侧 OK | mihomo 侧对部分 ICMP 支持有限（见 FAQ Q 章节） |
| ingress 钩子（观察/统计入站） | 未做 | 为省性能刻意不做 |
| tproxy 模式（`mode: tproxy`） | 不可行 | 内核硬限制：tproxy 目标只支持 PREROUTING，不支持本机出站方向（见"tproxy 模式"节） |
| eBPF 劫持 → mihomo TUN | 已解决 | `skb->queue_mapping=0` 修复（v1.0.4），真机 curl 200 + Play 可用 |
| 原生 Android App（UI 开关） | 未做 | 现在 root shell / Magisk 方式（android/app/README）；**KernelSU WebUI**（webroot/）已含：状态/stats/DNS 学习器/在线规则列表与增删/日志/配置编辑/版本号（v1.2.2） |
| BPF 单元测试套件 | 骨架 | tests/unit/README 有规划 |
| DNS 拦截（domain 级分流） | 已实现（v1.1.0） | 用户态学 DNS 响应（IP→域名）+ 内核后缀规则；限制：只学 IPv4 传输的 UDP/53、无分片重组、**CNAME 链支持（v1.2.0）**、首连有学习滞后；超大域名列表请交给 mihomo 规则（fake-ip 模式） |
| 域名规则在线增删（add-domain/del-domain） | 未做 | 目前走 config + `splitctl reload` 全量应用 |
| 自动选择 tun 设备 | 半自动 | 必须与配置名一致；失败会明确报错 |
| 多用户（工作资料）UID 处理 | 配置化 | 需手动加 uid |

## 路线

```
v1.0（2026-08 基线）  骨架完整可用：内核分流 + mihomo 转发 + 安卓模块
v1.0.1                在线规则增删（rule_del 已实现）+ NDK 交叉编译文档
v1.0.2                修复 WSL2 实测发现的 3 个 bug：netlink bind、config 尾空白、
                      TUN 剥头改"自动剥头"（移除 bpf_skb_adjust_room）
                       真机(小米5.10 GKI+KernelSU)实测：-mcpu=v1、SPLIT_SOCKET、分流验证通过
                       tproxy 形态 A 实测否定（tproxy 只支持 PREROUTING，不支持本机出站）
                       端到端接入 box mihomo TUN：CN 直连/海外代理全链路验证通过
                       真机再修 2 bug：config 布尔解析(parse_bool)、utun 误挂回环(exclude)
v1.0.3                TUN redirect 研究：曾误判"mihomo 无法接受 bpf_redirect 注入"
v1.0.4（当前）        **根因找到并修复：skb->queue_mapping=0**（tun 多队列索引越界→drop）。
                      真机验证：curl google 200、Play 可用、内核 CNIP 分流 + mihomo 全链路打通
v1.1.0                域名分流：用户态 DNS 学习（AF_PACKET）+ 内核域名后缀规则表
v1.1.9                安全/健壮性审查轮次（CNAME 预过滤修正、逐位解析加固等）
v1.2.0                运行时规则（add-rule/del-rule）跨 reload 保留；dns 缓冲复用；CNAME 链学习
v1.2.1                mihomo 重载配置重建 utun 后即时对齐 map_tun（网络事件/reload 两处触发 tun_sync）
v1.2.3                 hijack 判定修复：route_tun_hijacked 的 RTA_OIF 遍历 payload 残值 bug
                      （非 main 表 default-via-tun 误判 main 表）+ rule_steals_table 误判
                      "内核恒带占位属性"（FRA_SUPPRESS_PREFIXLEN=-1 / PROTOCOL / PRIORITY）导致
                      真实无条件劫持漏判；新增 clean-mihomo-residue.sh 清理 mihomo auto-route 残留
v1.2.4                 tun_sync 快照权威复核 + 降级快重试：修复 mihomo 重载配置重建 utun 时，
                      事件快照恰拍在 DELLINK/NEWLINK 间隙导致"ip link 可见 utun 但 map_tun 误置 0、
                      代理完全失效"的假象（快照缺 utun 时强制重扫复核；utun 缺失降级期间
                      心跳 1s→300ms，事件漏收时恢复 ≤300ms）
v1.2.5                 tun 名字漂移兜底：mihomo 重载后新 TUN 可能不再叫配置名。精确匹配
                      （含复核）仍缺时按"比最近一次有效 ifindex 更新 + IFF_UP + TUN 类名字"
                      找候选自动对齐并 WARN；"不存在"日志附带 TUN 类接口清单便于诊断
v1.2.6                 源码修正 + 按类型兜底：mihomo Alpha listener/sing_tun/sing_tun.go 核实——
                       Linux 回退名是 InterfaceName 默认 "Meta"（device 为空时），并非 v1.2.5
                       假设的 tunN。tun_name_like 直接认 "Meta"；tun_find_drift 追加
                       ARPHRD_NONE（L3 TUN）类型兜底，覆盖重载后落到任意 device 名（含 WebUI
                       把 device 改空），排除 wg/tailscale 防误挂
v1.2.7（当前）        审查修复轮次：①DNS 学习器移除 cBPF 内核预过滤（RAWIP 蜂窝偏移错位致
                       静默漏学，改用户态全过滤，Ethernet/RAWIP 双布局正确）②A/AAAA 记录按
                       自身 owner 归属（旧方案归属到查询名/CNAME 目标，多 owner 应答错配）
                      ③poll 错误事件（POLLERR/HUP/NVAL）显式消费防忙循环，ctl listen/netlink
                       watch 自动重建、DNS 学习器降级④list-rules 客户端断连即中止枚举
                      ⑤status 增 tun 缺失 WARN（map_tun=0 静默降级可见）⑥route_tun_hijacked
                       路由表集合容量 16→64、写满按检测失败处理防漏报接管⑦del-rule 前缀收敛
                       补 WARN 与 add 一致⑧tun_name_like 空 tun_device 不匹配⑨check-kernel.sh
                       退出码接入硬依赖检查⑩gen-magisk.sh versionCode 改为无碰撞方案
v1.2                  BPF 单元测试（回环注入最小包）+ CI
v1.3                  Android App MVP：开关 + stats 展示（root/JNI）
v1.4                  可选：DNS 拦截模块增强（TCP/53、分片重组、CNAME 链）
```

## 已知设计取舍（不再摇摆）

1. **挂载在 egress 而非 ingress**：简单、可预测，代价是看不到入站统计。
2. **不碰 fwmark/iptables（主线）**：避免厂商差异；bpf_redirect 单钩子两状态。tproxy 是可选形态，见下节。
3. **默认未知→代理**：安全默认（海外）；如需"未知→直连"改配置 `verdict: direct`。
4. **fake-ip 与内核 CNIP 分流不可兼得**：文档已写明，二选一。**v1.1.0 补充**：域名分流
   面向"真实 DNS + 内核规则表"场景（app 走公共 DNS，内核学 IP→域名）；fake-ip 场景的
   域名规则由 mihomo 自己的规则引擎处理（内核只需 fake-ip 段 proxy 规则）——两条路都
   不需要改内核判定模型。

## tproxy 模式：技术约束与可选形态（研究结论，暂未实现）

> 结论先行：**TPROXY 目标在内核里只支持 PREROUTING 钩子，不支持 OUTPUT（本机出站方向）**。
> 我们的 eBPF 处理的是本机进程发起的出站流量，方向相反，**形态 A 已实测否定**。

### 硬约束 1（源码核实，小米 5.10 GKI `net/ipv4/ip_output.c`）
出站路径执行顺序：
```
本地 socket → ip_local_out()[nf_hook NF_INET_LOCAL_OUT, line 115]
            → 路由决策(dst_output)
            → ip_finish_output()[BPF_CGROUP_RUN_PROG_INET_EGRESS, line 322]
            → __dev_queue_xmit()[tc egress sch_handle_egress, 我们现在的挂点]
```
- `nf_hook(NF_INET_LOCAL_OUT)` 在 **cgroup egress 与 tc egress 之前**执行。
- 因此无论 cgroup egress 还是 tc egress 里 `bpf_skb_set_mark()`，**mark 都晚于 OUTPUT 链的路由决策**，`iptables -t mangle -A OUTPUT -m mark` 匹配不到，TPROXY 无法生效。
- Cilium 文档亦确认："tc BPF egress 在 POSTROUTING 之后执行"。

### 硬约束 2（决定性的，WSL2 6.18 + 真机 5.10 均实测 + 源码核实）
**`tproxy` 目标只允许挂在 `NF_INET_PRE_ROUTING` 链**：
```c
// 小米 GKI net/netfilter/nft_tproxy.c:301
static int nft_tproxy_validate(...) {
    ...
    return nft_chain_validate_hooks(ctx->chain, 1 << NF_INET_PRE_ROUTING);
}
```
- 在 OUTPUT 链添加 tproxy 规则 → 内核返回 `Operation not supported`（WSL2 实测复现）。
- 这是 Linux 内核的长期固定行为（tproxy 依赖 PREROUTING 的 socket 匹配语义）。
- **含义**：tproxy 只能拦截"入站/转发"的包，**无法**用于本机进程发起的出站流量重定向——恰好和我们的 eBPF 出站分流方向相反。

### 形态 A 实测否定（2026-08 验证）
形态 A（eBPF egress 打 mark + `ip rule fwmark` 重路由 + mihomo IP_TRANSPARENT）**不可行**：
- 即使 mark 在 egress 被设置，tproxy 目标不支持 OUTPUT 链 → 无 netfilter 目标可把已标记的出站包转给 mihomo。
- WSL2 6.18 实测：`nft add rule inet ... tproxy` 于 output hook 报 `Operation not supported`。

### 可选形态（若未来要实现）

**形态 B：纯 iptables TPROXY + eBPF 仅观测（放弃内核 CNIP 分流）**
```
iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 7892 --tproxy-mark 0x1/0x1
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```
- 注意：必须是 **PREROUTING**（拦截其他设备/转发的流量），对"本机自己发起的出站"仍无效。
- 本机出站 tproxy 的替代是 `REDIRECT`（nat output 链，`nft add rule nat output tcp dport 853 redirect to 10053`），但 REDIRECT 会改目标、丢原始 dst（需 SO_ORIGINAL_DST 才能还原，Android 上支持有限）。
- 均不满足"内核级 CNIP 分流 + 本机出站"的目标。

### 结论
tproxy 模式**不可行**（内核硬限制：tproxy 不支持本机出站方向）。**保持 TUN 为主线**（内核 CNIP 分流 + 零拷贝 redirect，已真机验证）。若未来要"复用 mihomo 端口"，只能走 REDIRECT（丢原始目标）或应用层代理端口（mixed），都不是透明内核分流。

## TUN redirect 兼容性：已解决（v1.0.4，queue_mapping 修复）

> **结论：tc egress + bpf_redirect 到 mihomo TUN 可行！** 关键是设置 `skb->queue_mapping=0`。

### 根因（源码核实 `drivers/net/tun.c` + 真机验证）
`tun_net_xmit()` 用 `skb->queue_mapping` 索引 `tun->tfiles[]` 找用户态读队列：
```c
tfile = rcu_dereference(tun->tfiles[skb->queue_mapping]);
if (!tfile) goto drop;
...
ptr_ring_produce(&tfile->tx_ring, skb);  // 放入读队列 → mihomo read()
```
Android 物理网卡（wlan0/rmnet）多队列，从它 egress bpf_redirect 来的 skb 继承物理网卡
的 queue_mapping（0~N-1），而单队列 tun 只有 `tfiles[0]`。queue_mapping>0 → tfile=NULL
→ **包被 drop**（tun tx_dropped 增长，mihomo read 读不到，utun_rx 不涨）。

**WSL2 eth0 单队列（queue_mapping 恒 0）所以此前"能读到"，Android 多队列暴露此 bug。**
这正是"补齐网络栈上下文"的确切含义——tun 设备需要的 queue_mapping 上下文。

### 修复
```c
// split.bpf.c，redirect 前：
skb->queue_mapping = 0;   // 保证包进入单队列 tun 的唯一读队列
bpf_redirect(tun, 0);     // flags=0(egress)，包进 tun 读队列
```

### 真机验证（小米 5.10 GKI + mihomo v1.19.29 gvisor）
```
curl google ×3        → 200, 0.38~0.43s（稳定）
Play 商店              → 正常打开
mihomo connections    → 14 条，含 www.google.com（Google_域 规则命中）
splitd stats          → proxy 5713 / direct_cn 2925 / parse_err 4 / dropped 0
tcpdump(utun)         → 完整 TCP 握手 + TLS 数据流（双向）
```

### 历史修正
- v1.0.3 曾误判"mihomo 无法接受 bpf_redirect 注入"，实为缺 `queue_mapping`。
- `BPF_F_INGRESS` 不可用：ingress 走 netif_receive，tun 设备不把包排入读队列（WSL2 reader 读不到）。
- 必须 `flags=0`(egress) + `queue_mapping=0`。

## 外部参考：mihomo 为何放弃 eBPF（2024-08-16 移除，issue #1278）

> 背景调研记录（2026-08），用于论证本项目"内核纯 IP 分流 + 用户态域名兜底"的设计合理性。

### 时间线（github.com/MetaCubeX/mihomo，主分支 Alpha）

| 时间 | 提交 | 事件 |
|---|---|---|
| 2022-07-29 | `31f4d20`（PR #144） | 合并 eBPF：`component/ebpf`（tc redirect_to_tun、redir auto-redirect）+ `listener/autoredir` |
| 2022-08-08 | `97270dc` | "rm EBpf tun && disable android ebpf"——Android 版立刻被禁 |
| 2024-08-16 | `0793998`（Larvan2） | **"chore: drop support of eBPF"**——删除全部 6304 行，彻底移除 |
| 2024-10-10 | — | #1278（改进 ebpf 分流方式）关闭为 not planned |

### 官方理由（#1278 评论原话）
1. **内核分流 = 无法域名分流**（contributor xishang0128）：
   "在ebpf区分流量意味着没法进行域名分流,所以这个功能不会做"
2. **与核心目标冲突**（collaborator Skyxim）：
   "这需要修改以满足将程序加载至内核，和原本目标冲突"
3. **dae 的 DNS 映射方案不完善**（xishang0128 反驳 dae 举例）：
   "dae是通过dns映射支持的,但是这并不完善,如果两个域名都是同一个ip,那么这两个域名都可能进入用户态程序,通过嗅探获取域名
   如果dns劫持不到,那就只能是纯ip分流,ip可能不会进入用户态程序进行域名分流,直接直连"

### 结论与对我们的启示
- mihomo 的灵魂是**域名级规则**（DOMAIN-SUFFIX/GeoSite），内核 TC 只见 IP、见不到域名；
  dae 式 DNS 映射（劫持 DNS 拿域名）又有共享 IP 误判、劫持失败退化为纯 IP 的硬伤。
- 叠加 Android 不可用、clang/libbpf 构建链与内核版本兼容问题（#763 "interface not found" 等报障），
  官方选择**删掉而不是改进**。
- 反证本项目设计：**内核只做 IP 集分流（CNIP/规则段），域名粒度全部交给 mihomo 用户态**
  （fake-ip / redir-host + sniffer 兜底），不与 mihomo 域名体系冲突；
  直连流量内核直出（TC_ACT_OK），正是 #1278 想要而 mihomo 没做成的效果。