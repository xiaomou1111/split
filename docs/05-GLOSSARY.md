# 05-GLOSSARY（术语表 & FAQ）

## 术语

| 术语 | 含义 |
|---|---|
| CNIP | 中国大陆 IP 地址段列表（含 IPv4/IPv6），来自各公开维护的"中国 IP 段"数据集；运行时可用 `splitctl cnip on|off|status` 临时控制是否参与策略裁决 |
| LPM_TRIE | 最长前缀匹配树；内核 BPF map 类型，适合路由前缀查询 |
| CO-RE | Compile Once, Run Everywhere；靠 BTF 在运行时适配内核结构体偏移 |
| tc / clsact | 流量控制；`clsact` 允许在设备 ingress/egress 挂 BPF 过滤器 |
| bpf_redirect | 把报文直接改道发往另一 netdev（我们用它把包塞进 tun0） |
| TUN | 虚拟网络设备，用户态程序可通过 fd 读写 IP 层报文（mihomo 的读接口） |
| fake-ip | mihomo DNS 方案：返回 198.18.x 伪 IP，连接时由 mihomo 还原域名 |
| redir-host | mihomo DNS 方案：返回真实 IP，应用直连真实地址 |
| fwmark | socket 的标记，可用于策略路由（我们没用它） |
| UID | Android/Linux 用户 ID；每个 app 一个（≥10000） |
| degraded | 降级模式：eBPF 不可用，自动回退 mihomo 自带 TUN 分流 |
| bpffs | `/sys/fs/bpf`，挂载 BPF map/prog pin 用的伪文件系统 |

## FAQ

### Q1. 需要什么权限？
宿主 Linux：root + 内核 bpf 支持。安卓：root(Magisk/KernelSU) + 见 docs/03。

### Q2. 会不会把我的包丢掉？
不会。任何解析失败/分支未知都默认放行（`TC_ACT_OK`），只有精确命中"代理"分支才会 redirect。

### Q3. 与 Clash/Meta 的 TUN 模式冲突吗？
我们接管了路由（把海外流量 redirect 进 tun0），所以 **mihomo 必须设 `auto-route: false`**（见
configs/mihomo/*.yaml 注释），否则双路由会打架。

### Q4. 我不用 mihomo 行吗？
可以。只要代理内核提供 TUN 接口（v2ray/xray/sing-box 均可），改 split.yaml 顶层的 `tun_device` 名字即可。

### Q5. 为什么选 egress 而不是 ingress？
出口看"目标是谁"，最直接。ingress 还要管五元组去重/回包识别，复杂度高且安卓驱动差异大。

### Q6. 用 fwmark 方案不是更"正统"吗？
正统但脆弱：它依赖 ip rule + iptables 的厂商一致性。bpf_redirect 单钩子两状态，
在 Android 上行为更可预测（本项目第一原则：**可预测 > 正统**）。

### Q7. 支持 IPv6 分流吗？
支持（map_cnip6 与 policy 的 v6 分支），默认开；mihomo `ipv6: false` 时建议关掉 v6 代理。

### Q8. 手机息屏/切网会怎样？
iface 订阅 netlink；断连自动 detach，重连自动 attach。详见 docs/03 §5。

### Q9. 延迟有多大？
直连：0 额外（仅几 ns 的 LPM 查询）；代理：等于代理延迟。

### Q10. 如何调试一条流？
```bash
splitctl stats            # 看 per-cpu 计数器
splitctl status           # 查看当前挂载的接口/map 状态
splitctl cnip on|off|status # 临时开启/绕过 CNIP 策略查询
# 内核侧 trace：
bpftool prog show; bpftool map dump id <map_id>
```

---
补充阅读：`docs/06-ROADMAP.md`。