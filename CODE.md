# 代码说明书（CODE.md）

> eBPF-Split v1.4.10 ｜ 面向：想读懂/改这份代码的开发者
> 先读：`README.md`（架构总览）→ 本文（代码细节）→ 各模块 `MEMORY.md`（改前必读）

---

## 1. 代码总览

```
split/
├── kernel/                  # 内核侧（eBPF，唯一入口 + 模块化头）
│   ├── include/split_bpf.h  共享类型/常量/verdict（L0 ABI）
│   └── bpf/
│       ├── split.bpf.c      SEC("classifier") 唯一入口
│       ├── maps.h           全部 BPF map（单一真相源）
│       ├── parse.h          报文解析（安全边界）
│       ├── radix.h          LPM_TRIE 匹配封装
│       └── policy.h         判定顺序（7 步，含 v6 开关）
│
├── userspace/               # 用户态（libbpf 驱动）
│   ├── common/              log / config(极简YAML) / netlink / paths
│   ├── loader/              BPF 加载 + tc 挂载 + map 操作
│   ├── cni/                 CNIP 数据灌入
│   ├── rule/                规则管理（CIDR）
│   ├── daemon/              splitd 守护（生命周期 / ctl 协议）
│   └── cli/                 splitctl 命令
└── scripts/                 # 构建 / 打包 / 工具
```

**调用链（内核侧）**：
```
split.bpf.c ──> parse.h（解析）──> policy.h（裁决）──> radix.h（LPM）
                    └──────────> maps.h（map 定义/统计）
```

---

## 2. 内核侧（kernel/）

### 2.1 split.bpf.c — 唯一入口

`SEC("classifier")` 程序，挂在 **tc clsact egress**。每包流程：

```
1. stats_inc(STAT_TOTAL)             # 计数
2. parse_skb(skb, &pkt)              # 解析，失败→TC_ACT_OK 放行
3. uid = bpf_get_socket_uid(skb)     # 安卓每 app 一 uid（前置条件 cfg->skip_uid_enabled，见 split.bpf.c:47-49）
4. verdict = policy_judge(...)       # 7 步裁决
5. 若 TUN → tun_ifindex() 检查 → bpf_redirect(tun, 0)
6. 直连 → TC_ACT_OK
```

**关键：`skb->queue_mapping = 0`（v1.0.4）**。
`tun_net_xmit()` 用 `skb->queue_mapping` 索引 `tun->tfiles[]` 找读队列。从 Android 多队列
物理网卡（wlan0/rmnet）egress redirect 来的 skb 继承其 queue_mapping（0~N-1），单队列 tun
只有 `tfiles[0]`，>0 则 tfile=NULL → 包被 drop。**强制 queue_mapping=0 保证进唯一读队列。**

### 2.2 maps.h — map 单一真相源

| map | 类型 | key | 容量 | 用途 |
|---|---|---|---|---|
| map_cnip4 | LPM_TRIE | lpm_key4 | 65536 | CNIP IPv4（直连） |
| map_cnip6 | LPM_TRIE | lpm_key6 | 65536 | CNIP IPv6 |
| map_rule_proxy4/6 | LPM_TRIE | lpm_key4/6 | 8192 | 强制代理段 |
| map_rule_direct4/6 | LPM_TRIE | lpm_key4/6 | 8192 | 强制直连段 |
| map_rawip（v1.1.5） | HASH | u32 ifindex | 32 | RAWIP 接口集合（蜂窝 rmnet_data*，ARPHRD_RAWIP=519，无 L2 头，内核据此跳过以太网解析） |
| map_skip_uid | HASH | u32 | 64 | UID 白名单（防回环） |
| map_tun | ARRAY | u32 | 1 | tun ifindex |
| map_cfg | ARRAY | u32 | 1 | split_cfg 运行时配置 |
| map_stats | PERCPU_ARRAY | u32 | STAT_MAX | 统计计数 |

> 改名/改结构 = 破坏 ABI：用户态 loader.c 按名字 `bpf_object__find_map_by_name` 查找。

### 2.3 parse.h — 安全解析

- 原则：**任何越界 → 返回 0（不可判），由上层放行，绝不越界读**
- v1.4.0 起仅提取 L3（family+dst，policy 的全部输入）；VLAN 支持至双标签 QinQ；L4 解析已删（无消费者）
- case 标签用 `bpf_htons(ETH_P_IP)`（网络序常量，勿用 htons 非常量）

### 2.4 radix.h — LPM 封装

```c
radix_match4(&map_cnip4, ip_be32)   // 查 32 位前缀，内核自动最长前缀回溯
radix_match6(&map_cnip6, ip6_ptr)
```
查询 key 的 prefixlen 填 32/128（查最具体），值统一 `__u8=1`（成员标记）。

### 2.5 policy.h — 判定顺序（7 步，含 v6 开关出口）

```
1. skip_uid 白名单      → PASS
2. v6 且 ipv6_classify=0 → PASS（v6 不参与任何分类，docs/04 契约）
3. 内置本地段           → PASS（127/8,169.254/16,224/4,255.255.255.255,::1,fe80::/10,ff00::/8）
4. proxy 规则段         → TUN
5. direct 规则段        → PASS
6. CNIP(4/6)           → PASS（`cnip on`；`cnip off` 跳过本步，落到 default）
7. 其余                → cfg->default_verdict（默认 TUN）
```
内置段：v4 用 `bpf_ntohl` 转主机序比较，v6 逐字节数组比较（均跨 CPU endian 一致，policy.h:49-63）。

---

## 3. 用户态（userspace/）

### 3.1 启动链（daemon.c main → daemon_loop）

```
config_load → split_load(loader.c) → iface_resolve_tun → map_set_tun
→ rule_apply_all → cnip_apply → iface_reconcile → ctl_listen → 事件循环
```

### 3.2 模块职责

| 文件 | 职责 | 关键函数 |
|---|---|---|
| loader/loader.c | BPF 加载 + map 句柄 | split_load / split_attach_iface / map_set_tun / map_rule_add_cidr |
| loader/iface.c | 挂载计划/网络切换 | iface_plan / iface_reconcile（v1.1.9 起支持快照复用，去重复 scan） |
| common/netlink.c | 接口发现（纯 netlink） | iface_scan / iface_is_physical |
| common/config.c | 极简 YAML 子集解析 | config_load / parse_bool |
| common/paths.c | 运行时路径 | split_socket_path（$SPLIT_SOCKET） |
| cni/cnip.c | CNIP 灌入 | cnip_apply / cnip_load_file |
| rule/rule.c | 规则管理（CIDR） | rule_apply_all / rule_add / rule_del |
| daemon/daemon.c | 生命周期 + ctl 协议 | daemon_loop / ctl_serve |
| cli/splitctl.c | 命令行 | 见下 |

> **splitd 退出码契约**（改必同步 `android/magisk/service.sh`，见 daemon/MEMORY）：config 失败 **exit 1**、
> BPF 加载失败 **exit 2**（直接退出，非降级）、tun 缺失 **exit 3**（BPF 已载、属预期降级路径）、单实例锁被占 **exit 4**。

### 3.3 ctl 协议（daemon ↔ cli 硬契约）

- Unix socket（`split_socket_path()`，默认 /run/splitd.sock）
- **单命令一连接**：回复后 return 0 即 close（防死锁，勿改多命令循环）
- 命令：`stats`/`status`/`list-rules`（v1.2.2）/`reload-cnip`/`update-cnip`（v1.4.1 手动更新 CNIP）/`cnip on|off|status`（临时绕过策略查询）/`reload`/`add-rule <cidr> [proxy|direct]`/`del-rule <cidr> [proxy|direct]`/`stop`
- 回复：首行 `OK/ERR`，数据行，末行 `END`
- **`status`（v1.1.3 扩展）**：`OK prog_fd=.. attached=.. tun=<ifindex> cnip4=<n> cnip6=<n> cnip=<on|off> hijack=<0|1|-1>`；
  其后可能跟 `WARN ...` 行（CNIP 0 条 / 路由被 mihomo auto-route 接管）——WebUI app.js 解析这些字段，改格式必须同步

### 3.4 关键坑（已修复，勿回退）

| 坑 | 修复 |
|---|---|
| BPF `BPF_STX uses reserved fields` | `-mcpu=v1`（生成 XADD，兼容 5.x GKI verifier） |
| `attach_auto: true` 解析成 0 | `parse_bool()` 支持 true/false/yes/no/1/0 |
| utun 被误挂回环 | iface_is_physical exclude 含 utun |
| netlink 扫不到接口 | iface_scan 先 bind() |
| config `tun0\n` 匹配失败 | str_trim_tail() 清尾空白 |
| mihomo 收不到 redirect 包 | `skb->queue_mapping=0` |
| 熄屏/doze 后代理失效、mihomo 只剩自身 DNS | v1.1.7 双重自愈：daemon 主循环 15s 节流 `iface_reconcile`（P3：5s→15s，防 netlink 事件漏收导致挂载陈旧，`split_attach_iface` 幂等去重经 `bpf_tc_query` 核验 filter 真实存在，丢失即重挂）+ `split-watchdog.sh` 探活拉起（防 splitd 进程死亡后 map_tun 无人维护）。停止闸收敛到 `splitctl stop/start`（`gate_set/gate_clear`），任意 stop 路径统一防"刚 stop 又被拉起" |
| splitd 存活但 mihomo TUN 消失（map_tun=0、代理全放行直连） | **v1.2.9：`split-watchdog.sh` 探活分支解析 `tun=` 字段**——连续 2 轮为 0 且 `bin/mihomo` 存在 → 先经 mihomo API 无感恢复 `tun.enable`（`PATCH /configs`），API 失败重启 mihomo，恢复后 5 分钟冷却。真机症状（miss_tun 持续增长却无报错）见 USAGE.md Q8 |
| mihomo auto-route 接管路由 → 分流静默失效 | daemon 每 30s 检测路由接管（P2：10s→30s，status hijack 字段）+ service.sh/WebUI 启动前 fix-mihomo-tun.sh 幂等修复 |
| CNIP 文件缺失 → direct_cn 恒 0 无报错 | status 报 cnip4/6 条数（0=缺失）+ 配 url 时启动自动补拉一次 |
| mihomo gso 不兼容 | 保持 gso:false + stack:gvisor |

---

## 4. 打包/脚本（scripts/）

| 脚本 | 用途 |
|---|---|
| build.sh | 顶层构建 |
| build_arm64.sh | 交叉编译 arm64（glibc 静态） |
| gen-magisk.sh | 打包 Magisk zip（分层结构） |
| fetch-cnip.sh | 下载 CNIP 数据 |
| load-debug.sh | 宿主机调试加载 |
| bump-version.sh | 版本号递增唯一入口（patch/minor/major，同步 module.prop/roadmap/根文档版本标注） |
| ensure-arm64-source.sh | 交叉编译前把 Ubuntu apt 源 pin `[arch=amd64]`（防 arm64 update 404） |

**zip 结构**（gen-magisk.sh）：
```
module.prop/customize.sh/post-fs-data.sh/service.sh/sepolicy.rule  ← 根（Magisk 强制）
config/split.yaml          bin/{splitd,splitctl,split.bpf.o}   scripts/*.sh
mihomo/config.yaml         bin/mihomo（若随包，脱敏模板）
```

---

## 5. 安全注意

- **打包配置只含占位符**（`YOUR_TOKEN_*`、`YOUR_HY2_SERVER_IP` 等）
- **原始敏感配置（config.yaml.real）不保留在项目/构建区**
- 改代码后同步：各模块 MEMORY.md、docs/02-MODULES.md
