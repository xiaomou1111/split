# eBPF-Split — 内核级 CNIP 分流流量转发框架

> v1.4.0 ｜ 用 eBPF 在**内核**完成"去往中国大陆的流量直连、海外流量进代理"的分流，
> 再把需要代理的流量转发给 **mihomo(Clash/Meta)** 等任意 TUN 代理内核。
> 设计目标：**高可读、强模块化、安卓优先兼容**。

```
 应用进程 (浏览器 / 视频 / 游戏 ...)
        │  TCP/UDP
        ▼
 ┌───────────────────────────────┐
 │  Linux 网络协议栈 (路由)        │
 │  ┌───────────────────────────┐ │
 │  │ TC-Egress: split.bpf.o    │ │ ← eBPF 在物理网卡发送侧挂载
 │  │  1. 解析报文 (L2/L3)       │ │
 │  │  2. 策略判定               │ │
 │  │     · CNIP(中国) → 直连    │ │  ← LPM_TRIE 免于内存
 │  │     · fake-ip → 交代理      │ │
 │  │     · UID 白名单 → 直连     │ │
 │  │     · 其它 → 依默认值       │ │
 │  │  3. 需要代理 → bpf_redirect │ │
 │  └───────────────────────────┘ │
 └──────┬─────────────────────────┘
        │ 直连（CN 等）              │ bpf_redirect(tun0)
        ▼                           ▼
   物理网卡                      虚拟网卡 tun0
   (wlan0/eth0/rmnet)           (mihomo TUN 读取)
                                    │
                              ┌─────▼─────┐
                              │  mihomo    │ DNS/规则/落地点
                              └────────────┘ 海外流量走代理
```

原理动画一句话：**直连流量根本不进代理，只有"该代理的流"才在内核被拦下来塞进
mihomo 的 TUN**——因此分流发生在内核侧，代理 CPU 压力极小、直连延迟隐断。

---

## 一、目录总览（模块化设计）

```
split/
├── README.md                 ← 本文件（入口）
├── USAGE.md                  使用说明书（快速开始/配置/Android/排障）
├── CODE.md                   代码说明书（代码结构/模块/关键实现）
├── BUILD.md                  构建指导（原生/交叉编译/打包）
├── CONTRIBUTING.md           贡献指南 / 开发规范（含模块记忆工作流）
├── Makefile                  顶层构建入口
│
├── docs/                      ← ① 文档模块
│   ├── 01-ARCHITECTURE.md     架构 + 数据流
│   ├── 02-MODULES.md          模块说明书（每个模块干什么/接口/依赖）
│   ├── 03-ANDROID.md          安卓兼容性方案（重点）
│   ├── 04-CONFIG.md           配置手册
│   ├── 05-GLOSSARY.md         术语表/FAQ
│   └── 06-ROADMAP.md          路线图
│
├── kernel/                    ← ② 内核侧（BPF，纯 C）
│   ├── include/split_bpf.h    共享常量/结构体/规则声明（L0 ABI）
│   ├── bpf/
│   │   ├── maps.h             所有 BPF MAP 定义（单一真相源）
│   │   ├── parse.h            报文解析（安全边界检查）
│   │   ├── radix.h            LPM_TRIE 匹配封装 (IPv4/IPv6)
│   │   ├── policy.h           策略判定（modular 判定顺序）
│   │   └── split.bpf.c        唯一入口程序（SEC("classifier")）
│   └── Makefile               BPF 编译
│
├── userspace/                 ← ③ 用户态
│   ├── common/                日志 / 配置 / netlink / paths
│   ├── loader/                BPF 对象加载、tc 挂载、接口发现
│   ├── cni/                   CNIP 数据灌入 map
│   ├── rule/                  规则管理（proxy/direct/UID）
│   ├── daemon/                splitd 守护（生命周期 / ctl 协议）
│   ├── cli/                   splitctl 命令行工具
│   └── Makefile
│
├── android/                   ← ④ 安卓兼容层
│   ├── magisk/                Magisk 模块骨架（customize/service/sepolicy/webroot）
│   ├── scripts/               起停/守护 watchdog/setup-box-tun/check-kernel/WebUI 后端
│   ├── app/                   (预留) 原生 App
│   ├── README.md
│   └── MEMORY.md              安卓模块记忆文档
│
├── configs/                   ← ⑤ 配置
│   ├── split.yaml.example       本框架配置样例
│   └── mihomo/
│       ├── mihomo-redir-host.yaml  推荐(内核分流可见真实 IP)
│       ├── mihomo-fake-ip.yaml     体验版(fake-ip 无法内核分流)
│       └── mihomo-package.yaml     随包脱敏配置模板（token 为 YOUR_* 占位）
│
├── scripts/                   ← ⑥ 辅助脚本（构建/调试/发布）
│   ├── build.sh               顶层构建
│   ├── build_arm64.sh         交叉编译 arm64（Android 真机）
│   ├── bump-version.sh        版本号一键递增（唯一真源 split_bpf.h，v1.3.0）
│   ├── fetch-cnip.sh          更新 CNIP 源
│   ├── gen-magisk.sh          打包 Magisk zip（带版本号）
│   └── load-debug.sh          宿主机(Linux)调试加载
│
├── tests/                     ← ⑦ 测试
│   ├── unit/                  纯用户态单测
│   └── integration.sh         端到端：直连/代理/超时校验
│
└── build/                     ← ⑧ 构建产物
    ├── split-magisk-v{VERSION}.zip   可刷入 Magisk 的模块包
    └── arm64/                        Android arm64 二进制（含可选 mihomo）
```

---

## 二、快速开始（宿主机调试）

```bash
# 1. 依赖（Debian/Ubuntu）
sudo apt install clang llvm libbpf-dev libelf-dev bpftool iproute2
#    mihomo 单独获取（仓库不捆绑代理二进制，避免合规/体积问题）

# 2. 构建
make bpf        # 生成 kernel/bpf/split.bpf.o
make userspace  # 生成 userspace/build/{splitd,splitctl}

# 3. 准备 mihomo（示例配置在 configs/mihomo/ 两套任选）
mihomo -f configs/mihomo/mihomo-redir-host.yaml &

# 4. 加载
sudo ./userspace/build/splitctl start -c configs/split.yaml

# 5. 验证
curl https://www.youtube.com     # 走代理
curl https://www.baidu.com       # 直连（不经过 mihomo）
./userspace/build/splitctl stats # 内核计数
```

> 安卓（Magisk/KernelSU/APatch）安装：`make android` 生成 `build/split-magisk-v{VERSION}.zip`（及 `build/split-ksu-v{VERSION}.zip` 别名），
> 见 `android/README.md` 与 `docs/03-ANDROID.md`；完整构建流程见 `BUILD.md`。

---

## 三、核心设计决策（为什么这样分模块）

| 决策 | 理由 |
|---|---|
| 挂载点选 **tc egress** 而非 XDP | Android 驱动设备多为 skb 路径、XDP 驱动支持差；tc 挂载方式在 netd 已有先例（sched_cls） |
| 转发用 `bpf_redirect(tun0)` 而非 fwmark+路由 | 无 iptables 依赖、单钩子两状态、代码路径短；Android 上 fwmark 与 policy 路由更常遭厂商魔改 |
| 分类用 **LPM_TRIE** | CNIP 是网络前缀最长匹配问题，恰是该 map 的最优解；IPv4/IPv6 两棵树天然分离 |
| UID 白名单过滤代理自身的出口 | 防止 mihomo → 远端 的连接被误判为"海外"重新进隧道（回环死循环） |
| 兼容策略**三级兜底** | eBPF 不可用 → 退化为 mihomo 自带 TUN 路由（纯用户态分流） |
| 配置全部**动态灌 map** 而非改 BPF 代码 | 规则热更新不掉线、不重新编译 |

---

## 四、模块清单（详见 docs/02-MODULES.md）

| 模块 | 位置 | 职责 |
|------|------|------|
| `parse` | kernel/bpf/parse.h | L2/L3 解析（v1.4.0 起仅 L3）、边界校验、vlan 处理 |
| `radix` | kernel/bpf/radix.h | LPM_TRIE 最长前缀匹配封装 |
| `policy` | kernel/bpf/policy.h | 分流裁决：直连 / 代理 / 默认 |
| `classify` | kernel/bpf/split.bpf.c | tc 入口 + UID 白名单 + redirect |
| `maps` | kernel/bpf/maps.h | 全局 map 清单（单一真相源） |
| `loader` | userspace/loader/ | libbpf 加载、BPF_TC 挂载 |
| `iface` | userspace/loader/iface.c | 接口发现 / 物理网卡判定 |
| `cnip` | userspace/cni/ | CNIP 下载 / 解析 / 写入 trie map |
| `rule` | userspace/rule/ | proxy/direct CIDR、UID 维护 |
| `daemon` | userspace/daemon/ | splitd 生命周期 / ctl 协议 / reload |
| `cli` | userspace/cli/ | splitctl（status/stats/add-rule/del-rule...） |
| `config` | userspace/common/ | split.yaml 解析（含 parse_bool） |
| `netlink` | userspace/common/ | 接口枚举（须先 bind）/ 物理判定 |
| `paths` | userspace/common/ | 运行时路径（Android 走 SPLIT_SOCKET） |
| `android.*` | android/ | Magisk 模块 / sepolicy / 启动胶水 |

每个模块单目录、单职责，**横不依赖**，只有 `maps.h` 是全局共享，改造某个模块只需
过一遍 `docs/02-MODULES.md` 中的"外部契约"表。

> **改模块代码前先读该目录的 `MEMORY.md`**（记忆文档）：记录各模块的实现决策、
> 踩过的坑、与别处的硬契约（见 `CONTRIBUTING.md §1.5`）。

---

## 五、文档索引

```text
USAGE.md                  使用说明书（快速开始/配置/Android/排障）
CODE.md                   代码说明书（代码结构/模块/关键实现）
BUILD.md                  构建指导（原生/交叉编译/打包/验证）
docs/01-ARCHITECTURE.md   安装/卸载 → 数据流 → 网络拓扑 → 限制
docs/02-MODULES.md        模块说明书：职责/接口/依赖/契约/测试
docs/03-ANDROID.md        安卓：内核要求/SELinux/fake-ip 冲突/常见问题
docs/04-CONFIG.md         split.yaml 全字段解析
docs/05-GLOSSARY.md       术语表 & 常见问题
docs/06-ROADMAP.md        未实现清单 / 方向
android/README.md         Magisk 模块装机流程
```

---
*本仓库在 Windows 上编写，仓库目标运行环境为 Linux 内核设备（含 Android GKI）。*