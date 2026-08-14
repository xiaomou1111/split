# eBPF-Split 使用说明书

> 版本 v1.4.6 ｜ 面向：想在 Linux / Android 真机上用起来的人
> 目标读者：能看懂 shell 命令、会 root 的普通用户。代码细节见 `docs/`。

---

## 0. 这是什么

**eBPF-Split** 是一个"内核级流量分流框架"：它挂在物理网卡出口（tc egress），用一个 eBPF 程序对每个出站包做判定——

- **去中国大陆的流量**（命中 CNIP / 内网 / 白名单）→ **内核直连**，完全不碰代理
- **海外流量** → 重定向进 **mihomo（或其它 TUN 代理内核）** 的虚拟网卡，交给它代理

一句话：**直连流量根本进不了代理，只有"该代理的流"才在内核被拦下来塞进 mihomo 的 TUN**。

```
应用 (浏览器/视频/游戏)
      │ TCP/UDP
      ▼
Linux 协议栈 ──► TC Egress: eBPF 判定
                    ├─ CNIP/内网/白名单 → TC_ACT_OK → 物理网卡直连
                    └─ 海外 → bpf_redirect → tun0 → mihomo 处理 → 代理节点
```

### 核心优势
| 优点 | 说明 |
|---|---|
| **CN 零开销** | 国内流量不进 mihomo，延迟≈0，省 CPU/电 |
| **内核级分流** | CNIP(IPv4/IPv6) 用 LPM_TRIE，纳秒级判定 |
| **热更新** | 规则/CNIP 动态写 map，不重启不掉线 |
| **安卓兼容** | Magisk/KernelSU 模块，GKI 内核直接可用 |

---

## 1. 快速开始（Linux 宿主机）

### 1.1 准备依赖（Debian/Ubuntu）

```bash
sudo apt install clang llvm libbpf-dev libelf-dev bpftool iproute2 curl
# 下载 CNIP 数据
./scripts/fetch-cnip.sh            # 生成 cn_cidr_v4.txt 等（输出目录/路径配置见 docs/04）
```

### 1.2 构建

```bash
make bpf         # 编译 kernel/bpf/split.bpf.o（架构无关）
make userspace   # 编译 userspace/build/splitd + splitctl
# 或一步：make all
```

### 1.3 准备 mihomo

用仓库自带的 mihomo 配置之一，改好节点后启动：

```bash
mihomo -f configs/mihomo/mihomo-redir-host.yaml &   # 推荐 redir-host
```

> **必须**：mihomo 的 `tun.device` 要和你 split.yaml 的 `tun_device` 一致（默认 `utun`）。
> **必须**：mihomo 的 tun 配置 `auto-route: false`（让 eBPF 接管路由，mihomo 不抢）。

### 1.4 配置

```bash
cp configs/split.yaml.example /etc/split/split.yaml   # 或 ./split.yaml
# 按需修改（详见 §3）
```

### 1.5 启动

```bash
sudo ./userspace/build/splitctl start -c ./split.yaml   # 或直接 sudo ./userspace/build/splitd -c split.yaml
./userspace/build/splitctl status        # → OK prog_fd=.. attached=N
```

### 1.6 验证

```bash
curl https://www.baidu.com     # 直连（direct_cn 计数 +1）
curl https://www.google.com    # 走代理（proxy 计数 +1）
./userspace/build/splitctl stats         # 看内核计数
```

---

## 2. Android 真机安装（Magisk/KernelSU）

### 2.1 交叉编译（在 x86 Linux 上出 arm64 二进制）

```bash
# 一次性准备交叉工具链 + libbpf（详见 scripts/build_arm64.sh 头部注释）
sudo apt install gcc-aarch64-linux-gnu libelf-dev:arm64 zlib1g-dev:arm64 \
                 libzstd-dev:arm64 liblzma-dev:arm64 libbz2-dev:arm64
# 编译 libbpf 到 /root/bpf_deps/libbpf
# 然后：
./scripts/build_arm64.sh        # 生成 build/arm64/{splitd,splitctl}
make -C kernel bpf              # split.bpf.o（架构无关）
```

### 2.2 打包 Magisk 模块

```bash
make android   # 或 ./scripts/gen-magisk.sh
# 产物: build/split-magisk-v{VERSION}.zip
```

### 2.3 安装

```bash
adb push build/split-magisk-v{VERSION}.zip /sdcard/
# 打开 Magisk/KernelSU → 模块 → 从本地安装 → 选 zip → 重启
```

> 若 zip 内置 mihomo（build/arm64/mihomo + 脱敏配置）：装完编辑
> `/data/adb/split/mihomo/config.yaml`，把 `YOUR_TOKEN_1..4`、`YOUR_HYSTERIA2_PASSWORD`
> 替换成你自己的订阅后重启生效。**脱敏是安全底线：仓库不带任何真实订阅 token/密码。**

### 2.4 接入已有 box 代理（一键，推荐）

真机上若已装 `box`（/data/adb/box，常见的代理模块），可复用它的 mihomo 和节点：

```bash
adb root
adb shell "sh /data/adb/split/scripts/setup-box-tun.sh"
```

脚本会自动：复制 box 的 mihomo 配置 → 改 TUN 段（auto-route:false + stack:gvisor + gso:off + mtu:1500 + auto-detect-interface:off）→ 复用 box 的 CNIP → 起 mihomo + splitd。

### 2.4.1 运行时目录（分层，安装后结构）

```text
/data/adb/split/
├── bin/      二进制 + split.bpf.o（mihomo 若随包也在这）
├── config/   split.yaml + cnip 数据
├── scripts/  辅助脚本（start/stop/setup-box-tun/check-kernel）
├── logs/     splitd.log / mihomo.log
├── run/      splitd.sock
└── mihomo/   mihomo 配置目录（box 复制）
```

> 日志统一进 `logs/`，配置统一进 `config/`，避免根级散落。

### 2.4.2 mihomo 该放哪？（权限结论）

**mihomo 二进制放运行目录 `/data/adb/split/bin/`（或复用 box 的 `/data/adb/box/bin/`），不要放 modules 目录**：
- `/data/adb/modules/` 对非 root 进程**不可读**（`su 2000 ls` → Permission denied）
- modules 目录受 **Magisk overlay** 管理，升级/卸载会丢配置
- box 的做法就是这个：mihomo 放 `/data/adb/box/bin/`（运行目录，root 跑）
- 随包 mihomo 时：二进制在 `bin/mihomo`，配置在 `mihomo/`

### 2.5 Android 注意事项

| 项 | 说明 |
|---|---|
| **内核要求** | GKI 5.4+，BPF/JIT/TUN 全开（见 docs/03） |
| **SPLIT_SOCKET** | Android 无 /run，脚本已自动 `export SPLIT_SOCKET=/data/adb/split/run/splitd.sock` |
| **SPLIT_LOG** | v1.1.9：`splitctl start` 派生 splitd 的日志路径（Android 由 service.sh 直接重定向，无需设） |
| **skip_uid** | mihomo 若以普通 app 跑，把它 uid 加进 skip_uid（防回环） |

---

## 3. 配置详解（split.yaml）

> 语法：极简 YAML 子集（`section:` / `key: value` / `- item` / `# 注释`），不支持引号/嵌套/多行。

```yaml
tun_device: utun            # 代理 TUN 设备名，与 mihomo tun.device 一致

ifaces:
  attach_auto: true         # true=自动挂所有物理网卡；false 用 attach_list
  attach_list:
    - wlan0
  exclude:                  # 前缀匹配排除（tun/utun 必须排除，防回环）
    - lo
    - tun
    - utun
    - dummy

default:
  verdict: tun              # 未命中时默认：tun(代理) 或 direct(直连)
  ipv6: true                # 是否参与 IPv6 分类

rules:
  proxy_cidr4:              # 强制代理段（优先级高于 CNIP）
    - 198.18.0.0/15         #   fake-ip 池（对齐 mihomo）
  # direct_cidr4:           # 强制直连段
  #   - 10.0.0.0/8
  skip_uid:                 # UID 白名单（直连，跳过判定）
    - 0                     #   root
    - 2000                  #   shell
    # - 10101               #   你的 mihomo app uid

cnip:
  path_v4: /data/adb/split/config/cn_cidr_v4.txt   # 建议绝对路径
  path_v6: /data/adb/split/config/cn_cidr_v6.txt
  auto_update_hours: 72
```

**判定顺序（policy.h 即真相，7 步；第 2 步是 `default.ipv6: false` 时的 v6 出口）**：
```
1. skip_uid 白名单        → 直连
2. v6 且 ipv6:false       → 直连（v6 不参与分类，docs/04 契约）
3. 内置本地段(回环/链路/组播) → 直连
4. proxy 规则段            → 代理
5. direct 规则段           → 直连
6. CNIP(4/6)              → 直连
7. 其余                    → default.verdict
```

> **rules 空列表告警（v1.2.9）**：声明了 `proxy_cidr4/direct_cidr4/proxy_cidr6/direct_cidr6`
> 但没有任何 `- item` 时，默认规则（fake-ip 段/内网直连段）会被覆盖式清空——启动/reload
> 日志会打 WARN 点明，请检查配置是否为误写（空列表用于"主动清空某族"是合法的）。

---

## 4. 命令参考（splitctl）

```bash
splitctl start [-c cfg] [-s path] [-b bpfobj] [-d]    # 启动 splitd（-s=splitd 路径，-d=debug）
splitctl stop                        # 停止
splitctl status                      # 状态（prog_fd/attached/tun/cnip4/cnip6/hijack + WARN 行）
splitctl stats                       # 内核计数
splitctl list-rules                  # 当前在线规则（proxy/direct 行，v1.2.2）
splitctl reload                      # 重载配置（增量写 map）
splitctl reload-cnip                 # 只刷新 CNIP（重读本地文件重灌）
splitctl update-cnip                 # 手动更新 CNIP（重新下载 url_v4/v6 后重灌，后台执行）
splitctl add-rule <cidr> [direct|proxy]   # 在线加规则
splitctl del-rule <cidr> [direct|proxy]   # 在线删规则
splitctl validate -c cfg             # 只校验配置
```

> **add-rule/del-rule 的运行时规则跨 reload 保留（v1.2.0）**：这些是"对配置基线的运行时偏差"
> 记录在 daemon 内存里并重放——`splitctl reload` 后仍生效（不再被配置重写冲掉）。但**重启 splitd
> （或 daemon 退出）即丢失**，仍未持久化到配置文件；要长期生效请写进 `config.yaml` 的 rules 节。

**status 字段（v1.1.3 起）**：`OK prog_fd=<n> attached=<n> tun=<ifindex> cnip4=<n> cnip6=<n> hijack=<0|1|-1>`，
后面可能跟 `WARN ...` 行。**看到 WARN 就是分流未生效，先修再走**：

| 字段 | 含义 | 期望 |
|---|---|---|
| prog_fd | BPF 程序 fd | >0 |
| attached | 已挂载网卡数 | >0 |
| tun | tun 设备 ifindex | = utun 的 ifindex |
| cnip4/cnip6 | CNIP map 条目数 | 数千条；**0 = 文件缺失/未导入**（放 cn_cidr_v4.txt 后 reload-cnip；配了 url 会自动补拉一次） |
| hijack | 路由是否被 mihomo auto-route 接管 | **必须 0**；1 = mihomo 接管路由 → eBPF 失明（direct_cn 恒 0），把 mihomo tun.auto-route 改 false 重启 |

**stats 字段含义**：

| key | 含义 | 期望 |
|---|---|---|
| total | 所有经 eBPF 的包 | >0 |
| direct_cn | CNIP 命中直连 | curl 百度后 +1 |
| direct_rule | direct 规则段命中 | 内网流量 +1 |
| proxy | 进代理（proxy 规则/默认） | curl 谷歌后 +1 |
| skip_uid | 白名单跳过 | 系统流量为主 |
| parse_err | 解析失败（放行） | 应≈0 |
| redirect_err | 重定向失败 | 恒 0 为佳 |
| dropped | 丢包（不应发生） | 恒 0 |
| miss_tun | 想代理但 tun 未就绪（放行） | 启动初期可出现；**持续增长 = mihomo TUN 消失（v1.2.9 watchdog 自愈，见 Q8）** |

---

## 5. 排障

> **debug 过程日志（v1.4.5）**：`split.yaml` 设 `debug: true`（或 `splitd -d`）后 splitd.log 会
> 输出更细的过程细节：map 逐个打开、split/libbpf 版本、CNIP 下载器与每源耗时、混合文件按族
> 加载跳过行数、rules 按族计数与 skip_uid 白名单、每条 ctl 命令、CNIP 更新子进程收尸结果、
> iface reconcile 每轮增删汇总。排障先开它，再对照下面的 Q&A。

### Q1. splitd 启动报"找不到 tun 设备"
→ 先启动 mihomo，确认 tun 设备出现：`ip link show utun`。设备名要和配置一致。

### Q2. BPF 加载报 `BPF_STX uses reserved fields`
→ 老内核（5.x GKI）不认新 clang 的 `BPF_ATOMIC`。必须 `-mcpu=v1` 编译（Makefile 已带，别去掉）。

### Q3. 流量没进 mihomo（连接数少）
→ 分三步查：
1. `splitctl stats` 看 `proxy` 是否增长（eBPF 判了没）
2. `curl 127.0.0.1:9090/connections` 看 mihomo 是否有连接（代理内核收没收到）
3. `ss -tnp | grep mihomo` 看是否有到代理节点的连接（节点通不通）
> 注意：**用 root/shell 测试流量会被 skip_uid 跳过**，验证代理路径要临时清空 skip_uid。

### Q4. 包进了 mihomo 但连接失败
→ 确认 mihomo：`stack: gvisor`（mixed 在 eBPF 注入下首连慢）、`gso: false`（vnetHdr 不兼容裸 IP 注入）、
`mtu: 1500`（默认 9000 会大包分片）、`auto-detect-interface: false`（出口由 eBPF 接管）。

### Q5. parse_err 暴涨 / 回环
→ 检查 `exclude` 是否包含 `utun`/`tun`。mihomo 回写流量再进 eBPF 会回环。

### Q6. `splitctl status` 报 WARN / `direct_cn` 恒 0（v1.1.3）
→ 两种典型：
1. `WARN CNIP 未导入（0 条）`：`/data/adb/split/config/cn_cidr_v4.txt` 缺失。Android 上直接
   `cp /data/adb/box/run/cn.zone config/cn_cidr_v4.txt`（box 数据可复用），或配了 url 时
   daemon 会在启动后 5 秒自动补拉一次。
2. `WARN 路由被 mihomo auto-route 接管`：mihomo 配置是 box 原样/被改回 `auto-route:true`，
   它接管了路由（`ip rule` 出现 9002/2022 表），物理网卡 egress 的 eBPF 看不到流量。
   把 `tun.auto-route` / `strict-route` 改回 `false` 并重启 mihomo（Android 侧
   `scripts/fix-mihomo-tun.sh` 可自动修复，service.sh 启动前已调用）。

### Q7. 节点 alive 但访问超时
→ 是 mihomo 节点自身的连通性问题（订阅/出口），不是框架问题。

### Q8. 代理突然全部放行直连，`miss_tun` 持续增长（v1.2.9 自愈）
→ 根因：mihomo 的 TUN 中途消失（`tun.enable` 被外部控制器（9090）改 false、或 utun 被系统/外部
清理）→ splitd 的 `map_tun` 置 0 → 代理流量被放行直连，`splitctl stats` 里 `miss_tun` 持续增长
却无报错。自 v1.2.9 起 `split-watchdog.sh` 已内置自愈：连续 2 轮探活到 `tun=0` 且 `bin/mihomo`
存在时，先经 mihomo API（`PATCH /configs {"tun":{"enable":true}}`）无感恢复，失败则重启 mihomo，
恢复后 5 分钟冷却。若仍复现，检查 `logs/splitd.log` 的 `[wd]` 前缀日志与 mihomo 9090 是否有
外部进程改配置（建议给 mihomo `external-controller` 设 `secret` 或改为仅 127.0.0.1 监听）。

---

## 6. 卸载

```bash
# Linux：停 splitd，清 tc 挂载
sudo ./userspace/build/splitctl stop
sudo tc qdisc del dev <iface> clsact   # 逐个物理网卡

# Android：Magisk/KernelSU 移除模块即可
```

---

## 7. 更多

| 主题 | 文档 |
|---|---|
| 架构/数据流 | docs/01-ARCHITECTURE.md |
| 模块说明书 | docs/02-MODULES.md |
| 安卓兼容 | docs/03-ANDROID.md |
| 配置全字段 | docs/04-CONFIG.md |
| 术语/FAQ | docs/05-GLOSSARY.md |
| 路线图/已知缺口 | docs/06-ROADMAP.md |

> 源码在 Windows 编写，目标 Linux（含 Android GKI）。仓库由 `git` 管理。
