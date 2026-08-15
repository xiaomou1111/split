# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 平台约束（最先确认）

- 仓库在 **Windows 上编写，目标运行环境是 Linux 内核设备（含 Android GKI）**。
- 当前本机是 win32：**不能本地编译/运行/验证任何 BPF 或用户态二进制**，只能做静态代码审查。
  构建与冒烟验证必须在 Linux（Debian/Ubuntu 或 WSL2）执行；**不要假想"编译通过"**。
- 代码审查重点是：BPF verifier 纪律、字节序契约、边界检查、map 名/结构 ABI（见下"硬契约"）。

## 文档地图（改码前先读）

| 文件 | 内容 |
|---|---|
| `AGENTS.md` | 项目硬约定：模块边界、语言风格、BPF 铁律、构建要点、版本号。**改码前必读** |
| `CODE.md` | 代码结构、内核/用户态调用链、已修复坑清单 |
| `BUILD.md` | 完整构建 / arm64 交叉 / Magisk 打包 / 验证 |
| `USAGE.md` | 使用 / split.yaml / 排障（Q1-Q8 为真机故障模式） |
| `docs/01..06` | 架构 / 模块说明书 / Android / 配置 / 术语 / 路线图 |
| **各目录 `MEMORY.md`** | **改该目录代码前必读**：实现决策、踩过的坑、硬契约。没有则视为新模块，改完补一份 |

提交信息格式（CONTRIBUTING §4）：`<模块>: <一句话改动>` + `- 影响：` / `- 验证：` 两行。改了行为/契约 → 同步对应 `MEMORY.md` + `docs/`（同一提交）。

## 构建 / 验证命令（Linux 或 WSL2）

```bash
make bpf           # kernel/bpf/split.bpf.o（架构无关；kernel/Makefile 的 -mcpu=v1 必须保留）
make userspace     # userspace/build/{splitd,splitctl}
make all           # = bpf + userspace
make arm64 LIBBPF=/root/bpf_deps/libbpf   # 或 ./scripts/build_arm64.sh（Android arm64 静态交叉）
make android       # 打包 build/split-magisk-v{VERSION}.zip（= ./scripts/gen-magisk.sh）
make prepare       # 一键安装全部构建依赖（Debian/Ubuntu，含 arm64 交叉工具链）

# 验证
./userspace/build/splitctl validate -c configs/split.yaml.example   # 配置校验
sudo ./tests/integration.sh        # 端到端冒烟（需 root + mihomo 已起 + 已 load；tests/unit 目前为空骨架）
make -C kernel validate           # BPF verifier 冒烟（需 root + bpffs）
./android/scripts/check-kernel.sh # 目标机内核能力矩阵
```

- BPF 验证注意：`SEC("classifier")` 是旧式 section，libbpf≥1.0 下裸 `bpftool prog load` 会报类型推断失败（非程序错误）。生产路径由 loader 显式 `bpf_program__set_type(..., BPF_PROG_TYPE_SCHED_CLS)`，验证用 splitd 加载（exit 非 2 即 verifier 通过）。
- 版本号递增**唯一入口**是 `./scripts/bump-version.sh [patch|minor|major] [-y]`，禁止手工改派生位置（见"版本号"节）。

## 架构总览

eBPF 内核级分流：挂在物理网卡 **tc egress**（`SEC("classifier")` 唯一程序），对每个出站包裁决：
- **直连**（CNIP LPM_TRIE 命中 / 内网 / UID 白名单 / default=direct）→ `TC_ACT_OK` 放行，不经代理。
- **代理**（proxy 规则 / default=proxy）→ 先 `skb->queue_mapping = 0`，再 `bpf_redirect(tun, 0)` 送进 mihomo 的 TUN。

**内核侧** `kernel/bpf/`（纯 C）：
```
split.bpf.c（唯一入口）──> parse.h（安全解析）──> policy.h（7 步裁决）──> radix.h（LPM 匹配）
                              └────────────────────────────> maps.h（全部 map，单一真相源）
```
- `kernel/include/split_bpf.h` 是 **L0 全局 ABI**：被内核 BPF 与用户态共用；结构体/枚举数值即 map 持久值，只可尾部追加、禁止重排。
- `maps.h` 是全部 BPF map 的单一真相源；改 map 类型/容量/结构必须同步 `userspace/loader/loader.c` 的按名查找期望表与 docs/02 的 map 表。

**用户态** `userspace/`（C + libbpf≥1.0，无其它第三方依赖）：
- `splitd`（daemon/daemon.c）：生命周期、ctl 协议、iface 挂载自愈心跳（15s，netlink 事件路径兜快速响应）、tun ifindex 存活同步（1s 心跳）、CNIP 定时刷新（fork 子进程）。
- `splitctl`（cli/）：`start stop status stats list-rules reload reload-cnip update-cnip add-rule del-rule validate`，经 Unix socket 与 daemon 通信。
- 模块划分：common（log/config 极简 YAML/netlink/paths）、loader（加载+tc 挂载）、cni（CNIP）、rule（规则）。

模块原则：一模块一目录一职责；**只有 `maps.h`（内核）与 `loader.h`（用户态）暴露全局 map**，其余模块经 map 名解耦。
splitd 退出码契约（daemon/MEMORY，改必同步 android/magisk/service.sh）：config 失败 exit 1、BPF 加载失败 exit 2（直接退出非降级）、tun 缺失 exit 3、单实例锁被占 exit 4。

## 硬契约（勿回退，详见 CODE.md §3.4 / 各 MEMORY.md）

- **绝不丢包**：任何解析失败/异常/无 tun 分支一律 `return TC_ACT_OK`；`parse` 越界 → 返回 0（不可判），上层放行。
- **`-mcpu=v1` 必须保留**：Android 5.x GKI verifier 只认老 `BPF_XADD`，去掉会在真机报 `BPF_STX uses reserved fields`。**WSL2 能过 ≠ 真机能过**。
- **`bpf_redirect(tun, 0)` 前必须先 `skb->queue_mapping = 0`**：多队列物理网卡 egress 继承的 queue_mapping>0 会让单队列 tun `tfile=NULL` 直接丢包。
- **policy 判定顺序固定（7 步，policy.h 注释即真相）**：skip_uid → v6 且 ipv6_classify=0 → 内置本地段 → proxy → direct → CNIP → default。改顺序 = 改分流语义，必须同步 docs/01、docs/02、README。
- **ctl 协议**：Unix socket，**单命令一连接**（回复后即 close，勿改回多命令循环）；命令前缀 `stats/status/list-rules/reload/reload-cnip/update-cnip/add-rule/del-rule/stop`；回复首行 `OK/ERR`、末行 `END`。`status` 字段与 WARN 行被 WebUI app.js 解析，改格式必须同步 app.js。
- **LPM key 字节序**：`prefixlen` 在前（内核 `lpm_key4/6` 与用户态 k4/k6 需字节级一致）。
- **tc attach 固定 `handle=1 priority=10`**；detach 必须传相同值；attach 必须带 `BPF_TC_F_REPLACE`（防残留 filter 静默失效）。
- **读 map value 的变量下标必须显式掩码到 `< 2 的幂` 且无条件前置**（放守卫内会被 clang 折叠掉，真机 5.x verifier 拒载）；勿对栈数组做变量偏移读（改读同内容 map value + 掩码）。此铁律曾沉淀自域名规则（v1.4.0 整模块移除，见 kernel/bpf/MEMORY 第 19 条），仍适用于任何读 map value 变量下标的代码。
- **map_cfg 是 ARRAY map，lookup 永不 NULL**：未写入时返回全零元素（default_verdict=0=直连，与"未知→代理"直觉相反）。loader `map_set_cfg` 置 `bpf_trace_enabled=1` 作"已初始化"哨兵；policy.h 对 `!cfg || bpf_trace_enabled==0` 回落 TUN 安全默认。
- **map 改名/结构改 = 破坏 ABI**：用户态按名字 `bpf_object__find_map_by_name` 查找。
- **stats key 编号与 `daemon.c ctl_stats` 的 names 数组一一对应**：只可尾部追加、不可重排/插入；`STAT_DROPPED=7` 是保留位（恒 0，勿删）。

## 版本号管理（唯一真源）

- **唯一真源**：`kernel/include/split_bpf.h` 的 `SPLIT_VERSION "X.Y.Z"`。
- **发版递增一律走 `./scripts/bump-version.sh [patch|minor|major]`**：自动同步 `android/magisk/module.prop`（version + versionCode，无碰撞公式 `major*10000+minor*100+patch`）、`docs/06-ROADMAP.md`、根文档头部版本标注。**禁止手工改这些派生位置**（多源漂移根因）。递增后手动补写 roadmap 新版本变更摘要并 `git diff` 复查。

## 语言与风格

- 仓库文档/注释用**中文**；代码标识符一律英文 `snake_case`；map 名前缀 `map_`，函数前缀 `split_/cnip_/iface_/rule_/ctl_`。
- `.c/.h` 成对；头文件防护 `#ifndef __SPLIT_..._`；每个 `.c/.h` 顶部带 `/* SPDX-License-Identifier: GPL-2.0 */`。
- 安全底线：打包配置只含占位符（`YOUR_TOKEN_*` 等）；原始敏感配置（`config.yaml.real`）不得入库。
