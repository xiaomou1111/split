# AGENTS.md — 项目约定（AI / 开发者通用）

> eBPF-Split：用 eBPF 在内核完成 CNIP 分流，海外流量转发给 mihomo 的 TUN。
> 面向读者：AI 助手 + 人类开发者。**改模块代码前先读对应 `MEMORY.md`。**
> 本文件是硬约定；详细文档见 README/CODE/BUILD/docs/。

## 目标环境与平台

- **仓库在 Windows 编写，目标运行环境为 Linux 内核设备（含 Android GKI）**。
- 不能在 Windows 上直接编译/运行；构建验证需在 Linux（Debian/Ubuntu 或 WSL2）执行。
- 本机是 win32，**禁止用 Windows 假想编译成功**——只能静态审查。

## 项目是什么

- 分层式网络分流：内核侧 `kernel/bpf/`（TC egress eBPF）判"直连 vs 代理"，
  直连放行，代理 `bpf_redirect(tun0)` 转给 mihomo。
- 一模块、一目录、一职责；`maps.h`（内核）与 `loader.h`（用户态）是全局 map 唯一通道。

## 必读工作流

1. 改某目录代码前，**先读该目录的 `MEMORY.md`**（实现决策、踩过的坑、硬契约）。
   没有则视为新模块，改完补一份。
2. 改了行为/契约 → 同步更新对应 `MEMORY.md` + `docs/`（同一提交）。
3. 提交信息格式：
   ```
   <模块>: <一句话改动>
   <空行>
   - 影响：
   - 验证：
   ```

## 模块边界（强约束）

- **只有** `kernel/bpf/maps.h`（内核）与 `userspace/loader/loader.h`（用户态）暴露全局 map。
- 改 map 类型/容量/结构 → 只改 `maps.h`，并同步 `docs/02-MODULES.md` 的 map 表 +
  `userspace/loader/loader.c` 的 map 名/期望表（用户态按名字 `bpf_object__find_map_by_name` 访问）。
- 新增 hook（如 ingress）→ 在 `split.bpf.c` 加 SEC + 挂载代码，其余模块不动。
- 内核侧唯一入口 `split.bpf.c` `SEC("classifier")`,挂 tc clsact **egress**。
- BPF 程序统一放 `kernel/bpf/`，以 `.bpf.c` 结尾。

## 语言与风格

- 仓库文档/注释用**中文**；代码标识符一律英文 `snake_case`。
- 源文件 `.c/.h` 成对；头文件防护宏 `#ifndef __SPLIT_..._`（统一前缀）。
- 每个 `.c/.h` 顶部带 `/* SPDX-License-Identifier: GPL-2.0` 头。
- 命名：map 名前缀 `map_`；函数前缀 `split_/cnip_/iface_/rule_/ctl_`。
- map 值统一 `__u8 = 1` 成员标记；`__be` 表示网络字节序。

## BPF 编写铁律（verifier）

- 所有指针读前做边界检查：`data + n > data_end` 一律放行放行，绝不越界读。
- **不确定时绝不丢包**：错误分支 `return TC_ACT_OK`。
- 栈占用 < 512B；无循环（除非明确 bounded 展开）；只调用允许的 helper。
- 内联函数全部 `__always_inline`。
- 先把 `skb->queue_mapping = 0` 再 `bpf_redirect(tun, 0)`（Android 多队列网卡必须）。
- 编译 `-mcpu=v1` 强制（避免 `BPF_STX uses reserved fields`，兼容 5.x GKI）。

## 关键硬契约（勿回退，详见 CODE.md §3.4 / 各 MEMORY.md）

- `parse` 越界 → 返回 0（不可判），上层放行。
- `policy` 判定顺序固定（policy.h 注释即真相）：skip_uid → v6 不分类直连（ipv6_classify=false）→ 内置本地段 → proxy → direct → CNIP → default。
- ctl 协议：Unix socket **单命令一连接**，回复后即 close；命令前缀 `stats/status/list-rules/reload/reload-cnip/add-rule/del-rule/stop`。
- LPM key 字节序：`prefixlen` 在前（`lpm_key4/6` 与用户态需字节级一致）。
- tc attach 固定 `handle=1 priority=10`；detach 必须传相同值。
- 打包配置只含占位符（`YOUR_*`），原始敏感配置（`config.yaml.real`）不得入库。

## 构建要点

- `make bpf`（内核 BPF，架构无关）、`make userspace`（splitd+splitctl）、`make all`。
- arm64 Android 交叉：`./scripts/build_arm64.sh <libbpf目录>`；打包：`./scripts/gen-magisk.sh`。
- 依赖：clang >= 12、llvm-strip、libbpf >= 1.0、libelf、bpftool；arm64 交叉需 `gcc-aarch64-linux-gnu`。
- libbpf 交叉编译放持久目录（如 `/root/bpf_deps`），勿放 `/tmp`（WSL 会清）。
- Windows 下无法编译，只能审查代码正确性。

## 版本号管理（唯一真源 + 一键递增）

- **唯一真源**：`kernel/include/split_bpf.h` 的 `SPLIT_VERSION "X.Y.Z"`。
- **发版递增一律走 `./scripts/bump-version.sh [patch|minor|major]`**（v1.3.0 起），
  它会同步 `module.prop`(version/versionCode)、`docs/06-ROADMAP.md`（当前标注）、
  根文档头部版本标注。**禁止手工改派生位置**，避免多源漂移。
- versionCode 无碰撞公式：`major*10000+minor*100+patch`（与 gen-magisk.sh 一致）。
- 打包时 `gen-magisk.sh` 读真源改写 zip 内 module.prop / webuiapi.sh 的 `SPLIT_VERSION`。
- 递增后需手动补写 roadmap 新版本变更摘要并复查无历史引用误改。

## 验证清单（提交前）

```bash
make bpf            # 至少纯编译通过
make userspace
sudo ./tests/integration.sh   # 冒烟
./android/scripts/check-kernel.sh  # 目标机能力
```

## 不做的事（Scope）

- 不引入重量级依赖（libbpf + libc 即可）；不把 UI/App 逻辑塞进 daemon。
- 不丢包兜底；不上线前不删 degrade 路径。
- 无 pinning（`SPLIT_PIN_NS` 仅常量未用）；新增前先对齐现有指南。