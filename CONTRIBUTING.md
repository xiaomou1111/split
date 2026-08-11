# CONTRIBUTING — 开发规范

> 本仓库理念：**一个模块，一个目录，一个职责**。提交代码前请自检本文件。

## 1. 目录与命名

- 目录名全小写，功能词（`kernel/`, `userspace/`, `android/`, `docs/`）。
- BPF 程序统一在 `kernel/bpf/`，以 `.bpf.c` 结尾；内含 SEC("classifier")。
- 用户态文件 `.c/.h` 成对出现；头文件 `#ifndef SPLIT_..._H_` 防护。
- 命名：`snake_case`；map 名前缀 `map_`；函数前缀 `split_/cnip_/iface_/rule_/ctl_`。

## 1.5 模块记忆（MEMORY.md）—— 改码前必读

- **改某个模块的代码前，先读该目录下的 `MEMORY.md`**（实现决策、踩过的坑、与别处硬契约）。没有记忆文档的目录视作新模块，改完应补一份。
- 记忆文档不是文档冗余，而是"被代码/历史验证过的结论"，包含：接口契约、端序/容量等易错点、已知缺口。它比 `docs/` 更贴近实现。
- 改了行为/契约 → 同步更新对应 `MEMORY.md`（一句话即可），否则记忆失真。

## 2. 模块边界

- **只有** `maps.h`（内核）与 `loader.h`（用户态）对其它模块暴露"全局 map"。
- 改动 map 内容/结构 → 编辑 `kernel/bpf/maps.h`，同时：
  - 更新 `docs/02-MODULES.md` 的 map 表
  - 检查 `userspace/loader/loader.c` 的 map 名引用
- 新增一个 hook（如 ingress）→ `split.bpf.c` 增加 SEC + `attach.c`，其余不动。

## 3. BPF 编写纪律（verifier 相关）

- 所有指针读前做边界检查（`data + n > data_end` 一律放行，不打折）。
- **不得在不确定时丢包**：错误分支 return `TC_ACT_OK`。
- 栈占用 < 512B；无循环（除非明确 bounded 展开）；无 helper 不允许的调用。
- 用 `__always_inline` 包裹所有内联函数。

## 4. 提交信息

```
<模块>: <一句话改动>

- 影响：
- 验证：
```

示例：
```
loader: 增加网络切换时 iface_reconcile 重挂

- 影响：daemon 网络变化自动跟随挂载
- 验证：tests/integration.sh（WIFI↔蜂窝切换）
```

## 4.5 版本号递增

- **唯一真源**：`kernel/include/split_bpf.h` 的 `SPLIT_VERSION`。
- **发版递增一律走 `./scripts/bump-version.sh [patch|minor|major]`**——自动同步
  `module.prop`（version/versionCode）、`docs/06-ROADMAP.md`（当前标注）、根文档头部版本。
  **不要手工改这些派生位置**（多源漂移根因）。
- 递增后手动补写 roadmap 新版本变更摘要，并 `git diff` 复查无功能历史引用被误改。

## 5. 验证清单（提交前）

```bash
make bpf            # 至少纯编译通过
make userspace
sudo ./tests/integration.sh   # 冒烟
./android/scripts/check-kernel.sh     # 目标机能力（或根 scripts/ 的宿主机版）
```

## 6. 文档同步

- 改了判定顺序/新增 map/新增命令 → 同步 `docs/01..06`。
- 写了新限制 → 记入 `docs/01-ARCHITECTURE.md` 的"已知边界"。
- 行为变化避免"文档与代码不一致"——优先改代码同时改文档，同一次提交。

## 7. 不做的事（Scope）

- 不引入重量级依赖（libbpf + libc 即可）。
- 不把 UI/App 逻辑塞进 daemon。
- 不丢包兜底、不上线前不删 degrade 路径。