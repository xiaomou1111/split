# kernel/include/split_bpf.h — 记忆文档（改本文件前必读）

## 地位
**L0 唯一共享头**：被 kernel/bpf/*.h、userspace 全部模块、docs 三方引用。**它是全局 ABI。**

## 契约与坑
1. `__KERNEL__` 守卫：`SPLIT_VERSION` / `SPLIT_PIN_NS` / `SPLIT_SOCKET` 仅用户态可见；BPF 编译时不可见（clang `-target bpf` 不定义 `__KERNEL__`）。
2. `enum split_verdict` / `enum split_family` / `struct split_cfg` 的**数值即 map 内持久值**：枚举顺序重排 = 破坏已写入 map 的数据兼容性，禁止重排（只可尾部追加）。
3. `struct lpm_key4/6` 与 `userspace/loader/loader.c` 的 `struct k4/k6` **字节布局必须一致**（prefixlen 在前、addr 在后、无填充歧义：uint32+u8[4]/u8[16]）。
4. `struct split_pkt` 的 dst 联合：v4 只写前 4 字节（`memcpy 4`），v6 写 16 字节——policy/parse 按 `family` 决定读哪里。
5. `STAT_*` 编号与 `daemon.c ctl_stats` 的名字数组**一一对应（下标即名字）**，只可追加不可重排。
   `STAT_DROPPED=7` 是**保留位**：本项目"绝不丢包"、无 drop 路径，恒 0（v1.2.8 注释点明，勿删）。
6. 改动任何结构/常量 → 同步检查：loader.c 的 map_set_cfg、k4/k6、daemon.c 的 stats 名、cli 的输出格式、docs/02-MODULES.md。

## 验证
- 无独立编译单元（header only）；改动后用 `make -C kernel bpf` + `make -C userspace` 双端验证。
