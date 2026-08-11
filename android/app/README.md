# app/ — 原生 App 骨架（预留）

当前阶段以"**root 脚本 / Magisk 模块**"方式交付，App 层是可选增强。

如果你想做成"真安卓应用"（无需 Magisk、带 UI），建议：

1. **JNI 封装**：把 `daemon/daemon.c` 的入口包装成 `Java` 调用
   （`System.loadLibrary("split")` + `splitStart(cfgPath)` / `splitStop()`）。
2. **shell 环境**：`splitd` 需要 root；App 通过 `Runtime.exec("su")` 代跑，
   或集成 [KernelSU/APatch] 的 binder。
3. **bpf/selinux**：路线同 docs/03-ANDROID.md §2（sepolicy 由 App 安装到
   `/data/adb/kernel-sepolicy` 或引导用户用 Magisk）。
4. 本项目建议 MVP：**App 只做开关 + 状态 + stats 展示**，内核逻辑全在 splitd。

> 现阶段直接在 adb 下：
> ```
> adb shell su -c sh /data/adb/split/scripts/start-split.sh
> ```
>
> 之后的 roadmap 里放"原生 App MVP"计划（见 docs/06-ROADMAP）。