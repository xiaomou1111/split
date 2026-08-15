# 安卓兼容层（android/）

本目录是 **eBPF-Split（v1.4.8）的安卓落地包**。核心逻辑与桌面 Linux 完全一致，
这里解决的是安卓特有的三件事：

1. **权限**：root（Magisk/KernelSU）+ SELinux 放行（sepolicy / magiskpolicy）
2. **打包**：Magisk 模块结构（`android/magisk/`）
3. **自检/降级**：`check-kernel.sh` 先探测，不满足就自动退纯 TUN
4. **存活守护**：`split-watchdog.sh`（splitd 探活拉起 + mihomo TUN 消失自愈，v1.2.9）

## 装机流程（Magisk 模块）

```bash
# 1. 在 Linux 宿主机构建
make bpf userspace
./scripts/gen-magisk.sh          # 生成 build/split-magisk-v{VERSION}.zip

# 2. 推送到手机并安装
adb push build/split-magisk-v{VERSION}.zip /sdcard/
# 打开 Magisk → 模块 → 从本地安装 → split-magisk-v{VERSION}.zip → 重启

# 3. 装代理（三选一）
#    a) 随包 mihomo（zip 内含 build/arm64/mihomo + 脱敏配置）：
#       编辑 /data/adb/split/mihomo/config.yaml 填入 YOUR_TOKEN_* → 重启即可
#    b) mihomo 官方 apk，确认 tun 设备名为 utun，再配置 split.yaml 的 skip_uid
#    c) 复用已有 box 代理：adb shell "sh /data/adb/split/scripts/setup-box-tun.sh"
#
#    mihomo 二进制放哪？→ 运行目录 /data/adb/split/bin/（或复用 box 的 /data/adb/box/bin/），
#    绝不放 /data/adb/modules/ 下（非 root 不可读 + Magisk overlay 管理会丢配置，见
#    android/MEMORY.md「mihomo 放哪」）

# 4. 验证
adb shell su -c "/data/adb/split/bin/splitctl status"
adb shell su -c "/data/adb/split/bin/splitctl stats"
```

> KernelSU / APatch 用户：模块同样可用，路径 `sepolicy.rule` 由 manager 自动注入。

## 目录说明

```
android/
├── README.md             ← 本文件
├── magisk/               ← Magisk 模块骨架（装完即 /data/adb/modules/split-magisk/）
│   ├── module.prop       ← 模块元信息
│   ├── customize.sh      ← 安装时动作（把二进制拷进 /data/adb/split/）
│   ├── post-fs-data.sh   ← 早启动：挂载 bpffs
│   ├── service.sh        ← late_start：起 mihomo → 起 splitd
│   └── sepolicy.rule     ← 安装时注入的 SELinux 规则（Magisk 编译进 policy）
├── scripts/              ← 独立脚本（可直接 adb 执行，不依赖模块）
│   ├── check-kernel.sh   ← 内核能力探测（返回 0/1）
│   ├── start-split.sh    ← 手动启动
│   ├── stop-split.sh     ← 手动停止
│   ├── split-watchdog.sh ← 存活守护：splitd 探活拉起 + mihomo TUN 消失自愈（v1.2.9）
│   ├── setup-box-tun.sh  ← 一键接入已有 box 代理（复用 mihomo + 订阅）
│   └── webuiapi.sh       ← KernelSU WebUI 后端（root，动作白名单）
├── magisk/webroot/       ← KernelSU WebUI 前端（index.html + app.js）
└── app/                  ← 预留原生 App 骨架位置（见其中 README）
```

## KernelSU WebUI（可选）

安装后若用 **KernelSU / APatch**，模块详情页会显示 **WebUI** 入口（KernelSU Manager
内置 WebView）：状态与 stats、在线规则列表与增删、编辑 split.yaml
（校验后保存并 reload）、splitd/mihomo 开关、日志查看、版本号。Magisk 无 WebUI 机制，
这类用户仍走 adb/原生 App（见 android/app/README）。

- 前端：`magisk/webroot/`（`index.html` + `app.js` + `style.css` + `kernelsu.js`，vendored npm `kernelsu`）。
- 后端：`scripts/webuiapi.sh`（root 经 `ksu.exec` 调用，装在 `/data/adb/split/scripts/`），动作白名单见文件头。

## 已知限制（务必先读 docs/03-ANDROID.md）

- **必须 root**；未 root 的手机请用 mihomo 官方 APK 的 TUN 模式（本框架自动降级即可，不装模块）。
- **fake-ip 模式失去内核 CNIP 分流**（原因见 docs/03-ANDROID.md §4）。
- 设备内核老于 4.19 或厂商砍了 `CONFIG_NET_CLS_BPF` → 模块启动时自动跳过 eBPF，
  退化为"mihomo 纯 TUN"（`service.sh` 会自动加 `auto-route` 让 mihomo 自己接管）。
