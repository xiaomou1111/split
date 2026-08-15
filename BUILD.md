# 构建指导（BUILD.md）

> eBPF-Split v1.4.7 ｜ 从源码到可分发模块的完整构建流程
> 覆盖：Linux 原生构建、arm64 交叉编译、Magisk 模块打包、常见问题

---

## 1. 构建产物总览

| 产物 | 位置 | 用途 |
|---|---|---|
| `kernel/bpf/split.bpf.o` | kernel/bpf/ | BPF 对象（架构无关） |
| `userspace/build/splitd` | userspace/build/ | 守护进程（x86_64） |
| `userspace/build/splitctl` | userspace/build/ | CLI（x86_64） |
| `build/arm64/splitd` | build/arm64/ | Android arm64 守护（静态） |
| `build/arm64/splitctl` | build/arm64/ | Android arm64 CLI（静态） |
| `build/arm64/mihomo` | build/arm64/ | Android arm64 代理内核（可选） |
| `build/split-magisk-v{VERSION}.zip` | build/ | 完整 Magisk 模块 |

---

## 2. 环境要求

### 2.1 通用（Debian/Ubuntu）
```bash
# 一键安装全部构建依赖（含 arm64 交叉工具链与 multiarch 链接库，等价下面全部）：
sudo make prepare
# 或手动（multiarch 源已就绪时）：
sudo dpkg --add-architecture arm64
sudo apt update
sudo apt install clang llvm libbpf-dev libelf-dev zip curl \
                 zlib1g-dev libzstd-dev liblzma-dev libbz2-dev \
                 gcc-aarch64-linux-gnu
# arm64 交叉链接库（build_arm64 需要）：
sudo apt install libelf-dev:arm64 zlib1g-dev:arm64 \
                 libzstd-dev:arm64 liblzma-dev:arm64 libbz2-dev:arm64
```
> **Ubuntu multiarch 源（v1.4.5，WSL2/24.04 实测）**：Ubuntu 的 `archive.ubuntu.com` /
> `security.ubuntu.com` 只发布 amd64/i386，**不发布 binary-arm64**（arm64 包只在
> `ports.ubuntu.com`）。裸 `dpkg --add-architecture arm64` 后 `apt update` 会对 native 源
> 请求 arm64 包 → **HTTP 404 直接失败**。`make prepare` 已内置 `scripts/ensure-arm64-source.sh`
> 幂等修复：native 源显式限 `Architectures: amd64` + 追加 ports arm64 源；手动搭环境时
> 先跑一次 `sudo ./scripts/ensure-arm64-source.sh`。Debian 无此问题（deb.debian.org 全架构同源）。
> **bpftool（可选，仅 `make -C kernel validate/disasm`）**：Ubuntu 24.04 无独立候选包，
> 需要时装 `linux-tools-common`。
> 注：用户态链接库清单 `-lbpf -lelf -lz -lzstd -llzma -lbz2` 在
> `userspace/Makefile` 的 `LIBS`（唯一真源），`scripts/build_arm64.sh` 通过
> `make print-libs` 读取，两边不会不一致。

### 2.2 libbpf 交叉编译（build_arm64 需要）
```bash
# 放到持久目录（/root，勿放 /tmp——WSL 会清）
git clone https://github.com/libbpf/libbpf /root/bpf_deps/libbpf
cd /root/bpf_deps/libbpf/src
make BUILD_STATIC_ONLY=1 CC=aarch64-linux-gnu-gcc AR=aarch64-linux-gnu-ar
# 产物: /root/bpf_deps/libbpf/src/libbpf.a
```

### 2.3 环境变量
```bash
export PATH="$HOME/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"  # 如用 NDK
```

---

## 3. 构建步骤

### 3.1 一步构建（Linux 宿主机全量）

```bash
make all        # = make bpf + make userspace
```

### 3.2 分开构建（推荐，便于排查）

```bash
# 1) BPF 对象（架构无关）
make bpf
# 产物 kernel/bpf/split.bpf.o

# 2) 用户态（x86_64，宿主机验证用）
make userspace
# 产物 userspace/build/{splitd,splitctl}
# （v1.1.0 起逐对象增量编译：中间 .o 在 userspace/build/obj/，改单文件只重编相关对象，
#   -MMD 头文件变更自动触发重编，支持 make -j 并行）
```

### 3.3 交叉编译 arm64（Android 真机）

```bash
# libbpf 就绪后：
./scripts/build_arm64.sh /root/bpf_deps/libbpf   # 默认输出到 build/arm64/
# 或等价：make arm64 LIBBPF=/root/bpf_deps/libbpf
# 产物 build/arm64/{splitd,splitctl}（静态 aarch64）
```
> build_arm64.sh 是 `userspace/Makefile` 的薄包装（覆盖 OUTDIR/CC/CFLAGS/LDFLAGS），
> 源文件与链接库清单只有 Makefile 一份。

### 3.4 准备 mihomo 内核（可选，随包）

把 Android arm64 mihomo 放 `build/arm64/mihomo`：
```bash
# 从真机拉取（root）：
adb root
adb shell "cp /data/adb/box/bin/mihomo /data/local/tmp/ && chmod 644 /data/local/tmp/mihomo"
adb pull /data/local/tmp/mihomo build/arm64/mihomo
```

### 3.5 准备 CNIP 数据（可选）

```bash
./scripts/fetch-cnip.sh        # 生成 data/cnip/cn_cidr_v4.txt 等
```

### 3.6 打包 Magisk 模块

```bash
# 确保 build/arm64/ 有 splitd/splitctl（mihomo 可选）
./scripts/gen-magisk.sh        # 或 make android
# 产物 build/split-magisk-v{VERSION}.zip
```
> 版本号唯一真源是 `kernel/include/split_bpf.h` 的 `SPLIT_VERSION`（v1.1.0 起打包时
> 自动改写 zip 内 module.prop 的 version/versionCode，不再需要手工同步两处）。
> **发版递增用 `./scripts/bump-version.sh [patch|minor|major]`**（v1.3.0 起）：读真源递增并同步
> module.prop / docs/06-ROADMAP.md / 根文档头部版本标注，避免多源漂移。

---

## 4. 验证

### 4.1 BPF 语法（WSL2/Linux）

> 注意：`SEC("classifier")` 是旧式 section 名，libbpf>=1.0 不再按它推断程序类型。
> `bpftool prog load ... type sched_cls` 会报
> `failed to guess program type from ELF section`（非程序本身错误）。生产路径由 loader
> 显式 `bpf_program__set_type(..., BPF_PROG_TYPE_SCHED_CLS)` 处理。**验证请用 splitd**：

```bash
# 1) 编译 + 通过内核 verifier（splitd 加载成功即 verifier 通过）
sudo ./userspace/build/splitd -c configs/split.yaml -b kernel/bpf/split.bpf.o
#    exit 0 / exit 3（缺 tun，属预期）= 加载 OK；exit 2 = 加载失败需排查
# 2) 旧式命令已失效，仅作参考：
#    bpftool prog load kernel/bpf/split.bpf.o /sys/fs/bpf/test type sched_cls
#    若报 BPF_STX uses reserved fields → 检查 -mcpu=v1 是否在 Makefile
```

### 4.2 配置校验

```bash
./userspace/build/splitctl validate -c configs/split.yaml.example
```

### 4.3 交叉编译产物校验

```bash
file build/arm64/splitd   # 应为: ARM aarch64, statically linked
file build/arm64/mihomo   # 应为: ARM aarch64, Android（动态）
```

### 4.4 打包内容校验（含脱敏检查）

```bash
unzip -l build/split-magisk-v{VERSION}.zip              # 检查结构
unzip -p build/split-magisk-v{VERSION}.zip mihomo/config.yaml \
  | grep -c 'YOUR_'                                     # 期望 = 8（全部为占位符）
# 确认压缩包内不含真实订阅 token / 密码 / 节点 IP：
unzip -l build/split-magisk-v{VERSION}.zip | grep -iE 'real|token|pass' || echo "clean"
```

---

## 5. Android 部署

```bash
adb push build/split-magisk-v{VERSION}.zip /sdcard/
# Magisk/KernelSU → 模块 → 本地安装 → 选 zip → 重启
# 若随包 mihomo：编辑 /data/adb/split/mihomo/config.yaml 填 YOUR_TOKEN_* → 重启
```

真机验证：
```bash
adb shell "sh /data/adb/split/scripts/setup-box-tun.sh"   # 接入 box（可选）
adb shell "export SPLIT_SOCKET=/data/adb/split/run/splitd.sock; /data/adb/split/bin/splitctl status"
adb shell "... splitctl stats"                             # 看 direct_cn/proxy
```

---

## 6. 常见问题

| 问题 | 解决 |
|---|---|
| BPF 编译报 `asm/types.h` 找不到 | kernel/Makefile 加 `-I /usr/include/$(uname -m)-linux-gnu` |
| 原生 `make userspace` 报缺 `-lzstd/-llzma/-lbz2` | `sudo make prepare`（或 `apt install libzstd-dev liblzma-dev libbz2-dev`） |
| 真机加载 `BPF_STX uses reserved fields` | 确认 `-mcpu=v1` |
| arm64 链接报 libelf 缺失 | `apt install libelf-dev:arm64`（multiarch） |
| Ubuntu 上 `apt update` 报 `archive.ubuntu.com` 404 / binary-arm64 | `sudo ./scripts/ensure-arm64-source.sh` 后重试（make prepare 已内置） |
| `apt install bpftool` 无候选包（24.04） | 可选包，仅 validate 用；装 `linux-tools-common` 或跳过 |
| gen-magisk.sh 报 zip 目录错误 | 确认 `zip` 已装；脚本已修 `mkdir -p "$(dirname)"` |
| 打包没 mihomo | 把 mihomo 放 build/arm64/mihomo |
| 构建区被 WSL 清 | libbpf 放 /root（持久），勿放 /tmp |

---

## 7. 完整流程速查

```bash
# 宿主机一步到位（Linux + arm64 交叉 + 打包）
make bpf && make userspace
./scripts/build_arm64.sh /root/bpf_deps/libbpf
# （可选）cp <mihomo> build/arm64/mihomo
./scripts/gen-magisk.sh
# 产物 build/split-magisk-v{VERSION}.zip 可直接刷
```
