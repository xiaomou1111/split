# scripts — 记忆文档（改本目录代码前必读）

## build.sh
- 顶层构建入口（透传目标给 make，缺省 `all`）：`./scripts/build.sh [bpf|userspace|all|arm64|android|test|install|clean|prepare]`。
- v1.1.0：加 `-h/--help/help` 与目标白名单校验（未知目标报错退出）。
- 后续：白名单补 `help`/`prepare`（此前 `build.sh prepare` 被误报"未知目标"，与 Makefile 目标不一致）；顶层 Makefile `.PHONY` 补 `arm64`。

## build_arm64.sh
- 交叉编译入口：**v1.0.6 起改为 userspace/Makefile 的薄包装**——只传 `OUTDIR/CC/CFLAGS/LDFLAGS`，
  源文件清单（COMMON/LOADER/CNI/RULE/DAEMON/CLI）与链接库清单不再在脚本里复制。
- 链接库清单唯一真源是 userspace/Makefile 的 `LIBS`（`-lbpf -lelf -lz -lzstd -llzma -lbz2`），
  脚本用 `make -C userspace -s print-libs` 读取，交叉时仅追加 `-static` 与 `-L` 路径。
- 入参不变：`./scripts/build_arm64.sh [libbpf_src_dir] [out_dir]`，默认
  libbpf=/root/bpf_deps/libbpf、out=build/arm64；缺 libbpf.a 时硬性报错退出。
- v1.1.0：开头加交叉工具链检查（aarch64-linux-gnu-gcc / aarch64-linux-gnu-ar 缺失即报错退出，
  提示 make prepare）；结果展示的 `file` 命令做存在性容错。
- 依赖：aarch64-linux-gnu-gcc + libbpf 源码 + libelf/libz/libzstd/llzma/libbz2 的 arm64 dev 包。
- **坑（v1.2.0，已消除）**：`-I$LIBBPF/include` 会把 libbpf 源码树自带的内部
  `include/linux/filter.h` 遮蔽系统 `/usr/include/linux/filter.h`，曾致 `dns/dns.c` 交叉编译
  报错（缺 cBPF 的 struct sock_filter/BPF_STMT）。修复当时在 `dns/dns.c` 用 `#ifndef BPF_STMT`
  守卫补 cBPF 定义；**v1.2.7 移除 dns 学习器 cBPF filter、v1.4.0 整模块移除后该坑不复存在**
  （勿回退——`userspace/dns/` 已删除，引回该模块即重新引入此坑）。

## load-debug.sh
- 宿主机（Linux）调试加载：先挂 clsact 再 attach 到主出口网卡（一般 `lo` 或主网卡），用于无 daemon 时快速验证。
- **v1.0.6 新增 `del` 模式**：`sudo ./scripts/load-debug.sh del` 卸载（tc filter del + qdisc del），
  修复"只加载不清理"的坑；注意会一并删掉该网卡原有 clsact。

## fetch-cnip.sh
- 默认源（**v1.4.3 起为 mihomo 生态权威源 Loyalsoldier/geoip**，与 config.c 默认 URL、docs/04 一致）：
  - 单一 `cn.txt`（`release` 分支 `text/cn.txt`，每日更新）：**v4+v6 混合**纯 CIDR 文件，
    LF、无注释行（实测 v4=4145 / v6=1235 条，0 非法行）。下载后按族 grep 拆分为
    `cn_cidr_v4.txt`（`^[0-9.]+/[0-9]+$`）/ `cn_cidr_v6.txt`（`^[0-9a-fA-F:]+/[0-9]+$`），
    再删中间文件——daemon 自动更新路径则直接落同一混合文件、按族加载（见 cni/MEMORY 第 8 条）。
    历史源已弃用：v4 `misakaio/chnroutes2`（每日 APNIC 聚合 3908 条）、v6 `gaoyifan`
    （1235 条）、更早 `17mon/china_ip_list`（季度、非聚合 ~8.7k 条、CC-BY-NC-SA）。
  - **多源 fallback（v1.4.2）**：`dl_candidates()` 按序尝试候选数组（jsDelivr 大陆可达
    优先 → raw.githubusercontent 兜底），任一成功（非空）即用；与 config.c 默认逗号串一致。
    WSL 实测（2026-08）：本网络 raw.githubusercontent.com 被屏蔽（HTTP=000），jsDelivr 可达
    （cn.txt v4=4145 / v6=1235 行，0 非法行），故 jsDelivr 作第一候选。
- 输出到 `data/cnip/`（默认）；路径写进 split.yaml 的 `cnip.path_v4/v6`。
- v1.0.6：curl 加 `-f`（HTTP 非 2xx 即失败）+ 下载后 `-s` 空文件检查，失败即退出，不再静默留空文件。
- 坑：依赖 `curl`（安卓 Magisk 环境通常没有）；`--max-time 120` 是硬超时，弱网会失败。cnip.c 的 `cnip_load_url` 同受此限。

## gen-magisk.sh
- 打包：二进制 + BPF + config + android/magisk 骨架 + android/scripts/*.sh → `build/split-magisk-v{VERSION}.zip`。
- **v1.0.6：二进制/BPF 缺失改为硬性报错退出**（不再打包空 bin/），报错提示先 make userspace / build_arm64.sh。
- **产物带版本号（v1.0.5）**：VERSION 从 `kernel/include/split_bpf.h` 的 `SPLIT_VERSION` 提取；
  打包前自动清理旧的 `split-magisk-v*.zip`（只保留最新）。
- **版本同源（v1.1.0 解决"两处硬编码"坑）**：打包时用 SPLIT_VERSION 改写 STAGE 内
  module.prop 的 `version`（x.y.z 原样）与 `versionCode`（**v1.2.7 起无碰撞公式
  `major*10000+minor*100+patch`**，如 1.2.9→10209、2.0.0→20000；旧式 `major*100+minor*10+patch`
  会在 1.10.0 与 2.0.0 撞值）；版本非法/缺省时跳过改写，module.prop 保留的版本号仅作手工打包兜底。
- **KernelSU/APatch（v1.0.5）**：同一 zip 兼容三种 manager（同为 Magisk 模块规范）。除规范名外另
  `cp` 一份 `build/split-ksu-v{VERSION}.zip` 便于识别。`webroot/` 目录随包 → KernelSU/APatch
  Manager 模块详情页自动识别为 WebUI。
- **zip 内结构（v1.0.3 分层整洁，v1.0.5 加 webroot）**：
  ```
  module.prop/customize.sh/post-fs-data.sh/service.sh/sepolicy.rule   ← 根（Magisk/KSU/APatch 强制）
  webroot/                                                            ← KernelSU/APatch WebUI
  config/split.yaml                                                   ← 配置
  bin/{splitd,splitctl,split.bpf.o}                                   ← 二进制+BPF
  scripts/*.sh                                                        ← 辅助脚本
  ```
- **架构选择（v1.0.2）**：优先 `build/arm64/{splitd,splitctl}`（aarch64 静态版，Android 真机用）；回退 `userspace/build/`（x86_64，仅模拟器）。`build_arm64.sh` 是交叉编译脚本（依赖 aarch64-linux-gnu-gcc + libbpf 源码 + libelf/libz/libzstd/llzma/libbz2 的 arm64 dev 包）。
- **scripts 打包（v1.0.2）**：android/scripts/*.sh（start/stop/check-kernel/setup-box-tun）会进 zip 的 scripts/，customize.sh 解包到 /data/adb/split/scripts/。
- 依赖 `zip` 命令；产物路径 `build/` 与 userspace/Makefile 的 build 目录同层。
- ~~坑：module.prop 的 version 与 split_bpf.h 的 SPLIT_VERSION 是两处硬编码，发版需同步~~（v1.1.0 由打包脚本自动改写，见上）。
- 坑（v1.0.2 修复）：`OUT` 用 `mkdir -p "$OUT"` 会把 zip 建成分目录导致失败——应为 `mkdir -p "$(dirname "$OUT")"`。
- 坑（v1.0.3）：`split.yaml` 移入 `config/` 子目录后，customize.sh 对应解包到 `/data/adb/split/config/`，service.sh/setup-box-tun.sh 用 `CONFIG_DIR` 变量，改结构必须三处同步（gen-magisk.sh / customize.sh / 脚本）。

## bump-version.sh（v1.3.0 新增，版本号唯一变更入口）
- **背景（版本号管理收敛）**：此前版本号散落 6+ 处（split_bpf.h / module.prop / roadmap /
  根文档头部 / gen-magisk.sh 公式 / webuiapi.sh 占位符），靠手工同步易漂移；且 scripts/MEMORY.md
  记录的 versionCode 公式在 v1.2.7 改无碰撞方案后已过时。**约定：唯一真源是 split_bpf.h 的
  `SPLIT_VERSION "X.Y.Z"`，发版递增一律走本脚本**，禁止手工改派生位置。
- **同步范围**：`split_bpf.h`（真源）→ `android/magisk/module.prop`（version + versionCode，
  无碰撞公式与 gen-magisk.sh 一致）→ `docs/06-ROADMAP.md`（旧"（当前）"转历史、顶部插入新版
  （当前）占位）→ 根文档头部当前版本标注（README/USAGE/BUILD/CODE/android/README，**仅前 5 行，
  不碰正文功能历史引用**如 "v1.2.9 watchdog 自愈"）。
- **用法**：`./scripts/bump-version.sh [patch|minor|major] [-y]`（默认 patch；`-y` 跳过交互确认）。
  递增后**手动**补写 roadmap 新版本的变更摘要（脚本只插入占位行）并 `git diff` 复查无历史引用误改。
- **不在此处理**：`gen-magisk.sh` 打包时读真源改写 zip 内 module.prop 与 webuiapi.sh 的
  `SPLIT_VERSION`（`@SPLIT_VERSION@` 占位符注入），无需在 bump 时同步。

## check-kernel.sh（在 android/scripts/ 下）
- 设备版 `android/scripts/check-kernel.sh`：查 bpf syscall、verifier 可用性、`/proc/config.gz`，输出 pass/fail 清单；根 `scripts/` 下无该文件（勿引用）。

## split-watchdog.sh（在 android/scripts/ 下，v1.1.7 新增 / v1.2.9 增 mihomo TUN 自愈）
- 打包：gen-magisk.sh 自动收 `android/scripts/*.sh`（本脚本无需单独加进打包清单）。
- 守护 splitd 存活（doze/LMK 杀后自动重启），详见 `android/MEMORY.md` 专节。
- **v1.2.9 增 mihomo TUN 自愈**：探活成功但 `splitctl status` 解析出 `tun=0`（mihomo TUN 消失、
  map_tun=0、代理放行直连）且 `bin/mihomo` 存在时，连续 2 轮确认后先经 mihomo API
  `PATCH /configs {"tun":{"enable":true}}` 无感恢复；API 不可达/失败则重启 mihomo
  （先 fix-mihomo-tun.sh 对齐契约）；恢复后 5 分钟冷却（`mihomo_recover_ts`）防循环。
  **注意**：`curl` 在 Android 上未必存在——API 分支失败自然落到重启分支，重启是保底。
