# 03-ANDROID（安卓兼容性方案 · 重点章节）

> 目标：让这套 eBPF 分流在**安卓（Android GKI 内核 5.10/5.15/6.1，绝大多数量产
> 手机）**上可落地；并在不满足条件时**优雅降级**而不是断网。

## 0. 结论先行（TL;DR）

| 条件 | 结果 |
|---|---|
| 有 root（Magisk/KernelSU）+ 内核支持 BPF | ✅ 完整内核分流 |
| 有 root，但内核编译未开 tc-egress 相关配置 | 🟡 降级为 mihomo 自带 TUN 路由（纯用户态分流，eBPF 失效但有网） |
| 无 root / 系统很怪 | ❌ 无法加载 eBPF，请用 Clash/Mihomo 等 TUN 模式的普通 APK |

## 2. 内核要求与检测

Android 内核（GKI）至少需要的 config：

```
CONFIG_BPF=y                # 必
CONFIG_BPF_SYSCALL=y        # 必（bpf() 系统调用）
CONFIG_BPF_JIT=y            # 必须，Android arm64 默认开
CONFIG_NET_CLS_BPF=y        # 必：tc bpf 支持
CONFIG_NET_CLS_ACT=y        # clsact 支持
CONFIG_NET_SCH_INGRESS=y    # ingress 层（我们偷懒也用 egress）
CONFIG_BPF_UNPRIV_DEFAULT_OFF??  -> 我们只用 root，不关心 unpriv
CONFIG_TUN  或 (内核 <5.4 无此时，用 veth 模拟可替代)  # mihomo 需要 tun 设备
CONFIG_BTF  (CONFIG_DEBUG_INFO_BTF)   # 便于 CO-RE 减小 BTF 依赖，GKI 默认开
```

执行一键检测：

```bash
adb root; adb shell sh /sdcard/Android/data/.../split/scripts/check-kernel.sh
```

> 真机注意：`/proc/config.gz` 有时不存在。check-kernel 的探测组合是 **/sys/fs/bpf 挂载 +
> /proc/config.gz 内核配置 + /dev/net/tun 存在性**（不发起 `bpf()` 系统调用，无权限/seccomp
> 拦截时也能静默出结果）；判定不准时再结合 dmesg。

## 2. SELinux：为什么 root 了还是 `bpf_prog_load EPERM`

安卓 firewalls 的规定：加载 eBPF 需要 `bpf_prog_load` 的 SELinux 权限，**默认只有
`magisk` 主后可加载，或 **某些厂商放的最细粒度**可能让 magisk 也没有**。这跟"root"
是完全两个概念。

解决路径（按侵入度从低到高）：

1. **临时 permissive（不推荐但立竿见影）**
   ```sh
   magiskpolicy --live "permissive magisk"
   ```
2. **精确 open/allow（推荐，我们的 magisk 模块自带）**：
   ```sh
   # 在 service.sh 中执行（即 service.sh:35-40 的实际规则，等价于 module 的 sepolicy.rule）
   magiskpolicy --live \
     'allow magisk bpf:bpf { prog_load prog_pin map_create map_read map_write prog_test_run }' \
     'allow magisk self:unix_stream_socket create_stream_socket' \
     'allow magisk tun_device:chr_file rw_file_perms' \
     'allow magisk net_device:netlink_socket create'
   ```
   （不同内核的 Security 类名可能略有差异，用 `dmesg | grep avc` 对照调整。）
3. **打包成 Magisk 模块的 `sepolicy.rule`**：`android/magisk/sepolicy.rule` 见其头部注释。
4. 还有一种非常通用：直接在整个 Android 上 `echo permissive > /sys/fs/selinux/enforce`
   或锁手机进 `magisk --disable` 调 `magiskpolicy --live "permissive *"`，一般没必要。

> 经验：**Audit 日志是唯一权威**。失败时 `adb logcat`/`dmesg` 查 `avc: denied ... scontext=u:r:magisk:s0 ... bpf`。

## 3. UID 语义（安卓特有）

- 每个 app 一个 linux uid（10000+），root=0，shell=2000，mihomo 若是普通apk 运行=该app uid。
- 我们的 eBPF 用 `bpf_get_socket_uid(skb)` 读此时发送套接字的 uid（tc 侧自 v4.x 可用）。
- **必须把 mihomo（及其子进程）的 uid 加入 map_skip_uid**，否则：
  ```
  mihomo --(连接代理服务器)--> wlan0 egress --> 判定"海外" → redirect 回 tun → 循环
  ```
  默认配置里已给 `2000(shell)`、`0(root/内核中的代理进程)` 和示例 uid。多用户/资料多开时
  名单给定集合，保证主用 dprev（第一用户）即可。

## 4. DNS 与 fake-ip：内核级流 <->真实 IP 冲突（你在设计时必须反自问的点）

**分类器只能看到目标 IP**。所以：

- `enhanced-mode: redir-host`（推荐）：DNS 返回真实 IP，应用连接真实 IP，分类器正确(bucus) → CNIP 直连、海外进代理。
- `enhanced-mode: fake-ip`：应用连的是 `198.18.x.x`（fake-ip 池），分类器看到 198.18 无法知道真实 -- 此时：
  - 把 fake-ip 段加进 `rules.proxy_cidr4`（默认我们配好 `198.18.0.0/15`），那么海外域名 → mihomo（对），
  - 但 CN 域名也会 → mihomo（因为也是 fake IP）→ 内核分流 "失效"，由 mihomo 自己的规则继续分流。
  - fake-ip 还有外部网卡的问题（`fake-ip-filter` 域名除外）→ 无法直连。

结论三点：
1. **想要真正发挥"内核级 CNIP 分流" → 用 redir-host。**
2. fake-ip 是体验至尊，但回到纯用户态分流（eBPF 只做兜底/不管）——两者不可兼得。
3. configs/mihomo/ 下给了两套配置各取所需；README 里描述了怎么一键切换。

> IPv6：fake-ip 同样存在 v6 池（`fake-ip-range6`）。rule 里建议带上默认 v6 fake 池；
> mihomo `ipv6: false` 时建议直接不启用 v6 流代理，直连 CN 域名由 CNIP6 直连。

## 5. 网络接口动态变化（WIFI↔蜂窝）

```
wlan0 (WiFi) / rmnet_data0(Verizon模版) / eth0(有线) / lo(除) ...
```
- iface.c 订阅 netlink，新增/UP 的接口即时 attach；消失时 detach。
- 挂载策略：**排除了** `lo、tun*、tap*、dummy`；其余带稳定判据生成表。
- 多网卡并存时（vpn 不上不炸），**只在"当前有默认路由主出口"的主网卡**挂载即可，
  避免双出口（本方案以简单优先：所有物理网卡都挂，策略只走 dst IP 不分源，效果等价）。

## 6. root 启动路径（Magisk 模块）

```
boot → post-fs-data(挂 bpffs) → late_start service.sh
 └─ 1) 能力探测：splitd 二进制是否在位  缺失 → 跳过 eBPF（check-kernel.sh 是独立手检工具，service.sh 不调用）
    2) magiskpolicy 打开 bpf/tc（见 §2）
    3) sysfs 挂载 /sys/fs/bpf 或 magisk_bpf
    4) 启动 mihomo(自带或已有app) → 确保 tun0 已起
    5) splitd -c $CFG -d      # daemon 加载 bpf、attach、灌 CNIP
    6) 检查 `splitctl status` → OK
    7) (v1.1.7) 拉起 `scripts/split-watchdog.sh` 守护 splitd（doze/LMK 杀掉后自动重启）
    8) (v1.2.9) watchdog 另守 mihomo TUN：探活到 map_tun=0（mihomo TUN 消失）时经 mihomo
       API 无感恢复，API 失败则重启 mihomo——"splitd 活着但代理静默放行"也能自愈
```

`android/magisk/` 里已放好 `module.prop、customize.sh、service.sh、post-fs-data.sh、
sepolicy.rule` 骨架；`scripts/gen-magisk.sh` 打包 zip。

> **目录职责（零重复）**：`/data/adb/modules/ebpf-split/`（module.prop `id=ebpf-split`）只是**安装源 + Magisk 必需文件**；
> customize.sh 会把 bin/config/scripts/mihomo 铺到 `/data/adb/split/`（**唯一运行真源**）后
> `rm -rf` 清掉模块预留副本。所有运行时脚本一律读 `/data/adb/split`，禁止从模块目录取执行内容。

## 7. 降级链（可逆，自动）

| 环节 | 降级动作 | 用户感知 |
|---|---|---|
| BPF 加载失败 | 跳过 eBPF、仅起 mihomo（auto-route 保持 false，不自动接管路由） | 仍可上网，但流量不进 mihomo TUN（需 TUN 代理请自行给 mihomo 配 auto-route） |
| mihomo 未开 tun | splitd 启动失败并报错给你 | 无网（故意的，提示先起 mihomo） |
| 单一接口 attach 失败 | 跳过该接口，写日志 | 个别网卡不走分流 |

## 8. 性能与功耗建议

- **不要 hook 在 ingress**（我们只挂 egress）——安卓本来就重收队。
- CNIP 直连 ≈ 0 附加延迟；海外进 mihomo 延迟=代理延迟。
- 用 `per-cpu` 计数器避免并发写竞争。
- 看《安卓机上 CPU 升温 vs 纯 userspace》建议：CNIP 段内每次查询是 LPM_TRIE（几ns），
  **几乎无感知**。真正成本远不如轮询 DNS 的 app 多。

## 8.5 真机验证要点（v1.0.2，小米 5.10 GKI + KernelSU 实测）

> 在真机（diting 22081212C, 5.10.256-gki, Android 16, KernelSU root）上验证通过的经验，
> 这些是**宿主(WSL2)能跑、真机不能**的典型差异。

1. **BPF 必须 `-mcpu=v1`**：新 clang 默认编出 `BPF_ATOMIC`（`atomic_fetch_add`），
   小米 5.10/5.15 GKI 的 verifier 只认老 `BPF_XADD`，报 `BPF_STX uses reserved fields` 拒载。
   `kernel/Makefile` 已加 `-mcpu=v1`。**改回高版本 cpu 前先确认目标内核支持。**
2. **Android 没有 `/run` 目录**：splitd 的 ctl unix socket 默认 `/run/splitd.sock` 无法 bind
   （根目录只读）。用 `export SPLIT_SOCKET=$INSTALL_DIR/run/splitd.sock` 覆盖（`/data/adb/split/run/`），
   splitd/splitctl 都读该环境变量（`userspace/common/paths.c`）。module 的 service.sh 已自动设置。
3. **真机验证命令**（root）：
   ```sh
   ip tuntap add dev tun0 mode tun && ip link set tun0 up
   export SPLIT_SOCKET=/data/adb/split/run/splitd.sock
   splitd -d -c split.yaml -b split.bpf.o &
   splitctl status   # → OK prog_fd=.. attached=N tun=16 cnip4=4145 cnip6=1235 cnip=on hijack=0
   splitctl stats    # 看 direct_cn/proxy 计数
   ```
   > **v1.1.3 起 status 带健康字段**：`cnip4/cnip6` 为 0 = CNIP 未导入（文件缺失，配了 url 会自动补拉，失败每 5 分钟重试直到成功——仅成功后才停止补拉）；关闭 CNIP 策略时可执行 `splitctl cnip off` 临时绕过 CNIP 命中直连，map 仍继续刷新，重启 splitd 后恢复 `cnip=on`。
   > `hijack=1` = 路由被 mihomo auto-route 接管，eBPF 分流已失效（见 8.6 的坑）；后续可能有 `WARN` 行。
4. 端到端分流实测：内网/CNIP → 直连（`direct_cn`），海外 → redirect 进 tun（`proxy` 计数 + ping loss），
   `add-rule <cidr> direct` 可即时让海外变直连，`del-rule` 可撤销。
5. **验证"流量是否真进 mihomo"的方法（避免假阳性）**：
   - **不要用 root/shell 测试**：`skip_uid` 默认含 `[0,2000]`，adb shell 的 curl/ping 是 uid 0/2000，全被白名单跳过 → 看到的直连不代表分流正确。
   - 正确做法：临时 `skip_uid: []`（测试专用，并给 mihomo 的 DNS/代理服务器 IP 加 direct 规则防回环），再看：
     - `curl 127.0.0.1:9090/connections`（mihomo 实际连接）
     - `ss -tnp | grep mihomo`（SYN-SENT 到代理节点 = 正在代理）
     - `utun rx_packets` 计数增长
   - 实测：curl google → `utun rx` 显著增长 + mihomo `SYN-SENT` 一堆代理节点 IP → 分流确凿。

## 8.5.5 蜂窝网卡 RAWIP 无以太网头（v1.1.5 修复，真机实测）

> **症状**：WiFi 下分流一切正常，切到蜂窝后"上不了网"（实际是海外流量全部
> 无法进代理，直连段正常）。`splitctl stats` 里 `parse_err` 暴涨（实测 63% 的包
> 解析失败），`proxy` 计数几乎不涨。

**根因**：Android 蜂窝网卡 `rmnet_data*`/`rmnet_ipa0` 是 `ARPHRD_RAWIP`(type 519)——
**tc egress 的 skb 没有以太网头，`skb->data` 直接就是 IP 头**（`dev->hard_header_len=0`）。
eBPF 解析器若硬按以太网头读 `h_proto`，会把 IP 头前 2 字节（version/ihl，如 `0x4500`）
当 ethertype → 全部判"不可解析"→ 放行直连 → 海外流量被墙。WiFi（type 1 Ethernet）
有以太网头所以正常——这就是"WiFi 好、蜂窝挂"的经典差异。

**修复（v1.1.5）**：
1. 新增 `map_rawip`：用户态 `map_rawip_sync` 在挂载/卸载/网络事件时，把
   **type==519 且 IFF_UP** 的接口写入该 map（key=ifindex）。
2. parse.h 对命中接口走"无 L2 头"路径：`data[0]>>4` 判 IPv4(4)/IPv6(6)，直接解析 IP 头。
3. `rmnet_ipa0`（IPA 聚合口）排除出挂载列表——它虽是 519 但帧带 RMNET MAP 封装头
   （非裸 IP，实测 tcpdump filter 都无法匹配），数据面实际走 `rmnet_data*` 子接口。

**验证**：`splitctl status` 的 `attached` 应含全部 rmnet_data* 且不含 rmnet_ipa0；
蜂窝下 `parse_err` 归零、`proxy` 增长、utun RX 涨、mihomo connections 出现 `type=Tun`
的应用连接（如 gms → android.googleapis.com）。

**排查命令**：
```sh
cat /sys/class/net/rmnet_data0/type   # 519 = ARPHRD_RAWIP（无以太网头）
tcpdump -i rmnet_data2 -X -n          # 首字节 0x45/0x60 = 裸 IP 头
```

## 8.6 接入已有 box 代理模块（端到端 TUN，一键脚本）

> 设备上若已装 box（`/data/adb/box`，常见的 Magisk/KernelSU 代理模块），可复用其 mihomo
> 二进制 + 订阅节点，直接接入 eBPF-Split。真机验证可复现。

```sh
# 一键：复制 box mihomo → 改 TUN → 复用 CNIP → 起 mihomo + splitd
sh /data/adb/split/scripts/setup-box-tun.sh   # 或仓库里 android/scripts/setup-box-tun.sh
```

脚本做的事：
1. **不改 box 原件**：`cp -a /data/adb/box/mihomo /data/adb/split/mihomo`
2. **改 tun 段**（`fix-mihomo-tun.sh` 幂等执行，单一真源）：
   `enable:true, device:utun, auto-route:false, strict-route:false, stack:gvisor, gso:false, mtu:1500, auto-detect-interface:false`
   - `auto-route:false` 是**必须**的：让 mihomo 只建 tun 设备、不接管路由，路由与分流全交给 eBPF。
3. **复用 CNIP**：`cp /data/adb/box/run/cn.zone → cn_cidr_v4.txt`（格式兼容，每行 CIDR）
4. 起 mihomo → 等 utun → 起 splitd → 验证

实测结果（小米 diting）：
```
CN 直连 ping 223.5.5.5 → 39ms（内核直连，不经过 mihomo）
海外 ping 8.8.8.8      → 219ms（走 mihomo TUN 隧道）
splitctl stats: direct_cn 增长 / proxy 增长 / redirect_err 0 / dropped 0
```

注意：节点 alive 但访问超时 → 是 mihomo 节点自身连通性问题（订阅/出口），不是框架问题。

## 9. 交叉编译（在 x86 上构建 arm64 二进制）

> **主推方案：glibc 全静态交叉编译**（`scripts/build_arm64.sh`，BUILD.md §3.3），
> 产物静态链接 aarch64，不依赖安卓自带 libc/exe。NDK（方案 B）仅在需要 bionic 链接时用。

### 9.1 准备交叉工具链（方案 A：glibc 静态，推荐）

```bash
sudo apt install gcc-aarch64-linux-gnu libelf-dev:arm64 zlib1g-dev:arm64 \
                 libzstd-dev:arm64 liblzma-dev:arm64 libbz2-dev:arm64
# libbpf 交叉编译到 /root/bpf_deps/libbpf（持久目录，勿放 /tmp）：
git clone https://github.com/libbpf/libbpf /root/bpf_deps/libbpf
cd /root/bpf_deps/libbpf/src
make BUILD_STATIC_ONLY=1 CC=aarch64-linux-gnu-gcc AR=aarch64-linux-gnu-ar
# 然后一键交叉编译：
./scripts/build_arm64.sh /root/bpf_deps/libbpf     # 产物 build/arm64/{splitd,splitctl}（静态）
file build/arm64/splitd   # 应为: ARM aarch64, statically linked
```

### 9.2 交叉编译（方案 B：NDK）

```bash
NDK=~/android-ndk-r26c
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
make -C userspace \
  CC="$TOOLCHAIN/bin/aarch64-linux-android34-clang" \
  LDFLAGS="-L/path/to/libbpf/src -lbpf -lelf -lz -lzstd -llzma -lbz2 -static"
# 产物: userspace/build/splitd  userspace/build/splitctl
# （库清单与 build_arm64.sh 一致，均源自 userspace/Makefile 的 LIBS）
```

> NDK 编译前需先为 aarch64 编出 libbpf.a（`CC=$TOOLCHAIN/...-clang make -C libbpf/src`）。

### 9.3 BPF 对象（与架构无关）

```bash
# kernel/bpf/split.bpf.o 用 clang -target bpf 编（与宿主 arch 无关），架构无关：
make -C kernel bpf
```

### 9.4 一体制品打包

```bash
./scripts/gen-magisk.sh     # 或 make android；用 build/arm64 优先，缺则回退 userspace/build
```

产物 `build/split-magisk-v{VERSION}.zip` 可直刷 Magisk。

### 9.5 注意

- **libbpf 静态链接**：Android 系统不带 libbpf.so，splitd/splitctl 必须静态链 libbpf + libelf + libz。
- **不需要 BTF/CO-RE**：本项目 `-mcpu=v1` + `-target bpf` 对 GKI 内核确定可载，无需 CO-RE（GKI 默认开 BTF，需要时才另配 bpftool）。
- Termux 用户可省去交叉编译：直接在 Termux 里 apt install clang libbpf 并 `make userspace`（原生编译，限 Android 本身具备这些包）。

## 10. 常见坑自查清单（Q&A）

Q1. 加载后 google 都玩不开手，curl 直连反而好 → 检查 skip_uid 是否忘了把 mihomo uid 加进去（§3）。
Q2. 手机切换 wifi 后就 Lose 分流 → 现在已是 netlink 事件订阅 + 15s reconcile 自动重挂（iface.c，
  见 §5），一般无需手动；仍异常时 `splitctl status` 看 attached、必要时 `reload` 强制对齐。
Q3. fake-ip 模式下 CN 流量也走 mihomo：→ 这是预期，见 §4。
Q4. `avc: denied { prog_load }` → SELinux §2 对照 dmesg 修。
Q5. 设备是 4.19 老内核 → tc cls 可用性需确认，先 `check-kernel.sh`；不行的情况下降级。
Q6. 我用的不是 mihomo，是 shadow/v2ray 自建 tun？→ 只要代理内核能读 tun0，接口从配置更换即可
   （`proxy device` 名字配置化）。

---
再往后：`docs/04-CONFIG.md`；装机走 `android/README.md`。