#!/bin/bash
# build_arm64.sh — 交叉编译 splitd/splitctl 为 aarch64（glibc 全静态链接）
#
# 用途：给 Android 真机（arm64）生成 Magisk 模块用的二进制。
# 前提（在 Linux x86_64 / WSL2 上）：
#   apt install gcc-aarch64-linux-gnu libelf-dev:arm64 zlib1g-dev:arm64 \
#             libzstd-dev:arm64 liblzma-dev:arm64 libbz2-dev:arm64
#   libbpf 源码交叉编译（产物放 /root/bpf_deps/libbpf/src/libbpf.a，持久目录勿放 /tmp）：
#     git clone https://github.com/libbpf/libbpf /root/bpf_deps/libbpf
#     cd /root/bpf_deps/libbpf/src && make BUILD_STATIC_ONLY=1 \
#         CC=aarch64-linux-gnu-gcc AR=aarch64-linux-gnu-ar
#
# 用法: ./scripts/build_arm64.sh  [libbpf_src_dir]  [out_dir]
# 默认: libbpf=/root/bpf_deps/libbpf, out=build/arm64
# 说明: 编译规则统一走 userspace/Makefile（OUTDIR/CC/CFLAGS/LDFLAGS 覆盖），
#       源文件与链接库清单只在 Makefile 一份，避免双份维护。
set -e

LIBBPF=${1:-/root/bpf_deps/libbpf}
SRC=$(cd "$(dirname "$0")/.." && pwd)      # 项目根
OUT=${2:-$SRC/build/arm64}
SYSINC=/usr/include/aarch64-linux-gnu

# 工具链检查（提示先行安装，避免链接时报错难定位）
command -v aarch64-linux-gnu-gcc >/dev/null 2>&1 || {
  echo "错误: 缺少 aarch64-linux-gnu-gcc" >&2
  echo "  sudo apt install gcc-aarch64-linux-gnu（顶层 make prepare 含此项）" >&2
  exit 1
}
command -v aarch64-linux-gnu-ar >/dev/null 2>&1 || {
  echo "错误: 缺少 aarch64-linux-gnu-ar（apt install binutils-aarch64-linux-gnu）" >&2
  exit 1
}

[ -f "$LIBBPF/src/libbpf.a" ] || {
  echo "错误: 未找到 $LIBBPF/src/libbpf.a" >&2
  echo "先按 BUILD.md §2.2 交叉编译 libbpf（放持久目录，勿放 /tmp）" >&2
  exit 1
}

# 链接库清单取自 userspace/Makefile（唯一真源），交叉仅追加 -static 与库路径
LIBS=$(make -C "$SRC/userspace" -s print-libs)

echo "== 交叉编译 aarch64（libbpf=$LIBBPF, out=$OUT）=="
make -C "$SRC/userspace" \
    OUTDIR="$OUT" \
    CC=aarch64-linux-gnu-gcc \
    CFLAGS="-O2 -g -Wall -Wextra -I$LIBBPF/include -I/usr/include -I$SYSINC" \
    LDFLAGS="-static -L$LIBBPF/src -L/usr/lib/aarch64-linux-gnu $LIBS"

echo "== result =="
if command -v file >/dev/null 2>&1; then
  file "$OUT/splitd" "$OUT/splitctl"
fi
ls -la "$OUT/"
