#!/bin/bash
# build.sh — 顶层构建入口
#
# 用法: ./scripts/build.sh [target]
#   target 缺省 all；可选 prepare / bpf / userspace / all / arm64 / android / test / install / clean
#   其余参数透传 make；-h/--help 列目标。
set -e
cd "$(dirname "$0")/.."

TARGETS="help prepare bpf userspace all arm64 android test install clean"

case "$1" in
  -h|--help|help)
    echo "用法: ./scripts/build.sh [target]"
    echo "可选 target: $TARGETS（缺省 all，透传 make）"
    exit 0
    ;;
esac

TARGET=${1:-all}
case " $TARGETS " in
  *" $TARGET "*) ;;
  *) echo "未知目标: $TARGET（可选: $TARGETS）" >&2; exit 1 ;;
esac

make "$TARGET"
echo "== 构建完成（$TARGET）=="
ls -la kernel/bpf/split.bpf.o userspace/build/ build/arm64/ 2>/dev/null || true
