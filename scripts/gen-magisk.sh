#!/bin/bash
# gen-magisk.sh — 打包 android/magisk 为可安装 zip（Magisk / KernelSU / APatch 通用）
#
# 用法: ./scripts/gen-magisk.sh            # 用 build/arm64 或 userspace/build 里的二进制
# 架构选择：
#   优先 build/arm64/{splitd,splitctl}（Android 真机 aarch64 静态版，推荐）
#   回退 userspace/build/{splitd,splitctl}（x86_64，仅模拟器）
#
# 产物：
#   build/split-magisk-v<版本>.zip    规范名（Magisk 使用，文档统一引用）
#   build/split-ksu-v<版本>.zip       别名（内容相同，KernelSU/APatch 用户便于识别）
# 版本号取自 kernel/include/split_bpf.h 的 SPLIT_VERSION，并自动改写 zip 内
# module.prop 的 version/versionCode（唯一真源在 split_bpf.h）。
# 旧版本 zip 会被清理（保留最新一个）。
#
# zip 内结构（Magisk 规范 + KernelSU/APatch 兼容）：
#   module.prop / customize.sh / post-fs-data.sh / service.sh / sepolicy.rule   ← 根（manager 强制）
#   webroot/                         ← KernelSU/APatch WebUI（自动识别）
#   config/split.yaml                                                            ← 配置
#   bin/{splitd,splitctl,split.bpf.o}                                            ← 二进制+BPF
#   scripts/*.sh                                                                 ← 辅助脚本
set -e
cd "$(dirname "$0")/.."

command -v zip >/dev/null 2>&1 || { echo "缺少 zip 命令（apt install zip）"; exit 1; }

ROOT=$(pwd)

# 版本号：从 split_bpf.h 提取 SPLIT_VERSION（如 "1.0.5" → v1.0.5）
VERSION=$(grep -oP 'SPLIT_VERSION\s+"[^"]+"' "$ROOT/kernel/include/split_bpf.h" \
          | grep -oP '"[^"]+"' | tr -d '"')
[ -n "$VERSION" ] || VERSION="dev"
echo "版本: v$VERSION"

OUT="$ROOT/build/split-magisk-v$VERSION.zip"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# Magisk 强制根级文件
cp -r android/magisk/module.prop      "$STAGE/"
cp -r android/magisk/customize.sh     "$STAGE/"
cp -r android/magisk/post-fs-data.sh  "$STAGE/"
cp -r android/magisk/service.sh       "$STAGE/"
cp -r android/magisk/sepolicy.rule    "$STAGE/"

# 版本与 split_bpf.h 同源（v1.1.0）：改写 STAGE 里的 module.prop，消除"两处硬编码"
# 发版漏同步的坑；module.prop 里保留的版本号仅作手工打包兜底。
if [ -n "$VERSION" ] && [ "$VERSION" != "dev" ]; then
  # v1.2.7（审查 L2）：旧式 `major*100+minor*10+patch` 会碰撞（1.10.0 与 2.0.0 都=200）。
  # 改 `major*10000+minor*100+patch`：1.2.6→10206、1.10.0→11000、2.0.0→20000，无碰撞。
  CODE=$(printf '%s' "$VERSION" | awk -F. 'NF==3 && $1>0 {printf "%d", $1*10000+$2*100+$3}')
  if [ -n "$CODE" ]; then
    sed -i -E "s/^version=.*/version=$VERSION/; s/^versionCode=.*/versionCode=$CODE/" "$STAGE/module.prop"
    echo "module.prop 版本已同步: $VERSION (versionCode=$CODE)"
  fi
fi

# KernelSU WebUI（留在模块根，由 KernelSU Manager 从 webroot/ 提供）
if [ -d android/magisk/webroot ]; then
  cp -r android/magisk/webroot        "$STAGE/webroot"
  echo "已包含 KernelSU WebUI（webroot/）"
fi

# 配置
mkdir -p "$STAGE/config"
[ -f "$ROOT/configs/split.yaml.example" ] && cp "$ROOT/configs/split.yaml.example" "$STAGE/config/split.yaml"

# 二进制：优先 arm64 静态版
BIN_DIR="$ROOT/build/arm64"
if [ ! -x "$BIN_DIR/splitd" ] || [ ! -x "$BIN_DIR/splitctl" ]; then
  BIN_DIR="$ROOT/userspace/build"
fi
if [ ! -x "$BIN_DIR/splitd" ] || [ ! -x "$BIN_DIR/splitctl" ]; then
  echo "错误: 未找到可用的 splitd/splitctl" >&2
  echo "  先 make bpf && make userspace（模拟器 x86_64）" >&2
  echo "  或 ./scripts/build_arm64.sh（Android 真机 aarch64）" >&2
  exit 1
fi
if [ ! -f "$ROOT/kernel/bpf/split.bpf.o" ]; then
  echo "错误: 未找到 kernel/bpf/split.bpf.o，先 make bpf" >&2
  exit 1
fi
echo "使用二进制来源: $BIN_DIR"
mkdir -p "$STAGE/bin"
for f in splitd splitctl; do
  [ -f "$BIN_DIR/$f" ] && cp "$BIN_DIR/$f" "$STAGE/bin/"
done
# BPF 对象（架构无关）
cp "$ROOT/kernel/bpf/split.bpf.o" "$STAGE/bin/"
# mihomo（可选随包）：把 mihomo 放 build/arm64/mihomo 就会打进 bin/mihomo
# 安装时 customize.sh 解包到运行目录 /data/adb/split/bin/mihomo（不放 modules，避免权限/overlay 问题）
[ -f "$BIN_DIR/mihomo" ] && cp "$BIN_DIR/mihomo" "$STAGE/bin/"
# mihomo 配置（脱敏模板）：configs/mihomo/mihomo-package.yaml → mihomo/config.yaml
# 注意：订阅 token/密码已脱敏为 YOUR_* 占位符，用户安装后需填入自己的订阅
if [ -f "$ROOT/configs/mihomo/mihomo-package.yaml" ] && [ -f "$BIN_DIR/mihomo" ]; then
  mkdir -p "$STAGE/mihomo"
  cp "$ROOT/configs/mihomo/mihomo-package.yaml" "$STAGE/mihomo/config.yaml"
  echo "已包含脱敏 mihomo 配置（安装后填 token 即可用）"
fi

# 辅助脚本（安装后到 /data/adb/split/scripts/）
mkdir -p "$STAGE/scripts"
for s in android/scripts/*.sh; do
  [ -f "$s" ] && cp "$s" "$STAGE/scripts/"
done
# 版本注入 webuiapi.sh（唯一真源 split_bpf.h）。
# 注意：只能替换"赋值行"，不能全局替换——webuiapi.sh 内的回退比较行
# `[ "$SPLIT_VERSION" = "@SPLIT_VERSION@" ]` 也含占位符，全局替换会让它恒真、
# 版本恒回退 dev。锚定到行首/行尾只改赋值。
sed -i "s|^SPLIT_VERSION=\"@SPLIT_VERSION@\"\$|SPLIT_VERSION=\"$VERSION\"|" \
  "$STAGE/scripts/webuiapi.sh" 2>/dev/null || true

# 清理旧版本 zip（保留当前要生成的，含 ksu 别名）——必须在全部校验通过后
# （审查 2026-08）：原先在脚本开头删，二进制/BPF 缺失导致 set -e 退出时
# 会把上一版好包也删掉；移到打包前，失败留上一版可回退。
rm -f "$ROOT"/build/split-magisk-v*.zip "$ROOT"/build/split-ksu-v*.zip
mkdir -p "$(dirname "$OUT")" && rm -f "$OUT"
(cd "$STAGE" && zip -rq "$OUT" .)

echo "已生成: $OUT"
echo "KernelSU/APatch 别名: $ROOT/build/split-ksu-v$VERSION.zip"
cp -f "$OUT" "$ROOT/build/split-ksu-v$VERSION.zip"
echo "推送安装: adb push $OUT /sdcard/  → Magisk/KernelSU/APatch 模块里安装"