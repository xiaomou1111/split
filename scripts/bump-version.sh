#!/bin/bash
# bump-version.sh — 统一版本号递增（v1.3.0）
#
# 版本号管理约定（本脚本即唯一变更入口）：
#   - 唯一真源：kernel/include/split_bpf.h 的 `SPLIT_VERSION "X.Y.Z"`。
#   - 所有派生位置由本脚本同步（禁止手工改，避免多源漂移）：
#       ① split_bpf.h                    真源
#       ② android/magisk/module.prop     version + versionCode（无碰撞公式 major*10000+minor*100+patch）
#       ③ docs/06-ROADMAP.md             "vX.Y.Z（当前）"标注：旧版本去掉（当前）转历史、顶部插入新版本（当前）占位
#       ④ 根文档头部"当前版本"标注       README/USAGE/BUILD/CODE/android/README（仅前 5 行，不碰功能历史引用）
#   - gen-magisk.sh 打包时读真源改写 zip 内 module.prop 与 webuiapi.sh 的 SPLIT_VERSION（无需在此处理）。
#
# 用法: ./scripts/bump-version.sh [patch|minor|major] [-y]
#   patch   0.0.1 递增（默认）：1.2.9 → 1.2.10
#   minor   x.y 递增，patch 归零：1.2.9 → 1.3.0
#   major   x 递增，y/z 归零：1.2.9 → 2.0.0
#   -y      跳过交互确认（CI/脚本调用）
set -e
cd "$(dirname "$0")/.."

BPF_H="kernel/include/split_bpf.h"
PROP="android/magisk/module.prop"
ROAD="docs/06-ROADMAP.md"

# ---------- 1. 读当前版本（与 gen-magisk.sh 同款提取） ----------
CUR=$(grep -oP 'SPLIT_VERSION\s+"[^"]+"' "$BPF_H" | grep -oP '"[^"]+"' | tr -d '"')
if [ -z "$CUR" ]; then
  echo "错误: 读不到 $BPF_H 的 SPLIT_VERSION" >&2
  exit 1
fi

# ---------- 2. 解析并递增 ----------
IFS='.' read -r MAJ MIN PAT <<<"$CUR"
if ! [[ "$MAJ" =~ ^[0-9]+$ ]] || ! [[ "$MIN" =~ ^[0-9]+$ ]] || ! [[ "$PAT" =~ ^[0-9]+$ ]]; then
  echo "错误: 非法版本号 $CUR（需 X.Y.Z）" >&2
  exit 1
fi

MODE=${1:-patch}
case "$MODE" in
  patch) PAT=$((PAT + 1)) ;;
  minor) MIN=$((MIN + 1)); PAT=0 ;;
  major) MAJ=$((MAJ + 1)); MIN=0; PAT=0 ;;
  *) echo "用法: $0 [patch|minor|major] [-y]" >&2; exit 1 ;;
esac
NEW="$MAJ.$MIN.$PAT"
CODE=$(printf '%d' $((MAJ * 10000 + MIN * 100 + PAT)))

echo "版本递增: $CUR → $NEW（versionCode=$CODE）"
if [[ " $* " != *" -y "* ]]; then
  read -r -p "确认执行? [y/N] " ans
  [[ "$ans" =~ ^[yY] ]] || { echo "已取消"; exit 0; }
fi

# ---------- 3. 同步全部位置 ----------
# ① 真源
sed -i "s|^#define SPLIT_VERSION \".*\"|#define SPLIT_VERSION \"$NEW\"|" "$BPF_H"
echo "  ✓ $BPF_H  → $NEW"

# ② module.prop
sed -i "s|^version=.*|version=$NEW|" "$PROP"
sed -i "s|^versionCode=.*|versionCode=$CODE|" "$PROP"
echo "  ✓ $PROP  → version=$NEW versionCode=$CODE"

# ③ roadmap：旧当前版本去掉"（当前）"转历史；顶部插入新版本（当前）占位
sed -i "s|^v$CUR（当前）|v$CUR|" "$ROAD"
sed -i "0,/^v$CUR /s|^v$CUR |v$NEW（当前）        （由 bump-version.sh 生成，请手动补写本版变更摘要）\nv$CUR |" "$ROAD"
echo "  ✓ $ROAD  → 旧版 v$CUR 转历史，新增 v$NEW（当前）占位"

# ④ 根文档头部"当前版本"标注（仅前 5 行；不碰文档正文的功能历史引用如 "v1.2.9 watchdog 自愈"）
sed -i "1,5s|^> v[0-9][0-9.]* ｜|> v$NEW ｜|" README.md
sed -i "1,5s|^> 版本 v[0-9][0-9.]* ｜|> 版本 v$NEW ｜|" USAGE.md
sed -i "1,5s|^> eBPF-Split v[0-9][0-9.]* ｜|> eBPF-Split v$NEW ｜|" BUILD.md CODE.md
sed -i "1,5s|eBPF-Split（v[0-9][0-9.]*）的安卓落地包|eBPF-Split（v$NEW）的安卓落地包|" android/README.md
echo "  ✓ 根文档头部版本标注（README/USAGE/BUILD/CODE/android/README）"

echo
echo "完成: $CUR → $NEW"
echo "下一步（手动）:"
echo "  1. 编辑 docs/06-ROADMAP.md 补写 v$NEW（当前）的变更摘要（替换占位行）"
echo "  2. 确认无功能历史引用（v$NEW 之前的版本号）被误改：git diff -- docs/ README.md USAGE.md BUILD.md CODE.md android/README.md"
echo "  3. 构建 + 提交：make bpf && make userspace && ./scripts/gen-magisk.sh"
