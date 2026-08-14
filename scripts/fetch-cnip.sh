#!/bin/bash
# fetch-cnip.sh — 更新 CNIP 数据（IPv4 + IPv6）
#
# 默认源（v1.4.3 起为 mihomo 生态权威源 Loyalsoldier/geoip，每日更新）：
#   https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/cn.txt
#   https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt
# cn.txt 是 v4+v6 混合的纯 CIDR 文件（实测 v4=4145 / v6=1235 条，无注释行），
# 下载后按族 grep 拆分为 cn_cidr_v4.txt / cn_cidr_v6.txt。
# 候选按序尝试，任一成功即用：jsDelivr（大陆可达）优先，raw.githubusercontent 兜底。
# cdn.jsdelivr.net 不可达时可换 https://fastly.jsdelivr.net/gh/... 前缀。
# 用法: ./scripts/fetch-cnip.sh [outdir]
set -e
cd "$(dirname "$0")/.."
OUT=${1:-data/cnip}

mkdir -p "$OUT"

# 多源候选（与 config.c 的默认 url_v4/v6 逗号串一致；v1.4.3 起 v4/v6 同源 cn.txt）
CN_URLS=(
  "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/cn.txt"
  "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt"
)

# 按序尝试候选 URL，任一成功（非空）即返回 0
dl_candidates() {   # $1=输出文件，其余=候选 URL
    local out="$1"; shift
    local u
    for u in "$@"; do
        echo "  尝试: $u"
        if curl -f -L --max-time 120 -s -o "$out" "$u" && [ -s "$out" ]; then
            return 0
        fi
        echo "  失败，换下一源"
    done
    return 1
}

echo "== 下载 cn.txt（Loyalsoldier/geoip 权威源，v4+v6 混合）=="
dl_candidates "$OUT/cn.txt" "${CN_URLS[@]}" || { echo "全部源下载失败"; exit 1; }

echo "== 拆分为 v4 / v6 =="
grep -E '^[0-9.]+/[0-9]+$' "$OUT/cn.txt" > "$OUT/cn_cidr_v4.txt" \
    || { echo "cn.txt 无 v4 CIDR 行（源格式异常）" >&2; exit 1; }
grep -E '^[0-9a-fA-F:]+/[0-9]+$' "$OUT/cn.txt" > "$OUT/cn_cidr_v6.txt" \
    || { echo "cn.txt 无 v6 CIDR 行（源格式异常）" >&2; exit 1; }
rm -f "$OUT/cn.txt"
wc -l "$OUT/cn_cidr_v4.txt" "$OUT/cn_cidr_v6.txt"

echo "完成: $OUT/"
echo "把路径写进 split.yaml 的 cnip.path_v4 / path_v6 即可。"
