#!/bin/bash
# fetch-cnip.sh — 更新 CNIP 数据（IPv4 + IPv6）
#
# 默认源（2026-08 更换 v4；v1.4.2 多源 fallback）：
#   v4: misakaio/chnroutes2（每日 APNIC 路由 dump，聚合约 3900 条；前 2 行是 # 注释）
#   v6: gaoyifan/china-operator-ip china6.txt（每日运营商 IP 库）
# 每族候选按序尝试，任一成功即用：jsDelivr（大陆可达）优先，raw.githubusercontent 兜底。
#   v4: https://cdn.jsdelivr.net/gh/misakaio/chnroutes2@master/chnroutes.txt
#       https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt
#   v6: https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china6.txt
#       https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt
# cdn.jsdelivr.net 不可达时可换 https://fastly.jsdelivr.net/gh/... 前缀。
# 用法: ./scripts/fetch-cnip.sh [outdir]
set -e
cd "$(dirname "$0")/.."
OUT=${1:-data/cnip}

mkdir -p "$OUT"

# 多源候选（与 config.c 的默认 url_v4/v6 逗号串一致）
V4_URLS=(
  "https://cdn.jsdelivr.net/gh/misakaio/chnroutes2@master/chnroutes.txt"
  "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
)
V6_URLS=(
  "https://cdn.jsdelivr.net/gh/gaoyifan/china-operator-ip@ip-lists/china6.txt"
  "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt"
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

echo "== IPv4 =="
dl_candidates "$OUT/cn_cidr_v4.txt" "${V4_URLS[@]}" || { echo "IPv4 全部源下载失败"; exit 1; }
# 该源文件头 2 行是 # 注释，过滤后保留 cidr
grep -E '^[0-9.]+/[0-9]+' "$OUT/cn_cidr_v4.txt" > "$OUT/cn_cidr_v4.txt.clean" || true
mv "$OUT/cn_cidr_v4.txt.clean" "$OUT/cn_cidr_v4.txt"
[ -s "$OUT/cn_cidr_v4.txt" ] || { echo "IPv4 下载失败（过滤后为空）"; exit 1; }
wc -l "$OUT/cn_cidr_v4.txt"

echo "== IPv6 =="
dl_candidates "$OUT/cn_cidr_v6.txt" "${V6_URLS[@]}" || { echo "IPv6 全部源下载失败"; exit 1; }
# 该源文件首行可能是注释，过滤后保留 cidr
grep -E '^[0-9a-fA-F:]+/[0-9]+' "$OUT/cn_cidr_v6.txt" > "$OUT/cn_cidr_v6.txt.clean" || true
mv "$OUT/cn_cidr_v6.txt.clean" "$OUT/cn_cidr_v6.txt"
[ -s "$OUT/cn_cidr_v6.txt" ] || { echo "IPv6 下载失败（过滤后为空）"; exit 1; }
wc -l "$OUT/cn_cidr_v6.txt"

echo "完成: $OUT/"
echo "把路径写进 split.yaml 的 cnip.path_v4 / path_v6 即可。"
