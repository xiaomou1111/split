#!/bin/bash
# fetch-cnip.sh — 更新 CNIP 数据（IPv4 + IPv6）
#
# 默认源：
#   v4: https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt
#   v6: https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt
# 用法: ./scripts/fetch-cnip.sh [outdir]
set -e
cd "$(dirname "$0")/.."
OUT=${1:-data/cnip}

mkdir -p "$OUT"

echo "== IPv4 =="
curl -f -L --max-time 120 -s \
  -o "$OUT/cn_cidr_v4.txt" \
  https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt
[ -s "$OUT/cn_cidr_v4.txt" ] || { echo "IPv4 下载失败（空文件）"; exit 1; }
wc -l "$OUT/cn_cidr_v4.txt"

echo "== IPv6 =="
curl -f -L --max-time 120 -s \
  -o "$OUT/cn_cidr_v6.txt" \
  https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt
# 该源文件首行可能是注释，过滤后保留 cidr
grep -E '^[0-9a-fA-F:]+/[0-9]+' "$OUT/cn_cidr_v6.txt" > "$OUT/cn_cidr_v6.txt.clean" || true
mv "$OUT/cn_cidr_v6.txt.clean" "$OUT/cn_cidr_v6.txt"
[ -s "$OUT/cn_cidr_v6.txt" ] || { echo "IPv6 下载失败（过滤后为空）"; exit 1; }
wc -l "$OUT/cn_cidr_v6.txt"

echo "完成: $OUT/"
echo "把路径写进 split.yaml 的 cnip.path_v4 / path_v6 即可。"
