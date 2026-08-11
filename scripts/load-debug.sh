#!/bin/bash
# load-debug.sh — Linux 桌面调试：加载 + 挂载 + 验证（默认），或 del 卸载
#
# 假设：已有 mihomo 且 tun 设备名 = utun
# 用法:
#   sudo ./scripts/load-debug.sh           # 加载并挂载到主出口网卡
#   sudo ./scripts/load-debug.sh del       # 卸载（tc filter del + qdisc del）
set -e
cd "$(dirname "$0")/.."

BPF=kernel/bpf/split.bpf.o
ACTION=${1:-load}

if [ "$ACTION" = "del" ]; then
  MAIN_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
  [ -n "$MAIN_IF" ] || { echo "未找到主出口网卡"; exit 1; }
  echo "== 卸载 $MAIN_IF =="
  tc filter del dev "$MAIN_IF" egress pref 10 handle 1 bpf 2>/dev/null || true
  tc qdisc del dev "$MAIN_IF" clsact 2>/dev/null || true
  echo "已清理（注意：该网卡原有 clsact 也会被删）"
  exit 0
fi
[ "$ACTION" = "load" ] || { echo "用法: $0 [load|del]"; exit 2; }

[ -f "$BPF" ] || { echo "先 make bpf"; exit 1; }

# 1. 检查 tun
TUN_IF=$(ip -o link show utun 2>/dev/null | awk -F'[ :]+' '{print $2}')
[ -n "$TUN_IF" ] || { echo "未发现 utun，请先启动 mihomo"; exit 1; }

# 2. 挂到主出口网卡
MAIN_IF=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')

echo "== 挂载到 $MAIN_IF（tun=$TUN_IF）=="
tc qdisc replace dev "$MAIN_IF" clsact 2>/dev/null || true
tc filter replace dev "$MAIN_IF" egress pref 10 handle 1 bpf da obj "$BPF" sec classifier

echo "== 检查 =="
tc filter show dev "$MAIN_IF" egress

echo "== 观测 =="
echo "  curl -4 https://www.baidu.com   → CNIP 直连（不进 mihomo）"
echo "  curl -4 https://www.youtube.com → 进 mihomo"
echo "  用 bpftool net 查看 挂载："
bpftool net show 2>/dev/null || echo "  (bpftool 不可用可忽略)"
echo "  调试完清理: sudo $0 del"
