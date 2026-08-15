#!/system/bin/sh
# setup-box-tun.sh — 端到端接入 box 模块的 mihomo（TUN 模式）
#
# 用途：设备已有 box（/data/adb/box）代理模块时，复用其 mihomo 二进制 + 节点，
#       切到 TUN 模式与 eBPF-Split 配合，实现"CN 内核直连 / 海外走代理"。
# 前提：root + box 已装 + 本模块已装（bin/ config/ scripts/ 分层于 /data/adb/split）
#
# 原理：
#   1. 复制 box 的 mihomo 目录到 split 专用目录（不改 box 原件）
#   2. 改 tun 段：enable:true, device:utun, mtu:1500, auto-route:false,
#      stack:gvisor, gso:false, auto-detect-interface:false
#   3. 复用 box 的 CNIP 数据（/data/adb/box/run/cn.zone）
#   4. 起 mihomo → 等 utun → 起 splitd
set -e

SPLIT_DIR=/data/adb/split
BIN_DIR=$SPLIT_DIR/bin
CONFIG_DIR=$SPLIT_DIR/config
LOG_DIR=$SPLIT_DIR/logs
RUN_DIR=$SPLIT_DIR/run
MIHOMO_DIR=$SPLIT_DIR/mihomo
BOX_MIHOMO=/data/adb/box/mihomo
BOX_RUN=/data/adb/box/run
MIHOMO_BIN=/data/adb/box/bin/mihomo
CONFIG=$CONFIG_DIR/split.yaml

echo "== 0. 前置检查 =="
[ -x "$MIHOMO_BIN" ] || { echo "缺少 mihomo 二进制 $MIHOMO_BIN"; exit 1; }
[ -d "$BOX_MIHOMO" ] || { echo "缺少 box mihomo 配置目录"; exit 1; }
[ -x "$BIN_DIR/splitd" ] || { echo "缺少 splitd（$BIN_DIR/splitd）"; exit 1; }
mkdir -p "$LOG_DIR" "$RUN_DIR"

echo "== 1. 准备 split 专用 mihomo 目录 =="
pkill -f "mihomo.*$MIHOMO_DIR" 2>/dev/null || true
rm -rf "$MIHOMO_DIR"
mkdir -p "$MIHOMO_DIR"
cp -a "$BOX_MIHOMO/." "$MIHOMO_DIR/"

echo "== 2. 改 tun 段（enable / device / mtu / auto-route / stack:gvisor / gso:off / auto-detect-interface）=="
# 委托给 fix-mihomo-tun.sh（v1.1.3 抽取，单一真源）：全部整行重写、幂等。
# v1.4.8：此处不再残留内联 sed——早期注释称"原内联 sed 已移除"但 enable/device 两条
#   实际残留，且 enable 是共享键名，无作用域的全文件 `^  enable:` 替换可能误中
#   dns.enable。enable:true / device:utun 均已收敛进 fix-mihomo-tun.sh（enable 段内
#   限域处理），toybox sed 不支持 `0,/re/` 地址也在该脚本内规避。
SELF=$(readlink -f "$0" 2>/dev/null || echo "$0")
sh "$(dirname "$SELF")/fix-mihomo-tun.sh" "$MIHOMO_DIR/config.yaml" || echo "  (fix-mihomo-tun 无 tun 段，跳过)"
echo "-- 修改后 tun 段："
sed -n '/^tun:/,/^  udp-timeout:/p' "$MIHOMO_DIR/config.yaml"

echo "== 3. 测试配置 =="
"$MIHOMO_BIN" -t -d "$MIHOMO_DIR" 2>/dev/null || { echo "mihomo 配置测试失败"; exit 1; }

echo "== 4. 复用 box CNIP 数据 =="
if [ -f "$BOX_RUN/cn.zone" ]; then
  cp "$BOX_RUN/cn.zone" "$CONFIG_DIR/cn_cidr_v4.txt"
  echo "CNIP v4: $(wc -l < "$CONFIG_DIR/cn_cidr_v4.txt") 行"
fi
if [ -f "$BOX_RUN/cn_ipv6.zone" ]; then
  cp "$BOX_RUN/cn_ipv6.zone" "$CONFIG_DIR/cn_cidr_v6.txt"
  echo "CNIP v6: $(wc -l < "$CONFIG_DIR/cn_cidr_v6.txt") 行"
fi

echo "== 5. 确保 split.yaml 的 cnip 用绝对路径 =="
sed -i "s|path_v4: .*|path_v4: $CONFIG_DIR/cn_cidr_v4.txt|" "$CONFIG"
sed -i "s|path_v6: .*|path_v6: $CONFIG_DIR/cn_cidr_v6.txt|" "$CONFIG"

echo "== 6. 启动 mihomo（TUN）=="
nohup "$MIHOMO_BIN" -d "$MIHOMO_DIR" > "$LOG_DIR/mihomo.log" 2>&1 &
echo "mihomo pid=$!"

echo "== 7. 等 utun（最多 15s）=="
utun_ok=""
for i in $(seq 1 15); do
  if [ -e /sys/class/net/utun ]; then echo "utun 已出现"; utun_ok=1; break; fi
  sleep 1
done
[ -n "$utun_ok" ] || { echo "utun 未出现，mihomo TUN 可能失败"; tail -10 "$LOG_DIR/mihomo.log"; exit 1; }
ip link set utun up 2>/dev/null || true

echo "== 8. 启动 splitd =="
export SPLIT_SOCKET="$RUN_DIR/splitd.sock"
"$BIN_DIR/splitctl" stop 2>/dev/null || true
pkill -f splitd 2>/dev/null || true
rm -f "$SPLIT_SOCKET"
# v1.1.7：清停止闸（防历史 stop 残留）+ 停掉旧 watchdog 再重拉（防双实例守护）
rm -f "$RUN_DIR/splitd.disabled"
pkill -f "split-watchdog.sh" 2>/dev/null || true
nohup "$BIN_DIR/splitd" -c "$CONFIG" -b "$BIN_DIR/split.bpf.o" > "$LOG_DIR/splitd.log" 2>&1 &
if [ -x "$SPLIT_DIR/scripts/split-watchdog.sh" ]; then
  "$SPLIT_DIR/scripts/split-watchdog.sh" >> "$LOG_DIR/splitd.log" 2>&1 &
fi
sleep 3

echo "== 9. 验证 =="
"$BIN_DIR/splitctl" status 2>&1
"$BIN_DIR/splitctl" stats 2>&1
echo "-- CN 直连测试 --"
ping -c 1 -W 2 223.5.5.5 2>&1 | tail -2
echo "-- 海外代理测试（延迟应明显更高）--"
ping -c 1 -W 2 8.8.8.8 2>&1 | tail -2
echo "== 完成：CN 内核直连 / 海外走 mihomo TUN =="
