#!/system/bin/sh
# stop-split.sh — 手动停止
INSTALL_DIR=/data/adb/split
BIN_DIR="$INSTALL_DIR/bin"
RUN_DIR="$INSTALL_DIR/run"
export SPLIT_SOCKET="$RUN_DIR/splitd.sock"

# v1.1.7：先置显式停止闸（watchdog 见之不再拉起），再停 splitd + 杀守护
# （splitctl stop 自身也会 touch 闸——v1.1.7 收敛在 splitctl，这里显式保留
#   是为了在 splitctl 版本不一致/失败时仍能防"刚 stop 又被拉起"）
touch "$RUN_DIR/splitd.disabled"
pkill -f "split-watchdog.sh" 2>/dev/null
"$BIN_DIR/splitctl" stop 2>/dev/null
pkill -f "$BIN_DIR/splitd" 2>/dev/null
echo done
