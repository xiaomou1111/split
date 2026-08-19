#!/system/bin/sh
# start-split.sh — 手动（debug）启动
INSTALL_DIR=/data/adb/split
BIN_DIR="$INSTALL_DIR/bin"
CONFIG="$INSTALL_DIR/config/split.yaml"
TUN_CONTRACT="$INSTALL_DIR/scripts/split-tun-contract.sh"
TUN_DEVICE=utun
export SPLIT_SOCKET="$INSTALL_DIR/run/splitd.sock"

if [ -x "$TUN_CONTRACT" ]; then
  TUN_DEVICE=$("$TUN_CONTRACT" "$CONFIG") || exit 1
fi

# v1.1.3：启动前先对齐 mihomo tun 段契约（auto-route:false），
# 防止 box 原样配置/用户手改导致 eBPF 分流被路由接管静默失效
if [ -x "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" ]; then
  if "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" "$INSTALL_DIR/mihomo/config.yaml" "$TUN_DEVICE" 2>&1; then
    :
  else
    rc=$?
    [ "$rc" -eq 1 ] || exit "$rc"
  fi
fi

"$BIN_DIR/splitd" -d -c "$CONFIG" -b "$BIN_DIR/split.bpf.o" 2>&1
