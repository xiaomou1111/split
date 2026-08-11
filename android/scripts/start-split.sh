#!/system/bin/sh
# start-split.sh — 手动（debug）启动
INSTALL_DIR=/data/adb/split
BIN_DIR="$INSTALL_DIR/bin"
export SPLIT_SOCKET="$INSTALL_DIR/run/splitd.sock"

# v1.1.3：启动前先对齐 mihomo tun 段契约（auto-route:false），
# 防止 box 原样配置/用户手改导致 eBPF 分流被路由接管静默失效
if [ -x "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" ]; then
  "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" "$INSTALL_DIR/mihomo/config.yaml" 2>&1 || true
fi

"$BIN_DIR/splitd" -d -c "$INSTALL_DIR/config/split.yaml" -b "$BIN_DIR/split.bpf.o" 2>&1
