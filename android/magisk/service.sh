#!/system/bin/sh
# service.sh — late_start：核心启动胶水
#
# 顺序：
#   1) 能力探测（无 bpf → 跳过 eBPF，mihomo 仍要起，纯 TUN 由它负责）
#   2) SELinux 放行（magiskpolicy --live）
#   3) 起 mihomo（若随包）——独立于 splitd，缺一个不影响另一个
#   4) 等 utun 出现 → 起 splitd
#   5) 自检
#
# 运行时分层（/data/adb/split/）：
#   bin/   config/   scripts/   logs/   run/   mihomo/

MODDIR=${0%/*}
INSTALL_DIR=/data/adb/split
BIN_DIR="$INSTALL_DIR/bin"
CONFIG="$INSTALL_DIR/config/split.yaml"
LOG_DIR="$INSTALL_DIR/logs"
RUN_DIR="$INSTALL_DIR/run"
LOG="$LOG_DIR/splitd.log"

mkdir -p "$BIN_DIR" "$INSTALL_DIR/config" "$LOG_DIR" "$RUN_DIR" 2>/dev/null
: > "$LOG"

log() { echo "[split] $(date '+%m-%d %H:%M:%S') $*" >> "$LOG"; }

# ---------- 1) 内核能力 ----------
has_splitd=0
if [ -x "$BIN_DIR/splitd" ]; then
  has_splitd=1
  log "内核: $(uname -r)"

  # ---------- 2) SELinux ----------
  if command -v magiskpolicy >/dev/null 2>&1; then
    magiskpolicy --live \
      'allow magisk bpf:bpf { prog_load prog_pin map_create map_read map_write prog_test_run }' \
      'allow magisk self:unix_stream_socket create_stream_socket' \
      'allow magisk tun_device:chr_file rw_file_perms' \
      'allow magisk net_device:netlink_socket create' \
      2>/dev/null
    log "sepolicy 已放行"
  fi
else
  log "splitd 缺失，跳过 eBPF（mihomo 纯 TUN 仍会尝试启动）"
fi

# ---------- 3) mihomo（若随包在 bin/mihomo）----------
# 注意：mihomo 启动不依赖 splitd 是否存在。若缺 splitd，mihomo 自带的
# auto-route 也能保底 TUN，避免"注释说纯 TUN 负责但实际没起"的死区。
start_mihomo() {
  if [ ! -x "$BIN_DIR/mihomo" ]; then
    log "未随包 mihomo，请用官方 app（tun.device=utun）或用 setup-box-tun.sh 接入 box"
    return 1
  fi
  # v1.1.3：启动前强制对齐 tun 段契约（auto-route:false 等），防止 box 原样
  # 配置/用户手改导致 mihomo 接管路由 → eBPF 分流失效（direct_cn 恒 0）
  # 注意：fix 脚本 exit 1 = 配置缺失/无 tun 段（跳过，不视为失败）
  if [ -x "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" ]; then
    "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" "$INSTALL_DIR/mihomo/config.yaml" >> "$LOG" 2>&1 || true
    log "tun 段契约检查完成（见上）"
  fi
  if pgrep -f "$BIN_DIR/mihomo" >/dev/null 2>&1; then
    log "mihomo 已在运行"
    return 0
  fi
  "$BIN_DIR/mihomo" -d "$INSTALL_DIR/mihomo" >> "$LOG_DIR/mihomo.log" 2>&1 &
  log "mihomo 已启动 pid=$!"
}

# late_start 时网络/接口可能未就绪，mihomo 可能早退，做有限重试
for try in 1 2 3; do
  start_mihomo
  sleep 3
  if pgrep -f "$BIN_DIR/mihomo" >/dev/null 2>&1; then
    break
  fi
  log "mihomo 尝试 $try 次后未存活（详见 mihomo.log），重试"
done

# ---------- 4) 等 tun + 起 splitd ----------
if [ "$has_splitd" -eq 1 ]; then
  i=0
  while [ $i -lt 30 ]; do
    if [ -d "/sys/class/net/utun" ] || ip link show utun >/dev/null 2>&1; then
      break
    fi
    i=$((i+1)); sleep 1
  done

  if [ $i -ge 30 ]; then
    log "30s 内未发现 utun，降级纯 TUN（看 mihomo.log 是否 tun 建失败）"
  else
    # Android 无 /run 目录，ctl socket 走 run/
    export SPLIT_SOCKET="$RUN_DIR/splitd.sock"
    if [ ! -f "$BIN_DIR/split.bpf.o" ]; then
      log "缺少 $BIN_DIR/split.bpf.o，无法启动 splitd（请重新安装模块）"
    else
      "$BIN_DIR/splitd" -c "$CONFIG" -b "$BIN_DIR/split.bpf.o" >> "$LOG" 2>&1 &
      sleep 2
      if "$BIN_DIR/splitctl" status >> "$LOG" 2>&1; then
        log "splitd 已启动"
      else
        log "splitd 启动失败或已退出（BPF 加载失败时 splitd 会直接退出；"
        log "  mihomo 若 auto-route:false 则无分流兜底，请查 splitd.log/dmesg/sepolicy）"
      fi
      # v1.1.7：清理历史 stop 残留的停止闸（全新 boot 本不应存在，防升级/缓存脏状态），
      # 并拉起存活守护——doze/LMK 杀 splitd 后自动按同参数重启（探活走 ctl socket）。
      rm -f "$INSTALL_DIR/run/splitd.disabled"
      if [ -x "$INSTALL_DIR/scripts/split-watchdog.sh" ]; then
        "$INSTALL_DIR/scripts/split-watchdog.sh" >> "$LOG" 2>&1 &
        log "split-watchdog 已拉起（每 15s 探活 splitd）"
      fi
    fi
  fi
fi

exit 0
