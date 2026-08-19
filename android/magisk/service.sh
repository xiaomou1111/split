#!/system/bin/sh
# service.sh — late_start：核心启动胶水
#
# 顺序：
#   1) 资产探测（splitd 缺失 → 跳过 eBPF，mihomo 仍可尝试启动，但不会自动接管纯 TUN 路由）
#   2) SELinux 放行（magiskpolicy --live）
#   3) 起 mihomo（若随包）——独立于 splitd，缺一个不影响另一个
#   4) 等 split.yaml 的 tun_device 出现 → 起 splitd；超时仍拉 watchdog 等待后续 TUN
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
TUN_CONTRACT="$INSTALL_DIR/scripts/split-tun-contract.sh"
CGROUP_SCRIPT="$INSTALL_DIR/scripts/split-cgroup.sh"
TUN_DEVICE=utun

mkdir -p "$BIN_DIR" "$INSTALL_DIR/config" "$LOG_DIR" "$RUN_DIR" 2>/dev/null
: > "$LOG"

log() { echo "[split] $(date '+%m-%d %H:%M:%S') $*" >> "$LOG"; }

# 把 split 服务进程迁入独立 cgroup，脱离 Android AppFreezer 冻结管控（v1.4.9）
# （详见 split-cgroup.sh 头部注释；失败静默容忍，不阻断服务启动）
adopt_cgroup() {
  [ -x "$CGROUP_SCRIPT" ] || return 0
  "$CGROUP_SCRIPT" >> "$LOG" 2>&1
}

if [ -x "$TUN_CONTRACT" ]; then
  if ! TUN_DEVICE=$("$TUN_CONTRACT" "$CONFIG" 2>>"$LOG"); then
    log "无法解析 split.yaml 的 tun_device，停止启动（默认值仅在 resolver 缺失时使用）"
    TUN_DEVICE=""
  fi
fi

start_watchdog() {
  [ -x "$INSTALL_DIR/scripts/split-watchdog.sh" ] || return 0
  "$INSTALL_DIR/scripts/split-watchdog.sh" >> "$LOG" 2>&1 &
  log "split-watchdog 已拉起（目标 TUN=$TUN_DEVICE，每 15s 探活 splitd）"
  adopt_cgroup
}

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
  log "splitd 缺失，跳过 eBPF（mihomo 仍会尝试启动；auto-route:false 下不会自动接管代理流量）"
fi

# ---------- 3) mihomo（若随包在 bin/mihomo）----------
# 注意：mihomo 启动不依赖 splitd 是否存在；但本模块的 auto-route:false 契约
# 不会在 splitd 缺失时自动提供可用的 pure-TUN 代理。
start_mihomo() {
  if [ -z "$TUN_DEVICE" ]; then
    log "tun_device 无效，跳过 mihomo 启动"
    return 1
  fi
  if [ ! -x "$BIN_DIR/mihomo" ]; then
    log "未随包 mihomo，请用官方 app（tun.device=$TUN_DEVICE）或用 setup-box-tun.sh 接入 box"
    return 1
  fi
  # v1.1.3：启动前强制对齐 tun 段契约（auto-route:false 等），防止 box 原样
  # 配置/用户手改导致 mihomo 接管路由 → eBPF 分流失效（direct_cn 恒 0）
  # 注意：fix 脚本 exit 1 = 配置缺失/无 tun 段（跳过，不视为失败）
  if [ -x "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" ]; then
    if "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" "$INSTALL_DIR/mihomo/config.yaml" "$TUN_DEVICE" >> "$LOG" 2>&1; then
      :
    else
      rc=$?
      if [ "$rc" -ne 1 ]; then
        log "tun 段契约修复失败（rc=$rc），不启动 mihomo"
        return "$rc"
      fi
    fi
    log "tun 段契约检查完成（目标 TUN=$TUN_DEVICE，见上）"
  fi
  if pgrep -f "$BIN_DIR/mihomo" >/dev/null 2>&1; then
    log "mihomo 已在运行"
    return 0
  fi
  "$BIN_DIR/mihomo" -d "$INSTALL_DIR/mihomo" >> "$LOG_DIR/mihomo.log" 2>&1 &
  log "mihomo 已启动 pid=$!"
  adopt_cgroup
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

# ---------- 4) 等目标 tun + 起 splitd ----------
if [ "$has_splitd" -eq 1 ]; then
  if [ -z "$TUN_DEVICE" ]; then
    log "tun_device 无效，跳过 splitd 与 watchdog"
  elif [ ! -x "$BIN_DIR/splitctl" ] || [ ! -f "$BIN_DIR/split.bpf.o" ]; then
    log "splitd 运行资产不完整（需要 splitd、splitctl、split.bpf.o），跳过启动"
  else
    i=0
    while [ $i -lt 30 ]; do
      if [ -d "/sys/class/net/$TUN_DEVICE" ] || ip link show "$TUN_DEVICE" >/dev/null 2>&1; then
        break
      fi
      i=$((i+1)); sleep 1
    done

    # 即使首次等待超时也启动 watchdog；它会在目标 TUN 后续出现时补拉 splitd。
    export SPLIT_SOCKET="$RUN_DIR/splitd.sock"
    rm -f "$INSTALL_DIR/run/splitd.disabled"
    if [ $i -ge 30 ]; then
      log "30s 内未发现 TUN $TUN_DEVICE，暂不启动 splitd；watchdog 将继续等待（见 mihomo.log）"
      start_watchdog
    else
      "$BIN_DIR/splitd" -c "$CONFIG" -b "$BIN_DIR/split.bpf.o" >> "$LOG" 2>&1 &
      sleep 2
      adopt_cgroup
      if "$BIN_DIR/splitctl" status >> "$LOG" 2>&1; then
        log "splitd 已启动（TUN=$TUN_DEVICE）"
      else
        log "splitd 启动失败或已退出（BPF 加载失败时 splitd 会直接退出；"
        log "  mihomo 若 auto-route:false 则不会自动切换为纯 TUN 代理，请查 splitd.log/dmesg/sepolicy）"
      fi
      start_watchdog
    fi
  fi
fi

exit 0
