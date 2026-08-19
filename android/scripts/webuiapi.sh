#!/system/bin/sh
# webuiapi.sh — KernelSU WebUI 后端（root 运行，由 webroot/app.js 通过 ksu.exec 调用）
#
# 为什么放 scripts/ 而非 webroot/：webroot 由 KernelSU 设定为"网页服务"上下文，
# 脚本执行放运行期目录 /data/adb/split/scripts/ 更符合本模块既有布局（start/stop 等同处）。
#
# 用法: webuiapi.sh <action> [args...]
#   status                 → status 文本（或 splitd 未运行提示）
#   stats                  → stats 文本
#   list-rules             → 当前在线规则（proxy/direct 行，v1.2.2）
#   version                → SPLIT_VERSION=...（打包时注入，仓库副本回退 dev）
#   start                  → 后台派生 splitd 并回 status（splitd 日志写 $LOG_DIR/splitd.log，
#                             见下方 export SPLIT_LOG——与 service.sh/watchdog 同源）
#   stop                   → splitctl stop
#   reload                 → splitctl reload
#   reload-cnip            → splitctl reload-cnip（重读本地文件重灌）
#   update-cnip            → splitctl update-cnip（下载 url_v4/v6 后重灌，后台执行）
#   cnip <on|off|status>   → 临时开启/绕过 CNIP 策略查询（白名单参数）
#   mihomo-status          → mihomo 运行状态（status=running/stopped + pid + ver + log）
#   mihomo-start           → 启动随包 mihomo（tun 契约对齐后起）
#   mihomo-stop            → 停止 mihomo
#   env                    → 环境信息（kernel/arch/android/sdk/device/selinux/uptime/splitd_pid/watchdog）
#   add-rule <cidr> <type> → splitctl add-rule（type: proxy|direct）
#   del-rule <cidr> <type> → splitctl del-rule
#   get-config             → 打印 split.yaml 全文
#   save-config <b64>      → 把 base64 内容写回 split.yaml，校验 + reload
#   validate-config <b64>  → 仅校验（写临时文件，不落盘不 reload）
#   get-log <which> [n]    → 打印日志尾部（which: splitd|mihomo，默认 n=200 行）
#
# 所有动作通过 SPLIT_SOCKET 指向运行期 socket（Android 无 /run，必须显式 export）。

INSTALL_DIR=/data/adb/split
BIN_DIR="$INSTALL_DIR/bin"
CONFIG_DIR="$INSTALL_DIR/config"
CFG="$CONFIG_DIR/split.yaml"
RUN_DIR="$INSTALL_DIR/run"
LOG_DIR="$INSTALL_DIR/logs"
# v1.2.2：版本号由 gen-magisk.sh 打包时注入（唯一真源 kernel/include/split_bpf.h）；
# 直接运行仓库副本时占位符未替换 → 回退 dev，便于本地调试。
SPLIT_VERSION="@SPLIT_VERSION@"
[ "$SPLIT_VERSION" = "@SPLIT_VERSION@" ] && SPLIT_VERSION="dev"
MIHOMO_DIR="$INSTALL_DIR/mihomo"
MIHOMO_BIN="$BIN_DIR/mihomo"
MIHOMO_LOG="$LOG_DIR/mihomo.log"
# mihomo 版本缓存：mihomo -v 是 Go 二进制冷启动（~百 ms），WebUI 每 5s 轮询
# 不值得反复执行。以缓存文件存在为有效（模块重装会重建 run/ 目录）。
MIHOMO_VER_CACHE="$RUN_DIR/mihomo.version"
export SPLIT_SOCKET="$RUN_DIR/splitd.sock"
# splitctl start 派生 splitd 的 stdout/stderr 走 split_log_path()（$SPLIT_LOG 优先，
# 默认 /var/log/splitd.log）。Android 上 service.sh / watchdog 都写 logs/splitd.log，
# 这里一并指向同一文件，否则 WebUI『启动』起的 splitd 日志落在日志页读不到的地方。
export SPLIT_LOG="$LOG_DIR/splitd.log"

CTL="$BIN_DIR/splitctl"
SPLITD="$BIN_DIR/splitd"
TUN_CONTRACT="$INSTALL_DIR/scripts/split-tun-contract.sh"
TUN_DEVICE=""
STATUS_OUT=""

ACTION="$1"

run() {
  "$CTL" "$@" 2>&1
  return $?
}

resolve_tun() {
  if [ ! -x "$TUN_CONTRACT" ]; then
    echo "ERR: 缺少 TUN 契约解析器 $TUN_CONTRACT（请重新安装模块）"
    return 1
  fi
  TUN_DEVICE=$("$TUN_CONTRACT" "$CFG") || {
    echo "ERR: 无法解析 split.yaml 的 tun_device"
    return 1
  }
  return 0
}

tun_exists() {
  [ -d "/sys/class/net/$TUN_DEVICE" ] || ip link show "$TUN_DEVICE" >/dev/null 2>&1
}

wait_for_tun() {
  limit="${1:-30}"
  i=0
  while [ "$i" -lt "$limit" ]; do
    tun_exists && return 0
    i=$((i + 1))
    sleep 1
  done
  return 1
}

splitd_ready() {
  STATUS_OUT=$("$CTL" status 2>&1) || return 1
  tun=$(printf '%s' "$STATUS_OUT" | sed -n 's/.*tun=\([0-9][0-9]*\).*/\1/p' | head -n1)
  [ -n "$tun" ] && [ "$tun" -gt 0 ]
}

wait_for_splitd_ready() {
  limit="${1:-10}"
  i=0
  while [ "$i" -lt "$limit" ]; do
    splitd_ready && return 0
    i=$((i + 1))
    sleep 1
  done
  return 1
}

ensure_watchdog() {
  if [ ! -x "$INSTALL_DIR/scripts/split-watchdog.sh" ]; then
    echo "ERR: 缺少 split-watchdog.sh（请重新安装模块）"
    return 1
  fi
  if ! pgrep -f "split-watchdog.sh" >/dev/null 2>&1; then
    "$INSTALL_DIR/scripts/split-watchdog.sh" >> "$LOG_DIR/splitd.log" 2>&1 &
  fi
  return 0
}

mihomo_alive() {
  pgrep -f "$MIHOMO_BIN" >/dev/null 2>&1
  return $?
}

# mihomo 版本（带缓存，见 MIHOMO_VER_CACHE 注释）
mihomo_ver() {
  if [ -f "$MIHOMO_VER_CACHE" ]; then
    cat "$MIHOMO_VER_CACHE" 2>/dev/null
    return 0
  fi
  v="$("$MIHOMO_BIN" -v 2>/dev/null | head -n1)"
  [ -n "$v" ] && printf '%s\n' "$v" > "$MIHOMO_VER_CACHE" 2>/dev/null
  echo "$v"
}

mihomo_status() {
  if [ ! -x "$MIHOMO_BIN" ]; then
    echo "status=no-binary"
    echo "note=未随包 mihomo 二进制（$MIHOMO_BIN）"
    return 0
  fi
  if mihomo_alive; then
    echo "status=running"
    echo "pid=$(pgrep -f "$MIHOMO_BIN" | head -n1)"
  else
    echo "status=stopped"
  fi
  echo "ver=$(mihomo_ver)"
  echo "log=$MIHOMO_LOG"
}

mihomo_start() {
  if [ ! -x "$MIHOMO_BIN" ]; then
    echo "ERR: 未随包 mihomo 二进制（$MIHOMO_BIN）"
    return 1
  fi
  resolve_tun || return 1
  # 与 service.sh 一致：启动前先按 split.yaml 的 tun_device 对齐 tun 段，
  # 防止 mihomo 配置与 splitd 的实际 TUN 目标不一致。
  if [ -x "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" ] && [ -f "$MIHOMO_DIR/config.yaml" ]; then
    if "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" "$MIHOMO_DIR/config.yaml" "$TUN_DEVICE" 2>&1; then
      :
    else
      rc=$?
      if [ "$rc" -ne 1 ]; then
        echo "ERR: mihomo tun 配置修复失败（rc=$rc）"
        return "$rc"
      fi
    fi
  fi
  if mihomo_alive; then
    echo "OK: mihomo 已在运行"
    return 0
  fi
  "$MIHOMO_BIN" -d "$MIHOMO_DIR" >> "$MIHOMO_LOG" 2>&1 &
  # 有限重试：晚启动/网络未就绪时 mihomo 偶尔早退
  for try in 1 2 3; do
    sleep 2
    if mihomo_alive; then
      echo "OK: mihomo 已启动"
      return 0
    fi
  done
  echo "ERR: mihomo 启动后退出（见日志尾）"
  [ -f "$MIHOMO_LOG" ] && tail -n 5 "$MIHOMO_LOG" 2>/dev/null
  return 1
}

mihomo_stop() {
  if ! mihomo_alive; then
    echo "OK: mihomo 未在运行"
    return 0
  fi
  pkill -f "$MIHOMO_BIN"
  sleep 1
  if mihomo_alive; then
    echo "ERR: mihomo 停止失败（残留进程）"
    return 1
  fi
  echo "OK: mihomo 已停止"
}

get_log() {
  # 参数: $1=splitd|mihomo, $2=行数（默认 200）
  which="$1"; n="${2:-200}"
  [ -n "$n" ] && case "$n" in (*[!0-9]*) n=200;; esac
  # v1.4.8：钳制上限——超大日志 tail 全文件会打爆 WebView
  [ "$n" -gt 5000 ] && n=5000
  case "$which" in
    splitd) L="$LOG_DIR/splitd.log" ;;
    mihomo) L="$MIHOMO_LOG" ;;
    *) echo "ERR: 未知日志 $which（可选 splitd|mihomo）"; return 1 ;;
  esac
  [ -f "$L" ] || { echo "ERR: 日志不存在 $L"; return 1; }
  # 按行截断，避免超大日志打爆 WebView
  if command -v tail >/dev/null 2>&1; then
    tail -n "$n" "$L"
  elif command -v busybox >/dev/null 2>&1; then
    busybox tail -n "$n" "$L"
  else
    cat "$L"
  fi
  return 0
}

save_config() {
  # 参数: $1=b64, $2=写入并reload(1) 或仅校验(0)
  b64="$1"
  do_write="${2:-1}"
  tmp="$CONFIG_DIR/.split.yaml.new"
  # base64 → 临时文件（base64 无 shell 危险字符，作为单引号参数传递安全）
  if command -v base64 >/dev/null 2>&1; then
    printf '%s' "$b64" | base64 -d > "$tmp" 2>/dev/null
  elif [ -x /system/bin/toybox ]; then
    printf '%s' "$b64" | /system/bin/toybox base64 -d > "$tmp" 2>/dev/null
  elif command -v busybox >/dev/null 2>&1; then
    printf '%s' "$b64" | busybox base64 -d > "$tmp" 2>/dev/null
  else
    echo "ERR: 设备无 base64，无法写配置（请手动编辑 $CFG）"
    return 1
  fi
  [ -s "$tmp" ] || { echo "ERR: 配置内容解码失败（空或非法 base64）"; rm -f "$tmp"; return 1; }

  # 先校验
  if ! "$CTL" validate -c "$tmp" >/dev/null 2>&1; then
    echo "ERR: 配置校验不通过，未写入（可用命令行 validate 定位）"
    rm -f "$tmp"
    return 1
  fi
  if [ "$do_write" = "0" ]; then
    echo "OK: 配置校验通过（仅校验，未落盘）"
    rm -f "$tmp"
    return 0
  fi
  mv -f "$tmp" "$CFG"
  "$CTL" reload 2>&1
}

case "$ACTION" in
  status)     run status ;;
  stats)      run stats ;;
  list-rules) run list-rules ;;
  version)    echo "SPLIT_VERSION=$SPLIT_VERSION" ;;
  start)
    # 完整启动顺序：mihomo → 目标 TUN → splitd → status → watchdog。
    # 失败时不清停止闸、不派生 watchdog，避免把 exit(3)/BPF 错误伪装成成功。
    resolve_tun || exit 1
    if [ ! -x "$SPLITD" ] || [ ! -x "$CTL" ] || [ ! -f "$BIN_DIR/split.bpf.o" ]; then
      echo "ERR: splitd 运行资产不完整（需要 splitd、splitctl、split.bpf.o）"
      exit 1
    fi

    # 幂等：已有健康 daemon 不再二次派生，避免单实例 exit(4) 噪声。
    if splitd_ready; then
      rm -f "$RUN_DIR/splitd.disabled"
      ensure_watchdog || exit 1
      printf '%s\n' "$STATUS_OUT"
      exit 0
    fi
    # 若进程已存在但 socket 尚未就绪，等待它，而不是再派生第二个实例。
    if pgrep -f "$SPLITD" >/dev/null 2>&1; then
      if wait_for_splitd_ready 10; then
        rm -f "$RUN_DIR/splitd.disabled"
        ensure_watchdog || exit 1
        printf '%s\n' "$STATUS_OUT"
        exit 0
      fi
      touch "$RUN_DIR/splitd.disabled"
      echo "ERR: splitd 进程已存在但 ctl status 未就绪，请查看 $LOG_DIR/splitd.log"
      exit 1
    fi

    # 随包 mihomo 由已有 helper 启动；没有随包二进制时允许外部代理先建 TUN。
    if [ -x "$MIHOMO_BIN" ]; then
      if ! mihomo_start; then
        touch "$RUN_DIR/splitd.disabled"
        exit 1
      fi
    else
      echo "未随包 mihomo，等待外部代理创建 TUN=$TUN_DEVICE"
    fi
    if ! wait_for_tun 30; then
      touch "$RUN_DIR/splitd.disabled"
      echo "ERR: 30s 内未发现 TUN=$TUN_DEVICE，请检查 mihomo.log 或外部代理配置"
      exit 1
    fi

    # TUN 已就绪后再次确认，覆盖并发的其它启动路径。
    if splitd_ready; then
      rm -f "$RUN_DIR/splitd.disabled"
      ensure_watchdog || exit 1
      printf '%s\n' "$STATUS_OUT"
      exit 0
    fi
    start_out=$("$CTL" -c "$CFG" -s "$SPLITD" -b "$BIN_DIR/split.bpf.o" start 2>&1)
    start_rc=$?
    if [ "$start_rc" -ne 0 ]; then
      printf '%s\n' "$start_out" >> "$LOG_DIR/splitd.log"
      touch "$RUN_DIR/splitd.disabled"
      echo "ERR: splitd 派生失败（rc=$start_rc），请查看 $LOG_DIR/splitd.log"
      exit 1
    fi
    if ! wait_for_splitd_ready 10; then
      touch "$RUN_DIR/splitd.disabled"
      echo "ERR: splitd 未在 10s 内达到 status OK/tun>0，请查看 $LOG_DIR/splitd.log"
      exit 1
    fi
    rm -f "$RUN_DIR/splitd.disabled"
    ensure_watchdog || exit 1
    printf '%s\n' "$STATUS_OUT"
    ;;
  stop)
    # 先置闸、停止 watchdog，再通过 socket 请求优雅退出；socket 失败时精确杀本模块 splitd。
    touch "$RUN_DIR/splitd.disabled"
    pkill -f "split-watchdog.sh" 2>/dev/null
    stop_out=$("$CTL" stop 2>&1)
    stop_rc=$?
    sleep 1
    if pgrep -f "$SPLITD" >/dev/null 2>&1; then
      pkill -f "$SPLITD" 2>/dev/null
      sleep 1
    fi
    if pgrep -f "$SPLITD" >/dev/null 2>&1; then
      echo "ERR: splitd 停止失败，仍有进程残留"
      [ -n "$stop_out" ] && printf '%s\n' "$stop_out"
      exit 1
    fi
    [ -n "$stop_out" ] && printf '%s\n' "$stop_out"
    # socket 不存在时 stop 是幂等成功；真实 ctl 错误且仍有进程的情况已在上面失败。
    [ "$stop_rc" -eq 0 ] || echo "OK: splitd 未运行（停止闸已设置）"
    ;;
  reload)     run reload ;;
  reload-cnip) run reload-cnip ;;
  update-cnip) run update-cnip ;;
  cnip)
    if [ -n "$3" ]; then
      echo "ERR: 用法 cnip on|off|status"
      exit 1
    fi
    case "$2" in
      on|off|status) run cnip "$2" ;;
      *) echo "ERR: 用法 cnip on|off|status"; exit 1 ;;
    esac
    ;;
  env)
    # 环境信息（WebUI 状态页"环境信息"卡 + 排障对照 docs/03-ANDROID.md）。
    # 全走系统只读命令，不经 ctl socket——splitd 未运行时也能展示。
    echo "kernel=$(uname -r 2>/dev/null)"
    echo "arch=$(uname -m 2>/dev/null)"
    echo "android=$(getprop ro.build.version.release 2>/dev/null)"
    echo "sdk=$(getprop ro.build.version.sdk 2>/dev/null)"
    echo "device=$(getprop ro.product.model 2>/dev/null)"
    echo "selinux=$(getenforce 2>/dev/null)"
    {
      read -r _up _ < /proc/uptime 2>/dev/null || _up=0
      _up=${_up%%.*}
      _up=${_up:-0}
      echo "uptime=$((_up / 3600))h$(((_up % 3600) / 60))m"
    }
    # splitd PID：-f 全路径匹配（watchdog 派生实例也是该路径，一并覆盖）；
    # webuiapi.sh 自身命令行不含该路径，不会自匹配。
    echo "splitd_pid=$(pgrep -f "$SPLITD" 2>/dev/null | head -n1)"
    if [ -n "$(pgrep -f "split-watchdog.sh" 2>/dev/null | head -n1)" ]; then
      echo "watchdog=1"
    else
      echo "watchdog=0"
    fi
    ;;
  mihomo-status) mihomo_status ;;
  mihomo-start)  mihomo_start ;;
  mihomo-stop)   mihomo_stop ;;
  add-rule)
    [ -n "$2" ] || { echo "ERR: 缺 CIDR"; exit 1; }
    # v1.3.1（审查修复）：未指定 which 时默认 proxy——旧实现传空串给 splitctl，
    # 后者报 "which 只能是 proxy 或 direct" 而非按默认处理。
    run add-rule "$2" "${3:-proxy}" ;;
  del-rule)
    [ -n "$2" ] || { echo "ERR: 缺 CIDR"; exit 1; }
    run del-rule "$2" "${3:-proxy}" ;;
  get-config)
    if [ -f "$CFG" ]; then
      cat "$CFG"
    else
      echo "ERR: 无配置文件 $CFG"
    fi
    ;;
  save-config)
    if [ -n "$2" ]; then
      save_config "$2" 1
    else
      echo "ERR: 缺 base64 内容"
      exit 1
    fi
    ;;
  validate-config)
    if [ -n "$2" ]; then
      save_config "$2" 0
    else
      echo "ERR: 缺 base64 内容"
      exit 1
    fi
    ;;
  get-log)
    if [ -n "$2" ]; then
      get_log "$2" "$3"
    else
      echo "ERR: 缺日志名（splitd|mihomo）"
      exit 1
    fi
    ;;
  *) echo "ERR: 未知命令 $1"; exit 1 ;;
esac
exit $?