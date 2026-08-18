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

ACTION="$1"

run() {
  "$CTL" "$@" 2>&1
  return $?
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
  # 与 service.sh 一致：启动前先对齐 tun 段契约（auto-route:false），
  # 防止 box 原样配置/用户手改导致 eBPF 分流被 mihomo 路由接管静默失效。
  if [ -x "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" ] && [ -f "$MIHOMO_DIR/config.yaml" ]; then
    "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" "$MIHOMO_DIR/config.yaml" 2>&1 || true
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
      echo "OK: mihomo 已启动" && return 0
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
    # 后台派生 splitd（splitctl start 自身 fork，脱离开断）
    # 必须带 -b 指定 BPF 对象（Android 默认 /etc/split/split.bpf.o 不存在）
    # v1.1.3：启动前先对齐 mihomo tun 段契约（auto-route:false），
    # 防止 box 原样配置/用户手改导致 eBPF 分流被路由接管静默失效
    if [ -f "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" ] && [ -f "$INSTALL_DIR/mihomo/config.yaml" ]; then
      "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" "$INSTALL_DIR/mihomo/config.yaml" 2>&1 || true
    fi
    # v1.1.7：清显式停止闸 + 拉起存活守护（防 doze/LMK 杀 splitd 后无人拉起）
    rm -f "$RUN_DIR/splitd.disabled"
    "$INSTALL_DIR/scripts/split-watchdog.sh" >> "$LOG_DIR/splitd.log" 2>&1 &
    # v1.2.2：splitd 路径用 -s（v1.1.9 起 -d 已改为零参 debug，旧 `-d 路径` 写法会导致
    # 派生到默认 /usr/local/bin/splitd 而非本模块 bin/，Android 上启动必失败）
    "$CTL" start -c "$CFG" -s "$SPLITD" -b "$BIN_DIR/split.bpf.o"
    sleep 1
    "$CTL" status
    ;;
  stop)
    # v1.1.7：先置停止闸再停 splitd，watchdog 见之不再拉起（防"刚 stop 又被拉活"）
    touch "$RUN_DIR/splitd.disabled"
    pkill -f "split-watchdog.sh" 2>/dev/null
    run stop ;;
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