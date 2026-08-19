#!/system/bin/sh
# split-watchdog.sh — splitd 存活守护（v1.1.7）
#
# 背景（真机症状）：长时间熄屏（doze）后无法代理、mihomo 只剩自身 DNS 连接。
# 根因路径：splitd 只由 service.sh 在 boot 时拉一次，之后无任何守护——
#   ① splitd 被 Android 冻结/LMK 杀掉后无人拉起；
#   ② 被杀瞬间 tc filter 残留持引用保住旧 prog+旧 maps，但 map_tun 不再更新，
#      mihomo 重建 utun（ifindex 漂移）后 bpf_redirect 到陈旧 ifindex →
#      __skb_do_redirect 静默丢包，代理流量全挂且无报错（skip_uid 的 uid0 直连仍通）。
# 本脚本：周期性探活 splitd（经 ctl socket，比 pidfile 可靠），失控即按同参数拉起。
#
# 设计要点：
#   - 探活用 `splitctl status`（连 ctl socket），而非 pidfile：覆盖 service.sh /
#     splitctl start / WebUI start 派生的各类实例；"在跑但失去响应"也视为死。
#   - 显式停止闸：`splitctl stop`（v1.1.7 起收敛在 splitctl）及 stop-split.sh /
#     WebUI stop 都会 touch $RUN_DIR/splitd.disabled，本脚本见之即跳过；
#     start 路径清闸。防"用户刚 stop 又被拉起"。
#   - 防 crash-loop：utun 不存在（mihomo 未起）直接跳过——splitd 依赖 mihomo
#     的 tun，没 tun 拉起也是 exit 3。utun/二进制缺失分支（本次不拉起）会复位
#     fails，避免陈旧退避拖慢恢复后的首次拉起；连续失败指数退避（最长 5 分钟）。
#   - 单实例：启动时清掉旧的本脚本进程（防止 service.sh + WebUI 各起一个）。
#
# 用法: split-watchdog.sh [interval秒]   （默认 15，服务由 service.sh 后台拉）

INSTALL_DIR=/data/adb/split
BIN_DIR="$INSTALL_DIR/bin"
RUN_DIR="$INSTALL_DIR/run"
CFG="$INSTALL_DIR/config/split.yaml"
LOG_DIR="$INSTALL_DIR/logs"
LOG="$LOG_DIR/splitd.log"
DISABLED="$RUN_DIR/splitd.disabled"
TUN_CONTRACT="$INSTALL_DIR/scripts/split-tun-contract.sh"
CGROUP_SCRIPT="$INSTALL_DIR/scripts/split-cgroup.sh"
TUN_DEVICE=utun
INTERVAL=${1:-15}
export SPLIT_SOCKET="$RUN_DIR/splitd.sock"

log() { echo "[wd] $(date '+%m-%d %H:%M:%S') $*" >> "$LOG"; }

# 服务进程迁入独立 cgroup（脱离 AppFreezer 冻结，v1.4.9），失败静默容忍
adopt_cgroup() {
  [ -x "$CGROUP_SCRIPT" ] || return 0
  "$CGROUP_SCRIPT" >> "$LOG" 2>&1
}

if [ -x "$TUN_CONTRACT" ]; then
  if ! TUN_DEVICE=$("$TUN_CONTRACT" "$CFG" 2>>"$LOG"); then
    log "无法解析 split.yaml 的 tun_device，watchdog 暂停"
    exit 1
  fi
fi

refresh_tun() {
  [ -x "$TUN_CONTRACT" ] || return 0
  next_tun=$("$TUN_CONTRACT" "$CFG" 2>>"$LOG") || return 1
  [ "$next_tun" = "$TUN_DEVICE" ] || log "目标 TUN 已更新: $TUN_DEVICE -> $next_tun"
  TUN_DEVICE="$next_tun"
  return 0
}

# mihomo 全重启（API 自愈失败后的兜底）：kill + fix-mihomo-tun.sh 对齐契约 + 重新拉起
# （从 API 分支抽成函数，供"带鉴权/不带鉴权"两条 PATCH 路径共用，避免重复块）。
restart_mihomo() {
  log "mihomo API 恢复失败，重启 mihomo"
  pkill -f "$BIN_DIR/mihomo" 2>/dev/null
  sleep 2
  if [ -x "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" ] && [ -f "$INSTALL_DIR/mihomo/config.yaml" ]; then
    if "$INSTALL_DIR/scripts/fix-mihomo-tun.sh" "$INSTALL_DIR/mihomo/config.yaml" "$TUN_DEVICE" >> "$LOG" 2>&1; then
      :
    else
      rc=$?
      if [ "$rc" -ne 1 ]; then
        log "mihomo tun 段修复失败（rc=$rc），取消本次重启"
        return "$rc"
      fi
    fi
  fi
  "$BIN_DIR/mihomo" -d "$INSTALL_DIR/mihomo" >> "$LOG_DIR/mihomo.log" 2>&1 &
  adopt_cgroup
}

# 单实例：杀掉其它正在跑的本脚本（含上一次启动残留），排除自身（$$）
for p in $(pgrep -f "split-watchdog.sh" 2>/dev/null); do
  [ "$p" != "$$" ] && kill "$p" 2>/dev/null
done

# 单调秒数（/proc/uptime，Android toybox 必有）：用于 mihomo 恢复冷却——
# 旧实现用 `date +%s`（墙钟）：部分设备无 date +%s（回退 echo 0 旁路冷却），
# 且墙钟跳时会让冷却失效/误延长。uptime 不随系统时间调整（v1.3.1 审查修复）。
uptime_s() {
  _up=""
  read -r _up _ < /proc/uptime 2>/dev/null
  case "$_up" in
    ''|*[!0-9.]*) echo 0 ;;
    *) echo "${_up%%.*}" ;;
  esac
}

fails=0
mihomo_tun_fails=0
mihomo_recover_ts=0
while :; do
  sleep "$INTERVAL"

  adopt_cgroup

  if ! refresh_tun; then
    log "无法刷新 split.yaml 的 tun_device，本轮跳过"
    fails=0
    continue
  fi

  # 显式停止闸：用户 stop 过则不再拉起
  if [ -f "$DISABLED" ]; then
    fails=0
    continue
  fi

  # splitd 探活：ctl socket 通 = 活着（含 splitctl start/WebUI 派生的实例）
  # v1.2.9：探活成功但 map_tun=0（mihomo TUN 消失）也要自愈——这是"splitd 活着
  # 但代理全放行直连"的静默降级（真机症状：miss_tun 持续增长、proxy 停滞却无报错）。
  # 原逻辑只在 splitd 死亡路径做动作，mihomo tun 丢失时 watchdog 完全无感知。
  if status_out=$("$BIN_DIR/splitctl" status 2>/dev/null); then
    fails=0
    tun=$(printf '%s' "$status_out" | sed -n 's/.*tun=\([0-9]*\).*/\1/p' | head -n1)
    if [ -n "$tun" ] && [ "$tun" = "0" ]; then
      mihomo_tun_fails=$((mihomo_tun_fails + 1))
      # 连续 2 轮（默认 15s×2=30s）确认缺失才动作，防瞬时抖动误重启
      if [ "$mihomo_tun_fails" -ge 2 ] && [ -x "$BIN_DIR/mihomo" ]; then
        now=$(uptime_s)
        # uptime 读不到时 uptime_s 回退 echo 0：此时不能再按 now>=冷却判定——
        # 0 永远 <300，TUN 自愈会被永久禁用（v1.3.1 换 uptime 前的"回退 echo 0 旁路
        # 冷却"意图被破坏，此处恢复：now=0 一律视为冷却已到，时钟恢复正常后冷却照常）。
        if [ "$now" -ge "$mihomo_recover_ts" ] || [ "$now" = 0 ]; then
          log "splitd 存活但 map_tun=0（mihomo TUN 消失），尝试恢复 mihomo TUN"
          # 恢复优先级：先经 mihomo 外部控制器把 tun.enable 拉回 true（无感、不丢连接）；
          # API 不可达/失败再重启 mihomo（断开但保证重建 utun）。
          # 审查修复（2026-08 全库审查批次）：mihomo 配了 secret 时 PATCH 必须带 Bearer
          # 鉴权，否则 401 被误判为"API 不可达"而多余重启（断连）；读不到/为空 → 按旧逻辑
          # 不带鉴权。读取只做简单 sed 清洗（去引号/行内注释），secret 含特殊字符时提取
          # 失败只会 401 → 自然落到 restart_mihomo 兜底，不会误动作。
          # v1.4.6（审查 P2）：curl 必须带 -f——此前 401/4xx 是"HTTP 成功"（curl 退出 0），
          # `|| restart_mihomo` 不触发，冷却 300s 后重试同一失败 PATCH，TUN 自愈永久卡死
          # 且与上述"401 → 落重启兜底"注释矛盾。加 -f 后任何非 2xx 都走重启兜底。
          _sec="$(sed -n 's/^[[:space:]]*secret:[[:space:]]*\(.*\)/\1/p' "$INSTALL_DIR/mihomo/config.yaml" 2>/dev/null | head -n1)"
          _sec="$(printf '%s' "$_sec" | sed -e 's/^[[:space:]]*//;s/["'\'']//g;s/[[:space:]]*#.*$//;s/[[:space:]]*$//')"
          if [ -n "$_sec" ]; then
            curl -s -f -m 3 -X PATCH http://127.0.0.1:9090/configs \
                 -H "Authorization: Bearer $_sec" \
                 -d '{"tun":{"enable":true}}' >/dev/null 2>&1 || restart_mihomo
          else
            curl -s -f -m 3 -X PATCH http://127.0.0.1:9090/configs \
                 -d '{"tun":{"enable":true}}' >/dev/null 2>&1 || restart_mihomo
          fi
          # 恢复动作后 5 分钟冷却，防 API 拉了又被外部关掉导致循环重启
          mihomo_recover_ts=$((now + 300))
          mihomo_tun_fails=0
        fi
      fi
    else
      mihomo_tun_fails=0
    fi
    continue
  fi

  # 死亡路径：确认具备拉起条件（mihomo tun 必须在，否则拉了也 exit 3）
  # v1.1.7/C：此二分支是"本次不尝试拉起"的跳过状态（非拉起失败），
  # 需复位 fails —— 否则先前失败计数会随 utun 缺席一直带进下一轮，
  # 待 mihomo tun 恢复后的首次拉起反而被陈旧指数退避拖慢。
  if [ ! -d "/sys/class/net/$TUN_DEVICE" ] && ! ip link show "$TUN_DEVICE" >/dev/null 2>&1; then
    fails=0
    continue
  fi
  if [ ! -x "$BIN_DIR/splitd" ] || [ ! -f "$BIN_DIR/split.bpf.o" ]; then
    fails=0
    continue
  fi

  # 连续失败指数退避（15s→...→最长 5 分钟），避免 BPF 加载失败等死循环刷日志
  fails=$((fails + 1))
  if [ "$fails" -gt 1 ]; then
    d=$INTERVAL
    i=1
    while [ "$i" -lt "$fails" ] && [ "$d" -lt 300 ]; do
      d=$((d * 2))
      i=$((i + 1))
    done
    [ "$d" -gt 300 ] && d=300
    sleep "$d"
  fi

  # 退避期间可能发生显式 stop；sleep 返回后必须再次检查停止闸，不能把旧决定带到 spawn。
  if [ -f "$DISABLED" ]; then
    log "停止闸已设置，取消本轮 splitd 拉起"
    fails=0
    continue
  fi

  log "splitd 未运行（探活失败），重新拉起（第 $fails 次尝试，TUN=$TUN_DEVICE）"
  "$BIN_DIR/splitd" -c "$CFG" -b "$BIN_DIR/split.bpf.o" >> "$LOG" 2>&1 &
  adopt_cgroup
  # 给 splitd 冷启动时间，下一轮循环再探活（避免启动过程被误判为死）
  sleep "$INTERVAL"
done