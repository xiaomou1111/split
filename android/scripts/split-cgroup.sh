#!/system/bin/sh
# split-cgroup.sh — 把 split 服务进程迁入独立 cgroup，脱离 Android AppFreezer 管控
#
# 背景（v1.4.9 真机）：mihomo/splitd/watchdog 由 KernelSU WebUI 拉起时继承 kernelsu
#   （uid_10443）的 cgroup（/sys/fs/cgroup/apps/uid_10443/pid_*）。熄屏/后台时
#   Android AppFreezer 冻结该 cgroup（cgroup.freeze=1），同 cgroup 的 mihomo 连带
#   冻结（wchan=do_freezer_trap，无法处理流量/心跳），随后被系统以 "while frozen"
#   名义 kill → 表现为"mihomo 频频崩溃/退出"。
#
# 方案：把 mihomo/splitd/watchdog 迁入独立 cgroup /sys/fs/cgroup/split_svc——
#   · 与 /sys/fs/cgroup/apps 平级（非子级），AppFreezer 只冻结 apps 子树，影响不到；
#   · 进程带 cgroup 是"随写随生效"：迁出后冻结即解除，无需向旧 cgroup 写 freeze=0。
# 幂等：已在该 cgroup 内则跳过；cgroup 创建/迁移失败（无权限/非 v2）静默容忍，
#   不影响服务本体启动。
#
# 用法: split-cgroup.sh [name...]
#   参数为要迁移的进程名关键词（默认 mihomo splitd split-watchdog）
#   返回: 0 总是（失败不阻断调用方）

CG=/sys/fs/cgroup
DIR="$CG/split_svc"
SELF=$$

# 目标进程名（可被 pgrep -f 匹配的命令行片段）
DEFAULT_NAMES="mihomo splitd split-watchdog.sh"
NAMES="${*:-$DEFAULT_NAMES}"

# cgroup v2 检测：非 v2（无 cgroup.controllers）直接放弃，保持兼容
[ -f "$CG/cgroup.controllers" ] || exit 0

mkdir -p "$DIR" 2>/dev/null || exit 0
# 确保该目录不被 AppFreezer 触碰（write 0 幂等；即使失败也不影响后续迁移）
echo 0 > "$DIR/cgroup.freeze" 2>/dev/null

migrate() {   # $1=pid
  [ -z "$1" ] && return
  [ "$1" = "$SELF" ] && return
  # 写入 cgroup.procs 即把该 pid 连同其线程一并迁入（cgroup v2 线程随进程）
  echo "$1" > "$DIR/cgroup.procs" 2>/dev/null
}

for n in $NAMES; do
  for p in $(pgrep -f "$n" 2>/dev/null); do
    migrate "$p"
  done
done

# 迁移成功后把 oom_score_adj 设为 -17（不可被杀），防止系统在内存压力下误杀
# 守护进程（split 是网络关键路径，宁可牺牲普通 App 的缓存页）
if [ -d "$DIR" ]; then
  for p in $(cat "$DIR/cgroup.procs" 2>/dev/null); do
    [ -w "/proc/$p/oom_score_adj" ] && echo -17 > "/proc/$p/oom_score_adj" 2>/dev/null
  done
fi

exit 0