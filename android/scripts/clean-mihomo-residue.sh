#!/system/bin/sh
# clean-mihomo-residue.sh — 清理 mihomo 从 auto-route:true 残留的路由/规则（幂等）
#
# 背景（v1.2.3 真机修复）：
#   mihomo 曾以 auto-route:true（box 原样配置）运行过时，sing-tun 会在
#   非 main 路由表（如 table 2022）写入 `default dev utun` 路由，并加
#   ip rule（如 `from all oif utun lookup 2022`）。改回 auto-route:false 后
#   mihomo 只清理自己运行时管理的部分，**可能残留 v4/v6 的规则与路由**——
#   split 的 hijack 检测（route_tun_hijacked）若把这些误判为"无条件接管"，
#   splitctl status 会恒报 hijack=1 + WARN，误导排查（实际分流不受影响）。
#
# 本脚本幂等清理：删除所有指向 tun 接口 default 路由所在的私有路由表
# （除 local/main），以及所有 oif/iif 指向 tun 的 ip rule。执行安全：
#   - 只删 "default dev <tun>"（/0 前缀）路由，不碰具体网段路由；
#   - 只删指向私有表的规则（table 不是 main/local/99/98/97/1002 等系统表）；
#   - 删失败（表/规则不存在）静默忽略。
#
# 用法: clean-mihomo-residue.sh [tun_device]   缺省 utun
# 返回: 0 总是（幂等清理，非失败语义）
set -u

TUN="${1:-utun}"

# 1) 清掉指向 tun 的私有表 default 路由（v4+v6）
# 先精确匹配 "default dev <tun> ... table N"，只删私有表（避开 local/main 等系统表）
ip -6 route show table all 2>/dev/null | grep "default dev $TUN" | grep -oE "table [0-9]+" |
while read -r tbl; do
  t="${tbl#table }"
  case "$t" in
    local|main|default|256|254|253|0) continue ;;  # 系统表不动
  esac
  echo "clean: ip -6 route del default dev $TUN table $t"
  ip -6 route del default dev "$TUN" table "$t" 2>/dev/null || true
done
ip route show table all 2>/dev/null | grep "default dev $TUN" | grep -oE "table [0-9]+" |
while read -r tbl; do
  t="${tbl#table }"
  case "$t" in
    local|main|default|256|254|253|0) continue ;;
  esac
  echo "clean: ip route del default dev $TUN table $t"
  ip route del default dev "$TUN" table "$t" 2>/dev/null || true
done

# 2) 清掉 oif/iif 指向 tun 的 ip rule（v4+v6）
for fam in -4 -6; do
  ip "$fam" rule show 2>/dev/null | grep -E "(oif|iif) $TUN" |
  while read -r line; do
    pref="${line%%:*}"
    echo "clean: ip $fam rule del pref $pref"
    ip "$fam" rule del pref "$pref" 2>/dev/null || true
  done
done

echo "clean-mihomo-residue: done (tun=$TUN)"
exit 0
