#!/system/bin/sh
# fix-mihomo-tun.sh — 校验/修复 mihomo tun 段，对齐 eBPF-Split 契约（幂等）
#
# 背景（v1.1.3 真机教训）：box 原样配置 / 用户手改 / 恢复备份时，tun 段可能带
# auto-route:true、strict-route:true、stack:system、gso:true、mtu:9000 等，
# 其中 auto-route:true 会让 mihomo 接管路由 → 物理网卡 egress 的 eBPF 完全
# 看不到流量 → CNIP/规则分流失效（direct_cn 恒 0 却无报错）。
#
# 本脚本在 service.sh/WebUI start 前调用：tun 段不合规则整行重写修复（幂等，
# 重复执行不累积损坏），关键项缺失时追加。打印修改前后对比。
#
# 用法: fix-mihomo-tun.sh [config.yaml]
#   缺省 /data/adb/split/mihomo/config.yaml
#   返回: 0=合规或已修复; 1=文件缺失/无 tun 段(跳过, 不视为失败)

CFG="${1:-/data/adb/split/mihomo/config.yaml}"
[ -f "$CFG" ] || exit 1

# 无 tun: 段（如未开 TUN）→ 无需修复
grep -q '^tun:' "$CFG" || exit 1

echo "== fix-mihomo-tun: 检查 $CFG =="
rm -f "$CFG.fixbak"
cp "$CFG" "$CFG.fixbak" 2>/dev/null

# 硬契约（与 setup-box-tun.sh / android/MEMORY.md 同步；改一处必改三处）：
#   device:utun      —— v1.2.6 补充：device 被 WebUI 重载改空/改名是"重载后新 TUN 落回
#                        Meta/tunN 漂移"的源头；启动前强制回 utun，与 split.yaml 的
#                        tun_device 保持字节一致（split 侧另有名字漂移兜底，双保险）
#   auto-route:false 必须 —— 路由与分流全交给 eBPF
#   strict-route:false
#   stack:gvisor     —— mixed/system 与 eBPF redirect 不兼容（v1.0.3 实测）
#   gso:false        —— vnetHdr 不兼容裸 IP（v1.0.4 实测，curl 000）
#   mtu:1500         —— 对齐物理网卡，避免大包分片/黑洞
#   auto-detect-interface:false —— 出口选择由 eBPF 接管
#
# 策略：key 已存在 → 整行重写；不存在 → 在 tun: 段后追加一行。
# 注意：Android toybox sed 不支持 `0,/re/` 地址形式（实测报 "no previous regex"），
# 追加只能用 a 命令；a 追加每执行一次多一行，故必须先 grep 判缺再追加。
fix_key() {
  key="$1"; val="$2"
  if grep -q "^  $key:" "$CFG"; then
    sed -i "s|^  $key:.*$|  $key: $val|" "$CFG"
  else
    sed -i "/^tun:/a\\  $key: $val" "$CFG"
  fi
}

fix_key device utun
fix_key auto-route false
fix_key strict-route false
fix_key stack "gvisor #system/minxd"
fix_key gso false
fix_key mtu 1500
fix_key auto-detect-interface false

if cmp -s "$CFG" "$CFG.fixbak"; then
  echo "  tun 段已合规，无需修改"
else
  echo "  tun 段已自动修复（旧值见 $CFG.fixbak）："
  sed -n '/^tun:/,/^dns:/p' "$CFG"
fi
rm -f "$CFG.fixbak"
exit 0
