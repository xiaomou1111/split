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
#   enable:true      —— v1.4.8 补充：此前仅 setup-box-tun.sh 内联强制 enable，本脚本漏项，
#                       与 android/MEMORY 的契约清单（含 enable）不符。tun.enable:false /
#                       tun 段无 enable 行（box 原样/恢复备份）时 mihomo 起不来 utun →
#                       service.sh 等 30s 无 utun 整机静默不激活；watchdog restart_mihomo
#                       在 API 又不可达时 5 分钟无限重启循环。watchdog 的 PATCH 恢复本就把
#                       enable 拉回 true，这里统一收敛。注意：enable 是共享键名（dns 等节
#                       也有），不能走 fix_key 的全文件 `^  enable:` 匹配，必须限定 tun 段。
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

# enable:true 段内限域处理（键名共享，不能走 fix_key 的全文件匹配，见上方注释）。
# 探测 awk：tun: 行后到下一个顶格 key 之前为 tun 块（注释/空行/子键不结束块），
# 块内已有 enable 行（任意值）→ 整行改 true；无 → 追加到 tun: 后（手法同 fix_key 的 a 追加）。
# 幂等：enable:true 已存在时探测命中，两个 awk/sed 均不再改动。
if awk '/^tun:/{t=1; next}
         t&&/^[A-Za-z0-9_][A-Za-z0-9_.-]*:/{t=0}
         t&&/^[[:space:]]*enable:/{f=1}
         END{exit f?0:1}' "$CFG"; then
  awk '/^tun:/{t=1; print; next}
       t&&/^[A-Za-z0-9_][A-Za-z0-9_.-]*:/{t=0}
       t&&/^[[:space:]]*enable:/{sub(/^[[:space:]]*enable:.*/, "  enable: true")}
       {print}' "$CFG" > "$CFG.fix.en" && mv "$CFG.fix.en" "$CFG"
else
  sed -i "/^tun:/a\\  enable: true" "$CFG"
fi

if cmp -s "$CFG" "$CFG.fixbak"; then
  echo "  tun 段已合规，无需修改"
else
  echo "  tun 段已自动修复（旧值见 $CFG.fixbak）："
  sed -n '/^tun:/,/^dns:/p' "$CFG"
fi
rm -f "$CFG.fixbak"
exit 0
