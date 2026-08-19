#!/system/bin/sh
# fix-mihomo-tun.sh — 校验/修复 mihomo tun 段，对齐 eBPF-Split 契约（幂等）
#
# 用法: fix-mihomo-tun.sh [config.yaml] [tun_device]
#   缺省配置 /data/adb/split/mihomo/config.yaml，缺省设备 utun
#   返回: 0=合规或已修复；1=文件缺失/无 tun 段（可跳过）；2=发现 tun 段但修复失败

CFG="${1:-/data/adb/split/mihomo/config.yaml}"
TUN_DEVICE="${2:-utun}"

[ -f "$CFG" ] || exit 1
grep -q '^tun:' "$CFG" || exit 1

case "$TUN_DEVICE" in
  ''|*[!A-Za-z0-9_.-]*)
    echo "== fix-mihomo-tun: 非法 TUN 设备名 $TUN_DEVICE ==" >&2
    exit 2
    ;;
esac

# 硬契约：这些字段只允许出现在 tun 段，避免 dns/其它顶层块存在同名键时被误改。
# awk 同时完成规范化、去重和缺项补齐；临时文件与原文件同目录，mv 在同一文件系统内原子替换。
tmp="$CFG.fix.$$"
bak="$CFG.fixbak"
rm -f "$tmp" "$bak"
cp "$CFG" "$bak" 2>/dev/null || {
  echo "无法备份 mihomo 配置: $CFG" >&2
  exit 2
}

if ! awk -v tun_device="$TUN_DEVICE" \
         -v v_enable="true" \
         -v v_auto_route="false" \
         -v v_strict_route="false" \
         -v v_stack="gvisor #system/minxd" \
         -v v_gso="false" \
         -v v_mtu="1500" \
         -v v_auto_detect="false" '
  BEGIN {
    n = split("enable device auto-route strict-route stack gso mtu auto-detect-interface", keys, " ")
    in_tun = 0
    cr = ""
  }
  function emit(s) { printf "%s%s\n", s, cr }
  function value_for(k) {
    if (k == "enable") return v_enable
    if (k == "device") return tun_device
    if (k == "auto-route") return v_auto_route
    if (k == "strict-route") return v_strict_route
    if (k == "stack") return v_stack
    if (k == "gso") return v_gso
    if (k == "mtu") return v_mtu
    if (k == "auto-detect-interface") return v_auto_detect
    return ""
  }
  function is_target(k, i) {
    for (i = 1; i <= n; i++) if (keys[i] == k) return 1
    return 0
  }
  function flush_missing(i) {
    if (!in_tun) return
    for (i = 1; i <= n; i++)
      if (!seen[keys[i]]) emit("  " keys[i] ": " value_for(keys[i]))
    in_tun = 0
  }
  {
    line = $0
    if (line ~ /\r$/) { sub(/\r$/, "", line); cr = "\r" }

    # 下一个无缩进 key 结束 tun 块；注释、空行和嵌套子项不会结束它。
    if (in_tun && line ~ /^[A-Za-z0-9_.-]+:[[:space:]]*/) flush_missing()

    if (line ~ /^tun:[[:space:]]*($|#)/) {
      in_tun = 1
      delete seen
      emit(line)
      next
    }

    # 只处理恰好两个空格的直接子项；四空格嵌套项保持原样。
    if (in_tun && line ~ /^  [A-Za-z0-9_.-]+:[[:space:]]*/) {
      child = line
      sub(/^  /, "", child)
      key = child
      sub(/:.*/, "", key)
      if (is_target(key)) {
        if (!seen[key]) {
          emit("  " key ": " value_for(key))
          seen[key] = 1
        }
        next
      }
    }
    emit(line)
  }
  END { flush_missing() }
' "$CFG" > "$tmp"; then
  echo "修复 mihomo tun 段失败，原配置保留: $CFG" >&2
  rm -f "$tmp"
  exit 2
fi

if ! mv -f "$tmp" "$CFG"; then
  echo "无法原子写回 mihomo 配置，备份保留: $bak" >&2
  rm -f "$tmp"
  exit 2
fi

if cmp -s "$CFG" "$bak"; then
  echo "== fix-mihomo-tun: tun 段已合规，无需修改 =="
else
  echo "== fix-mihomo-tun: tun 段已修复（备份: $bak）=="
  awk '
    /^tun:[[:space:]]*($|#)/ { p=1 }
    p && /^[A-Za-z0-9_.-]+:[[:space:]]*/ && $0 !~ /^tun:/ { exit }
    p { print }
  ' "$CFG"
fi
rm -f "$bak"
exit 0
