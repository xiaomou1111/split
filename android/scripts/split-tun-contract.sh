#!/system/bin/sh
# split-tun-contract.sh — 读取 split.yaml 的 Android TUN 设备真源
#
# 用法: split-tun-contract.sh [split.yaml]
# 输出: 目标接口名（缺省 utun）
# 返回: 0=成功；1=配置缺失/字段非法

CFG="${1:-/data/adb/split/config/split.yaml}"

[ -f "$CFG" ] || {
  echo "TUN 配置不存在: $CFG" >&2
  exit 1
}

value=$(awk '
  function trim(s) {
    gsub(/^[[:space:]]+/, "", s)
    gsub(/[[:space:]]+$/, "", s)
    return s
  }
  BEGIN { found = 0 }
  {
    line = $0
    sub(/\r$/, "", line)
    # 只读取顶层 tun_device；缩进字段属于其它 YAML 节，不能误中。
    if (!found && line ~ /^[A-Za-z0-9_.-]+:[[:space:]]*/) {
      key = line
      sub(/:.*/, "", key)
      if (key == "tun_device") {
        val = line
        sub(/^[^:]*:[[:space:]]*/, "", val)
        sub(/[[:space:]]+#.*$/, "", val)
        print trim(val)
        found = 1
        exit
      }
    }
  }
  END { if (!found) print "__SPLIT_TUN_DEFAULT__" }
' "$CFG" 2>/dev/null)

[ -n "$value" ] || {
  echo "tun_device 为空: $CFG" >&2
  exit 1
}

if [ "$value" = "__SPLIT_TUN_DEFAULT__" ]; then
  value=utun
fi

# 兼容常见的 YAML 单值引号；接口名本身不允许空白、路径分隔符或 shell 特殊字符。
value=$(printf '%s' "$value" | sed -e 's/^"//;s/"$//' -e "s/^'//;s/'$//")
case "$value" in
  ''|*[!A-Za-z0-9_.-]*)
    echo "tun_device 非法（仅允许接口名）: $value" >&2
    exit 1
    ;;
esac
if [ "${#value}" -gt 15 ]; then
  echo "tun_device 过长（Linux 接口名最多 15 字符）: $value" >&2
  exit 1
fi

printf '%s\n' "$value"
exit 0
