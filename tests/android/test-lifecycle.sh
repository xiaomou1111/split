#!/bin/sh
# test-lifecycle.sh — Android TUN 契约/配置修复脚本的纯 shell fixture
# 在 Linux/WSL2：sh tests/android/test-lifecycle.sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
RESOLVER="$ROOT/android/scripts/split-tun-contract.sh"
FIXER="$ROOT/android/scripts/fix-mihomo-tun.sh"
TMP=${TMPDIR:-/tmp}/split-lifecycle-$$
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP"

fail() { echo "FAIL: $*" >&2; exit 1; }
expect_eq() { [ "$1" = "$2" ] || fail "expected [$2], got [$1]"; }

# 默认、CRLF、行内注释和非法名称。
printf 'debug: false\r\nrules:\r\n  tun_device: ignored\r\n' > "$TMP/default.yaml"
expect_eq "$(sh "$RESOLVER" "$TMP/default.yaml")" utun
printf 'tun_device: split0 # custom interface\n' > "$TMP/custom.yaml"
expect_eq "$(sh "$RESOLVER" "$TMP/custom.yaml")" split0
printf 'tun_device: bad/name\n' > "$TMP/invalid.yaml"
if sh "$RESOLVER" "$TMP/invalid.yaml" >/dev/null 2>&1; then
  fail 'invalid tun_device unexpectedly accepted'
fi

# 同名键出现在其它块时绝不能误改；tun 块全部字段被规范化且幂等。
cat > "$TMP/mihomo.yaml" <<'EOF'
dns:
  enable: false
  device: dns-device
  mtu: 5353
tun:
  enable: false
  device: Meta
  mtu: 9000
  nested:
    device: keep
  gso: true
  gso: true
rules:
  stack: system
  auto-route: true
EOF
sh "$FIXER" "$TMP/mihomo.yaml" split0 >/dev/null
# 其它块保持原值。
grep -A3 '^dns:' "$TMP/mihomo.yaml" | grep -q '^  enable: false$' || fail 'dns.enable changed'
grep -A3 '^dns:' "$TMP/mihomo.yaml" | grep -q '^  device: dns-device$' || fail 'dns.device changed'
grep -A3 '^dns:' "$TMP/mihomo.yaml" | grep -q '^  mtu: 5353$' || fail 'dns.mtu changed'
grep -A2 '^rules:' "$TMP/mihomo.yaml" | grep -q '^  stack: system$' || fail 'rules.stack changed'
# tun 块关键值存在，缺项被补齐。
grep -q '^  enable: true$' "$TMP/mihomo.yaml" || fail 'tun.enable not normalized'
grep -q '^  device: split0$' "$TMP/mihomo.yaml" || fail 'tun.device not normalized'
grep -q '^  auto-route: false$' "$TMP/mihomo.yaml" || fail 'tun.auto-route missing'
grep -q '^  strict-route: false$' "$TMP/mihomo.yaml" || fail 'tun.strict-route missing'
grep -q '^  stack: gvisor #system/minxd$' "$TMP/mihomo.yaml" || fail 'tun.stack missing'
grep -q '^  gso: false$' "$TMP/mihomo.yaml" || fail 'tun.gso not normalized'
grep -q '^  mtu: 1500$' "$TMP/mihomo.yaml" || fail 'tun.mtu not normalized'
grep -q '^  auto-detect-interface: false$' "$TMP/mihomo.yaml" || fail 'tun.auto-detect missing'
[ "$(grep -c '^  gso:' "$TMP/mihomo.yaml")" -eq 1 ] || fail 'duplicate tun.gso not removed'
cp "$TMP/mihomo.yaml" "$TMP/once.yaml"
sh "$FIXER" "$TMP/mihomo.yaml" split0 >/dev/null
cmp -s "$TMP/mihomo.yaml" "$TMP/once.yaml" || fail 'fixer is not idempotent'

printf 'dns:\n  enable: true\n' > "$TMP/no-tun.yaml"
if sh "$FIXER" "$TMP/no-tun.yaml" >/dev/null 2>&1; then
  fail 'missing tun unexpectedly accepted'
else
  rc=$?
  [ "$rc" -eq 1 ] || fail "missing tun expected rc=1, got $rc"
fi

echo 'test-lifecycle: PASS'
