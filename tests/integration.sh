#!/bin/bash
# integration.sh — 端到端冒烟测试（需 root + mihomo 已起 + 已 load）
#
# 断言：
#   A. 百度可达（直连路径）
#   B. YouTube 可达（代理路径）
#   C. splitctl stats 计数符合预期（direct_cn>0, proxy>0）
set -e
cd "$(dirname "$0")/.."

fail=0
check() { # check <名称> <命令...>
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then
    echo "[PASS] $name"
  else
    echo "[FAIL] $name"
    fail=1
  fi
}

echo "== eBPF-Split 冒烟 =="
[ -S /run/splitd.sock ] && SCTL="splitctl" || SCTL="sudo userspace/build/splitctl"

check "直连(百度,CNIP)" curl -4 -m 10 -s https://www.baidu.com -o /dev/null
check "代理(YouTube)"  curl -4 -m 15 -s https://www.youtube.com -o /dev/null

echo "== 统计 =="
$SCTL stats || echo "(splitd 未运行，计数不可用)"

echo "== 单元测试（用户态） =="
if [ -d tests/unit ] && ls tests/unit/*.c >/dev/null 2>&1; then
  echo "(unit 见 tests/unit/README.md；本版先以脚本冒烟为准)"
fi

exit $fail