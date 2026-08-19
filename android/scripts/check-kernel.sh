#!/system/bin/sh
# check-kernel.sh — 安卓内核 eBPF 能力自检
#
# 用法: adb shell su -c sh check-kernel.sh
# 说明：shell 里无法直接调 bpf() 系统调用，这里用"配置快照 + 特征文件"
#       组合探测，并给出人工验证指引（真伪见 dmesg）。
# 返回：0=基本可用 1=基本不可用（脚本主要面向人类阅读）

ok=1
echo "== eBPF-Split 内核自检 =="
echo "内核版本: $(uname -r)"
echo "架构: $(uname -m)"

# 1) 特征文件/目录
[ -d /sys/fs/bpf ] && echo "  [OK] /sys/fs/bpf 存在" || echo "  [..] /sys/fs/bpf 缺失（可手动 mount -t bpf）"

# 2) 配置快照（部分厂商有）
if [ -f /proc/config.gz ]; then
  echo "-- 内核配置 --"
  for c in CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_BPF_JIT \
           CONFIG_NET_CLS_BPF CONFIG_NET_CLS_ACT CONFIG_NET_SCH_INGRESS \
           CONFIG_TUN CONFIG_DEBUG_INFO_BTF; do
    v=$(zcat /proc/config.gz 2>/dev/null | grep "^$c=")
    echo "  ${v:-$c=?(厂商裁剪)}"
    # v1.2.7（审查 L1）：把静态检查结果接入退出码（此前 ok 变量是死代码）。
    # 硬依赖缺失即 ok=0；CONFIG_DEBUG_INFO_BTF 缺失不致命（本项目不用 CO-RE）。
    case "$c" in
      CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_NET_CLS_BPF|CONFIG_TUN)
        [ "$v" = "$c=y" ] || [ "$v" = "$c=m" ] || ok=0 ;;
      CONFIG_NET_CLS_ACT|CONFIG_NET_SCH_INGRESS)
        [ "$v" = "$c=y" ] || [ "$v" = "$c=m" ] || ok=0 ;;
      *) : ;;
    esac
  done
else
  echo "-- 无 /proc/config.gz（常见），跳过静态检查 --"
fi

# 3) tun
if [ -e /dev/net/tun ]; then
  echo "  [OK] /dev/net/tun 存在"
else
  echo "  [NO] /dev/net/tun 缺失 → mihomo TUN 也无法工作"
  ok=0
fi

# 4) 权威验证指引（人工执行）
echo "-- 人工权威验证（需能编译的小工具或如下命令） --"
echo "  1) 直接安装模块后看 /data/adb/split/logs/splitd.log 是否出现 BPF 加载成功"
echo "  2) 失败时: adb shell su -c 'dmesg | grep -i bpf | tail' "
echo "            adb shell su -c 'dmesg | grep avc | tail'   # SELinux 拦截"

echo "== 结论 =="
if [ "$ok" -eq 1 ]; then
  echo "  基本可用；eBPF 可行性请按第 4 步实测。当前模块在 eBPF 失败时保持 auto-route:false，不会自动切换为纯 TUN 代理。"
else
  echo "  存在缺失项（见上），先解决后再用。"
fi
exit "$ok"