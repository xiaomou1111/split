#!/system/bin/sh
# post-fs-data.sh — 早启动阶段：挂载 bpffs
# （eBPF map pin / prog load 一般不需要 bpffs，但保持标准做法）

MODDIR=${0%/*}
INSTALL_DIR=/data/adb/split

# bpffs（Magisk 内核通常自带 /sys/fs/bpf）
if [ ! -d /sys/fs/bpf ]; then
  mkdir -p /sys/fs/bpf 2>/dev/null
fi
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null
fi

exit 0