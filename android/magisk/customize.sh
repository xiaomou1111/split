#!/system/bin/sh
# customize.sh — Magisk 模块安装阶段
# 作用：把模块内容铺到 /data/adb/split/ 的分层目录（重启后 service.sh 使用）
#
# 运行时结构：
#   /data/adb/split/
#     bin/      二进制 + BPF 对象
#     config/   配置（split.yaml / cnip 数据）
#     scripts/  辅助脚本
#     logs/     运行日志
#     run/      运行时 socket
#     mihomo/   mihomo 配置目录（box 复制）

SKIPUNZIP=0

ui_print "- installing eBPF-Split..."

# Magisk 应用内安装时 BOOTMODE=true；KernelSU/APatch 可能不导出该变量，
# 不因此中止（真正无法写 /data 时下面 mkdir 会失败兜底）。
if [ "$BOOTMODE" != "true" ]; then
  ui_print "- 未在应用内安装（BOOTMODE!=true），尝试继续（需 root）"
fi

INSTALL_DIR=/data/adb/split
mkdir -p "$INSTALL_DIR" 2>/dev/null || {
  ui_print "创建 $INSTALL_DIR 失败（无 root？）"
  abort
}

# 二进制（构建期由 gen-magisk.sh 填进去）
mkdir -p "$INSTALL_DIR/bin"
if [ -f "$MODPATH/bin/splitd" ]; then
  cp "$MODPATH/bin/splitd" "$INSTALL_DIR/bin/splitd"
  chmod 0755 "$INSTALL_DIR/bin/splitd"
  cp "$MODPATH/bin/splitctl" "$INSTALL_DIR/bin/splitctl"
  chmod 0755 "$INSTALL_DIR/bin/splitctl"
fi
if [ -f "$MODPATH/bin/split.bpf.o" ]; then
  cp "$MODPATH/bin/split.bpf.o" "$INSTALL_DIR/bin/split.bpf.o"
fi

# 配置（含默认值 + 用户可改）
mkdir -p "$INSTALL_DIR/config"
# 升级保护（审查修复，2026-08 全库审查批次）：只在首次安装铺默认 split.yaml。
# 旧实现无条件 cp，模块每次升级都会用打包默认值覆盖用户改过的自定义规则
# （P0：静默丢用户配置）。口径与下方 mihomo config 的 [ ! -f ] 保护一致。
if [ ! -f "$INSTALL_DIR/config/split.yaml" ]; then
  cp "$MODPATH/config/split.yaml" "$INSTALL_DIR/config/split.yaml" 2>/dev/null || true
fi

# 辅助脚本（start/stop/check-kernel/setup-box-tun）
if [ -d "$MODPATH/scripts" ]; then
  mkdir -p "$INSTALL_DIR/scripts"
  cp "$MODPATH/scripts/"*.sh "$INSTALL_DIR/scripts/" 2>/dev/null
  chmod 0755 "$INSTALL_DIR/scripts/"*.sh 2>/dev/null
fi

# 日志/运行目录（避免运行时散落根级）
mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/run"
# v1.4.8：升级清 mihomo 版本缓存——webuiapi.sh 以 run/mihomo.version 存在为有效
# （"模块重装会重建 run/"只对全新安装成立），升级不重建 run/ 会显示旧 mihomo 版本。
# 下次 WebUI 轮询自动重探（mihomo -v 冷启动 ~百 ms，可忽略）。
rm -f "$INSTALL_DIR/run/mihomo.version"

# mihomo（可选，若随包携带）
# 注意：mihomo 放运行目录 bin/（不放 modules），因为：
#   1) modules 目录受 Magisk overlay 管理，升级/卸载会丢配置
#   2) 非 root 进程读 modules 目录受限（SELinux/mode）
#   3) box 也是把 mihomo 放 /data/adb/box/bin/（运行目录）
if [ -f "$MODPATH/bin/mihomo" ]; then
  cp "$MODPATH/bin/mihomo" "$INSTALL_DIR/bin/mihomo"
  chmod 0755 "$INSTALL_DIR/bin/mihomo"
  mkdir -p "$INSTALL_DIR/mihomo"   # mihomo 配置目录（service.sh -d 指向这里）
  # 若随包脱敏配置，安装时铺入（用户之后填自己的订阅 token）
  if [ -f "$MODPATH/mihomo/config.yaml" ] && [ ! -f "$INSTALL_DIR/mihomo/config.yaml" ]; then
    cp "$MODPATH/mihomo/config.yaml" "$INSTALL_DIR/mihomo/config.yaml"
    ui_print "- mihomo 配置已装（含脱敏订阅，请编辑填写 YOUR_TOKEN_*）"
  fi
fi

# ---------- 清理模块预留副本 ----------
# 运行期唯一真源是 /data/adb/split/（service.sh/post-fs-data.sh 全读这里）。
# 铺完即删 /data/adb/modules/split/ 里的 bin/config/scripts/mihomo，避免两处重复；
# 模块目录只留 Magisk 强制文件（module.prop/customize.sh/service.sh/.../webroot）。
# 升级时 Magisk 会整包重跑 customize.sh 重新铺入，故删除不丢功能。
rm -rf "$MODPATH/bin" "$MODPATH/config" "$MODPATH/scripts" "$MODPATH/mihomo"

ui_print "- installed to $INSTALL_DIR（运行源唯一：/data/adb/split/）"
ui_print " 模块目录已清理 bin/config/scripts 副本"
ui_print " 重启后由 service.sh 自动启动（KernelSU/APatch 同样适用）"
ui_print " 可先 adb 运行 scripts/check-kernel.sh 探测内核能力"
