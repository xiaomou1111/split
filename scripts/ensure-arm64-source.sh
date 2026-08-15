#!/bin/bash
# ensure-arm64-source.sh — 幂等修复 Ubuntu apt 源的 arm64 multiarch 支持
#
# 背景（WSL2/Ubuntu 24.04 实测踩坑）：
#   Ubuntu 的 archive.ubuntu.com / security.ubuntu.com 只发布 amd64/i386，
#   不发布 binary-arm64（arm64 包只在 ports.ubuntu.com/ubuntu-ports 发布）。
#   若 apt 源没按架构拆分，`dpkg --add-architecture arm64` 后 `apt-get update`
#   会对这两个源请求 arm64 包 → HTTP 404，update 直接失败，`make prepare` 挂掉。
# 本脚本把 native 源显式限为 amd64，并追加 ports.ubuntu.com 的 arm64 源（幂等，可重复执行）。
# Debian 自动跳过（deb.debian.org 全架构同源，无此问题）。
#
# 用法: sudo ./scripts/ensure-arm64-source.sh          # 修 /etc/apt/sources.list.d/ubuntu.sources
#       sudo ./scripts/ensure-arm64-source.sh <文件>   # 指定 deb822 源文件（测试用）
# 修完后需自行 `apt-get update`（make prepare 已接好）。
set -euo pipefail

DEB822="${1:-/etc/apt/sources.list.d/ubuntu.sources}"
LEGACY="/etc/apt/sources.list"

[ "$(id -u)" -eq 0 ] || { echo "错误: 需要 root（sudo ./scripts/ensure-arm64-source.sh）"; exit 1; }

# Debian 无需修复（deb.debian.org 全架构同源）
if grep -qi '^ID=debian' /etc/os-release; then
    echo "skip: Debian 的 deb.debian.org 全架构同源，无需 arm64 源修复"; exit 0
fi

codename_of() {
    local c
    c="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    [ -n "$c" ] || c="$(sed -n 's/^VERSION=.*(\(.*\))/\1/p' /etc/os-release)"
    [ -n "$c" ] || c="$(lsb_release -cs 2>/dev/null || true)"
    printf '%s' "$c"
}

fix_deb822() {
    local f="$1" codename
    codename="$(codename_of)"
    if grep -q 'ports\.ubuntu\.com' "$f"; then
        echo "ok: $f 已含 ports.ubuntu.com arm64 源"; return
    fi
    if ! grep -q 'archive\.ubuntu\.com' "$f"; then
        echo "skip: $f 未引用 archive.ubuntu.com（非 Ubuntu 源），不动"; return
    fi
    echo "== 修复 $f: native 源追加 Architectures: amd64 + 追加 ports arm64（$codename）=="
    cp "$f" "$f.bak.$(date +%s)"
    # 给 native 源（archive/security.ubuntu.com）的 stanza 若无 Architectures 则补 amd64
    awk '
        BEGIN { in_block = 0; native = 0; has_arch = 0 }
        {
            if ($0 ~ /^[[:space:]]*$/) {
                if (in_block && native && !has_arch) print "Architectures: amd64"
                print ""
                in_block = 0; native = 0; has_arch = 0
                next
            }
            in_block = 1
            if ($0 ~ /^URIs:.*(archive|security)\.ubuntu\.com/) native = 1
            if ($0 ~ /^Architectures:/) has_arch = 1
            print
        }
        END { if (in_block && native && !has_arch) print "Architectures: amd64" }
    ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    cat >> "$f" <<EOF

# arm64 multiarch（ports 源：archive/security.ubuntu.com 不发布 binary-arm64）
Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports/
Suites: ${codename} ${codename}-updates ${codename}-backports
Components: main universe restricted multiverse
Architectures: arm64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://ports.ubuntu.com/ubuntu-ports/
Suites: ${codename}-security
Components: main universe restricted multiverse
Architectures: arm64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
    echo "ok: 已追加 ports.ubuntu.com arm64 源（$codename），请 apt-get update"
}

fix_legacy() {
    local f="$1" codename
    codename="$(codename_of)"
    if grep -q 'ports\.ubuntu\.com' "$f"; then
        echo "ok: $f 已含 ports.ubuntu.com arm64 源"; return
    fi
    if ! grep -q '^deb .*archive\.ubuntu\.com' "$f"; then
        echo "skip: $f 无 native Ubuntu 行（非 Ubuntu 源），不动"; return
    fi
    echo "== 修复 $f: native 行加 [arch=amd64] + 追加 ports arm64（$codename）=="
    cp "$f" "$f.bak.$(date +%s)"
    # https 变体（archive.ubuntu.com 常见 https 镜像）同样要 pin——此前只匹配
    # http://，https 官方源会漏加 [arch=amd64]，追加 arm64 架构后 update 照样 404。
    sed -i -E 's|^deb (https?://(archive|security)\.ubuntu\.com)|deb [arch=amd64] \1|' "$f"
    cat >> "$f" <<EOF

# arm64 multiarch（ports 源：archive/security.ubuntu.com 不发布 binary-arm64）
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${codename} main universe restricted multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${codename}-updates main universe restricted multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${codename}-security main universe restricted multiverse
EOF
    echo "ok: 已追加 ports.ubuntu.com arm64 源（$codename），请 apt-get update"
}

if [ -f "$DEB822" ]; then
    fix_deb822 "$DEB822"
elif [ -f "$LEGACY" ]; then
    fix_legacy "$LEGACY"
else
    echo "skip: 未找到 apt 源配置文件（$DEB822 / $LEGACY）"; exit 0
fi
