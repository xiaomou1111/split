# 顶层 Makefile — 一键构建
#
#   make help      列出全部目标
#   make prepare   安装全部构建依赖（Debian/Ubuntu，含 arm64 交叉工具链/multiarch）
#   make bpf       编译 BPF 对象 kernel/bpf/split.bpf.o
#   make userspace 编译 splitd + splitctl
#   make all       以上全部
#   make arm64     交叉编译 aarch64（默认 LIBBPF=/root/bpf_deps/libbpf，可覆盖）
#   make install   安装到 /usr/local（含示例配置）
#   make test      编译 + 冒烟
#   make android   编译 + 打包 Magisk 模块
#   make clean

LIBBPF ?= /root/bpf_deps/libbpf

.PHONY: all bpf userspace arm64 install prepare clean test android help

help:
	@echo "目标: help prepare bpf userspace all arm64 install test android clean"
	@echo "  prepare   一键安装依赖（含 arm64 交叉: gcc-aarch64-linux-gnu + multiarch dev 包）"
	@echo "  arm64     ./scripts/build_arm64.sh [libbpf_dir]（默认 /root/bpf_deps/libbpf）"
	@echo "  android   make bpf userspace + ./scripts/gen-magisk.sh"

all: bpf userspace

bpf:
	$(MAKE) -C kernel

userspace:
	$(MAKE) -C userspace

arm64:
	./scripts/build_arm64.sh $(LIBBPF)

prepare:
	./scripts/ensure-arm64-source.sh   # Ubuntu: native 源限 amd64 + 追加 ports arm64（幂等）
	dpkg --add-architecture arm64
	apt-get update
	apt-get install -y clang llvm libbpf-dev libelf-dev \
	    iproute2 curl wget jq ca-certificates file zip \
	    zlib1g-dev libzstd-dev liblzma-dev libbz2-dev \
	    gcc-aarch64-linux-gnu \
	    libelf-dev:arm64 zlib1g-dev:arm64 \
	    libzstd-dev:arm64 liblzma-dev:arm64 libbz2-dev:arm64
	@echo "提示: bpftool（仅 make -C kernel validate/disasm 可选）在 Ubuntu 24.04 无独立候选包，需要时装 linux-tools-common"

install: all
	mkdir -p /etc/split
	install -D -m0755 userspace/build/splitd  /usr/local/bin/splitd
	install -D -m0755 userspace/build/splitctl /usr/local/bin/splitctl
	install -D -m0644 kernel/bpf/split.bpf.o /etc/split/split.bpf.o
	@if [ -f /etc/split/split.yaml ]; then \
		echo "跳过: /etc/split/split.yaml 已存在（保留用户配置，参考 configs/split.yaml.example）"; \
	else \
		install -D -m0644 configs/split.yaml.example /etc/split/split.yaml; \
	fi

test: all
	./tests/integration.sh

android: all
	./scripts/gen-magisk.sh

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C userspace clean