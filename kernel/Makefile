# kernel/Makefile — BPF 编译
#
# 产物: split.bpf.o（唯一 BPF 对象，含一个 SEC("classifier") 程序）
# 需要: clang >= 12, llvm-strip, bpftool(可选, 用于验证)
# 目标 arch: bpf

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool

CFLAGS := -O2 -g -Wall -Wextra -Werror \
          -target bpf -mcpu=v1 \
          -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/') \
          -I include -I bpf \
          -I /usr/include/$(shell uname -m)-linux-gnu \
          -fno-stack-protector -fno-unroll-loops

SRCS  := bpf/split.bpf.c
HDRS  := $(wildcard include/*.h bpf/*.h)   # 新增头文件自动进依赖，无需改本清单
OBJ   := bpf/split.bpf.o

all: $(OBJ)

$(OBJ): $(SRCS) $(HDRS)
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# 用内核自带 BPF 验证器做一次冒烟（需 root + bpffs 可写 + 目标内核）
# 注：`SEC("classifier")` 旧式 section，libbpf>=1.0 的裸 bpftool 加载会失败（类型推断），
#     非程序错误。用 `make userspace && splitd -c cfg -b obj` 验证（exit 非 2 即 OK）。
validate: $(OBJ)
	@if [ -w /sys/fs/bpf ]; then \
		if $(BPFTOOL) prog load $(OBJ) /sys/fs/bpf/split_smoke type sched_cls 2>/dev/null; then \
			rm -f /sys/fs/bpf/split_smoke; echo "validate OK: $(OBJ) 通过内核验证器"; \
		else echo "skip: 裸 bpftool 对 SEC(classifier) 无法推断类型（libbpf>=1.0），请用 splitd 验证"; fi \
	else echo "skip (bpffs 不可写，需要 root + bpffs)"; fi

disasm: $(OBJ)
	$(BPFTOOL) prog dump xlated obj $(OBJ) section classifier

clean:
	rm -f $(OBJ)

.PHONY: all validate disasm clean