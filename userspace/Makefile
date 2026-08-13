# userspace/Makefile — 用户态构建
#
# 目标：splitd（守护进程） + splitctl（CLI）
# 依赖：libbpf（>=1.0）
#   - 原生构建：make prepare（或 apt install libbpf-dev libelf-dev zlib1g-dev \
#               libzstd-dev liblzma-dev libbz2-dev）
#   - arm64 交叉：scripts/build_arm64.sh（本 Makefile 的 OUTDIR/CC/CFLAGS/LDFLAGS 覆盖）
#
# 链接库集合 LIBS 是唯一真源：scripts/build_arm64.sh 通过 `make print-libs` 读取，
# 交叉编译只追加 -static 与 -L 路径，保证两处库清单永远一致。
#
# 逐对象增量编译（v1.1.0 重构）：每个源文件编成 $(OUTDIR)/obj/ 下的 .o，
# -MMD/-MP 生成 .d 头依赖，改头文件/单文件只重编相关对象（可 -j 并行）。
# 产物路径不变：$(OUTDIR)/{splitd,splitctl}，交叉/原生同一套规则。

CC      ?= gcc
OUTDIR  ?= build
OBJDIR   = $(OUTDIR)/obj
CFLAGS  ?= -O2 -g -Wall -Wextra -Werror
# override: build_arm64.sh 从命令行传 CFLAGS 时也会生效（普通 += 对命令行变量无效）
override CFLAGS += -I../kernel/include -MMD -MP

LIBS     ?= -lbpf -lelf -lz -lzstd -llzma -lbz2
LDFLAGS  ?= $(LIBS)

COMMON  := common/log.c common/config.c common/netlink.c common/paths.c
LOADER  := loader/loader.c loader/iface.c
CNI     := cni/cnip.c
RULE    := rule/rule.c
DAEMON  := daemon/daemon.c
CLI     := cli/splitctl.c

SRCS     := $(COMMON) $(LOADER) $(CNI) $(RULE)
OBJS     := $(addprefix $(OBJDIR)/,$(SRCS:.c=.o))
DAEMON_O  = $(OBJDIR)/$(DAEMON:.c=.o)
CLI_O     = $(OBJDIR)/$(CLI:.c=.o)
DEPS     := $(OBJS:.o=.d) $(DAEMON_O:.o=.d) $(CLI_O:.o=.d)

all: $(OUTDIR)/splitd $(OUTDIR)/splitctl

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OUTDIR)/splitd: $(OBJS) $(DAEMON_O) | $(OUTDIR)/
	$(CC) $(OBJS) $(DAEMON_O) -o $@ $(LDFLAGS)

$(OUTDIR)/splitctl: $(OBJS) $(CLI_O) | $(OUTDIR)/
	$(CC) $(OBJS) $(CLI_O) -o $@ $(LDFLAGS)

$(OUTDIR)/:
	mkdir -p $(OUTDIR)

# 输出链接库清单，供 scripts/build_arm64.sh 使用（勿在脚本里复制清单）
print-libs:
	@echo $(LIBS)

info:
	@echo "OUTDIR=$(OUTDIR) OBJDIR=$(OBJDIR) CC=$(CC)"
	@echo "CFLAGS=$(CFLAGS)"
	@echo "LIBS=$(LIBS) LDFLAGS=$(LDFLAGS)"

clean:
	rm -rf $(OUTDIR)

-include $(DEPS)

.PHONY: all clean print-libs info
