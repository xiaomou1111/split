/* SPDX-License-Identifier: GPL-2.0
 * split_bpf.h — 内核侧全局类型/常量/verdict（L0 唯一共享头）
 *
 * 本文件同时被 kernel/bpf/\*.h 与文档引用；修改要连 docs/02-MODULES.md 一起。
 */
#ifndef __SPLIT_BPF_H_
#define __SPLIT_BPF_H_

#include <linux/types.h>

/* ---- verdict ---- */
enum split_verdict {
    SPLIT_VERDICT_PASS  = 0, /* 直连：放行（TC 语义=不处理） */
    SPLIT_VERDICT_TUN   = 1, /* 代理：redirect 到 tun0 */
};

/* ---- family ---- */
enum split_family {
    SPLIT_FAMILY_IPV4 = 0,
    SPLIT_FAMILY_IPV6 = 1,
    SPLIT_FAMILY_OTHER = 2,
};

/* ---- LPM trie key（prefix = 前缀长度位数） ---- */
struct lpm_key4 {
    __u32 prefixlen;   /* 0..32 */
    __u8  addr[4];
};
struct lpm_key6 {
    __u32 prefixlen;   /* 0..128 */
    __u8  addr[16];
};

/* ---- 解析后的报文元数据 ----
 * v1.4.0（性能审查）：proto/dport 不再填充——policy 纯 L3/UID 判定，只消费 family+dst
 * （L4 解析是无消费者的热路径死代码，已随 v1.4.0 从 parse.h 删除）。字段保留（ABI 稳定），
 * 勿假定其含有效值。 */
struct split_pkt {
    __u16 family;
    __u8  proto;                  /* 保留：不再填充（L4 解析已删） */
    __be16 dport;                 /* 保留：不再填充（L4 解析已删） */
    union {
        __be32 ip4;
        __u8   ip6[16];
    } dst;
};

/* ---- 运行时配置（map_cfg value） ---- */
struct split_cfg {
    __u8  default_verdict;  /* split_verdict，默认 TUN */
    __u8  bpf_trace_enabled;/* v1.3.1 起兼作"已初始化"哨兵：loader map_set_cfg 置 1；
                             * 0 = map_cfg 尚未写入（ARRAY map lookup 永不 NULL，未写入
                             * 返回全零元素）→ policy.h 回落 TUN 安全默认（勿依赖 0 语义） */
    __u8  ipv6_classify;    /* 0/1 */
    __u8  skip_uid_enabled; /* map_skip_uid 非空=1（热路径：空则跳过 get_socket_uid+查表） */
    __u8  reserved[3];
};

/* ---- stats key 常量 ---- */
enum split_stats_key {
    STAT_TOTAL        = 0,
    STAT_DIRECT_CN    = 1,
    STAT_DIRECT_RULE  = 2,  /* 命中 direct 规则 */
    STAT_PROXY        = 3,  /* 命中 proxy 规则 / 默认 */
    STAT_SKIP_UID     = 4,
    STAT_PARSE_ERR    = 5,
    STAT_REDIRECT_ERR = 6,
    STAT_DROPPED      = 7,  /* 保留位：本项目"绝不丢包"，无 drop 路径，恒 0（勿删——序号被 daemon names 数组引用） */
    STAT_MISS_TUN     = 8,  /* 想代理但没有 tun ifindex */
    STAT_DIRECT_V6    = 9,  /* v6 且 ipv6_classify=false → 直连（配置性直连，与 CNIP 直连分开计，policy.h 第 2 步） */
    STAT_MAX          = 16,
};

#ifndef __KERNEL__
/* 仅 userspace 使用的宏（编译 bpf 时不可见） */
#define SPLIT_VERSION "1.4.7"
#define SPLIT_PIN_NS "/sys/fs/bpf/split"
#define SPLIT_SOCKET "/run/splitd.sock"
#define SPLIT_LOG "/var/log/splitd.log"
#endif

#endif /* __SPLIT_BPF_H_ */