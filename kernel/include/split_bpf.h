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

/* ---- 解析后的报文元数据 ---- */
struct split_pkt {
    __u16 family;
    __u8  proto;                  /* IPPROTO_TCP / IPPROTO_UDP / ... */
    __be16 dport;
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
    __u8  dom_enabled;      /* map_dom_* 任一非空=1（热路径：空则跳过域名整段） */
    __u8  reserved[3];
};

/* ---- 域名分流（v1.1.0）----
 * 背景：TC egress 的 eBPF 看不到域名，域名分流分两段：
 *   用户态（splitd）用 AF_PACKET 抓 UDP 53 响应 → 解析 → 把 IP→域名 写进
 *   map_dns4/6（HASH）；内核 egress 时查"连接的 dst IP 属于哪个域名"，再在
 *   map_dom_proxy/direct（LPM_TRIE）里做域名后缀匹配。
 *
 * 字节序硬契约（用户态 loader.c / dns.c 必须与这里字节级一致）：
 *   - 域名一律**小写**；
 *   - 为把"后缀匹配"变成 LPM 前缀匹配，域名按字节**反转**后存储：
 *     "example.com" → "moc.elpmaxe"。规则 "com"（反转 "moc"）因此天然是
 *     "www.example.com"（反转 "moc.elpmaxe.www"）的字节前缀。
 */
#define SPLIT_DOM_MAX 64      /* 单域名最大字节数（反转后存 dns_entry.name） */

/* map_dns4/6 的 value：一条"IP → 域名"学习结果 */
struct dns_entry {
    __u64 expire_ns;            /* 启动时钟（ktime/CLOCK_BOOTTIME）过期时刻，0=无效 */
    __u8  name_len;             /* 1..SPLIT_DOM_MAX，反转后字节数 */
    __u8  name[SPLIT_DOM_MAX];  /* 反转 + 小写，不带头点 */
};

/* map_dom_proxy/direct 的 key：LPM_TRIE，反转域名按字节前缀匹配 */
struct dom_key {
    __u32 prefixlen;          /* bits，= 反转字节数 * 8 */
    __u8  data[SPLIT_DOM_MAX];
};

/* map_dom_proxy/direct 的 value：规则长度（字节）。
 * 必须自己记录长度——LPM_TRIE 的 lookup 不返回命中前缀长度，
 * 内核靠它做"下一字节必须是 '.'"的标签边界检查。 */
struct dom_rule {
    __u8 len;                 /* 1..SPLIT_DOM_MAX */
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
    STAT_DOM_PROXY    = 9,  /* 域名规则命中 → 代理 */
    STAT_DOM_DIRECT   = 10, /* 域名规则命中 → 直连 */
    STAT_DIRECT_V6    = 11, /* v6 且 ipv6_classify=false → 直连（配置性直连，与 CNIP 直连分开计，policy.h 第 2 步） */
    STAT_MAX          = 16,
};

#ifndef __KERNEL__
/* 仅 userspace 使用的宏（编译 bpf 时不可见） */
#define SPLIT_VERSION "1.3.1"
#define SPLIT_PIN_NS "/sys/fs/bpf/split"
#define SPLIT_SOCKET "/run/splitd.sock"
#define SPLIT_LOG "/var/log/splitd.log"
#endif

#endif /* __SPLIT_BPF_H_ */