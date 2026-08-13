/* SPDX-License-Identifier: GPL-2.0
 * maps.h — 所有 BPF map 的单一真相源
 *
 * 规则：
 *   1. 新 map 必须加在 "全局 MAP 清单" 区内，不要散落各处。
 *   2. 改类型/容量/大小 → 同步修改 userspace/loader/loader.c 的 map 期望表。
 *   3. 名称保持稳定（split_ 前缀），用户态通过名字访问。
 */
#ifndef __SPLIT_BPF_MAPS_H_
#define __SPLIT_BPF_MAPS_H_

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "split_bpf.h"

/* ============ 全局 MAP 清单 ============ */

/* 1. CNIP（中国段）—— 内核分流主数据 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_cnip4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_cnip6 SEC(".maps");

/* 2. 强制规则（优先级高于 CNIP） */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __type(key, struct lpm_key4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_rule_proxy4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __type(key, struct lpm_key6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_rule_proxy6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __type(key, struct lpm_key4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_rule_direct4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 8192);
    __type(key, struct lpm_key6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_rule_direct6 SEC(".maps");

/* 3. UID 白名单（mihomo/root/shell 等直连，防回环） */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} map_skip_uid SEC(".maps");

/* 4. 代理 TUN 设备 ifindex */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} map_tun SEC(".maps");

/* 5. 运行时配置 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct split_cfg);
} map_cfg SEC(".maps");

/* 5.2 RAWIP 接口集合（v1.1.5）
 * key=ifindex value=__u8(=1)。用户态在挂载/网络事件时同步：
 * 接口类型 ARPHRD_RAWIP(519)（Android 蜂窝 rmnet_data*，无以太网头，
 * tc egress 的 skb->data 直接是 IP 头）→ 写入；
 * 其它类型（wlan0/eth0 等 Ethernet）→ 不写（查不到=有 L2 头）。
 * parse.h 据此选择"无 L2 头解析路径"，避免把 IP 头前 2 字节误当
 * ethertype（蜂窝流量 parse_err 暴涨、海外无法进代理，v1.1.5 真机修复）。 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} map_rawip SEC(".maps");

static __always_inline int rawip_lookup(__u32 ifindex)
{
    __u8 *v = bpf_map_lookup_elem(&map_rawip, &ifindex);

    return v ? 1 : 0;
}

/* 6. 观测：per-cpu 计数器 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} map_stats SEC(".maps");

/* ============ 便捷封装 ============ */

/* STAT_MAX 必须是 2 的幂（stats_inc 用 key & (STAT_MAX-1) 防越界） */
_Static_assert((STAT_MAX & (STAT_MAX - 1)) == 0, "STAT_MAX must be power of 2");

static __always_inline void stats_inc(__u32 key)
{
    __u32 k = key & (STAT_MAX - 1);
    __u64 *v;

    v = bpf_map_lookup_elem(&map_stats, &k);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline __u32 tun_ifindex(void)
{
    __u32 zero = 0;
    __u32 *idx = bpf_map_lookup_elem(&map_tun, &zero);

    return idx ? *idx : 0;
}

static __always_inline const struct split_cfg *get_cfg(void)
{
    __u32 zero = 0;

    return bpf_map_lookup_elem(&map_cfg, &zero);
}

#endif /* __SPLIT_BPF_MAPS_H_ */