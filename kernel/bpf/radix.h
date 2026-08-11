/* SPDX-License-Identifier: GPL-2.0
 * radix.h — LPM_TRIE 最长前缀匹配封装
 *
 * 职责：对 v4/v6 地址查询指定的 LPM_TRIE map（CNIP / 规则段统一复用）。
 * 用法：
 *   if (radix_match4(&map_cnip4, ip_be32))  → 命中 CNIP4
 *   if (radix_match6(&map_cnip6, ip6_ptr))  → 命中 CNIP6
 * 实现：key 的 prefixlen 传 32/128（查最具体），LPM 内核自动做最长前缀回溯，
 *       因此提前把常见更短前缀（如 10.0.0.0/8）放入 map 即可命中。
 */
#ifndef __SPLIT_BPF_RADIX_H_
#define __SPLIT_BPF_RADIX_H_

#include <bpf/bpf_helpers.h>
#include "split_bpf.h"

/*
 * @map_ptr  : 指向目标 map 的指针（类型：struct {...} *，libbpf 风格）
 * @be32     : 目标 IPv4（网络字节序，__be32）
 */
#define radix_match4(map_ptr, be32)                                    \
    ({                                                                 \
        struct lpm_key4 _k = { .prefixlen = 32 };                      \
        __builtin_memcpy(_k.addr, &(be32), 4);                         \
        bpf_map_lookup_elem((map_ptr), &_k) != NULL;                   \
    })

/*
 * @ip6_ptr  : 指向 16 字节 IPv6 地址（网络字节序）
 */
#define radix_match6(map_ptr, ip6_ptr)                                 \
    ({                                                                 \
        struct lpm_key6 _k = { .prefixlen = 128 };                     \
        __builtin_memcpy(_k.addr, (ip6_ptr), 16);                      \
        bpf_map_lookup_elem((map_ptr), &_k) != NULL;                   \
    })

#endif /* __SPLIT_BPF_RADIX_H_ */