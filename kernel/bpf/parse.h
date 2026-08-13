/* SPDX-License-Identifier: GPL-2.0
 * parse.h — 报文解析模块
 *
 * 职责：安全地从 __sk_buff 读出 L3 元数据（family + dst，即 policy 判定的全部输入）。
 * 原则：任何越界/未知一律返回 0（= 不可判，由上层放行），绝不越界读。
 * 支持：IPv4 / IPv6 / VLAN(0x8100,0x88a8) 直至双标签（QinQ）。
 * v1.4.0（性能审查）：删除全部 L4 解析（dport/proto、IPv4 分片检查、IPv6 扩展头链）
 * ——policy 只消费 family+dst（纯 L3/UID 判定），L4 解析是无消费者的热路径死代码。
 * struct split_pkt 的 proto/dport 字段保留（ABI 稳定），不再填充。
 */
#ifndef __SPLIT_BPF_PARSE_H_
#define __SPLIT_BPF_PARSE_H_

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "split_bpf.h"

/* VLAN 内层头（只有两个字段；不定义在其它地方） */
struct vlan_hdr {
    __be16 tci;
    __be16 inner;
};

/* 最多剥几层 VLAN 标签（QinQ 双标签够用；多变长会使 verifier 上界难证） */
#define VLAN_MAX_TAGS 2

/*
 * 解析 skb → split_pkt
 * @return 1=成功 0=失败/不可判（调用方按放行处理）
 */
static __always_inline int parse_skb(struct __sk_buff *skb, struct split_pkt *pkt)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    __be16 ethertype;
    __u32 off;
    int ihl;

    /*
     * v1.1.5：RAWIP 接口（Android 蜂窝 rmnet_data*，ARPHRD_RAWIP=519）的
     * tc egress skb 没有以太网头（dev->hard_header_len=0），data 直接就是
     * IP 头。此前硬按 ethhdr 读 h_proto → 把 IP 头前 2 字节（version/ihl,
     * 0x45xx 等）当 ethertype → 全部 parse 失败放行直连 → 蜂窝海外流量
     * 无法进代理（真机 parse_err 暴涨 1748/2763）。map_rawip 由用户态在
     * 挂载时写入（仅 RAWIP 接口），这里查一次即可安全区分。
     */
    if (rawip_lookup(skb->ifindex)) {
        __u8 first;

        if ((void *)data + 1 > data_end)
            return 0;
        first = *(const __u8 *)data;
        ethertype = (first >> 4) == 4 ? bpf_htons(ETH_P_IP) :
                    (first >> 4) == 6 ? bpf_htons(ETH_P_IPV6) : 0;
        off = 0;
        if (ethertype == 0)
            return 0; /* 非 IPv4/IPv6（如 ARP 裸包）→ 放行不可判 */
    } else {
        if ((void *)data + sizeof(*eth) > data_end)
            return 0;
        eth = data;

        ethertype = eth->h_proto;
        off = sizeof(*eth);

        /* VLAN 标签（0x8100/0x88a8）：最多剥 VLAN_MAX_TAGS 层（下标 `_v` 放
         * 循环外以兼容 gnu89 编译；常量上界 + 全展开），剥净后 ethertype 即内层
         * L3 类型。支持 QinQ（运营商/机房常见）；剥不动（越界/已非 VLAN）即止。 */
        {
            int _v;

            _Pragma("clang loop unroll(full)")
            for (_v = 0; _v < VLAN_MAX_TAGS; _v++) {
                struct vlan_hdr *vh;

                if (ethertype != bpf_htons(ETH_P_8021Q) &&
                    ethertype != bpf_htons(ETH_P_8021AD))
                    break;
                if ((void *)data + off + sizeof(*vh) > data_end)
                    return 0;
                vh = (struct vlan_hdr *)(data + off);
                ethertype = vh->inner;
                off += sizeof(*vh);
            }
        }
    }

    switch (ethertype) {
    case bpf_htons(ETH_P_IP):  /* 0x0800 网络序 → 主机序 */
        if ((void *)data + off + sizeof(*iph) > data_end)
            return 0;
        iph = (struct iphdr *)(data + off);
        ihl = (int)(iph->ihl * 4);
        if (ihl < (int)sizeof(*iph) || (void *)data + off + ihl > data_end)
            return 0;

        pkt->family = SPLIT_FAMILY_IPV4;
        pkt->dst.ip4 = iph->daddr;
        return 1;

    case bpf_htons(ETH_P_IPV6): /* 0x86DD 网络序 → 主机序 */
        if ((void *)data + off + sizeof(*ip6h) > data_end)
            return 0;
        ip6h = (struct ipv6hdr *)(data + off);

        pkt->family = SPLIT_FAMILY_IPV6;
        __builtin_memcpy(pkt->dst.ip6, &ip6h->daddr, 16);
        return 1;

    default:
        return 0;
    }
}

#endif /* __SPLIT_BPF_PARSE_H_ */