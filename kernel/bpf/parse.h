/* SPDX-License-Identifier: GPL-2.0
 * parse.h — 报文解析模块
 *
 * 职责：安全地从 __sk_buff 读出 L3/L4 元数据。
 * 原则：任何越界/未知一律返回 0（= 不可判，由上层放行），绝不越界读。
 * 支持：IPv4 / IPv6 / VLAN(0x8100,0x88a8) 直至双标签（QinQ）；IPv6 扩展头
 * （HOPOPTS/ROUTING/DSTOPTS/FRAGMENT，可链式：OPT*→FRAGMENT→L4，仅首片取端口）；TCP/UDP 端口。
 */
#ifndef __SPLIT_BPF_PARSE_H_
#define __SPLIT_BPF_PARSE_H_

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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

/* IPv6 扩展头（仅提取所需字段；用 split_ 前缀避免与系统头 struct 重名冲突） */
struct split_v6_opt_hdr {
    __u8  nexthdr;
    __u8  hdrlen;
};
struct split_v6_frag_hdr {
    __u8  nexthdr;
    __u8  reserved;
    __be16 frag_off;
    __be32 ident;
};

/*
 * 处理一个 IPv6 FRAGMENT 扩展头（位于 data+off，调用方已确认此处确是分片头）。
 * 仅首片（frag_off 的 offset 位 & 0xFFF8 == 0）才可能带 L4 头：TCP/UDP 取 dport，
 * 否则 dport 留 0。掩码必须 0xFFF8：IPv6 frag_off 布局是 offset 占高 13 位
 * （bits 3-15）、M 标志在 bit 0——0x1FFF 是 IPv4 的 IP_OFFMASK，用它会把
 * M=1 的首片（0x0001）漏判、且 offset≥8192 的非首片（0x2000）误判为首片。
 * @return 1=成功（proto 已更新，dport 可能已写 / 非首片保持调用方初值）
 *         0=越界→parse 失败（调用方按放行处理）；绝不越界读。
 */
static __always_inline int split_ipv6_frag_l4(void *data, void *data_end,
                                              __u32 off, __u8 *proto,
                                              __be16 *dport)
{
    struct split_v6_frag_hdr *fh;
    struct tcphdr *tp;
    struct udphdr *up;

    if ((void *)data + off + sizeof(*fh) > data_end)
        return 0;
    fh = (struct split_v6_frag_hdr *)(void *)(data + off);
    *proto = fh->nexthdr;
    if ((bpf_ntohs(fh->frag_off) & 0xFFF8) != 0)
        return 1; /* 非首片：无 L4 头，dport 留 0，仍 parse 成功 */
    if (*proto == IPPROTO_TCP) {
        if ((void *)data + off + sizeof(*fh) + sizeof(*tp) > data_end)
            return 0;
        tp = (struct tcphdr *)(void *)(data + off + sizeof(*fh));
        *dport = tp->dest;
    } else if (*proto == IPPROTO_UDP) {
        if ((void *)data + off + sizeof(*fh) + sizeof(*up) > data_end)
            return 0;
        up = (struct udphdr *)(void *)(data + off + sizeof(*fh));
        *dport = up->dest;
    }
    return 1;
}

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
    struct tcphdr *tcph;
    struct udphdr *udph;
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
        pkt->proto = iph->protocol;
        pkt->dst.ip4 = iph->daddr;
        pkt->dport = 0;

        /* IPv4 分片（v1.1.4）：非首片（offset≠0）无 L4 头，dport 留 0
         * （与 IPv6 fragment 分支语义对齐）；首片/原子片（offset=0）照常取端口。
         * 此前会把分片数据偏移处误当 L4 头读（dport 当前未被 policy 使用，
         * 无实际影响，属防御性对齐）。 */
        if ((bpf_ntohs(iph->frag_off) & 0x1FFF) != 0) {
            pkt->dport = 0;
            return 1;
        }

        if (iph->protocol == IPPROTO_TCP) {
            if ((void *)data + off + ihl + sizeof(*tcph) > data_end)
                return 0;
            tcph = (struct tcphdr *)(void *)(data + off + ihl);
            pkt->dport = tcph->dest;
        } else if (iph->protocol == IPPROTO_UDP) {
            if ((void *)data + off + ihl + sizeof(*udph) > data_end)
                return 0;
            udph = (struct udphdr *)(void *)(data + off + ihl);
            pkt->dport = udph->dest;
        }
        return 1;

    case bpf_htons(ETH_P_IPV6): /* 0x86DD 网络序 → 主机序 */
        if ((void *)data + off + sizeof(*ip6h) > data_end)
            return 0;
        ip6h = (struct ipv6hdr *)(data + off);

        pkt->family = SPLIT_FAMILY_IPV6;
        pkt->proto = ip6h->nexthdr;
        __builtin_memcpy(pkt->dst.ip6, &ip6h->daddr, 16);
        pkt->dport = 0;
        off += sizeof(*ip6h);

        /*
         * IPv6 扩展头链式解析。
         * 此前只支持"无扩展头直取端口"或"单一扩展头(OPT*)后取端口"，
         * OPT*→FRAGMENT→L4 等连续扩展头不穿越（dport 恒 0）。
         * 现按序支持：
         *   - 无扩展头：nexthdr 即 L4，直接取端口（与 IPv4 分支对齐）；
         *   - OPT*(HOPOPTS/ROUTING/DSTOPTS，相同布局)：跳 (hdrlen+1)*8 字节，
         *     再取下一 nexthdr，按 L4 / FRAGMENT 继续；
         *   - FRAGMENT（固定 8 字节）：取其 nexthdr；仅首片（offset=0）带 L4 头。
         * 更深（如 OPT*→OPT*→L4、隧道封装）不穿越：dport 留 0，仍 parse 成功放行。
         * 铁律：每步先 data_end 边界检查再读；越界即 parse 失败（0）由调用方放行。
         * 注意：dport 当前未被 policy 使用，此为防御性对齐，勿回退到"恒 0 旧版"。
         */
        if (pkt->proto == IPPROTO_TCP) {
            if ((void *)data + off + sizeof(*tcph) > data_end)
                return 0;
            tcph = (struct tcphdr *)(void *)(data + off);
            pkt->dport = tcph->dest;
            return 1;
        }
        if (pkt->proto == IPPROTO_UDP) {
            if ((void *)data + off + sizeof(*udph) > data_end)
                return 0;
            udph = (struct udphdr *)(void *)(data + off);
            pkt->dport = udph->dest;
            return 1;
        }
        if (pkt->proto == IPPROTO_HOPOPTS ||
            pkt->proto == IPPROTO_ROUTING ||
            pkt->proto == IPPROTO_DSTOPTS) {
            struct split_v6_opt_hdr *oh;
            __u32 hlen;

            if ((void *)data + off + sizeof(*oh) > data_end)
                return 0;
            oh = (struct split_v6_opt_hdr *)(void *)(data + off);
            hlen = ((__u32)oh->hdrlen + 1) * 8;
            if ((void *)data + off + hlen > data_end)
                return 0;
            pkt->proto = oh->nexthdr;
            off += hlen;
            /* 第一层扩展头之后：L4 或 FRAGMENT；再深不穿（dport 留 0） */
            if (pkt->proto == IPPROTO_TCP) {
                if ((void *)data + off + sizeof(*tcph) > data_end)
                    return 0;
                tcph = (struct tcphdr *)(void *)(data + off);
                pkt->dport = tcph->dest;
            } else if (pkt->proto == IPPROTO_UDP) {
                if ((void *)data + off + sizeof(*udph) > data_end)
                    return 0;
                udph = (struct udphdr *)(void *)(data + off);
                pkt->dport = udph->dest;
            } else if (pkt->proto == IPPROTO_FRAGMENT) {
                if (!split_ipv6_frag_l4(data, data_end, off,
                                        &pkt->proto, &pkt->dport))
                    return 0;
            }
            return 1;
        }
        if (pkt->proto == IPPROTO_FRAGMENT)
            return split_ipv6_frag_l4(data, data_end, off,
                                      &pkt->proto, &pkt->dport);
        /* 其余协议（ESP/AH/GRE/未知）：dport 留 0，放行 */
        return 1;

    default:
        return 0;
    }
}

#endif /* __SPLIT_BPF_PARSE_H_ */