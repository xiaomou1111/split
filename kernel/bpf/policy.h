/* SPDX-License-Identifier: GPL-2.0
 * policy.h — 分流策略裁决
 *
 * 判定顺序（即优先级；default_verdict 只影响最后一步）：
 *   1. uid 白名单 → 直连（防代理自身回环）
 *   2. ipv6_classify=false 且 v6 → 直连（v6 不参与分类，docs/04 契约）
 *   3. 内置本地段（回环/链路本地/组播） → 直连
 *   4. proxy 规则段命中 → 代理（fake-ip 池等）
 *   5. direct 规则段命中 → 直连
 *   6. CNIP(4/6) 命中 → 直连
 *   7. 其余 → cfg.default_verdict
 */
#ifndef __SPLIT_BPF_POLICY_H_
#define __SPLIT_BPF_POLICY_H_

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include "split_bpf.h"
#include "maps.h"
#include "radix.h"

/*
 * 用 bpf_ntohl 把地址转成与"主机字节序"无关的"数值"：
 * 高 8 位即首字节（127.0.0.1 → 0x7F000001），判定段属性能跨 CPU endian 一致。
 */

/* ---- 内置直连段（硬编码，无需配置） ---- */
static __always_inline int builtin_is_local(const struct split_pkt *pkt)
{
    if (pkt->family == SPLIT_FAMILY_IPV4) {
        __u32 a = bpf_ntohl(pkt->dst.ip4); /* 主机序 */

        /* 127.0.0.0/8 */
        if ((a & 0xFF000000) == 0x7F000000)
            return 1;
        /* 169.254.0.0/16 */
        if ((a & 0xFFFF0000) == 0xA9FE0000)
            return 1;
        /* 224.0.0.0/4 组播 */
        if ((a & 0xF0000000) == 0xE0000000)
            return 1;
        /* 255.255.255.255 */
        if (a == 0xFFFFFFFF)
            return 1;
        return 0;
    }

    if (pkt->family == SPLIT_FAMILY_IPV6) {
        const __u8 *p = pkt->dst.ip6;

        /* ::1/128 */
        if (p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0 &&
            p[4] == 0 && p[5] == 0 && p[6] == 0 && p[7] == 0 &&
            p[8] == 0 && p[9] == 0 && p[10] == 0 && p[11] == 0 &&
            p[12] == 0 && p[13] == 0 && p[14] == 0 && p[15] == 1)
            return 1;
        /* fe80::/10 链路本地 */
        if (p[0] == 0xFE && (p[1] & 0xC0) == 0x80)
            return 1;
        /* ff00::/8 组播 */
        if (p[0] == 0xFF)
            return 1;
        return 0;
    }
    /* 不可达（parse_skb 成功时 family 恒为 IPV4/IPV6，此分支不会走到）；
     * 防御性默认：非 IP 视为本地/直连放行，绝不误判代理。 */
    return 1; /* 非 IP（ARP 等）按放行处理 */
}

/*
 * 主裁决入口
 * @return split_verdict
 */
static __always_inline int policy_judge(const struct split_pkt *pkt,
                                        __u32 uid,
                                        const struct split_cfg *cfg)
{
    /* cfg 为 NULL 或"未初始化"时使用安全默认值：ipv6 不分类，默认代理
     * （未知→代理是安全默认，与 kernel/bpf/MEMORY.md 第 11 条、split_bpf.h
     * "default_verdict" 注释一致）。
     * v1.3.1（审查修复）：map_cfg 是 ARRAY map，bpf_map_lookup_elem 永不返回
     * NULL——未写入时返回全零元素（default_verdict=0=直连），旧注释"map 未
     * 初始化按默认代理"并不成立。现以 loader 写入的 `bpf_trace_enabled==1`
     * 作为"已初始化"哨兵：=0 视为未写入/写入失败，回落到 TUN 安全默认。 */
    struct split_cfg default_cfg = { .default_verdict = SPLIT_VERDICT_TUN,
                                     .cnip_enabled = 1 };

    if (!cfg || cfg->bpf_trace_enabled == 0)
        cfg = &default_cfg;

    /* 1. UID 白名单（mihomo 自身、root、shell）。
     * v1.2.0：cfg.skip_uid_enabled==0（map_skip_uid 空）时跳过整段——
     * 省下 bpf_get_socket_uid helper 外的 HASH 查表（helper 调用在
     * split.bpf.c 按同一 flag 短路，见下）。 */
    if (cfg->skip_uid_enabled) {
        __u8 *allow = bpf_map_lookup_elem(&map_skip_uid, &uid);

        if (allow) {
            stats_inc(STAT_SKIP_UID);
            return SPLIT_VERDICT_PASS;
        }
    }

    /* 2. ipv6_classify=false：v6 不参与任何分类，一律直连（docs/04 契约）。
     * 必须置于规则/CNIP 之前——否则 proxy6/direct6 规则仍会命中，与
     * "v6 一律直连"语义相悖。统计记 STAT_DIRECT_V6（"配置性直连"，与第 6 步
     * 的 CNIP 直连 STAT_DIRECT_CN 区分开，观测语义更准）。 */
    if (pkt->family == SPLIT_FAMILY_IPV6 && !cfg->ipv6_classify) {
        stats_inc(STAT_DIRECT_V6);
        return SPLIT_VERDICT_PASS;
    }

    /* 3. 内置本地段（127/8、链路本地、组播、ff00::/8 等；不含 RFC1918，见
     * builtin_is_local）。审查（2026-08）澄清：STAT_DIRECT_RULE 是"直连判定"类计数，
     * 与本步内置本地、第 5 步直连规则、第 7 步 default=direct 共用（CNIP 单列
     * STAT_DIRECT_CN）——别把它的数值误读成"直连规则命中数"。 */
    if (builtin_is_local(pkt)) {
        stats_inc(STAT_DIRECT_RULE);
        return SPLIT_VERDICT_PASS;
    }

    /* 4. 强制代理规则（fake-ip 池等，优先级高于 CNIP） */
    if (pkt->family == SPLIT_FAMILY_IPV4) {
        if (radix_match4(&map_rule_proxy4, pkt->dst.ip4)) {
            stats_inc(STAT_PROXY);
            return SPLIT_VERDICT_TUN;
        }
    } else if (pkt->family == SPLIT_FAMILY_IPV6) {
        if (radix_match6(&map_rule_proxy6, pkt->dst.ip6)) {
            stats_inc(STAT_PROXY);
            return SPLIT_VERDICT_TUN;
        }
    }

    /* 5. 强制直连规则（内网/vpn/自有服务） */
    if (pkt->family == SPLIT_FAMILY_IPV4) {
        if (radix_match4(&map_rule_direct4, pkt->dst.ip4)) {
            stats_inc(STAT_DIRECT_RULE);
            return SPLIT_VERDICT_PASS;
        }
    } else if (pkt->family == SPLIT_FAMILY_IPV6) {
        if (radix_match6(&map_rule_direct6, pkt->dst.ip6)) {
            stats_inc(STAT_DIRECT_RULE);
            return SPLIT_VERDICT_PASS;
        }
    }

    /* 6. CNIP（中国段 → 直连）—— 核心内核分流。运行时临时开关关闭时跳过
     * 查询，继续落到第 7 步 default_verdict；map 内容仍由用户态正常刷新。 */
    if (cfg->cnip_enabled) {
        if (pkt->family == SPLIT_FAMILY_IPV4) {
            if (radix_match4(&map_cnip4, pkt->dst.ip4)) {
                stats_inc(STAT_DIRECT_CN);
                return SPLIT_VERDICT_PASS;
            }
        } else if (pkt->family == SPLIT_FAMILY_IPV6) {
            if (radix_match6(&map_cnip6, pkt->dst.ip6)) {
                stats_inc(STAT_DIRECT_CN);
                return SPLIT_VERDICT_PASS;
            }
        }
    }

    /* 7. 默认行为。STAT_PROXY / STAT_DIRECT_RULE 都含此默认路径（审查 2026-08 澄清：
     * 与第 4/5 步同计数器，故代理计数含"默认代理"、直连计数含"默认直连"）。 */
    if (cfg->default_verdict == SPLIT_VERDICT_TUN)
        stats_inc(STAT_PROXY);
    else
        stats_inc(STAT_DIRECT_RULE);
    return cfg->default_verdict;
}

#endif /* __SPLIT_BPF_POLICY_H_ */