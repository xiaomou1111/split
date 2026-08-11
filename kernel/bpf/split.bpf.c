/* SPDX-License-Identifier: GPL-2.0
 * split.bpf.c — eBPF 分流器唯一入口程序
 *
 * 模块关系：
 *   split.bpf.c ──> parse.h（解析）──> policy.h（裁决）──> radix.h（LPM）
 *                        └──────────> maps.h（map 定义/统计/工具）
 *
 * 挂载：tc clsact egress（物理网卡出口），SEC 名 "classifier"
 * 行为：
 *   - 判定直连 → return TC_ACT_OK（原样出网）
 *   - 判定代理 → bpf_redirect(tun_ifindex, 0)（从 tun0 发出 → mihomo 读到）
 *   - 任何异常/未知 → TC_ACT_OK 放行，绝不丢包
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "split_bpf.h"
#include "maps.h"
#include "parse.h"
#include "radix.h"
#include "policy.h"

char LICENSE[] SEC("license") = "GPL";

SEC("classifier")
int split_classify(struct __sk_buff *skb)
{
    struct split_pkt pkt = {};
    const struct split_cfg *cfg;
    __u32 uid = 0;
    __u32 tun;
    int verdict;

    stats_inc(STAT_TOTAL);

    /* 1. 解析（失败=放行） */
    if (!parse_skb(skb, &pkt)) {
        stats_inc(STAT_PARSE_ERR);
        return TC_ACT_OK;
    }

    /* 2. 读取发送套接字 UID（Android 每 app 一 uid；无 socket 时为 0）。
     * v1.2.0：cfg.skip_uid_enabled==0（无白名单）时完全跳过 bpf_get_socket_uid
     * helper 调用——该 helper 相对昂贵，热路径下能省则省（policy.h 第 1 步同
     * flag 短路，uid 保持 0 无害）。 */
    cfg = get_cfg();
    if (cfg && cfg->skip_uid_enabled)
        uid = bpf_get_socket_uid(skb);

    /* 3. 裁决 */
    verdict = policy_judge(&pkt, uid, cfg);

    /* 4. 执行 */
    if (verdict == SPLIT_VERDICT_TUN) {
        tun = tun_ifindex();
        if (!tun) {
            /* 还没有 tun：放行（保联网），记录一次 */
            stats_inc(STAT_MISS_TUN);
            return TC_ACT_OK;
        }
        /*
         * flags=0 → egress 方向：把包"从 tun0 发出"，进入 tun 驱动读队列 → 用户态读取。
         *
         * 关键（v1.0.4 源码核实）：**必须先设 skb->queue_mapping=0**。
         * tun_net_xmit() 用 skb->queue_mapping 索引 tun->tfiles[] 找读队列：
         *   tfile = rcu_dereference(tun->tfiles[skb->queue_mapping]);
         * 从物理网卡（wlan0/rmnet 多队列）egress redirect 来的 skb，queue_mapping
         * 继承物理网卡的队列号（0~N-1），而单队列 tun 只有 tfiles[0]。若 queue_mapping>0
         * → tfile=NULL → 包被 drop（WSL2 eth0 单队列恒 0 所以正常，Android 多队列出问题）。
         * 这里强制 queue_mapping=0，保证包进入唯一读队列 → mihomo read() 能读到。
         */
        skb->queue_mapping = 0;
        if (bpf_redirect(tun, 0) != TC_ACT_REDIRECT) {
            /* redirect 失败（如 tun 恰在查表后被移除）：放行保联网，绝不丢包 */
            stats_inc(STAT_REDIRECT_ERR);
            return TC_ACT_OK;
        }
        return TC_ACT_REDIRECT;
    }

    /* 直连 */
    return TC_ACT_OK;
}
