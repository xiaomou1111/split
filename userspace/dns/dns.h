/* SPDX-License-Identifier: GPL-2.0
 * dns.h — DNS 响应学习器（v1.1.0 域名分流）
 *
 * 职责：用 AF_PACKET 原始套接字抓取所有接口上"发给本机"的 DNS 响应
 * （UDP 源端口 53，IPv4 传输），解析出 A/AAAA 记录后把 IP→域名 写进
 * map_dns4/6（内核 egress 时用它做域名规则判定）。
 *
 * 为什么在用户态：DNS 响应解析（压缩指针/多记录/CNAME 链/0x20 大小写）
 * 在 eBPF 里做有 verifier 与真机兼容风险；用户态 AF_PACKET 无约束，
 * 且 splitd 本就以 root 运行（CAP_NET_RAW）。内核侧因此**不需要新增
 * ingress hook**（既定取舍，见 kernel/bpf/MEMORY.md）。
 *
 * 失败语义：学习器任何解析失败都只是"漏判该域名"，不影响联网
 * （内核侧域名未学到 → 回落 IP/CNIP 判定）——绝不阻断主链路。
 */
#ifndef SPLIT_USERS_DNS_H_
#define SPLIT_USERS_DNS_H_

#include <stdint.h>
#include "../loader/loader.h"

struct dns_learn {
    int fd;                    /* AF_PACKET socket（IPv4 帧），-1 = 未打开 */
    struct split_bpf_ctx *ctx;
    uint8_t *rbuf;             /* v1.2.0（H3）：poll 复用的 64KB 读缓冲，open 时分配 */
    uint64_t learned;          /* 累计学习条数（日志/排查） */
    uint64_t skipped;          /* 累计跳过条数（分片/TCP/解析失败） */
};

/* 打开学习 socket（所有接口，只收 IPv4 帧 + PACKET_HOST）。
 * 失败返回 -1——不致命，主分流照常（只是域名功能不生效），调用方记 WARN。 */
int dns_learn_open(struct dns_learn *dl, struct split_bpf_ctx *ctx);

/* 读尽当前可读数据并学习（poll 驱动，非阻塞；无数据立即返回）。
 * 返回本次处理包数。 */
int dns_learn_poll(struct dns_learn *dl);

void dns_learn_close(struct dns_learn *dl);

#endif
