/* SPDX-License-Identifier: GPL-2.0
 * iface.c — 根据配置决定"挂哪些网卡"，并驱动网络切换
 *
 * 职责：
 *   - attach_auto=on：扫描物理网卡（common/netlink 过滤），全挂
 *   - attach_auto=off：只挂 attach_list，并过滤 exclude
 */
#include <stdio.h>
#include <string.h>

#include "../common/netlink.h"
#include "../common/config.h"
#include "../common/log.h"
#include "loader.h"

static int should_exclude(const struct split_config *cfg, const char *name)
{
    for (int k = 0; k < cfg->nexclude; k++) {
        if (!cfg->exclude[k][0]) /* 空项忽略，避免 strlen("")==0 前缀恒匹配排除全部 */
            continue;
        if (strncmp(name, cfg->exclude[k], strlen(cfg->exclude[k])) == 0)
            return 1;
    }
    return 0;
}

/*
 * 计算需要挂载的 ifindex 列表（不含已挂载的）。
 * @out 输出, @max 容量; 返回个数（>=0）；错误 -1
 */
int iface_plan(struct split_bpf_ctx *ctx, const struct split_config *cfg,
               int *out, int max, const struct iface_list *snap)
{
    struct iface_list owned;
    const struct iface_list *list;
    int n = 0;

    (void)ctx; /* 保留参数以对齐统一签名（当前实现不依赖 ctx） */

    if (snap) {
        /* 复用调用方已扫描的快照（netlink 事件路径），免去二次全量 dump */
        list = snap;
    } else {
        if (iface_scan(&owned) < 0) {
            LOG_ERRORF("接口扫描失败");
            return -1;
        }
        list = &owned;
    }

    for (int k = 0; k < list->count && n < max; k++) {
        const struct iface *i = &list->items[k];
        int want;

        if (should_exclude(cfg, i->name))
            continue;
        /* 两个分支统一套 iface_is_physical（审查修正）：此前 attach_auto=0 只比对
         * attach_list 名字 + exclude，没应用 iface_is_physical 的"物理网卡"过滤，
         * 用户若把 utun0/tun0 写进 attach_list 会把虚拟/tun 接口挂载上去
         * （回环 + parse_err）。现在 attach_list 命中后仍需经 iface_is_physical
         * 确认，与 attach_auto=1 分支口径一致。 */
        if (cfg->attach_auto) {
            want = iface_is_physical(i);
        } else {
            want = 0;
            for (int m = 0; m < cfg->nattach; m++) {
                if (strcmp(i->name, cfg->attach_list[m]) == 0) {
                    if (iface_is_physical(i))
                        want = 1;
                    break;
                }
            }
        }
        if (want)
            out[n++] = i->ifindex;
    }
    /* 每 5s 心跳也会走这里（v1.1.7），扫描计数只是数量提示，降为 DEBUG
     * 避免空闲时每 5s 一条刷爆 splitd.log；真正挂载/卸载仍是 INFO。 */
    LOG_DEBUGF("扫描到待挂载接口 %d 个", n);
    return n;
}

/*
 * 重挂：把当前 ctx 已挂的与期望集合对齐（增量重挂/卸载）
 */
int iface_reconcile(struct split_bpf_ctx *ctx, const struct split_config *cfg,
                    const struct iface_list *snap)
{
    struct iface_list owned;
    const struct iface_list *list = snap;
    int plan[IFACE_MAX], n, k, already;

    /* v1.1.9：本函数全程复用一个快照（传入或自扫一次），并向下透传给
     * iface_plan / split_attach|detach_iface / map_rawip_sync，消除此前
     * 每次 reconcile 内部多次 iface_scan 的重复扫描。
     * v1.2.8（审查修复）：NULL 快照时也**只自扫一次**并向下透传——旧实现让
     * iface_plan/每个 attach/detach 各自自扫（1+N+1 次全量 dump），
     * loader/MEMORY 声称的"全程只 scan 一次"在 NULL 路径并不成立。 */
    if (!list) {
        if (iface_scan(&owned) < 0) {
            LOG_ERRORF("接口扫描失败");
            return -1;
        }
        list = &owned;
    }
    n = iface_plan(ctx, cfg, plan, IFACE_MAX, list);
    if (n < 0)
        return -1;

    /* 卸载不在计划里的 */
    for (k = 0; k < ctx->nattached; k++) {
        already = 0;
        for (int m = 0; m < n; m++)
            if (plan[m] == ctx->attached[k]) already = 1;
        if (!already)
            split_detach_iface(ctx, ctx->attached[k--], list);
    }
    /* 新增 */
    for (k = 0; k < n; k++)
        split_attach_iface(ctx, plan[k], list);
    /* v1.1.5：网络事件后全量重建 map_rawip（RAWIP=无 L2 头接口集合）。
     * 挂载路径已逐接口同步，这里兜底处理"挂载前就存在的接口类型变化"、
     * "接口 UP 状态变化但没触发 attach/detach"等边角场景。 */
    map_rawip_sync(ctx, 0, list);
    return 0;
}

/* 帮助"name → ifindex"，方便把 tun_device 解析为 map_tun 值 */
int iface_resolve_tun(const char *name)
{
    if (!name || !name[0])
        return -1;
    return iface_index_by_name(name);
}