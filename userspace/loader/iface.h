/* SPDX-License-Identifier: GPL-2.0
 * iface.h — 挂载计划 / tun 解析（userspace/loader/iface.c 的头）
 */
#ifndef SPLIT_USERS_LOADER_IFACE_H_
#define SPLIT_USERS_LOADER_IFACE_H_

#include "../common/config.h"
#include "loader.h"

/*
 * 计算需要挂载的 ifindex 列表。@out 数组需 >= @max。
 * @snap：可选（可为 NULL）。非 NULL 时复用已扫描的接口快照，免去再扫一次
 * rtnetlink；NULL 则内部 iface_scan 全量扫描。
 * 返回个数（>=0），错误 -1。
 */
int iface_plan(struct split_bpf_ctx *ctx, const struct split_config *cfg,
               int *out, int max, const struct iface_list *snap);

/* 把 ctx 已挂的接口与期望集合对齐（增量挂/卸）。@snap 语义同 iface_plan（v1.1.9：
 * netlink 事件路径复用 iface_watch_poll 已拿到的快照，消除重复 scan）。 */
int iface_reconcile(struct split_bpf_ctx *ctx, const struct split_config *cfg,
                    const struct iface_list *snap);

/* 把代理设备名解析为 ifindex（不存在 = -1） */
int iface_resolve_tun(const char *name);

#endif