/* SPDX-License-Identifier: GPL-2.0
 * loader.h — BPF 对象加载 / tc 挂载 对外接口
 *
 * 模块：userspace/loader
 * 依赖：libbpf (>= 1.0)、common/log、common/netlink
 * 契约：
 *   split_load()        加载 split.bpf.o 并绑定 map fd
 *   split_attach()      挂到指定 ifindex 的 egress（可重入，先 detach）
 *   split_detach_all()  卸载
 *   map_*()             针对 map 的写入/读取
 */
#ifndef SPLIT_USERS_LOADER_H_
#define SPLIT_USERS_LOADER_H_

#include <bpf/libbpf.h>
#include <stdint.h>
#include <stdbool.h>

#include "../../kernel/include/split_bpf.h"
#include "../common/netlink.h"

struct split_bpf_ctx {
    struct bpf_object *obj;
    struct bpf_program *prog;   /* SEC("classifier") */
    int  prog_fd;
    /* map fd（libbpf 对象内直接操作 map，本字段备用） */
    struct bpf_map *m_cnip4, *m_cnip6;
    struct bpf_map *m_proxy4, *m_proxy6, *m_direct4, *m_direct6;
    struct bpf_map *m_skip_uid, *m_tun, *m_cfg, *m_stats;
    /* v1.1.5 RAWIP 接口集合（无以太网头的接口，如 Android 蜂窝 rmnet_data*） */
    struct bpf_map *m_rawip;
    int  attached[IFACE_MAX];   /* 已挂载的 ifindex */
    int  nattached;
};

int  split_load(struct split_bpf_ctx *ctx, const char *obj_path);
void split_unload(struct split_bpf_ctx *ctx);

/* attach/detach 单个接口。@snap 可选（v1.1.9）：非 NULL 复用已扫描快照做 RAWIP
 * 同步，免去内部再 scan；NULL 则自行扫描（独立调用路径行为不变）。 */
int  split_attach_iface(struct split_bpf_ctx *ctx, int ifindex,
                        const struct iface_list *snap);
int  split_detach_iface(struct split_bpf_ctx *ctx, int ifindex,
                        const struct iface_list *snap);
void split_detach_all(struct split_bpf_ctx *ctx);

/* v1.1.5：同步 map_rawip（RAWIP=无 L2 头接口集合）。
 * @ifindex >0：按 iface.type 决定写入(RAWIP)/删除(其它)该接口；
 * @ifindex 0：全量重建（扫描所有接口，对当前 UP 的 RAWIP 接口写入）。
 * @snap 可选（v1.1.9）：非 NULL 复用快照，NULL 内部扫描。
 * 返回 0 成功；-1 扫描失败。挂载/卸载/网络事件后都应调用。 */
int map_rawip_sync(struct split_bpf_ctx *ctx, int ifindex,
                   const struct iface_list *snap);

/* ---- map 操作（返回 0 成功） ---- */
int map_set_tun(struct split_bpf_ctx *ctx, int ifindex);
int map_get_tun(struct split_bpf_ctx *ctx, uint32_t *ifindex);
int map_set_cfg(struct split_bpf_ctx *ctx, uint8_t default_verdict, bool ipv6_on,
                bool skip_uid_on);
int map_skip_uid_add(struct split_bpf_ctx *ctx, uint32_t uid);
int map_skip_uid_del(struct split_bpf_ctx *ctx, uint32_t uid);
/* cidr: "A.B.C.D/N" 或 "xxxx:xxxx::/N"，写入 rule map（which=RULE_PROXY/DIRECT） */
int map_rule_add_cidr(struct split_bpf_ctx *ctx, const char *cidr, int which);
int map_cnip_add_cidr(struct split_bpf_ctx *ctx, const char *cidr, int family);
/* v1.4.6（审查 P2）：校验 CIDR 能否写入 CNIP map（dry-run，不写 map）。
 * 与 map_cnip_add_cidr 判定口径一致（parse_pfix 0..128 + inet_pton，超范围 clamp
 * 计合法），供下载校验阶段计 ok/bad——校验期若直接写 map，rename 失败（磁盘满/权限）
 * 且全配置族失败跳过 cnip_apply 时，map 会残留本地旧文件里没有的条目（map≠file）。 */
int map_cnip_cidr_ok(const char *cidr, int family);
/* 读取统计（per-cpu 求和） */
int map_stats_dump(struct split_bpf_ctx *ctx, uint64_t out[STAT_MAX]);

/* 删除规则（LPM_TRIE delete_elem） */
int map_rule_del_cidr(struct split_bpf_ctx *ctx, const char *cidr, int which);

/* ---- v1.2.2 在线规则枚举（WebUI 规则列表）----
 * 遍历某 which（0=proxy / 1=direct，与 rule.h RULE_PROXY/RULE_DIRECT 一致）的
 * 两个 LPM map（v4+v6），把每条 key 还原成 "1.2.3.0/24" 文本后回调 cb(which, cidr, priv)。
 * 顺序：v4 map → v6 map。返回：回调非 0 中止返回 -1；否则返回遍历条目总数。
 * 遍历用 prev-key 顺序迭代（不删键，get_next_key(prev) 稳定前进）——与 map_cnip_count 同款。 */
typedef int (*map_rule_foreach_cb)(int which, const char *cidr, void *priv);
int map_rule_foreach(struct split_bpf_ctx *ctx, int which,
                     map_rule_foreach_cb cb, void *priv);

/* reload 前清空：跳过 UID / proxy/direct 规则 map（幂等"先清空再写"） */
int map_rule_clear(struct split_bpf_ctx *ctx);
/* reload-cnip 前清空 CNIP map（幂等"先清空再写"） */
int map_cnip_clear(struct split_bpf_ctx *ctx);
/* map_cnip_clear 的别名（历史调用名兼容） */
int map_cnip_clear_all(struct split_bpf_ctx *ctx);

/* 统计 CNIP map 当前条目数（status 自检用；0 条 = 文件缺失/未导入） */
int map_cnip_count(struct split_bpf_ctx *ctx, uint32_t *n4, uint32_t *n6);

#endif