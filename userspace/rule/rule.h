/* SPDX-License-Identifier: GPL-2.0
 * rule.h — 规则管理器（rules 段 → 各类 map）
 */
#ifndef SPLIT_USERS_RULE_H_
#define SPLIT_USERS_RULE_H_

#include "../common/config.h"
#include "../loader/loader.h"

#define RULE_PROXY 0
#define RULE_DIRECT 1

/* 把配置里的 rule 段全部写入 map（幂等；先清空再写） */
int rule_apply_all(struct split_bpf_ctx *ctx, const struct split_config *cfg);

/* 单条 cidr 的 add/del（对应 splitctl add-rule/del-rule） */
int rule_add(struct split_bpf_ctx *ctx, const char *cidr, int which);
int rule_del(struct split_bpf_ctx *ctx, const char *cidr, int which);

/* ---- v1.2.0 运行时规则追踪（H1 修复）----
 * add-rule/del-rule 是"对配置基线的运行时偏差"：直接写 map 会被下一次
 * reload（rule_apply_all 先 clear 再写）冲掉。这里记录"期望状态"，让
 * reload 在重放配置基线之后把运行时偏差重放回去，保证 CLI 增删不丢失。
 * 只支持 CIDR 规则（which=RULE_PROXY/DIRECT）。 */
#define RULE_OVERRIDE_MAX 64

struct rule_override {
    char cidr[CFG_STRLEN];
    uint8_t which;     /* RULE_PROXY / RULE_DIRECT */
    uint8_t present;   /* 1=期望存在(add) 0=期望删除(del) */
};

struct rule_overrides {
    struct rule_override items[RULE_OVERRIDE_MAX];
    int count;
};

void rule_overrides_init(struct rule_overrides *rov);
/* 记录一条运行时偏差（同 cidr+which 覆盖，last-wins）；满/非法返回 -1。
 * 只记录内存状态、不触碰 map；实际写 map 由调用方经 rule_add/rule_del 完成。 */
int rule_override_record(struct rule_overrides *rov,
                         const char *cidr, int which, int present);
/* reload 时序：在 rule_apply_all(配置基线) 之后调用，把全部运行时偏差重放回 map。 */
void rule_overrides_replay(struct split_bpf_ctx *ctx,
                           const struct rule_overrides *rov);

#endif