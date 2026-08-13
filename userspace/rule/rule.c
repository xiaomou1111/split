/* SPDX-License-Identifier: GPL-2.0 */
#include "rule.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>   /* AF_INET */

#include "../common/log.h"

static void rule_add_list(struct split_bpf_ctx *ctx,
                          const char list[][CFG_STRLEN], int n, int which)
{
    for (int k = 0; k < n; k++) {
        if (map_rule_add_cidr(ctx, list[k], which) < 0)
            LOG_WARNF("规则写入失败: %s", list[k]);
    }
}

int rule_apply_all(struct split_bpf_ctx *ctx, const struct split_config *cfg)
{
    /* 先清空（幂等：remove 配置中已移除的旧项），再全量写入 */
    map_rule_clear(ctx);

    /* UID 白名单（覆盖式） */
    for (int k = 0; k < cfg->nskip_uid; k++)
        map_skip_uid_add(ctx, cfg->skip_uid[k]);

    /* 规则 CIDR */
    rule_add_list(ctx, cfg->proxy4,  cfg->nproxy4,  RULE_PROXY);
    rule_add_list(ctx, cfg->proxy6,  cfg->nproxy6,  RULE_PROXY);
    rule_add_list(ctx, cfg->direct4, cfg->ndirect4, RULE_DIRECT);
    rule_add_list(ctx, cfg->direct6, cfg->ndirect6, RULE_DIRECT);

    /* 运行时配置 —— v1.3.1（审查修复）：返回值必须检查。map_cfg 写入失败时
     * 内核会把它当"未初始化"回落到 TUN 安全默认（见 policy.h），但若用户配置
     * 的 default_verdict 就是 direct，静默回落会改变分流语义——显式报错便于排查。 */
    if (map_set_cfg(ctx, cfg->default_verdict, cfg->ipv6_classify ? true : false,
                    cfg->nskip_uid > 0) != 0)
        LOG_ERRORF("map_cfg 写入失败(%s)，内核按 TUN 安全默认运行（default_verdict=%s）",
                   strerror(errno), cfg->default_verdict ? "tun" : "direct");

    LOG_INFOF("rules 已应用: uid=%d proxy4=%d direct4=%d",
              cfg->nskip_uid, cfg->nproxy4, cfg->ndirect4);
    return 0;
}

int rule_add(struct split_bpf_ctx *ctx, const char *cidr, int which)
{
    return map_rule_add_cidr(ctx, cidr, which);
}

int rule_del(struct split_bpf_ctx *ctx, const char *cidr, int which)
{
    return map_rule_del_cidr(ctx, cidr, which);
}

/* ---- v1.2.0 运行时规则偏差（H1 修复） ---- */

void rule_overrides_init(struct rule_overrides *rov)
{
    memset(rov, 0, sizeof(*rov));
}

int rule_override_record(struct rule_overrides *rov,
                         const char *cidr, int which, int present)
{
    int k;

    if (!rov || !cidr || !cidr[0] || (which != RULE_PROXY && which != RULE_DIRECT))
        return -1;
    /* v1.2.9（审查加固）：cidr 超长会在此处 snprintf 截断存储，reload 重放时
     * 会写入截断串（与运行时 map 里的完整 CIDR 不一致）。显式拒绝并告警——
     * 实际 CIDR 最长 <50 字节，触发即异常输入。 */
    if (strlen(cidr) >= CFG_STRLEN) {
        LOG_WARNF("运行时规则 %s 超长（≥%d 字节），不记录跨 reload 追踪",
                  cidr, CFG_STRLEN);
        return -1;
    }
    /* 同 cidr+which 已存在：覆盖（last-wins） */
    for (k = 0; k < rov->count; k++) {
        if (rov->items[k].which == which &&
            strcmp(rov->items[k].cidr, cidr) == 0) {
            rov->items[k].present = present ? 1 : 0;
            return 0;
        }
    }
    if (rov->count >= RULE_OVERRIDE_MAX)
        return -1; /* 满：拒绝记录，避免 reload 后丢规则 */
    snprintf(rov->items[rov->count].cidr, CFG_STRLEN, "%s", cidr);
    rov->items[rov->count].which = (uint8_t)which;
    rov->items[rov->count].present = present ? 1 : 0;
    rov->count++;
    return 0;
}

void rule_overrides_replay(struct split_bpf_ctx *ctx,
                           const struct rule_overrides *rov)
{
    int k;

    if (!rov)
        return;
    for (k = 0; k < rov->count; k++) {
        const struct rule_override *o = &rov->items[k];

        if (o->present)
            rule_add(ctx, o->cidr, o->which);
        else
            rule_del(ctx, o->cidr, o->which);
    }
}