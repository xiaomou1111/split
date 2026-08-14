/* SPDX-License-Identifier: GPL-2.0
 * config.h — 配置解析（自研"极简 YAML 子集"解析器）
 *
 * 支持语法（仅这些，严格自上而下）：
 *   # 注释
 *   section:            ← 分组（缩进无关，按行解析）
 *   key: value
 *   list:               ← 属于上一节
 *     - item1
 *     - item2
 * 其它 YAML 特性一概不支持——文档写明，保持无依赖。
 */
#ifndef SPLIT_USERS_CONFIG_H_
#define SPLIT_USERS_CONFIG_H_

#include <stdint.h>

/* v1.4.2：128→256——CNIP url 多源 fallback 后默认 url 是"jsDelivr,raw"逗号拼接
 * 双 URL（v1.4.2 实测 143 字符起；v1.4.3 换 Loyalsoldier/geoip 后 139 字符，v4/v6 同源），
 * 128 会截断。纯用户态配置缓冲，无 ABI/持久化影响。 */
#define CFG_STRLEN 256
#define CFG_LIST_MAX 16

struct split_config {
    int  debug;

    /* proxy */
    char tun_device[CFG_STRLEN];

    /* ifaces */
    int  attach_auto;
    char attach_list[CFG_LIST_MAX][CFG_STRLEN]; int nattach;
    char exclude[CFG_LIST_MAX][CFG_STRLEN];     int nexclude;

    /* default */
    uint8_t default_verdict; /* 0=direct 1=tun */
    int     ipv6_classify;

    /* rules */
    char proxy4[CFG_LIST_MAX][CFG_STRLEN];  int nproxy4;
    char proxy6[CFG_LIST_MAX][CFG_STRLEN];  int nproxy6;
    char direct4[CFG_LIST_MAX][CFG_STRLEN]; int ndirect4;
    char direct6[CFG_LIST_MAX][CFG_STRLEN]; int ndirect6;
    uint32_t skip_uid[CFG_LIST_MAX];        int nskip_uid;

    /* cnip */
    char cnip4_path[CFG_STRLEN];
    char cnip6_path[CFG_STRLEN];
    char cnip4_url[CFG_STRLEN];
    char cnip6_url[CFG_STRLEN];
    int  cnip_auto_update_hours;
};

/* 解析文件；成功 0，失败 -1（错误已打印） */
int config_load(const char *path, struct split_config *cfg);
/* 用默认值填充 */
void config_defaults(struct split_config *cfg);
void config_dump(const struct split_config *cfg);

#endif