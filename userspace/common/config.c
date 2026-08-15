/* SPDX-License-Identifier: GPL-2.0 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h> /* fstat + S_ISDIR（config_load 拒绝目录路径，审查 2026-08） */

#include "log.h"

void config_defaults(struct split_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->tun_device, CFG_STRLEN, "utun");
    cfg->attach_auto = 1;
    cfg->default_verdict = 1;  /* tun */
    cfg->ipv6_classify = 1;

    /* 默认强制代理：fake-ip 段（mihomo 默认 fake-ip-range=198.18.0.1/16，
     * 此处 /15 为超集覆盖，兼容用户自定义的 198.19.0.0/16 等范围） */
    snprintf(cfg->proxy4[0], CFG_STRLEN, "198.18.0.0/15");
    cfg->nproxy4 = 1;

    /* 默认强制直连：内网 / 链路 / CGNAT */
    static const char *i4[] = { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                "169.254.0.0/16", "100.64.0.0/10" };
    for (int i = 0; i < 5; i++) {
        snprintf(cfg->direct4[cfg->ndirect4++], CFG_STRLEN, "%s", i4[i]);
    }
    static const char *i6[] = { "fe80::/10", "fc00::/7", "::1/128" };
    for (int i = 0; i < 3; i++) {
        snprintf(cfg->direct6[cfg->ndirect6++], CFG_STRLEN, "%s", i6[i]);
    }

    cfg->skip_uid[0] = 0;     /* root */
    cfg->skip_uid[1] = 2000;  /* shell */
    cfg->nskip_uid = 2;

    cfg->cnip_auto_update_hours = 24;

    /* CNIP 默认数据源（与 scripts/fetch-cnip.sh 一致；v1.4.2 起多源 fallback，
     * v1.4.3 起为 mihomo 生态权威源 Loyalsoldier/geoip，cn.txt 每日更新）。
     * cn.txt 是 v4+v6 混合文件（实测 v4=4145 / v6=1235 条，纯 CIDR 无注释行），
     * 故 url_v4/v6 指向同一份，加载时按族过滤（见 cnip.c cnip_line_family）。
     * 逗号分隔按序尝试：jsDelivr（大陆可达）优先，raw.githubusercontent 兜底。 */
    snprintf(cfg->cnip4_url, CFG_STRLEN, "%s",
             "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/cn.txt,"
             "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt");
    snprintf(cfg->cnip6_url, CFG_STRLEN, "%s",
             "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/cn.txt,"
             "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt");
}

/* 截掉行尾空白/换行（fgets 会带 \n，这里统一清理） */
static void str_trim_tail(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' ||
                     s[n-1] == ' ' || s[n-1] == '\t'))
        s[--n] = '\0';
}

/* YAML 布尔解析：true/false/yes/no/on/off/1/0（大小写不敏感）。
 * 输入先清首尾空白再比对（容忍 "TRUE " 之类的尾空白，v1.1.9 加固）。
 * v1.4.6（审查）：无法识别的串返回 -1（调用方告警并按 false），不再静默吞错。 */
static int parse_bool(const char *s)
{
    char buf[16];
    size_t n, i;

    if (!s)
        return 0;
    snprintf(buf, sizeof(buf), "%s", s);
    n = strlen(buf);
    while (n > 0 && isspace((unsigned char)buf[n - 1]))
        buf[--n] = '\0';
    for (i = 0; buf[i] && isspace((unsigned char)buf[i]); i++)
        ;
    if (strcasecmp(buf + i, "true") == 0 || strcasecmp(buf + i, "yes") == 0 ||
        strcasecmp(buf + i, "on") == 0 || strcmp(buf + i, "1") == 0)
        return 1;
    if (strcasecmp(buf + i, "false") == 0 || strcasecmp(buf + i, "no") == 0 ||
        strcasecmp(buf + i, "off") == 0 || strcmp(buf + i, "0") == 0)
        return 0;
    return -1; /* 无法识别：调用方 WARN 并按 false 处理 */
}

/* 布尔值解析 + 非法值告警（v1.4.6 审查，与 verdict 白名单校验一致）。
 * 返回 0/1；无法识别时 WARN 并按 false 处理，不再静默。 */
static int parse_bool_checked(const char *what, const char *v)
{
    int b = parse_bool(v);

    if (b < 0) {
        LOG_WARNF("配置 %s 非法布尔值: %s（已按 false 处理）", what, v);
        b = 0;
    }
    return b;
}

/* section 上下文 */
enum { S_NONE, S_IFACES, S_DEFAULT, S_RULES, S_CNIP };

/* section 行若带内联值（如 "default: tun"）会被当作节头吞掉该值——打警告防静默误配。
 * line: 原始行（已去前导空白）；sec: section 名（如 "default"）。 */
static void section_inline_warn(const char *line, const char *sec)
{
    const char *v = line + strlen(sec) + 1;

    while (*v == ' ' || *v == '\t')
        v++;
    if (*v != '\0' && *v != '\n' && *v != '\r')
        LOG_WARNF("配置行 \"%s\"：inline 值不受支持（已忽略），请写成 %s: 节下的 key: value",
                  line, sec);
}

/* 列表声明 key 若带内联值（如 "proxy_cidr4: 1.2.3.0/24"）会被当作列表头吞掉该值——
 * 列表项必须以 "- item" 逐行给出。与 section_inline_warn 同理，显式告警防静默误配
 * （审查修正 v1.2.8：此前列表 key 的冒号后内容被静默丢弃，用户以为加了一条规则）。 */
static void list_key_inline_warn(const char *key, const char *v)
{
    if (v[0])
        LOG_WARNF("配置 %s: 内联值 %s 不受支持（已忽略）——请在其后逐行写 \"- item\"",
                  key, v);
}

/* 判断 `p` 是否是 section 头：节名后必须紧跟 ':'，且冒号后是空白或行尾。
 * 收紧（v1.1.5）：统一并明确"节头 = `name:` 或 `name: 值`"的判据。
 * 此前依赖 `strcmp(p,N':')==0 || strncmp(p,N':',len)==0` 两条分支，虽已能
 * 挡住象 "rules_extra:"（冒号未紧贴节名）这类假节头，但对"冒号后直接跟
 * 内容（如 `rules:camel`，无空格）"会当作节头吞掉整行。此处要求冒号后必须
 * 是空白或行尾，杜绝该脚枪，也让节头判据单一、易读。
 * v1.4.6（审查 P2）：补 '\r'——str_trim_tail 只清 value 不清节头行，Windows
 * 编辑器（CRLF）写的 split.yaml 的 `ifaces:`/`default:`/`rules:`/`cnip:` 会被
 * 整节漏识别（节内 key 变"未知顶层 key" WARN，规则/CNIP 静默失效）。 */
static int is_section(const char *p, const char *name)
{
    size_t n = strlen(name);

    if (strncmp(p, name, n) != 0 || p[n] != ':')
        return 0;
    return p[n + 1] == '\0' || p[n + 1] == '\n' || p[n + 1] == '\r' ||
           p[n + 1] == ' ' || p[n + 1] == '\t';
}

/* 拷贝配置值并检出截断（P3 #3）：CFG_STRLEN=256，超长值被 snprintf 静默截断会让
 * CIDR/URL/路径下游解析失败且无提示（截断后的 CIDR inet_pton 失败、URL 下载失败但
 * 原因归到别处）。解析期显式 WARN，点明"值太长被截断"。 */
static void set_str_checked(char out[CFG_STRLEN], const char *what, const char *v)
{
    int n = snprintf(out, CFG_STRLEN, "%s", v);

    if (n >= CFG_STRLEN)
        LOG_WARNF("配置 %s 值超长（%d>%d）已截断: %.40s…", what, n, CFG_STRLEN - 1, v);
}

/* 列表溢出告警去重：同一列表"一次声明块"内首次溢出告警一次——config_load 进入前
 * 重置 + 列表 key 声明处清除（审查补），避免 100 条 proxy_cidr4 刷 80+ 行相同 WARN，
 * 同时保证规则列表（proxy/direct/skip_uid，声明即重置计数）二次声明后溢出仍会告警——
 * 只按指针去重会让第二次溢出完全静默（恰违"第 17 条起不生效要有提示"初衷）。 */
static const void *s_list_full_warned = NULL;

static void list_full_warn(const void *list, const char *what, const char *item)
{
    size_t l;

    if (s_list_full_warned == list)
        return;
    s_list_full_warned = list;
    /* 项可能超长（与 set_str_checked 截断口径一致），全打会刷屏 */
    l = strlen(item);
    LOG_WARNF("%s 列表已满（上限 %d 项），后续项被忽略: %.*s%s",
              what, CFG_LIST_MAX, (int)(l > 40 ? 40 : l), item, l > 40 ? "…" : "");
}

static void add_str(char list[][CFG_STRLEN], int *n, const char *what, const char *v)
{
    if (*n >= CFG_LIST_MAX) {
        list_full_warn(list, what, v);
        return;
    }
    set_str_checked(list[*n], what, v);
    (*n)++;
}

/* 节内未知 key 告警（P3 #12）：顶层 key（debug/tun_device/attach_auto）只能放文件顶部，
 * 若出现在节内，通用"未知 key"信息会误导（用户以为 debug 已生效）。识别出顶层 key 时
 * 点明正确位置；attach_auto 另合法于 ifaces 节，单独说明。 */
static void section_unknown_key_warn(int section, const char *key)
{
    const char *secname = section == S_IFACES ? "ifaces" :
                          section == S_DEFAULT ? "default" :
                          section == S_RULES ? "rules" : "cnip";

    if (strcmp(key, "attach_auto") == 0)
        LOG_WARNF("%s 下配置 attach_auto 仅支持顶层或 ifaces 节（当前节不支持，已忽略）"
                  "——如需精确挂载请写在 ifaces 节或文件顶部", secname);
    else if (strcmp(key, "debug") == 0 || strcmp(key, "tun_device") == 0)
        LOG_WARNF("%s 下配置 %s 是顶层 key，节内不支持（已忽略）——请移到文件顶部",
                  secname, key);
    else
        LOG_WARNF("%s 下未知配置 key: %s", secname, key);
}

/* 节内标量 key:value；返回 1=已处理，0=未知 key（调用方打 WARN） */
static int handle_scalar(struct split_config *cfg, int section,
                         const char *key, const char *v)
{
    if (section == S_DEFAULT) {
        if (strcmp(key, "verdict") == 0) {
            /* 严格校验（L3）：仅 "direct" 视为直连，"tun" 视为代理（默认值即 TUN）。
             * 此前任何非 "direct" 串（含 "directx"/"tun " 拼写错误）都被静默当 TUN，
             * 误配无告警。显式列白名单，未知值打 WARN。 */
            if (strcasecmp(v, "direct") == 0) {
                cfg->default_verdict = 0;
            } else if (strcasecmp(v, "tun") == 0) {
                cfg->default_verdict = 1;
            } else {
                LOG_WARNF("default 下 verdict 非法值: %s（已按默认 tun 处理）", v);
                cfg->default_verdict = 1;
            }
            return 1;
        }
        if (strcmp(key, "ipv6") == 0) {
            cfg->ipv6_classify = parse_bool_checked("default.ipv6", v);
            return 1;
        }
    }
    return 0;
}

int config_load(const char *path, struct split_config *cfg)
{
    FILE *fp;
    char line[512];
    int section = S_NONE;
    char cur_list = 0; /* 0:无 1:attach 2:exclude 3:proxy4 4:proxy6 5:direct4 6:direct6 7:skip_uid */
    /* v1.2.9：rules 节列表声明标志——列表 key 是"覆盖式"（声明即清零默认计数），
     * 若声明了却没有任何 "- item"（空列表/仅注释），默认规则会被静默清空
     * （如默认 fake-ip 段 198.18.0.0/15），解析结束时据此告警。 */
    int declared_proxy4 = 0, declared_proxy6 = 0;
    int declared_direct4 = 0, declared_direct6 = 0;
    int declared_skip_uid = 0;

    /* 先打开文件再写默认值（v1.1.4 修正）：此前 config_defaults 在 fopen 之前执行，
     * 文件打不开时 cfg 已被重置成默认值——daemon reload 的"失败沿用内存配置"
     * 语义被破坏（实际重放的是默认规则，用户自定义 proxy/direct/skip_uid 全丢）。 */
    fp = fopen(path, "r");
    if (!fp) {
        LOG_ERRORF("无法打开配置 %s: %s", path, strerror(errno));
        return -1;
    }
    /* 审查（2026-08）：fopen 对"目录路径"在 Linux 上同样成功（目录可按读打开），
     * 随后首个 fgets 报 EISDIR、解析循环不跑——函数返回 0 且 cfg 已被重置为默认值，
     * 静默绕过 v1.1.4 修的"失败沿用内存配置"语义（目录当配置 = 规则全丢且无提示）。
     * 显式拒绝目录，走统一失败路径。 */
    {
        struct stat st;

        if (fstat(fileno(fp), &st) == 0 && S_ISDIR(st.st_mode)) {
            LOG_ERRORF("配置路径是目录而非文件: %s", path);
            fclose(fp);
            return -1;
        }
    }
    s_list_full_warned = NULL; /* 列表溢出告警只报一次（见 list_full_warn） */
    config_defaults(cfg);

    while (fgets(line, sizeof(line), fp)) {
        /* P3 #3：fgets 填满缓冲且末尾无 '\n' = 该行超过 511 字符被拆断，剩余部分会被
         * 当成新行解析（静默错位）。检出后告警并排干该行剩余部分。 */
        {
            size_t llen = strlen(line);

            if (llen >= sizeof(line) - 1 && line[llen - 1] != '\n') {
                LOG_WARNF("配置行过长（>%zu 字符），已按前 %zu 字符处理，其余丢弃: %.48s…",
                          sizeof(line) - 1, sizeof(line) - 1, line);
                while (fgets(line, sizeof(line), fp) && !strchr(line, '\n'))
                    ;
                continue;
            }
        }
        char *p = line, *c;

        /* 仅把"行首或空白前"的 # 当注释：值内嵌 #（如 URL fragment）不截断 */
        for (c = line; *c; c++) {
            if (*c == '#' && (c == line || c[-1] == ' ' || c[-1] == '\t')) {
                *c = '\0';
                break;
            }
        }
        while (*p && isspace(*p)) p++;
        if (*p == '\0')
            continue;

        /* section 行 */
        if (is_section(p, "ifaces")) {
            section = S_IFACES; cur_list = 0;
            if (p[7] != '\0')
                section_inline_warn(p, "ifaces");
            continue;
        }
        if (is_section(p, "default")) {
            section = S_DEFAULT; cur_list = 0;
            if (p[8] != '\0')
                section_inline_warn(p, "default");
            continue;
        }
        if (is_section(p, "rules")) {
            section = S_RULES; cur_list = 0;
            if (p[6] != '\0')
                section_inline_warn(p, "rules");
            continue;
        }
        if (is_section(p, "cnip")) {
            section = S_CNIP; cur_list = 0;
            if (p[5] != '\0')
                section_inline_warn(p, "cnip");
            continue;
        }

        /* 顶层简单 key: value（未知 key 打 WARN，防拼写错误被静默吞掉） */
        if (section == S_NONE) {
            char *sp = strchr(p, ':');

            if (!sp) {
                LOG_WARNF("无法识别的配置行（缺少 ':'）: %s", p);
                continue;
            }
            *sp = '\0';
            /* P3 #4：key 冒号前带空格（如 `debug : true`）不 trim 会静默不匹配 */
            str_trim_tail(p);
            if (p[0] == '\0') {
                LOG_WARNF("配置行缺少 key（冒号前为空）: %s", line);
                continue;
            }
            char *v = sp + 1; while (*v && isspace(*v)) v++;
            str_trim_tail(v);
            if (strcmp(p, "debug") == 0) cfg->debug = parse_bool_checked("debug", v);
            else if (strcmp(p, "tun_device") == 0) set_str_checked(cfg->tun_device, "tun_device", v);
            else if (strcmp(p, "attach_auto") == 0) cfg->attach_auto = parse_bool_checked("attach_auto", v);
            else LOG_WARNF("未知顶层配置 key: %s", p);
            continue;
        }

        /* 列表项 - item */
        if (*p == '-') {
            char *item = p + 1; while (*item && isspace(*item)) item++;
            str_trim_tail(item);
            switch (cur_list) {
            case 1: add_str(cfg->attach_list, &cfg->nattach, "attach_list", item); break;
            case 2: add_str(cfg->exclude,   &cfg->nexclude,  "exclude",     item); break;
            case 3: add_str(cfg->proxy4,    &cfg->nproxy4,   "proxy_cidr4", item); break;
            case 4: add_str(cfg->proxy6,    &cfg->nproxy6,   "proxy_cidr6", item); break;
            case 5: add_str(cfg->direct4,   &cfg->ndirect4,  "direct_cidr4",item); break;
            case 6: add_str(cfg->direct6,   &cfg->ndirect6,  "direct_cidr6",item); break;
            case 7: {
                char *endp = NULL;
                unsigned long u;

                u = strtoul(item, &endp, 10);
                /* "abc" 会被 strtoul 解析成 0（=root），显式拒绝非法/溢出值；
                 * 基数固定 10，避免 "010" 被当八进制（v1.1.8 审查加固）。 */
                if (endp != item && *endp == '\0' && u <= UINT32_MAX) {
                    if (cfg->nskip_uid < CFG_LIST_MAX)
                        cfg->skip_uid[cfg->nskip_uid++] = (uint32_t)u;
                    else
                        list_full_warn(cfg->skip_uid, "skip_uid", item);
                } else {
                    LOG_WARNF("skip_uid 非法值: %s（已忽略）", item);
                }
                break;
            }
            default:
                /* P3 #5：孤儿列表项——未声明任何列表 key 时（cur_list==0）的 `- item`
                 * 被静默丢弃，用户以为加了一条规则实际没生效 */
                LOG_WARNF("孤立的列表项（未处于任何列表内，已忽略）: %s", item);
                break;
            }
            continue;
        }

        /* 节内 key: value（既是字段也是列表声明） */
        {
            char *sp = strchr(p, ':');
            if (!sp)
                continue;
            *sp = '\0';
            /* P3 #4：key 冒号前带空格（如 `proxy_cidr4 :`）不 trim 会静默不匹配 */
            str_trim_tail(p);
            char *v = sp + 1; while (*v && isspace(*v)) v++;
            str_trim_tail(v);

            if (section == S_IFACES) {
                if (strcmp(p, "attach_auto") == 0) { cfg->attach_auto = parse_bool_checked("ifaces.attach_auto", v); cur_list = 0; }
                else if (strcmp(p, "attach_list") == 0) { cur_list = 1; s_list_full_warned = NULL; list_key_inline_warn(p, v); }
                else if (strcmp(p, "exclude") == 0) { cur_list = 2; s_list_full_warned = NULL; list_key_inline_warn(p, v); }
                else { section_unknown_key_warn(S_IFACES, p); cur_list = 0; }
                continue;
            }
            if (section == S_DEFAULT) {
                if (!handle_scalar(cfg, S_DEFAULT, p, v))
                    section_unknown_key_warn(S_DEFAULT, p);
                continue;
            }
            if (section == S_RULES) {
                if (strcmp(p, "proxy_cidr4") == 0)  { cfg->nproxy4  = 0; cur_list = 3; declared_proxy4 = 1; s_list_full_warned = NULL; list_key_inline_warn(p, v); }
                else if (strcmp(p, "proxy_cidr6") == 0)  { cfg->nproxy6  = 0; cur_list = 4; declared_proxy6 = 1; s_list_full_warned = NULL; list_key_inline_warn(p, v); }
                else if (strcmp(p, "direct_cidr4") == 0) { cfg->ndirect4 = 0; cur_list = 5; declared_direct4 = 1; s_list_full_warned = NULL; list_key_inline_warn(p, v); }
                else if (strcmp(p, "direct_cidr6") == 0) { cfg->ndirect6 = 0; cur_list = 6; declared_direct6 = 1; s_list_full_warned = NULL; list_key_inline_warn(p, v); }
                else if (strcmp(p, "skip_uid") == 0)     { cfg->nskip_uid = 0; declared_skip_uid = 1; cur_list = 7; s_list_full_warned = NULL; list_key_inline_warn(p, v); }
                /* v1.3.1（审查修复）：未知 key 不清 cur_list 会让其后的 "- item" 行
                 * 被并入上一个列表（静默误分流）。未知 key 一律复位当前列表。 */
                else { section_unknown_key_warn(S_RULES, p); cur_list = 0; }
                continue;
            }
            if (section == S_CNIP) {
                if (strcmp(p, "path_v4") == 0)
                    set_str_checked(cfg->cnip4_path, "cnip.path_v4", v);
                else if (strcmp(p, "path_v6") == 0)
                    set_str_checked(cfg->cnip6_path, "cnip.path_v6", v);
                else if (strcmp(p, "url_v4") == 0)
                    set_str_checked(cfg->cnip4_url, "cnip.url_v4", v);
                else if (strcmp(p, "url_v6") == 0)
                    set_str_checked(cfg->cnip6_url, "cnip.url_v6", v);
                else if (strcmp(p, "auto_update_hours") == 0) {
                    /* v1.1.9：atoi 对 "24abc"/负值静默吞错 → 改用 strtol+endptr 严格校验。
                     * 审查（2026-08 P2）：非法值用 break 会直接跳出整个解析 while 循环，
                     * 静默丢弃该行之后的所有配置行仍返成功（如 path_v6/整个 rules 节）。
                     * 改 continue（仅跳过本行、保留默认值）；endp==v 检出空值——strtol("")
                     * 返 0 且校验通过，空 `auto_update_hours:` 会被静默当成 0=禁用自动更新。 */
                    char *endp = NULL;
                    long u;

                    errno = 0;
                    u = strtol(v, &endp, 10);
                    if (errno != 0 || !endp || endp == v || *endp != '\0' ||
                        u < 0 || u > INT_MAX) {
                        LOG_WARNF("cnip 下 auto_update_hours 非法值: %s（已忽略）", v);
                        continue;
                    }
                    cfg->cnip_auto_update_hours = (int)u;
                }
                else section_unknown_key_warn(S_CNIP, p);
                continue;
            }
        }
    }

    fclose(fp);

    /* v1.2.9：空列表告警——声明了列表 key 但最终 0 项（空列表/仅注释），
     * 默认规则已被"覆盖式"清零且用户无感知。fake-ip 段丢失后若同时
     * default 节 verdict 配成 direct，mihomo fake-ip 流量会被直连断网。 */
    if (declared_proxy4 && cfg->nproxy4 == 0)
        LOG_WARNF("rules: 声明了 proxy_cidr4 但无列表项，默认 fake-ip 段 198.18.0.0/15 已被清空"
                  "（如需保留请补 \"- 198.18.0.0/15\"）");
    if (declared_proxy6 && cfg->nproxy6 == 0)
        LOG_WARNF("rules: 声明了 proxy_cidr6 但无列表项，代理 v6 规则为空");
    if (declared_direct4 && cfg->ndirect4 == 0)
        LOG_WARNF("rules: 声明了 direct_cidr4 但无列表项，默认内网直连段（10/8 等）已被清空");
    if (declared_direct6 && cfg->ndirect6 == 0)
        LOG_WARNF("rules: 声明了 direct_cidr6 但无列表项，默认 v6 直连段（fe80::/10 等）已被清空");
    /* v1.4.6（审查）：非空覆盖同样告警——声明 direct_cidr4/6 会连默认内网/链路/CGNAT 段一起
     * 清空（config_defaults 种下的 10/8、172.16/12、192.168/16、169.254/16、100.64/10 与
     * fe80::/10、fc00::/7、::1/128）。用户"只加一条"时其余私网段静默丢失 → 落到默认代理，
     * 与配置注释"默认已含 rfc1918"相悖。纯诊断，不改行为。 */
    if (declared_direct4 && cfg->ndirect4 > 0)
        LOG_WARNF("rules: 已声明 direct_cidr4（%d 条），默认内网直连段（10/8、172.16/12、"
                  "192.168/16、169.254/16、100.64/10）已被清空——如需保留请连同默认段写入",
                  cfg->ndirect4);
    if (declared_direct6 && cfg->ndirect6 > 0)
        LOG_WARNF("rules: 已声明 direct_cidr6（%d 条），默认 v6 直连段（fe80::/10、fc00::/7、"
                  "::1/128）已被清空——如需保留请连同默认段写入", cfg->ndirect6);
    /* P3 #2（审查）：skip_uid 空列表清默认——声明 skip_uid 会清零 config_defaults 种下的
     * root(0)/shell(2000)，空列表时这两个默认被静默清掉（root/shell 不再绕过代理）。
     * 只对空列表告警；非空声明是显式列 UID 的常规用法，不再多告警（与 direct 非空告警
     * 的"只加一条丢其它"脚枪不同，skip_uid 常整体替换）。 */
    if (declared_skip_uid && cfg->nskip_uid == 0)
        LOG_WARNF("rules: 声明了 skip_uid 但无列表项，默认 root(0)/shell(2000) 已被清空"
                  "——root/shell 将不再绕过代理");

    /* v1.4.1（功能冲突审查）：跨字段静默失效告警——配置项叠加时一方被另一方静默吞掉
     * （行为无提示），显式 WARN 防"以为生效"：
     *  (a) attach_auto=on 时 iface_plan 走物理网卡分支，attach_list 被完全忽略（互斥）；
     *  (b) ipv6=false 时 policy 第 2 步短路，proxy_cidr6/direct_cidr6/CNIP6 全不生效
     *      （proxy6 是"意图相反"的真冲突；direct6/CNIP6 结果仍直连、属冗余不告警）。 */
    if (cfg->attach_auto && cfg->nattach > 0)
        LOG_WARNF("ifaces: attach_auto=on 时 attach_list 被忽略（已配 %d 个接口不生效）"
                  "——两者互斥，如需精确挂载请设 attach_auto: false", cfg->nattach);
    if (!cfg->ipv6_classify && cfg->nproxy6 > 0)
        LOG_WARNF("default: ipv6=false 但 rules 配置了 proxy_cidr6（%d 条）——v6 一律直连，"
                  "v6 代理规则不生效，如需代理 v6 请设 ipv6: true", cfg->nproxy6);

    return 0;
}

void config_dump(const struct split_config *cfg)
{
    LOG_INFOF("tun_device=%s attach_auto=%d", cfg->tun_device, cfg->attach_auto);
    LOG_INFOF("default_verdict=%s ipv6_classify=%d",
              cfg->default_verdict ? "tun" : "direct", cfg->ipv6_classify);
    LOG_INFOF("skip_uid=%d proxy4=%d direct4=%d cnip4=%s",
              cfg->nskip_uid, cfg->nproxy4, cfg->ndirect4,
              cfg->cnip4_path[0] ? cfg->cnip4_path : "(未配置)");
    LOG_INFOF("cnip_auto_update_hours=%d url_v4=%s",
              cfg->cnip_auto_update_hours,
              cfg->cnip4_url[0] ? cfg->cnip4_url : "(未配置)");
}