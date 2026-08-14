/* SPDX-License-Identifier: GPL-2.0 */
#include "netlink.h"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h> /* struct fib_rule_hdr / FR_ACT_TO_TBL / FRA_* */
#include <sys/socket.h>
#include <sys/uio.h>     /* struct iovec（iface_watch_poll 的 recvmsg，v1.2.8） */
#include <sys/time.h> /* struct timeval（SO_RCVTIMEO） */
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "log.h"

int iface_is_physical(const struct iface *i)
{
    /* 排除虚拟/特殊接口（前缀匹配，含 "utun" 这类以 ut 开头的 tun 变体）。
     * 注意：不能只匹配 "tun"，因为 mihomo 的 tun 设备常叫 utun/nic/tun0 等，
     * 需匹配 "utun" 与 "tun" 前缀，否则 utun 会被当物理接口挂载 →
     * mihomo 回写流量再次进 eBPF → 回环 + parse_err。 */
    static const char *exclude[] = {
        "lo", "tun", "utun", "tap", "dummy", "rmnet_usb", "vsock",
        "ip6tnl", "gretap", "erspan", "sit", "br", "wg",
        "ifb", "gre", "ip6gre", "ip_vti", "ip6_vti", "tunl", "wifi-aware",
        "p2p", "r_rmnet", "veth", "docker", "virbr",
        /* v1.1.5：rmnet_ipa0 是 Qualcomm IPA 聚合口（type 519 RAWIP），
         * 其帧带 RMNET MAP 封装头（非裸 IP），且数据面实际走
         * rmnet_data* 子接口——挂载它只会产生 parse_err 噪音
         * （真机实测 tcpdump filter 都无法匹配其帧）。 */
        "rmnet_ipa", NULL
    };
    int k;

    if (!i || i->ifindex <= 0)
        return 0;
    if (!(i->flags & 0x1))  /* IFF_UP */
        return 0;

    for (k = 0; exclude[k]; k++) {
        if (strncmp(i->name, exclude[k], strlen(exclude[k])) == 0)
            return 0;
    }
    /* 常见物理：Ethernet(1)、WLAN(803)、PPP(512)、rmnet_data(519)；
       这里用"非虚拟类"白名单+名字排除的保守策略 */
    return 1;
}

int iface_index_by_name(const char *name)
{
    struct iface_list list;
    int k;

    if (iface_scan(&list) < 0)
        return -1;
    for (k = 0; k < list.count; k++) {
        if (strcmp(list.items[k].name, name) == 0)
            return list.items[k].ifindex;
    }
    return -1;
}

/*
 * 路由接管检测（v1.1.3）：mihomo auto-route:true 时会在 tun 上挂 default 路由
 * （`default dev utun table 2022`），此时物理网卡 egress 的 eBPF 完全看不到
 * 流量，CNIP/规则分流失效（真机教训：direct_cn 恒 0 却无任何报错）。
 *
 * 纯 netlink，不依赖 iproute2；每 10s 调用一次（<1ms）。
 *
 * 判定（v1.1.8 收紧，消除"非选中表 default 路由"误报）：
 *   1. 路由侧：dump RTM_GETROUTE（v4+v6），找 `default dev tun` 及其**所在路由表**
 *      （RTA_TABLE，缺省即 main）。
 *      - 在 main 表 → 一定被内核隐式规则 `from all lookup main`(pref 32766) 命中，
 *        全部流量进 tun = 确定接管，直接返回 1。
 *      - 在非 main 表 → 仅记录该表 id，不直接判定（路由存在≠流量真被导进去）。
 *   2. 规则侧：仅当记录到非 main 表后，dump RTM_GETRULE（v4+v6），看是否存在
 *      "无条件把全部流量导向该表"的规则（action==FR_ACT_TO_TBL 且无 dst/src 前缀、
 *      源接口、fwmark/出口、UID/端口、suppress_prefixlength 等选择条件）。
 *      存在 → 返回 1。
 *   这样 mihomo 旧的 `from all lookup 2022` 接管会被抓住，而仅仅在无人引用的私有表
 *   里残留 `default dev utun`（或带 fwmark 精确匹配的规则）不会误报。
 *
 * 返回：1=被接管（需告警） 0=正常 -1=检测失败（netlink 错误/超时；调用方应跳过本轮，避免误报）。
 */

/* 一条 default-via-tun 路由所在的路由表；RTA_TABLE 缺省即 main（内核 dump 对 main 表不吐该属性）。
 * v1.2.3 补充：优先 RTA_TABLE（非 main 大表；table id >255 时内核必须走属性），
 * 读不到再回退 `rtm->rtm_table` 字段（u8，兼容部分内核只写该字段的小表场景）。 */
static uint32_t default_route_table(struct rtmsg *rtm, int payload)
{
    struct rtattr *rta;

    for (rta = (struct rtattr *)((char *)rtm + sizeof(*rtm));
         RTA_OK(rta, payload); rta = RTA_NEXT(rta, payload)) {
        if (rta->rta_type == RTA_TABLE && RTA_PAYLOAD(rta) >= (int)sizeof(uint32_t)) {
            uint32_t t;

            memcpy(&t, RTA_DATA(rta), sizeof(t));
            return t;
        }
    }
    /* RTA_TABLE 缺失时回退到 rtmsg 的 rtm_table 字段（u8；0=RT_TABLE_UNSPEC）。 */
    if (rtm->rtm_table != 0 && rtm->rtm_table != RT_TABLE_MAIN)
        return (uint32_t)rtm->rtm_table;
    return RT_TABLE_MAIN;
}

/* 判一条 ip rule（RTM_NEWRULE）是否会把"全部流量"无条件导向表 tbl。
 * 必须 action==FR_ACT_TO_TBL、无前缀/接口/fwmark/uid/端口等选择条件。
 *
 * v1.2.3（真机修复，WSL/Android 内核实测）：内核 dump 对每条规则**恒带**
 * `FRA_SUPPRESS_PREFIXLEN`（值 0xFFFFFFFF=-1，表示"未设置"）与 `FRA_PROTOCOL`
 * （规则来源元数据）、`FRA_PRIORITY`（优先级）——此前把它们当"选择条件"直接
 * return 0，导致真正的无条件劫持（`from all lookup 2022`）被漏判 → hijack=0 假阴性。
 *   1. suppress 类属性：只有**值 != -1**（真设置了抑制）才算抑制条件；
 *   2. FRA_PROTOCOL / FRA_PRIORITY / FRA_FLOW / FRA_PAD：元数据/优先级，不匹配流量，忽略；
 *   3. 真正的匹配条件（dst/src/接口/fwmark/uid/端口/l3mdev/dscp/flowlabel）→ return 0。
 * 注：iif/oif/l3mdev 经 FRA_* 属性传递（fib_rule_hdr 无这些字段，编译已验证）。 */
static int rule_steals_table(struct nlmsghdr *nlh, uint32_t tbl)
{
    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)NLMSG_DATA(nlh);
    int payload = NLMSG_PAYLOAD(nlh, sizeof(struct fib_rule_hdr));
    struct rtattr *rta;
    uint32_t rtab = (uint32_t)frh->table;

    if (frh->action != FR_ACT_TO_TBL)
        return 0;
    /* 前缀条件：dst_len/src_len（rule 的 to/from 前缀）/tos 非 0 → 只匹配部分流量 */
    if (frh->dst_len != 0 || frh->src_len != 0 || frh->tos != 0)
        return 0;
    for (rta = (struct rtattr *)((char *)frh + sizeof(*frh));
         RTA_OK(rta, payload); rta = RTA_NEXT(rta, payload)) {
        switch (rta->rta_type) {
        case FRA_TABLE:
            if (RTA_PAYLOAD(rta) >= (int)sizeof(uint32_t))
                memcpy(&rtab, RTA_DATA(rta), sizeof(rtab));
            continue;
        /* suppress 类：内核 dump 未设置时恒带值 0xFFFFFFFF（-1）占位，
         * 只有值 != -1（真正设置了抑制）才算是选择条件 */
        case FRA_SUPPRESS_PREFIXLEN:
        case FRA_SUPPRESS_IFGROUP:
            if (RTA_PAYLOAD(rta) >= (int)sizeof(uint32_t)) {
                uint32_t v = 0;
                memcpy(&v, RTA_DATA(rta), sizeof(v));
                if (v != (uint32_t)-1)
                    return 0;
            }
            continue;
        /* 元数据/优先级：不匹配流量，忽略（内核恒带 FRA_PROTOCOL） */
        case FRA_PROTOCOL:
        case FRA_PRIORITY:
        case FRA_FLOW:
        case FRA_PAD:
            continue;
        /* 任一真正的匹配条件出现 → 不是"全接管"，不算 */
        case FRA_DST:
        case FRA_SRC:
        case FRA_IIFNAME:
        case FRA_GOTO:
        case FRA_FWMARK:
        case FRA_FWMASK:
        case FRA_OIFNAME:
        case FRA_UID_RANGE:
        case FRA_IP_PROTO:
        case FRA_SPORT_RANGE:
        case FRA_DPORT_RANGE:
        case FRA_L3MDEV:
        case FRA_DSCP:
        case FRA_FLOWLABEL:
        case FRA_FLOWLABEL_MASK:
            return 0;
        default:
            continue;
        }
    }
    return rtab == tbl;
}

/* dump 一族 ip rule，查是否存在把全部流量导向 tables[] 中任一张表的规则。
 * 返回：1=命中 0=未命中（dump 完整） -1=检测失败（send/recv 失败、畸形报文）。 */
static int rule_dump_targets_any(int fd, int fam,
                                 const uint32_t *tables, int ntab)
{
    struct {
        struct nlmsghdr      nlh;
        struct fib_rule_hdr  frh;
    } req;
    char buf[65536];
    int len, off, j;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
    req.nlh.nlmsg_type = RTM_GETRULE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.frh.family = (unsigned char)fam;

    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0)
        return -1;
    for (;;) {
        struct nlmsghdr *nlh;

        len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0)
            return -1;
        for (off = 0; (size_t)off + sizeof(struct nlmsghdr) <= (size_t)len;
             off += NLMSG_ALIGN(nlh->nlmsg_len)) {
            nlh = (struct nlmsghdr *)(buf + off);
            if (nlh->nlmsg_len < sizeof(struct nlmsghdr) ||
                (size_t)off + NLMSG_ALIGN(nlh->nlmsg_len) > (size_t)len)
                return -1;
            if (nlh->nlmsg_type == NLMSG_DONE)
                return 0;
            /* NLMSG_ERROR：内核对 rule dump 请求报错（EPERM/命名空间损坏/畸形
             * 报文等）。v1.2.8（审查修复）：此前按"未命中"返回 0——真错误被吞成
             * hijack=0 假阴性（静默漏报路由接管）。与路由侧/iface_scan 口径统一：
             * 按检测失败返回 -1，daemon 跳过本轮（不误报、不吞错）。
             * 注：调用方只传合法 family（AF_INET/AF_INET6），不存在"非法 family
             * 只回 ERROR 不发 DONE"的旧顾虑。 */
            if (nlh->nlmsg_type == NLMSG_ERROR)
                return -1;
            if (nlh->nlmsg_type != RTM_NEWRULE)
                continue;
            for (j = 0; j < ntab; j++) {
                if (rule_steals_table(nlh, tables[j]))
                    return 1;
            }
        }
    }
}

int route_tun_hijacked(int tun_ifindex)
{
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
    } req;
    struct sockaddr_nl sa;
    char buf[65536];
    /* 非 main 表中含 default-via-tun 的表 id 集合（v1.2.7：16→64，超限按检测失败处理
     * 防漏报接管，见 route 收集处注释） */
    enum { HIJACK_TABLES_MAX = 64 };
    uint32_t tables[HIJACK_TABLES_MAX];
    int ntab = 0;
    int fd, len, off;
    int hijacked = 0;

    if (tun_ifindex <= 0)
        return 0;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    /* 防御：recv 必须有超时。正常 dump 以 NLMSG_DONE 收尾，但极端情况
     * （内核异常/命名空间损坏）可能收不到——daemon 主循环是同步调用本函数，
     * 永久阻塞=整个 splitd 停摆（v1.1.3 审查加固）。
     * F2（2026-08 调度审查）：超时从 2s 收紧到 300ms——本函数在主循环同步跑
     * （10s 节流），最坏 v4+v6 路由 dump + 规则 dump 共 4 个阶段 × 超时 = 8s 停摆，
     * 期间 tun_sync / CNIP fork / ctl 全冻结。正常 dump <1ms，300ms 余量充足；
     * 异常时把主循环停摆压到 ~1.2s。 */
    {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 };

        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    /* v4 与 v6 各 dump 一次（AF_UNSPEC 不保证返回全部）。
     * 注意：必须显式枚举 {AF_INET, AF_INET6}，不能 for(fam=AF_INET; fam<=AF_INET6; fam++)
     * ——中间值全是无效 family（AX25/APPLETALK...），内核对这些值只回 NLMSG_ERROR
     * 且**不发 NLMSG_DONE**，同步 recv 会永久阻塞，卡死 daemon 主循环（v1.1.3 审查发现）。 */
    {
        static const int fams[] = { AF_INET, AF_INET6 };
        int nfam = (int)(sizeof(fams) / sizeof(fams[0]));
        int i;

        /* 第一趟：路由 */
        for (i = 0; i < nfam && !hijacked; i++) {
            int fam = fams[i];

            memset(&req, 0, sizeof(req));
            req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
            req.nlh.nlmsg_type = RTM_GETROUTE;
            req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
            req.rtm.rtm_family = (unsigned char)fam;

            if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
                /* send 失败 = 检测失败（区别于 "未接管"）。此前 goto out 会把
                 * hijacked=-1 经 `return hijacked ? 1 : 0` 误判成 1 → 假报"路由被
                 * 接管"。改走 out_err 返回 -1，与 recv 失败路径语义一致。 */
                goto out_err;
            }

            for (;;) {
                struct nlmsghdr *nlh;

                len = recv(fd, buf, sizeof(buf), 0);
                if (len < 0)
                    goto out_err;   /* 超时/错误：检测失败，返回 -1（不吞成 0） */
                for (off = 0; (size_t)off + sizeof(struct nlmsghdr) <= (size_t)len;
                     off += NLMSG_ALIGN(nlh->nlmsg_len)) {
                    struct rtmsg *rtm;
                    int payload;
                    int oif = -1;

                    nlh = (struct nlmsghdr *)(buf + off);
                    if (nlh->nlmsg_len < sizeof(struct nlmsghdr) ||
                        (size_t)off + NLMSG_ALIGN(nlh->nlmsg_len) > (size_t)len)
                        goto out_err; /* 畸形报文按检测失败处理，不吞成"未接管" */
                    if (nlh->nlmsg_type == NLMSG_DONE)
                        goto next_family;
                    /* NLMSG_ERROR：内核对该 family 的 dump 请求报错（异常/命名空间
                     * 损坏等）。与 iface_scan 口径一致按检测失败处理，返回 -1——
                     * 此前 continue 会静默吞掉，仅靠 2s SO_RCVTIMEO 兜底，误判
                     * "未接管"或拖慢本轮检测（L1）。 */
                    if (nlh->nlmsg_type == NLMSG_ERROR)
                        goto out_err;
                    if (nlh->nlmsg_type != RTM_NEWROUTE)
                        continue;

                    rtm = (struct rtmsg *)NLMSG_DATA(nlh);
                    /* default 路由：目标前缀长度为 0 */
                    if (rtm->rtm_dst_len != 0)
                        continue;
                    payload = NLMSG_PAYLOAD(nlh, sizeof(struct rtmsg));
                    /* v1.2.3（真机修复）：RTA_OIF 的遍历必须用独立 attrlen——
                     * RTA_NEXT 会递减长度，若直接复用 payload，循环结束后 payload
                     * 耗尽（0），下方 default_route_table 用残值遍历 RTA_OK 立即 false，
                     * 读不到 RTA_TABLE → 恒返回 main → mihomo 重载残留的
                     * `default dev utun table 2022`（非 main 表）被误判为 main 表
                     * 劫持 → hijack=1 假报。iproute2 显示 table 2022 正是因为它
                     * 单独重算 attr 长度。 */
                    {
                        int attrlen = payload;
                        struct rtattr *rta2;

                        for (rta2 = (struct rtattr *)((char *)rtm + sizeof(*rtm));
                             RTA_OK(rta2, attrlen); rta2 = RTA_NEXT(rta2, attrlen)) {
                            if (rta2->rta_type == RTA_OIF &&
                                RTA_PAYLOAD(rta2) >= (int)sizeof(int)) {
                                /* RTA_DATA 不保证对齐，用 memcpy 防 ARM 未对齐陷阱 */
                                memcpy(&oif, RTA_DATA(rta2), sizeof(oif));
                            }
                        }
                    }
                    if (oif != tun_ifindex)
                        continue;

                    /* default dev tun：看它落在哪张路由表 */
                    {
                        uint32_t t = default_route_table(rtm, payload);
                        int dup = 0, k2;

                        if (t == RT_TABLE_MAIN) {
                            /* main 表的 default 恒被 `from all lookup main` 命中 */
                            hijacked = 1;
                            goto out;
                        }
                        for (k2 = 0; k2 < ntab; k2++)
                            if (tables[k2] == t) { dup = 1; break; }
                        if (!dup) {
                            /* v1.2.7（审查 M2）：表 id 集合超出容量时无法完整校验
                             * "全部流量被导进某张表"——按检测失败返回 -1（daemon 跳过
                             * 本轮、status 显示 -1），避免漏报路由接管（假阴性）。 */
                            if (ntab >= HIJACK_TABLES_MAX) {
                                LOG_WARNF("default-via-tun 私有路由表超过 %d 张，本轮接管检测无法完成",
                                          HIJACK_TABLES_MAX);
                                goto out_err;
                            }
                            tables[ntab++] = t;
                        }
                    }
                }
            }
next_family: ;
        }

        /* 第二趟：仅当存在非 main 表 default-via-tun 时才需要查规则。
         * 找不到任何"无条件指向该表的规则"→ 流量其实没被导进 tun，不算接管。 */
        for (i = 0; i < nfam && !hijacked && ntab > 0; i++) {
            int r = rule_dump_targets_any(fd, fams[i], tables, ntab);

            if (r < 0)
                goto out_err; /* 规则 dump 失败：无法确认是否接管，按检测失败返回 -1 */
            if (r == 1)
                hijacked = 1;
        }
    }
out:
    close(fd);
    return hijacked ? 1 : 0;
out_err:
    close(fd);
    return -1;
}

int iface_scan(struct iface_list *list)
{
    struct {
        struct nlmsghdr  nlh;
        struct ifinfomsg ifm;
    } req;
    struct sockaddr_nl sa;
    char buf[65536];
    int fd, len, off;
    struct nlmsghdr *nlh;

    memset(list, 0, sizeof(*list));
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return -1;

    /* netlink 必须 bind 才能收到内核应答 */
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }

    /* 防御：recv 必须有超时（与 route_tun_hijacked 一致，v1.1.3 加固）。
     * 正常 dump 以 NLMSG_DONE 收尾，但内核异常/命名空间损坏时可能收不到——
     * 本函数被 daemon 的 tun_sync 每秒调用 + 每次网络事件调用，
     * 永久阻塞=整个 splitd 停摆。
     * F2（2026-08 调度审查）：超时从 2s 收紧到 300ms——比 route_tun_hijacked
     * 更频繁（每 1s 心跳都调），2s 超时在 netlink 异常时让主循环每轮停摆 2s；
     * 接口 dump <1ms，300ms 余量充足，超时按失败处理（调用方保持 map 原值，不误清）。 */
    {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 300000 };

        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.ifm.ifi_family = AF_UNSPEC;

    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        close(fd);
        return -1;
    }

    for (;;) {
        len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0) {
            close(fd);
            return -1;
        }
        for (off = 0; (size_t)off + sizeof(struct nlmsghdr) <= (size_t)len; off += NLMSG_ALIGN(nlh->nlmsg_len)) {
            nlh = (struct nlmsghdr *)(buf + off);
            if (nlh->nlmsg_len < sizeof(struct nlmsghdr) ||
                (size_t)off + NLMSG_ALIGN(nlh->nlmsg_len) > (size_t)len)
                goto done;
            if (nlh->nlmsg_type == NLMSG_DONE)
                goto done;
            if (nlh->nlmsg_type == RTM_NEWLINK) {
                struct ifinfomsg *ifm = (struct ifinfomsg *)NLMSG_DATA(nlh);
                int attrs_off;
                struct rtattr *rta;

                if (list->count >= IFACE_MAX) {
                    LOG_WARNF("iface 扫描达到上限 %d，列表可能被截断", IFACE_MAX);
                    goto done;
                }
                attrs_off = NLMSG_PAYLOAD(nlh, sizeof(struct ifinfomsg));
                for (rta = (struct rtattr *)((char *)ifm + sizeof(*ifm));
                     RTA_OK(rta, attrs_off); rta = RTA_NEXT(rta, attrs_off)) {
                    if (rta->rta_type == IFLA_IFNAME) {
                        /* RTA_DATA 不保证 NUL 结尾：按 attr 长度有界拷贝 */
                        int nlen = rta->rta_len - RTA_LENGTH(0);
                        const char *nm = (const char *)RTA_DATA(rta);

                        if (nlen > IFACE_NAME_MAX - 1)
                            nlen = IFACE_NAME_MAX - 1;
                        memcpy(list->items[list->count].name, nm, (size_t)nlen);
                        list->items[list->count].name[nlen] = '\0';
                    }
                }
                list->items[list->count].ifindex = ifm->ifi_index;
                list->items[list->count].type = ifm->ifi_type;
                list->items[list->count].flags = ifm->ifi_flags;
                if (list->items[list->count].name[0])
                    list->count++;
            }
        }
    }
done:
    close(fd);
    return 0;
}

int iface_watch_open(void)
{
    struct sockaddr_nl sa;
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return -1;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int iface_watch_poll(int fd, struct iface_list *snapshot)
{
    char buf[4096];
    struct msghdr msg;
    struct iovec iov;
    int len;
    int changed = 0;
    struct nlmsghdr *nlh;

    for (;;) {
        /* v1.2.8（审查修复）：改用 recvmsg 并检查 MSG_TRUNC——旧 recv 对超缓冲的
         * 单条 netlink 消息返回被截断长度且无任何迹象，NLMSG_OK 会按半截数据解析
         * （可能漏判/错判事件）。netlink 每 recv 一条 skb，缓冲 4096 对 link 事件
         * 足够，但防御性处理截断：无法可靠解析时保守视为"有变化"（reconcile 幂等，
         * 多一次对齐无害），并丢弃本条继续收拢。 */
        memset(&msg, 0, sizeof(msg));
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        len = recvmsg(fd, &msg, MSG_DONTWAIT);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            return -1;
        }
        if (msg.msg_flags & MSG_TRUNC) {
            changed = 1; /* 消息被截断：按"有变化"处理，不解析本条 */
            continue;
        }
        for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len);
             nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK)
                changed = 1;
        }
    }
    if (!changed)
        return 0;
    /* v1.1.9：有变化才真正填快照（此前这个参数被忽略，调用方拿到的是未初始化栈；
     * header 契约即"调用方用快照做下一步"）。调用方据此做后续对齐，省一次重复 scan。
     * 无变化（返回 0）不填、也不触发 scan。 */
    if (snapshot && iface_scan(snapshot) < 0)
        return -1;
    return changed;
}

void iface_close(int fd)
{
    if (fd >= 0)
        close(fd);
}