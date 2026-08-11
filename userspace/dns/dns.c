/* SPDX-License-Identifier: GPL-2.0 */
#include "dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "../common/log.h"

/* v1.2.7：不再使用 cBPF socket filter（见 dns_learn_open 注释）。此前 `<linux/filter.h>`
 * 与 cBPF struct sock_filter/sock_fprog/BPF_STMT/BPF_JUMP 在此按 #ifndef BPF_STMT 兜底定义，
 * 现随 filter 一并移除。 */

/* DNS 报文内偏移（头部 12 字节） */
#define DNS_HDR_LEN 12
#define DNS_FLAGS_QR 0x8000u
#define DNS_TYPE_A    1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_AAAA 28

/* 单次 poll 最多解析的 answer 记录数（防恶意构造超大响应拖慢 daemon） */
#define DNS_MAX_RR 64
/* question 区同样有上限（v1.1.4）：qd 最大 65535，无上限时恶意 64KB 响应
 * 单包可触发约 1.3 万次 dns_parse_name（每次最多 8 跳指针）拖慢 daemon */
#define DNS_MAX_QUESTIONS 16
/* 压缩指针最大跳数（防指针环） */
#define DNS_MAX_JUMPS 8

/* 与内核 bpf_ktime_get_boot_ns() 同源（CLOCK_BOOTTIME），字节级一致 */
static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * 解析 DNS 名字（支持压缩指针，跳转 ≤ DNS_MAX_JUMPS 防环）。
 * 输出到 out：正序 + 小写 + 去尾点（如 "www.example.com"），长度 ≤ outsz-1。
 * 返回名字**消费位置**（名字字段实际结束处：最后一个指针/根标签之后），
 * 失败/越界返回 NULL。
 * 注意：解析游标（跳指针）与消费位置是两回事——名字以压缩指针结尾时，
 * 消费位置是"指针之后"，解析游标在跳转目标处；返回的必须是前者。
 * 因此只有"仍位于名字字段内"（in_field）时的读取才更新 consumed——
 * 跳转目标上的标签/根属于被引用的其它名字，不得覆盖字段结束位置。
 */
static const uint8_t *dns_parse_name(const uint8_t *p, const uint8_t *end,
                                     const uint8_t *msg,
                                     char *out, size_t outsz)
{
    const uint8_t *cur = p;
    const uint8_t *consumed = p;
    size_t olen = 0;
    int jumps = 0;
    int in_field = 1;

    for (;;) {
        uint8_t len;
        int i;

        if (cur >= end)
            return NULL;
        len = *cur;
        if (len == 0) {              /* 根标签，名字结束 */
            if (in_field)
                consumed = cur + 1;
            break;
        }
        if ((len & 0xC0) == 0xC0) {  /* 压缩指针 */
            uint16_t off;

            if (cur + 1 >= end)
                return NULL;
            off = (uint16_t)(((len & 0x3F) << 8) | cur[1]);
            if (in_field) {
                consumed = cur + 2;  /* 名字字段到此为止 */
                in_field = 0;        /* 之后读取的是跳转目标，不再更新 */
            }
            if (jumps++ >= DNS_MAX_JUMPS)
                return NULL;
            if ((size_t)off >= (size_t)(end - msg))
                return NULL;         /* 指针越界 */
            cur = msg + off;         /* 解析游标跳到目标，继续追加标签 */
            continue;
        }
        if (len & 0xC0)              /* 0x40/0x80 保留位 */
            return NULL;
        if (cur + 1 + len > end)
            return NULL;
        for (i = 1; i <= len; i++) {
            uint8_t c = cur[i];

            if (olen + 1 >= outsz)
                return NULL;         /* 超缓冲（255 上限已够，防御性） */
            out[olen++] = (char)((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c);
        }
        out[olen++] = '.';
        if (in_field)
            consumed = cur + 1 + len;
        cur += 1 + len;
    }
    if (olen > 0 && out[olen - 1] == '.')
        olen--;
    out[olen] = '\0';
    return consumed;
}

/*
 * 把一条 IP→域名 学习进 map。
 * name：正序小写；只保留**后缀**（最后 SPLIT_DOM_MAX 字节）再反转——
 * 与内核 dom.h 的编码契约一致（后缀匹配靠反转前缀实现，截掉头部不影响）。
 */
static void dns_learn_one(struct dns_learn *dl, const void *ip, int family,
                          const char *name, size_t nlen, uint32_t ttl)
{
    char rev[SPLIT_DOM_MAX];
    size_t K, i;

    if (ttl == 0 || nlen == 0)
        return;                       /* TTL=0 或空名：无学习价值 */
    if (ttl > 604800)
        ttl = 604800;                 /* TTL 上限 7 天：防恶意/异常 TTL 长期占满学习 map */
    K = nlen > SPLIT_DOM_MAX ? SPLIT_DOM_MAX : nlen;
    if (nlen > SPLIT_DOM_MAX) {
        /* 截断保留"最后 SPLIT_DOM_MAX 字节"（后缀）。若截断点落在标签中间
         * （保留段前一字节不是 '.'），保留串不是对齐后缀——内核 dom.h 对
         * "规则==整个存储名"（len==name_len）的命中不做首边界检查，会把
         * 该规则误判为合法后缀（假阳性，v1.2.8 审查修正）。此处保守跳过：
         * 只是漏判该域名（回落 IP 判定），绝不写入边界含混的条目。 */
        if (name[nlen - SPLIT_DOM_MAX - 1] != '.')
            return;
    }
    for (i = 0; i < K; i++)
        rev[i] = name[nlen - 1 - i];  /* name 已小写，直接反转 */
    if (map_dns_set(dl->ctx, family, ip, rev, (int)K,
                    now_ns() + (uint64_t)ttl * 1000000000ULL) == 0)
        dl->learned++;
    else
        dl->skipped++;                /* map 满等：静默，学习失败只是漏判 */
}

/* 处理一个 IPv4 UDP 包（buf 起点 = IP 头）
 * 注意：buf 是字节数组（read 所得），不能直接强转为 struct 指针（未对齐访问
 * 是 C UB，ARM32 会 SIGBUS）；头结构用 memcpy 拷入本地对齐副本再读字段。 */
static void dns_process_ip4(struct dns_learn *dl, const uint8_t *buf, size_t n)
{
    struct iphdr ip;
    struct udphdr udp;
    const uint8_t *dns, *end, *p;
    size_t ihl, dlen;
    uint16_t frag;
    uint16_t qd, an, flags;
    char name[256];
    char qname[256]; /* v1.2.0（H4）查询名：推进 answer 游标 + 防呆（v1.2.7 归属修正后不再作学习用） */
    int i;

    if (n < sizeof(ip))
        return;
    memcpy(&ip, buf, sizeof(ip));
    if (ip.version != 4)
        return;
    if (ip.protocol != IPPROTO_UDP)
        return;
    frag = ntohs(ip.frag_off);
    if ((frag & 0x3FFF) != 0)
        return;                       /* 分片（offset≠0 或 MF=1）不做重组（已知缺口） */
    ihl = (size_t)ip.ihl * 4;
    if (ihl < sizeof(ip) || ihl + sizeof(udp) > n)
        return;
    memcpy(&udp, buf + ihl, sizeof(udp));
    if (ntohs(udp.source) != 53)
        return;                       /* 只学 DNS 服务器（UDP/53）的响应 */
    dns = buf + ihl + sizeof(udp);
    if (n < ihl + sizeof(udp) + DNS_HDR_LEN)
        return;
    dlen = n - ihl - sizeof(udp);
    end = dns + dlen;

    flags = (uint16_t)((dns[2] << 8) | dns[3]);
    if (!(flags & DNS_FLAGS_QR))
        return;                       /* 不是响应（QR=0） */
    qd = (uint16_t)((dns[4] << 8) | dns[5]);
    an = (uint16_t)((dns[6] << 8) | dns[7]);
    if (an == 0)
        return;                       /* 无答案（NXDOMAIN 等） */
    if (qd > DNS_MAX_QUESTIONS)
        return;                       /* question 异常多：整包放弃（防 DoS，避免游标错位） */

    /* 解析 question 区：推进游标到 answer 区起点（QNAME 规范不允许指针，
     * 仍走同一解析器防呆；qd 已在上方限 16 防恶意放大）。 */
    p = dns + DNS_HDR_LEN;
    for (i = 0; i < qd; i++) {
        p = dns_parse_name(p, end, dns, qname, sizeof(qname));
        if (!p || p + 4 > end)
            return;
        p += 4;                       /* QTYPE + QCLASS */
    }
    if (!qname[0])
        return;                       /* 连查询名都没有，无法把 IP 关联到域名 */

    /* 解析 answer 区（v1.2.0 支持 CNAME 链；v1.2.7 归属修正）：
     * 每条 A/AAAA 记录按其**自身 owner name**（本轮解析出的 `name`）学习，而不是按
     * "查询名/CNAME 目标"（旧 cur_name 方案）——旧方案在应答区含多个不同 owner 的
     * A/AAAA（CDN 多域名混答等）时会错误归属，导致域名规则误命中/漏命中。
     * 规范 CNAME 链里 A 记录的 owner 本就是最终规范名（链上每个名字都拿到自己该拿的
     * 映射），因此 CNAME 记录只需推进游标，无需追踪其目标域名。 */
    for (i = 0; i < an && i < DNS_MAX_RR; i++) {
        uint16_t type, rdlen;
        uint32_t ttl;
        const uint8_t *rdata;

        p = dns_parse_name(p, end, dns, name, sizeof(name));
        if (!p || p + 10 > end)
            return;
        type   = (uint16_t)((p[0] << 8) | p[1]);
        ttl    = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                 ((uint32_t)p[6] << 8) | p[7];
        rdlen  = (uint16_t)((p[8] << 8) | p[9]);
        rdata  = p + 10;
        if (rdata + rdlen > end)
            return;

        if (type == DNS_TYPE_A && rdlen >= 4 && name[0]) {
            dns_learn_one(dl, rdata, AF_INET, name, strlen(name), ttl);
        } else if (type == DNS_TYPE_AAAA && rdlen >= 16 && name[0]) {
            dns_learn_one(dl, rdata, AF_INET6, name, strlen(name), ttl);
        }
        /* CNAME 及其它类型：仅推进游标（rdata + rdlen，比解析名字字段更稳，
         * 兼容 rdlen 与名字编码长度不一致的畸形应答） */
        p = rdata + rdlen;
    }
}

int dns_learn_open(struct dns_learn *dl, struct split_bpf_ctx *ctx)
{
    struct sockaddr_ll sll;

    memset(dl, 0, sizeof(*dl));
    dl->ctx = ctx;
    dl->fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (dl->fd < 0) {
        LOG_WARNF("dns 学习: AF_PACKET socket 失败(%s)，域名分流不生效",
                  strerror(errno));
        return -1;
    }
    /* v1.2.0（H3）：读缓冲 open 时一次分配，poll 复用——避免每次 poll 都
     * malloc/free 64KB。分配失败则不致命（域名功能不生效，同 socket 失败语义）。 */
    dl->rbuf = malloc(65536);
    if (!dl->rbuf) {
        LOG_WARNF("dns 学习: 分配读缓冲失败，域名分流不生效");
        close(dl->fd);
        dl->fd = -1;
        return -1;
    }

    /* 绑定所有接口（ifindex 0）+ IPv4 帧协议；PACKET_HOST 默认只收发给本机的帧 */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = 0;
    if (bind(dl->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_WARNF("dns 学习: bind 失败(%s)，域名分流不生效", strerror(errno));
        close(dl->fd);
        dl->fd = -1;
        free(dl->rbuf);
        dl->rbuf = NULL;
        return -1;
    }
    /* v1.2.7：**不再安装 cBPF socket filter**。
     * 历史（v1.1.x-v1.2.x）：曾用 cBPF 在内核侧预过滤 UDP/53，以"减少用户态唤醒"。
     * 但它按【固定 14B 以太网头偏移】读字段——对 Android 蜂窝接口（rmnet_data*，
     * ARPHRD_RAWIP 无 L2 头）偏移错位，会把蜂窝 DNS 响应当无关帧在**内核侧**滤掉
     * （加载成功、静默错滤），导致域名学习在蜂窝上长期失效（真机目标平台）。且该
     * 过滤器无法同时兼容 Ethernet 与 RAWIP 两种布局（cBPF 无布局感知）。
     * 现在放弃内核预过滤，改由 dns_process_ip4 在用户态做全部过滤
     * （version==4 && protocol==UDP && sport==53 && 非分片），对两种布局都正确。
     * 代价：AF_PACKET socket（已按 ETH_P_IP 协议在 bind 时过滤到 IPv4 帧）上
     * 每收到 IPv4 入站帧都会唤醒 daemon 一次。DNS 学习非关键路径（失败只影响
     * 域名分流），此代价可接受；若需再省 CPU，可改为按接口分别绑定 socket 过滤。 */
    /* 非阻塞：poll 驱动，绝不阻塞 daemon 主循环 */
    fcntl(dl->fd, F_SETFL, O_NONBLOCK);
    LOG_INFOF("dns 学习器已启动（AF_PACKET, IPv4 传输, 用户态过滤）");
    return 0;
}

int dns_learn_poll(struct dns_learn *dl)
{
    uint8_t *buf;
    int pkts = 0;

    if (dl->fd < 0 || !dl->rbuf)
        return 0;
    /* v1.2.0（H3）：复用 open 时分配的一次性缓冲，不再每轮 malloc/free */
    buf = dl->rbuf;
    for (;;) {
        ssize_t n = read(dl->fd, buf, 65536);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            /* v1.2.7（审查 M5）：持续性读错误（socket 失效/接口被删等）——
             * 关闭学习器降级（域名功能不生效，主分流不受影响），避免 fd 留在
             * poll 集合里每轮反复唤醒。reload 会重新 open。 */
            LOG_WARNF("dns 学习器 read 失败(%s)，关闭学习器（reload 后重开）",
                      strerror(errno));
            dns_learn_close(dl);
            break;
        }
        if (n >= (ssize_t)sizeof(struct iphdr))
            dns_process_ip4(dl, buf, (size_t)n);
        pkts++;
    }
    return pkts;
}

void dns_learn_close(struct dns_learn *dl)
{
    if (dl->fd >= 0) {
        close(dl->fd);
        dl->fd = -1;
    }
    /* v1.2.0（H3）：释放 open 时分配的复用缓冲 */
    free(dl->rbuf);
    dl->rbuf = NULL;
}
