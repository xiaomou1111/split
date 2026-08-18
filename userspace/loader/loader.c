/* SPDX-License-Identifier: GPL-2.0
 * loader.c — BPF 对象加载 + tc 挂载 + map 操作
 *
 * 用 libbpf 的 tc API（bpf_tc_hook_create / bpf_tc_attach）做挂载，
 * 在 Android 上同样走 netlink，不依赖系统 tc 二进制。
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "loader.h"
#include "../common/log.h"
#include "../../kernel/include/split_bpf.h"

/* key 布局与内核 lpm_key4/6 保持一致 */
struct k4 { uint32_t prefixlen; uint8_t addr[4]; };
struct k6 { uint32_t prefixlen; uint8_t addr[16]; };

static struct bpf_map *map_by_name(struct bpf_object *obj, const char *name)
{
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);

    if (!m)
        LOG_ERRORF("map %s 缺失", name);
    else
        LOG_DEBUGF("map %s 打开成功", name);
    return m;
}

int split_load(struct split_bpf_ctx *ctx, const char *obj_path)
{
    struct bpf_program *prog;
    int err;

    memset(ctx, 0, sizeof(*ctx));

    ctx->obj = bpf_object__open_file(obj_path, NULL);
    if (!ctx->obj) {
        LOG_ERRORF("打开 %s 失败", obj_path);
        return -1;
    }

    prog = bpf_object__find_program_by_name(ctx->obj, "split_classify");
    if (!prog) {
        LOG_ERRORF("找不到程序 split_classify");
        goto fail;
    }

    /* 内核 section 用旧式 `SEC("classifier")`，现代 libbpf(>=1.0) 不再按 section
     * 名推断 SCHED_CLS，必须显式指定程序类型，否则 bpf_object__load 报
     * "failed to guess program type from ELF section"。 */
    bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);

    err = bpf_object__load(ctx->obj);
    if (err) {
        /* libbpf 返回负 errno；全局 errno 不可靠（内部多次 syscall） */
        LOG_ERRORF("bpf_object__load 失败(%s)", strerror(-err));
        goto fail;
    }

    ctx->prog = prog;
    ctx->prog_fd = bpf_program__fd(prog);
    ctx->m_cnip4 = map_by_name(ctx->obj, "map_cnip4");
    ctx->m_cnip6 = map_by_name(ctx->obj, "map_cnip6");
    ctx->m_proxy4 = map_by_name(ctx->obj, "map_rule_proxy4");
    ctx->m_proxy6 = map_by_name(ctx->obj, "map_rule_proxy6");
    ctx->m_direct4 = map_by_name(ctx->obj, "map_rule_direct4");
    ctx->m_direct6 = map_by_name(ctx->obj, "map_rule_direct6");
    ctx->m_skip_uid = map_by_name(ctx->obj, "map_skip_uid");
    ctx->m_tun = map_by_name(ctx->obj, "map_tun");
    ctx->m_cfg = map_by_name(ctx->obj, "map_cfg");
    ctx->m_stats = map_by_name(ctx->obj, "map_stats");
    ctx->m_rawip = map_by_name(ctx->obj, "map_rawip");
    if (!ctx->m_cnip4 || !ctx->m_cnip6 || !ctx->m_proxy4 || !ctx->m_proxy6 ||
        !ctx->m_direct4 || !ctx->m_direct6 || !ctx->m_skip_uid ||
        !ctx->m_tun || !ctx->m_cfg || !ctx->m_stats || !ctx->m_rawip)
        goto fail;

    /* v1.4.5：附带 split 版本与 libbpf 版本——BPF 加载失败/行为异常排障时
     * 一眼区分"代码旧了"与"libbpf 行为变化"，避免去翻构建环境。 */
    LOG_INFOF("加载成功 prog_fd=%d (split v%s, libbpf %s)",
              ctx->prog_fd, SPLIT_VERSION, libbpf_version_string());
    return 0;

fail:
    bpf_object__close(ctx->obj);
    ctx->obj = NULL;
    return -1;
}

void split_unload(struct split_bpf_ctx *ctx)
{
    if (ctx->obj) {
        split_detach_all(ctx);
        bpf_object__close(ctx->obj);
        ctx->obj = NULL;
    }
}

/*
 * filter 真实存在性核验（v1.1.7，补"挂载自愈"最后一环）。
 *
 * 背景：daemon 的 `ctx->attached[]` 只是**用户态内存自认为的状态**——
 * 若网卡上的 cls_bpf filter 被外部手段清除（ifindex 不变、netlink 无事件、
 * Android wifi down/up 等），5s reconcile 心跳只看 attached[] 会误以为
 * "已挂"而跳过 attach，eBPF 实际已不在流量路径上（静默失效）。
 *
 * 用 libbpf 的 `bpf_tc_query`（RTM_GETTFILTER）对照内核真实状态：
 *   - 返回 0 = cls_bpf filter 真的挂在 dev/egress/handle=1/priority=10；
 *   - 非 0（含 -ENOENT：filter 不存在 / qdisc 被删）→ 视为已丢失。
 * bpf_tc_query 是 libbpf>=1.0 的 API，与既有 bpf_tc_attach/detach 同源，无新依赖。
 */
static int split_filter_exists(int ifindex)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .handle = 1,
        .priority = 10,
    );

    return bpf_tc_query(&hook, &opts) == 0;
}

int split_attach_iface(struct split_bpf_ctx *ctx, int ifindex,
                       const struct iface_list *snap)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = ctx->prog_fd,
        .handle = 1,
        .priority = 10,
        /* v1.1.4：必须 REPLACE。splitd 异常退出（kill -9/崩溃）后 cls_bpf
         * filter 残留网卡并持引用保住旧 prog+旧 maps；不带 REPLACE 的
         * bpf_tc_attach 对同 handle/priority 返回 EEXIST → 新 daemon 挂不上
         * （nattached=0），残留 filter 继续用旧 map（新规则全落空）→ 静默失效。 */
        .flags = BPF_TC_F_REPLACE,
    );
    int err, k;
    int retried = 0;

    /* 幂等去重必须先于容量检查（审查修正）：去重里对"已挂且真实存在"的接口
     * 在此 return 0，对"filter 丢失"的接口会先移除记录（nattached--）腾出容量。
     * 若容量检查跑在去重之前，nattached==IFACE_MAX 时 5s 心跳 reconcile 会对每个
     * 已挂接口先撞 -ENOSPC + ERROR 日志刷屏，去重分支永远走不到。因此容量检查
     * 必须放在去重之后，只拦截"真正要新增"的接口。 */
    for (k = 0; k < ctx->nattached; k++) {
        if (ctx->attached[k] != ifindex)
            continue;
        /* v1.1.7：幂等去重改为"核验真实状态"——attached[] 只是内存记录，
         * 网卡上 filter 可能已被外部清除而记录不知情（ifindex 不变时心跳
         * 看不到漂移）。filter 确实在 → 跳过；丢失 → 移除记录走重挂。 */
        if (split_filter_exists(ifindex)) {
            return 0; /* 已挂且真实存在 */
        }
        LOG_WARNF("iface %d egress filter 丢失（可能被外部清除），重新挂载",
                  ifindex);
        ctx->attached[k] = ctx->attached[--ctx->nattached];
        break;
    }

    /* v1.1.9：显式上限防护（attached[] 容量 IFACE_MAX）。在去重之后、attach
     * 动作之前检查——若已满则拒绝挂载，避免"filter 已挂上但记录未写入"的泄漏。
     * 去重已先 return(0) 或腾出容量，此处只拦截真正要新增的接口。 */
    if (ctx->nattached >= IFACE_MAX) {
        LOG_ERRORF("iface %d 挂载失败: attached[] 已满(%d)", ifindex, IFACE_MAX);
        return -ENOSPC;
    }

    /* clsact 已存在时创建返回 -EINVAL，属正常 */
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EINVAL && err != -EEXIST) {
        LOG_WARNF("iface %d clsact 创建失败(%s)", ifindex, strerror(-err));
    }

retry:
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        if (err == -EEXIST && !retried) {
            /* 上次进程（崩溃/异常退出）残留的同 handle+priority filter：
             * bpf_tc_attach 是 create|excl 语义，旧 filter 不除则永远 EEXIST，
             * 新 daemon 会出现"已启动但实际未挂载"的静默失效（v1.1.4）。
             * 先按同 handle/priority detach 再重挂一次。 */
            LOG_WARNF("iface %d 存在旧 filter（handle=1 priority=10），先移除再重挂",
                      ifindex);
            bpf_tc_detach(&hook, &opts);
            retried = 1;
            goto retry;
        }
        LOG_ERRORF("iface %d attach 失败(%s)", ifindex, strerror(-err));
        return err;
    }
    ctx->attached[ctx->nattached++] = ifindex;
    LOG_INFOF("iface %d 已挂载 egress", ifindex);
    /* v1.1.5：RAWIP 接口（蜂窝 rmnet）同步进 map_rawip，内核据此跳过
     * 以太网头解析（不 sync 则蜂窝流量 parse 全失败，海外无法进代理）。 */
    map_rawip_sync(ctx, ifindex, snap);
    return 0;
}

/* detach 与 attached[] 记录维护，不做 map_rawip 同步（由调用方统一处理）。 */
static int split_detach_core(struct split_bpf_ctx *ctx, int ifindex)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    );
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 10);
    int k;

    bpf_tc_detach(&hook, &opts);
    for (k = 0; k < ctx->nattached; k++) {
        if (ctx->attached[k] == ifindex) {
            ctx->attached[k] = ctx->attached[--ctx->nattached];
            break;
        }
    }
    return 0;
}

int split_detach_iface(struct split_bpf_ctx *ctx, int ifindex,
                       const struct iface_list *snap)
{
    split_detach_core(ctx, ifindex);
    /* v1.1.5：与 attach 对称——按接口当前类型重写/删除 map_rawip
     * （接口若仍是 RAWIP+UP 则保留条目，卸载后重挂无需重建）。 */
    map_rawip_sync(ctx, ifindex, snap);
    LOG_INFOF("iface %d 已卸载", ifindex);
    return 0;
}

void split_detach_all(struct split_bpf_ctx *ctx)
{
    /* v1.1.9：先整体 detach 全部接口，最后一次统一 map_rawip_sync——避免
     * 逐个 split_detach_iface 各自触发一次全量 netlink 扫描（N 个接口=N 次
     * 全量 dump，纯开销）。rawip 同步只需在全卸后做一次。 */
    while (ctx->nattached > 0)
        split_detach_core(ctx, ctx->attached[ctx->nattached - 1]);
    map_rawip_sync(ctx, 0, NULL);
}

/* ================= RAWIP 接口集合（v1.1.5） =================
 * Android 蜂窝网卡 rmnet_data* 是 ARPHRD_RAWIP(519)：tc egress 的 skb
 * 没有以太网头（data 直接是 IP 头）。内核 parse.h 据此选择无 L2 解析路径；
 * 本函数负责把接口类型同步进 map_rawip（挂载/卸载/网络事件后调用）。
 * 判据：iface.type == ARPHRD_RAWIP（linux/if_arp.h，519）。 */
#include <linux/if_arp.h>

static int map_clear_by_keys(struct bpf_map *m); /* 定义在文件后部 */

static int rawip_iface_type(const struct iface *i)
{
    return i && i->type == ARPHRD_RAWIP ? 1 : 0;
}

int map_rawip_sync(struct split_bpf_ctx *ctx, int ifindex,
                   const struct iface_list *snap)
{
    struct iface_list owned;
    const struct iface_list *list;
    uint32_t key;
    uint8_t one = 1;
    int k;

    if (!ctx->m_rawip)
        return -1;

    /* v1.1.9：复用调用方快照免去重复 scan（iface_reconcile 已扫）；NULL 才自扫。 */
    if (snap)
        list = snap;
    else {
        if (iface_scan(&owned) < 0)
            return -1;
        list = &owned;
    }

    if (ifindex > 0) {
        /* 单接口：查类型后写入或删除。 */
        for (k = 0; k < list->count; k++) {
            if (list->items[k].ifindex != ifindex)
                continue;
            key = (uint32_t)ifindex;
            /* 与全量重建路径口径一致：仅 RAWIP 且是物理接口（IFF_UP，排除
             * rmnet_ipa/tun 等）才写 map。iface_is_physical 内建 IFF_UP 检查，
             * 亦排除 rmnet_ipa（RAWIP 但带 RMNET MAP 封装头，不可按裸 IP 解析）。 */
            if (rawip_iface_type(&list->items[k]) &&
                iface_is_physical(&list->items[k]))
                bpf_map__update_elem(ctx->m_rawip, &key, sizeof(key),
                                     &one, sizeof(one), BPF_ANY);
            else
                bpf_map__delete_elem(ctx->m_rawip, &key, sizeof(key), 0);
            return 0;
        }
        /* 接口不存在（已删除）：清掉残留条目 */
        key = (uint32_t)ifindex;
        bpf_map__delete_elem(ctx->m_rawip, &key, sizeof(key), 0);
        return 0;
    }

    /* 全量同步（v1.1.8 起"无变化零开销"）：先算出目标集合并与 map 现状比对，
     * 集合相同直接跳过——不再每 5s 心跳无条件"清空+重建"（清空窗口内内核
     * parse 无法识别 RAWIP 接口、瞬间退化成全物理接口解析，放大瞬时直连窗口）。
     * 判据统一为 rawip_iface_type() && iface_is_physical()（与单接口路径及挂载
     * 计划口径一致）：iface_is_physical 内建 IFF_UP 检查（DOWN 不产生流量、
     * 避免残留），并排除 rmnet_ipa（RAWIP 519 但帧带 RMNET MAP 封装头，
     * 不可按裸 IP 解析）。 */
    {
        uint32_t cap = bpf_map__max_entries(ctx->m_rawip);
        uint32_t want[32], cur[32];
        int nwant = 0, ncur = 0, r;

        if (cap == 0 || cap > 32)
            cap = 32;
        for (k = 0; k < list->count && nwant < (int)cap; k++) {
            const struct iface *i = &list->items[k];

            if (rawip_iface_type(i) && iface_is_physical(i))
                want[nwant++] = (uint32_t)i->ifindex;
        }

        /* 读 map 现状。注意：**必须 prev-key 推进遍历**（先取首键，再
         * get_next_key(prev,next)；只读不删，不能每轮 get_next_key(NULL)
         * ——那会永远返回同一首键死循环，与 loader/MEMORY 项 10/13 同坑）。 */
        {
            unsigned char kb[4], nb[4];
            size_t ksz = bpf_map__key_size(ctx->m_rawip);

            if (ksz == 0 || ksz > sizeof(kb))
                return -1;
            r = bpf_map__get_next_key(ctx->m_rawip, NULL, kb, ksz);
            while (r == 0) {
                if (ncur >= (int)cap)
                    break; /* 超出容量视为有差异，走重建 */
                memcpy(&cur[ncur], kb, (size_t)ksz);
                ncur++;
                r = bpf_map__get_next_key(ctx->m_rawip, kb, nb, ksz);
                if (r == 0)
                    memcpy(kb, nb, (size_t)ksz);
            }
        }

        /* 集合比对（元素顺序无关） */
        if (ncur == nwant) {
            int same = 1;

            for (k = 0; k < nwant && same; k++) {
                int found = 0;

                for (r = 0; r < ncur; r++)
                    if (cur[r] == want[k]) { found = 1; break; }
                if (!found)
                    same = 0;
            }
            if (same)
                return 0; /* 无变化：跳过清空+重建 */
        }

        map_clear_by_keys(ctx->m_rawip);
        for (k = 0; k < nwant; k++) {
            key = want[k];
            if (bpf_map__update_elem(ctx->m_rawip, &key, sizeof(key),
                                     &one, sizeof(one), BPF_ANY) != 0)
                LOG_WARNF("map_rawip 写入 ifindex %u 失败(%s)",
                          (unsigned)key, strerror(errno));
        }
    }
    return 0;
}

/* ================= map 操作 ================= */

int map_set_tun(struct split_bpf_ctx *ctx, int ifindex)
{
    uint32_t zero = 0, v = (uint32_t)ifindex;

    return bpf_map__update_elem(ctx->m_tun, &zero, sizeof(zero),
                                &v, sizeof(v), BPF_ANY);
}

int map_get_tun(struct split_bpf_ctx *ctx, uint32_t *ifindex)
{
    uint32_t zero = 0;

    if (!ifindex)
        return -1;
    if (bpf_map__lookup_elem(ctx->m_tun, &zero, sizeof(zero), ifindex,
                             sizeof(*ifindex), 0) != 0)
        return -1;
    return 0;
}

int map_set_cfg(struct split_bpf_ctx *ctx, uint8_t default_verdict, bool ipv6_on,
                bool skip_uid_on, bool cnip_on)
{
    uint32_t zero = 0;
    struct split_cfg cfg = {
        .default_verdict = default_verdict,
        /* 初始化标记（v1.3.1）：map_cfg 是 ARRAY map，lookup 永不返回 NULL——
         * 未写入时返回全零元素（default_verdict=0=直连），与文档"未知→代理
         * 安全默认"相悖。bpf_trace_enabled 置 1 作为"已初始化"哨兵，内核
         * policy.h 据此把"未初始化/写入失败"回落到 TUN 安全默认（见 policy.h）。 */
        .bpf_trace_enabled = 1,
        .ipv6_classify = ipv6_on ? 1 : 0,
        .skip_uid_enabled = skip_uid_on ? 1 : 0,
        .cnip_enabled = cnip_on ? 1 : 0,
    };

    return bpf_map__update_elem(ctx->m_cfg, &zero, sizeof(zero),
                                &cfg, sizeof(cfg), BPF_ANY);
}

int map_skip_uid_add(struct split_bpf_ctx *ctx, uint32_t uid)
{
    uint8_t one = 1;

    return bpf_map__update_elem(ctx->m_skip_uid, &uid, sizeof(uid),
                                &one, sizeof(one), BPF_ANY);
}

int map_skip_uid_del(struct split_bpf_ctx *ctx, uint32_t uid)
{
    return bpf_map__delete_elem(ctx->m_skip_uid, &uid, sizeof(uid), 0);
}

/*
 * 清空一个 map 的所有元素（BPF_MAP_TYPE_HASH / BPF_MAP_TYPE_LPM_TRIE 均可）。
 * 用 get_next_key + delete_elem 迭代删除；用于 reload 时"先清空再写"保证幂等。
 *
 * 注意：必须"反复取首键（cur_key=NULL）"+ delete，直到 -ENOENT。
 * 不要用"取前一个键再继续"的迭代方式——对 LPM_TRIE，已删的键在树里不存在，
 * 内核 lpm_trie_get_next_key 会因 trie_lookup_key 失败直接返回 -ENOENT、提前终止，
 * 导致 CNIP 树清不干净（残留旧前缀）。
 */
static int map_clear_by_keys(struct bpf_map *m)
{
    unsigned char cur[128]; /* ≥ 所有 map 的 key 大小（最大 lpm_key6=4+16=20） */
    size_t ksz = bpf_map__key_size(m);

    if (ksz == 0 || ksz > sizeof(cur))
        return -1;

    for (;;) {
        int err = bpf_map__get_next_key(m, NULL, cur, ksz);

        if (err != 0) {
            if (err == -ENOENT)
                return 0; /* 正常清空完毕 */
            return -1;    /* 其它错误：清空不完整，如实上报 */
        }
        if (bpf_map__delete_elem(m, cur, ksz, 0) != 0)
            return -1; /* 删除失败避开死循环，但清空不完整必须上报 */
    }
}

int map_rule_clear(struct split_bpf_ctx *ctx)
{
    /* 审查（2026-08 P2）：任一 map 清空失败必须上抛——否则 reload 在"半清空"的
     * map 上叠加写入，配置中已移除的旧规则静默残留、继续影响数据面。仍逐个清空
     * 其余 map（尽量清理），最终返回是否有任一失败。 */
    int rc = 0;

    if (map_clear_by_keys(ctx->m_skip_uid) < 0) rc = -1;
    if (map_clear_by_keys(ctx->m_proxy4)   < 0) rc = -1;
    if (map_clear_by_keys(ctx->m_proxy6)   < 0) rc = -1;
    if (map_clear_by_keys(ctx->m_direct4)  < 0) rc = -1;
    if (map_clear_by_keys(ctx->m_direct6)  < 0) rc = -1;
    return rc;
}

int map_cnip_clear(struct split_bpf_ctx *ctx)
{
    int rc = 0;

    if (map_clear_by_keys(ctx->m_cnip4) < 0) rc = -1;
    if (map_clear_by_keys(ctx->m_cnip6) < 0) rc = -1;
    return rc;
}

/* 别名：语义同 map_cnip_clear（保留历史调用名，避免误改方断裂） */
int map_cnip_clear_all(struct split_bpf_ctx *ctx)
{
    return map_cnip_clear(ctx);
}

/*
 * 统计 CNIP map 条目数（v1.1.3，status 自检）。
 * 注意：与 map_clear_by_keys 不同——这里**不删除**键，LPM_TRIE 的
 * get_next_key(prev) 迭代稳定，不会提前终止；因此用 prev-key 顺序遍历
 * （若复用"反复取首键"方式且不删键，会永远取到同一个首键 → 死循环）。
 * 用 prev-key 顺序遍历（key/next 双缓冲，err==0 才拷贝）。
 */
int map_cnip_count(struct split_bpf_ctx *ctx, uint32_t *n4, uint32_t *n6)
{
    unsigned char key[128], next[128];
    size_t ksz;
    uint32_t c4 = 0, c6 = 0;

    if (n4)
        *n4 = 0;
    if (n6)
        *n6 = 0;

    ksz = bpf_map__key_size(ctx->m_cnip4);
    if (ksz > 0 && ksz <= sizeof(key)) {
        int err = bpf_map__get_next_key(ctx->m_cnip4, NULL, key, ksz);

        while (err == 0) {
            c4++;
            err = bpf_map__get_next_key(ctx->m_cnip4, key, next, ksz);
            if (err == 0)
                memcpy(key, next, ksz);
        }
    }
    ksz = bpf_map__key_size(ctx->m_cnip6);
    if (ksz > 0 && ksz <= sizeof(key)) {
        int err = bpf_map__get_next_key(ctx->m_cnip6, NULL, key, ksz);

        while (err == 0) {
            c6++;
            err = bpf_map__get_next_key(ctx->m_cnip6, key, next, ksz);
            if (err == 0)
                memcpy(key, next, ksz);
        }
    }
    if (n4)
        *n4 = c4;
    if (n6)
        *n6 = c6;
    return 0;
}

/* which: 0=proxy, 1=direct */
static struct bpf_map *rule_map_pick(struct split_bpf_ctx *ctx,
                                     int family, int which)
{
    if (family == AF_INET)
        return which == 0 ? ctx->m_proxy4 : ctx->m_direct4;
    return which == 0 ? ctx->m_proxy6 : ctx->m_direct6;
}

/*
 * 解析 CIDR 的 "/<前缀长>" 后缀；s==NULL 时用默认值（v4=32 / v6=128）。
 * 严格校验（v1.1.2）：atoi 会把 "/abc" 解析成 0 → LPM prefixlen=0 匹配全部
 * 流量（全流量误分流，高危）；"/-1" 会被静默收敛成 32。非法/负值/超 128 返回 -1。
 * v1.1.3+：空串（"1.2.3.4/"）同样拒绝——strtol("")==0 会静默成为 /0。
 */
static int parse_pfix(const char *s, int def)
{
    char *end = NULL;
    long v;

    if (!s)
        return def;
    if (!s[0])
        return -1;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || !end || *end != '\0' || v < 0 || v > 128)
        return -1;
    return (int)v;
}

int map_rule_add_cidr(struct split_bpf_ctx *ctx, const char *cidr, int which)
{
    char buf[200], *slash;
    struct bpf_map *m;
    uint8_t one = 1;
    int fam, err;
    uint32_t pfix;
    struct in_addr a4;
    struct in6_addr a6;
    struct k4 k4; struct k6 k6;

    if (snprintf(buf, sizeof(buf), "%s", cidr) >= (int)sizeof(buf)) {
        LOG_ERRORF("cidr 过长: %s", cidr);
        return -1;
    }
    slash = strchr(buf, '/');
    if (slash)
        *slash++ = '\0';
    {
        int p = parse_pfix(slash, strchr(buf, ':') ? 128 : 32);

        if (p < 0) {
            LOG_ERRORF("非法前缀长: %s", cidr);
            return -1;
        }
        pfix = (uint32_t)p;
    }

    if (inet_pton(AF_INET, buf, &a4) == 1) {
        fam = AF_INET;
        if (pfix > 32) {
            LOG_WARNF("v4 前缀长 %u 超出 32，按 /32 处理: %s", pfix, cidr);
            pfix = 32;
        }
    } else if (inet_pton(AF_INET6, buf, &a6) == 1) {
        fam = AF_INET6;
        if (pfix > 128) {
            LOG_WARNF("v6 前缀长 %u 超出 128，按 /128 处理: %s", pfix, cidr);
            pfix = 128;
        }
    } else {
        LOG_ERRORF("非法 cidr: %s", cidr);
        return -1;
    }

    m = rule_map_pick(ctx, fam, which);
    if (fam == AF_INET) {
        memset(&k4, 0, sizeof(k4));
        k4.prefixlen = pfix;
        memcpy(k4.addr, &a4, 4);
        err = bpf_map__update_elem(m, &k4, sizeof(k4), &one, sizeof(one), BPF_ANY);
    } else {
        memset(&k6, 0, sizeof(k6));
        k6.prefixlen = pfix;
        memcpy(k6.addr, &a6, 16);
        err = bpf_map__update_elem(m, &k6, sizeof(k6), &one, sizeof(one), BPF_ANY);
    }
    if (err)
        LOG_ERRORF("写入规则失败 %s(%s)", cidr, strerror(errno));
    return err;
}

int map_cnip_add_cidr(struct split_bpf_ctx *ctx, const char *cidr, int family)
{
    char buf[200], *slash;
    struct bpf_map *m;
    uint8_t one = 1;
    uint32_t pfix;
    struct in_addr a4;
    struct in6_addr a6;
    struct k4 k4; struct k6 k6;

    if (snprintf(buf, sizeof(buf), "%s", cidr) >= (int)sizeof(buf)) {
        LOG_ERRORF("cidr 过长: %s", cidr);
        return -1;
    }
    slash = strchr(buf, '/');
    if (slash)
        *slash++ = '\0';
    {
        int p = parse_pfix(slash, family == AF_INET ? 32 : 128);

        if (p < 0) {
            LOG_ERRORF("非法前缀长: %s", cidr);
            return -1;
        }
        pfix = (uint32_t)p;
    }

    if (family == AF_INET) {
        if (inet_pton(AF_INET, buf, &a4) != 1)
            return -1;
        m = ctx->m_cnip4;
        memset(&k4, 0, sizeof(k4));
        if (pfix > 32) {
            LOG_WARNF("v4 前缀长 %u 超出 32，按 /32 处理: %s", pfix, cidr);
            pfix = 32;
        }
        k4.prefixlen = pfix;
        memcpy(k4.addr, &a4, 4);
        return bpf_map__update_elem(m, &k4, sizeof(k4), &one, sizeof(one), BPF_ANY);
    }

    if (inet_pton(AF_INET6, buf, &a6) != 1)
        return -1;
    m = ctx->m_cnip6;
    memset(&k6, 0, sizeof(k6));
    if (pfix > 128) {
        LOG_WARNF("v6 前缀长 %u 超出 128，按 /128 处理: %s", pfix, cidr);
        pfix = 128;
    }
    k6.prefixlen = pfix;
    memcpy(k6.addr, &a6, 16);
    return bpf_map__update_elem(m, &k6, sizeof(k6), &one, sizeof(one), BPF_ANY);
}

/* v1.4.6（审查 P2）：dry-run 校验——判定 cidr 能否被 map_cnip_add_cidr 接受，但不写
 * map。与 map_cnip_add_cidr 的 ok/bad 口径严格一致（parse_pfix 0..128 + inet_pton，
 * 超范围前缀 clamp 计合法），仅略去 bpf_map__update_elem（CNIP map 65536 容量实际
 * 不会满，update 失败不改变校验结论）。 */
int map_cnip_cidr_ok(const char *cidr, int family)
{
    char buf[200], *slash;
    uint32_t pfix;
    struct in_addr a4;
    struct in6_addr a6;

    if (snprintf(buf, sizeof(buf), "%s", cidr) >= (int)sizeof(buf))
        return -1;
    slash = strchr(buf, '/');
    if (slash)
        *slash++ = '\0';
    {
        int p = parse_pfix(slash, family == AF_INET ? 32 : 128);

        if (p < 0)
            return -1;
        pfix = (uint32_t)p;
    }
    if (family == AF_INET) {
        if (inet_pton(AF_INET, buf, &a4) != 1)
            return -1;
    } else {
        if (inet_pton(AF_INET6, buf, &a6) != 1)
            return -1;
    }
    (void)pfix; /* clamp 不影响 ok/bad 判定，与 map_cnip_add_cidr 一致 */
    return 0;
}

int map_stats_dump(struct split_bpf_ctx *ctx, uint64_t out[STAT_MAX])
{
    uint32_t k;
    int ncpus = libbpf_num_possible_cpus();
    uint64_t *vals;
    uint64_t sum;

    vals = calloc((size_t)ncpus, sizeof(uint64_t));
    if (!vals)
        return -1;

    memset(out, 0, sizeof(uint64_t) * STAT_MAX);
    for (k = 0; k < STAT_MAX; k++) {
        uint32_t idx = k;
        int ret;

        memset(vals, 0, (size_t)ncpus * sizeof(uint64_t));
        ret = bpf_map__lookup_elem(ctx->m_stats, &idx, sizeof(idx),
                                   vals, (size_t)ncpus * sizeof(uint64_t), 0);
        if (ret < 0) {
            /* v1.2.8（审查修复）：lookup 失败不再静默 continue——PERCPU_ARRAY 的
             * value_size 以创建时 CPU 数定，极端（CPU 热插拔/环境不一致）时可能
             * 不足而失败；加 WARN 让"统计缺槽"可查，而非 stats 输出少项无痕。
             * libbpf 封装返回 -1、errno 由底层 syscall 设置（与文件内其它
             * bpf_map__* 的 strerror(errno) 约定一致）。 */
            LOG_WARNF("读取统计槽 %u 失败(%s)，该槽计为 0", k, strerror(errno));
            continue;
        }
        sum = 0;
        for (int c = 0; c < ncpus; c++)
            sum += vals[c];
        out[k] = sum;
    }
    free(vals);
    return 0;
}

int map_rule_del_cidr(struct split_bpf_ctx *ctx, const char *cidr, int which)
{
    char buf[200], *slash;
    struct bpf_map *m;
    int fam, err;
    uint32_t pfix;
    struct in_addr a4;
    struct in6_addr a6;
    struct k4 k4; struct k6 k6;

    if (snprintf(buf, sizeof(buf), "%s", cidr) >= (int)sizeof(buf)) {
        LOG_ERRORF("cidr 过长: %s", cidr);
        return -1;
    }
    slash = strchr(buf, '/');
    if (slash)
        *slash++ = '\0';
    {
        int p = parse_pfix(slash, strchr(buf, ':') ? 128 : 32);

        if (p < 0) {
            LOG_ERRORF("非法前缀长: %s", cidr);
            return -1;
        }
        pfix = (uint32_t)p;
    }

    if (inet_pton(AF_INET, buf, &a4) == 1) {
        fam = AF_INET;
        if (pfix > 32) {
            /* v1.2.7（审查 M3）：与 map_rule_add_cidr 口径一致，收敛时打 WARN——
             * 静默收敛会让"删 /64 实际删的是 /32"无从察觉。 */
            LOG_WARNF("v4 前缀长 %u 超出 32，按 /32 处理: %s", pfix, cidr);
            pfix = 32;
        }
    } else if (inet_pton(AF_INET6, buf, &a6) == 1) {
        fam = AF_INET6;
        if (pfix > 128) {
            LOG_WARNF("v6 前缀长 %u 超出 128，按 /128 处理: %s", pfix, cidr);
            pfix = 128;
        }
    } else {
        LOG_ERRORF("非法 cidr: %s", cidr);
        return -1;
    }

    m = rule_map_pick(ctx, fam, which);
    if (fam == AF_INET) {
        memset(&k4, 0, sizeof(k4));
        k4.prefixlen = pfix;
        memcpy(k4.addr, &a4, 4);
        err = bpf_map__delete_elem(m, &k4, sizeof(k4), 0);
    } else {
        memset(&k6, 0, sizeof(k6));
        k6.prefixlen = pfix;
        memcpy(k6.addr, &a6, 16);
        err = bpf_map__delete_elem(m, &k6, sizeof(k6), 0);
    }
    if (err)
        LOG_ERRORF("删除规则失败 %s(%s)", cidr, strerror(errno));
    return err;
}

int map_rule_foreach(struct split_bpf_ctx *ctx, int which,
                     map_rule_foreach_cb cb, void *priv)
{
    struct bpf_map *maps[2];
    int n = 0;

    /* which 0=proxy / 1=direct（与 rule.h 的 RULE_PROXY/RULE_DIRECT 一致） */
    if (which == 0) {
        maps[0] = ctx->m_proxy4;
        maps[1] = ctx->m_proxy6;
    } else {
        maps[0] = ctx->m_direct4;
        maps[1] = ctx->m_direct6;
    }
    for (int mi = 0; mi < 2; mi++) {
        struct bpf_map *m = maps[mi];
        size_t ksz = bpf_map__key_size(m);
        unsigned char key[128], next[128];
        int err;

        /* k4=4+4=8 字节，k6=4+16=20 字节；key 缓冲 ≥ 最大 key */
        if (ksz < (size_t)(mi == 0 ? 8 : 20) || ksz > sizeof(key))
            continue;
        err = bpf_map__get_next_key(m, NULL, key, ksz);
        while (err == 0) {
            char text[64];
            struct k4 k4;
            struct k6 k6;

            /* 用 memcpy 进局部 struct，避免对齐假设 */
            if (mi == 0) {
                memcpy(&k4, key, sizeof(k4));
                inet_ntop(AF_INET, k4.addr, text, sizeof(text));
                snprintf(text + strlen(text), sizeof(text) - strlen(text),
                         "/%u", k4.prefixlen);
            } else {
                memcpy(&k6, key, sizeof(k6));
                inet_ntop(AF_INET6, k6.addr, text, sizeof(text));
                snprintf(text + strlen(text), sizeof(text) - strlen(text),
                         "/%u", k6.prefixlen);
            }
            if (cb && cb(which, text, priv) != 0)
                return -1;    /* 回调中止（如客户端断开） */
            n++;
            /* prev-key 顺序迭代：不删键，get_next_key(prev) 稳定前进 */
            err = bpf_map__get_next_key(m, key, next, ksz);
            if (err == 0)
                memcpy(key, next, ksz);
        }
    }
    return n;
}