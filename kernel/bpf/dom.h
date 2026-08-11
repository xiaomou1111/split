/* SPDX-License-Identifier: GPL-2.0
 * dom.h — 域名分流判定（v1.1.0）
 *
 * 编码硬契约（与 split_bpf.h「域名分流」一节、用户态 loader.c/dns.c 字节级一致）：
 *   - map_dns4/6 的 name：**反转 + 小写**的域名（"example.com" → "moc.elpmaxe"）；
 *   - map_dom_proxy/direct 的 key：反转 + 小写的规则后缀（"com" → "moc"）。
 *
 * 匹配语义 = Clash DOMAIN-SUFFIX（规则必须是查询域名的完整后缀，标签边界）。
 * 反转后"后缀"变成"字节前缀"，一次 LPM 查询即可命中；但 LPM_TRIE 只返回
 * **最长**前缀且不返回命中长度（所以 value 里必须自记 dom_rule.len），
 * 存在"遮蔽"问题：规则 xample.com（反转 moc.elpmax，10B）会遮蔽更短规则
 * com（moc，3B）——边界检查（下一字节必须是 '.'）失败后必须缩短再查。
 *
 * 缩短方式（v1.1.1 起）：**逐字节递减 prefixlen 再查**，不再"找最后一个
 * '.' 跳标签"。LPM 只按 prefixlen 位匹配，key->data 全量拷入、无需缩短；
 * 最长 64 步线性查询，任何合法后缀规则必在 prefixlen == 规则字节数的
 * 查询步以最长前缀命中。代价是遮蔽路径多查若干次（无性能实质影响）。
 * 无命中路径（v1.1.2 优化）：规则要命中必先是"反转域名"的字节前缀，
 * LPM 全长查询返回最长前缀——**任何一次 lookup miss 即 return 0**，
 * 常见"学得到 IP 但无规则命中"路径只付 1 次 LPM 查询（热路径防放大）。
 *
 * verifier 纪律（全部实测于 WSL2 6.18 内核，-mcpu=v1）：
 *   - 两个 map 都是编译期常量引用，故用宏生成 proxy/direct 两份实例
 *     （BPF 不允许把 map 指针作为运行时函数参数）；
 *   - dom_rule.len 来自 map value（未约束标量），用它索引 key->data 前
 *     必须先显式 `len < SPLIT_DOM_MAX` 证明上界；
 *   - **禁止任何"运行时边界 + 读栈数组"的循环**（如 `for (j=0;j<remain;j++)
 *     if (data[j]=='.')...`）：verifier 状态不收敛，processed 1000001 insn
 *     超限 -E2BIG。先试 break 提前退出、全程扫描无 break、全 __u32 类型、
 *     显式 64 条线性分支（pos 状态机）、逐字节递减 prefixlen 查询
 *     （unroll(full)）均失败；**同样禁止"展开后仍带未知条件分支"的逐字节
 *     拷贝循环**（每字节 `j<remain` 比较是 unknown 分支，64 个分支点组合
 *     爆炸）——拷入一律 `__builtin_memcpy` 64 字节无分支展开，LPM 只按
 *     prefixlen 位匹配，key->data 尾部字节不参与匹配、无需清零。
 *     最终方案：memcpy 全量拷贝 + unroll(full) 逐字节递减 prefixlen 查询，
 *     WSL2 6.18 内核通过 verifier（详见 kernel/bpf/MEMORY.md）。
 *   - 读 key->data[remain] 前必须证明 remain < SPLIT_DOM_MAX（见命中判断）。
*   - **真机 5.x GKI verifier 拒载"变量偏移读"（v1.2.0 实测两版演化）**：
*     ① `key->data[v->len]`（栈数组）→ `invalid variable-offset read from stack
*     var_off=(0x0;0xff)`；② 改读 `de->name[v->len]`（map value）→ `invalid access
*     to map value value_size=80 off=264`。两版 WSL2 6.18 都过、5.10 GKI 都拒，
*     根因同：`v->len`/`remain` 是 map value 未约束标量（umax 255），即便代码里
*     `X < SPLIT_DOM_MAX` 条件存在，旧 verifier 不把该限定传导到寻址寄存器的
*     umax。**铁律：读 map value 前必须把下标显式掩码到 `< SPLIT_DOM_MAX`**
*     （`idx = X & (SPLIT_DOM_MAX-1)`，合法输入本就在 [0,63] 语义不变，且让
*     verifier 确信 off+63 < value_size）。对"栈数组 + 未约束下标"一律改读
*     **同内容的 map value** + 掩码，勿直接读栈数组。
 */
#ifndef __SPLIT_BPF_DOM_H_
#define __SPLIT_BPF_DOM_H_

#include <bpf/bpf_helpers.h>
#include "split_bpf.h"
#include "maps.h"

/* 查"连接的 dst IP 属于哪个域名"（过期视为未命中，删除交给用户态定期清理） */
static __always_inline const struct dns_entry *
dns_lookup_entry(const struct split_pkt *pkt)
{
    const struct dns_entry *de;
    __u64 now;

    if (pkt->family == SPLIT_FAMILY_IPV4) {
        de = bpf_map_lookup_elem(&map_dns4, &pkt->dst.ip4);
    } else if (pkt->family == SPLIT_FAMILY_IPV6) {
        de = bpf_map_lookup_elem(&map_dns6, pkt->dst.ip6);
    } else {
        return NULL;
    }
    if (!de)
        return NULL;
    now = bpf_ktime_get_boot_ns();
    if (de->expire_ns < now)  /* 过期条目：视为未命中，走 IP 判定（不丢包） */
        return NULL;
    return de;
}

/* @de:  dns_entry（name 已是反转小写）
 * @key: 调用方栈上的 dom_key（data[] 全量拷贝，查询只改 prefixlen）
 *
 * 注意：proxy 与 direct 是各自独立的 LPM trie，且**优先级要求 proxy 整段判定
 * 完（含遮蔽回溯）才轮到 direct**。一旦合并成单循环，会在 proxy 某 remain 因
 * 遮蔽未决时先返回 direct 命中 —— 改变"proxy 优先级高于 direct"的分流语义。
 * 故必须保持两遍独立递减扫描（v1.2.0 性能评估后回退；遮蔽热路径罕见，代价可
 * 接受）。真正的热路径收益由 map_cfg.dom_enabled 空规则短路承担（policy.h）。 */
#define DOM_MATCH_FN(fn, mapvar)                                            \
static __always_inline int fn(const struct dns_entry *de,                   \
                              struct dom_key *key)                          \
{                                                                           \
    __u32 remain;                                                           \
    __u32 name_len;                                                         \
    int j;                                                                  \
    __u8 idx;       /* 下标掩码副本：真机 verifier 需证明 map value 越界前   \
                     * 对未约束标量收窄到 < SPLIT_DOM_MAX（v1.2.0 修）。     \
                     * 掩码源必须是未受 `<SPLIT_DOM_MAX` 比较约束的量——clang   \
                     * 对"已约束到<64 的值 &63"会恒等折叠成无操作，verifier    \
                     * 就看不到掩码、仍按 0-255 判越界。故在循环顶无条件         \
                     * `idx = v->len & 63`（不参与 v->len 上界比较，clang 无法   \
                     * 判其恒等折叠），verifier 遂见 off+idx<=value_size。 */    \
    const struct dom_rule *v;                                               \
                                                                            \
    remain = de->name_len;                                                  \
    if (remain == 0 || remain > SPLIT_DOM_MAX)                              \
        return 0;                                                           \
    name_len = remain;                                                      \
    /* 全量拷贝反转域名（64B 无分支；LPM 只按 prefixlen 位匹配，key->data   \
     * 尾部字节不参与匹配，无需按 remain 清零。禁止逐字节条件拷贝——           \
     * 展开后每字节一个 unknown 分支，verifier 状态爆炸）。 */              \
    __builtin_memcpy(key->data, de->name, SPLIT_DOM_MAX);                   \
    /* 逐字节递减 prefixlen 查询：LPM 只按 prefixlen 位匹配，无需缩短 data。 \
     * unroll(full) 展开成 64 份线性块（无回边），每份一次 map lookup。      \
     * 命中条件（标签边界）见下；最长前缀规则若边界非法（遮蔽）则继续缩短。 */ \
    _Pragma("clang loop unroll(full)")                                      \
    for (j = 0; j < SPLIT_DOM_MAX; j++) {                                   \
        key->prefixlen = remain * 8;                                        \
        v = bpf_map_lookup_elem(&(mapvar), key);                            \
        if (!v)                                                             \
            return 0; /* 规则要命中必先是域名(反转)的字节前缀；LPM 全长查询  \
                       * 返回最长前缀，查无 → 任何 remain 都不可能命中。     \
                       * 无规则匹配的常见路径因此只付 1 次查询（v1.1.2）。 */ \
        idx = v->len & (SPLIT_DOM_MAX - 1); /* 无条件掩码（循环顶）：真机     \
                                             * verifier 需见 off+idx<=size；  \
                                             * 若掩码延迟到守卫内，clang 会   \
                                             * 据 v->len<SPLIT_DOM_MAX 恒等   \
                                             * 折叠掉 &63，verifier 按 0-255  \
                                             * 判越界拒载。见文件头 v1.2.0。 */\
        if (v->len == remain && remain == name_len)                         \
            return 1; /* 规则 = 整个域名 */                                 \
        if (v->len == remain && v->len > 0 && v->len < SPLIT_DOM_MAX) {     \
            if (de->name[idx] == '.')                                        \
                return 1; /* 规则 = 当前查询前缀，且前缀止于标签边界 */        \
        }                                                                   \
        if (v->len > 0 && v->len < remain && v->len < name_len &&        \
            v->len < SPLIT_DOM_MAX) {                                    \
            if (de->name[idx] == '.')                                    \
                return 1; /* 规则边界后是标签分隔符 */                     \
        }                                                               \
        /* 其余（遮蔽/非边界）继续缩短 */                                   \
        if (remain == 1)                                                    \
            break; /* 已是单字节，无法更短 */                               \
        remain--;                                                           \
    }                                                                       \
    return 0;                                                               \
}

DOM_MATCH_FN(dom_match_proxy, map_dom_proxy)
DOM_MATCH_FN(dom_match_direct, map_dom_direct)

#endif /* __SPLIT_BPF_DOM_H_ */
