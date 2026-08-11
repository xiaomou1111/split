/* SPDX-License-Identifier: GPL-2.0
 * netlink.h — 接口(iface)发现与监听（纯 netlink，不依赖 iproute2）
 *
 * 使用：
 *   struct iface_list {
 *       struct iface_info  items[IFACE_MAX];
 *       int                count;
 *   };
 *   iface_scan(&list)                       // 快照
 *   int fd = iface_watch_open();            // 进入监听，配合 poll()
 *   iface_watch_poll(fd, &list)             // >0 有变化，且填好最新快照；0 无变化不填
 */
#ifndef SPLIT_USERS_NETLINK_H_
#define SPLIT_USERS_NETLINK_H_

#include <linux/if_link.h>
#include <stdint.h>

#define IFACE_MAX 128
#define IFACE_NAME_MAX 16

struct iface {
    char  name[IFACE_NAME_MAX];
    int   ifindex;
    int   type;           /* ARPHRD_* */
    unsigned flags;       /* IFF_* , 内核位 */
};

struct iface_list {
    struct iface items[IFACE_MAX];
    int count;
};

/* 该接口是否是"值得挂载 eBPF"的物理网卡（排除 lo/tun/tap/dummy/...） */
int iface_is_physical(const struct iface *i);

/* 按名字得到 ifindex；失败 -1 */
int iface_index_by_name(const char *name);

/* 检测路由是否被外部接管：存在"default 路由指向 tun_ifindex"且其所在路由表被
 * 无条件 ip rule 选中（或就在 main 表）。1=被接管 0=正常 -1=检测失败 */
int route_tun_hijacked(int tun_ifindex);

/* 扫描当前接口，填入 list。返回 0 成功 */
int iface_scan(struct iface_list *list);

/* 打开监听 socket（订阅 link 事件）。返回 fd（poll 用）或 -1 */
int iface_watch_open(void);

/* 处理待读事件，返回 1=网络有变化 0=无 -1=错误 */
int iface_watch_poll(int fd, struct iface_list *snapshot);

void iface_close(int fd);

#endif