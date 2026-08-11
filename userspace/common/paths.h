/* SPDX-License-Identifier: GPL-2.0
 * paths.h — 运行路径解析（用户态）
 *
 * 提供跨平台的运行时路径（unix socket 等）。
 * Android 没有 /run 目录，故支持 SPLIT_SOCKET 环境变量覆盖默认值。
 */
#ifndef SPLIT_USERS_PATHS_H_
#define SPLIT_USERS_PATHS_H_

/* 返回控制 socket 路径；优先 $SPLIT_SOCKET，否则默认 /run/splitd.sock。
 * 返回值指向静态缓冲区，每次调用可能不同（Android 建议 export SPLIT_SOCKET=/data/adb/split/splitd.sock）。 */
const char *split_socket_path(void);

/* 返回 splitctl start 派生 splitd 的日志文件路径；优先 $SPLIT_LOG，否则默认
 * /var/log/splitd.log（v1.1.9：此前 hardcode 在 splitctl.c，现收敛到路径体系）。
 * 返回值指向静态缓冲区；Android 侧由 service.sh 直接重定向 logs/splitd.log，不走本函数。 */
const char *split_log_path(void);

#endif
