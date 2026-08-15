/* SPDX-License-Identifier: GPL-2.0
 * paths.h — 运行路径解析（用户态）
 *
 * 提供跨平台的运行时路径（unix socket 等）。
 * Android 没有 /run 目录，故支持 SPLIT_SOCKET 环境变量覆盖默认值。
 */
#ifndef SPLIT_USERS_PATHS_H_
#define SPLIT_USERS_PATHS_H_

/* 返回控制 socket 路径；优先 $SPLIT_SOCKET，否则默认 /run/splitd.sock。
 * 审查（2026-08）纠偏：返回值**不是**静态缓冲——是 getenv 返回的环境变量字符串或
 * 编译期字面量（见 paths.c），调用方不得 free；本程序不修改环境变量，指针进程期稳定。
 * Android 建议 export SPLIT_SOCKET=/data/adb/split/splitd.sock。 */
const char *split_socket_path(void);

/* 返回 splitctl start 派生 splitd 的日志文件路径；优先 $SPLIT_LOG，否则默认
 * /var/log/splitd.log（v1.1.9：此前 hardcode 在 splitctl.c，现收敛到路径体系）。
 * 返回值同 split_socket_path：非静态缓冲（env 字符串或字面量），不得 free。
 * Android 侧由 service.sh 直接重定向 logs/splitd.log，不走本函数。 */
const char *split_log_path(void);

#endif
