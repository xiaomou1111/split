/* SPDX-License-Identifier: GPL-2.0
 * log.h — 日志模块
 * 仅依赖 libc；不引入第三方日志库，保证 Android 交叉编译简便。
 */
#ifndef SPLIT_USERS_LOG_H_
#define SPLIT_USERS_LOG_H_

#include <stdio.h>

enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3,
};

extern int g_log_level;

#define LOG_DEBUGF(...) log_impl(LOG_DEBUG, __func__, __LINE__, __VA_ARGS__)
#define LOG_INFOF(...)  log_impl(LOG_INFO,  __func__, __LINE__, __VA_ARGS__)
#define LOG_WARNF(...)  log_impl(LOG_WARN,  __func__, __LINE__, __VA_ARGS__)
#define LOG_ERRORF(...) log_impl(LOG_ERROR, __func__, __LINE__, __VA_ARGS__)

void log_impl(int level, const char *fn, int line, const char *fmt, ...);

#endif