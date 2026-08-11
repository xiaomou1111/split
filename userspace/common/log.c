/* SPDX-License-Identifier: GPL-2.0 */
#include "log.h"

#include <stdarg.h>
#include <time.h>

int g_log_level = LOG_INFO;

void log_impl(int level, const char *fn, int line, const char *fmt, ...)
{
    static const char *LV[] = { "DBG", "INF", "WRN", "ERR" };
    char buf[1024];
    char tbuf[32];
    va_list ap;
    struct timespec ts;
    struct tm tm;

    if (level < g_log_level)
        return;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s.%03ld [%s] %s:%d  %s\n",
            tbuf, ts.tv_nsec / 1000000,
            LV[level], fn, line, buf);
}