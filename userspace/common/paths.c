/* SPDX-License-Identifier: GPL-2.0 */
#include "paths.h"

#include <stdlib.h>
#include <string.h>

#include "../../kernel/include/split_bpf.h"

const char *split_socket_path(void)
{
    const char *env = getenv("SPLIT_SOCKET");

    if (env && env[0])
        return env;
    return SPLIT_SOCKET;
}

const char *split_log_path(void)
{
    const char *env = getenv("SPLIT_LOG");

    if (env && env[0])
        return env;
    return SPLIT_LOG;
}
