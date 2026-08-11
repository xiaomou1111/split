/* SPDX-License-Identifier: GPL-2.0
 * daemon.h — splitd 守护进程公共声明
 */
#ifndef SPLIT_USERS_DAEMON_H_
#define SPLIT_USERS_DAEMON_H_

#include "../../kernel/include/split_bpf.h"

#ifndef SPLIT_BPF_OBJ_DEFAULT
#define SPLIT_BPF_OBJ_DEFAULT "/etc/split/split.bpf.o"
#endif

void daemon_loop(const char *cfg_path, const char *bpf_obj, int debug);

#endif