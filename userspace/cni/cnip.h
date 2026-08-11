/* SPDX-License-Identifier: GPL-2.0
 * cnip.h — CNIP 数据源加载模块
 */
#ifndef SPLIT_USERS_CNIP_H_
#define SPLIT_USERS_CNIP_H_

#include "../loader/loader.h"
#include "../common/config.h"

/* 从本地文本文件（每行一条 A.B.C.D/N 或 IPv6/N）灌入 cnip map。
 * family: AF_INET / AF_INET6。返回 0 成功，-1 失败。 */
int cnip_load_file(struct split_bpf_ctx *ctx, const char *path, int family);

/* 从 URL 下载到临时文件再调用 cnip_load_file（无网络库，借 curl/wget） */
int cnip_load_url(struct split_bpf_ctx *ctx, const char *url,
                  const char *tmp_path, int family);

/* 全量加载（两族），按配置 */
int cnip_apply(struct split_bpf_ctx *ctx, const struct split_config *cfg);

/* 自动更新：下载 url_v4/v6（若配置）到对应本地文件后全量应用。
 * 返回 0 成功/无可更新，-1 失败。依赖 curl/wget。 */
int cnip_auto_update(struct split_bpf_ctx *ctx, const struct split_config *cfg);

#endif