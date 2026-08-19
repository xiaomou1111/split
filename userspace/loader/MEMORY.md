# userspace/loader — 记忆文档（改本目录代码前必读）

> 覆盖：`loader.{c,h}`（加载/挂载/map 操作）、`iface.{c,h}`（挂载计划/tun 解析）。
> 依赖 libbpf>=1.0。**loader 是用户态对全局 map 的唯一通道**（CONTRIBUTING §2）。

## 接口契约（loader.h 即 ABI）
- `split_load(ctx, obj_path)`：open → find `split_classify` → load → 绑定 **11 个 map 句柄**（v1.4.0 起：v1.1.5 的 15 个 - 域名分流 4 个）。
- `split_attach_iface / split_detach_iface / split_detach_all`：tc 挂载管理。
- `map_set_tun / map_get_tun / map_set_cfg / map_skip_uid_add|del / map_rule_add_cidr / map_cnip_add_cidr / map_rule_clear / map_cnip_clear / map_stats_dump`。
  - **`map_set_cfg`（v1.2.0，v1.4.9 增加 cnip_on）签名为 `(ctx, default_verdict, ipv6_on, skip_uid_on, cnip_on)`**：
    新增 `skip_uid_on` 短路 flag，供内核热路径跳过空 map 的查表
    （对应 `split_cfg.skip_uid_enabled`）。**唯一调用方 rule.c 必须同步传值。**
    **v1.4.0：移除 `dom_on` 参数**（域名分流整模块删除，见 kernel/bpf/MEMORY 第 19 条）。
    **v1.3.1（审查修复）：内部把 `bpf_trace_enabled` 置 1 作为"已初始化"哨兵**——
    map_cfg 是 ARRAY map lookup 永不 NULL，未写入时返回全零元素（default_verdict=0=直连），
    与"未知→代理安全默认"契约相悖；内核 policy.h 凭 `bpf_trace_enabled==0` 回落 TUN。
  - **`map_get_tun`（v1.0.6 新增）**：读 map_tun 当前 ifindex，供 daemon `tun_sync` 做"变化才写"的
    对齐（见 daemon/MEMORY.md tun 存活同步节）。
- **`map_cnip_count(ctx,&n4,&n6)`（v1.1.3 新增）**：遍历 CNIP map 计数（status 自检用；0 条=文件缺失/未导入）。
  实现**必须用 prev-key 顺序迭代**（先取首键，再 `get_next_key(prev,next)` 循环）——与 `map_clear_by_keys` 的
  "反复取首键"相反：那是删除场景（删键后 get_next_key(prev) 提前 -ENOENT），计数不删键，若复用"反复取首键"
  会永远返回同一首键 → 死循环。
  **v1.4.6（审查 P2）**：daemon `status` 不再每次同步全量遍历（WebUI 5s 轮询会阻塞主循环）——
  改由 daemon 缓存计数、仅启动/重灌/自动更新完成时失效重算（见 daemon/MEMORY.md）；`map_cnip_count`
  仍是缓存失效时的重算源。新增 **`map_cnip_cidr_ok(cidr, family)`**（dry-run，不写 map）——
  与 `map_cnip_add_cidr` 判定口径一致（parse_pfix 0..128 + inet_pton，超范围 clamp 计合法），
  供 cni 下载校验阶段计 ok/bad，避免校验期写 map 造成 map≠file（见 cni/MEMORY.md）。
- `map_rule_clear / map_cnip_clear`：reload 前清空对应 map（get_next_key+delete 迭代，HASH/LPM_TRIE 通用），保证"先清空再写"幂等。
  **v1.4.7（审查 P2）**：清空失败必须回传 -1——此前 `map_clear_by_keys` 恒定返 0，任何
  非 -ENOENT 的删除错误（EPERM/句柄失效等）被当成功吞掉，reload 后**旧规则/旧 CNIP 静默残留**
  （配置里已移除的项继续命中）。现 `map_clear_by_keys` 对 `-ENOENT`（正常清完）返 0、其余错误
  （首键查找失败/delete 失败/非 -ENOENT 的 next 错误）返 -1；`map_rule_clear`/`map_cnip_clear`
  任一子 map 清空失败即回传 -1，调用方（rule.c `rule_apply_all` / cni.c `cnip_apply`）显式
  LOG_ERROR 提示"map 状态不一致"但**不中止**（保住可用性，下次 reload 重试）。
- **`map_rule_foreach(ctx, which, cb, priv)`（v1.2.2 新增）**：枚举某 which（0=proxy/1=direct）的 v4+v6 两个规则
  map，把每条 LPM key 还原成 CIDR 文本回调 `cb(which, cidr, priv)`（daemon `list-rules` / WebUI 规则列表用）。
  实现**必须用 prev-key 顺序迭代**（先取首键，再 `get_next_key(prev,next)` 前进）——与 `map_cnip_count` 同款、
  不删键，故不能复用"反复取首键"的 `map_clear_by_keys` 风格（那会死循环）。k4/k6 的 key 从缓冲
  `memcpy` 进局部 struct 再 `inet_ntop`，避免对齐假设。
- `iface_plan(ctx,cfg,out,max[,snap])`：计算待挂 ifindex 列表；`iface_reconcile(ctx,cfg[,snap])`：与已挂集合对齐（增量挂/卸）。
  - **v1.1.9 快照复用（去重复 scan）**：`iface_reconcile`/`iface_plan`/`split_attach_iface`/
    `split_detach_iface`/`map_rawip_sync` 均新增可选 `const struct iface_list *snap` 参数——
    非 NULL 复用调用方已扫的快照，NULL 内部自扫。**`iface_reconcile` 全程只 scan 一次**
    （传入或自扫，v1.2.8 起 NULL 路径由 reconcile 统一自扫并透传，不再"1+N+1 次"）——
    并向 iface_plan + 各 attach/detach + 尾部 `map_rawip_sync(0)` 透传同一快照；
    daemon 网络事件路径复用 `iface_watch_poll` 已填的快照 → **一次事件 0~1 次 scan**。
    此前 `iface_reconcile` 一次会扫 1(plan)+N(每接口 rawip)+1(全量 rawip) 次。
  - **v1.1.7 调用频次变化**：`iface_reconcile` 现由 daemon 主循环 **5s 节流周期调用**（接口挂载
    自愈心跳，见 daemon/MEMORY「网络切换」），不再只依赖 netlink 事件。`iface_plan` 的
    "待挂接口 n 个"日志已由 INFO 降为 DEBUG——周期调用下 INFO 会每 5s 刷一条，真正挂/卸仍是 INFO。
  - **v1.1.7 `split_attach_iface` 幂等去重改为"核验真实状态"**：原逻辑只看 `ctx->attached[]`
    （daemon 内存自认为状态），网卡上的 cls_bpf filter 若被外部清除（ifindex 不变、netlink
    无事件、Android wifi down/up）会误判"已挂"而跳过 → eBPF 实际已在路径外（静默失效）。
    现先用 `split_filter_exists()`（`bpf_tc_query` / RTM_GETTFILTER，对照 dev/egress/handle=1/
    priority=10）核验：filter 在 → 跳过；丢失 → 从 attached[] 移除记录并走重挂。这样 5s 心跳
    对每个 plan 接口各做一次 netlink query（<1ms，可忽略），补齐"attached[] 盲区"。
  - **v1.1.9 `split_detach_all` 去冗余扫描**：抽出 `split_detach_core`（仅 detach+attached[] 维护，
    不做 map_rawip 同步）；`split_detach_all` 先循环 `split_detach_core` 全卸，结尾统一一次
    `map_rawip_sync(0,NULL)`。此前对 N 个接口各调 `split_detach_iface(x,NULL)` 会触发 N 次
    全量 netlink dump（纯开销）。
  - **v1.1.9 `attached[]` 显式上限防护**：`split_attach_iface` 在 attach 动作前检查
    `ctx->nattached >= IFACE_MAX` 即拒绝（返回 -ENOSPC）——必须**在 attach 前**，避免
    "filter 已挂上但记录因满而未写入"泄漏。**审查修正（审查条目 1）：此检查必须放在
    幂等去重之后**，否则 `nattached==IFACE_MAX` 时去重分支永远走不到（见「关键实现与坑」1）。

## 关键实现与坑
1. **`split_attach_iface` 顺序：去重先于容量检查（审查修正）**。函数内
   "幂等去重 + 按真实 filter 状态核验"（`for k` 循环，`split_filter_exists`）
   必须**先于** `nattached >= IFACE_MAX` 的容量检查执行。理由：
   - 去重里"已挂且真实存在"→ return 0；"filter 丢失且记录在 attached[]"→
     先移除记录（`nattached--`）腾出容量再走重挂；
   - 若容量检查前置，`nattached==IFACE_MAX` 时 5s 心跳 reconcile 会对每个
     已挂接口先撞 `-ENOSPC` + ERROR 刷屏，去重分支永远走不到。
   因此容量检查只在去重之后、attach 动作之前拦截"真正要新增"的接口。
2. **`SEC("classifier")` 旧式 section，libbpf>=1.0 不再按它推断程序类型**（报
   "failed to guess program type from ELF section 'classifier'"）。`bpf_object__load`
   前必须 `bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS)`（loader.c:split_load
   已做）。这也是 `bpftool prog load ... type sched_cls` 在现代 libbpf 下失效的原因，
   验证只能走 splitd（见 BUILD.md §4.1）。
3. **k4/k6 用户态 key 必须与内核 `lpm_key4/6` 字节一致**（prefixlen 在前）。改内核结构 = 改这里。
4. **tc attach 固定 handle=1 priority=10**：detach 必须传相同 handle/priority，否则 detach 失败（libbpf bpf_tc_detach 按此匹配）。
5. `bpf_tc_hook_create` 返回 `-EINVAL/-EEXIST` 属正常（clsact 已存在），只 warn 不 fail；**attach 失败才报错**。
   **v1.1.4 加固：attach 必须带 `BPF_TC_F_REPLACE`**——splitd 异常退出（kill -9/崩溃）后
   cls_bpf filter 残留网卡并持引用保住旧 prog+旧 maps；不带 REPLACE 的 `bpf_tc_attach`
   对同 handle=1/priority=10 返回 EEXIST → 新 daemon 挂不上（nattached=0），残留 filter
   继续用旧 map（新规则全落空）→ **静默失效**。clean 重启不受影响（detach_all 已清）。
   **兜底（同一提交）**：REPLACE 之外仍保留"遇 -EEXIST 先 `bpf_tc_detach`（同 handle/priority）
   再重挂一次"的 retry 路径，覆盖 libbpf 未实现 REPLACE 的版本。
6. 幂等：`split_attach_iface` 查 `attached[]` 防重挂（v1.1.7 起还查真实 filter 存在性，
   `split_filter_exists`，丢失即重挂）；`iface_reconcile` 先卸（不在计划）后挂（新）。注意 `iface_reconcile` 卸载时用 `ctx->attached[k--]` 索引回退，避免移位漏项。
7. `map_rule_add_cidr` / `map_rule_del_cidr` 的前缀长收敛（v1.0.5 修正）：v4 `pfix>32 → 32`、v6 `pfix>128 → 128`。
   **此前 v4 特判 `pfix>32 && pfix!=128` 会把 `1.2.3.0/128` 写进 v4 map**——LPM key 的 prefixlen=128 对 v4 trie 非法，
   内核 update 直接失败（返回 -EINVAL）。cnip 版本无此特例（`map_cnip_add_cidr` 早已直接收敛）。
   **v1.1.2 严格化（`parse_pfix`）**：三个入口统一用 `strtol+endptr` 校验，拒绝垃圾输入——
   旧 `atoi` 会把 `"/abc"` 解析成 0（LPM prefixlen=0 → **匹配全部流量**，高危误分流）、
   `"/-1"` 静默收敛成 32。非法/负值/超 128 → 返回 -1 记 ERROR。合法 `/0` 与跨族 `/128`
   （v4 侧仍收敛 32）行为不变。
   **v1.1.3 补漏**：**空串（`"1.2.3.4/"`）同样拒绝**——`strtol("")==0` 同样会静默成为 /0。
   **审查（2026-08）`map_rule_del_cidr` 对 `-ENOENT` 降级**：删除不存在的键（如 `del-rule` 一条
   早已不在配置基线、仅存于运行时覆盖里的规则，`rule_overrides_replay` 的 present=0 分支）是合法
   no-op——此前 `bpf_map__delete_elem` 返 `-ENOENT` 打 ERROR 刷日志误导"删除失败"。现 `-ENOENT`
   记 DEBUG 并返回 0（幂等），仅其它真错误才 ERROR。
8. `map_cnip_add_cidr` 失败返回 `-1` 但**不打印具体原因**；cnip.c 用返回值计数 ok/bad。
9. `map_skip_uid_del` 用 `bpf_map__delete_elem(..., 0)`；HASH map 才支持 delete，LPM_TRIE 也支持（v1.0.1 新增 `map_rule_del_cidr`）。
10. `map_stats_dump`：PERCPU_ARRAY 逐槽 `libbpf_num_possible_cpus()` 求和。
    **v1.2.8（审查加固）**：单槽 lookup 失败加 `LOG_WARNF`（不再静默 continue 计 0）——
    PERCPU value_size 以创建时 CPU 数定，极端（CPU 热插拔/环境不一致）时可能不足而失败；
    失败槽按 0 输出但日志可查。
11. `map_rule_clear / map_cnip_clear`（reload 前清空，保证"先清空再写"幂等，走 `map_clear_by_keys`）。清 LPM_TRIE 必须"反复取首键（cur=NULL）+ delete"；**不要**用 `get_next_key(前一个键)` 迭代——删键不在 trie 后 `lpm_trie_get_next_key` 会 -ENOENT 提前终止导致残留。
    **v1.0.5 防死循环**：`delete_elem` 失败（如权限/竞争）时必须 break，否则反复取回同一键无限循环。
    **v1.1.1 修复**：键缓冲 `cur[128]` ≥ 最大 key 大小（当时最大为 dom_key=4+64=68B；v1.4.0
    移除域名 map 后现最大为 lpm_key6=4+16=20B）。此前 `cur[32]` 让 `map_dom_clear` 静默失败
    （返回 -1 被忽略），reload 后旧域名规则残留——改 key 大小必须复查此缓冲。
12. `iface.h`：`iface_resolve_tun(name)` 用 `iface_index_by_name` 兜；不存在返回 -1 → daemon 提前退出（exit 3）。
13. **map_rawip（v1.1.5，蜂窝 RAWIP 修复）**：`map_rawip_sync(ctx, ifindex[, snap])`——
    ifindex>0 单接口按 `iface.type==ARPHRD_RAWIP(519)` 写入/删除；ifindex=0 全量同步。
    **v1.1.9：新增可选 `snap` 快照参数**（非 NULL 复用、NULL 自扫），`iface_reconcile`
    全程透传同一快照，使"挂载+RAWIP 同步"在一次 reconcile 里共用一次 scan。
    **v1.1.8（审查加固）：全量路径"无变化零开销"**——先扫描算目标集合、与 map 现状比对
    （HASH 只读遍历），集合相同直接返回，不再每 5s 心跳无条件 `map_clear_by_keys`+重写
    （清空窗口内内核 parse 对 RAWIP 接口退化成"按有 L2 头解析"，瞬时直连窗口放大）。
    **v1.1.6 加固：写入判据统一为 `rawip_iface_type() && iface_is_physical()`**——
    之前的全量重建只查 type+UP 而未套 `iface_is_physical`，会把 `rmnet_ipa0`（RAWIP 519
    但帧带 RMNET MAP 封装头，不可按裸 IP 解析）也写进 map；虽因该接口从不挂 tc 而无实害，
    但注释声称"与挂载计划口径一致"实则有出入。现在单接口与全量两条路径一致用
    `iface_is_physical`（内建 IFF_UP 与 rmnet_ipa/tun 排除）。
    调用点：`split_attach_iface`/`split_detach_iface`（单接口）+ `iface_reconcile` 末尾（全量兜底，
    覆盖"接口类型变化但没触发挂/卸"的边角）。**不改会怎样**：Android 蜂窝 rmnet_data*
    无以太网头，内核 parse.h 若按以太网解析全失败 → 海外无法进代理（v1.1.5 真机问题）。
    注意 `map_clear_by_keys` 是文件后部 static，本函数里用要先前向声明。
    另：`map_rule_add_cidr/map_rule_del_cidr/map_cnip_add_cidr` 的 CIDR 缓冲
    `char buf[64]` **v1.1.6 加大到 `[200]` 并对 snprintf 返回值判溢出**——配置行源可达
    CFG_STRLEN(128)，旧 64 会让超长 cidr 静默截断 → inet_pton 解析失败记错。
17. **`iface_reconcile` 一轮汇总（v1.4.5，DEBUG）**：记 `n_before`（调整前已挂数）→ detach 后
    `n_keep`（保持集）→ attach 后算 `n_detach=n_before-n_keep`、`n_add=nattached-n_keep`。
    `n_keep` 必须**在 detach 循环后、attach 循环前**捕获——若放 attach 后，nattached 已含新增，
    n_detach 会为负、n_add 恒 0。仅当 `n_add>0 || n_detach>0` 打 DEBUG（15s 心跳无变化不打，
    避免每轮刷屏）。
16. **`iface_plan`（iface.c）：两个分支统一套 `iface_is_physical`（审查修正）**。
    `attach_auto=0` 分支在比对 `attach_list` 名字命中后，仍需经 `iface_is_physical`
    确认真正是物理网卡——此前只比对名字 + exclude，用户若把 `utun0`/`tun0` 写进
    `attach_list` 会把虚拟/tun 接口挂载上去（回环 + parse_err）。与 `attach_auto=1`
    分支口径一致；`iface_is_physical` 内建 IFF_UP 与 lo/tun/utun/rmnet_ipa 等排除。
    **审查（2026-08）补充：未命中项此前完全静默**——拼错接口名（wlan1 vs 实际 wlan0）
    或显式列出非物理接口都无提示、静默不挂（流量全走默认直连）。现 `iface_plan` 对
    "设备上不存在"/"非物理网卡"两个类别各告警一次到进程级（每 5~15s 心跳都跑，不去重
    会刷屏；daemon reload 沿用同一 cfg 结构故不重复）。仅诊断提示，不改变挂载行为。

## 日志（v1.4.5 补全）
- `map_by_name`：map 打开失败 `LOG_ERRORF`（名字），成功 `LOG_DEBUGF`（debug:true 下逐 map 核对打开情况）。
- `split_load` 成功行（INFO）：附 `split v%s` + `libbpf %s`（`libbpf_version_string()`）——一眼核对二进制与库版本是否匹配。

## 已知缺口
- 无 pinning（`SPLIT_PIN_NS` 仅常量未用）；无 map 类型/大小自检。

## CNIP 临时开关（v1.4.9）
- `map_set_cfg(ctx, default_verdict, ipv6_on, skip_uid_on, cnip_on)` 继续是 map_cfg 的唯一写入口；`cnip_on` 只改策略 flag，不新增 map。
- daemon 的 `cnip on|off` 用当前完整配置调用该接口，写成功后才更新进程状态；CNIP map 的清空/灌入/定时更新不受开关影响。

## 验证
- `make -C userspace`；挂载冒烟见 tests/integration.sh（需 Linux root）。