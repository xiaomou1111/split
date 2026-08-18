# 06-ROADMAP — 路线图与已知缺口

> 这里如实记录"尚未实现 / 计划中的部分"，避免使用者误以为已经完备。

## 已实现（本版）

- [x] 内核：tc egress 分类 + `bpf_redirect(tun0)` 转发
- [x] CNIP(IPv4/IPv6) LPM_TRIE 分流
- [x] proxy/direct 规则段 + UID 白名单
- [x] 内置本地段（回环/链路本地/组播）
- [x] 用户态：splitd 守护 + splitctl 命令 + netlink 网络跟随
- [x] CNIP 文本导入（文件/URL）
- [x] 配置解析与示例（redir-host / fake-ip 两套 mihomo 配置）
- [x] Android：Magisk 模块骨架 + sepolicy + 降级路径
- [x] **域名分流（v1.1.0 引入，v1.4.0 整模块移除）**：曾为"用户态 AF_PACKET 学 DNS 响应
  （IP→域名）+ 内核 `map_dom_proxy/direct` 域名后缀规则（反转 LPM 匹配，优先级高于 IP
  段规则）"；v1.4.0 移除内核域名判定（policy 8→7 步）、4 个 map、学习器模块与配置，
  主线回归纯 IP/UID 分流（取舍见文末"已知设计取舍"第 4 点）
- [x] **熄屏/doze 自愈（v1.1.7）**：daemon 主循环 15s 节流 `iface_reconcile`（P3：5s→15s，netlink 事件漏收
   时自动重建挂载，且 `split_attach_iface` 经 `bpf_tc_query` 核验 filter 真实存在、丢失即重挂）
  + `scripts/split-watchdog.sh`（splitd 进程死亡后按同参数拉起，配停止闸）
- [x] **mihomo TUN 自愈（v1.2.9）**：`split-watchdog.sh` 探活分支解析 `tun=` 字段，`map_tun=0`
  （mihomo TUN 消失、代理静默放行直连）连续 2 轮且 `bin/mihomo` 存在 → 先经 mihomo API
  `PATCH /configs {"tun":{"enable":true}}` 无感恢复，API 失败重启 mihomo，5 分钟冷却防循环——
  补上"splitd 活着但代理失效"这条原 watchdog 盲区（真机问题）
- [x] **文档：架构 / 模块说明书 / 安卓兼容 / 配置 / 术语**
- [x] **v1.1.9 审查收敛**：DNS 过期时钟改 BOOTTIME（熄屏也推进，`bpf_ktime_get_boot_ns`，需内核 ≥5.8）；
  `iface_reconcile` 全程快照复用去重复 scan；`splitctl` 的 `-d` 语义改为 debug、splitd 路径改 `-s`；
  日志路径收敛 `split_log_path()`；补 `.gitignore`（构建产物/敏感配置不入库）
- [x] **v1.2.9 审查加固**：CNIP 更新子进程 exec curl 前 fd 全置 `FD_CLOEXEC`；config 空列表告警
  （声明规则列表但无项 → 默认 fake-ip/内网段被静默清空可见）；运行时规则 cidr 超长显式拒绝
  （防 snprintf 截断 → reload 重放写截断串）

## 缺口（诚实清单）

| 项 | 状态 | 说明 |
|---|---|---|
| `del-rule`（在线删规则） | 已实现 | `bpf_map__delete_elem` 走 LPM_TRIE delete；cli → daemon 协议已支持 |
| TUN 以太网头 | 无需处理 | WSL2 实测：`bpf_redirect` 到 /IFF_TUN 时 tun xmit 自动剥 L2，mihomo 读到裸 IP；手动 `bpf_skb_adjust_room` 反而会损坏 IP 头（已回滚） |
| rule map 全量重建 | 已实现（v1.0.5） | `reload` 用 `map_rule_clear` 先清空再全量写（幂等），删减配置无需重启；CNIP 的 `reload-cnip` 同理（`map_cnip_clear`） |
| CNIP 自动更新下载器 | 已解决（v1.4.1） | 依赖 curl 的缺口补齐：绝对路径优先，回落 wget/busybox（Android 常无 curl）；下载失败/HTTP 错误/内容 0 条沿用本地旧文件，不把 CNIP 清空（见 cni/MEMORY） |
| VLAN 双层/多标签 | 双层（v1.1.x）| parse 跳至双标签 QinQ（`VLAN_MAX_TAGS=2`）；三标签以上等 roadmap |
| ICMP 进 mihomo | 内核侧 OK | mihomo 侧对部分 ICMP 支持有限（见 FAQ Q 章节） |
| ingress 钩子（观察/统计入站） | 未做 | 为省性能刻意不做 |
| tproxy 模式（`mode: tproxy`） | 不可行 | 内核硬限制：tproxy 目标只支持 PREROUTING，不支持本机出站方向（见"tproxy 模式"节） |
| eBPF 劫持 → mihomo TUN | 已解决 | `skb->queue_mapping=0` 修复（v1.0.4），真机 curl 200 + Play 可用 |
| 原生 Android App（UI 开关） | 未做 | 现在 root shell / Magisk 方式（android/app/README）；**KernelSU WebUI**（webroot/）已含：状态/stats/在线规则列表与增删/日志/配置编辑/版本号（v1.2.2；v1.4.0 移除 DNS 卡片） |
| BPF 单元测试套件 | 骨架 | tests/unit/README 有规划 |
| DNS 拦截（domain 级分流） | **已移除（v1.4.0）** | 整模块移除：内核域名判定 + 用户态 DNS 学习器 + 4 个 map + `dns` 命令 + 域名配置段；域名粒度分流统一交给 mihomo（fake-ip/redir-host + 规则引擎） |
| 域名规则在线增删（add-domain/del-domain） | 不再需要 | 域名分流已随 v1.4.0 整模块移除 |
| 自动选择 tun 设备 | 半自动 | 必须与配置名一致；失败会明确报错 |
| 多用户（工作资料）UID 处理 | 配置化 | 需手动加 uid |

## 路线

```
v1.0（2026-08 基线）  骨架完整可用：内核分流 + mihomo 转发 + 安卓模块
v1.0.1                在线规则增删（rule_del 已实现）+ NDK 交叉编译文档
v1.0.2                修复 WSL2 实测发现的 3 个 bug：netlink bind、config 尾空白、
                      TUN 剥头改"自动剥头"（移除 bpf_skb_adjust_room）
                       真机(小米5.10 GKI+KernelSU)实测：-mcpu=v1、SPLIT_SOCKET、分流验证通过
                       tproxy 形态 A 实测否定（tproxy 只支持 PREROUTING，不支持本机出站）
                       端到端接入 box mihomo TUN：CN 直连/海外代理全链路验证通过
                       真机再修 2 bug：config 布尔解析(parse_bool)、utun 误挂回环(exclude)
v1.0.3                TUN redirect 研究：曾误判"mihomo 无法接受 bpf_redirect 注入"
v1.0.4                 **根因找到并修复：skb->queue_mapping=0**（tun 多队列索引越界→drop）。
                       真机验证：curl google 200、Play 可用、内核 CNIP 分流 + mihomo 全链路打通
v1.1.0                域名分流：用户态 DNS 学习（AF_PACKET）+ 内核域名后缀规则表
v1.1.9                安全/健壮性审查轮次（CNAME 预过滤修正、逐位解析加固等）
v1.2.0                运行时规则（add-rule/del-rule）跨 reload 保留；dns 缓冲复用；CNAME 链学习
v1.2.1                mihomo 重载配置重建 utun 后即时对齐 map_tun（网络事件/reload 两处触发 tun_sync）
v1.2.3                 hijack 判定修复：route_tun_hijacked 的 RTA_OIF 遍历 payload 残值 bug
                      （非 main 表 default-via-tun 误判 main 表）+ rule_steals_table 误判
                      "内核恒带占位属性"（FRA_SUPPRESS_PREFIXLEN=-1 / PROTOCOL / PRIORITY）导致
                      真实无条件劫持漏判；新增 clean-mihomo-residue.sh 清理 mihomo auto-route 残留
v1.2.4                 tun_sync 快照权威复核 + 降级快重试：修复 mihomo 重载配置重建 utun 时，
                      事件快照恰拍在 DELLINK/NEWLINK 间隙导致"ip link 可见 utun 但 map_tun 误置 0、
                      代理完全失效"的假象（快照缺 utun 时强制重扫复核；utun 缺失降级期间
                      心跳 1s→300ms（持续缺失按 300ms→1s→5s→30s 退避封顶，"恢复 ≤300ms"仅瞬时抖动成立））
v1.2.5                 tun 名字漂移兜底：mihomo 重载后新 TUN 可能不再叫配置名。精确匹配
                      （含复核）仍缺时按"比最近一次有效 ifindex 更新 + IFF_UP + TUN 类名字"
                      找候选自动对齐并 WARN；"不存在"日志附带 TUN 类接口清单便于诊断
v1.2.6                 源码修正 + 按类型兜底：mihomo Alpha listener/sing_tun/sing_tun.go 核实——
                       Linux 回退名是 InterfaceName 默认 "Meta"（device 为空时），并非 v1.2.5
                       假设的 tunN。tun_name_like 直接认 "Meta"；tun_find_drift 追加
                       ARPHRD_NONE（L3 TUN）类型兜底，覆盖重载后落到任意 device 名（含 WebUI
                       把 device 改空），排除 wg/tailscale 防误挂
v1.2.7                 审查修复轮次：①DNS 学习器移除 cBPF 内核预过滤（RAWIP 蜂窝偏移错位致
                       静默漏学，改用户态全过滤，Ethernet/RAWIP 双布局正确）②A/AAAA 记录按
                       自身 owner 归属（旧方案归属到查询名/CNAME 目标，多 owner 应答错配）
                      ③poll 错误事件（POLLERR/HUP/NVAL）显式消费防忙循环，ctl listen/netlink
                       watch 自动重建、DNS 学习器降级④list-rules 客户端断连即中止枚举
                      ⑤status 增 tun 缺失 WARN（map_tun=0 静默降级可见）⑥route_tun_hijacked
                       路由表集合容量 16→64、写满按检测失败处理防漏报接管⑦del-rule 前缀收敛
                       补 WARN 与 add 一致⑧tun_name_like 空 tun_device 不匹配⑨check-kernel.sh
                       退出码接入硬依赖检查⑩gen-magisk.sh versionCode 改为无碰撞方案
v1.4.9（当前）        2026-08-18 CNIP 临时绕过开关：新增 `splitctl cnip on|off|status` 与
                        KernelSU WebUI 控制；`off` 仅跳过 BPF policy 第 6 步 CNIP LPM 查询、
                        后续按 default verdict 裁决，CNIP map 仍继续启动导入/后台刷新，普通
                        reload 保留状态、重启 splitd 恢复 on；map_cfg ABI 尾部追加 cnip_enabled，
                        status 增 `cnip=on|off` 供 WebUI 解析
v1.4.8        2026-08-15 模块脚本审查批（行为：fix-mihomo-tun.sh 强制 tun.enable:true
                        段内限域 + setup-box-tun.sh 去冗余内联 sed + customize.sh 升级清 mihomo
                        版本缓存 + webuiapi.sh get_log 上限；详见当次提交）
v1.4.7        2026-08-15 审查剩余 P2 修复批（5 项真 P2 + 1 项连带，详见当次提交）：
                      ①config.c auto_update_hours 非法值用 break 直接跳出整个解析 while 循环，
                        静默丢弃该行之后的所有配置行仍返成功（如 path_v6/整个 rules 节）；改
                        continue 仅跳过本行保留默认值，并加 endp==v 检出空值（strtol("") 返 0
                        且校验通过，空 `auto_update_hours:` 被静默当成 0=禁用自动更新）
                      ②daemon update-cnip 只查 url 不查 path——配了 url 缺 path 时回"OK 已安排"、
                        子进程空转返 0、父进程按成功回收（用户以为已更新实际没动）；改为与
                        boot_once 同口径 (url&&path) 同族配齐判定，无可用组合回 ERR 点明
                      ③daemon ctl listen fd 错误重建后同轮 POLLIN 会对新建的空监听 socket 调
                        阻塞式 accept()（ctl_listen 不设 O_NONBLOCK）→ 主循环整体冻结（心跳/
                        reconcile/hijack/CNIP 调度停摆）；重建后 continue 跳过本轮 POLLIN 分支
                      ④netlink iface_scan 达 IFACE_MAX=128 时返"部分成功"截断列表——调用方
                        （iface_reconcile）据截断 plan 把第 128 名之后已挂接口误卸载（静默丢
                        路由）；改为 return -1，与 NLMSG_ERROR/畸形口径一致，调用方保持原状态
                      ⑤loader map_clear_by_keys 任意错误 break 但恒返 0——clear 失败被当成功，
                        reload 在"半清空"map 上叠加写，配置中已移除的旧规则/CNIP 前缀静默残留；
                        改 -ENOENT 正常完成返 0、其它错误返 -1，map_rule_clear/map_cnip_clear
                        上抛，rule_apply_all/cnip_apply 显式 LOG_ERROR（不中止，下次 reload 重试）
v1.4.6        2026-08-15 全库再审查 P2 修复批（7 项，详见当次提交）：
                      ①splitctl send_cmd 映射 ERR 退出码——daemon 回 ERR 时 $? 非 0，
                        webuiapi/app.js 不再把操作失败当成功（规则增删/update-cnip 误报）
                      ②config.c is_section 补 '\r'——Windows/CRLF 写的 split.yaml 节头不再整节失效
                      ③split-watchdog.sh curl PATCH 加 -f——API 401/4xx 落 restart_mihomo 兜底，
                        TUN 自愈不再永久卡死
                      ④daemon status 的 CNIP 计数缓存化（启动/重灌/自动更新后失效重算，
                        轮询期 O(1)，消除每 5s 全量遍历阻塞主循环）
                      ⑤cnip 下载校验改 dry-run——rename 失败时不再出现 map≠file 残留
                      ⑥docs/04 verdict 示例去引号（解析器不剥引号，带引号会 WARN 回落）
                      ⑦"url 留空=周期重读本地"虚假声明纠偏（实为自动更新对该族空转）
                      ⑧config.c P3 解析健壮性批次（5 项，纯诊断+宽容性，详见 common/MEMORY 坑 13）：
                        skip_uid 空列表清默认 root/shell 补 WARN；长行 fgets 拆断+>255 截断检出；
                        `key : value` 冒号前空格 trim；孤儿 `- item` WARN；顶层 key 误放节内
                        点明"请移到文件顶部"
v1.4.5        DEBUG 日志补全（纯增量，无行为/契约变更；debug:true 下可见更多过程细节）：
                      ①loader：map 打开成功/失败明细、加载成功附带 split/libbpf 版本
                      ②cnip：下载器识别（curl/wget）、每源下载耗时、混合文件按族加载跳过行数
                      ③rule：reload 后按族规则计数（uid/proxy4/proxy6/direct4/direct6）、
                        skip_uid 白名单枚举（DEBUG）
                      ④daemon：ctl 实际收到命令、CNIP 更新子进程收尸结果（成功/失败形态）
                      ⑤iface：reconcile 一轮"新增/卸载/保持"汇总（有变化才打）
                      ⑥版本号 1.4.5（bump-version.sh）
v1.4.4        CNIP 加载诊断改进（2026-08 CNIP 审查 P3 修理）：
                      ①下载校验按失败形态区分日志：bad>0 → "N 行非法（疑似错误页/垃圾）"；
                        bad==0 → "空或全为另一地址族行（检查 url 配错族）"（v1.4.3 族过滤
                        使异族行不计 bad，二者不再同报"疑似错误页"）
                      ②本地加载 0 条显式 LOG_WARNF：文件空/全为另一族/全非法不再被 INFO 掩盖
                        （如 v4-only 文件配到 v6）；行为零变化，纯诊断
                      ③版本号 1.4.4（bump-version.sh）
v1.4.3        CNIP 默认源换 mihomo 生态权威源 Loyalsoldier/geoip + 混合文件按族加载：
                      ①**默认源换权威**：v4/v6 都指向 `Loyalsoldier/geoip` `release/text/cn.txt`
                        （mihomo 生态默认 GeoIP，每日更新；实测 v4=4145 / v6=1235 条，纯 CIDR
                        无注释，v6 与旧 gaoyifan 完全一致=零损失，v4 较 chnroutes2 的 3908 更全）。
                        jsDelivr 优先（大陆可达）+ raw 兜底，双候选 fallback 不变
                      ②**混合文件按族加载**：cn.txt 是 v4+v6 混合单文件，url_v4/v6 指向同一份，
                        daemon 下载后 cnip_load_fd 用新增 cnip_line_family() 探测行地址族——
                        **异族行跳过不计 bad、非法行仍计 bad**（此前异族行会全计"失败"，日志
                        误导）；fetch-cnip.sh 改为单下载 + grep 按族拆分（拆出 v4=4145/v6=1235）
                      ③配置/文档/MEMORY 全量同步；CFG_STRLEN 保持 256（新 URL 实测 139 字符）；
                        版本号 1.4.3（bump-version.sh）
v1.4.2        CNIP 数据源多源 fallback（2026-08 源批次 + 双源兜底）：
                      ①**CNIP v4 默认源更换**：17mon/china_ip_list（每季度更新、非聚合
                        ~8.7k 条、CC-BY-NC-SA 许可）→ misakaio/chnroutes2（每日 APNIC
                        路由 dump、聚合约 3900 条、省近半 map 内存）；v6 保留
                        gaoyifan/china-operator-ip（每日，实测未归档）
                      ②**多源 fallback**：cnip url 支持逗号分隔多候选按序尝试——cnip_load_url
                        拆分出 cnip_try_url 单源尝试 + 循环，下载器探测一次、候选间不重复；
                        任一成功即用、全部失败 return -1 沿用本地旧文件（不归零）；默认
                        jsDelivr 优先（大陆实测可达，本机 raw.githubusercontent 被屏蔽）
                        + raw 兜底（全球更稳），互为备份
                      ③**CFG_STRLEN 128→256**：双 URL 逗号拼接 v4=143/v6=155 字符，128 会
                        截断（WSL 用旧二进制 validate 可复现截断）；纯用户态配置缓冲，
                        无 ABI/持久化影响；fetch-cnip.sh 同步 dl_candidates 多源 fallback
                      ④文档 / 各 MEMORY 全量同步；版本号 1.4.2（bump-version.sh）
v1.4.1        CNIP 更新失败修复 + update-cnip 手动更新（统一后台调度）：
                      ①**CNIP 更新失败修复**（根因 3 个，见 cni/MEMORY）：
                        a. 下载器回落：Android Magisk 常无 curl，旧实现绝对路径探测全空 →
                          exec 失败 exit 127 → 每 5 分钟死循环重试。现补齐 wget/busybox 探测
                          （绝对路径优先，回落 PATH 查找），全缺失由调用方明确报错（不再
                          fork 空转）；curl 加 `-f`（HTTP>=400 失败）
                        b. 下载内容 0 条校验：404/502 错误页/空文件不再以 0 退出码被当成功
                          → rename 覆盖好文件 → cnip_apply 全量清空重灌 → CNIP 静默归零、
                          直连分流失效（本次修复的核心根因）
                        c. 配置族判定：仅 url+path 都配的族参与成败判定——单族配置时该族
                          下载失败不再被未配置族"成功"吞掉、不再误报未配置族失败、失败
                          会走 return -1 稍后重试；失败族沿用本地旧文件重灌不归零
                      ②**update-cnip 手动更新 + 统一后台调度**：新增 `splitctl update-cnip`
                        与 WebUI "更新 CNIP"按钮（下载 url_v4/v6 后重灌）；`reload-cnip` 改
                        后台执行（旧同步 cnip_apply 阻塞 poll 主循环数秒）；定时/补拉/
                        update-cnip/reload-cnip 统一走 g_cnip_req 请求位 + fork 子进程路径，
                        共用 g_cnip_busy 并发闸，ctl 只置位立即回"已安排"
                      ③**配置冲突告警（功能冲突审查）**：attach_auto=on 时 attach_list 被忽略、
                        ipv6=false 却配 proxy_cidr6（意图相反的静默失效）——解析结束显式 WARN，
                        不改裁决语义
                      ④文档 / 各 MEMORY 全量同步；版本号 1.4.1（bump-version.sh）
v1.4.0        移除域名分流（DNS 学习器）整模块，主线回归纯 IP/UID 分流：
                       ①内核 policy 8 步 → 7 步（删原第 4 步域名规则）；删 dom.h 与 4 个 map
                         （map_dns4/6、map_dom_proxy/direct，map 15 → 11）；split_bpf.h 删
                         struct dns_entry/dom_key/dom_rule、SPLIT_DOM_MAX、cfg.dom_enabled；
                         stats 删 STAT_DOM_PROXY/DIRECT，STAT_DIRECT_V6 重排 11 → 9
                         （运行时 map 无持久 ABI）
                       ②用户态删 userspace/dns/ 模块（AF_PACKET 学习器）、ctl dns 命令、
                         loader 的 map_dom_*/map_dns_*、config 的 proxy_domains/direct_domains、
                         daemon 的 poll fd / 30s prune / 心跳注释去 DNS
                       ③配置与 UI：split.yaml 删域名规则段；WebUI 删 DNS 卡片与统计项；
                         splitctl/脚本撤 dns
                       ④文档 / 各 MEMORY 全量同步；域名特化的 verifier 教训（读 map value
                         变量下标显式掩码到 < 2 的幂且无条件前置）沉淀为通用硬契约
                       ⑤v1.4 原规划"DNS 拦截增强（TCP/53、分片重组）"随整模块移除作废；
                         域名粒度分流统一交给 mihomo（redir-host/fake-ip + 规则引擎）
v1.3.1        v1.3.0 审查修复批次（6 项）：
                        ①**map_cfg 安全默认契约修正**：map_cfg 是 ARRAY map、lookup 永不 NULL，
                          未写入返回全零元素（default_verdict=0=直连），与"未知→代理安全默认"
                          相悖。loader `map_set_cfg` 置 `bpf_trace_enabled=1` 作"已初始化"哨兵，
                          内核 policy.h 凭 `==0` 回落 TUN 安全默认；rule.c 对 map_set_cfg 失败
                          LOG_ERROR（不再静默）
                        ②**CNIP 缺失补拉收紧**：仅"某族 url 与 path 同时配置"才补拉——
                          空 path 时 cnip_auto_update 是 no-op，旧实现 fork 空转静默"成功"
                          但 CNIP 保持 0 条；url 有 path 无补专门 WARN
                        ③**config 未知 key 复位 cur_list**：rules/ifaces 节未知 key 后跟
                          "- item" 会被并入上一列表（静默误分流），现已复位
                        ④daemon ctl_stats 注释 13→12（names 数组实际 12 项）
                        ⑤**watchdog 冷却改单调时钟**：`date +%s`（墙钟）在部分设备缺失回退
                          echo 0 旁路冷却、跳时失效——改用 /proc/uptime 单调秒
                        ⑥webuiapi add-rule/del-rule 未指定 which 默认 proxy（旧传空串报错）
v1.3.0        版本号管理统一 + 文档全量同步：
                       ①新增 scripts/bump-version.sh：唯一真源 split_bpf.h，一键递增 patch/minor/major
                         （默认 patch），自动同步 module.prop（version+versionCode 无碰撞公式
                         major*10000+minor*100+patch）、docs/06-ROADMAP.md（当前标注）、
                         根文档头部版本标注；AGENTS/CONTRIBUTING/BUILD/scripts-MEMORY 同步约定
                       ②修 scripts/MEMORY.md 过时 versionCode 公式（major*100+minor*10+patch
                         → 无碰撞方案，与 gen-magisk.sh 一致）
                       ③根文档版本号统一并同步递增（README/USAGE/BUILD/CODE/android/README），
                         watchdog mihomo TUN 自愈 / config 空列表告警 / rule 超长拒绝 写入各层文档
                       ④清理冗余构建目录 userspace/build/arm64、修 .gitignore 过时注释
v1.2.9        审查加固 + 真机问题修复：
                       ①CNIP 更新子进程 exec curl 前对全部继承 fd 置 FD_CLOEXEC（防 fd 泄漏脏现场）
                      ②config 空列表告警（rules 声明 proxy/direct 列表但无项 → 默认规则被静默清空可见）
                      ③运行时规则 cidr 超长显式拒绝（防 snprintf 截断 → reload 重放写截断串）
                      ④split-watchdog 增 mihomo TUN 自愈（真机问题：splitd 存活但 mihomo TUN 中途
                       消失（如 9090 外部控制器改 tun.enable、utun 被清理）→ map_tun=0、miss_tun
                       持续增长、代理全放行直连且无报错；watchdog 探活分支解析 tun= 连续 2 轮为 0
                       时经 mihomo API 无感恢复，API 失败重启 mihomo，5 分钟冷却防循环）
v1.2                  BPF 单元测试（回环注入最小包）+ CI（规划未交付，见"缺口（诚实清单）"）
v1.3                  Android App MVP：开关 + stats 展示（root/JNI）（规划未交付，见"缺口（诚实清单）"）
```

## 已知设计取舍（不再摇摆）

1. **挂载在 egress 而非 ingress**：简单、可预测，代价是看不到入站统计。
2. **不碰 fwmark/iptables（主线）**：避免厂商差异；bpf_redirect 单钩子两状态。tproxy 是可选形态，见下节。
3. **默认未知→代理**：安全默认（海外）；如需"未知→直连"改配置 `verdict: direct`。
4. **fake-ip 与内核 CNIP 分流不可兼得**：文档已写明，二选一。**v1.1.0 补充**：域名分流
   面向"真实 DNS + 内核规则表"场景（app 走公共 DNS，内核学 IP→域名）；fake-ip 场景的
   域名规则由 mihomo 自己的规则引擎处理（内核只需 fake-ip 段 proxy 规则）——两条路都
   不需要改内核判定模型。
   **v1.4.0 移除域名分流**：前一条路（内核域名规则表）已整模块移除，主线回归纯 IP/UID
   分流；域名粒度分流统一交给 mihomo（redir-host/fake-ip + 规则引擎），不再维护内核
   域名 map 与用户态学习器的 ABI/开销。

## tproxy 模式：技术约束与可选形态（研究结论，暂未实现）

> 结论先行：**TPROXY 目标在内核里只支持 PREROUTING 钩子，不支持 OUTPUT（本机出站方向）**。
> 我们的 eBPF 处理的是本机进程发起的出站流量，方向相反，**形态 A 已实测否定**；
> 形态 C（loopback 反弹）内核可行但不推荐（见下）。

### 硬约束 1（源码核实，小米 5.10 GKI `net/ipv4/ip_output.c`）
出站路径执行顺序：
```
本地 socket → ip_local_out()[nf_hook NF_INET_LOCAL_OUT, line 115]
            → 路由决策(dst_output)
            → ip_finish_output()[BPF_CGROUP_RUN_PROG_INET_EGRESS, line 322]
            → __dev_queue_xmit()[tc egress sch_handle_egress, 我们现在的挂点]
```
- `nf_hook(NF_INET_LOCAL_OUT)` 在 **cgroup egress 与 tc egress 之前**执行。
- 因此无论 cgroup egress 还是 tc egress 里 `bpf_skb_set_mark()`，**mark 都晚于 OUTPUT 链的路由决策**，`iptables -t mangle -A OUTPUT -m mark` 匹配不到，TPROXY 无法生效。
- Cilium 文档亦确认："tc BPF egress 在 POSTROUTING 之后执行"。

### 硬约束 2（决定性的，WSL2 6.18 + 真机 5.10 均实测 + 源码核实）
**`tproxy` 目标只允许挂在 `NF_INET_PRE_ROUTING` 链**：
```c
// 小米 GKI net/netfilter/nft_tproxy.c:301
static int nft_tproxy_validate(...) {
    ...
    return nft_chain_validate_hooks(ctx->chain, 1 << NF_INET_PRE_ROUTING);
}
```
- 在 OUTPUT 链添加 tproxy 规则 → 内核返回 `Operation not supported`（WSL2 实测复现）。
- 这是 Linux 内核的长期固定行为（tproxy 依赖 PREROUTING 的 socket 匹配语义）。
- **含义**：tproxy 只能拦截"入站/转发"的包，**无法**用于本机进程发起的出站流量重定向——恰好和我们的 eBPF 出站分流方向相反。

### 形态 A 实测否定（2026-08 验证）
形态 A（eBPF egress 打 mark + `ip rule fwmark` 重路由 + mihomo IP_TRANSPARENT）**不可行**：
- 即使 mark 在 egress 被设置，tproxy 目标不支持 OUTPUT 链 → 无 netfilter 目标可把已标记的出站包转给 mihomo。
- WSL2 6.18 实测：`nft add rule inet ... tproxy` 于 output hook 报 `Operation not supported`。

### 可选形态（若未来要实现）

**形态 B：纯 iptables TPROXY + eBPF 仅观测（放弃内核 CNIP 分流）**
```
iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 7892 --tproxy-mark 0x1/0x1
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```
- 注意：必须是 **PREROUTING**（拦截其他设备/转发的流量），对"本机自己发起的出站"仍无效。
- 本机出站 tproxy 的替代是 `REDIRECT`（nat output 链，`nft add rule nat output tcp dport 853 redirect to 10053`），但 REDIRECT 会改目标、丢原始 dst（需 SO_ORIGINAL_DST 才能还原，Android 上支持有限）。
- 均不满足"内核级 CNIP 分流 + 本机出站"的目标。

**形态 C（未覆盖的缝隙）：loopback 反弹（内核可行，但工程上不推荐）**

上述"本机出站 tproxy 不可行"否定的是**原地打 mark + 重路由**（形态 A）。
若补一个步骤——tc egress 里 `bpf_skb_set_mark()` + `bpf_redirect(lo, 0)`——包从 lo 重入走的是
**lo 的 RX 路径 → PREROUTING**，而 TPROXY 在 PREROUTING 是合法的（硬约束 2 的例外面），
skb 的 mark 在同一次重入中保留。配合 mark 精确匹配即可把 eBPF 判定的代理流量喂给 mihomo
tproxy socket（mihomo 侧零改动，`mihomo-package.yaml` 已开 `tproxy-port: 1536`）：

```
iptables -t mangle -A PREROUTING -m mark --mark 0x2/0x2 -p tcp -j TPROXY --on-port 1536
ip rule add fwmark 0x2 table 100
ip route add local 0.0.0.0/0 dev lo table 100
```

- **2026-08 二次审查确认**：内核层面能跑通（`bpf_redirect` 到 lo → `loopback_xmit` →
  `netif_rx` → `NF_INET_PRE_ROUTING`），不是形态 A 那种 verifier/挂载层就断的死路。
- **但不建议做**，代价与形态 B 同源、另有新坑：
  1. 循环/静默丢包两把刀：TPROXY 未命中（规则未加载/协议未覆盖）时 marked 包重路由出网 →
     再过 eBPF → 必须加"已标记不再反弹"守卫否则无限循环；即便加守卫，`ip route add local ...
     dev lo table 100` 会把未接住的 marked 包送 lo → 无 socket → 静默丢包（比 TUN 断流更隐蔽）。
     两点都触碰"任何异常一律 TC_ACT_OK 绝不丢包"铁律。
  2. 双判定点漂移：eBPF 判"代理" + iptables `-m mark` 判"转 mihomo"两套分类，改一处漏一处。
  3. 全局路由/netfilter 操纵回归：ip rule + local 路由 + iptables 正是主线刻意规避的厂商差异面
     （Android netd 管理 iptables、厂商魔改 fwmark 路由）；`route_tun_hijacked` 监控需适配，
     否则把 tproxy 自身规则误报成"auto-route 接管"。
  4. mihomo 仍需从 tun mode 切 tproxy mode，DNS 拦截链（`tun.dns-hijack`）重做，fake-ip 映射故事要改。
  5. 性能上 lo 反弹每个代理包多一次完整栈重入（lo xmit→RX→PREROUTING netfilter→重路由），
     把 tproxy"内核 TCP 栈"的稳态收益吃回去一大块；eBPF 侧成本本就极低（一次 LPM+redirect），
     瓶颈在 mihomo 用户态栈不在 BPF。
- 低成本替代方向（TUN 架构内）：mihomo `stack: system`（内核栈 + 仍走 TUN，保留单钩子模型），
  在 Linux 桌面先测 gvisor vs system 的 CPU/延迟差异再决定。

### 结论
tproxy 模式**不可行**（内核硬限制：tproxy 不支持本机出站方向）。**保持 TUN 为主线**（内核 CNIP 分流 + 零拷贝 redirect，已真机验证）。若未来要"复用 mihomo 端口"，只能走 REDIRECT（丢原始目标）或应用层代理端口（mixed），都不是透明内核分流。
形态 C（loopback 反弹）内核可行但工程上不推荐（见上）：把 netfilter/路由操纵整套搬回，另添循环与静默丢包新坑，收益仅在 mihomo CPU 稳态——若只为省 CPU，先试 TUN 架构内的 `stack: system`。

## TUN redirect 兼容性：已解决（v1.0.4，queue_mapping 修复）

> **结论：tc egress + bpf_redirect 到 mihomo TUN 可行！** 关键是设置 `skb->queue_mapping=0`。

### 根因（源码核实 `drivers/net/tun.c` + 真机验证）
`tun_net_xmit()` 用 `skb->queue_mapping` 索引 `tun->tfiles[]` 找用户态读队列：
```c
tfile = rcu_dereference(tun->tfiles[skb->queue_mapping]);
if (!tfile) goto drop;
...
ptr_ring_produce(&tfile->tx_ring, skb);  // 放入读队列 → mihomo read()
```
Android 物理网卡（wlan0/rmnet）多队列，从它 egress bpf_redirect 来的 skb 继承物理网卡
的 queue_mapping（0~N-1），而单队列 tun 只有 `tfiles[0]`。queue_mapping>0 → tfile=NULL
→ **包被 drop**（tun tx_dropped 增长，mihomo read 读不到，utun_rx 不涨）。

**WSL2 eth0 单队列（queue_mapping 恒 0）所以此前"能读到"，Android 多队列暴露此 bug。**
这正是"补齐网络栈上下文"的确切含义——tun 设备需要的 queue_mapping 上下文。

### 修复
```c
// split.bpf.c，redirect 前：
skb->queue_mapping = 0;   // 保证包进入单队列 tun 的唯一读队列
bpf_redirect(tun, 0);     // flags=0(egress)，包进 tun 读队列
```

### 真机验证（小米 5.10 GKI + mihomo v1.19.29 gvisor）
```
curl google ×3        → 200, 0.38~0.43s（稳定）
Play 商店              → 正常打开
mihomo connections    → 14 条，含 www.google.com（Google_域 规则命中）
splitd stats          → proxy 5713 / direct_cn 2925 / parse_err 4 / dropped 0
tcpdump(utun)         → 完整 TCP 握手 + TLS 数据流（双向）
```

### 历史修正
- v1.0.3 曾误判"mihomo 无法接受 bpf_redirect 注入"，实为缺 `queue_mapping`。
- `BPF_F_INGRESS` 不可用：ingress 走 netif_receive，tun 设备不把包排入读队列（WSL2 reader 读不到）。
- 必须 `flags=0`(egress) + `queue_mapping=0`。

## 外部参考：mihomo 为何放弃 eBPF（2024-08-16 移除，issue #1278）

> 背景调研记录（2026-08），用于论证本项目"内核纯 IP 分流 + 用户态域名兜底"的设计合理性。

### 时间线（github.com/MetaCubeX/mihomo，主分支 Alpha）

| 时间 | 提交 | 事件 |
|---|---|---|
| 2022-07-29 | `31f4d20`（PR #144） | 合并 eBPF：`component/ebpf`（tc redirect_to_tun、redir auto-redirect）+ `listener/autoredir` |
| 2022-08-08 | `97270dc` | "rm EBpf tun && disable android ebpf"——Android 版立刻被禁 |
| 2024-08-16 | `0793998`（Larvan2） | **"chore: drop support of eBPF"**——删除全部 6304 行，彻底移除 |
| 2024-10-10 | — | #1278（改进 ebpf 分流方式）关闭为 not planned |

### 官方理由（#1278 评论原话）
1. **内核分流 = 无法域名分流**（contributor xishang0128）：
   "在ebpf区分流量意味着没法进行域名分流,所以这个功能不会做"
2. **与核心目标冲突**（collaborator Skyxim）：
   "这需要修改以满足将程序加载至内核，和原本目标冲突"
3. **dae 的 DNS 映射方案不完善**（xishang0128 反驳 dae 举例）：
   "dae是通过dns映射支持的,但是这并不完善,如果两个域名都是同一个ip,那么这两个域名都可能进入用户态程序,通过嗅探获取域名
   如果dns劫持不到,那就只能是纯ip分流,ip可能不会进入用户态程序进行域名分流,直接直连"

### 结论与对我们的启示
- mihomo 的灵魂是**域名级规则**（DOMAIN-SUFFIX/GeoSite），内核 TC 只见 IP、见不到域名；
  dae 式 DNS 映射（劫持 DNS 拿域名）又有共享 IP 误判、劫持失败退化为纯 IP 的硬伤。
- 叠加 Android 不可用、clang/libbpf 构建链与内核版本兼容问题（#763 "interface not found" 等报障），
  官方选择**删掉而不是改进**。
- 反证本项目设计：**内核只做 IP 集分流（CNIP/规则段），域名粒度全部交给 mihomo 用户态**
  （fake-ip / redir-host + sniffer 兜底），不与 mihomo 域名体系冲突；
  直连流量内核直出（TC_ACT_OK），正是 #1278 想要而 mihomo 没做成的效果。