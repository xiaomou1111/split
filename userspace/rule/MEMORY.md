# userspace/rule — 记忆文档（改本目录代码前必读）

> 覆盖：`rule.{c,h}`。职责：把配置里的 proxy/direct CIDR、skip_uid 写进 map。

## 接口契约
- `RULE_PROXY=0`、`RULE_DIRECT=1`（`which` 参数语义）。
- `rule_apply_all(ctx, cfg)`：uid 覆盖式写入 + 规则 list 写入 + **域名规则 list 写入（v1.1.0）** + `map_set_cfg`。
- `rule_add(ctx, cidr, which)` / `rule_del(ctx, cidr, which)`：单条增删（cli add-rule/del-rule 目标）。
- 域名规则（v1.1.0）：配置字段 `rules: proxy_domains:/direct_domains:`（上限 CFG_DOM_MAX=64 条），
  经 `map_dom_add`（loader 层：校验字符/去 `*.` 通配与 FQDN 尾点 → 反转+小写 → LPM key）写入
  `map_dom_proxy/direct`。**只支持 reload 全量应用，暂无 CLI 在线增删域名**（roadmap）。

## 关键决策与坑
1. **rule_del 已实现（v1.0.1）**：走 `bpf_map__delete_elem` 对 LPM_TRIE 删除（kernel 5.4+ 支持）。key 的 host bits 不影响删除（LPM_TRIE 按 prefix 路径匹配节点，不检查 host bits）。
2. **rule_apply_all 是"先清空再写"（幂等）**：开头先调 `map_rule_clear`（delete UID/proxy/direct map 的全部元素），再全量写入；reload 会把配置中已移除的旧项一并清掉。启动时调用也安全（map 本为空）。
   - **v1.1.0**：域名规则同样"先清空再写"（`map_dom_clear` + 全量 `map_dom_add`），reload 移除旧域名规则生效。
3. `rule_add_list` 失败只 `LOG_WARNF`（map 满/非法 CIDR 不中断整体应用）；域名列表同理（`dom_add_list`）。
4. `map_set_cfg` 写入 default_verdict + ipv6 开关——**这是判定最后一步 / 第 2 步 v6 出口（v1.1.1 起：`ipv6_classify=false` 时 v6 在第 2 步直接直连，不再落到规则/CNIP 分支）的运行时依据**。
   - **v1.2.0：`map_set_cfg` 新签名加 `skip_uid_on`（=`cfg->nskip_uid>0`）与 `dom_on`（=`cfg->ndom_proxy+ndom_direct>0`）**——内核据此短路空 map 分支（UID/域名）的连接，提升热路径吞吐。语义不变（map 空时短路本就 miss）。
5. skip_uid 默认值（0/2000）在 config_defaults 里，这里只是灌入——改默认白名单去 config.c。
6. **域名规则与 IP 段规则的前后优先级（v1.1.0）**：内核判定顺序"域名规则"在"proxy/direct CIDR"之前——
   域名是应用层意图，应优先于 IP 段。规则落位在 `map_dom_*` 与 `map_rule_*` 是两套独立 map，
   互不影响写入顺序。
7. **运行时规则偏差（v1.2.0，H1 修复）**：`rule_add/rule_del` 只写 map，会被下一次 reload（
   `rule_apply_all` 先 `map_rule_clear` 再写配置基线）冲掉。新增 `rule_overrides` 追踪（rule.h）：
   - `rule_override_record(rov, cidr, which, present)` 记录"期望状态"（同 cidr+which last-wins；
     上限 `RULE_OVERRIDE_MAX=64`，满/非法返回 -1）；
   - daemon 的 add-rule/del-rule 处理：**先写 map、成功后再记录**（失败不记录，防幻影覆盖）；
   - `rule_overrides_replay(ctx, rov)` 在 reload 的 `rule_apply_all` 之后调用，把运行时偏差重放回去。
   - 语义：跨 reload 保留，但 daemon 重启即丢（不落盘）。只支持 CIDR 规则；域名规则无 CLI 在线增删。

## 与本仓库其它模块的关系
- 依赖 loader 的 `map_skip_uid_add / map_rule_add_cidr / map_set_cfg`。
- 被 daemon（启动+reload+**ctl add-rule/del-rule**）和 cli（add-rule/del-rule）调用。

## 验证
- `make -C userspace` 后 `splitctl reload` → `splitctl stats` 看 proxy/direct 计数变化（需 Linux）。
- 单元级：可以在宿主上 mock loader 后把 cidr 打进去再 `map_stats_dump`（tests/unit 骨架）。