# 04-CONFIG（split.yaml 配置手册）

> 框架配置文件示例：`configs/split.yaml.example`。
> 本页按字段分组解释 + 默认值 + 与 map 的对应关系。
> **语法极简**：只支持 `section:` / `key: value` / `- list-item` / `# 注释`；无缩进语义、无引号、无嵌套、无多行。
> **section 头必须顶格**（`ifaces:`/`default:`/`rules:`/`cnip:`，冒号后无内联值）；行尾换行（LF/CRLF）被正确识别为节尾。
> 未知顶层 key / 未知节内 key 会打 WARN 但不阻断（v1.1.8+）。

## 1. 顶层

```yaml
debug: false              # true：log 级别=debug，且不 daemon 化
tun_device: utun          # 代理 TUN 设备名（mihomo tun.device，二者必须一致）
```

顶层 `tun_device` 由 daemon 解析其 ifindex 写进 `map_tun`；运行期由 `tun_sync` 持续对齐（mihomo 重建 utun（含重载配置文件）导致 ifindex 漂移时自动重写；新 TUN 改名（如 mihomo 回退名 `Meta`、同前缀 `utunN`，或任意名的 ARPHRD_NONE 设备）时按名字/类型自动对齐——**系统 VPN 的 `tunN` 已被排除（v1.2.8，防误把 VpnService 当新 TUN）**；接口消失时置 0 放行保联网，见 docs/02 §2.4）。

## 2. ifaces(挂载范围)

```yaml
ifaces:
  attach_auto: true           # true=自动发现物理网卡并全挂；false=只用 attach_list
  attach_list:                # attach_auto=false 时才生效
    - wlan0
    - rmnet_data0
  exclude:                    # 前缀/全名匹配排除（tun/utun 必须排除，防回环）
    - lo
    - tun
    - utun
    - tap
    - dummy
```

## 3. default(未命中时的行为)

```yaml
default:
  verdict: "tun"            # "tun" | "direct"；安全起见选 tun(海外默认代理)
  ipv6: true                # 是否参与 v6 分类（false 则 v6 一律直连）
```

## 4. rules(强制规则段——优先级高于 CNIP)

```yaml
rules:
  # 强制走代理的 CIDR（一般放 fake-ip 池，见 docs/03-ANDROID §4）
  proxy_cidr4:
    - 198.18.0.0/15
  proxy_cidr6:
    - fdfe:dcba:9876::/64      # 对应 mihomo fake-ip-range6

  # 强制直连（内网私有网段等；内置已含 rfc1918/链路本地，见 §6）
  # direct_cidr4:
  #   - 10.0.0.0/8
  # direct_cidr6:
  #   - fc00::/7

  # uid 白名单（直连，跳过一切判定）——mihomo 自己的 uid 必须在这！
  skip_uid:
    - 0       # root
    - 2000    # shell
    # - 10142 # mihomo-app 示例
```

> 注意：列表**声明行即覆盖**（"="，非"+="）。声明一个 list 项组会清空该组默认值——
> 因此声明 `skip_uid` 时要把默认 root/shell(0/2000) 一起带上（config.c 语义）。
> **v1.2.9 空列表告警**：声明了 `proxy_cidr4/direct_cidr4/proxy_cidr6/direct_cidr6` 但没有任何
> `- item`（空列表/仅注释）时，默认规则（如 fake-ip 段 `198.18.0.0/15`、内网直连段）会被静默
> 清空——解析结束打 WARN 点明。若想清空某族（保留空列表）属合法，只看 WARN 确认即可。

## 5. cnip

```yaml
cnip:
  path_v4: /data/adb/split/config/cn_cidr_v4.txt   # 本地文件，每行 A.B.C.D/N
  path_v6: /data/adb/split/config/cn_cidr_v6.txt
  url_v4: https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt
  url_v6: https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt
  auto_update_hours: 24       # 0=不自动更新；默认 24(每天)
```

> linux 桌面请改成自己的绝对路径（如 /etc/split/cn_cidr_v4.txt）。
> 两个 path 都留空 = 纯规则分流（不做 CNIP）。
> **自动更新**：daemon 每 `auto_update_hours`（默认 24=每天）用下载器下载 `url_v4/v6`
> 到 `path_v4/v6` 覆盖本地文件，再全量重灌 `map_cnip4/6`（先清空后写入，幂等）。
> 下载器探测顺序：curl → wget/busybox（绝对路径优先，回落 PATH；Android Magisk 环境通常
> 没有 curl，有 busybox 即可，见 cni/MEMORY）。下载失败 / HTTP 错误 / 内容 0 条时**沿用本地
> 旧文件**，不覆盖不重灌（不会把 CNIP 清空归零）。无任何下载器时留空 url、只按间隔重读本地
> 文件，或外部脚本跑 `fetch-cnip.sh` + `splitctl reload-cnip`；`splitctl update-cnip`
> （v1.4.1 手动更新）与自动更新同路径。
> Android 可直接复用 box 的 `cn.zone`/`cn_ipv6.zone` 改名后用（每行 CIDR，格式兼容）。

## 6. 内置直连段（policy 硬编码，无需配置）

```
IPv4:  127.0.0.0/8（回环）  169.254.0.0/16（链路本地）
       224.0.0.0/4（组播）  255.255.255.255（受限广播）
IPv6:  ::1/128（回环）  fe80::/10（链路本地）  ff00::/8（组播）
```

> 直接命中=直连，不查询 CNIP，优先级在 CNIP 之前（判定第 3 步，位于 uid 白名单与
> v6 开关之后；详见 docs/02 §1.4 的 7 步顺序）。

## 7. 与 map 的映射关系

| 配置段 | 写入 map |
|---|---|
| rules.proxy_cidr4/6 | map_rule_proxy4/6 |
| rules.direct_cidr4/6 | map_rule_direct4/6 |
| rules.skip_uid | map_skip_uid |
| cnip.path_v4/6 | map_cnip4/6 |
| default.verdict / default.ipv6 | map_cfg[0]（default_verdict / ipv6_classify） |
| tun_device | map_tun[0]（启动时解析；运行期由 daemon `tun_sync` 持续对齐——mihomo 重建 utun（含重载配置文件）导致 ifindex 漂移/改名时自动重写，接口消失时置 0 放行保联网，见 docs/02 §2.4） |

## 8. 热重载

```bash
splitctl reload            # 读配置 → 增量更新 maps（不重编译/不掉线）
splitctl reload-cnip       # 只刷新 CNIP（v1.0.5 起为"先清空再全量重灌"，非追加；v1.4.1 起后台执行）
splitctl update-cnip       # 手动更新 CNIP（v1.4.1）：重新下载 url_v4/v6 后重灌（后台执行）
```

> 注意：v1.0.5 起 reload 是"先清空再全量写入"（幂等），配置里删掉的规则/UID/CNIP 段会一并移除，无需重启 daemon。
> v1.0.6 起 reload 会**真正重读配置文件**再应用（此前只重放内存中的旧配置）；重读失败则沿用内存配置继续重放并记日志。
> CNIP 段的增删走 `reload-cnip`（重新灌入本地文件），reload 不触碰 CNIP。
> v1.2.1 起 reload 还会**立即对齐 map_tun**（tun_device 变更 / mihomo 重建 utun 时若只靠 1s 心跳会有 stale 丢包窗口）。

## 9. 校验

```bash
splitctl validate -c split.yaml   # 语法 + 段合法性（不加载）
```

---
详细命令见 `USAGE.md`；术语见 `docs/05-GLOSSARY.md`。