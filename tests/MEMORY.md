# tests — 记忆文档（改本目录代码前必读）

## integration.sh
- 端到端冒烟：A. 百度可达（直连/CNIP）B. YouTube 可达（代理）C. splitctl stats 计数。
- 脚本要求 root 运行（`sudo ./tests/integration.sh`）；`cd "$(dirname "$0")/.."` 切到仓库根，
  依赖 `curl`；splitd 未运行时 stats 计数不可用属预期（不判失败）。
- 坑（v1.1.4 修复）：`"$SCTL" stats` 引号 bug——`$SCTL="sudo userspace/build/splitctl"` 含空格，
  加引号会被 bash 当单个命令名，报 `No such file or directory`；必须**不加引号**（SCTL 值固定无注入面）。
- 单元测试目录 `tests/unit/` 目前为空，脚本只输出提示。

## 运行方式
```bash
sudo ./tests/integration.sh        # 需 root + mihomo 已起 + 已 load（splitd）
```
