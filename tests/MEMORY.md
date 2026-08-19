# tests — 记忆文档（改本目录代码前必读）

## integration.sh
- 端到端冒烟：A. 百度可达（直连/CNIP）B. YouTube 可达（代理）C. splitctl stats 计数。
- 脚本要求 root 运行（`sudo ./tests/integration.sh`）；`cd "$(dirname "$0")/.."` 切到仓库根，
  依赖 `curl`；splitd 未运行时 stats 计数不可用属预期（不判失败）。
- 坑（v1.1.4 修复）：`"$SCTL" stats` 引号 bug——`$SCTL="sudo userspace/build/splitctl"` 含空格，
  加引号会被 bash 当单个命令名，报 `No such file or directory`；必须**不加引号**（SCTL 值固定无注入面）。
- 单元测试目录 `tests/unit/` 目前为空，脚本只输出提示。

## Android shell fixture
- `tests/android/test-lifecycle.sh`：纯 shell fixture，不依赖 root/BPF，验证 `split-tun-contract.sh` 对默认值/CRLF/行内注释/非法接口名的处理，以及 `fix-mihomo-tun.sh` 只改 `tun:` 直接子项、不误改 dns/rules 同名键、补全契约并保持幂等。
- 运行：`sh tests/android/test-lifecycle.sh`。脚本使用临时目录，退出时清理；适合 Windows 的 Git Bash/WSL/Linux 静态脚本回归，不能替代 Android 真机生命周期测试。

## 运行方式
```bash
sudo ./tests/integration.sh        # 需 root + mihomo 已起 + 已 load（splitd）
```
