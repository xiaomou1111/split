# tests/unit — 用户态单元测试（骨架）
#
# 现状：本仓库以 `tests/integration.sh`（真机/容器冒烟）为主，
# 这里是预留的纯用户态单测目录。建议按模块补：
#
#   tests/unit/test_config.c   — config 解析（含错误输入）
#   tests/unit/test_cnip.c     — cidr 文本 → map key 转换
#   tests/unit/test_rule.c     — rule 增删
#
# 运行（需要宿主机有 libbpf / 可加载 bpf 的内核或 mock）：
#   cc -Iuserspace -Ikernel/include test_config.c ../userspace/common/config.c -o t && ./t
#
# BPF 侧单测（可选）：编译后用 `bpftool prog load ... type sched_cls` + XDP 回环
# 打最小包验证 parse/radix/policy 逻辑（见 docs/06-ROADMAP）。
