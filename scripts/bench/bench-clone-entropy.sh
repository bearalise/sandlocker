#!/usr/bin/env bash
# bench-clone-entropy.sh — 克隆熵回归（Q3）+ 恢复时序（Q4）：同一快照恢复两实例，
# 断言 machine-id/RNG/会话密钥皆异（ADR-12 reinit 消除克隆状态泄漏）。
#
# 与其它 bench 不同，这是**安全回归红线**而非纯指标：
#   - KVM/环境缺失 → 输出 skip JSON、退 0（不阻塞 CI）。
#   - KVM 就绪但两实例身份/熵**相同** → sl-node 退非 0 → 本脚本退非 0 → CI 红。
# stdout：单行 JSON（run-all.sh 入库）；人类信息走 stderr。
set -euo pipefail
. "$(dirname "$0")/_common.sh"

if ! bench_prep; then
  echo '{"skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

# W4 起 sl-envd 契约新增 Reinit——强制重建 rootfs，确保新 sl-envd 进 guest
# （bench_prep 仅在 rootfs 缺失时才建，缓存命中会漏掉本周的 guest 侧改动）。
echo "[clone-entropy] 重建 rootfs（纳入新 sl-envd reinit 例程）..." >&2
"$REPO_ROOT/scripts/build-rootfs.sh" >&2

SNAP="$REPO_ROOT/build/run/snap-clone-entropy"
rm -rf "$SNAP"

# 先烘焙一份快照（无网络，D5 点：身份/随机性尚未初始化）
( cd "$REPO_ROOT" && "$SL_NODE" --snap-create "$SNAP" ) >&2

# 同快照恢复两实例并比对（--json：stdout 单行 metric；FAIL 时退非 0）
( cd "$REPO_ROOT" && "$SL_NODE" --clone-entropy-check "$SNAP" --json )
