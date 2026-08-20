#!/usr/bin/env bash
# bench-pool.sh — M2-Q2 / 硬出口①：预热池·温池池命中创建时延（冷/热分档）。
#
# 流程：① --build 造预烘焙模板（deny 离线，无需 root/网络）→ ② --pool-bench 进程内跑冷档
#       （无池，copy 计入关键路径）vs 热档（温池预填满，池命中 copy_ms=0），算 P50/P90 + 命中率。
#
# 门禁（分层口径，见 .github/workflows/bench.yml）：
#   - KVM/环境缺失 → 输出 skip JSON、退 0（不阻塞 CI）。
#   - 回归红线（任何 runner）：warm_p50 > cold_p50 → sl-node 退非 0 → CI 红（温池不得劣于冷档）。
#   - 绝对达标（仅裸金属 bench-density job 设 POOL_P50_BUDGET_MS=100）：warm_p50 > 预算 → 退非 0。
#     托管 runner 慢且共享，故 bench-light **不设预算**，只跑回归+分位入库（PRD §8.1 真 SLO 在裸金属）。
# stdout：单行 JSON（run-all.sh 入库）；人类信息走 stderr。
set -euo pipefail
. "$(dirname "$0")/_common.sh"

if ! bench_prep; then
  echo '{"metric":"pool_bench","skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

CYCLES="${POOL_CYCLES:-10}"

# ① 造预烘焙模板（version 内容寻址派生）
echo "[pool] 构建预烘焙模板 examples/hello.sandlocker.toml ..." >&2
BUILD_OUT="$( cd "$REPO_ROOT" && "$SL_NODE" --build examples/hello.sandlocker.toml --json )"
echo "[pool] build: $BUILD_OUT" >&2
VER="$(echo "$BUILD_OUT" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ -n "$VER" ] || { echo "[pool] 未从 --build 输出取到 version" >&2; exit 1; }
TPL="$REPO_ROOT/build/templates/hello/$VER"

# ② 冷/热分档 bench（--json：stdout 单行 metric）。POOL_P50_BUDGET_MS 由 sl-node 侧读 env，
#    设则追加绝对预算 gate（warm_p50 > 预算 → 退非 0）。
( cd "$REPO_ROOT" && "$SL_NODE" --pool-bench "$TPL" --cycles "$CYCLES" --json )
