#!/usr/bin/env bash
# bench-restore-create.sh — Q2 创建时延：预烘焙快照 → 创建走**恢复路径**，P50 ≤ 500ms
# （无池、page-cache 热；分段定位大头）。
#
# 流程：① --build 造预烘焙模板（deny 离线，无需 root/网络）→ ② --orch-bench 进程内循环
#       create→destroy × N（首个 warm-up 丢弃），算 P50/P90 + 分段（copy/api-ready/load/resume）。
# 与冷启动 bench 不同处：创建 = 从快照恢复（rootless mount-ns bind 私有 rootfs），非冷 boot。
#
# 同时是 **Q2 门禁**（类比 clone-entropy 红线）：
#   - KVM/环境缺失 → 输出 skip JSON、退 0（不阻塞 CI）。
#   - KVM 就绪但 P50 > 500ms → sl-node 退非 0 → 本脚本退非 0 → CI 红。
# stdout：单行 JSON（run-all.sh 入库）；人类信息走 stderr。
set -euo pipefail
. "$(dirname "$0")/_common.sh"

if ! bench_prep; then
  echo '{"skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

CYCLES="${RESTORE_CYCLES:-20}"

# ① 造预烘焙模板（version 由构建输入哈希派生，内容寻址）
echo "[restore-create] 构建预烘焙模板 examples/hello.sandlocker.toml ..." >&2
BUILD_OUT="$( cd "$REPO_ROOT" && "$SL_NODE" --build examples/hello.sandlocker.toml --json )"
echo "[restore-create] build: $BUILD_OUT" >&2
VER="$(echo "$BUILD_OUT" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ -n "$VER" ] || { echo "[restore-create] 未从 --build 输出取到 version" >&2; exit 1; }
TPL="$REPO_ROOT/build/templates/hello/$VER"

# ② 创建时延 bench（--json：stdout 单行 metric；P50 > 500ms 退非 0）
( cd "$REPO_ROOT" && "$SL_NODE" --orch-bench "$TPL" --cycles "$CYCLES" --json )
