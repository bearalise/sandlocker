#!/usr/bin/env bash
# bench-exec-overhead.sh — §8.1「exec 启动开销 ≤ 20ms」实测。
#
# 在此脚本之前，§8.1 六行口径里**这一行没有任何测量**——裸金属取证收工时会直接缺一格，
# 而 M3-Q9 的判据是「创建/恢复分位在裸金属产出 SLO 口径」，缺一格就是没产出。
#
# 口径：一个已就绪沙箱上 `exec("true")` 的端到端往返（host 连 vsock → 下发 → guest
# `/bin/sh -c true` → 回读）。取 `true` 是把 guest 内命令自身耗时压到近零，剩下的就是
# 通道 + agent 固定开销——正是 §8.1 那一行想约束的东西。首次丢弃（含 vsock 首连）。
#
# 达标判定不在这里，在 scripts/bench/slo-gate.sh（§8.1 集中编码一处）。本脚本只负责产出数字。
# stdout：单行 JSON（run-all.sh 入库）；人类信息走 stderr。
set -euo pipefail
. "$(dirname "$0")/_common.sh"

if ! bench_prep; then
  echo '{"metric":"exec_overhead","skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

CYCLES="${EXEC_BENCH_CYCLES:-50}"

echo "[exec-overhead] 构建预烘焙模板 examples/hello.sandlocker.toml ..." >&2
BUILD_OUT="$( cd "$REPO_ROOT" && "$SL_NODE" --build examples/hello.sandlocker.toml --json )"
VER="$(echo "$BUILD_OUT" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ -n "$VER" ] || { echo "[exec-overhead] 未从 --build 输出取到 version" >&2; exit 1; }
TPL="$REPO_ROOT/build/templates/hello/$VER"

( cd "$REPO_ROOT" && "$SL_NODE" --exec-bench "$TPL" --cycles "$CYCLES" --json )
