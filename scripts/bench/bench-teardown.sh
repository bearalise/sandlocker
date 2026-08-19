#!/usr/bin/env bash
# bench-teardown.sh — 销毁对账（Q6）：N 轮 create/destroy 后断言无残留。
# sl-node --cycles 自身逐轮断言（firecracker 进程/host tap/vsock.sock），非 0 退出即失败。
set -euo pipefail
. "$(dirname "$0")/_common.sh"

N="${TEARDOWN_CYCLES:-5}"

if ! bench_prep; then
  echo '{"skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

if node --cycles "$N" >&2; then
  echo "[teardown] $N 轮无残留" >&2
  printf '{"metric":"teardown","cycles":%d,"residue":0,"pass":true}\n' "$N"
else
  echo "[teardown] 检出残留" >&2
  printf '{"metric":"teardown","cycles":%d,"pass":false}\n' "$N"
  exit 1
fi
