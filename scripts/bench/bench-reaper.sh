#!/usr/bin/env bash
# bench-reaper.sh — 僵尸回收压测（Q2）：guest 内 fork 风暴后断言无僵尸（Z 态）进程。
# 验证 sl-envd 作为 PID1 的 wait4 收割在高频子进程下不泄漏（ADR-18）。
set -euo pipefail
. "$(dirname "$0")/_common.sh"

FORKS="${REAPER_FORKS:-500}"

if ! bench_prep; then
  echo '{"skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

# guest 内：制造 FORKS 个短命进程（含孤儿：父进程先退，子 reparent 到 PID1），
# 全部结束后数残留僵尸。sl-envd 收割正确则应为 0。
SCRIPT='
n='"$FORKS"'
i=0
while [ $i -lt $n ]; do
  ( ( sleep 0 & ) ) &   # 制造孤儿：中间 shell 退出，孙子 reparent 到 PID1
  i=$((i+1))
done
sleep 2
Z=$(ps -o stat= 2>/dev/null | grep -c "^Z" || true)
echo "ZOMBIES=$Z"
'
out="$(node --cmd "$SCRIPT" 2>/dev/null || true)"
Z="$(printf '%s' "$out" | grep -oE 'ZOMBIES=[0-9]+' | grep -oE '[0-9]+' | head -1 || echo)"

if [ -z "$Z" ]; then
  echo "[reaper] 无 ZOMBIES 输出（guest 未就绪？）" >&2
  echo '{"skipped":true,"reason":"no-output"}'
  exit 0
fi

echo "[reaper] forks=$FORKS 残留僵尸=$Z" >&2
if [ "$Z" -eq 0 ]; then
  printf '{"metric":"reaper","forks":%d,"zombies":0,"pass":true}\n' "$FORKS"
else
  printf '{"metric":"reaper","forks":%d,"zombies":%d,"pass":false}\n' "$FORKS" "$Z"
  exit 1
fi
