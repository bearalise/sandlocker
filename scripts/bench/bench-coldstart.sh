#!/usr/bin/env bash
# bench-coldstart.sh — 冷启动分段计时（Q3）：跑 N 次 sl-node --json，算 P50/P99。
# stdout：单行 JSON（run-all.sh 入库）；人类信息走 stderr。
set -euo pipefail
. "$(dirname "$0")/_common.sh"

N="${COLDSTART_N:-10}"

if ! bench_prep; then
  echo '{"skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

totals=(); prek=(); guest=()
for i in $(seq 1 "$N"); do
  line="$(node --json 2>/dev/null | grep -oE '\{.*\}' | head -1)"
  t="$(printf '%s' "$line"  | grep -oE '"total_ms":[0-9]+'     | grep -oE '[0-9]+' || echo)"
  p="$(printf '%s' "$line"  | grep -oE '"pre_kernel_ms":[0-9]+'| grep -oE '[0-9]+' || echo)"
  g="$(printf '%s' "$line"  | grep -oE '"guest_boot_ms":[0-9]+'| grep -oE '[0-9]+' || echo)"
  [ -n "$t" ] || { echo "[coldstart] 第 $i 次无计时输出，跳过" >&2; continue; }
  totals+=("$t"); prek+=("${p:-0}"); guest+=("${g:-0}")
  echo "[coldstart] $i/$N total=${t}ms pre_kernel=${p}ms guest_boot=${g}ms" >&2
done

M="${#totals[@]}"
[ "$M" -gt 0 ] || { echo '{"skipped":true,"reason":"no-samples"}'; exit 0; }

# 百分位：升序后取 ceil(p*M)-1 位（最近秩法）
pct() { # $1=百分比 $2..=样本
  local p=$1; shift
  local sorted; sorted=$(printf '%s\n' "$@" | sort -n)
  local idx=$(( (p * $# + 99) / 100 )); [ "$idx" -lt 1 ] && idx=1
  printf '%s\n' "$sorted" | sed -n "${idx}p"
}
p50=$(pct 50 "${totals[@]}"); p99=$(pct 99 "${totals[@]}")
tmin=$(printf '%s\n' "${totals[@]}" | sort -n | head -1)
tmax=$(printf '%s\n' "${totals[@]}" | sort -n | tail -1)
pk50=$(pct 50 "${prek[@]}"); gb50=$(pct 50 "${guest[@]}")

echo "[coldstart] N=$M P50=${p50}ms P99=${p99}ms min=${tmin} max=${tmax}" >&2
printf '{"metric":"coldstart","n":%d,"p50_ms":%d,"p99_ms":%d,"min_ms":%d,"max_ms":%d,"pre_kernel_p50_ms":%d,"guest_boot_p50_ms":%d}\n' \
  "$M" "$p50" "$p99" "$tmin" "$tmax" "$pk50" "$gb50"
