#!/usr/bin/env bash
# bench-density.sh — 密度实测（Q4）：并发爬坡起 N 实例至启动失败/内存地板/上限，
# 输出「实例数 vs 可用内存」曲线 + max_instances。
#
# opt-in：仅 BENCH_DENSITY=1 时运行（bench-light 不设 → 自动跳过）；
# 真实 SLO 数据须在 64C/128G 裸金属跑（计划 §5/§8.1），托管 runner/开发机仅缩比验证方法学。
#
# 并发隔离：每实例唯一 --workdir（tap 各在自身 netns、vsock 走 per-instance UDS，
# 故 tap 名/guest_cid 无需唯一，见 W6 验证）。各实例 --hold-secs 保活后自清理。
set -euo pipefail
. "$(dirname "$0")/_common.sh"

if [ "${BENCH_DENSITY:-0}" != "1" ]; then
  echo "[density] 未 opt-in（BENCH_DENSITY=1 开启），跳过" >&2
  echo '{"metric":"density","skipped":true,"reason":"not-opted-in"}'
  exit 0
fi
if ! bench_prep; then
  echo '{"metric":"density","skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

HOLD="${DENSITY_HOLD:-120}"          # 每实例保活秒数（须覆盖整个爬坡+测量窗口）
MAX="${DENSITY_MAX:-256}"            # 硬上限（裸金属调高；小机由内存地板先触发）
MEM_FLOOR_MB="${DENSITY_MEM_FLOOR_MB:-512}"  # 可用内存低于此值即停，避免打爆宿主
READY_TIMEOUT="${DENSITY_READY_TIMEOUT:-30}"
DDIR="$REPO_ROOT/build/run/density"
rm -rf "$DDIR"; mkdir -p "$DDIR"

mem_avail_mb() { awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo; }

pids=(); points=""; max_ok=0; stop_reason="reached-max"
mem0=$(mem_avail_mb)
echo "[density] 起始 MemAvailable=${mem0}MB，上限 MAX=$MAX，内存地板=${MEM_FLOOR_MB}MB" >&2

for i in $(seq 1 "$MAX"); do
  avail=$(mem_avail_mb)
  if [ "$avail" -lt "$MEM_FLOOR_MB" ]; then
    stop_reason="mem-floor"; echo "[density] 触内存地板（avail=${avail}MB），停在 $max_ok" >&2; break
  fi

  wd="$DDIR/i$i"; mkdir -p "$wd"
  ( "$SL_NODE" run --workdir "$wd" --hold-secs "$HOLD" > "$wd/log" 2>&1 ) &
  pids+=("$!")

  # 等该实例 HELD（就绪）或失败
  ok=0; t=0
  while [ "$t" -lt "$READY_TIMEOUT" ]; do
    if grep -q 'HELD' "$wd/log" 2>/dev/null; then ok=1; break; fi
    if grep -qE 'FAIL|提前退出|失败' "$wd/log" 2>/dev/null; then break; fi
    sleep 1; t=$((t+1))
  done

  if [ "$ok" != 1 ]; then
    stop_reason="boot-fail"
    echo "[density] 实例 #$i 未就绪（$(grep -oE 'FAIL.*|.*提前退出.*' "$wd/log" 2>/dev/null | head -1)），停在 $max_ok" >&2
    break
  fi

  max_ok=$i
  a=$(mem_avail_mb)
  points="${points}${points:+,}{\"instances\":$i,\"mem_avail_mb\":$a}"
  echo "[density] 实例 #$i 就绪，MemAvailable=${a}MB（累计用 $((mem0-a))MB）" >&2
done

used_total=$(( mem0 - $(mem_avail_mb) ))
per_vm=0; [ "$max_ok" -gt 0 ] && per_vm=$(( used_total / max_ok ))
echo "[density] 峰值 $max_ok 实例，停因=$stop_reason，均摊 ~${per_vm}MB/实例" >&2

# 等所有实例保活到期自清理（干净销毁走 sl-node 既有 teardown）
echo "[density] 等待 $max_ok 实例自清理（hold=${HOLD}s）..." >&2
wait || true

# 残留断言
resid=$(count_proc firecracker)
echo "[density] 自清理后 firecracker 残留=$resid" >&2

# M2-Q10 目标 gate（可选，缺省关）：DENSITY_MIN>0 且峰值实例 < DENSITY_MIN → 退非 0。
# 裸金属 dispatch（bench-density job）设 DENSITY_MIN=200（≥200@默认规格，计划 §5/§8.1）方硬达标；
# 托管/开发机不设 BENCH_DENSITY → 本脚本整体 skip，此 gate 天然不触发（无裸金属 runner 前为待补）。
DENSITY_MIN="${DENSITY_MIN:-0}"

printf '{"metric":"density","max_instances":%d,"stop_reason":"%s","mem_start_mb":%d,"used_total_mb":%d,"per_vm_mb_est":%d,"residue":%d,"density_min":%d,"curve":[%s]}\n' \
  "$max_ok" "$stop_reason" "$mem0" "$used_total" "$per_vm" "$resid" "$DENSITY_MIN" "$points"

if [ "$DENSITY_MIN" -gt 0 ] && [ "$max_ok" -lt "$DENSITY_MIN" ]; then
  echo "[density] M2-Q10 未达标：峰值 $max_ok < DENSITY_MIN=$DENSITY_MIN（停因=$stop_reason）" >&2
  exit 1
fi
