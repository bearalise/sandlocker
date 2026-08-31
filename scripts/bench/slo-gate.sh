#!/usr/bin/env bash
# slo-gate.sh — 把 build/bench/results.jsonl 判成一个**结论**，而不是一堆数字。
#
# 为什么要有这个文件：裸金属是按小时租的，跑完机器就毁。如果收工时拿到的是一份 JSONL，还得
# 人肉去比对「这个 p99 算不算达标」，那这枪就白打了——尤其 §8.1 有 6 行口径，此前只有 2 行
# 被硬门（池命中 P50、密度），其余 4 行只测不判。本脚本把 §8.1 **集中编码在一处**，输出一张
# 判定表并以退出码表态。
#
# 用法：
#   scripts/bench/slo-gate.sh [results.jsonl]        # 宽松：缺测项记 SKIP，不失败
#   SLO_STRICT=1 scripts/bench/slo-gate.sh           # 严格：**缺测即失败**（裸金属取证用这个）
#
# 严格档的理由：M3-Q9 的判据是「创建/恢复分位在裸金属产出 SLO 口径」。一行没测出来，就是没产出，
# 不能当作通过。宁可红，也不要拿一张有窟窿的表去过出口评审。
#
# 口径来源：PRD §8.1（可用同名 env 覆写，仅供实验；**出口取证不得下调**，见计划 §4 D4）。
set -uo pipefail

FILE="${1:-build/bench/results.jsonl}"
STRICT="${SLO_STRICT:-0}"

# —— §8.1 口径（唯一编码处）——
POOL_P50_MS="${SLO_POOL_P50_MS:-100}"          # 沙箱创建 P50（池命中）
COLDSTART_P99_MS="${SLO_COLDSTART_P99_MS:-1500}" # 沙箱创建 P99（冷启动）
RESTORE_P50_MS="${SLO_RESTORE_P50_MS:-200}"    # 快照恢复 P50
EXEC_OVERHEAD_MS="${SLO_EXEC_OVERHEAD_MS:-20}" # exec 启动开销
DENSITY_DEFAULT="${SLO_DENSITY_DEFAULT:-200}"  # 密度 ≥200 @ 默认规格 2vCPU/512MiB
DENSITY_MICRO="${SLO_DENSITY_MICRO:-500}"      # 密度 ≥500 @ micro 规格 128MiB

if [ ! -f "$FILE" ]; then
  echo "[slo-gate] 找不到 ${FILE}——先跑 scripts/bench/run-all.sh" >&2
  exit 2
fi

# —— 宿主类型闸：§8.1 的**绝对**口径只在真裸金属上成立（计划 §4 D4）——
#
# 云 VM（腾讯云 CVM 标准型、普通 EC2 等）里跑 Firecracker 是嵌套虚拟化，分位数没有可比性。
# 那条路是 D4 明确写的**逃生口**——「产方法学 + 相对分位，绝对 SLO 标『待补』+ go/no-go 上报」，
# 不是取证。严格档因此直接拒收：宁可当场红，也不要事后有人把一份虚拟机数据当成出口证据
# （两者在 JSONL 里长得一模一样，除了这个标记）。
HOST_KIND="$(grep -o '"host_kind":"[a-z-]*"' "$FILE" 2>/dev/null | tail -1 | cut -d'"' -f4)"
HOST_KIND="${HOST_KIND:-unknown}"
if [ "$HOST_KIND" != "bare-metal" ]; then
  if [ "$STRICT" = "1" ]; then
    echo "[slo-gate] 拒收：宿主类型=${HOST_KIND}，非裸金属。" >&2
    echo "[slo-gate] §8.1 绝对口径只在真裸金属上成立（计划 §4 D4）。云 VM 上的 Firecracker 是嵌套" >&2
    echo "[slo-gate] 虚拟化，分位不可比。若确实只能用云 VM，走 D4 逃生口：去掉 SLO_STRICT 跑，" >&2
    echo "[slo-gate] 产出**方法学 + 相对分位**，绝对 SLO 标「待补」并做 go/no-go 上报——不得当作取证。" >&2
    exit 3
  fi
  echo "⚠️  宿主类型=${HOST_KIND}（非裸金属）：以下数字仅可作**相对**回归对照，"
  echo "⚠️  不能充当 §8.1 绝对口径取证。见计划 §4 D4 逃生口。"
  echo
fi

# 从 results.jsonl 取某 metric 的某字段。多行取**最后一条**（同一 metric 可能跑多档）。
# $1=metric $2=字段 $3=可选的额外匹配串（如 '"spec":"micro"'）
field() {
  local metric="$1" key="$2" extra="${3:-}"
  grep "\"metric\":\"$metric\"" "$FILE" 2>/dev/null \
    | { if [ -n "$extra" ]; then grep -F "$extra"; else cat; fi; } \
    | tail -1 \
    | grep -oE "\"$key\":[0-9]+" | grep -oE '[0-9]+$' || true
}

PASS=0; FAIL=0; SKIP=0
printf '%-34s %10s %10s   %s\n' "指标（PRD §8.1）" "实测" "口径" "判定"
printf '%s\n' "----------------------------------------------------------------------------"

# $1=名字 $2=实测（空=未测） $3=口径 $4=cmp(le|ge) $5=单位
row() {
  local name="$1" got="$2" budget="$3" cmp="$4" unit="$5"
  if [ -z "$got" ]; then
    if [ "$STRICT" = "1" ]; then
      printf '%-34s %10s %10s   %s\n' "$name" "未测" "$budget$unit" "FAIL（严格档：缺测即未达标）"
      FAIL=$((FAIL+1))
    else
      printf '%-34s %10s %10s   %s\n' "$name" "未测" "$budget$unit" "SKIP"
      SKIP=$((SKIP+1))
    fi
    return
  fi
  local ok=0
  case "$cmp" in
    le) [ "$got" -le "$budget" ] && ok=1 ;;
    ge) [ "$got" -ge "$budget" ] && ok=1 ;;
  esac
  if [ "$ok" = 1 ]; then
    printf '%-34s %10s %10s   %s\n' "$name" "$got$unit" "$budget$unit" "PASS"
    PASS=$((PASS+1))
  else
    printf '%-34s %10s %10s   %s\n' "$name" "$got$unit" "$budget$unit" "**FAIL**"
    FAIL=$((FAIL+1))
  fi
}

row "创建 P50（池命中/温池）" "$(field pool_bench warm_p50)" "$POOL_P50_MS" le "ms"
row "创建 P99（冷启动）"       "$(field coldstart p99_ms)"    "$COLDSTART_P99_MS" le "ms"

# 快照恢复 P50：§8.1 这一行指的是**恢复本身**，故取 restore_create 的 load+resume 两段之和，
# 不含 copy 与 api-ready（那两段是编排开销，已单列在创建口径里）。这个映射是一个判断，
# 出口评审时应显式确认；整体 restore_create.p50_ms 一并打印在下方备查。
_load="$(field restore_create load_p50)"; _res="$(field restore_create resume_p50)"
if [ -n "$_load" ] && [ -n "$_res" ]; then _restore=$(( _load + _res )); else _restore=""; fi
row "快照恢复 P50（load+resume）" "$_restore" "$RESTORE_P50_MS" le "ms"

row "exec 启动开销 P50"        "$(field exec_overhead p50_ms)" "$EXEC_OVERHEAD_MS" le "ms"
row "密度 @ 默认规格 2c/512M"  "$(field density max_instances '"spec":"default"')" "$DENSITY_DEFAULT" ge "台"
row "密度 @ micro 规格 128M"   "$(field density max_instances '"spec":"micro"')"   "$DENSITY_MICRO"   ge "台"

printf '%s\n' "----------------------------------------------------------------------------"
_whole="$(field restore_create p50_ms)"
[ -n "$_whole" ] && echo "备查：restore_create 整体 P50 = ${_whole}ms（含 copy/api-ready 编排开销）"
_hot="$(field pool_bench hot_p50)"
[ -n "$_hot" ] && echo "备查：热池命中 P50 = ${_hot}ms"

echo
echo "[slo-gate] PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP} 宿主=${HOST_KIND}（严格档=${STRICT}，口径来源 PRD §8.1）"
if [ "$FAIL" -gt 0 ]; then
  echo "[slo-gate] 未达标——**口径不下调**（计划 §4 D4）；须以配置/实现改进补，或走 go/no-go 上报。" >&2
  exit 1
fi
if [ "$STRICT" = "1" ] && [ "$SKIP" -gt 0 ]; then
  echo "[slo-gate] 严格档下不应出现 SKIP" >&2
  exit 1
fi
echo "[slo-gate] 全部达标。"
