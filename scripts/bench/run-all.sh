#!/usr/bin/env bash
# run-all.sh — 基准入口：环境检查 + 顺序执行 scripts/bench/bench-*.sh
# 结果追加写入 build/bench/results.jsonl（含 git sha 与时间戳，供回归对比）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="$REPO_ROOT/build/bench"
mkdir -p "$OUT_DIR"

"$REPO_ROOT/scripts/bench/check-env.sh"

SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
TS="$(date -u +%FT%TZ)"

# 宿主类型钉进**每一行**结果：绝对 SLO 口径只在真裸金属上成立（计划 §4 D4）。虚拟机上跑出来的
# 数字若不带这个标记，事后与裸金属数据长得一模一样，会被误当出口证据。slo-gate.sh 严格档据此拒收。
. "$REPO_ROOT/scripts/bench/_common.sh"
HOST_KIND="$(host_kind)"
CPUS="$(nproc 2>/dev/null || echo 0)"
MEM_GB="$(awk '/^MemTotal:/{print int($2/1048576)}' /proc/meminfo 2>/dev/null || echo 0)"
echo "[bench] 宿主=$HOST_KIND cpus=$CPUS mem=${MEM_GB}G"
if [ "$HOST_KIND" != "bare-metal" ]; then
  echo "[bench] ⚠️  非裸金属宿主：分位数仅可作**相对**回归对照，不能充当 §8.1 绝对口径取证（D4 逃生口）。"
fi

# BENCH_ONLY=名字[,名字...]：只跑指定的几个（不带 bench- 前缀亦可）。
# 裸金属按小时计费，密度要按 §8.1 分「默认档 / micro 档」跑两趟——第二趟只需重跑密度，
# 没必要把建内核/建模板/冷启动/池 全都再来一遍。
shopt -s nullglob
BENCHES=("$REPO_ROOT"/scripts/bench/bench-*.sh)
if [ -n "${BENCH_ONLY:-}" ]; then
  filtered=()
  for b in "${BENCHES[@]}"; do
    name="$(basename "$b" .sh)"
    case ",${BENCH_ONLY}," in
      *",${name},"*|*",${name#bench-},"*) filtered+=("$b") ;;
    esac
  done
  BENCHES=("${filtered[@]}")
  echo "[bench] BENCH_ONLY=${BENCH_ONLY} → 只跑 ${#BENCHES[@]} 项"
fi
if [ ${#BENCHES[@]} -eq 0 ]; then
  echo "[bench] 暂无 bench-*.sh（W4 冷启动/销毁、W6 密度落地后自动纳入）"
fi

for b in "${BENCHES[@]}"; do
  name="$(basename "$b" .sh)"
  echo "[bench] 运行 $name ..."
  "$b" | while IFS= read -r line; do
    printf '{"sha":"%s","ts":"%s","host_kind":"%s","cpus":%s,"mem_gb":%s,"bench":"%s","data":%s}\n' \
      "$SHA" "$TS" "$HOST_KIND" "$CPUS" "$MEM_GB" "$name" "$line" \
      >> "$OUT_DIR/results.jsonl"
  done
  echo "[bench] $name 完成"
done

echo "[bench] 结果: $OUT_DIR/results.jsonl"
