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
    printf '{"sha":"%s","ts":"%s","bench":"%s","data":%s}\n' "$SHA" "$TS" "$name" "$line" \
      >> "$OUT_DIR/results.jsonl"
  done
  echo "[bench] $name 完成"
done

echo "[bench] 结果: $OUT_DIR/results.jsonl"
