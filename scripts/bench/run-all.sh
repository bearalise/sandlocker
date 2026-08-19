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

shopt -s nullglob
BENCHES=("$REPO_ROOT"/scripts/bench/bench-*.sh)
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
