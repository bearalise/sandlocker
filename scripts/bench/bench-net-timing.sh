#!/usr/bin/env bash
# bench-net-timing.sh — 网络策略恢复时序探针（Q4）：反复恢复同一快照，断言每次
# 「策略钩子生效早于 resume」（ADR-13：resume 前 vCPU 停摆、构造上无发包窗口，策略先就位）。
#
# 与 bench-clone-entropy.sh 同属**安全回归红线**而非纯指标：
#   - KVM/环境缺失 → 输出 skip JSON、退 0（不阻塞 CI）。
#   - 任一轮 policy_before_resume=false → 退非 0 → CI 红（时序被破坏 = 存在发包窗口）。
# 记录 policy_margin_us（策略早于 resume 的余量，微秒；亚毫秒级，真实 nft gate 随 M2
# jailer --netns 落地，见 crates/sl-node/src/main.rs 的 apply_network_policy 注释）。
# stdout：单行 JSON（run-all.sh 入库）；人类信息走 stderr。
set -euo pipefail
. "$(dirname "$0")/_common.sh"

if ! bench_prep; then
  echo '{"metric":"net_timing","skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

CYCLES="${CYCLES:-6}"
SNAP="$REPO_ROOT/build/run/snap-net-timing"
rm -rf "$SNAP"

# 模式判定（M2 W2）：root + nft + ip 齐 → **live 档**（真具名 netns + 真 nft forward-hook
# 门禁 ensure，resume 之前），`policy_margin_us` 真实非 0；否则 → **rootless 结构档**
# （W10 原行为，margin 结构性、不阻塞，真门禁随 root 落地）。
LOAD_ARGS=()
MODE="rootless-structural"
MARGIN_MUST_POS=false
if [ "$(id -u)" = 0 ] && command -v nft >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
  MODE="root-live"
  MARGIN_MUST_POS=true
  LOAD_ARGS+=(--net-live)
  # uplink 缺省交给守护自动探测（netlive::detect_uplink）；可经 NET_UPLINK 覆盖。
  [ -n "${NET_UPLINK:-}" ] && LOAD_ARGS+=(--uplink "$NET_UPLINK")
fi
echo "[net-timing] 模式=$MODE（margin 须>0=$MARGIN_MUST_POS）" >&2

# 烘焙一份快照供反复恢复（无网络，rootless，免 root——live 档也复用它：快照无网卡，
# live 只在恢复外围起真 netns+真门禁，证"门禁真被 ensure 且钉在 resume 前"）
echo "[net-timing] 烘焙快照 → $SNAP" >&2
( cd "$REPO_ROOT" && "$SL_NODE" --snap-create "$SNAP" ) >&2

all_before_resume=true
min_margin=""
for i in $(seq 1 "$CYCLES"); do
  # --json：stdout 单行 metric（含 policy_before_resume / policy_margin_us）；恢复/断言失败退非 0
  line="$( cd "$REPO_ROOT" && "$SL_NODE" --snap-load "$SNAP" "${LOAD_ARGS[@]}" --json )"
  before="$(printf '%s' "$line" | sed -n 's/.*"policy_before_resume":\([a-z]*\).*/\1/p')"
  margin="$(printf '%s' "$line" | sed -n 's/.*"policy_margin_us":\([0-9]*\).*/\1/p')"
  echo "[net-timing] 轮 $i/$CYCLES：policy_before_resume=$before margin=${margin}µs" >&2
  [ "$before" = "true" ] || all_before_resume=false
  if [ -n "$margin" ]; then
    if [ -z "$min_margin" ] || [ "$margin" -lt "$min_margin" ]; then min_margin="$margin"; fi
  fi
done

[ -n "$min_margin" ] || min_margin=0
pass=false
[ "$all_before_resume" = "true" ] && pass=true
# live 档额外红线：真门禁 ensure 必须产生真实非 0 余量（否则说明门禁未真正落到 resume 前）。
if [ "$MARGIN_MUST_POS" = true ] && [ "$min_margin" -le 0 ]; then
  pass=false
fi

printf '{"metric":"net_timing","mode":"%s","cycles":%s,"policy_before_resume_all":%s,"margin_us_min":%s,"pass":%s}\n' \
  "$MODE" "$CYCLES" "$all_before_resume" "$min_margin" "$pass"

if [ "$pass" != "true" ]; then
  if [ "$all_before_resume" != "true" ]; then
    echo "[net-timing] FAIL：存在 policy_before_resume=false 轮（ADR-13 时序被破坏）" >&2
  else
    echo "[net-timing] FAIL：live 档 margin_us_min=$min_margin 非正（真门禁未落到 resume 前）" >&2
  fi
  exit 1
fi
