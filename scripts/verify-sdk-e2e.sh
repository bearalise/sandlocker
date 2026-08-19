#!/usr/bin/env bash
# verify-sdk-e2e.sh — W9 Python SDK 端到端自测（US-1 / US-4 / US-7，出口标准 Q8）。
#
# 流程：① --build 造预烘焙模板 → ② 后台起 `sl-node --serve`（隔离 run-root）→ 轮询就绪
#       → ③ 依次跑 examples/sdk/us{1,4,7}_*.py（纯 SDK 调用）→ ④ 断言零残留。
# 覆盖出口标准「三场景通过（Q8)」；SDK 面（create/run/files/logs/list/自毁）逐一实测。
#
# 同时是 W9 门禁：KVM/环境/python3 缺失 → 输出 skip JSON、退 0（不阻塞 CI）；
#                 就绪但任一场景失败 → 退非 0。stdout：单行 JSON；人类信息走 stderr。
#
# SDK 免安装：PYTHONPATH 指向 sdk/python/src（与单测一致，不强依赖 pip install）。
# 文件读写依赖 guest base64 applet——先探测，缺失则给 US-1 传 SL_SKIP_FILES=1（warn，不误判红）。
set -euo pipefail

# 复用 bench 前置（幂等构建 sl-node/sl-envd + KVM 检查）；_common.sh 用 $0 推 REPO_ROOT，
# 本脚本在 scripts/ 下会算偏，故 source 后用 BASH_SOURCE 修正。
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO_ROOT/scripts/bench/_common.sh"
# _common.sh 用 $0 推 REPO_ROOT，本脚本在 scripts/ 下会算偏一层，故修正 REPO_ROOT
# 及 bench_prep 依赖的 FC/KERNEL/ROOTFS/SL_NODE（否则 bench_prep 误判「缺 firecracker」）。
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SL_NODE="$REPO_ROOT/target/release/sl-node"
KERNEL="$REPO_ROOT/build/kernel/vmlinux"
ROOTFS="$REPO_ROOT/build/rootfs/rootfs.ext4"
FC="$REPO_ROOT/build/firecracker/firecracker"

if ! command -v python3 >/dev/null 2>&1; then
  echo '{"metric":"sdk_e2e","skipped":true,"reason":"no-python3"}'
  exit 0
fi

if ! bench_prep; then
  echo '{"metric":"sdk_e2e","skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

# 用户面 CLI（bench_prep 不建它）——仅用于就绪轮询 + base64 探测。
cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" -p sandlocker >&2
SL_CLI="$REPO_ROOT/target/release/sandlocker"

PORT="${SDK_PORT:-17979}"
ADDR="127.0.0.1:$PORT"
RROOT="$(mktemp -d "${TMPDIR:-/tmp}/sl-sdk-run.XXXXXX")"
DLOG="$(mktemp "${TMPDIR:-/tmp}/sl-sdk-daemon.XXXXXX.log")"
DAEMON_PID=""

export SANDLOCKER_ADDR="$ADDR"
export PYTHONPATH="$REPO_ROOT/sdk/python/src${PYTHONPATH:+:$PYTHONPATH}"

fail() { echo "[sdk-e2e] FAIL: $*" >&2; echo '{"metric":"sdk_e2e","pass":false}'; exit 1; }

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  [ -n "$DAEMON_PID" ] && wait "$DAEMON_PID" 2>/dev/null || true
  rm -rf "$RROOT" "$DLOG" 2>/dev/null || true
}
trap cleanup EXIT

# ① 造预烘焙模板（默认落 build/templates/sl.db + build/templates/hello/<ver>，与守护默认一致）
echo "[sdk-e2e] 构建模板 examples/hello.sandlocker.toml ..." >&2
BUILD_OUT="$( cd "$REPO_ROOT" && "$SL_NODE" --build examples/hello.sandlocker.toml --json )"
echo "$BUILD_OUT" | grep -q '"pass":true' || fail "模板构建未 pass: $BUILD_OUT"

# ② 后台起守护（隔离 run-root；store/template-root 用默认，与 build 一致）
echo "[sdk-e2e] 起守护 sl-node --serve $ADDR （run-root=$RROOT）..." >&2
( cd "$REPO_ROOT" && exec "$SL_NODE" --serve --addr "$ADDR" --run-root "$RROOT" --tick-secs 2 ) >"$DLOG" 2>&1 &
DAEMON_PID=$!

# 轮询就绪：CLI ps 成功即守护 up（最多 ~10s）
ready=0
for _ in $(seq 1 100); do
  if "$SL_CLI" --addr "$ADDR" ps >/dev/null 2>&1; then ready=1; break; fi
  kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$DLOG" >&2; fail "守护提前退出"; }
  sleep 0.1
done
[ "$ready" = 1 ] || { cat "$DLOG" >&2; fail "守护未就绪"; }
echo "[sdk-e2e] 守护就绪" >&2

# ③-探测 guest base64（US-1 文件读写依赖）：整条命令作为单参传入，guest sh -c 执行。
PROBE="$("$SL_CLI" --addr "$ADDR" run hello -- "command -v base64 >/dev/null 2>&1 && echo YES || echo NO" 2>/dev/null || echo NO)"
if printf '%s' "$PROBE" | grep -q YES; then
  export SL_SKIP_FILES=0
  echo "[sdk-e2e] guest 有 base64，US-1 跑完整文件读写" >&2
else
  export SL_SKIP_FILES=1
  echo "::warning::guest 无 base64 applet，US-1 跳过 SDK 文件 API（run 产物断言仍验证）" >&2
fi

# ③ 三场景（纯 SDK，经 SANDLOCKER_ADDR 连守护）
run_us() {
  local name="$1" script="$2"
  echo "[sdk-e2e] 跑 $name ..." >&2
  if python3 "$REPO_ROOT/examples/sdk/$script" >&2; then
    echo "[sdk-e2e] $name OK" >&2
  else
    fail "$name 失败"
  fi
}
run_us US-1 us1_quickstart.py
run_us US-4 us4_template.py
run_us US-7 us7_ci_ephemeral.py

# ③-KA keepalive 续期冒烟（M2-Q9）：SDK sbx.keep_alive() 在线滑 idle 窗、回 lease/ttl_deadline。
echo "[sdk-e2e] 跑 keepalive 续期冒烟 ..." >&2
python3 - <<'PY' >&2 || fail "keepalive 冒烟失败"
import os
from sandlocker import Sandbox
with Sandbox.create(template="hello", timeout=120, idle=5, addr=os.environ["SANDLOCKER_ADDR"]) as sbx:
    r = sbx.keep_alive()
    assert r["id"] == sbx.id, r
    assert "lease_deadline" in r and "ttl_deadline" in r, r
    print("[sdk-e2e] keep_alive ->", r)
PY
echo "[sdk-e2e] keepalive 续期 OK" >&2

# ④ 零残留断言：无 firecracker 进程 + run-root 无实例目录（US-1 空闲回收 + US-7 焚毁后）
sleep 0.5
FC_N="$(count_proc firecracker)"
[ "$FC_N" = 0 ] || fail "残留 firecracker 进程数=$FC_N"
LEFT="$(find "$RROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
[ "$LEFT" = 0 ] || fail "run-root 残留实例目录数=$LEFT"

echo "[sdk-e2e] PASS：US-1/US-4/US-7 三场景端到端 + 零残留" >&2
echo '{"metric":"sdk_e2e","pass":true}'
