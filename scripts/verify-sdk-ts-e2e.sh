#!/usr/bin/env bash
# verify-sdk-ts-e2e.sh — TypeScript SDK 端到端自测（US-1 / US-4 / US-7，对标 verify-sdk-e2e.sh）。
#
# 流程：① 构建 TS SDK（dist）→ ② --build 造预烘焙模板 → ③ 后台起 `sl-node --serve`（隔离 run-root）
#       → 轮询就绪 → ④ 依次跑 examples/sdk-ts/us{1,4,7}_*.ts（纯 SDK 调用）→ ⑤ 断言零残留。
#
# 门禁：node(≥22.6，需类型剥离)/npm/KVM/环境缺失 → 输出 skip JSON、退 0（不阻塞 CI）；
#       就绪但任一场景失败 → 退非 0。stdout：单行 JSON；人类信息走 stderr。
set -euo pipefail

# 复用 bench 前置；_common.sh 用 $0 推 REPO_ROOT，本脚本在 scripts/ 下会算偏一层，故 source 后
# 用 BASH_SOURCE 修正 REPO_ROOT + bench_prep 依赖的 FC/KERNEL/ROOTFS/SL_NODE。
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO_ROOT/scripts/bench/_common.sh"
# _common.sh 定义了 shell 函数 node()（= sl-node run），会遮蔽真 node 二进制——本脚本用真 node，去掉它。
unset -f node 2>/dev/null || true
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SL_NODE="$REPO_ROOT/target/release/sl-node"
KERNEL="$REPO_ROOT/build/kernel/vmlinux"
ROOTFS="$REPO_ROOT/build/rootfs/rootfs.ext4"
FC="$REPO_ROOT/build/firecracker/firecracker"
TS_DIR="$REPO_ROOT/sdk/typescript"

command -v node >/dev/null 2>&1 || { echo '{"metric":"sdk_ts_e2e","skipped":true,"reason":"no-node"}'; exit 0; }
command -v npm  >/dev/null 2>&1 || { echo '{"metric":"sdk_ts_e2e","skipped":true,"reason":"no-npm"}'; exit 0; }
# 示例 .ts 直跑需内核类型剥离（Node ≥22.6，含 --experimental-strip-types）。
node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=6)?0:1)' \
  || { echo '{"metric":"sdk_ts_e2e","skipped":true,"reason":"node-lt-22.6"}'; exit 0; }

if ! bench_prep; then
  echo '{"metric":"sdk_ts_e2e","skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

# 用户面 CLI（bench_prep 不建它）——就绪轮询 + base64 探测用。
cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" -p sandlocker >&2
SL_CLI="$REPO_ROOT/target/release/sandlocker"

fail() { echo "[sdk-ts-e2e] FAIL: $*" >&2; echo '{"metric":"sdk_ts_e2e","pass":false}'; exit 1; }

# 构建 TS SDK（examples 从 dist/esm 导入）。
echo "[sdk-ts-e2e] 构建 TS SDK ..." >&2
( cd "$TS_DIR" && (npm ci >&2 2>&1 || npm install >&2 2>&1) && npm run build >&2 ) || fail "TS SDK 构建失败"

PORT="${SDK_TS_PORT:-17980}"
ADDR="127.0.0.1:$PORT"
RROOT="$(mktemp -d "${TMPDIR:-/tmp}/sl-sdkts-run.XXXXXX")"
DLOG="$(mktemp "${TMPDIR:-/tmp}/sl-sdkts-daemon.XXXXXX.log")"
DAEMON_PID=""
export SANDLOCKER_ADDR="$ADDR"

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  [ -n "$DAEMON_PID" ] && wait "$DAEMON_PID" 2>/dev/null || true
  rm -rf "$RROOT" "$DLOG" 2>/dev/null || true
}
trap cleanup EXIT

# ① 造预烘焙模板
echo "[sdk-ts-e2e] 构建模板 examples/hello.sandlocker.toml ..." >&2
BUILD_OUT="$( cd "$REPO_ROOT" && "$SL_NODE" --build examples/hello.sandlocker.toml --json )"
echo "$BUILD_OUT" | grep -q '"pass":true' || fail "模板构建未 pass: $BUILD_OUT"

# ② 后台起守护（隔离 run-root）
echo "[sdk-ts-e2e] 起守护 sl-node --serve $ADDR （run-root=$RROOT）..." >&2
( cd "$REPO_ROOT" && exec "$SL_NODE" --serve --addr "$ADDR" --run-root "$RROOT" --tick-secs 2 ) >"$DLOG" 2>&1 &
DAEMON_PID=$!

# 轮询就绪
ready=0
for _ in $(seq 1 100); do
  if "$SL_CLI" --addr "$ADDR" ps >/dev/null 2>&1; then ready=1; break; fi
  kill -0 "$DAEMON_PID" 2>/dev/null || { cat "$DLOG" >&2; fail "守护提前退出"; }
  sleep 0.1
done
[ "$ready" = 1 ] || { cat "$DLOG" >&2; fail "守护未就绪"; }
echo "[sdk-ts-e2e] 守护就绪" >&2

# 探测 guest base64（US-1 文件读写依赖）
PROBE="$("$SL_CLI" --addr "$ADDR" run hello -- "command -v base64 >/dev/null 2>&1 && echo YES || echo NO" 2>/dev/null || echo NO)"
if printf '%s' "$PROBE" | grep -q YES; then
  export SL_SKIP_FILES=0
  echo "[sdk-ts-e2e] guest 有 base64，US-1 跑完整文件读写" >&2
else
  export SL_SKIP_FILES=1
  echo "::warning::guest 无 base64 applet，US-1 跳过 SDK 文件 API" >&2
fi

# ③ 三场景（.ts 直跑，内核类型剥离；示例从 dist/esm 导入 SDK）
run_us() {
  local name="$1" script="$2"
  echo "[sdk-ts-e2e] 跑 $name ..." >&2
  if node --experimental-strip-types "$REPO_ROOT/examples/sdk-ts/$script" >&2; then
    echo "[sdk-ts-e2e] $name OK" >&2
  else
    fail "$name 失败"
  fi
}
run_us US-1 us1_quickstart.ts
run_us US-4 us4_template.ts
run_us US-7 us7_ci_ephemeral.ts

# ③-KA keepalive 续期冒烟（纯 JS inline，导入 dist/esm，免类型剥离）
echo "[sdk-ts-e2e] 跑 keepalive 续期冒烟 ..." >&2
node --input-type=module -e "
import { Sandbox } from '$TS_DIR/dist/esm/index.js';
import assert from 'node:assert/strict';
const sbx = await Sandbox.create('hello', { timeout: 120, idle: 5, addr: process.env.SANDLOCKER_ADDR });
try {
  const r = await sbx.keepAlive();
  assert.equal(r.id, sbx.id);
  assert.ok('lease_deadline' in r && 'ttl_deadline' in r, JSON.stringify(r));
  console.error('[sdk-ts-e2e] keepAlive ->', JSON.stringify(r));
} finally { await sbx.kill(); }
" >&2 || fail "keepalive 冒烟失败"
echo "[sdk-ts-e2e] keepalive 续期 OK" >&2

# ④ 零残留断言
sleep 0.5
FC_N="$(count_proc firecracker)"
[ "$FC_N" = 0 ] || fail "残留 firecracker 进程数=$FC_N"
LEFT="$(find "$RROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
[ "$LEFT" = 0 ] || fail "run-root 残留实例目录数=$LEFT"

echo "[sdk-ts-e2e] PASS：US-1/US-4/US-7 三场景端到端 + 零残留" >&2
echo '{"metric":"sdk_ts_e2e","pass":true}'
