#!/usr/bin/env bash
# verify-api-e2e.sh — W8 控制面端到端自测（REST 守护 + sandlocker CLI 全子命令）。
#
# 流程：① --build 造预烘焙模板 → ② 后台起 `sl-node --serve`（隔离 run-root）→ 轮询就绪
#       → ③ CLI + 直连 REST 走一遍 create/exec/files/logs/ps/destroy → ④ 断言零残留。
# 覆盖出口标准「单命令起全组件；CLI 全子命令可用」+ 契约（openapi.yaml）逐端点实测。
#
# 同时是 W8 门禁：KVM/环境缺失 → 输出 skip JSON、退 0（不阻塞 CI）；就绪但任一断言失败 → 退非 0。
# stdout：单行 JSON（run-all/CI 消费）；人类信息走 stderr。
#
# REST 直连用 bash /dev/tcp（守护回 `Connection: close`，可 read-to-EOF，免 curl/nc 依赖）。
# 文件读写走 guest base64 桥接——若 guest 无 base64 applet 则跳过该断言（warn，不误判红）。
set -euo pipefail

# 复用 bench 前置（幂等构建 sl-node/sl-envd + KVM 检查）；但 _common.sh 用 $0 推 REPO_ROOT，
# 本脚本在 scripts/ 下会算偏，故 source 后用 BASH_SOURCE 修正路径变量。
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO_ROOT/scripts/bench/_common.sh"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SL_NODE="$REPO_ROOT/target/release/sl-node"
KERNEL="$REPO_ROOT/build/kernel/vmlinux"
ROOTFS="$REPO_ROOT/build/rootfs/rootfs.ext4"
FC="$REPO_ROOT/build/firecracker/firecracker"

if ! bench_prep; then
  echo '{"metric":"api_e2e","skipped":true,"reason":"env-not-ready"}'
  exit 0
fi

# 用户面 CLI（bench_prep 不建它）
cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" -p sandlocker >&2
SL_CLI="$REPO_ROOT/target/release/sandlocker"

PORT="${API_PORT:-17878}"
ADDR="127.0.0.1:$PORT"
RROOT="$(mktemp -d "${TMPDIR:-/tmp}/sl-e2e-run.XXXXXX")"
DLOG="$(mktemp "${TMPDIR:-/tmp}/sl-e2e-daemon.XXXXXX.log")"
DAEMON_PID=""

fail() { echo "[api-e2e] FAIL: $*" >&2; echo '{"metric":"api_e2e","pass":false}'; exit 1; }

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null || true
  [ -n "$DAEMON_PID" ] && wait "$DAEMON_PID" 2>/dev/null || true
  rm -rf "$RROOT" "$DLOG" 2>/dev/null || true
}
trap cleanup EXIT

# 直连 REST：$1 method $2 path $3 body(可空) $4 ctype(默认 json)。回「状态码<TAB>body」。
http_req() {
  local method="$1" path="$2" body="${3:-}" ctype="${4:-application/json}" resp code out
  exec 3<>"/dev/tcp/127.0.0.1/$PORT" || { echo "000	dial-failed"; return 0; }
  printf '%s %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
    "$method" "$path" "$ctype" "${#body}" "$body" >&3
  resp="$(cat <&3)"; exec 3<&- 3>&- || true
  code="$(printf '%s' "$resp" | head -1 | awk '{print $2}')"
  out="$(printf '%s' "$resp" | sed '1,/^\r\{0,1\}$/d')"
  printf '%s\t%s' "$code" "$out"
}
http_code() { printf '%s' "$1" | cut -f1; }
http_body() { printf '%s' "$1" | cut -f2-; }

# ① 造预烘焙模板（默认落 build/templates/sl.db + build/templates/hello/<ver>，与守护默认一致）
echo "[api-e2e] 构建模板 examples/hello.sandlocker.toml ..." >&2
BUILD_OUT="$( cd "$REPO_ROOT" && "$SL_NODE" --build examples/hello.sandlocker.toml --json )"
echo "[api-e2e] build: $BUILD_OUT" >&2
echo "$BUILD_OUT" | grep -q '"pass":true' || fail "模板构建未 pass"

# ② 后台起守护（隔离 run-root；store/template-root 用默认，与 build 一致）
echo "[api-e2e] 起守护 sl-node --serve $ADDR （run-root=$RROOT）..." >&2
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
echo "[api-e2e] 守护就绪" >&2

# ③-A CLI ps 起始为空（仅表头）
PS0="$("$SL_CLI" --addr "$ADDR" ps 2>/dev/null || true)"
[ "$(printf '%s\n' "$PS0" | grep -c .)" -le 1 ] || fail "起始 ps 非空: $PS0"

# ③-B CLI snapshot ls 含 hello（GET /v1/templates）
"$SL_CLI" --addr "$ADDR" snapshot ls 2>/dev/null | grep -q '^hello' || fail "snapshot ls 未列出 hello"

# ③-C CLI run（create→exec→destroy 跑完即焚 + 退出码透传）
RUN_OUT="$("$SL_CLI" --addr "$ADDR" run hello -- echo sl-e2e-token 2>/dev/null)" || fail "run 退出码非 0"
printf '%s' "$RUN_OUT" | grep -q 'sl-e2e-token' || fail "run 输出缺 token: $RUN_OUT"
# 退出码透传：守护侧 sl-envd 已 `/bin/sh -c <cmd>`，故直接传 `exit 7`（勿再套 sh -c，会双层包裹归 0）
set +e
"$SL_CLI" --addr "$ADDR" run hello -- exit 7 >/dev/null 2>&1
rc=$?
set -e
[ "$rc" = 7 ] || fail "run 退出码未透传（期望 7，得 $rc）"

# ③-D 直连 REST create（留一个常驻沙箱做 exec/files/logs/ps/destroy）
CREATE="$(http_req POST /v1/sandboxes '{"template":"hello"}')"
[ "$(http_code "$CREATE")" = 201 ] || fail "REST create 非 201: $CREATE"
ID="$(http_body "$CREATE" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
[ -n "$ID" ] || fail "REST create 无 id: $(http_body "$CREATE")"
echo "[api-e2e] 常驻沙箱 id=$ID" >&2

# ③-E CLI exec 常驻沙箱
EX="$("$SL_CLI" --addr "$ADDR" exec "$ID" -- echo hello-from-exec 2>/dev/null)" || fail "exec 退出码非 0"
printf '%s' "$EX" | grep -q 'hello-from-exec' || fail "exec 输出错: $EX"

# ③-E2 keepalive 续期（POST /v1/sandboxes/{id}/keepalive，M2-Q9）：200 且回 lease/ttl_deadline
KA="$(http_req POST "/v1/sandboxes/$ID/keepalive")"
[ "$(http_code "$KA")" = 200 ] || fail "REST keepalive 非 200: $KA"
printf '%s' "$(http_body "$KA")" | grep -q '"lease_deadline"' || fail "keepalive 响应缺 lease_deadline: $(http_body "$KA")"
printf '%s' "$(http_body "$KA")" | grep -q "\"id\":\"$ID\"" || fail "keepalive 响应 id 不符: $(http_body "$KA")"
# 未知沙箱 → 404
KA404="$(http_req POST "/v1/sandboxes/does-not-exist/keepalive")"
[ "$(http_code "$KA404")" = 404 ] || fail "keepalive 未知沙箱应 404，得: $KA404"
echo "[api-e2e] keepalive 续期 OK（含 404 分支）" >&2

# ③-F 文件读写往返（探测 guest base64；缺失则 warn 跳过，不误判红）
HAS_B64="$("$SL_CLI" --addr "$ADDR" exec "$ID" -- sh -c 'command -v base64 >/dev/null && echo YES || echo NO' 2>/dev/null || echo NO)"
if printf '%s' "$HAS_B64" | grep -q YES; then
  PUT="$(http_req PUT "/v1/sandboxes/$ID/files/tmp/e2e.txt" 'payload-1234' application/octet-stream)"
  [ "$(http_code "$PUT")" = 204 ] || fail "文件 PUT 非 204: $PUT"
  GET="$(http_req GET "/v1/sandboxes/$ID/files/tmp/e2e.txt")"
  [ "$(http_code "$GET")" = 200 ] || fail "文件 GET 非 200: $GET"
  printf '%s' "$(http_body "$GET")" | grep -q 'payload-1234' || fail "文件往返内容不符: $(http_body "$GET")"
  echo "[api-e2e] 文件往返 OK" >&2
else
  echo "::warning::guest 无 base64 applet，跳过文件读写断言（exec 仍验证）" >&2
fi

# ③-G CLI logs 非空
LOGS="$("$SL_CLI" --addr "$ADDR" logs "$ID" 2>/dev/null || true)"
[ -n "$LOGS" ] || fail "logs 为空"

# ③-H ps 现列出该沙箱（GET /v1/sandboxes 含 id）
"$SL_CLI" --addr "$ADDR" --json ps 2>/dev/null | grep -q "$ID" || fail "ps 未列出常驻沙箱 $ID"

# ③-I 直连 REST destroy
DEL="$(http_req DELETE "/v1/sandboxes/$ID")"
[ "$(http_code "$DEL")" = 204 ] || fail "REST delete 非 204: $DEL"

# ④ 零残留断言：GET list 空 + 无 firecracker/unshare 进程 + run-root 无实例目录
LIST_AFTER="$(http_req GET /v1/sandboxes)"
printf '%s' "$(http_body "$LIST_AFTER")" | grep -q "$ID" && fail "destroy 后 list 仍含 $ID"
sleep 0.3
FC_N="$(count_proc firecracker)"
[ "$FC_N" = 0 ] || fail "残留 firecracker 进程数=$FC_N"
LEFT="$(find "$RROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
[ "$LEFT" = 0 ] || fail "run-root 残留实例目录数=$LEFT"

echo "[api-e2e] PASS：CLI 全子命令 + REST 端到端 + 零残留" >&2
echo '{"metric":"api_e2e","pass":true}'
