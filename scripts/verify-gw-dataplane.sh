#!/usr/bin/env bash
# verify-gw-dataplane.sh — M3 W5 余项活证（M3-Q3 + FR-7.1 集群内 mTLS）。
#
# 造一套 CA/网关/节点证书（openssl），然后：
#   ① 明文：`--gw-dataplane-reconcile --gw-insecure` 全套断言过；
#   ② mTLS：同一套断言**跑在 mTLS 之上** + 明文连接不得被节点接入端口收编；
#   ③ 无客户端证书的 TLS 客户端（openssl s_client）连节点接入端口 → **握手被拒**
#      （这条是 mTLS 的真凭据：只有 ② 里的 in-process 断言不足以证明"外人连不上"）。
#
# 用法：
#   scripts/verify-gw-dataplane.sh                       # SQLite 后端
#   scripts/verify-gw-dataplane.sh http://127.0.0.1:2379 # 真 etcd 后端（同一套断言）
#
# 依赖：openssl、cargo（`--features cluster`）。
set -euo pipefail

ETCD_EP="${1:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BIN="${SL_NODE_BIN:-}"
if [[ -z "$BIN" ]]; then
  echo "== 构建 sl-node（--features cluster）"
  cargo build -p sl-node --features cluster --manifest-path "$ROOT/Cargo.toml" >/dev/null
  BIN="$ROOT/target/debug/sl-node"
fi

echo "== 造证书（CA → 网关证书[SAN=sandlocker-gw] + 节点证书）"
cd "$WORK"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=sandlocker-ca" \
  -keyout ca.key -out ca.pem 2>/dev/null

gen_cert() { # $1=名字 $2=CN/SAN
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$2" -keyout "$1.key" -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 \
    -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$2") \
    -out "$1.pem" 2>/dev/null
}
gen_cert gw sandlocker-gw
gen_cert node sandlocker-node

ETCD_ARGS=()
[[ -n "$ETCD_EP" ]] && ETCD_ARGS=(--etcd "$ETCD_EP")
LABEL="${ETCD_EP:-SQLite}"

echo
echo "== ① 明文传输：全套数据面断言（${LABEL}）"
"$BIN" --gw-dataplane-reconcile --gw-insecure "${ETCD_ARGS[@]}"

echo
echo "== ② mTLS 传输：同一套断言跑在 mTLS 之上 + 明文连接被拒（${LABEL}）"
# 对账把网关与节点跑在同一进程里，故这**一张**证书要同时充当服务端与客户端身份：
# 取 SAN=sandlocker-gw 的那张（gen_cert 已给它 serverAuth+clientAuth 双 EKU），
# 客户端侧的 --gw-tls-name 才对得上服务端出示的名字。
"$BIN" --gw-dataplane-reconcile "${ETCD_ARGS[@]}" \
  --gw-tls-cert "$WORK/gw.pem" --gw-tls-key "$WORK/gw.key" \
  --gw-tls-ca "$WORK/ca.pem" --gw-tls-name sandlocker-gw

echo
echo "== ③ 无客户端证书的 TLS 客户端应被网关节点接入端口拒绝"
# 起一个真 sandlocker-gw 进程（mTLS），拿它的节点接入端口做负向测试。
GW_BIN="$(dirname "$BIN")/sandlocker-gw"
if [[ ! -x "$GW_BIN" ]]; then
  echo "  跳过：未构建 sandlocker-gw（应与 sl-node 同目录）" >&2
  exit 0
fi
if [[ -z "$ETCD_EP" ]]; then
  echo "  跳过：③ 需 --etcd（sandlocker-gw 按 etcd 的 sandbox/<sid>/node 映射转发）"
  exit 0
fi
"$GW_BIN" --bind 127.0.0.1:17879 --node-bind 127.0.0.1:17880 --etcd "$ETCD_EP" \
  --tls-cert "$WORK/gw.pem" --tls-key "$WORK/gw.key" --tls-ca "$WORK/ca.pem" >"$WORK/gw.log" 2>&1 &
GW_PID=$!
trap 'kill "$GW_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT
for _ in $(seq 1 50); do
  grep -q "节点接入就绪" "$WORK/gw.log" && break
  sleep 0.2
done

# 不带客户端证书 → 服务端要求证书 → 握手失败。
set +e
OUT="$(echo | openssl s_client -connect 127.0.0.1:17880 -CAfile "$WORK/ca.pem" \
  -servername sandlocker-gw 2>&1)"
RC=$?
set -e
if [[ $RC -eq 0 ]] && ! grep -qiE "certificate required|handshake failure|alert|bad certificate" <<<"$OUT"; then
  echo "FAIL：无客户端证书竟握手成功——mTLS 未强制" >&2
  exit 1
fi
echo "  无客户端证书 → 握手被拒 ✓"

# 带合法客户端证书 → 握手成功（证明拒绝的原因是缺证书，而非端口不通）。
set +e
OUT2="$(echo | openssl s_client -connect 127.0.0.1:17880 -CAfile "$WORK/ca.pem" \
  -cert "$WORK/node.pem" -key "$WORK/node.key" -servername sandlocker-gw 2>&1)"
set -e
if ! grep -q "Verify return code: 0" <<<"$OUT2"; then
  echo "FAIL：合法客户端证书也握不上手（对照组失败）" >&2
  echo "$OUT2" | tail -20 >&2
  exit 1
fi
echo "  合法客户端证书 → 握手成功 ✓（拒绝确因缺证书）"

echo
echo "[verify-gw-dataplane] M3 W5 余项 PASS（${LABEL}：明文 + mTLS + 强制客户端证书）"
