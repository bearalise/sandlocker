#!/usr/bin/env bash
# verify-build-egress.sh — M2-Q8「allow-network 构建」端到端自测（构建期真出口）。
#
# 用法（需 root + KVM + 网络）:
#   sudo scripts/verify-build-egress.sh ["构建期 egress 验证命令"]
#     默认命令 = "nslookup one.one.one.one"（经 guest resolv.conf=1.1.1.1 解析 → 证 UDP53
#     经 netns+NAT 出 uplink；不依赖 SSL/HTTP 语义，最稳）。
#
# 流程：
#   ① 写临时 allow-all 模板（from 省略 = 基座 rootfs），--build → 构建沙箱 boot 进 netns（veth+tap+NAT）
#      → RUN 跑 egress 验证命令（fail-fast：出口不通即 build 失败）。
#   ② 断言 pass:true + 构建后无 netns 残留（sl-* / veth）。
#
# 门禁：非 root / 无 KVM / 缺内核·fc·基座 rootfs / 缺 sl-node 二进制 → 输出 skip JSON 退 0（不阻塞 CI）。
# 不自行 cargo build（假设调用方/CI 已构建好 sl-node + sl-envd + 基座 rootfs）——便于在 sudo 下运行。
# stdout：单行 JSON；人类信息走 stderr。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SL_NODE="$REPO_ROOT/target/release/sl-node"
KERNEL="$REPO_ROOT/build/kernel/vmlinux"
FC="$REPO_ROOT/build/firecracker/firecracker"
ROOTFS="$REPO_ROOT/build/rootfs/rootfs.ext4"

EGRESS_CMD="${1:-nslookup one.one.one.one}"
NAME="beg-$$"

emit_skip() { echo "{\"metric\":\"build_egress\",\"skipped\":true,\"reason\":\"$1\"}"; exit 0; }
fail() { echo "[build-egress] FAIL: $*" >&2; echo '{"metric":"build_egress","pass":false}'; exit 1; }

[ "$(id -u)" = 0 ] || emit_skip "not-root"          # allow-all 需 root（ip/nft/netns）
[ -w /dev/kvm ] || emit_skip "no-kvm"
[ -x "$SL_NODE" ] || emit_skip "no-sl-node"         # 先 cargo build -p sl-node --release
[ -f "$KERNEL" ] || emit_skip "no-kernel"
[ -x "$FC" ] || emit_skip "no-firecracker"
[ -f "$ROOTFS" ] || emit_skip "no-rootfs"           # scripts/build-rootfs.sh（含 busybox nslookup）

TMPD="$(mktemp -d "${TMPDIR:-/tmp}/sl-beg.XXXXXX")"
TOML="$TMPD/$NAME.sandlocker.toml"
STORE="$TMPD/sl.db"
OUT_DIR="$REPO_ROOT/build/templates/$NAME"
cleanup() { rm -rf "$TMPD" "$OUT_DIR" 2>/dev/null || true; }
trap cleanup EXIT

# 记录构建前 netns，事后对账残留
NS_BEFORE="$(ip netns list 2>/dev/null | awk '{print $1}' | sort || true)"

cat > "$TOML" <<TOMLEOF
name = "$NAME"
build_network = "allow-all"
run = ["$EGRESS_CMD"]
TOMLEOF

echo "[build-egress] --build allow-all（egress 验证命令：$EGRESS_CMD）..." >&2
BUILD="$( cd "$REPO_ROOT" && "$SL_NODE" --build "$TOML" --store "$STORE" --json )" \
  || { echo "$BUILD" >&2; fail "--build 失败（出口不通？uplink/DNS？看 $OUT_DIR/*/console.build.log）"; }
echo "[build-egress] build: $BUILD" >&2
echo "$BUILD" | grep -q '"pass":true' || fail "--build 未 pass（egress RUN 失败）"

# 零残留：构建后 netns 集合应与构建前一致（sl-<hash> 已被 run_build_phase 兜底 down）
NS_AFTER="$(ip netns list 2>/dev/null | awk '{print $1}' | sort || true)"
if [ "$NS_BEFORE" != "$NS_AFTER" ]; then
  echo "[build-egress] netns 残留：before=[$NS_BEFORE] after=[$NS_AFTER]" >&2
  fail "构建后 netns 未清理干净"
fi

echo "[build-egress] PASS：allow-all 构建真出口生效（$EGRESS_CMD 通过）+ netns 零残留" >&2
echo "{\"metric\":\"build_egress\",\"egress_cmd\":\"$EGRESS_CMD\",\"pass\":true}"
