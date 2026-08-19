#!/usr/bin/env bash
# verify-oci-e2e.sh — M2 W3「OCI 镜像当 rootfs 来源」端到端自测（M2-Q12 / ADR-18 / D5）。
#
# 用法:
#   scripts/verify-oci-e2e.sh [源] [构建期验证命令]
#
#   源（默认 docker://alpine:latest）:
#     docker://<ref>         远程 registry 拉取（需网络；sl-node 内建 ureq+rustls，**不经 docker**）
#     docker-archive:<tar>   docker save 产物（daemonless；本地新建的镜像走这条最稳）
#     oci-archive:<tar>      OCI layout 归档（daemonless）
#     <本地镜像:tag>         无 scheme：若本机 docker 里有该镜像，自动 `docker save` → docker-archive
#                            （daemonless 后续）；否则按远程 docker://<ref> 处理
#   构建期验证命令（默认 "echo oci-e2e-ok"）:
#     在**真 microVM** 内经 /bin/sh -c 执行；退非 0 即 fail —— 这就是 M2-Q12 的 boot 判据。
#     勿含双引号（会破坏临时 TOML）。
#
# 流程：
#   ① --oci-pull 单独取证：拉取/解包 → ext4（产层数/字节/source_digest），e2fsck 校验产物健康。
#   ② --build（from=源）：在真 microVM 内跑验证命令 → pass:true 即证 OCI 基座 boot 成功。
#   ③ 校验预烘焙快照产物齐全（rootfs.ext4/vmstate/mem/manifest.json/manifest.sig）→ 清理。
#
# 门禁：sl-node/sl-envd 可构建 + 内核 + firecracker + /dev/kvm 齐 → 跑；缺任一 → 输出 skip JSON 退 0
#       （不阻塞 CI）。就绪但任一步失败 → 退非 0。stdout 单行 JSON；人类信息走 stderr。
#
# ⚠️ 预烘焙第二阶段烘死 1 vCPU / 128 MiB（crates/sl-node/src/build.rs 的 /machine-config）——
#    大镜像（python/node 等）boot 到预烘焙点可能 OOM 而 fail。先用 alpine 验通路；真镜像 OOM
#    需先把 machine-config 改成从 DSL 读（这条对 oci2rootfs.sh 与内建 oci.rs 两条路径都成立）。
# 注：--oci-cache（build/oci-cache/）是内容寻址缓存，**故意不清**——同源重跑秒过。
set -euo pipefail

# 复用 _common.sh 的 cargo env + count_proc；但 OCI 测试不需要 Alpine 基座 rootfs，故不走 bench_prep
# （它会强制 build-rootfs），改用下面的轻量 prep。
# 注意：_common.sh 用 $0 推 REPO_ROOT，它假设自己被 scripts/bench/ 下的脚本 source（两层深），
# 而本脚本在 scripts/ 下（一层深）会把 REPO_ROOT 算到仓库上一级——故 source 后必须用 BASH_SOURCE
# 重算 REPO_ROOT 并**显式重设** SL_NODE/KERNEL/FC（同 verify-api-e2e.sh）。
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO_ROOT/scripts/bench/_common.sh"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SL_NODE="$REPO_ROOT/target/release/sl-node"
KERNEL="$REPO_ROOT/build/kernel/vmlinux"
FC="$REPO_ROOT/build/firecracker/firecracker"

SRC_IN="${1:-docker://alpine:latest}"
RUNCMD="${2:-echo oci-e2e-ok}"
NAME="ocie2e"

emit_skip() { echo "{\"metric\":\"oci_e2e\",\"skipped\":true,\"reason\":\"$1\"}"; exit 0; }
fail() { echo "[oci-e2e] FAIL: $*" >&2; echo '{"metric":"oci_e2e","pass":false}'; exit 1; }

# ── 轻量 prep（不强制 build-rootfs；OCI 基座来自源，不是 Alpine 基座）──
command -v cargo >/dev/null 2>&1 || emit_skip "no-cargo"
cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" -p sl-node >&2 || emit_skip "build-failed"
cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" \
  -p sl-envd --target x86_64-unknown-linux-musl >&2 || emit_skip "build-failed"
[ -x "$FC" ] || emit_skip "no-firecracker"     # scripts/fetch-firecracker.sh
[ -f "$KERNEL" ] || emit_skip "no-kernel"       # scripts/build-kernel.sh
[ -w /dev/kvm ] || emit_skip "no-kvm"

TMPD="$(mktemp -d "${TMPDIR:-/tmp}/sl-oci-e2e.XXXXXX")"
STORE="$TMPD/sl.db"                              # 隔离 store，不污染共享 build/templates/sl.db
OUT_DIR="$REPO_ROOT/build/templates/$NAME"       # --build 输出固定于此（不受 --template-root 影响）
PULL_EXT4="$TMPD/pull.ext4"
TOML="$TMPD/$NAME.sandlocker.toml"
PASSED=0
KEEP="${KEEP:-0}"
# 失败时**总是**保留 OUT_DIR：console.build.log / console.bake.log 是排查 boot/快照失败的关键证据，
# 删了就得从头重跑（本脚本第一版就吃过这亏）。成功时默认清理；KEEP=1 则成功也保留，便于回看 VM 输出。
cleanup() {
  rm -rf "$TMPD" 2>/dev/null || true
  [ "$PASSED" = 1 ] && [ "$KEEP" != 1 ] && rm -rf "$OUT_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ── 解析源：本地 docker 镜像 ref → docker save 成 docker-archive（后续 daemonless）──
SRC="$SRC_IN"
case "$SRC_IN" in
  docker://*|docker-archive:*|oci-archive:*) : ;;   # 已带 scheme，原样交给 sl-node classify
  *)
    if command -v docker >/dev/null && docker image inspect "$SRC_IN" >/dev/null 2>&1; then
      echo "[oci-e2e] docker save $SRC_IN → docker-archive（daemonless 转换）..." >&2
      docker save "$SRC_IN" -o "$TMPD/img.tar" || fail "docker save 失败: $SRC_IN"
      SRC="docker-archive:$TMPD/img.tar"
    else
      echo "[oci-e2e] $SRC_IN 无 scheme 且非本地 docker 镜像 → 按远程 docker://$SRC_IN 处理" >&2
      SRC="docker://$SRC_IN"
    fi ;;
esac
echo "[oci-e2e] 源 = $SRC ；构建期验证命令 = [$RUNCMD]" >&2

# ── ① --oci-pull 单独取证（拉取/解包 → ext4）──
echo "[oci-e2e] ① --oci-pull ..." >&2
PULL="$( cd "$REPO_ROOT" && "$SL_NODE" --oci-pull "$SRC" --oci-out "$PULL_EXT4" --json )" \
  || { echo "$PULL" >&2; fail "--oci-pull 失败（远程档需网络；本地档请确认是 docker save / OCI layout 归档）"; }
echo "[oci-e2e] pull: $PULL" >&2
echo "$PULL" | grep -q '"pass":true' || fail "--oci-pull 未 pass"
LAYERS="$(echo "$PULL" | sed -n 's/.*"layers":\([0-9]*\).*/\1/p')"
[ -s "$PULL_EXT4" ] || fail "--oci-pull 未产出 ext4"
if command -v e2fsck >/dev/null; then
  e2fsck -fn "$PULL_EXT4" >/dev/null 2>&1 || fail "产出 ext4 e2fsck 不通过"
fi

# ── ② --build（from=源）：真 microVM 内跑验证命令 ──
cat > "$TOML" <<TOMLEOF
name = "$NAME"
from = "$SRC"
run = ["$RUNCMD"]
build_network = "deny"
TOMLEOF
echo "[oci-e2e] ② --build（真 microVM 内跑 run，fail-fast）..." >&2
BUILD="$( cd "$REPO_ROOT" && "$SL_NODE" --build "$TOML" --store "$STORE" --json )" \
  || { echo "$BUILD" >&2
       echo "[oci-e2e] --build 失败。看控制台日志定位（已保留）：" >&2
       echo "  build 阶段: $OUT_DIR/*/console.build.log" >&2
       echo "  prebake 阶段: $OUT_DIR/*/console.bake.log" >&2
       echo "  常见：guest 内 128MiB 预烘焙不够（大镜像 boot OOM）→ 见脚本头；快照阶段卡住多为 I/O 超时。" >&2
       fail "--build 失败"; }
echo "[oci-e2e] build: $BUILD" >&2
echo "$BUILD" | grep -q '"pass":true' || fail "--build 未 pass（boot 起镜像失败）"
VER="$(echo "$BUILD" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ -n "$VER" ] || fail "--build 未回 version"

# ── ③ 预烘焙快照产物齐全（可恢复）──
D="$OUT_DIR/$VER"
for f in rootfs.ext4 vmstate mem manifest.json manifest.sig; do
  [ -s "$D/$f" ] || fail "缺产物 $D/$f"
done

PASSED=1
echo "[oci-e2e] PASS：源=$SRC 层数=${LAYERS:-?} → boot 起镜像 + run 通过 + 预烘焙快照齐全" >&2

# KEEP=1：保留产物并回看 VM 输出（guest 内核 + sl-envd 控制台）。注意：本脚本用 --json 跑 --build，
# run 命令的 stdout 被抑制——要看命令输出请直接 `sl-node --build <toml>`（不加 --json），见提示。
if [ "$KEEP" = 1 ]; then
  cp "$TOML" "$D/$NAME.sandlocker.toml" 2>/dev/null || true   # TMPD 会被清，副本留进保留目录
  echo "[oci-e2e] KEEP=1：已保留产物 $D" >&2
  echo "===== console.bake.log（预烘焙 boot + 快照）=====" >&2
  cat "$D/console.bake.log" >&2 2>/dev/null || true
  echo "===== console.build.log 见: $D/console.build.log =====" >&2
  echo "[提示] run 命令的 stdout 被 --json 抑制；看命令输出请直接跑（不加 --json）：" >&2
  echo "       $SL_NODE --build $D/$NAME.sandlocker.toml" >&2
  echo "       或起沙箱交互： $REPO_ROOT/target/release/sandlocker up && $REPO_ROOT/target/release/sandlocker run $NAME -- <命令>" >&2
fi
echo "{\"metric\":\"oci_e2e\",\"source\":\"$SRC\",\"layers\":${LAYERS:-0},\"version\":\"$VER\",\"pass\":true}"
