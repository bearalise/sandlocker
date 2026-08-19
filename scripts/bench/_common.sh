# _common.sh — bench-*.sh 共享前置（source 我；不向 stdout 输出，保持 stdout 纯 JSON）
# 幂等构建 sl-node/sl-envd + 确保 rootfs 存在；检查 /dev/kvm。
# 返回：0 就绪 / 2 环境不满足（调用方应 emit skip JSON 后 exit 0，不阻塞 CI）。

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

SL_NODE="$REPO_ROOT/target/release/sl-node"
KERNEL="$REPO_ROOT/build/kernel/vmlinux"
ROOTFS="$REPO_ROOT/build/rootfs/rootfs.ext4"
FC="$REPO_ROOT/build/firecracker/firecracker"

bench_prep() {
  command -v cargo >/dev/null 2>&1 || { echo "[bench] 无 cargo，跳过" >&2; return 2; }
  cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" -p sl-node >&2 || return 2
  cargo build --release -q --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p sl-envd --target x86_64-unknown-linux-musl >&2 || return 2
  [ -x "$FC" ] || { echo "[bench] 缺 firecracker，跳过（scripts/fetch-firecracker.sh）" >&2; return 2; }
  [ -f "$KERNEL" ] || { echo "[bench] 缺内核，跳过（scripts/build-kernel.sh）" >&2; return 2; }
  [ -f "$ROOTFS" ] || "$REPO_ROOT/scripts/build-rootfs.sh" >&2 || return 2
  [ -w /dev/kvm ] || { echo "[bench] /dev/kvm 不可写，跳过" >&2; return 2; }
  return 0
}

# node <args...>：跑 sl-node，工作目录 REPO_ROOT，独立 workdir 避免并发/残留串扰
node() { ( cd "$REPO_ROOT" && "$SL_NODE" run "$@" ); }

# count_proc <名字子串>：扫 /proc/*/comm 计数（不依赖 pgrep）
count_proc() {
  local needle="$1" n=0 f
  for f in /proc/[0-9]*/comm; do
    [ -r "$f" ] && grep -q "$needle" "$f" 2>/dev/null && n=$((n+1))
  done
  echo "$n"
}
