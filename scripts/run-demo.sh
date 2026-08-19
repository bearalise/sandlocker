#!/usr/bin/env bash
# run-demo.sh — M0 W2 端到端 demo：构建 → 造 rootfs → 启 microVM → host↔guest vsock echo
#
# 前置：/dev/kvm 可用、Rust 工具链（含 x86_64-unknown-linux-musl target）、
#       build/kernel/vmlinux（scripts/build-kernel.sh）、
#       build/firecracker/firecracker（scripts/fetch-firecracker.sh）
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# 载入 cargo 环境（rustup 默认安装路径）
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
command -v cargo >/dev/null || { echo "[demo] 错误: 未找到 cargo，先装 Rust 工具链" >&2; exit 1; }

echo "[demo] 1/4 构建 sl-node（host）..."
cargo build --release -p sl-node

echo "[demo] 2/4 构建 sl-envd（guest, musl 静态）..."
cargo build --release -p sl-envd --target x86_64-unknown-linux-musl

echo "[demo] 3/4 构建 rootfs ..."
scripts/build-rootfs.sh

echo "[demo] 4/4 启动 microVM 并做 vsock echo ..."
exec target/release/sl-node run \
  --kernel build/kernel/vmlinux \
  --rootfs build/rootfs/rootfs.ext4 \
  --fc build/firecracker/firecracker \
  --workdir build/run
