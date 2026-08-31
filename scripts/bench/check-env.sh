#!/usr/bin/env bash
# check-env.sh — 基准环境前置检查（KVM / FC / 内核镜像 / 机器规格）
# 任何一项缺失即非零退出；CI bench job 的第一步。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FAIL=0

report() { printf '%-24s %s\n' "$1" "$2"; }

echo "== 机器规格 =="
report "cpu_cores" "$(nproc)"
report "mem_total_gb" "$(free -g | awk '/^Mem:/{print $2}')"
report "kernel" "$(uname -r)"
report "arch" "$(uname -m)"

echo "== 前置检查 =="
if [ -w /dev/kvm ]; then
  report "kvm" "OK (/dev/kvm 可写)"
else
  report "kvm" "FAIL: /dev/kvm 不存在或不可写（需要裸金属或嵌套虚拟化）"
  FAIL=1
fi

if [ -x "$REPO_ROOT/build/firecracker/firecracker" ]; then
  report "firecracker" "OK ($("$REPO_ROOT/build/firecracker/firecracker" --version 2>/dev/null | head -1))"
else
  report "firecracker" "FAIL: 缺失，运行 scripts/fetch-firecracker.sh"
  FAIL=1
fi

if [ -f "$REPO_ROOT/build/kernel/vmlinux" ]; then
  report "guest_kernel" "OK ($(readlink "$REPO_ROOT/build/kernel/vmlinux"))"
else
  report "guest_kernel" "FAIL: 缺失，运行 scripts/build-kernel.sh"
  FAIL=1
fi

# reflink 实测（不是看文件系统名，而是真做一次）：
#
# 创建热路径每次都要拷一份私有 rootfs，走的是 `cp --reflink=auto`（orch.rs cp_reflink）。
# **ext4 不支持 reflink，会静默回退成全量拷贝**——密度爬坡起 200~500 个实例就是 200~500 次
# 全量拷贝，create 的 copy 分段与整体 P50 会被显著抬高，而且**没有任何报错**，事后看数字
# 完全看不出来是文件系统的锅。故此处主动探一次。XFS（reflink=1，mkfs.xfs 现默认开）或 Btrfs 支持。
FS_TYPE="$(stat -f -c %T "$REPO_ROOT" 2>/dev/null || echo unknown)"
RL_DIR="$REPO_ROOT/build/.reflink-probe"
mkdir -p "$RL_DIR" 2>/dev/null || true
if printf 'x' > "$RL_DIR/a" 2>/dev/null && cp --reflink=always "$RL_DIR/a" "$RL_DIR/b" 2>/dev/null; then
  report "reflink" "OK（fs=${FS_TYPE}，create 走 CoW 秒拷）"
else
  report "reflink" "WARN: fs=$FS_TYPE 不支持 reflink → 每次 create 全量拷 rootfs，创建分位会被抬高"
  echo "  └ 取 SLO 取证时请把工作目录放到 XFS(reflink=1) 或 Btrfs 上；ext4 不支持 reflink。" >&2
fi
rm -rf "$RL_DIR" 2>/dev/null || true

if [ "$FAIL" -ne 0 ]; then
  echo "环境检查未通过" >&2
  exit 1
fi
echo "环境检查通过"
