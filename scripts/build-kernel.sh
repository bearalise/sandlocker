#!/usr/bin/env bash
# build-kernel.sh — 构建 SandLocker 自带精简 guest 内核（PRD 14.1 决策 2）
#
# 用法: scripts/build-kernel.sh [内核主版本，默认 6.6]
# 产物: build/kernel/vmlinux-<version>、build/kernel/vmlinux（软链）、.sha256、build-info.txt
#
# 设计要点：
# - 基线配置用 Firecracker 官方 guest config（6.1），经 olddefconfig 适配目标版本
# - scripts/kernel-fragment.config 叠加 SandLocker 必需项（vmgenid/vsock/dm-thin 等）
# - 构建依赖（flex/bison/m4）优先用系统安装，缺失时回退到仓库内 .toolchain（见 docs/）
set -euo pipefail

MAJOR="${1:-6.6}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/kernel"
FC_CONFIG_URL="https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config"
FRAGMENT="$REPO_ROOT/scripts/kernel-fragment.config"

mkdir -p "$BUILD_DIR"

# --- 硬依赖预检：缺 make/gcc 无 .toolchain 回退，提前失败给出明确指引 ---
for tool in make gcc ld objcopy bc; do
  command -v "$tool" >/dev/null || {
    echo "[build-kernel] 错误: 缺少 $tool（安装: sudo apt-get install -y build-essential bc）" >&2
    exit 1
  }
done

# --- openssl 头预检：FC 基线开了模块签名/可信密钥环，certs/extract-cert 需要 libssl-dev ---
if ! echo '#include <openssl/bio.h>' | gcc -E - >/dev/null 2>&1; then
  echo "[build-kernel] 错误: 缺少 openssl 开发头（安装: sudo apt-get install -y libssl-dev）" >&2
  exit 1
fi

# --- 构建依赖回退：系统缺失时使用仓库内 .toolchain ---
if ! command -v flex >/dev/null || ! command -v bison >/dev/null || ! command -v m4 >/dev/null; then
  TC="$REPO_ROOT/.toolchain/usr"
  if [ -x "$TC/bin/flex" ]; then
    export PATH="$TC/bin:$PATH"
    export M4="$TC/bin/m4"
    export BISON_PKGDATADIR="$TC/share/bison"
    echo "[build-kernel] 使用 .toolchain 本地构建工具"
  else
    echo "[build-kernel] 错误: 缺少 flex/bison/m4，且 .toolchain 不存在" >&2
    exit 1
  fi
fi

# objtool 需要 libelf 头文件；系统无 libelf-dev 时回退 .toolchain
TC_LIBS="$REPO_ROOT/.toolchain/usr"
if [ ! -f /usr/include/gelf.h ] && [ -f "$TC_LIBS/include/gelf.h" ]; then
  export HOSTCFLAGS="${HOSTCFLAGS:-} -I$TC_LIBS/include"
  export HOSTLDFLAGS="${HOSTLDFLAGS:-} -L$TC_LIBS/lib/x86_64-linux-gnu"
  export LD_LIBRARY_PATH="$TC_LIBS/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  echo "[build-kernel] libelf 使用 .toolchain（HOSTCFLAGS/HOSTLDFLAGS 已注入）"
fi

# --- 解析目标主版本的最新补丁版本 ---
echo "[build-kernel] 查询 kernel.org 上 6.x 最新 ${MAJOR}.y ..."
VERSION="$(curl -fsSL --connect-timeout 20 --max-time 60 --retry 3 --retry-delay 2 https://cdn.kernel.org/pub/linux/kernel/v6.x/ \
  | grep -oE "linux-${MAJOR}\.[0-9]+(\.[0-9]+)?\.tar\.xz" \
  | sed -E "s/linux-(.*)\.tar\.xz/\1/" \
  | sort -t. -k2,2n -k3,3n | tail -1)"
[ -n "$VERSION" ] || { echo "[build-kernel] 错误: 未找到 ${MAJOR}.y 版本" >&2; exit 1; }
echo "[build-kernel] 目标版本: ${VERSION}"

TARBALL="linux-${VERSION}.tar.xz"
SRC_DIR="$BUILD_DIR/linux-${VERSION}"

# --- 下载（带缓存） ---
if [ ! -f "$BUILD_DIR/$TARBALL" ]; then
  echo "[build-kernel] 下载 $TARBALL ..."
  curl -fSL --connect-timeout 20 --retry 3 --retry-delay 2 -o "$BUILD_DIR/$TARBALL" "https://cdn.kernel.org/pub/linux/kernel/v6.x/$TARBALL"
fi

# --- 解压 ---
if [ ! -d "$SRC_DIR" ]; then
  echo "[build-kernel] 解压 ..."
  tar -xJf "$BUILD_DIR/$TARBALL" -C "$BUILD_DIR"
fi

# --- 配置：FC 基线 + SandLocker fragment ---
if [ ! -f "$BUILD_DIR/fc-baseline.config" ]; then
  echo "[build-kernel] 获取 Firecracker 基线配置 ..."
  curl -fSL --connect-timeout 20 --max-time 60 --retry 3 --retry-delay 2 -o "$BUILD_DIR/fc-baseline.config" "$FC_CONFIG_URL"
fi
cp "$BUILD_DIR/fc-baseline.config" "$SRC_DIR/.config"
make -C "$SRC_DIR" olddefconfig
# shellcheck disable=SC2086
"$SRC_DIR/scripts/kconfig/merge_config.sh" -m -O "$SRC_DIR" "$SRC_DIR/.config" "$FRAGMENT"
make -C "$SRC_DIR" olddefconfig

# --- 验证 fragment 逐项生效（静默丢弃即失败；教训：CONFIG_MD 前置缺失曾导致 dm-thin 被丢） ---
MISSING=0
while IFS= read -r key; do
  if ! grep -q "^${key}=y" "$SRC_DIR/.config"; then
    echo "[build-kernel] 错误: fragment 配置未生效: ${key}" >&2
    MISSING=1
  fi
done < <(grep -oE '^CONFIG_[A-Z0-9_]+' "$FRAGMENT")
[ "$MISSING" -eq 0 ] || exit 1
echo "[build-kernel] fragment 配置全部生效"
echo "[build-kernel] 开始构建（-$(nproc)）..."
# Firecracker（截至 v1.16.1）在 x86_64 上仅接受未压缩 ELF vmlinux；bzImage 支持尚未发布
# （CHANGELOG PR #6037 仍在 [Unreleased]）。构建 vmlinux 目标而非 bzImage，否则 boot 静默失败。
make -C "$SRC_DIR" -j"$(nproc)" vmlinux

# --- 产出 ---
OUT="$BUILD_DIR/vmlinux-${VERSION}"
cp "$SRC_DIR/vmlinux" "$OUT"

# --- 断言产物为未压缩 ELF（防止误改回 bzImage 后 FC 静默启不动）---
if [ "$(head -c4 "$OUT" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
  echo "[build-kernel] 错误: 产物不是未压缩 ELF vmlinux（FC v1.16.1 无法引导 bzImage）" >&2
  exit 1
fi
echo "[build-kernel] 产物已确认为未压缩 ELF vmlinux"
ln -sf "vmlinux-${VERSION}" "$BUILD_DIR/vmlinux"
sha256sum "$OUT" > "$OUT.sha256"
{
  echo "version=$VERSION"
  echo "built_at=$(date -u +%FT%TZ)"
  echo "baseline=firecracker microvm-kernel-ci-x86_64-6.1.config"
  echo "fragment=scripts/kernel-fragment.config"
  echo "gcc=$(gcc -dumpversion)"
} > "$BUILD_DIR/build-info.txt"

echo "[build-kernel] 完成: $OUT ($(du -h "$OUT" | cut -f1))"
