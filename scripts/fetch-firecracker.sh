#!/usr/bin/env bash
# fetch-firecracker.sh — 获取指定版本 Firecracker 二进制（firecracker + jailer）
#
# 用法: scripts/fetch-firecracker.sh [版本，默认 latest]
# 产物: build/firecracker/firecracker、build/firecracker/jailer
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/build/firecracker"
mkdir -p "$OUT_DIR"

VERSION="${1:-latest}"
if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest \
    | grep -oE '"tag_name": *"[^"]+"' | cut -d'"' -f4)"
fi
echo "[fetch-fc] 版本: $VERSION"

ARCHIVE="firecracker-${VERSION}-x86_64.tgz"
URL="https://github.com/firecracker-microvm/firecracker/releases/download/${VERSION}/${ARCHIVE}"

if [ ! -f "$OUT_DIR/$ARCHIVE" ]; then
  echo "[fetch-fc] 下载 $URL ..."
  curl -fSL -o "$OUT_DIR/$ARCHIVE" "$URL"
fi
tar -xzf "$OUT_DIR/$ARCHIVE" -C "$OUT_DIR" --strip-components=1 \
  --wildcards "*/firecracker-${VERSION}-x86_64" "*/jailer-${VERSION}-x86_64"
mv "$OUT_DIR/firecracker-${VERSION}-x86_64" "$OUT_DIR/firecracker"
mv "$OUT_DIR/jailer-${VERSION}-x86_64" "$OUT_DIR/jailer"
chmod +x "$OUT_DIR/firecracker" "$OUT_DIR/jailer"

"$OUT_DIR/firecracker" --version
echo "[fetch-fc] 完成: $OUT_DIR/"
