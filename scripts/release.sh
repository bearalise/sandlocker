#!/usr/bin/env bash
# release.sh — 组装 v0.x 发布产物（本地可跑，无需 root/网络/secrets）。
#
# 产出 dist/：
#   sl-node, sandlocker          （host 面二进制，target/release）
#   sl-envd                      （guest PID1，musl 静态，target/x86_64-unknown-linux-musl/release）
#   SHA256SUMS                   （全产物校验和）
#   sbom.cdx.json                （CycloneDX SBOM，装了 cargo-cyclonedx 才生成；缺则 warn 跳过）
#
# 签名（cosign keyless）与 GitHub Release 由 .github/workflows/release.yml 在 tag 推送时
# 于 CI（OIDC）完成——本脚本只负责本地可验证的「构建 + 校验和 + SBOM」部分。
# 用法：scripts/release.sh [版本号]；版本号缺省取 Cargo.toml 的 workspace.version。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

VERSION="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}"
DIST="$REPO_ROOT/dist"
echo "[release] 组装 v$VERSION 产物 → $DIST"

# 干净的 dist（不用 rm -rf 整树，逐项清）
mkdir -p "$DIST"
find "$DIST" -mindepth 1 -maxdepth 1 -exec rm -f {} + 2>/dev/null || true

echo "[release] 构建 host 面（sl-node / sandlocker，release）..."
cargo build --release -p sl-node -p sandlocker

echo "[release] 构建 guest 面（sl-envd，musl 静态）..."
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
cargo build --release -p sl-envd --target x86_64-unknown-linux-musl

cp -f target/release/sl-node          "$DIST/sl-node"
cp -f target/release/sandlocker       "$DIST/sandlocker"
cp -f target/x86_64-unknown-linux-musl/release/sl-envd "$DIST/sl-envd"

echo "[release] 计算 SHA256SUMS ..."
( cd "$DIST" && sha256sum sl-node sandlocker sl-envd > SHA256SUMS )

# SBOM：优先 cargo-cyclonedx（Rust 原生），退化提示 CI 用 syft
if command -v cargo-cyclonedx >/dev/null 2>&1; then
  echo "[release] 生成 CycloneDX SBOM（cargo-cyclonedx）..."
  cargo cyclonedx --format json --override-filename sbom.cdx >/dev/null 2>&1 || \
    cargo cyclonedx -f json >/dev/null 2>&1 || true
  # cargo-cyclonedx 产物落各 crate 目录，聚合工作区级到 dist（取根 bom）
  found="$(find . -maxdepth 2 -name 'sbom.cdx.json' -o -maxdepth 2 -name 'bom.json' 2>/dev/null | head -1 || true)"
  if [ -n "$found" ]; then cp -f "$found" "$DIST/sbom.cdx.json"; fi
fi
if [ ! -f "$DIST/sbom.cdx.json" ]; then
  echo "[release] ::warning:: 未装 cargo-cyclonedx，跳过本地 SBOM（CI 用 syft 生成，见 release.yml）" >&2
fi

echo "[release] 完成。产物："
ls -la "$DIST"
echo "[release] 校验：( cd dist && sha256sum -c SHA256SUMS )"
