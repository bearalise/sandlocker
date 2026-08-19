# 发布指南（Releasing）

SandLocker 的版本化产物、SBOM 与签名流程。目标（PRD 8.2 供应链）：**可复核、可验签、
带物料清单**的发布产物。

## 版本

- 单一版本源：`Cargo.toml` 的 `[workspace.package] version`（5 个 crate 全部继承）。
- Python SDK 版本：`sdk/python/pyproject.toml`，与工作区对齐（当前 0.1.0）。
- 变更记录：`CHANGELOG.md`（Keep a Changelog 风格）。

## 产物

`scripts/release.sh` 组装 `dist/`：

| 产物 | 说明 |
|---|---|
| `sl-node` | host 面：FC 后端 / 编排 / REST 守护（`target/release`） |
| `sandlocker` | 用户面 CLI（`target/release`） |
| `sl-envd` | guest PID1，musl 静态（`target/x86_64-unknown-linux-musl/release`） |
| `SHA256SUMS` | 全产物校验和 |
| `sbom.cdx.json` | CycloneDX SBOM（本地 cargo-cyclonedx / CI syft） |
| `*.sig` / `*.pem` | cosign keyless 签名与证书（**仅 CI 产出**） |

## 发布步骤

1. 更新 `CHANGELOG.md`（把 Unreleased 收敛到新版本号 + 日期）与版本号（`Cargo.toml` /
   `sdk/python/pyproject.toml`），合并入 `main`。
2. 本地自检产物（无需 root/网络/secrets）：
   ```bash
   scripts/release.sh            # 构建 + SHA256SUMS（+ 若装 cargo-cyclonedx 则本地 SBOM）
   ( cd dist && sha256sum -c SHA256SUMS )
   ```
3. 打 tag 触发 CI 发布：
   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```
   `.github/workflows/release.yml` 会：构建产物 → syft 生成 SBOM → **cosign keyless 签名**
   （GitHub OIDC，无需存储私钥）→ 建 GitHub Release 并附全部产物。

## 验签（下游用户）

```bash
# 1) 校验完整性
sha256sum -c SHA256SUMS

# 2) 验证 cosign keyless 签名（证书身份绑定本仓库 release workflow）
cosign verify-blob SHA256SUMS \
  --signature SHA256SUMS.sig \
  --certificate SHA256SUMS.pem \
  --certificate-identity-regexp 'https://github.com/Richardo1o1/sandlocker/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 边界与状态（诚实标注）

- **签名与 GitHub Release 步依赖 CI 的 tag + OIDC，未在本开发环境端到端验证**（无 tag 推送、
  无 Actions OIDC/secrets）。本地已验证的部分：产物构建、`SHA256SUMS` 生成、workflow 语法。
  首个真实 v0.1.0 发布须在 CI 跑通后，按上节验签确认。
- 与**模板签名**（`crates/sl-node/src/build.rs` 的 ed25519 模板入库签名）是不同关注点：
  前者护发布产物供应链，后者护模板产物内容寻址与来源。
