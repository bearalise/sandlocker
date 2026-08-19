# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/). During the v0.x series the public API may still change.

## [Unreleased]

Milestone M2 (in progress).

### Added
- **OCI images as rootfs sources** — `from = "docker://<ref>"` or `docker-archive:`/`oci-archive:`
  tarballs are pulled (hand-written registry v2 over `ureq` + rustls), digest-verified, layer
  flattened (whiteout/opaque), and baked to ext4; image `Env`/`WorkingDir`/`Cmd` materialize as
  template defaults. `sl-node --oci-pull` for standalone forensics. Registry pulls honor
  `HTTPS_PROXY` / `ALL_PROXY`.
- **Build-time network egress** — `build_network = "allow-all"` gives the build sandbox real egress
  (named netns + veth + tap + host NAT), so `pip install` / `npm install` install dependencies into
  the template. Root required; `deny` remains the default and stays rootless.
- **Live network gating & keepalive** — real forward-hook egress policy applied before resume
  (deny-by-default + allowlist on real traffic); keepalive renewal endpoint.
- **TypeScript SDK** — hand-written, zero runtime dependency (`node:http`), dual ESM/CJS,
  contract-tested against `contracts/openapi.yaml`, mirroring the Python SDK.

## [0.1.0] — 2026-08-07

Milestone M1 complete: the minimal end-to-end loop of a Firecracker microVM secure code-execution
sandbox (US-1 / US-4 / US-7 usable; create via snapshot restore, P50 ≤ 500 ms).

### Added
- **Snapshot-restore engine (W1–W2)** — Firecracker API boot + jailer +
  `snapshot/load {resume_vm:false}` → policy hook → resume; `sl-node --snap-create` / `--snap-load`.
- **dm-thin CoW storage (W3)** — base origin + per-sandbox thin snapshot; writes don't pollute the
  base; destroy frees exclusive blocks with no orphans (`--dmthin-reconcile`).
- **Clone isolation (W4)** — post-restore reinit (rotates machine-id / RNG / session key) + policy
  applied before resume; clone-entropy regression (`--clone-entropy-check`).
- **nftables network backend (W5)** — per-sandbox table, default drop + IP/port allowlist
  (`--nftfw-reconcile`).
- **Template build (W6)** — template DSL + build-as-sandbox + pre-baked snapshot + content
  addressing + ed25519 template signing; `sl-node --build`.
- **In-process orchestration (W7)** — full lifecycle (create via restore / keepalive / idle expiry /
  TTL hard cap / destroy) with rootless mount-ns private rootfs; create latency P50 ≤ 500 ms +
  zero-residue reclaim.
- **REST daemon + CLI (W8)** — `sl-node --serve` REST control plane (authoritative contract in
  `contracts/openapi.yaml`) + `sandlocker up/build/run/ps/exec/logs/snapshot`; contract-first + e2e.
- **Python SDK (W9)** — hand-written stdlib-only thin client + contract-drift tests + US-1/4/7
  scenario e2e.
- **Release & docs (W10)** — network timing probe in CI; v0.1 release pipeline (artifacts + SBOM +
  cosign keyless signing, see `docs/design/RELEASING.md`); mdBook docs site; M1 exit review
  (`docs/design/M1出口评审.md`).

### Security
- Post-restore reinit eliminates clone-state leakage; policy-before-resume closes the packet-send
  window.
- ed25519-signed template artifacts; SHA256 + cosign keyless signing for release artifacts.

[Unreleased]: https://github.com/Richardo1o1/sandlocker/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Richardo1o1/sandlocker/releases/tag/v0.1.0
