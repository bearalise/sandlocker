# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/). During the v0.x series the public API may still change.

## [Unreleased]

Milestone M2 (in progress).

### Added
- **Interactive PTY + SDK M2 endpoints (M2-Q7)** — a new `sl-proto` `Pty{cols,rows}` frame makes
  `sl-envd` `forkpty` an interactive `/bin/sh` (guest now mounts `devpts`); after the `Ok` ack the
  vsock connection carries **framed input** (`pty_stdin_frame` / `pty_resize_frame` — stdin vs
  `TIOCSWINSZ` resize) and **raw PTY output**, so a client gets a bidirectional terminal with live
  window resize. `sl-node --pty-reconcile` validates M2-Q7 (echo round-trip + `stty size` reflects a
  resize + clean teardown + zero residue; CI `pty` job). The **TypeScript and Python SDKs** gain the
  M2 endpoints — `pause` / `resume` / `fork` / `ticket` / `listBackends` — with `ROUTES` and
  contract-drift tests kept in sync with `contracts/openapi.yaml`.
- **Data-plane gateway + one-time HMAC signed URLs + port exposure (ADR-22, FR-3.3, M2-Q6)** — a
  separate in-process gateway listener (`--gw-addr`, default `127.0.0.1:7879`) serves the data plane
  behind **one-time HMAC-SHA256 signed URLs** (hand-rolled HMAC over `sha2`, no new dep). The control
  plane mints tickets via `POST /v1/sandboxes/{id}/ticket {action, port?, ttl?}`; the gateway verifies
  the signature **statelessly** + checks expiry + consumes the nonce once (`/gw/exec`, `/gw/file`,
  `/gw/logs`, `/gw/p`). **Port exposure** (`/gw/p`): a new `sl-proto` `Connect{port}` frame makes
  `sl-envd` dial `127.0.0.1:port` in the guest and bidirectionally splice over vsock (guest brings
  `lo` up), and the gateway HTTP-reverse-proxies to it — so an external client reaches a service
  **inside** the VM through a signed URL, even though sandboxes are vsock-only (no eth0). `sl-node
  --gw-reconcile` validates M2-Q6 end-to-end (CI `gateway` job). Tampered / expired / reused tickets
  are rejected (403).
- **pause / resume / fork user API (FR-1.4, M2-Q5)** — `POST /v1/sandboxes/{id}/pause` snapshots the
  running VM to disk and stops it (`state: paused`, no exec while paused); `/resume` restores it; and
  `/fork` derives a new sandbox from a paused parent's snapshot. Added to the `SandboxBackend` ABI
  (capability-gated: `pause_resume` / `snapshot_fork` — gVisor lacks both → create-time
  `UNSUPPORTED_BY_BACKEND`). Every resume and fork re-runs ADR-12 reinit, so a paused sandbox and all
  its forks get **distinct** machine-id / RNG seed / session key — clone-entropy is preserved across
  fork/resume, not just fresh restore (fork reuses the parent rootfs/snapshot, so it does **not**
  refresh the security boundary). `sl-node --q5-reconcile` validates M2-Q5 end-to-end (CI
  `pause-resume` job).
- **ABI contract suite & two-backend switchable acceptance (ADR-14, M2 hard exit ②)** —
  `sl-node --abi-contract <template>` runs one common scenario set (lifecycle / exec / fs /
  clone-isolation / destroy-clean) against **both** backends through the ABI, plus a capability
  matrix over every `Capability`: a backend that has a capability must accept a
  `required_capabilities` create for it (`has`); one that lacks it must reject at create time
  (`unsupported-ok`) — anything else is a `GATE-FAIL` (silent runtime degradation). Emits the
  official compatibility matrix (`docs/design/后端兼容矩阵.md`); passes only when both backends
  clear the common scenarios and the capability matrix has no GATE-FAIL (`both_backends` +
  `switchable`). CI `abi-contract` job runs it with fc (KVM) + gVisor (runsc).
- **gVisor (runsc) second backend (ADR-14 / M2-Q4)** — a `GvisorBackend` implements the same
  `SandboxBackend` ABI: rootless `runsc run --detach` + `runsc exec` + `kill`/`delete`
  (`--rootless --platform=systrap --network=none`, no root/KVM); the OCI bundle rootfs is extracted
  from the template's `rootfs.ext4` via `debugfs rdump` (no root), cached per template + reflink-copied
  per instance. `Orch` now holds a **multi-backend registry** and picks a backend per create
  (`backend` field, default `fc`); each instance routes destroy/exec/logs to its owning backend. The
  data path is abstracted behind `ExecTarget` (FC = vsock+sl-envd, gVisor = `runsc exec`), so
  `exec`/file-put/file-get/logs work over either backend. gVisor's capability set is **empty**
  (no prebake/pause/fork) — pools are capability-gated off, matching its short-task role. Same API,
  two isolation kernels (gVisor Sentry vs Firecracker microVM). `sl-node --gvisor-reconcile` validates
  M2-Q4 rootless end-to-end; `--serve --gvisor` registers it.
- **Sandbox ABI + capability model (ADR-14)** — the Firecracker mechanism (restore, warm/hot pools,
  vsock endpoint, instance lifecycle) is refactored behind a `SandboxBackend` trait; `Orch` now holds
  a `Box<dyn SandboxBackend>` and keeps only orchestration (store / lease / TTL / tick). Backends
  register a capability bitset (`pause_resume` / `snapshot_fork` / `prebake_snapshot` /
  `gpu_passthrough` / `persistent_volume`); the FC backend registers the first three. A create can
  declare `required_capabilities` — unmet capabilities are rejected at **create time** with
  `UNSUPPORTED_BY_BACKEND` (no runtime silent degradation). Pools are capability-gated (a backend
  without `prebake_snapshot` / `pause_resume` gets cold create only). New `GET /v1/backends` lists
  backends and their capabilities. This is the abstraction step for the second backend (gVisor, W7).
- **Hot pool (热池)** — `restore_core` is split into `restore_park` (spawn Firecracker + load snapshot
  to a **paused** VM) and `restore_activate` (policy → resume → reinit → validate); a background
  thread pre-parks paused VMs so a pool-hit `create` only activates (resume + reinit), moving FC spawn
  + snapshot load off the critical path too. `--serve --pool-template <name> --hot-size <N>`
  (default 0 — parked VMs stay memory-resident; hot-hit takes priority over the warm pool). Reinit
  runs at activate, so two hot-hit sandboxes still get distinct machine-id / RNG / session key
  (clone-entropy preserved — asserted by the `--orch-reconcile` hot case). `--pool-bench` now also
  reports `hot_p50` (hot-hit only-activate latency; <50 ms target informational on bare metal).
- **Warm pool (温池)** — a background refill thread pre-stages instance dirs (rootfs reflink copy +
  vmstate/mem hardlink) off the create critical path and warms the snapshot page cache
  (`posix_fadvise`); pool-hit `create` skips the copy (`copy_ms=0`) and restores from warm cache.
  `--serve --pool-template <name> --pool-size <N>` (default 2, 0 disables); `--pool-bench` reports
  cold-vs-warm tiers. On a hello template: warm P50 ≈70 ms vs cold ≈100 ms.
- **Pool-hit latency in CI (M2 hard exit ①)** — `scripts/bench/bench-pool.sh` lands the cold/warm
  pool-hit percentiles in the bench CI. `bench-light` (managed runner) gates regression only
  (warm P50 must not exceed cold P50); the absolute pool-hit **P50 ≤100 ms** target is hard-gated
  only on the bare-metal `bench-density` job (`POOL_P50_BUDGET_MS=100`), alongside the M2-Q10
  density target (`DENSITY_MIN=200`, ≥200 sandboxes at default spec). Real SLO numbers await a
  registered 64C/128G self-hosted runner (M2-Q10 pending bare-metal, per plan D4).
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
