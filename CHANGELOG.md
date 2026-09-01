# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/). During the v0.x series the public API may still change.

## [Unreleased]

Milestone **M3 Beta in progress** — clustering + multi-tenancy on top of the M2 single-machine base.
The narrow `Store` trait (already MVCC-shaped in M1) gains an etcd implementation, so the daemon runs
either single-machine (SQLite, zero regression) or clustered (`--serve --etcd`, multi-replica
active-standby). W1–W9 delivered: etcd store, leader election, node heartbeat + dead-node reclaim,
multi-node convergence, API-Key/scope/project multi-tenancy, per-project quota + append-only audit
(M3-Q4 met), and Prometheus metrics + log sink + a read-only Grafana dashboard (M3-Q5/Q12). The
data-plane gateway is now a **separate `sandlocker-gw` process** fed by node-initiated outbound
streams over mTLS, so cross-node exec/logs/files/ports/streaming work with **zero inbound ports on
nodes** (M3-Q3 met). Paused snapshots are sealed at rest under a KMS → tenant KEK → per-snapshot DEK
envelope with 4 MiB chunked AES-256-GCM (M3-Q6 met, one of the four debts M2 handed over). Each week ships a backend-agnostic `--*-reconcile` verified against real etcd.
See the plan: `docs/design/M3技术计划.md`.

Milestone **M2 complete** — both hard exits met (pool-hit P50: warm ≈70 ms / hot ≈48 ms ≤100 ms;
two switchable backends: Firecracker + gVisor pass one ABI contract suite). M2-Q1–Q9 and Q12 have
per-question conclusions; M2-Q10 (bare-metal density) is method-ready but **pending a self-hosted
runner**; M2-Q11 (snapshot encryption) is **deferred to M3** per the plan's cut-list. See the exit
review: `docs/design/M2出口评审.md`.

### Added

#### M3 Beta (clustering + multi-tenancy)
- **SDK API-Key auth + typed errors (TS 0.5.0 / Python 0.2.0)** — both SDKs now send an API key as
  `Authorization: Bearer <key>` on every request, so they work against a multi-tenant daemon
  (`--serve --require-auth`). Pass it via the client constructor / factory (`apiKey` / `api_key`) or
  the `SANDLOCKER_API_KEY` env var. HTTP 401/403/429 map to typed errors (`Unauthorized` / `Forbidden`
  / `QuotaExceeded`, all `ApiError` subclasses), and a new `audit()` method reads `GET /v1/audit`
  (project-filtered). openapi.yaml, `ROUTES`, and the contract tests are kept in sync.
- **Snapshot envelope encryption (ADR-15, M3-Q6, W9)** — paused snapshots are now sealed at rest
  under a three-level envelope: a KMS root key wraps a per-project **tenant KEK**, which wraps a
  fresh **per-snapshot DEK**, which encrypts `vmstate` and `mem` as AES-256-GCM in **4 MiB chunks**.
  Enable it with `--snap-kms-key <file>` (`--snap-kms-init` mints a 0600 root key and refuses to
  overwrite an existing one). Off by default: encryption changes the on-disk snapshot format, so
  when to switch is the operator's call. **Recommended on by default at GA.**
  - Firecracker writes and `mmap`s its own snapshot files and has no hook for a custom storage
    layer, so encryption wraps *around* it: `pause` seals `vmstate|mem` into `.enc` and shreds the
    plaintext; `resume`/`fork` unseal before handing the files to Firecracker. **What this protects
    is the paused snapshot — the state that outlives the node.** A running instance's `mem` is
    necessarily plaintext (Firecracker mmaps it for the VM's lifetime), which is no extra exposure
    since that memory is in host RAM anyway. Decrypting onto tmpfs would make plaintext never touch
    disk but costs a second copy of RAM per instance, which would sink the density exit (M3-Q9).
  - The node **never persists a plaintext DEK or KEK**: the DEK lives wrapped in the snapshot
    header, the KEK lives wrapped in the control plane at `kek/<project>` (established by CAS on
    first use), and in-memory keys are zeroed on drop.
  - The `SLSNAP1` header is plaintext but **every header field is bound into each chunk's AAD**, so
    altering one byte of it fails the whole chunk. Chunk *i* starts at a computed offset, so the
    format **supports random reads** — the groundwork for userfaultfd lazy loading (P2) without a
    format change, which is why ADR-15 chose chunked AEAD over whole-file AEAD.
  - New `Request::WipeKeys`: the host sends it **before** `PATCH /vm Paused` so sl-envd overwrites
    and unlinks the session key it issued. Lossless — `resume`/`fork` always run `Reinit`, which
    mints a fresh one. This wipes only sl-envd's *own* key material; **pause still captures whatever
    secrets live in guest memory** (PRD §8.2).
  - Sealing **fails closed**: if it cannot complete, the plaintext and any partial output are
    shredded and the VM is put back in the running state (the sandbox survives, the pause fails).
    Plaintext guest memory is never left on disk because sealing failed.
  - AEAD comes from **ring**, already in the tree via ureq → rustls, so this feature adds **zero new
    crates**.
  - `--snapcrypt-reconcile [--etcd]` drives the same `seal_snapshot`/`unseal_snapshot` and tenant-KEK
    paths `pause`/`resume` use, asserting: plaintext gone after sealing and recoverable, no plaintext
    needle in the ciphertext, no plaintext KEK in the control plane, no plaintext DEK in the snapshot
    file, one flipped byte refused with no partial plaintext left behind, project A's snapshot
    unopenable with project B's key, repeated KEK unwraps agreeing, a different root key failing, and
    a single random-access chunk matching the full decrypt. SQLite and real etcd both pass, alongside
    9 crypto unit tests.
  - Outstanding: end-to-end (real Firecracker pause → sealed on disk → resume) needs KVM and is
    covered on KVM hosts; the **Vault KMS plugin stays P1/GA**, so V1's file KMS keeps the root key on
    the node — it defends against a stolen disk, not against a compromised node; and overwrite-before-
    unlink is defence in depth, not a guarantee on CoW filesystems or SSDs.
- **Standalone data-plane gateway + node-initiated outbound streams + cluster mTLS (ADR-22 /
  FR-7.1, M3-Q3, W5 remainder)** — a new **`sandlocker-gw` binary** terminates client traffic and
  relays it to whichever node owns the sandbox, looked up live from etcd (`sandbox/<sid>/node`), so
  **any replica serves any sandbox with no session stickiness**. Connections always run
  **node → gateway**: each node pre-dials a pool of idle persistent connections (`--gw-pool`, default
  8) and parks them; the gateway borrows one, hands over the already-verified ticket, and the node
  serves it through **the same `serve_gw_ticket` path the in-process gateway uses** — ADR-22's
  "splitting changes no semantics", cashed. **Nodes still listen on no inbound port.**
  - The node refills the pool **the moment a stream opens**, not when it ends — otherwise long-lived
    streams (PTY) would pin the idle budget and `--gw-pool` sessions could wedge a node's data plane.
    Past `--gw-max-streams` (default 256) new streams are served inline, applying backpressure
    instead of spawning threads without bound.
  - Relaying is **full duplex** (PTY and NDJSON streaming exec need it). Since rustls' synchronous
    `StreamOwned` cannot be read and written from two threads, `dataplane::Duplex` implements duplex
    TLS directly: blocking socket reads happen *outside* the connection lock, and the write path
    takes the socket lock *before* releasing the connection lock so TLS records reach the wire in the
    order the state machine produced them.
  - **mTLS** on the node-facing port (`WebPkiClientVerifier`, client certs mandatory). rustls is
    pinned to `default-features = false` + **ring** — the provider ureq already uses — which keeps
    the default `aws-lc-rs` (cmake + a lot of C) out of the tree; **`rustls-pemfile` is the only new
    crate**. Plaintext is never a silent fallback: missing certs are an error unless `--gw-insecure`
    is passed explicitly.
  - Control-plane replicas forward `/v1/.../exec|logs|files` and `/v1/.../exec/stream` for
    non-local sandboxes through `--gw-url`, streaming the response back chunk by chunk.
  - `--gw-dataplane-reconcile [--etcd] [--gw-tls-*|--gw-insecure]` stands up a real gateway plus two
    real node agents and asserts: ownership routing, no stickiness, one-time tickets, tamper
    rejection, 404 for unknown sandboxes, bounded 503 when the owning node is absent, chunk-by-chunk
    delivery (proving the relay is not buffering), and that a plaintext peer cannot join an mTLS
    port. `scripts/verify-gw-dataplane.sh` adds an openssl live check that a client without a
    certificate is refused while a valid one succeeds. Plaintext and mTLS × SQLite and real etcd all
    pass.
  - Still missing (stated plainly): **control-plane** routes (pause/resume/fork/destroy/keepalive/
    expose) against a sandbox on another node — a gap left by W4's multi-node scheduling, not the
    data plane.
- **Observability: Prometheus metrics + log sink + read-only dashboard (§7.8, M3-Q5/Q12, W8)** —
  `GET /metrics` (unauthenticated) exposes create-latency histograms, pool hits, exec latency, live
  sandbox count and API request/error counters in the Prometheus text format, hand-written with
  **no dependencies**; quantiles are computed by `histogram_quantile()` on the Prometheus side.
  `--log-sink <url>` forwards structured lifecycle events (create events carry a segment-by-segment
  timing breakdown). `dashboards/sandlocker.json` is a curated Grafana dashboard with **no bespoke
  front-end**. A full OTLP tracing exporter is still outstanding.
- **Per-project quota + append-only audit (FR-7.2/7.3, M3-Q4, W7)** — per-project limits
  (`quota/<project>`: max sandboxes / vcpus / mem, 0 = unlimited); usage is computed **live** from
  the project's current sandbox metas (crash-safe, no drifting counters). `create` / `fork` pre-flight
  a quota check — over any limit → `QUOTA_EXCEEDED` mapped to **HTTP 429**, before the VM is built.
  A backend-agnostic **append-only audit log** (`audit/<ts>-<seq>`, put-only) records every
  Write/Build request under `--require-auth`; `GET /v1/audit` lists entries filtered by the caller's
  project. `--quota-set` / `--quota-reconcile [--etcd]`.
- **Multi-tenant API Key + scopes + project isolation (FR-7.1, M3-Q4, W6)** — `org → project → Key`
  with three scopes (readonly / readwrite / build). The store holds only `apikey/<sha256(token)>` →
  record, so leaking the store does not leak usable tokens. `--serve --require-auth` gates every
  `/v1` request: authenticate (`Authorization: Bearer` / `X-API-Key`), authorize by scope, and
  project-guard sandbox routes (a sandbox carries its project; list is filtered, single-sandbox routes
  require ownership match). Default off = zero regression. `--apikey-create` / `--auth-reconcile`.
- **Splittable data-plane gateway (ADR-22, W5)** — the ticket HMAC secret converges via a store CAS
  (`cluster/gw_secret`) and the one-time nonce is consumed via store CAS, so **any gateway replica
  statelessly verifies any replica's ticket and one-time holds across replicas** — the M2-pinned
  interface is now split-ready with zero semantic change. Single-machine keeps the in-process
  secret/nonce. `--gw-cluster-reconcile [--etcd]`. (Node-agent outbound streams + cross-node data
  forwarding remain a follow-up.)
- **Multi-node daemon on etcd + active-standby (M3-Q1/Q2, W4)** — `--serve --etcd <ep>` backs the
  orchestrator, heartbeat, and election with etcd; multiple replicas share state, only the leader runs
  the reaper/reclaim, and a standby takes over on leader death (verified live with two daemons:
  election + failover + a shared sandbox view). `--cluster-reconcile [--etcd]`.
- **Node heartbeat + dead-node sandbox reclaim (M3-Q2, W3)** — volatile state via lease TTL: a node
  writes a lease-backed `node/<id>` liveness key; on crash the lease expires and the leader reclaims
  that node's sandboxes (a sandbox carries `sandbox/<id>/node`). Safety rail: a node **never** reclaims
  its own sandboxes. `--node-reclaim-reconcile [--etcd]`.
- **Leader election + cluster-init migration (M3-Q2, W2)** — backend-agnostic election over
  `compare_and_swap` + lease (`cluster/leader`); single-machine SQLite is always-leader (ADR-17, no
  election). `migrate_all` powers `--cluster-init --store <sqlite> --etcd <ep>` (one-time downtime
  migration). `--election-reconcile [--etcd]`.
- **EtcdStore + store contract suite (M3-Q1, W1)** — an `EtcdStore` implements the same `Store` trait
  over etcd's gRPC-gateway HTTP/JSON API using synchronous `ureq` + rustls — **zero tokio/tonic**
  (`cluster` feature; single-machine builds pull none of it). A backend-agnostic contract
  (`contract::run_all`) runs against SqliteStore and EtcdStore, proving no dual semantics.
  `--store-contract [--etcd]`.

#### Post-M2 runtime features
- **Runtime network egress (`network:egress`)** — a sandbox can cold-boot with a NIC into a
  per-instance netns (veth + tap + host NAT), so code inside can reach the network (`npm` / `pip
  install`) at runtime, not just at build time. `POST /v1/sandboxes {network:"egress"}`; FC + root,
  capability-gated. `sl-node --net-egress-reconcile`.
- **Port exposure L4 passthrough** — external clients reach a dynamic service inside the VM (e.g. a
  Next.js dev server) through a stable address via raw L4 splice over vsock, beyond the simple HTTP/1.0
  reverse proxy. `POST /v1/sandboxes/{id}/expose`; `sl-node --expose-reconcile`.
- **Streaming exec** — `run(cmd, {onStdout, onStderr})` streams output chunk-by-chunk (NDJSON, stdout
  / stderr separated, exit code propagated) instead of buffering. `sl-node --exec-stream-reconcile`.
- **`Sandbox.connect`** — attach to an existing sandbox by id (TS + Python SDKs).

#### M2 Alpha
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
