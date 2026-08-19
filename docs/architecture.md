# Architecture

SandLocker is a Rust workspace: a host-side node process, a tiny guest agent, a CLI, and client
SDKs, all speaking a contract-first REST/vsock API.

## Components

- **`sl-node`** (host) — the core. Drives Firecracker over its HTTP API (boot, snapshot
  create/load), manages dm-thin CoW storage, per-sandbox nftables networking (named netns + veth +
  NAT for live egress), builds templates (build-as-sandbox → pre-baked snapshot → content-addressed,
  ed25519-signed artifacts), resolves OCI images into ext4 rootfs bases, and serves the REST control
  plane (`sl-node --serve`) with an in-process orchestrator.
- **`sl-envd`** (guest) — a static musl binary running as PID 1. Mounts `/proc`/`/sys`/`/dev`/`/tmp`,
  reaps zombies, and serves an exec channel over vsock. It applies the image environment
  (`/etc/sl-envd/env`) to executed commands.
- **`sl-proto` / `sl-store`** — the vsock wire protocol and the SQLite metadata store.
- **`sandlocker`** (CLI) — the user-facing command (`up/build/run/ps/exec/logs/snapshot`).
- **SDKs** (`sdk/python`, `sdk/typescript`) — thin, hand-written, contract-tested clients.

## Create path (snapshot restore)

Creating a sandbox is a snapshot **restore**, not a cold boot — that's how create stays in the
hundreds-of-milliseconds range:

1. A template is pre-baked once (`sl-node --build`): boot a build sandbox, run the template's `RUN`
   steps, then snapshot at the pre-bake point. The result is content-addressed and signed.
2. On create, the orchestrator restores the snapshot with `snapshot/load {resume_vm:false}` (loaded
   but paused), applies the network policy **before** resume (ADR-13: no packet-send window), then
   resumes. Post-restore reinit rotates identity/entropy so clones never share `machine-id`, RNG
   seed, or session key (ADR-12).

## Contract-first API

`contracts/openapi.yaml` (plus `sandlocker.proto`) is the source of truth. The daemon
(`crates/sl-node/src/api.rs`) is a hand-written HTTP/1.1 server (`Content-Length` + `Connection:
close`, local loopback, no TLS/auth in M1). Each SDK carries a `ROUTES` set that is asserted equal
to a hand-copied subset of the contract in its tests — a drift guard that replaces codegen. Changing
the API means updating three places in lockstep: the OpenAPI spec, each SDK's `ROUTES`, and the SDK
contract test.

## OCI images as rootfs sources (M2)

`from = "docker://<ref>"` or a `docker-archive:`/`oci-archive:` tarball is pulled with a hand-written
registry v2 client (`ureq` + rustls, honoring `HTTPS_PROXY`), digest-verified, layer-flattened
(whiteout/opaque semantics), and baked to ext4 with `sl-envd` installed and `machine-id` cleared.
Image `Env`/`WorkingDir`/`Cmd` materialize as template defaults. Results are cached by source digest
(the cache key also includes the `sl-envd` hash, so changing the guest agent invalidates the cache).

## Build-time network (M2)

By default the build sandbox is fully offline (`build_network = "deny"`). With
`build_network = "allow-all"` (root required), the build boots into a named netns with veth + tap +
host NAT so `RUN` steps have real egress — enough for `pip install` / `npm install`. The guest is
configured via the kernel `ip=` autoconfig (no in-guest tooling required), which works for minimal
images that lack `iproute2`.

## Design history

The detailed design record — milestone plans, exit reviews, the PRD, and ADRs — lives under
[`docs/design/`](design/) (kept in Chinese as historical record).
