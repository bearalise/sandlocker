# Contributing to SandLocker

Thanks for your interest in contributing! This guide covers how to build, test, and open a pull
request. By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

For security vulnerabilities, **do not open a public issue** — follow [SECURITY.md](SECURITY.md).

## Project layout

SandLocker is a Rust workspace plus client SDKs. Key crates and directories:

- `crates/sl-node` — host node (Firecracker control, snapshot engine, storage, networking, template
  build, REST daemon).
- `crates/sl-envd` — guest agent (PID 1, static musl).
- `crates/sl-proto`, `crates/sl-store` — vsock protocol / metadata store.
- `crates/sandlocker` — user-facing CLI.
- `sdk/python`, `sdk/typescript` — client SDKs.
- `contracts/` — `openapi.yaml` + `sandlocker.proto`, the API source of truth.

The original design history (milestone plans, exit reviews, PRD, ADRs) lives under `docs/design/`
(kept in Chinese as historical record).

## Prerequisites

- Linux with `/dev/kvm` writable (for anything that boots a microVM).
- A recent stable Rust toolchain, plus the `x86_64-unknown-linux-musl` target for `sl-envd`.
- For SDK work: Python 3.8+ (Python SDK) and Node.js ≥ 20 (TypeScript SDK).
- One-time setup for VM-based work:

```bash
scripts/fetch-firecracker.sh    # firecracker + jailer binaries
scripts/build-kernel.sh         # guest kernel
scripts/build-rootfs.sh         # base rootfs (needs sl-envd built first)
```

## Build & test

```bash
# Rust
cargo build --workspace
cargo test -p sl-node -p sl-proto -p sl-store -p sandlocker

# Python SDK (no KVM needed — in-process fake daemon + contract check)
python3 -m unittest discover -s sdk/python/tests

# TypeScript SDK (no KVM needed)
npm --prefix sdk/typescript ci && npm --prefix sdk/typescript test
```

Many integration checks need root and/or KVM and are gated accordingly (they skip cleanly when the
environment is missing). Representative end-to-end scripts, each emitting a single-line JSON verdict:

- `scripts/verify-api-e2e.sh` — REST + CLI end-to-end.
- `scripts/verify-sdk-e2e.sh` / `scripts/verify-sdk-ts-e2e.sh` — SDK scenarios (US-1/4/7).
- `scripts/verify-oci-e2e.sh` — OCI image as rootfs.
- `scripts/verify-build-egress.sh` — build-time network (needs root).

CI (`.github/workflows/bench.yml`) runs the no-KVM checks on every PR and the KVM-gated ones on
hosted runners where `/dev/kvm` is available.

## Pull requests

1. Branch from `main` (e.g. `feat/…`, `fix/…`, `docs/…`, `chore/…`).
2. Keep changes focused; update or add tests. Match the style and comment density of the surrounding
   code.
3. If you change the REST API, keep the three contract points in sync:
   `contracts/openapi.yaml` ↔ each SDK's `ROUTES` ↔ the SDK contract test.
4. Ensure `cargo build --workspace` is warning-free and the relevant tests pass.
5. Open the PR against `main` with a clear description of what changed and how you verified it.

## Commit messages

Use conventional prefixes where they fit: `feat(scope): …`, `fix(scope): …`, `docs: …`,
`chore: …`, `refactor: …`, `test: …`. Explain the *why* in the body when it isn't obvious.
