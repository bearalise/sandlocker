# SandLocker

A secure code-execution sandbox — open source, self-host first. A pluggable strong-isolation
runtime layer plus a developer-friendly sandbox platform layer.

> Let any team launch millisecond-start, kernel-isolated code-execution sandboxes on their own
> infrastructure with a single command.

## Status

**Milestone M1 complete — v0.1.** The minimal end-to-end loop is working: pre-baked template →
snapshot-restore create (**P50 = 114 ms, ≤ 500 ms**) → REST / CLI / SDK surfaces → run-to-completion
teardown. Milestone M2 (in progress) adds live network egress gating, OCI images as rootfs sources,
build-time network (real `pip install`), and a TypeScript SDK.

The project is under active development; the public API may change during the v0.x series.

## Highlights

- **Firecracker microVM by default** — hardware-level isolation, with a pluggable Sandbox ABI
  (gVisor / Kata as additional backends).
- **Snapshots as infrastructure** — template pre-baking, warm pools, and snapshot-restore create.
- **Secure by default** — network deny-by-default, snapshot envelope encryption, and clone-state
  protection after restore/fork.
- **Self-host as a first-class citizen** — one command on a single machine; no Docker daemon
  dependency for the build path.
- **OCI images as rootfs sources** — `from = "docker://python:3.12-slim"` (or a `docker save`
  tarball) pulls, verifies, flattens, and bakes an ext4 base; `build_network = "allow-all"` gives
  the build real egress so `pip` / `npm` dependencies install into the template.

## Quick start

Prerequisites: Linux with `/dev/kvm`, a Rust toolchain, and the guest kernel + Firecracker binary
(`scripts/fetch-firecracker.sh`, `scripts/build-kernel.sh`, `scripts/build-rootfs.sh`).

**CLI (three steps):**

```bash
sandlocker up                                    # start the local daemon (sl-node --serve)
sandlocker build examples/hello.sandlocker.toml  # build a pre-baked template
sandlocker run hello -- "echo hello from microVM"
```

**Python SDK** (`sandlocker`, pure standard library):

```python
from sandlocker import Sandbox

with Sandbox.create(template="hello", timeout=300) as sbx:   # auto-destroy on exit
    print(sbx.run("echo hi").stdout)
```

**TypeScript SDK** (`sandlocker`, zero runtime dependencies):

```ts
import { Sandbox } from "sandlocker";

await using sbx = await Sandbox.create("hello", { timeout: 300 });  // auto-destroy on scope exit
console.log((await sbx.run("echo hi")).stdout);
```

See [docs/introduction.md](docs/introduction.md) and [docs/architecture.md](docs/architecture.md)
for a fuller overview.

## Repository layout

| Path | What |
| --- | --- |
| `crates/sl-node` | Host-side node: Firecracker control, snapshot engine, storage, networking, template build, REST daemon |
| `crates/sl-envd` | Guest agent (PID 1, static musl): mounts, zombie reaping, vsock exec |
| `crates/sl-proto` / `crates/sl-store` | vsock wire protocol / metadata store |
| `crates/sandlocker` | User-facing CLI |
| `sdk/python`, `sdk/typescript` | Client SDKs (hand-written, contract-tested) |
| `contracts/` | `openapi.yaml` + `sandlocker.proto` — the API source of truth |
| `examples/` | Template DSL examples + SDK usage scenarios (US-1 / US-4 / US-7) |
| `scripts/` | Build/fetch/bench/verify scripts |
| `docs/` | English docs; `docs/design/` holds the original design history (Chinese) |

## Documentation

The documentation site is built with mdBook (`mdbook serve --open`).

- [Introduction & quick start](docs/introduction.md)
- [Architecture overview](docs/architecture.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)
- **Design history (Chinese):** milestone plans, exit reviews, the PRD, and ADRs live under
  [`docs/design/`](docs/design/). These are the original internal design documents, kept in
  Chinese as historical record.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, and open
a pull request, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community expectations.

## Security

SandLocker runs untrusted code; security is the first-order requirement. To report a vulnerability,
see [SECURITY.md](SECURITY.md) — please do not open a public issue for security reports.

## License

[Apache License 2.0](LICENSE).
