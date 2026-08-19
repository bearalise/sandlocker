# Introduction

**A secure code-execution sandbox built on Firecracker microVMs.** SandLocker provides strong
isolation (a hardware-virtualization boundary) for running untrusted code, with second-scale
readiness (snapshot restore, create P50 ≤ 500 ms) and run-to-completion teardown.

> Status: **M1 complete, v0.1**; Milestone M2 in progress (live network gating, OCI-image rootfs
> sources, build-time network, TypeScript SDK). The public API may change during v0.x.

## Capabilities (M1 / v0.1)

| Layer | Capability |
|---|---|
| Isolation | Firecracker microVM + jailer; post-restore reinit (rotates machine-id / RNG / session key); network policy applied before resume (no packet-send window) |
| Storage | dm-thin CoW (base origin + per-sandbox thin snapshot); destroy frees blocks with no orphans |
| Network | nftables per-sandbox table, default drop + IP/port allowlist |
| Templates | template DSL + build-as-sandbox + pre-baked snapshot + content addressing + ed25519 signing |
| Orchestration | in-process lifecycle (restore / keepalive / idle / TTL / destroy) with zero-residue reclaim |
| Interfaces | REST control plane (`sl-node --serve`) + CLI (`sandlocker`) + Python & TypeScript SDKs |

## Quick start

**Three steps (CLI)** — start the daemon, build a template, run a command:

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
    sbx.files.write("/tmp/out.txt", b"payload")
    print(sbx.files.read("/tmp/out.txt"))
```

**TypeScript SDK** (`sandlocker`, zero runtime dependencies):

```ts
import { Sandbox } from "sandlocker";

await using sbx = await Sandbox.create("hello", { timeout: 300 });  // auto-destroy on scope exit
console.log((await sbx.run("echo hi")).stdout);
```

Environment setup (Firecracker + guest kernel + base rootfs) is covered in
[CONTRIBUTING](../CONTRIBUTING.md); see [Architecture](architecture.md) for how it fits together.

## Building real dependency templates (M2)

The base rootfs is Alpine busybox + `sl-envd` (no Python). To bake a real "Python + dependencies"
template, use an OCI image as the rootfs source and enable build-time network:

```toml
name = "py"
from = "docker://python:3.12-slim"     # or docker-archive:/path/to/img.tar
build_network = "allow-all"            # real egress during RUN (needs root)
run = ["pip install --no-cache-dir requests"]
```
