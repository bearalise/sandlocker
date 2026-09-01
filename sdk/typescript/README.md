# SandLocker TypeScript SDK

A thin REST client with zero runtime dependencies (uses only `node:http`), on par with the
[Python SDK](../python/) and [`contracts/openapi.yaml`](../../contracts/openapi.yaml).
Targets Node.js (server-side) with an async Promise API.

- **Node ≥ 20** (`await using` / `Symbol.asyncDispose` require ≥ 20; running the `.ts` examples directly requires ≥ 22.6).
- **Zero runtime dependencies**; devDeps are just `typescript` + `@types/node`; tests use the built-in `node:test`.
- Dual module: ESM + CJS + `.d.ts`.

## Quick start

```ts
import { Sandbox } from "sandlocker";

// create → run → collect output; auto-destroyed when the scope exits (fire-and-forget).
await using sbx = await Sandbox.create("hello", { timeout: 120, idle: 30 });
const r = await sbx.run("echo hello && uname -a");
console.log(r.exitCode, r.stdout);          // exit code passthrough + buffered output

await sbx.files.write("/work/in.csv", "col\n1\n2\n");
const data = await sbx.files.read("/work/in.csv");   // Buffer

// Or manage the lifecycle manually (without `await using`):
const s2 = await Sandbox.create("hello");
try { /* ... */ } finally { await s2.kill(); }        // kill is idempotent
```

Attach to a sandbox created elsewhere (another process / request / `sandlocker up` session) by id:

```ts
import { Sandbox } from "sandlocker";

const sbx = await Sandbox.connect("sbx-123");                 // verify it exists, then drive it
const r = await sbx.run("echo attached");

// Lazy attach — no network round-trip; errors surface on the first real op:
const lazy = await Sandbox.connect("sbx-123", { verify: false });
```

`Sandbox.create` / `list` / `connect` / `get` accept `{ addr }` (default `127.0.0.1:7878`, requires the
`sandlocker up` daemon to be running), or you can share a `Client`.

### Auth (multi-tenant daemon, M3 W6)

Against a daemon started with `--require-auth`, pass an API key — via the factory/`Client` option or the
`SANDLOCKER_API_KEY` env var. It is sent as `Authorization: Bearer <key>` on every request.

```ts
const sbx = await Sandbox.create("hello", { apiKey: process.env.SANDLOCKER_API_KEY });
// or: new Client("127.0.0.1:7878", 120000, "<key>")
```

`401` / `403` / `429` map to `Unauthorized` / `Forbidden` / `QuotaExceeded` (all `ApiError` subclasses).
`client.audit()` reads the project-filtered audit log.

---

## High-level API — `Sandbox`

The recommended entry point. Factory methods create/discover sandboxes; instance methods drive one.

### Factories (static)

| Method | Parameters | Returns | Notes |
| --- | --- | --- | --- |
| `Sandbox.create(template, opts?)` | `template: string`, `opts?: CreateOptions` | `Promise<Sandbox>` | Create + boot a sandbox from a template. |
| `Sandbox.list(opts?)` | `opts?: { addr?: string; client?: Client }` | `Promise<SandboxInfo[]>` | List all sandboxes. |
| `Sandbox.connect(id, opts?)` | `id: string`, `opts?: { addr?: string; client?: Client; verify?: boolean }` | `Promise<Sandbox>` | **Attach** to an existing sandbox by id for subsequent async ops. `verify: true` (default) does a `GET /v1/sandboxes/{id}` round-trip (throws `NotFound` if gone); `verify: false` binds **lazily with no network call** — errors defer to the first real operation. |
| `Sandbox.get(id, opts?)` | `id: string`, `opts?: { addr?: string; client?: Client }` | `Promise<Sandbox>` | Verifying alias of `connect` (always round-trips to fetch metadata). |

**`CreateOptions`** (all optional):

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `timeout` | `number` | `300` | Absolute TTL ceiling in seconds — a hard cap that `keepAlive()` cannot extend past. |
| `idle` | `number` | server = `ttl` | Idle-reclaim window in seconds (sliding). |
| `cpu` | `number` | daemon = `2` | vCPU count. |
| `mem` | `number` | daemon = `512` | Memory in MiB. |
| `env` | `Record<string, string>` | — | Injected as sandbox labels / metadata. |
| `network` | `"none" \| "egress"` | `"none"` | `"egress"` cold-boots the sandbox with a NIC + NAT so it can reach the internet (e.g. `npm install`). FC backend + root daemon only; slower than snapshot-restore, not pooled. |
| `addr` | `string` | `127.0.0.1:7878` | Daemon address (ignored if `client` is supplied). |
| `client` | `Client` | — | Reuse a shared low-level client. |

### Instance methods

| Method | Parameters | Returns | Notes |
| --- | --- | --- | --- |
| `run(cmd, opts?)` | `cmd: string`, `opts?: RunOptions` | `Promise<ExecResult>` | Run one command. Buffered by default; pass `onStdout`/`onStderr` to stream output chunk-by-chunk (see below). |
| `keepAlive()` | — | `Promise<any>` | Sliding renewal of the idle window (does not move the TTL ceiling). Returns `{ id, lease_deadline, ttl_deadline }`. |
| `logs()` | — | `Promise<string>` | Fetch sandbox logs. |
| `info()` | — | `Promise<SandboxInfo>` | Refresh metadata. |
| `kill()` | — | `Promise<void>` | Destroy; idempotent (swallows `NotFound`). |
| `files.write(path, data)` | `path: string`, `data: string \| Uint8Array` | `Promise<void>` | Write a file (strings are UTF-8 encoded). |
| `files.read(path)` | `path: string` | `Promise<Buffer>` | Read a file (raw bytes). |
| `[Symbol.asyncDispose]()` | — | `Promise<void>` | Enables `await using` → auto-`kill()` on scope exit. |

### Instance properties (from the create response)

- `id: string`
- `machineId: string | undefined`
- `totalMs: number | undefined`
- `state: string | undefined`

### Streaming output — `RunOptions`

Pass either callback to `run` and output is delivered **chunk-by-chunk as the command runs**, with
`stdout`/`stderr` kept separate. The returned `ExecResult` still carries the full aggregated
`stdout`/`stderr` and `exitCode`. Under the hood this uses the daemon's NDJSON streaming endpoint
(`POST /v1/sandboxes/{id}/exec/stream`, FC/vsock backend only).

| Field | Type | Meaning |
| --- | --- | --- |
| `onStdout` | `(data: string) => void` | Called per stdout chunk (UTF-8 decoded). |
| `onStderr` | `(data: string) => void` | Called per stderr chunk (UTF-8 decoded). |

```ts
const buffers = { stdout: "", stderr: "" };
const result = await sbx.run("for i in 1 2 3; do echo $i; sleep 1; done", {
  onStdout: (data) => { buffers.stdout += data; process.stdout.write(data); },
  onStderr: (data) => { buffers.stderr += data; },
});
console.log(result.exitCode, result.stdout === buffers.stdout); // aggregate also returned
```

---

## Low-level API — `Client`

One method per OpenAPI route; no shared mutable state (new connection per call → concurrency-safe).
Construct with `new Client(addr?, timeoutMs?)` — `addr` defaults to `127.0.0.1:7878`, `timeoutMs` to `120000`.

### Lifecycle

| Method | Parameters | Route | Returns |
| --- | --- | --- | --- |
| `createSandbox(body)` | `body: Record<string, unknown>` | `POST /v1/sandboxes` | `Promise<any>` (201) |
| `listSandboxes()` | — | `GET /v1/sandboxes` | `Promise<any[]>` |
| `getSandbox(id)` | `id: string` | `GET /v1/sandboxes/{id}` | `Promise<any>` |
| `deleteSandbox(id)` | `id: string` | `DELETE /v1/sandboxes/{id}` | `Promise<void>` (204/200) |
| `keepAlive(id)` | `id: string` | `POST /v1/sandboxes/{id}/keepalive` | `Promise<any>` |

### pause / resume / fork (M2 W9)

| Method | Parameters | Route | Notes |
| --- | --- | --- | --- |
| `pause(id)` | `id: string` | `POST /v1/sandboxes/{id}/pause` | Snapshot + stop VM (needs backend `pause_resume`). |
| `resume(id)` | `id: string` | `POST /v1/sandboxes/{id}/resume` | Restore from snapshot (reinit issues a fresh machine-id). |
| `fork(id, body?)` | `id: string`, `body?: Record<string, unknown>` (default `{}`) | `POST /v1/sandboxes/{id}/fork` | Derive a new sandbox from a paused parent (independent identity; needs backend `snapshot_fork`). Returns 201. |

### Command / files / logs

| Method | Parameters | Route | Returns |
| --- | --- | --- | --- |
| `exec(id, cmd)` | `id: string`, `cmd: string` | `POST /v1/sandboxes/{id}/exec` | `Promise<any>` |
| `execStream(id, cmd, handlers?)` | `id: string`, `cmd: string`, `handlers?: { onStdout?; onStderr? }` | `POST /v1/sandboxes/{id}/exec/stream` | `Promise<{ exit_code, stdout, stderr }>` — NDJSON stream, FC/vsock only. |
| `putFile(id, path, data)` | `id: string`, `path: string`, `data: Uint8Array` | `PUT /v1/sandboxes/{id}/files/{path}` | `Promise<void>` (leading `/` stripped) |
| `getFile(id, path)` | `id: string`, `path: string` | `GET /v1/sandboxes/{id}/files/{path}` | `Promise<Buffer>` |
| `logs(id)` | `id: string` | `GET /v1/sandboxes/{id}/logs` | `Promise<string>` |

### Data-plane gateway & port exposure (M2 W10, FR-3.3)

| Method | Parameters | Route | Notes |
| --- | --- | --- | --- |
| `ticket(id, action, opts?)` | `id: string`, `action: "exec"\|"file"\|"logs"\|"port"`, `opts?: { port?: number; ttl?: number }` | `POST /v1/sandboxes/{id}/ticket` | Mint a one-time HMAC-signed gateway URL. |
| `expose(id, port, opts?)` | `id: string`, `port: number`, `opts?: { hostPort?: number; bind?: string }` | `POST /v1/sandboxes/{id}/expose` | L4 passthrough reverse proxy → stable external address to a VM-internal service (FC backend only; non-loopback `bind` needs the daemon's `--expose-allow-public`). Returns `{ url, bind, host_port, guest_port }` (201). |
| `unexpose(id, guestPort)` | `id: string`, `guestPort: number` | `DELETE /v1/sandboxes/{id}/expose/{guest_port}` | Revoke an exposure (stop the listener). |
| `listExposes(id)` | `id: string` | `GET /v1/sandboxes/{id}/exposes` | `Promise<any[]>` — exposed ports for a sandbox. |

### Discovery

| Method | Parameters | Route | Returns |
| --- | --- | --- | --- |
| `listBackends()` | — | `GET /v1/backends` | `Promise<any[]>` — backends + capability sets (ADR-14). |
| `listTemplates()` | — | `GET /v1/templates` | `Promise<any[]>` |

> `Template.list(opts?)` (`opts?: { addr?: string; client?: Client }`) is the high-level wrapper → `Promise<Template[]>`.

---

## Models

- **`ExecResult`** — `exitCode: number`, `stdout: string`, `stderr: string`, `raw: Record<string, any>`, getter `ok` (`exitCode === 0`).
- **`SandboxInfo`** — `id`, `template`, `vcpus`, `memMib`, `ttlSecs`, `idleSecs`, `createdAt`, `ttlDeadline`, `labels`, `raw`.
- **`Template`** — `name: string`, `version: string | null`; plus static `Template.list(opts?)`.

## Errors

Only HTTP 404 is specialized to `NotFound`; all other non-expected statuses throw `ApiError`.

```
SandLockerError            — SDK error base (catch-all)
├── ConnectionError        — daemon unreachable / bad address
└── ApiError               — unexpected HTTP status (.status / .detail)
    └── NotFound           — HTTP 404
```

## Development

```bash
npm ci
npm test        # fake-daemon scenarios + ROUTES contract reconciliation (node:test, no KVM needed)
npm run build   # outputs dist/esm + dist/cjs + .d.ts
```

Contract-drift guard: `contracts/openapi.yaml` ↔ `ROUTES` in `src/client.ts` ↔ `expected` in
`test/sdk.test.ts` must stay in sync (change one and the unit tests go red). For end-to-end
testing see `scripts/verify-sdk-ts-e2e.sh`.
