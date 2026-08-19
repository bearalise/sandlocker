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

`Sandbox.create` / `list` / `get` accept `{ addr }` (default `127.0.0.1:7878`, requires the
`sandlocker up` daemon to be running), or you can share a `Client`. `Template.list()` lists
registered templates.

## API (on par with the Python SDK)

- `Sandbox.create(template, opts)` / `Sandbox.list(opts)` / `Sandbox.get(id, opts)`
- Instance: `run(cmd)→ExecResult`, `keepAlive()`, `logs()→string`, `info()→SandboxInfo`, `kill()`,
  `files.write(path, string|Uint8Array)` / `files.read(path)→Buffer`, `[Symbol.asyncDispose]`
- Low-level `Client` (one method per route), models `ExecResult`/`SandboxInfo`/`Template`,
  errors `SandLockerError`/`ConnectionError`/`ApiError`/`NotFound` (only 404→NotFound).

## Development

```bash
npm ci
npm test        # fake-daemon scenarios + ROUTES contract reconciliation (node:test, no KVM needed)
npm run build   # outputs dist/esm + dist/cjs + .d.ts
```

Contract-drift guard: `contracts/openapi.yaml` ↔ `ROUTES` in `src/client.ts` ↔ `expected` in
`test/sdk.test.ts` must stay in sync (change one and the unit tests go red). For end-to-end
testing see `scripts/verify-sdk-ts-e2e.sh`.
