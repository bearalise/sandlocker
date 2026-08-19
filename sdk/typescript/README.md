# SandLocker TypeScript SDK

零运行时依赖的薄 REST 客户端（仅用 `node:http`），对标 [Python SDK](../python/) 与
[`contracts/openapi.yaml`](../../contracts/openapi.yaml)。面向 Node.js（服务端），异步 Promise API。

- **Node ≥ 20**（`await using` / `Symbol.asyncDispose` 需 ≥ 20；示例 `.ts` 直跑需 ≥ 22.6）。
- **零运行时依赖**；devDep 仅 `typescript` + `@types/node`；测试用内置 `node:test`。
- 双模块：ESM + CJS + `.d.ts`。

## 快速上手

```ts
import { Sandbox } from "sandlocker";

// create → run → 取产物；作用域退出自动销毁（跑完即焚）。
await using sbx = await Sandbox.create("hello", { timeout: 120, idle: 30 });
const r = await sbx.run("echo hello && uname -a");
console.log(r.exitCode, r.stdout);          // 退出码透传 + 缓冲输出

await sbx.files.write("/work/in.csv", "col\n1\n2\n");
const data = await sbx.files.read("/work/in.csv");   // Buffer

// 或手动生命周期（无 `await using` 时）：
const s2 = await Sandbox.create("hello");
try { /* ... */ } finally { await s2.kill(); }        // kill 幂等
```

`Sandbox.create` / `list` / `get` 可传 `{ addr }`（默认 `127.0.0.1:7878`，需 `sandlocker up` 已起守护）
或复用一个 `Client`。`Template.list()` 列已注册模板。

## API（对标 Python SDK）

- `Sandbox.create(template, opts)` / `Sandbox.list(opts)` / `Sandbox.get(id, opts)`
- 实例：`run(cmd)→ExecResult`、`keepAlive()`、`logs()→string`、`info()→SandboxInfo`、`kill()`、
  `files.write(path, string|Uint8Array)` / `files.read(path)→Buffer`、`[Symbol.asyncDispose]`
- 低层 `Client`（一方法一路由）、模型 `ExecResult`/`SandboxInfo`/`Template`、
  异常 `SandLockerError`/`ConnectionError`/`ApiError`/`NotFound`（仅 404→NotFound）。

## 开发

```bash
npm ci
npm test        # 假 daemon 场景 + ROUTES 契约对账（node:test，无需 KVM）
npm run build   # 产出 dist/esm + dist/cjs + .d.ts
```

契约漂移防线：`contracts/openapi.yaml` ↔ `src/client.ts` 的 `ROUTES` ↔ `test/sdk.test.ts` 的
`expected` 三处必须同步（改任一即单测红）。端到端见 `scripts/verify-sdk-ts-e2e.sh`。
