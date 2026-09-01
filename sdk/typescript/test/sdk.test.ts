// 单测（node:test，无需 KVM/真守护，对标 sdk/python/tests/test_sdk.py）：
//   进程内假 daemon（node:http）重实现 M1 子集路由，驱动真 SDK；外加 ROUTES 契约对账。
import { test } from "node:test";
import assert from "node:assert/strict";
import * as http from "node:http";
import type { AddressInfo } from "node:net";

import { Sandbox, Client, Template, ROUTES, NotFound, ApiError } from "../src/index.js";

// ── 进程内假 daemon ────────────────────────────────────────────────────────
interface State {
  sandboxes: Map<string, any>;
  files: Map<string, Buffer>; // key = `${id}:${path}`
  seq: number;
}

function b64(s: string): string {
  return Buffer.from(s, "utf8").toString("base64");
}

function startFakeDaemon(): Promise<{ addr: string; close: () => Promise<void>; state: State }> {
  const state: State = { sandboxes: new Map(), files: new Map(), seq: 0 };
  const send = (res: http.ServerResponse, code: number, obj: unknown, ctype = "application/json") => {
    const body = code === 204 ? Buffer.alloc(0) : Buffer.from(typeof obj === "string" ? obj : JSON.stringify(obj), "utf8");
    res.writeHead(code, { "Content-Type": ctype, "Content-Length": String(body.length), Connection: "close" });
    res.end(body);
  };
  const err = (res: http.ServerResponse, code: number, msg: string) => send(res, code, { error: msg });

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const path = (req.url ?? "").split("?")[0]!;
      const segs = path.split("/").filter(Boolean); // e.g. ["v1","sandboxes","id","exec"]
      const m = req.method ?? "GET";
      try {
        // /v1/sandboxes
        if (segs[0] === "v1" && segs[1] === "sandboxes" && segs.length === 2) {
          if (m === "POST") {
            const b = JSON.parse(body.toString("utf8") || "{}");
            const id = `sbx-${++state.seq}`;
            const meta = { id, state: "running", machine_id: `mid-${id}`, template: b.template, total_ms: 12 };
            state.sandboxes.set(id, {
              id,
              template: b.template,
              vcpus: b.cpu ?? 2,
              mem_mib: b.mem ?? 512,
              ttl_secs: b.ttl ?? 300,
              idle_secs: b.idle ?? b.ttl ?? 300,
              created_at: 1000,
              ttl_deadline: 1000 + (b.ttl ?? 300),
              labels: b.env ?? {},
              network: b.network ?? "none", // 回显以便断言 SDK 透传 network 选项
            });
            return send(res, 201, meta);
          }
          if (m === "GET") return send(res, 200, [...state.sandboxes.values()]);
        }
        // /v1/templates
        if (m === "GET" && segs[0] === "v1" && segs[1] === "templates" && segs.length === 2) {
          return send(res, 200, [{ name: "hello", version: "abc123" }]);
        }
        // /v1/sandboxes/{id}...
        if (segs[0] === "v1" && segs[1] === "sandboxes" && segs.length >= 3) {
          const id = segs[2]!;
          const exists = state.sandboxes.has(id);
          if (segs.length === 3) {
            if (m === "GET") return exists ? send(res, 200, state.sandboxes.get(id)) : err(res, 404, "no such sandbox");
            if (m === "DELETE") {
              if (!exists) return err(res, 404, "no such sandbox");
              state.sandboxes.delete(id);
              return send(res, 204, null);
            }
          }
          if (segs.length === 4 && segs[3] === "keepalive" && m === "POST") {
            if (!exists) return err(res, 404, "no such sandbox");
            return send(res, 200, { id, lease_deadline: 2000, ttl_deadline: 3000 });
          }
          if (segs.length === 4 && segs[3] === "exec" && m === "POST") {
            const cmd: string = JSON.parse(body.toString("utf8") || "{}").cmd ?? "";
            const mExit = /^\s*exit\s+(\d+)/.exec(cmd); // 特判 `exit N` 透传退出码
            const code = mExit ? Number(mExit[1]) : 0;
            return send(res, 200, { exit_code: code, stdout: mExit ? "" : `ran: ${cmd}\n`, stderr: "" });
          }
          // 流式 exec：NDJSON（每行一 JSON 事件，无 Content-Length）。分多次 write 模拟边跑边推。
          if (segs.length === 5 && segs[3] === "exec" && segs[4] === "stream" && m === "POST") {
            if (!exists) return err(res, 404, "no such sandbox");
            const cmd: string = JSON.parse(body.toString("utf8") || "{}").cmd ?? "";
            const mExit = /^\s*exit\s+(\d+)/.exec(cmd);
            const code = mExit ? Number(mExit[1]) : 0;
            res.writeHead(200, { "Content-Type": "application/x-ndjson", Connection: "close" });
            const emit = (obj: unknown) => res.write(JSON.stringify(obj) + "\n");
            emit({ stream: "stdout", data: b64("out1\n") });
            emit({ stream: "stdout", data: b64("out2\n") });
            emit({ stream: "stderr", data: b64("err1\n") });
            emit({ exit_code: code });
            return res.end();
          }
          if (segs.length === 4 && segs[3] === "logs" && m === "GET") {
            if (!exists) return err(res, 404, "no such sandbox");
            return send(res, 200, "boot ok\nready\n", "text/plain; charset=utf-8");
          }
          if (segs.length >= 5 && segs[3] === "files") {
            const fpath = segs.slice(4).join("/");
            const key = `${id}:${fpath}`;
            if (m === "PUT") {
              state.files.set(key, body);
              return send(res, 204, null);
            }
            if (m === "GET") {
              const data = state.files.get(key);
              return data ? (res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": String(data.length), Connection: "close" }), res.end(data)) : err(res, 500, "no such file");
            }
          }
        }
        return err(res, 404, "no such route");
      } catch (e) {
        return err(res, 500, String(e));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      resolve({
        addr: `127.0.0.1:${port}`,
        state,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

// ── 契约对账（三处同步防线，对标 Python test_contract_alignment）────────────
test("contract alignment: ROUTES == openapi M1 集合", () => {
  const expected = new Set<string>([
    "POST /v1/sandboxes",
    "GET /v1/sandboxes",
    "GET /v1/sandboxes/{id}",
    "DELETE /v1/sandboxes/{id}",
    "POST /v1/sandboxes/{id}/keepalive",
    "POST /v1/sandboxes/{id}/exec",
    "POST /v1/sandboxes/{id}/exec/stream",
    "PUT /v1/sandboxes/{id}/files/{path}",
    "GET /v1/sandboxes/{id}/files/{path}",
    "GET /v1/sandboxes/{id}/logs",
    "POST /v1/sandboxes/{id}/pause",
    "POST /v1/sandboxes/{id}/resume",
    "POST /v1/sandboxes/{id}/fork",
    "POST /v1/sandboxes/{id}/ticket",
    "POST /v1/sandboxes/{id}/expose",
    "GET /v1/sandboxes/{id}/exposes",
    "DELETE /v1/sandboxes/{id}/expose/{guest_port}",
    "GET /v1/templates",
    "GET /v1/backends",
    "GET /v1/audit",
    // 注：POST /v1/templates:build M1 恒 501，SDK 不封装，故不入集。
  ]);
  assert.deepEqual(new Set(ROUTES), expected);
});

// ── 场景测试（逐一对标 Python）─────────────────────────────────────────────
test("create → run → files 往返 → logs → kill", async () => {
  const d = await startFakeDaemon();
  try {
    const sbx = await Sandbox.create("hello", { timeout: 120, idle: 8, addr: d.addr });
    assert.equal(sbx.state, "running");
    assert.ok(sbx.machineId?.startsWith("mid-"));
    const r = await sbx.run("echo hi");
    assert.ok(r.ok);
    assert.match(r.stdout, /ran: echo hi/);
    await sbx.files.write("/work/in.csv", "col\n1\n2\n");
    const back = await sbx.files.read("work/in.csv"); // 前导 / 可省
    assert.equal(back.toString("utf8"), "col\n1\n2\n");
    await sbx.files.write("/b.bin", new Uint8Array([1, 2, 3]));
    assert.deepEqual([...(await sbx.files.read("/b.bin"))], [1, 2, 3]);
    assert.match(await sbx.logs(), /ready/);
    await sbx.kill();
    assert.equal(d.state.sandboxes.has(sbx.id), false);
  } finally {
    await d.close();
  }
});

test("await using 跑完即焚（asyncDispose）", async () => {
  const d = await startFakeDaemon();
  try {
    let leaked: string;
    {
      await using sbx = await Sandbox.create("hello", { addr: d.addr });
      leaked = sbx.id;
      assert.ok(d.state.sandboxes.has(leaked));
    }
    assert.equal(d.state.sandboxes.has(leaked), false); // 作用域退出自动 kill
  } finally {
    await d.close();
  }
});

test("退出码透传 + ok 语义", async () => {
  const d = await startFakeDaemon();
  try {
    const sbx = await Sandbox.create("hello", { addr: d.addr });
    const r = await sbx.run("exit 7");
    assert.equal(r.exitCode, 7);
    assert.equal(r.ok, false);
    await sbx.kill();
  } finally {
    await d.close();
  }
});

test("run 流式：onStdout/onStderr 分离逐块 + 聚合 + 退出码", async () => {
  const d = await startFakeDaemon();
  try {
    const sbx = await Sandbox.create("hello", { addr: d.addr });
    const outs: string[] = [];
    const errs: string[] = [];
    const r = await sbx.run("whatever", { onStdout: (s) => outs.push(s), onStderr: (s) => errs.push(s) });
    assert.deepEqual(outs, ["out1\n", "out2\n"]); // 逐块（base64 解码回字符串）
    assert.deepEqual(errs, ["err1\n"]);
    assert.equal(r.stdout, "out1\nout2\n"); // 聚合
    assert.equal(r.stderr, "err1\n");
    assert.equal(r.exitCode, 0);
    assert.ok(r.ok);
    await sbx.kill();
  } finally {
    await d.close();
  }
});

test("run 流式：退出码透传", async () => {
  const d = await startFakeDaemon();
  try {
    const sbx = await Sandbox.create("hello", { addr: d.addr });
    const r = await sbx.run("exit 7", { onStdout: () => {} });
    assert.equal(r.exitCode, 7);
    assert.equal(r.ok, false);
    await sbx.kill();
  } finally {
    await d.close();
  }
});

test("run 流式：未知沙箱 → NotFound", async () => {
  const d = await startFakeDaemon();
  try {
    const ghost = await Sandbox.connect("nope", { addr: d.addr, verify: false });
    await assert.rejects(ghost.run("x", { onStdout: () => {} }), (e: unknown) => e instanceof NotFound);
  } finally {
    await d.close();
  }
});

test("list / get / templates", async () => {
  const d = await startFakeDaemon();
  try {
    const a = await Sandbox.create("hello", { addr: d.addr });
    const infos = await Sandbox.list({ addr: d.addr });
    assert.equal(infos.length, 1);
    assert.equal(infos[0]!.id, a.id);
    assert.equal(infos[0]!.vcpus, 2);
    const got = await Sandbox.get(a.id, { addr: d.addr });
    assert.equal(got.id, a.id);
    const tpls = await Template.list({ addr: d.addr });
    assert.equal(tpls[0]!.name, "hello");
    await a.kill();
  } finally {
    await d.close();
  }
});

test("create：network 选项透传到 body（none 不发 / egress 发）", async () => {
  const d = await startFakeDaemon();
  try {
    const a = await Sandbox.create("hello", { addr: d.addr });
    assert.equal(d.state.sandboxes.get(a.id).network, "none"); // 缺省不发 → 守护默认 none
    const b = await Sandbox.create("hello", { addr: d.addr, network: "egress" });
    assert.equal(d.state.sandboxes.get(b.id).network, "egress");
    await a.kill();
    await b.kill();
  } finally {
    await d.close();
  }
});

test("connect：校验式往返 + 惰性绑定（verify:false 不打网络）", async () => {
  const d = await startFakeDaemon();
  try {
    const a = await Sandbox.create("hello", { addr: d.addr });
    // 默认 verify:true——往返拉元数据（不存在 → NotFound，与 get 同）。
    const attached = await Sandbox.connect(a.id, { addr: d.addr });
    assert.equal(attached.id, a.id);
    assert.equal((await attached.info()).template, "hello");
    await assert.rejects(Sandbox.connect("nope", { addr: d.addr }), (e: unknown) => e instanceof NotFound);
    // verify:false——惰性绑定：即使 id 不存在也不抛（无往返），错误延迟到首个真实操作。
    const lazy = await Sandbox.connect("nope", { addr: d.addr, verify: false });
    assert.equal(lazy.id, "nope");
    await assert.rejects(lazy.info(), (e: unknown) => e instanceof NotFound);
    await a.kill();
  } finally {
    await d.close();
  }
});

test("404 → NotFound（且是 ApiError 子类）", async () => {
  const d = await startFakeDaemon();
  try {
    await assert.rejects(Sandbox.get("nope", { addr: d.addr }), (e: unknown) => {
      assert.ok(e instanceof NotFound);
      assert.ok(e instanceof ApiError);
      assert.equal((e as ApiError).status, 404);
      return true;
    });
  } finally {
    await d.close();
  }
});

test("kill 幂等（二次 kill 吞 NotFound）", async () => {
  const d = await startFakeDaemon();
  try {
    const sbx = await Sandbox.create("hello", { addr: d.addr });
    await sbx.kill();
    await sbx.kill(); // 不抛
  } finally {
    await d.close();
  }
});

test("keepalive 续期 + 未知沙箱 404", async () => {
  const d = await startFakeDaemon();
  try {
    const sbx = await Sandbox.create("hello", { addr: d.addr });
    const ka = await sbx.keepAlive();
    assert.equal(ka.id, sbx.id);
    assert.equal(typeof ka.lease_deadline, "number");
    const c = new Client(d.addr);
    await assert.rejects(c.keepAlive("nope"), (e: unknown) => e instanceof NotFound);
    await sbx.kill();
  } finally {
    await d.close();
  }
});

test("连接失败 → ConnectionError", async () => {
  // 指向没人监听的端口
  await assert.rejects(Sandbox.list({ addr: "127.0.0.1:1" }), (e: unknown) => {
    assert.equal((e as Error).name, "ConnectionError");
    return true;
  });
});

// ── M3 W6/W7 鉴权 + 类型化错误 ─────────────────────────────────────────────
import { Unauthorized, Forbidden, QuotaExceeded } from "../src/index.js";

// 小工具：起一个只回固定状态并记录 Authorization 头的服务器。
function startProbe(status: number, obj: unknown): Promise<{ addr: string; close: () => Promise<void>; lastAuth: () => string | undefined }> {
  let lastAuth: string | undefined;
  const server = http.createServer((req, res) => {
    lastAuth = req.headers["authorization"] as string | undefined;
    req.on("data", () => {});
    req.on("end", () => {
      const body = Buffer.from(JSON.stringify(obj), "utf8");
      res.writeHead(status, { "Content-Type": "application/json", "Content-Length": String(body.length), Connection: "close" });
      res.end(body);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const p = (server.address() as AddressInfo).port;
      resolve({
        addr: `127.0.0.1:${p}`,
        close: () => new Promise((r) => server.close(() => r())),
        lastAuth: () => lastAuth,
      });
    });
  });
}

test("apiKey → Authorization: Bearer 头注入", async () => {
  const d = await startProbe(200, []);
  try {
    const c = new Client(d.addr, 120000, "tok-abc");
    await c.listSandboxes();
    assert.equal(d.lastAuth(), "Bearer tok-abc");
  } finally {
    await d.close();
  }
});

test("无 apiKey → 不带 Authorization 头", async () => {
  const d = await startProbe(200, []);
  try {
    const c = new Client(d.addr); // 无 key、无环境变量
    delete process.env.SANDLOCKER_API_KEY;
    await c.listSandboxes();
    assert.equal(d.lastAuth(), undefined);
  } finally {
    await d.close();
  }
});

test("401/403/429 → Unauthorized/Forbidden/QuotaExceeded（均 ApiError 子类）", async () => {
  for (const [status, ctor] of [[401, Unauthorized], [403, Forbidden], [429, QuotaExceeded]] as const) {
    const d = await startProbe(status, { error: "x" });
    try {
      const c = new Client(d.addr, 120000, "k");
      await assert.rejects(c.listSandboxes(), (e: unknown) => {
        assert.ok(e instanceof ctor, `${status} 应为 ${ctor.name}`);
        assert.ok(e instanceof ApiError);
        assert.equal((e as ApiError).status, status);
        return true;
      });
    } finally {
      await d.close();
    }
  }
});
