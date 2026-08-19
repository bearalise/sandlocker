// US-4（P2）——团队模板 + 秒级就绪（对标 examples/sdk/us4_template.py）。
//
// 验证：模板已注册（Template.list）+ 从模板起沙箱走快照恢复、秒级就绪。
// 前置：sandlocker up + 已 build hello 模板。SANDLOCKER_ADDR（默认 127.0.0.1:7878）；
// 就绪阈值 SL_READY_MS_MAX（默认 2000ms，恢复路径非冷启动，含 CI 抖动余量）。
import assert from "node:assert/strict";
import { Sandbox, Template } from "../../sdk/typescript/dist/esm/index.js";

const ADDR = process.env.SANDLOCKER_ADDR ?? "127.0.0.1:7878";
const READY_MS_MAX = Number(process.env.SL_READY_MS_MAX ?? "2000");

// ① 团队模板已注册。
const tpls = new Map((await Template.list({ addr: ADDR })).map((t) => [t.name, t]));
console.log(`[US-4] 已注册模板：${[...tpls.keys()].sort().join(", ")}`);
assert.ok(tpls.has("hello"), "模板 hello 未注册（先 `sandlocker build examples/hello.sandlocker.toml`）");
console.log(`[US-4] 模板 hello 版本（内容寻址）：${tpls.get("hello")!.version}`);

// ② 从模板起沙箱：秒级就绪（走快照恢复）。以服务端 totalMs 为准，去客户端抖动。
const t0 = Date.now();
const sbx = await Sandbox.create("hello", { timeout: 120, addr: ADDR });
const wallMs = Date.now() - t0;
const serverMs = sbx.totalMs;
console.log(`[US-4] 就绪：server totalMs=${serverMs} wallMs=${wallMs}`);
let measured = typeof serverMs === "number" ? serverMs : wallMs;
try {
  // ③ 就绪即可用。
  const r = await sbx.run("echo ready && uname -a");
  assert.ok(r.ok && r.stdout.includes("ready"), `起后不可用：${r.stdout}`);
  assert.ok(measured < READY_MS_MAX, `就绪耗时 ${measured}ms 超阈值 ${READY_MS_MAX}ms`);
} finally {
  await sbx.kill();
}
console.log(`US-4 PASS：团队模板已注册 + 从模板秒级就绪（${measured}ms < ${READY_MS_MAX}ms）`);
