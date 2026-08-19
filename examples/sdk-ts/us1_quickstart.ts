// US-1（P1）——TS SDK 几行 create→run→取产物 + 空闲自动销毁（对标 examples/sdk/us1_quickstart.py）。
//
// 对应 PRD 7.6 / US-1「数据科学家几行代码起沙箱跑分析、5 分钟无活动自动回收」。
// M1 基座是 busybox（无 Python），故 run 里跑 shell 生成产物；真 python 需 M2 allow-network 模板。
//
// 前置：sandlocker up 已起守护。地址取 SANDLOCKER_ADDR（默认 127.0.0.1:7878）。
// 文件读写依赖 guest base64 applet；设 SL_SKIP_FILES=1 跳过该段（e2e 探测缺失时用）。
import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import { Sandbox } from "sandlocker";

const ADDR = process.env.SANDLOCKER_ADDR ?? "127.0.0.1:7878";
const SKIP_FILES = process.env.SL_SKIP_FILES === "1";

// ① 几行手感：起沙箱 → 跑「分析」→ 取产物。idle=8s → 空闲后服务端自动回收。
const sbx = await Sandbox.create("hello", { timeout: 120, idle: 8, addr: ADDR });
console.log(`[US-1] 已创建沙箱 id=${sbx.id} totalMs=${sbx.totalMs}`);

// ② 跑「分析」：生成产物文件。
const r = await sbx.run("mkdir -p /work && echo 'analysis-result-42' > /work/out.txt && echo done");
assert.ok(r.ok, `run 失败：exit=${r.exitCode} stderr=${r.stderr}`);
assert.match(r.stdout, /done/, `run stdout 异常：${r.stdout}`);

// ③ 取产物：先经 run 读回（不依赖 base64），再验 SDK 文件 API。
const got = await sbx.run("cat /work/out.txt");
assert.match(got.stdout, /analysis-result-42/, `产物内容不符：${got.stdout}`);
console.log(`[US-1] 产物（经 run）：${got.stdout.trim()}`);

if (!SKIP_FILES) {
  const data = await sbx.files.read("/work/out.txt");
  assert.equal(data.toString("utf8").trim(), "analysis-result-42", `files.read 内容不符：${data}`);
  await sbx.files.write("/work/in.csv", "col\n1\n2\n");
  const back = await sbx.files.read("/work/in.csv");
  assert.equal(back.toString("utf8"), "col\n1\n2\n", `files 往返不符：${back}`);
  console.log("[US-1] 文件读写往返 OK（SDK files API）");
} else {
  console.log("[US-1] 跳过 SDK files API（SL_SKIP_FILES=1）");
}

// ④ 空闲自动销毁：不手动 kill，轮询直到该沙箱从列表消失（服务端 idle 回收）。
console.log("[US-1] 等待空闲自动回收（idle=8s）...");
const deadline = Date.now() + 40_000;
let reclaimed = false;
while (Date.now() < deadline) {
  const ids = new Set((await Sandbox.list({ addr: ADDR })).map((s) => s.id));
  if (!ids.has(sbx.id)) {
    reclaimed = true;
    break;
  }
  await sleep(1000);
}
assert.ok(reclaimed, `沙箱 ${sbx.id} 未在 40s 内被空闲回收`);
console.log("US-1 PASS：几行 create→run→取产物 + 空闲自动销毁（零残留）");
