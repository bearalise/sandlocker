// US-7（P4）——CI 里跑不可信 PR 测试，跑完即焚（对标 examples/sdk/us7_ci_ephemeral.py）。
//
// 用 `await using`（Symbol.asyncDispose）保证：无论测试通过与否，作用域退出都自动销毁沙箱；
// 沙箱内命令退出码原样透传，CI 据此判红绿。M1 基座 busybox：用 shell 模拟「测试套件」。
// 前置：sandlocker up。SANDLOCKER_ADDR（默认 127.0.0.1:7878）。
import assert from "node:assert/strict";
import { Sandbox } from "../../sdk/typescript/dist/esm/index.js";

const ADDR = process.env.SANDLOCKER_ADDR ?? "127.0.0.1:7878";

let leakedId = "";
{
  // 跑完即焚：作用域退出自动 DELETE，即便中途 assert 抛错也会销毁。
  await using sbx = await Sandbox.create("hello", { timeout: 120, addr: ADDR });
  leakedId = sbx.id;
  console.log(`[US-7] CI 沙箱 id=${sbx.id}`);

  // ① 不可信「测试」失败 → 退出码透传（CI 会据此判红）。
  const failing = await sbx.run("echo 'running suite' && exit 3");
  console.log(`[US-7] 失败用例 exitCode=${failing.exitCode} stdout=${failing.stdout.trim()}`);
  assert.equal(failing.exitCode, 3, `退出码未透传（期望 3，得 ${failing.exitCode}）`);

  // ② 通过用例 → exit 0；失败不影响后续（隔离）。
  const passing = await sbx.run("echo 'all green' && exit 0");
  assert.ok(passing.ok && passing.stdout.includes("all green"), `通过用例异常：${passing.stdout}`);
  console.log("[US-7] 通过用例 OK");
}

// ③ 跑完即焚：退出作用域后沙箱应已销毁，无残留。
const ids = new Set((await Sandbox.list({ addr: ADDR })).map((s) => s.id));
assert.ok(!ids.has(leakedId), `跑完未焚毁：${leakedId} 仍在列表`);
console.log("US-7 PASS：不可信测试退出码透传 + await using 跑完即焚（零残留）");
