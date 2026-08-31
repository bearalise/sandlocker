// 最新 TS SDK 特性示例（对标 CHANGELOG「Post-M2 runtime features」）：
//   ① 流式 exec —— run(cmd, {onStdout,onStderr}) 逐块回调（守护边跑边推 NDJSON，stdout/stderr 分离）；
//   ② Sandbox.connect —— 按 id 附着到已存在沙箱（另一「句柄」，模拟跨进程/请求重新拿到沙箱）。
//
// 前置：sandlocker up 已起守护。地址取 SANDLOCKER_ADDR（默认 127.0.0.1:7878）。
// 需 SDK ≥ 0.3（流式 exec 0.3.0 / connect 0.2.0）——见 examples/sdk-ts/package.json 依赖 ^0.4.0。
import assert from "node:assert/strict";
import { Sandbox } from "sandlocker";

const ADDR = process.env.SANDLOCKER_ADDR ?? "127.0.0.1:7878";

// 起一个沙箱（较长 idle，供下面 connect 再附着）。
const sbx = await Sandbox.create("hello", { timeout: 120, idle: 60, addr: ADDR });
console.log(`[stream+connect] 已创建沙箱 id=${sbx.id}`);

try {
  // ① 流式 exec：命令分多次输出（每行间 sleep），onStdout 逐块到达 → 边跑边收，而非跑完一次性拿。
  const chunks: string[] = [];
  const res = await sbx.run("for i in 1 2 3; do echo line$i; sleep 0.3; done", {
    onStdout: (d) => {
      chunks.push(d);
      process.stdout.write(`[stream] chunk: ${JSON.stringify(d)}\n`);
    },
    onStderr: (d) => process.stderr.write(`[stream] stderr: ${d}`),
  });
  // 回调至少被调用一次（流式路径生效）；聚合结果含全部行 + 退出码 0。
  assert.ok(chunks.length >= 1, "流式 onStdout 未收到任何块");
  const streamed = chunks.join("");
  for (const line of ["line1", "line2", "line3"]) {
    assert.ok(streamed.includes(line) || res.stdout.includes(line), `流式输出缺 ${line}`);
  }
  assert.ok(res.ok, `流式 exec 退出码非 0：exit=${res.exitCode} stderr=${res.stderr}`);
  console.log(`[stream+connect] 流式 exec OK：收到 ${chunks.length} 块，exit=${res.exitCode}`);

  // ② connect：仅凭 id 重新附着（另一句柄，verify 默认往返校验存在）。
  const attached = await Sandbox.connect(sbx.id, { addr: ADDR });
  assert.equal(attached.id, sbx.id, "connect 拿到的 id 不符");
  const r2 = await attached.run("echo attached-ok");
  assert.ok(r2.ok && r2.stdout.includes("attached-ok"), `附着句柄不可用：${r2.stdout}`);
  console.log("[stream+connect] Sandbox.connect（校验式）+ run OK");

  // connect(verify:false)：惰性绑定，不打网络，错误延迟到首个真实操作——适合确信在、省往返的场景。
  const lazy = await Sandbox.connect(sbx.id, { addr: ADDR, verify: false });
  const r3 = await lazy.run("echo lazy-ok");
  assert.ok(r3.ok && r3.stdout.includes("lazy-ok"), `惰性附着不可用：${r3.stdout}`);
  console.log("[stream+connect] Sandbox.connect(verify:false) 惰性附着 + run OK");
} finally {
  await sbx.kill();
}

console.log("STREAM+CONNECT PASS：流式 exec 逐块回调 + Sandbox.connect 附着（校验式/惰性）");
