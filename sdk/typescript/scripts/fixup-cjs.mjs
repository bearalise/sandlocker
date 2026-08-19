// 双模块 dual build 收尾：包根是 "type":"module"，故 dist/cjs 下的 .js 会被 Node 当 ESM。
// 写一个 dist/cjs/package.json {"type":"commonjs"} 把该子树标回 CJS，令 require() 正确加载。
import { writeFileSync, mkdirSync } from "node:fs";
mkdirSync("dist/cjs", { recursive: true });
writeFileSync("dist/cjs/package.json", JSON.stringify({ type: "commonjs" }) + "\n");
console.log("[fixup-cjs] wrote dist/cjs/package.json {type:commonjs}");
