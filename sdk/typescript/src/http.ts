// 传输层（对标 sdk/python/src/sandlocker/_http.py）：node:http，零运行时依赖。
// 守护是手写 HTTP/1.1，仅 Content-Length + `Connection: close`（无 chunked/keep-alive）——一请求一连接。
import * as http from "node:http";
import { ConnectionError } from "./errors.js";

export const DEFAULT_ADDR = "127.0.0.1:7878";

/** host:port → {host, port}；缺端口默认 7878，空 host 默认 127.0.0.1（末个冒号分割，兼容 IPv6 少见场景从简）。 */
export function splitAddr(addr: string): { host: string; port: number } {
  const i = addr.lastIndexOf(":");
  if (i === -1) return { host: addr || "127.0.0.1", port: 7878 };
  const host = addr.slice(0, i) || "127.0.0.1";
  const port = parseInt(addr.slice(i + 1), 10) || 7878;
  return { host, port };
}

export interface RawResponse {
  status: number;
  body: Buffer;
}

export interface RequestOptions {
  body?: Uint8Array;
  contentType?: string;
  addr?: string;
  timeoutMs?: number;
}

/** 发一次请求，读满 body（按 Content-Length / 连接关闭），返回 (status, bytes)。传输失败 → ConnectionError。 */
export function request(method: string, path: string, opts: RequestOptions = {}): Promise<RawResponse> {
  const addr = opts.addr ?? DEFAULT_ADDR;
  const { host, port } = splitAddr(addr);
  const headers: Record<string, string> = { Connection: "close" };
  if (opts.contentType) headers["Content-Type"] = opts.contentType;
  const body = opts.body;
  if (body) headers["Content-Length"] = String(body.length);
  const timeoutMs = opts.timeoutMs ?? 120000;

  return new Promise<RawResponse>((resolve, reject) => {
    const req = http.request({ host, port, method, path, headers, timeout: timeoutMs }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }));
      res.on("error", (e: Error) => reject(new ConnectionError(`读响应失败 ${addr}：${e.message}`)));
    });
    req.on("error", (e: Error) =>
      reject(new ConnectionError(`连接守护 ${addr} 失败：${e.message}（sandlocker up 是否已起？）`)),
    );
    req.on("timeout", () => req.destroy(new Error(`超时 ${timeoutMs}ms`)));
    if (body) req.write(body);
    req.end();
  });
}
