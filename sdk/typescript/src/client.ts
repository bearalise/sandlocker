// 低层 REST 客户端（对标 sdk/python/src/sandlocker/client.py）：一方法一 OpenAPI 路由。
// 无共享可变状态、每调用新连接 → 天然并发安全。
import { request, DEFAULT_ADDR } from "./http.js";
import { ApiError, NotFound } from "./errors.js";

// 契约漂移防线（替代 codegen，对标 Python client.ROUTES）：改 openapi 或路由时，
// contracts/openapi.yaml ↔ 此 ROUTES ↔ test 的 expected 三处必须同步，否则单测红。
// 注：POST /v1/templates:build 在 M1 恒返 501、SDK 不封装，故不在此集合。
export const ROUTES: ReadonlySet<string> = new Set<string>([
  "POST /v1/sandboxes",
  "GET /v1/sandboxes",
  "GET /v1/sandboxes/{id}",
  "DELETE /v1/sandboxes/{id}",
  "POST /v1/sandboxes/{id}/keepalive",
  "POST /v1/sandboxes/{id}/exec",
  "PUT /v1/sandboxes/{id}/files/{path}",
  "GET /v1/sandboxes/{id}/files/{path}",
  "GET /v1/sandboxes/{id}/logs",
  "GET /v1/templates",
]);

/** 非预期状态 → 异常（仅 404 特化为 NotFound；错误体形如 {"error":"..."}）。 */
function decodeError(status: number, body: Buffer): ApiError {
  let detail: string;
  try {
    const obj = JSON.parse(body.toString("utf8"));
    detail = typeof obj?.error === "string" ? obj.error : body.toString("utf8");
  } catch {
    detail = body.toString("utf8");
  }
  return status === 404 ? new NotFound(status, detail) : new ApiError(status, detail);
}

export class Client {
  readonly addr: string;
  readonly timeoutMs: number;

  constructor(addr: string = DEFAULT_ADDR, timeoutMs = 120000) {
    this.addr = addr;
    this.timeoutMs = timeoutMs;
  }

  /** JSON in/out；空体返回 null；状态不在 expect → decodeError。 */
  private async json(method: string, path: string, bodyObj?: unknown, expect: number[] = [200]): Promise<any> {
    let body: Uint8Array | undefined;
    let contentType: string | undefined;
    if (bodyObj !== undefined) {
      body = Buffer.from(JSON.stringify(bodyObj), "utf8");
      contentType = "application/json";
    }
    const resp = await request(method, path, { body, contentType, addr: this.addr, timeoutMs: this.timeoutMs });
    if (!expect.includes(resp.status)) throw decodeError(resp.status, resp.body);
    if (resp.body.length === 0) return null;
    return JSON.parse(resp.body.toString("utf8"));
  }

  /** 剥前导 `/`（守护 files 路由参数不带前导斜杠；多段路径原样保留）。 */
  private static cleanPath(p: string): string {
    return p.replace(/^\/+/, "");
  }

  async createSandbox(body: Record<string, unknown>): Promise<any> {
    return this.json("POST", "/v1/sandboxes", body, [201]);
  }
  async listSandboxes(): Promise<any[]> {
    return (await this.json("GET", "/v1/sandboxes")) ?? [];
  }
  async getSandbox(id: string): Promise<any> {
    return this.json("GET", `/v1/sandboxes/${id}`);
  }
  async deleteSandbox(id: string): Promise<void> {
    await this.json("DELETE", `/v1/sandboxes/${id}`, undefined, [204, 200]);
  }
  async keepAlive(id: string): Promise<any> {
    return this.json("POST", `/v1/sandboxes/${id}/keepalive`, undefined, [200]);
  }
  async exec(id: string, cmd: string): Promise<any> {
    return this.json("POST", `/v1/sandboxes/${id}/exec`, { cmd });
  }
  async putFile(id: string, path: string, data: Uint8Array): Promise<void> {
    const resp = await request("PUT", `/v1/sandboxes/${id}/files/${Client.cleanPath(path)}`, {
      body: data,
      contentType: "application/octet-stream",
      addr: this.addr,
      timeoutMs: this.timeoutMs,
    });
    if (resp.status !== 204 && resp.status !== 200) throw decodeError(resp.status, resp.body);
  }
  async getFile(id: string, path: string): Promise<Buffer> {
    const resp = await request("GET", `/v1/sandboxes/${id}/files/${Client.cleanPath(path)}`, {
      addr: this.addr,
      timeoutMs: this.timeoutMs,
    });
    if (resp.status !== 200) throw decodeError(resp.status, resp.body);
    return resp.body;
  }
  async logs(id: string): Promise<string> {
    const resp = await request("GET", `/v1/sandboxes/${id}/logs`, { addr: this.addr, timeoutMs: this.timeoutMs });
    if (resp.status !== 200) throw decodeError(resp.status, resp.body);
    return resp.body.toString("utf8");
  }
  async listTemplates(): Promise<any[]> {
    return (await this.json("GET", "/v1/templates")) ?? [];
  }
}
