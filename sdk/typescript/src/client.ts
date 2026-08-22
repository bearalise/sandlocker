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
  "POST /v1/sandboxes/{id}/pause",
  "POST /v1/sandboxes/{id}/resume",
  "POST /v1/sandboxes/{id}/fork",
  "POST /v1/sandboxes/{id}/ticket",
  "POST /v1/sandboxes/{id}/expose",
  "GET /v1/sandboxes/{id}/exposes",
  "DELETE /v1/sandboxes/{id}/expose/{guest_port}",
  "GET /v1/templates",
  "GET /v1/backends",
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
  /** M2 W9：暂停沙箱（落快照停 VM，需后端 pause_resume）。 */
  async pause(id: string): Promise<any> {
    return this.json("POST", `/v1/sandboxes/${id}/pause`, undefined, [200]);
  }
  /** M2 W9：恢复沙箱（从快照拉起，reinit 换发新 machine-id）。 */
  async resume(id: string): Promise<any> {
    return this.json("POST", `/v1/sandboxes/${id}/resume`, undefined, [200]);
  }
  /** M2 W9：从（已 pause 的）父派生新沙箱（独立身份，需后端 snapshot_fork）。 */
  async fork(id: string, body: Record<string, unknown> = {}): Promise<any> {
    return this.json("POST", `/v1/sandboxes/${id}/fork`, body, [201]);
  }
  /** M2 W10：签发数据面网关一次性 HMAC 签名 URL（action: exec|file|logs|port）。 */
  async ticket(id: string, action: string, opts: { port?: number; ttl?: number } = {}): Promise<any> {
    return this.json("POST", `/v1/sandboxes/${id}/ticket`, { action, ...opts }, [200]);
  }
  /** 端口暴露（L4 透传持久反代）：外部经稳定地址访问 VM 内动态服务，支持完整协议。仅 FC 后端；
   *  非回环 bind 需守护带 --expose-allow-public。返回 {url,bind,host_port,guest_port}。 */
  async expose(id: string, port: number, opts: { hostPort?: number; bind?: string } = {}): Promise<any> {
    const body: Record<string, unknown> = { port };
    if (opts.hostPort !== undefined) body.host_port = opts.hostPort;
    if (opts.bind !== undefined) body.bind = opts.bind;
    return this.json("POST", `/v1/sandboxes/${id}/expose`, body, [201]);
  }
  /** 撤销端口暴露（停止监听器）。 */
  async unexpose(id: string, guestPort: number): Promise<void> {
    await this.json("DELETE", `/v1/sandboxes/${id}/expose/${guestPort}`, undefined, [204, 200]);
  }
  /** 列出某沙箱已暴露端口。 */
  async listExposes(id: string): Promise<any[]> {
    return (await this.json("GET", `/v1/sandboxes/${id}/exposes`)) ?? [];
  }
  /** M2 W6：后端列表与能力集（ADR-14）。 */
  async listBackends(): Promise<any[]> {
    return (await this.json("GET", "/v1/backends")) ?? [];
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
