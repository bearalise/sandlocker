// 高层 Sandbox（对标 sdk/python/src/sandlocker/sandbox.py）：create/list/get 工厂 +
// run/keepAlive/logs/info/kill 实例操作 + files 读写 + `await using` 跑完即焚。
import { Client } from "./client.js";
import { DEFAULT_ADDR } from "./http.js";
import { ApiError, NotFound } from "./errors.js";
import { ExecResult, SandboxInfo } from "./models.js";

export class FilesProxy {
  constructor(
    private readonly client: Client,
    private readonly sid: string,
  ) {}
  /** 写文件：str（utf-8 编码）或字节。 */
  async write(path: string, data: string | Uint8Array): Promise<void> {
    const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : data;
    await this.client.putFile(this.sid, path, bytes);
  }
  /** 读文件：返回原始字节。 */
  async read(path: string): Promise<Buffer> {
    return this.client.getFile(this.sid, path);
  }
}

export interface CreateOptions {
  /** TTL 绝对存活硬顶（秒，默认 300）——keepalive 续不过。 */
  timeout?: number;
  /** 空闲回收窗（秒，缺省 = 服务端取 ttl）。 */
  idle?: number;
  /** vCPU 数（守护默认 2）。 */
  cpu?: number;
  /** 内存 MiB（守护默认 512）。 */
  mem?: number;
  /** 注入为沙箱 labels/元数据。 */
  env?: Record<string, string>;
  addr?: string;
  client?: Client;
}

export class Sandbox {
  readonly id: string;
  readonly files: FilesProxy;
  private readonly client: Client;
  private readonly meta: Record<string, any>;

  constructor(id: string, client: Client, meta: Record<string, any> = {}) {
    this.id = id;
    this.client = client;
    this.meta = meta;
    this.files = new FilesProxy(client, id);
  }

  static async create(template: string, opts: CreateOptions = {}): Promise<Sandbox> {
    const c = opts.client ?? new Client(opts.addr ?? DEFAULT_ADDR);
    const body: Record<string, unknown> = { template, ttl: Math.trunc(opts.timeout ?? 300) };
    if (opts.idle != null) body.idle = Math.trunc(opts.idle);
    if (opts.cpu != null) body.cpu = Math.trunc(opts.cpu);
    if (opts.mem != null) body.mem = Math.trunc(opts.mem);
    if (opts.env && Object.keys(opts.env).length > 0) body.env = { ...opts.env };
    const resp = await c.createSandbox(body);
    const id = resp?.id;
    if (!id) throw new ApiError(201, `create 响应缺 id: ${JSON.stringify(resp)}`);
    return new Sandbox(id, c, resp);
  }

  static async list(opts: { addr?: string; client?: Client } = {}): Promise<SandboxInfo[]> {
    const c = opts.client ?? new Client(opts.addr ?? DEFAULT_ADDR);
    return (await c.listSandboxes()).map((d) => SandboxInfo.fromJson(d));
  }

  static async get(id: string, opts: { addr?: string; client?: Client } = {}): Promise<Sandbox> {
    const c = opts.client ?? new Client(opts.addr ?? DEFAULT_ADDR);
    const meta = await c.getSandbox(id);
    return new Sandbox(id, c, meta);
  }

  /** 在沙箱内跑一条命令（buffered，非流式）。 */
  async run(cmd: string): Promise<ExecResult> {
    return ExecResult.fromJson(await this.client.exec(this.id, cmd));
  }
  /** 续期：滑窗重置 idle（不动 TTL 硬顶）。返回 {id, lease_deadline, ttl_deadline}。 */
  async keepAlive(): Promise<any> {
    return this.client.keepAlive(this.id);
  }
  async logs(): Promise<string> {
    return this.client.logs(this.id);
  }
  async info(): Promise<SandboxInfo> {
    return SandboxInfo.fromJson(await this.client.getSandbox(this.id));
  }
  /** 销毁（幂等：已消失则吞 NotFound）。 */
  async kill(): Promise<void> {
    try {
      await this.client.deleteSandbox(this.id);
    } catch (e) {
      if (!(e instanceof NotFound)) throw e;
    }
  }

  // create 响应元数据（对标 Python 的 machine_id/total_ms/state 属性）。
  get machineId(): string | undefined {
    return this.meta.machine_id;
  }
  get totalMs(): number | undefined {
    return this.meta.total_ms;
  }
  get state(): string | undefined {
    return this.meta.state;
  }

  /** `await using sbx = await Sandbox.create(...)` → 作用域退出自动 kill（跑完即焚）。 */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.kill();
  }
}
