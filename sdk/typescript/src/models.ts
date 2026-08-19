// 数据模型（对标 sdk/python/src/sandlocker/models.py）：宽松反序列化——只取已知字段，
// 全量原始字典留在 raw（前向兼容）。仅反序列化（请求体在 Sandbox/Client 里以普通对象构造）。
import { Client } from "./client.js";
import { DEFAULT_ADDR } from "./http.js";

export class ExecResult {
  constructor(
    readonly exitCode: number,
    readonly stdout: string = "",
    readonly stderr: string = "",
    readonly raw: Record<string, any> = {},
  ) {}
  get ok(): boolean {
    return this.exitCode === 0;
  }
  static fromJson(d: Record<string, any>): ExecResult {
    return new ExecResult(Number(d.exit_code ?? 0), d.stdout ?? "", d.stderr ?? "", { ...d });
  }
}

export class SandboxInfo {
  constructor(
    readonly id: string,
    readonly template: string | null = null,
    readonly vcpus: number | null = null,
    readonly memMib: number | null = null,
    readonly ttlSecs: number | null = null,
    readonly idleSecs: number | null = null,
    readonly createdAt: number | null = null,
    readonly ttlDeadline: number | null = null,
    readonly labels: Record<string, string> = {},
    readonly raw: Record<string, any> = {},
  ) {}
  static fromJson(d: Record<string, any>): SandboxInfo {
    return new SandboxInfo(
      d.id ?? "",
      d.template ?? null,
      d.vcpus ?? null,
      d.mem_mib ?? null,
      d.ttl_secs ?? null,
      d.idle_secs ?? null,
      d.created_at ?? null,
      d.ttl_deadline ?? null,
      d.labels ?? {},
      { ...d },
    );
  }
}

export class Template {
  constructor(
    readonly name: string,
    readonly version: string | null = null,
  ) {}
  static fromJson(d: Record<string, any>): Template {
    return new Template(d.name ?? "", d.version ?? null);
  }
  static async list(opts: { addr?: string; client?: Client } = {}): Promise<Template[]> {
    const c = opts.client ?? new Client(opts.addr ?? DEFAULT_ADDR);
    return (await c.listTemplates()).map((d) => Template.fromJson(d));
  }
}
