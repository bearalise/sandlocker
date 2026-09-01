// 异常层级（对标 sdk/python/src/sandlocker/errors.py）：
//   SandLockerError            —— SDK 错误基类（catch-all）
//   ├── ConnectionError        —— 守护不可达 / 地址错
//   └── ApiError               —— 非预期 HTTP 状态（带 .status/.detail）
//       ├── NotFound           —— HTTP 404
//       ├── Unauthorized       —— HTTP 401（缺/错 API Key，M3 W6）
//       ├── Forbidden          —— HTTP 403（作用域不足 / 跨项目，M3 W6）
//       └── QuotaExceeded      —— HTTP 429（项目配额超限，M3 W7/W10）

export class SandLockerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SandLockerError";
  }
}

export class ConnectionError extends SandLockerError {
  constructor(message: string) {
    super(message);
    this.name = "ConnectionError";
  }
}

export class ApiError extends SandLockerError {
  /** HTTP 状态码 */
  readonly status: number;
  /** 服务端 {"error":...} 文本（Python 侧的 .message）；err.message 为 "HTTP {status}: {detail}"。 */
  readonly detail: string;
  constructor(status: number, detail: string) {
    super(`HTTP ${status}: ${detail}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export class NotFound extends ApiError {
  constructor(status: number, detail: string) {
    super(status, detail);
    this.name = "NotFound";
  }
}

export class Unauthorized extends ApiError {
  constructor(status: number, detail: string) {
    super(status, detail);
    this.name = "Unauthorized";
  }
}

export class Forbidden extends ApiError {
  constructor(status: number, detail: string) {
    super(status, detail);
    this.name = "Forbidden";
  }
}

export class QuotaExceeded extends ApiError {
  constructor(status: number, detail: string) {
    super(status, detail);
    this.name = "QuotaExceeded";
  }
}
