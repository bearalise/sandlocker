// SandLocker TypeScript SDK 公共入口（对标 sdk/python/src/sandlocker/__init__.py）。
export { Client, ROUTES } from "./client.js";
export { Sandbox, FilesProxy } from "./sandbox.js";
export type { CreateOptions } from "./sandbox.js";
export { ExecResult, SandboxInfo, Template } from "./models.js";
export { SandLockerError, ConnectionError, ApiError, NotFound } from "./errors.js";
export { DEFAULT_ADDR } from "./http.js";

export const VERSION = "0.2.1";
