"""低层 REST 客户端：逐一映射 contracts/openapi.yaml 的端点。

每个方法对应一条 openapi 路由，返回已解析的原生结构（dict/list/bytes/None）。
高层 Sandbox（sandbox.py）在此之上封装产品手感。

契约漂移防线（替代 codegen）：本模块维护 ``ROUTES`` —— SDK 实际调用的
``(method, path_template)`` 集合；tests/test_sdk.py 断言它 == 一份据
openapi.yaml 手抄的期望集合。改了 openapi 却没同步 SDK（或反之）→ 单测红。
"""

import base64
import json
from typing import Any, Dict, List, Optional

from . import _http
import os

from .errors import ApiError, Forbidden, NotFound, QuotaExceeded, Unauthorized

# openapi.yaml 声明、且 M1 已实现的端点全集（method, path_template）。
# 改动此表时，务必同步 contracts/openapi.yaml 与 tests/test_sdk.py 的期望集合。
# 注：/v1/templates:build 在 openapi 中恒返 501（M1 用 CLI build 单发），SDK 不封装它。
ROUTES = frozenset(
    {
        ("POST", "/v1/sandboxes"),
        ("GET", "/v1/sandboxes"),
        ("GET", "/v1/sandboxes/{id}"),
        ("DELETE", "/v1/sandboxes/{id}"),
        ("POST", "/v1/sandboxes/{id}/keepalive"),
        ("POST", "/v1/sandboxes/{id}/exec"),
        ("POST", "/v1/sandboxes/{id}/exec/stream"),
        ("PUT", "/v1/sandboxes/{id}/files/{path}"),
        ("GET", "/v1/sandboxes/{id}/files/{path}"),
        ("GET", "/v1/sandboxes/{id}/logs"),
        ("POST", "/v1/sandboxes/{id}/pause"),
        ("POST", "/v1/sandboxes/{id}/resume"),
        ("POST", "/v1/sandboxes/{id}/fork"),
        ("POST", "/v1/sandboxes/{id}/ticket"),
        ("POST", "/v1/sandboxes/{id}/expose"),
        ("GET", "/v1/sandboxes/{id}/exposes"),
        ("DELETE", "/v1/sandboxes/{id}/expose/{guest_port}"),
        ("GET", "/v1/templates"),
        ("GET", "/v1/backends"),
        ("GET", "/v1/audit"),
    }
)


def _error_for(status, msg):
    """状态码 → 特化异常（404/401/403/429，其余通用 ApiError）。"""
    if status == 404:
        return NotFound(status, msg)
    if status == 401:
        return Unauthorized(status, msg)
    if status == 403:
        return Forbidden(status, msg)
    if status == 429:
        return QuotaExceeded(status, msg)
    return ApiError(status, msg)


def _decode_error(status, body):
    """把错误响应体（openapi Error: {"error": "..."}）解析成异常。"""
    msg = ""
    try:
        msg = json.loads(body.decode("utf-8")).get("error", "")
    except (ValueError, UnicodeDecodeError):
        msg = body.decode("utf-8", "replace")
    return _error_for(status, msg)


class Client:
    """薄 REST 客户端。线程安全（无共享可变状态，每次调用新建连接）。"""

    def __init__(self, addr=_http.DEFAULT_ADDR, timeout=120.0, api_key=None):
        self.addr = addr
        self.timeout = timeout
        # M3 W6 多租户 API Key（Authorization: Bearer）。缺省取环境变量 SANDLOCKER_API_KEY。
        self.api_key = api_key if api_key is not None else os.environ.get("SANDLOCKER_API_KEY")

    # --- 内部 helper ---
    def _json(self, method, path, body_obj=None, expect=(200,)):
        body = None
        ctype = None
        if body_obj is not None:
            body = json.dumps(body_obj).encode("utf-8")
            ctype = "application/json"
        status, data = _http.request(
            method, path, body=body, content_type=ctype,
            addr=self.addr, timeout=self.timeout, api_key=self.api_key,
        )
        if status not in expect:
            raise _decode_error(status, data)
        if not data:
            return None
        return json.loads(data.decode("utf-8"))

    @staticmethod
    def _clean_path(path):
        """guest 文件路径规整：去前导 / （守护路由参数不含前导 /），保留多段。"""
        return path.lstrip("/")

    # --- 沙箱生命周期（POST/GET/DELETE /v1/sandboxes[/{id}]） ---
    def create_sandbox(self, body):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        return self._json("POST", "/v1/sandboxes", body_obj=body, expect=(201,))

    def list_sandboxes(self):
        # type: () -> List[Dict[str, Any]]
        return self._json("GET", "/v1/sandboxes") or []

    def get_sandbox(self, sid):
        # type: (str) -> Dict[str, Any]
        return self._json("GET", "/v1/sandboxes/{}".format(sid))

    def delete_sandbox(self, sid):
        # type: (str) -> None
        status, data = _http.request(
            "DELETE", "/v1/sandboxes/{}".format(sid),
            addr=self.addr, timeout=self.timeout, api_key=self.api_key,
        )
        if status not in (204, 200):
            raise _decode_error(status, data)

    # --- keepalive（POST /v1/sandboxes/{id}/keepalive） ---
    def keep_alive(self, sid):
        # type: (str) -> Dict[str, Any]
        # 续期只滑 idle lease 窗；TTL 绝对硬顶 keepalive 救不了（M2-Q9）。返回 lease/ttl 到期秒。
        return self._json("POST", "/v1/sandboxes/{}/keepalive".format(sid), expect=(200,))

    # --- pause/resume/fork（M2 W9，FR-1.4 / M2-Q5） ---
    def pause(self, sid):
        # type: (str) -> Dict[str, Any]
        # 暂停：落快照停 VM（需后端 pause_resume；如 gVisor 无 → 409 UNSUPPORTED_BY_BACKEND）。
        return self._json("POST", "/v1/sandboxes/{}/pause".format(sid), expect=(200,))

    def resume(self, sid):
        # type: (str) -> Dict[str, Any]
        # 恢复：从快照拉起（reinit 换发新 machine-id/rng/session-key）。
        return self._json("POST", "/v1/sandboxes/{}/resume".format(sid), expect=(200,))

    def fork(self, sid, ttl=None, idle=None):
        # type: (str, int, int) -> Dict[str, Any]
        # 从（已 pause 的）父派生新沙箱（独立身份，需后端 snapshot_fork）。返回新 sandbox（含 forked_from）。
        body = {}
        if ttl is not None:
            body["ttl"] = ttl
        if idle is not None:
            body["idle"] = idle
        return self._json("POST", "/v1/sandboxes/{}/fork".format(sid), body_obj=body, expect=(201,))

    # --- 数据面网关一次性签名 URL（M2 W10，ADR-22 / M2-Q6） ---
    def ticket(self, sid, action, port=None, ttl=None):
        # type: (str, str, int, int) -> Dict[str, Any]
        # 签发一次性 HMAC 签名 URL（action: exec|file|logs|port）。返回 {"url": ...}。
        body = {"action": action}
        if port is not None:
            body["port"] = port
        if ttl is not None:
            body["ttl"] = ttl
        return self._json("POST", "/v1/sandboxes/{}/ticket".format(sid), body_obj=body, expect=(200,))

    # --- 端口暴露（L4 透传持久反代：外部经稳定地址访问 VM 内动态服务，支持完整协议） ---
    def expose(self, sid, port, host_port=None, bind=None):
        # type: (str, int, int, str) -> Dict[str, Any]
        # 暴露 VM 内 port 为稳定地址。返回 {"url","bind","host_port","guest_port"}。仅 FC 后端；
        # 非回环 bind 需守护带 --expose-allow-public。
        body = {"port": port}
        if host_port is not None:
            body["host_port"] = host_port
        if bind is not None:
            body["bind"] = bind
        return self._json("POST", "/v1/sandboxes/{}/expose".format(sid), body_obj=body, expect=(201,))

    def unexpose(self, sid, guest_port):
        # type: (str, int) -> None
        self._json("DELETE", "/v1/sandboxes/{}/expose/{}".format(sid, guest_port), expect=(204,))

    def list_exposes(self, sid):
        # type: (str) -> List[Dict[str, Any]]
        return self._json("GET", "/v1/sandboxes/{}/exposes".format(sid)) or []

    # --- 后端列表与能力集（M2 W6，ADR-14） ---
    def list_backends(self):
        # type: () -> List[Dict[str, Any]]
        return self._json("GET", "/v1/backends") or []

    # --- 审计日志（M3 W7，FR-7.3；鉴权模式按调用者项目过滤，append-only） ---
    def audit(self):
        # type: () -> List[Dict[str, Any]]
        return self._json("GET", "/v1/audit") or []

    # --- exec（POST /v1/sandboxes/{id}/exec） ---
    def exec(self, sid, cmd):
        # type: (str, str) -> Dict[str, Any]
        return self._json(
            "POST", "/v1/sandboxes/{}/exec".format(sid),
            body_obj={"cmd": cmd},
        )

    # --- 流式 exec（POST /v1/sandboxes/{id}/exec/stream） ---
    def exec_stream(self, sid, cmd, on_stdout=None, on_stderr=None):
        # type: (str, str, Optional[callable], Optional[callable], ) -> Dict[str, Any]
        """流式执行：守护以 NDJSON 边跑边推 ``{stream,data(base64)}`` 逐块 + 末行 ``{exit_code}``。

        on_stdout/on_stderr 收到即回调（已 base64 解码为 UTF-8 str）；返回聚合
        ``{exit_code,stdout,stderr}``（与缓冲式 exec 同形，便于复用 ExecResult）。
        """
        agg = {"stdout": [], "stderr": [], "exit_code": 0, "error": None}

        def _on_line(line):
            try:
                ev = json.loads(line)
            except ValueError:
                return  # 容忍非 JSON 行
            if ev.get("stream") == "stdout":
                s = base64.b64decode(ev.get("data", "")).decode("utf-8", "replace")
                agg["stdout"].append(s)
                if on_stdout is not None:
                    on_stdout(s)
            elif ev.get("stream") == "stderr":
                s = base64.b64decode(ev.get("data", "")).decode("utf-8", "replace")
                agg["stderr"].append(s)
                if on_stderr is not None:
                    on_stderr(s)
            elif "exit_code" in ev:
                agg["exit_code"] = ev["exit_code"]
            elif "error" in ev:
                agg["error"] = ev["error"]  # 守护流前错误体 {"error":..}

        status = _http.request_lines(
            "POST", "/v1/sandboxes/{}/exec/stream".format(sid),
            body=json.dumps({"cmd": cmd}).encode("utf-8"),
            content_type="application/json",
            addr=self.addr, timeout=self.timeout, api_key=self.api_key,
            on_line=_on_line,
        )
        if status != 200:
            detail = agg["error"] or "HTTP {}".format(status)
            raise _error_for(status, detail)
        return {
            "exit_code": agg["exit_code"],
            "stdout": "".join(agg["stdout"]),
            "stderr": "".join(agg["stderr"]),
        }

    # --- 文件（PUT/GET /v1/sandboxes/{id}/files/{path}，octet-stream 原始字节） ---
    def put_file(self, sid, path, data):
        # type: (str, str, bytes) -> None
        p = "/v1/sandboxes/{}/files/{}".format(sid, self._clean_path(path))
        status, resp = _http.request(
            "PUT", p, body=data, content_type="application/octet-stream",
            addr=self.addr, timeout=self.timeout, api_key=self.api_key,
        )
        if status not in (204, 200):
            raise _decode_error(status, resp)

    def get_file(self, sid, path):
        # type: (str, str) -> bytes
        p = "/v1/sandboxes/{}/files/{}".format(sid, self._clean_path(path))
        status, data = _http.request(
            "GET", p, addr=self.addr, timeout=self.timeout, api_key=self.api_key,
        )
        if status != 200:
            raise _decode_error(status, data)
        return data

    # --- 日志（GET /v1/sandboxes/{id}/logs，text/plain） ---
    def logs(self, sid):
        # type: (str) -> str
        status, data = _http.request(
            "GET", "/v1/sandboxes/{}/logs".format(sid),
            addr=self.addr, timeout=self.timeout, api_key=self.api_key,
        )
        if status != 200:
            raise _decode_error(status, data)
        return data.decode("utf-8", "replace")

    # --- 模板（GET /v1/templates） ---
    def list_templates(self):
        # type: () -> List[Dict[str, Any]]
        return self._json("GET", "/v1/templates") or []
