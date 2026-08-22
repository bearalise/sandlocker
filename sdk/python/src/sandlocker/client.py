"""低层 REST 客户端：逐一映射 contracts/openapi.yaml 的端点。

每个方法对应一条 openapi 路由，返回已解析的原生结构（dict/list/bytes/None）。
高层 Sandbox（sandbox.py）在此之上封装产品手感。

契约漂移防线（替代 codegen）：本模块维护 ``ROUTES`` —— SDK 实际调用的
``(method, path_template)`` 集合；tests/test_sdk.py 断言它 == 一份据
openapi.yaml 手抄的期望集合。改了 openapi 却没同步 SDK（或反之）→ 单测红。
"""

import json
from typing import Any, Dict, List, Optional

from . import _http
from .errors import ApiError, NotFound

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
    }
)


def _decode_error(status, body):
    """把错误响应体（openapi Error: {"error": "..."}）解析成异常。"""
    msg = ""
    try:
        msg = json.loads(body.decode("utf-8")).get("error", "")
    except (ValueError, UnicodeDecodeError):
        msg = body.decode("utf-8", "replace")
    if status == 404:
        return NotFound(status, msg)
    return ApiError(status, msg)


class Client:
    """薄 REST 客户端。线程安全（无共享可变状态，每次调用新建连接）。"""

    def __init__(self, addr=_http.DEFAULT_ADDR, timeout=120.0):
        self.addr = addr
        self.timeout = timeout

    # --- 内部 helper ---
    def _json(self, method, path, body_obj=None, expect=(200,)):
        body = None
        ctype = None
        if body_obj is not None:
            body = json.dumps(body_obj).encode("utf-8")
            ctype = "application/json"
        status, data = _http.request(
            method, path, body=body, content_type=ctype,
            addr=self.addr, timeout=self.timeout,
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
            addr=self.addr, timeout=self.timeout,
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

    # --- exec（POST /v1/sandboxes/{id}/exec） ---
    def exec(self, sid, cmd):
        # type: (str, str) -> Dict[str, Any]
        return self._json(
            "POST", "/v1/sandboxes/{}/exec".format(sid),
            body_obj={"cmd": cmd},
        )

    # --- 文件（PUT/GET /v1/sandboxes/{id}/files/{path}，octet-stream 原始字节） ---
    def put_file(self, sid, path, data):
        # type: (str, str, bytes) -> None
        p = "/v1/sandboxes/{}/files/{}".format(sid, self._clean_path(path))
        status, resp = _http.request(
            "PUT", p, body=data, content_type="application/octet-stream",
            addr=self.addr, timeout=self.timeout,
        )
        if status not in (204, 200):
            raise _decode_error(status, resp)

    def get_file(self, sid, path):
        # type: (str, str) -> bytes
        p = "/v1/sandboxes/{}/files/{}".format(sid, self._clean_path(path))
        status, data = _http.request(
            "GET", p, addr=self.addr, timeout=self.timeout,
        )
        if status != 200:
            raise _decode_error(status, data)
        return data

    # --- 日志（GET /v1/sandboxes/{id}/logs，text/plain） ---
    def logs(self, sid):
        # type: (str) -> str
        status, data = _http.request(
            "GET", "/v1/sandboxes/{}/logs".format(sid),
            addr=self.addr, timeout=self.timeout,
        )
        if status != 200:
            raise _decode_error(status, data)
        return data.decode("utf-8", "replace")

    # --- 模板（GET /v1/templates） ---
    def list_templates(self):
        # type: () -> List[Dict[str, Any]]
        return self._json("GET", "/v1/templates") or []
