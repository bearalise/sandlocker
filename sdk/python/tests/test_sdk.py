"""SandLocker SDK 单测（stdlib unittest，无需 KVM/守护）。

起一个进程内「假 daemon」（http.server 线程）模拟 contracts/openapi.yaml 的路由，
验证 SDK 的请求构造与响应解析正确。覆盖：
  ① create/run/files 往返
  ② 上下文管理器退出触发 DELETE（跑完即焚）
  ③ run exit_code 透传
  ④ 404 → NotFound
  ⑤ 契约对账：client.ROUTES == 据 openapi.yaml 手抄的期望集合

运行：``python3 -m unittest discover -s sdk/python/tests``
（需 PYTHONPATH 含 sdk/python/src，或先 `pip install -e sdk/python`）。
"""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

# 允许直接从源码树跑（免安装）：把 src 加进 sys.path。
_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if os.path.isdir(_SRC):
    sys.path.insert(0, os.path.abspath(_SRC))

from sandlocker import (  # noqa: E402
    ApiError,
    ExecResult,
    NotFound,
    Sandbox,
    Template,
)
from sandlocker.client import ROUTES  # noqa: E402


# --- 假 daemon：进程内实现 openapi 的 M1 端点子集 ---
class _State:
    def __init__(self):
        self.sandboxes = {}   # id -> meta dict
        self.files = {}       # (id, path) -> bytes
        self.counter = 0


class _Handler(BaseHTTPRequestHandler):
    state = None  # 由 fixture 注入

    def log_message(self, *a):  # 静音
        pass

    # --- 响应 helper ---
    def _send(self, status, body=b"", ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj), "application/json")

    def _err(self, status, msg):
        self._json(status, {"error": msg})

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n else b""

    def _segs(self):
        return [s for s in self.path.split("?")[0].split("/") if s]

    # --- 路由分发 ---
    def do_POST(self):
        segs = self._segs()
        body = self._read_body()
        # /v1/sandboxes
        if segs == ["v1", "sandboxes"]:
            req = json.loads(body.decode("utf-8")) if body else {}
            if "template" not in req:
                return self._err(400, "missing template")
            self.state.counter += 1
            sid = "sbx-{}".format(self.state.counter)
            meta = {
                "id": sid,
                "state": "running",
                "machine_id": "mach-{}".format(self.state.counter),
                "template": req["template"],
                "ttl_secs": req.get("ttl"),
                "idle_secs": req.get("idle", req.get("ttl")),
                "total_ms": 123,
                "labels": req.get("env", {}),
            }
            self.state.sandboxes[sid] = meta
            return self._json(201, meta)
        # /v1/sandboxes/{id}/keepalive
        if len(segs) == 4 and segs[:2] == ["v1", "sandboxes"] and segs[3] == "keepalive":
            sid = segs[2]
            meta = self.state.sandboxes.get(sid)
            if meta is None:
                return self._err(404, "no such sandbox")
            # 续期滑 idle 窗（模拟）；TTL 硬顶不动。
            return self._json(
                200,
                {"id": sid, "lease_deadline": 1000, "ttl_deadline": meta.get("ttl_secs")},
            )
        # /v1/sandboxes/{id}/exec
        if len(segs) == 4 and segs[:2] == ["v1", "sandboxes"] and segs[3] == "exec":
            sid = segs[2]
            if sid not in self.state.sandboxes:
                return self._err(404, "no such sandbox")
            req = json.loads(body.decode("utf-8")) if body else {}
            cmd = req.get("cmd", "")
            # 约定：`exit N` → 透传退出码 N（模拟 guest sh -c 行为）；否则回显。
            if cmd.strip().startswith("exit "):
                try:
                    code = int(cmd.strip().split()[1])
                except (ValueError, IndexError):
                    code = 0
                return self._json(200, {"exit_code": code, "stdout": "", "stderr": ""})
            return self._json(200, {"exit_code": 0, "stdout": cmd + "\n", "stderr": ""})
        return self._err(404, "no route")

    def do_GET(self):
        segs = self._segs()
        if segs == ["v1", "sandboxes"]:
            return self._json(200, list(self.state.sandboxes.values()))
        if segs == ["v1", "templates"]:
            return self._json(200, [{"name": "hello", "version": "v-test"}])
        if len(segs) >= 4 and segs[:2] == ["v1", "sandboxes"] and segs[3] == "files":
            sid = segs[2]
            path = "/".join(segs[4:])
            data = self.state.files.get((sid, path))
            if data is None:
                return self._err(500, "no such file")
            return self._send(200, data, "application/octet-stream")
        if len(segs) == 4 and segs[:2] == ["v1", "sandboxes"] and segs[3] == "logs":
            sid = segs[2]
            if sid not in self.state.sandboxes:
                return self._err(404, "no such sandbox")
            return self._send(200, "boot ok\nconsole line\n", "text/plain")
        if len(segs) == 3 and segs[:2] == ["v1", "sandboxes"]:
            sid = segs[2]
            meta = self.state.sandboxes.get(sid)
            if meta is None:
                return self._err(404, "no such sandbox")
            return self._json(200, meta)
        return self._err(404, "no route")

    def do_PUT(self):
        segs = self._segs()
        body = self._read_body()
        if len(segs) >= 4 and segs[:2] == ["v1", "sandboxes"] and segs[3] == "files":
            sid = segs[2]
            path = "/".join(segs[4:])
            self.state.files[(sid, path)] = body
            return self._send(204, b"")
        return self._err(404, "no route")

    def do_DELETE(self):
        segs = self._segs()
        if len(segs) == 3 and segs[:2] == ["v1", "sandboxes"]:
            sid = segs[2]
            if sid not in self.state.sandboxes:
                return self._err(404, "no such sandbox")
            del self.state.sandboxes[sid]
            return self._send(204, b"")
        return self._err(404, "no route")


class FakeDaemon:
    """上下文管理器：起假 daemon 线程，暴露 addr。"""

    def __init__(self):
        self.state = _State()
        handler = type("H", (_Handler,), {"state": self.state})
        self.httpd = HTTPServer(("127.0.0.1", 0), handler)
        self.addr = "127.0.0.1:{}".format(self.httpd.server_address[1])

    def __enter__(self):
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


class SdkTest(unittest.TestCase):
    def test_create_run_files_roundtrip(self):
        with FakeDaemon() as d:
            sbx = Sandbox.create(template="hello", timeout=60, idle=3, addr=d.addr)
            self.assertTrue(sbx.id)
            self.assertEqual(sbx.state, "running")
            self.assertEqual(sbx.total_ms, 123)
            # run 回显
            r = sbx.run("echo hi")
            self.assertIsInstance(r, ExecResult)
            self.assertTrue(r.ok)
            self.assertIn("echo hi", r.stdout)
            # 文件往返（str 与 bytes 都测）
            sbx.files.write("/tmp/out.txt", "payload-数据")
            self.assertEqual(sbx.files.read("/tmp/out.txt"), "payload-数据".encode("utf-8"))
            sbx.files.write("tmp/bin.dat", b"\x00\x01\x02")  # 无前导 / 也可
            self.assertEqual(sbx.files.read("/tmp/bin.dat"), b"\x00\x01\x02")
            # logs
            self.assertIn("console line", sbx.logs())
            sbx.kill()

    def test_context_manager_auto_destroy(self):
        with FakeDaemon() as d:
            with Sandbox.create(template="hello", timeout=60, addr=d.addr) as sbx:
                sid = sbx.id
                self.assertIn(sid, d.state.sandboxes)
            # 退出 with 后应已 DELETE
            self.assertNotIn(sid, d.state.sandboxes)

    def test_exit_code_passthrough(self):
        with FakeDaemon() as d:
            with Sandbox.create(template="hello", addr=d.addr) as sbx:
                self.assertEqual(sbx.run("exit 7").exit_code, 7)
                self.assertEqual(sbx.run("exit 0").exit_code, 0)
                self.assertFalse(sbx.run("exit 1").ok)

    def test_list_and_get(self):
        with FakeDaemon() as d:
            a = Sandbox.create(template="hello", addr=d.addr)
            b = Sandbox.create(template="hello", addr=d.addr)
            ids = {s.id for s in Sandbox.list(addr=d.addr)}
            self.assertEqual(ids, {a.id, b.id})
            info = Sandbox.get(a.id, addr=d.addr).info()
            self.assertEqual(info.id, a.id)
            self.assertEqual(info.template, "hello")
            a.kill()
            b.kill()

    def test_templates_list(self):
        with FakeDaemon() as d:
            tpls = Template.list(addr=d.addr)
            self.assertEqual([t.name for t in tpls], ["hello"])
            self.assertEqual(tpls[0].version, "v-test")

    def test_not_found_maps_to_exception(self):
        with FakeDaemon() as d:
            with self.assertRaises(NotFound):
                Sandbox.get("nope", addr=d.addr).info()
        # NotFound 是 ApiError 的子类（调用方可只 except ApiError）
        self.assertIsInstance(NotFound(404, "x"), ApiError)

    def test_kill_is_idempotent(self):
        with FakeDaemon() as d:
            sbx = Sandbox.create(template="hello", addr=d.addr)
            sbx.kill()
            sbx.kill()  # 第二次不应抛（NotFound 被吞）

    def test_keep_alive_renews_lease(self):
        with FakeDaemon() as d:
            with Sandbox.create(template="hello", timeout=300, idle=5, addr=d.addr) as sbx:
                r = sbx.keep_alive()
                self.assertEqual(r["id"], sbx.id)
                self.assertIn("lease_deadline", r)
                self.assertIn("ttl_deadline", r)
                # TTL 硬顶（=create 的 timeout）透传，keepalive 不动它。
                self.assertEqual(r["ttl_deadline"], 300)

    def test_keep_alive_unknown_is_not_found(self):
        from sandlocker.client import Client
        with FakeDaemon() as d:
            # 直接构造句柄（跳过 GET 校验），令 keepalive 自身命中 404。
            sbx = Sandbox("nope", Client(addr=d.addr))
            with self.assertRaises(NotFound):
                sbx.keep_alive()

    def test_contract_alignment(self):
        # 据 contracts/openapi.yaml 手抄的 M1 已实现端点全集。
        # 改 openapi 或 SDK 路由时，两处 + client.ROUTES 必须同步，否则此测试红。
        expected = frozenset(
            {
                ("POST", "/v1/sandboxes"),                    # createSandbox
                ("GET", "/v1/sandboxes"),                     # listSandboxes
                ("GET", "/v1/sandboxes/{id}"),                # getSandbox
                ("DELETE", "/v1/sandboxes/{id}"),             # deleteSandbox
                ("POST", "/v1/sandboxes/{id}/keepalive"),     # keepAliveSandbox
                ("POST", "/v1/sandboxes/{id}/exec"),          # execInSandbox
                ("PUT", "/v1/sandboxes/{id}/files/{path}"),   # putFile
                ("GET", "/v1/sandboxes/{id}/files/{path}"),   # getFile
                ("GET", "/v1/sandboxes/{id}/logs"),           # getLogs
                ("POST", "/v1/sandboxes/{id}/pause"),         # pauseSandbox (M2 W9)
                ("POST", "/v1/sandboxes/{id}/resume"),        # resumeSandbox (M2 W9)
                ("POST", "/v1/sandboxes/{id}/fork"),          # forkSandbox (M2 W9)
                ("POST", "/v1/sandboxes/{id}/ticket"),        # mintTicket (M2 W10)
                ("POST", "/v1/sandboxes/{id}/expose"),        # exposePort (L4 透传)
                ("GET", "/v1/sandboxes/{id}/exposes"),        # listExposes
                ("DELETE", "/v1/sandboxes/{id}/expose/{guest_port}"),  # unexposePort
                ("GET", "/v1/templates"),                     # listTemplates
                ("GET", "/v1/backends"),                      # listBackends (M2 W6)
                # 注：POST /v1/templates:build 在 M1 恒返 501，SDK 不封装，故不在此集合。
            }
        )
        self.assertEqual(ROUTES, expected)


if __name__ == "__main__":
    unittest.main()
