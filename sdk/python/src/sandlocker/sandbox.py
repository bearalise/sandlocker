"""高层产品 API：``Sandbox`` —— PRD 7.6 的三行手感。

    from sandlocker import Sandbox
    with Sandbox.create(template="hello", timeout=300) as sbx:
        r = sbx.run("echo hi")
        sbx.files.write("/tmp/out.txt", b"payload")
        data = sbx.files.read("/tmp/out.txt")
    # 退出 with 自动销毁（跑完即焚 = US-7）

M1 边界：run 在 guest 走 busybox ``/bin/sh -c``（基座无 Python，见 README）。
M2 W2：``keep_alive`` 续期端点已上线——在线滑 idle lease 窗；TTL 绝对硬顶 keepalive 救不了。
"""

from typing import Any, Dict, List, Optional, Union

from ._http import DEFAULT_ADDR
from .client import Client
from .models import ExecResult, SandboxInfo


class FilesProxy:
    """``sbx.files.write/read`` —— 经守护 base64 桥接读写 guest 文件。

    write 收 bytes 或 str（str 按 utf-8 编码）；read 返 bytes。
    """

    def __init__(self, client, sid):
        self._client = client
        self._sid = sid

    def write(self, path, data):
        # type: (str, Union[bytes, str]) -> None
        if isinstance(data, str):
            data = data.encode("utf-8")
        self._client.put_file(self._sid, path, data)

    def read(self, path):
        # type: (str) -> bytes
        return self._client.get_file(self._sid, path)


class Sandbox:
    """一个运行中的沙箱句柄。"""

    def __init__(self, sid, client, meta=None):
        # type: (str, Client, Optional[Dict[str, Any]]) -> None
        self.id = sid
        self._client = client
        self._meta = meta or {}
        self.files = FilesProxy(client, sid)

    # --- 工厂 ---
    @classmethod
    def create(
        cls,
        template,
        timeout=300,
        idle=None,
        cpu=None,
        mem=None,
        env=None,
        addr=DEFAULT_ADDR,
        client=None,
    ):
        # type: (...) -> "Sandbox"
        """创建并启动沙箱（走快照恢复，~秒级）。

        template: 已注册模板名（经 template/<name>/latest 解析）。
        timeout : 绝对存活硬顶（秒）→ 映射 openapi 的 ttl。
        idle    : 空闲回收窗口（秒），缺省 = ttl（服务端语义）。
        cpu/mem : vCPU 数 / 内存 MiB，缺省用守护默认（2 / 512）。
        env     : dict[str,str]，注入为沙箱 labels/元数据。
        """
        c = client or Client(addr=addr)
        body = {"template": template, "ttl": int(timeout)}
        if idle is not None:
            body["idle"] = int(idle)
        if cpu is not None:
            body["cpu"] = int(cpu)
        if mem is not None:
            body["mem"] = int(mem)
        if env:
            body["env"] = dict(env)
        resp = c.create_sandbox(body)
        sid = resp.get("id")
        if not sid:
            from .errors import ApiError
            raise ApiError(201, "create 响应缺 id：{}".format(resp))
        return cls(sid, c, meta=resp)

    @classmethod
    def list(cls, addr=DEFAULT_ADDR, client=None):
        # type: (...) -> List[SandboxInfo]
        c = client or Client(addr=addr)
        return [SandboxInfo.from_json(d) for d in c.list_sandboxes()]

    @classmethod
    def connect(cls, sid, addr=DEFAULT_ADDR, client=None, verify=True):
        # type: (str, str, Optional[Client], bool) -> "Sandbox"
        """附着（attach）到已存在的沙箱以便后续操作（run/keep_alive/logs/files/...）。

        典型场景：沙箱由别处（另一进程/请求/``sandlocker up`` 会话）创建，此处只按 id 重拿句柄。

        verify=True（默认）：做一次 ``GET /v1/sandboxes/{id}`` 校验存在并填充元数据
                            （不存在 → NotFound）。
        verify=False       ：惰性绑定，**不打任何网络**，立即返回句柄，错误延迟到首个真实操作。
        """
        c = client or Client(addr=addr)
        if not verify:
            return cls(sid, c)
        meta = c.get_sandbox(sid)
        return cls(sid, c, meta=meta)

    @classmethod
    def get(cls, sid, addr=DEFAULT_ADDR, client=None):
        # type: (...) -> "Sandbox"
        """connect 的校验式别名（总是往返一次拉取元数据）。"""
        return cls.connect(sid, addr=addr, client=client, verify=True)

    # --- 操作 ---
    def run(self, cmd):
        # type: (str) -> ExecResult
        """在沙箱内跑命令（缓冲式，返 exit/stdout/stderr）。

        cmd 直接交给 guest ``/bin/sh -c``；退出码原样透传（run("exit 7").exit_code == 7）。
        """
        return ExecResult.from_json(self._client.exec(self.id, cmd))

    def keep_alive(self):
        # type: () -> Dict[str, Any]
        """续期：在线滑 idle lease 窗，避免被空闲回收。

        **不**延长 TTL 绝对硬顶——过硬顶 keep_alive 救不了（M2-Q9）。
        返回 ``{"id", "lease_deadline", "ttl_deadline"}``（unix 秒）。
        """
        return self._client.keep_alive(self.id)

    def logs(self):
        # type: () -> str
        return self._client.logs(self.id)

    def info(self):
        # type: () -> SandboxInfo
        return SandboxInfo.from_json(self._client.get_sandbox(self.id))

    def kill(self):
        # type: () -> None
        """销毁沙箱（杀进程 + 清目录 + 删 store 键）。幂等：已不存在则静默。"""
        from .errors import NotFound
        try:
            self._client.delete_sandbox(self.id)
        except NotFound:
            pass

    # --- 元数据快捷访问（来自 create 响应） ---
    @property
    def machine_id(self):
        return self._meta.get("machine_id")

    @property
    def total_ms(self):
        """create 端到端耗时（ms），服务端上报。"""
        return self._meta.get("total_ms")

    @property
    def state(self):
        return self._meta.get("state")

    # --- 上下文管理器（跑完即焚） ---
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.kill()
        return False

    def __repr__(self):
        return "Sandbox(id={!r}, addr={!r})".format(self.id, self._client.addr)
