"""SDK 数据模型（dataclass），字段镜像 contracts/openapi.yaml 的 schemas。

保持「宽松反序列化」：只认已知字段，未知字段进 ``raw`` 保留，避免守护新增字段
就打挂旧 SDK（前向兼容）。
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ExecResult:
    """openapi: ExecResult —— 缓冲式 exec 的聚合结果。"""

    exit_code: int
    stdout: str = ""
    stderr: str = ""

    @classmethod
    def from_json(cls, d):
        return cls(
            exit_code=int(d.get("exit_code", 0)),
            stdout=d.get("stdout", "") or "",
            stderr=d.get("stderr", "") or "",
        )

    @property
    def ok(self):
        """退出码为 0 即成功。"""
        return self.exit_code == 0


@dataclass
class SandboxInfo:
    """openapi: SandboxMeta —— GET /v1/sandboxes[/{id}] 的元数据。"""

    id: str
    template: Optional[str] = None
    vcpus: Optional[int] = None
    mem_mib: Optional[int] = None
    ttl_secs: Optional[int] = None
    idle_secs: Optional[int] = None
    created_at: Optional[int] = None
    ttl_deadline: Optional[int] = None
    labels: Dict[str, str] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, d):
        return cls(
            id=d.get("id", ""),
            template=d.get("template"),
            vcpus=d.get("vcpus"),
            mem_mib=d.get("mem_mib"),
            ttl_secs=d.get("ttl_secs"),
            idle_secs=d.get("idle_secs"),
            created_at=d.get("created_at"),
            ttl_deadline=d.get("ttl_deadline"),
            labels=d.get("labels") or {},
            raw=dict(d),
        )


@dataclass
class Template:
    """openapi: Template —— M1 语义「模板 = 预烘焙快照」。"""

    name: str
    version: Optional[str] = None

    @classmethod
    def from_json(cls, d):
        return cls(name=d.get("name", ""), version=d.get("version"))

    @classmethod
    def list(cls, addr=None, client=None):
        """列出守护已注册的模板（M1：模板 = 预烘焙快照）。

        延迟导入 Client，避免与 client.py 的循环导入。
        """
        from .client import Client
        from ._http import DEFAULT_ADDR

        c = client or Client(addr=addr or DEFAULT_ADDR)
        return [cls.from_json(d) for d in c.list_templates()]
