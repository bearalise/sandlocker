"""SandLocker Python SDK —— 微 VM 沙箱控制面的薄客户端。

零第三方依赖（纯 stdlib）。契约见 contracts/openapi.yaml。

快速上手（需先 `sandlocker up` 起守护）::

    from sandlocker import Sandbox
    with Sandbox.create(template="hello", timeout=300) as sbx:
        print(sbx.run("echo hi").stdout)
        sbx.files.write("/tmp/out.txt", b"payload")
        print(sbx.files.read("/tmp/out.txt"))
    # 退出 with 自动销毁
"""

from .client import Client
from .errors import (
    ApiError,
    ConnectionError,
    NotFound,
    SandLockerError,
)
from .models import ExecResult, SandboxInfo, Template
from .sandbox import FilesProxy, Sandbox

__version__ = "0.1.0"

__all__ = [
    "Sandbox",
    "FilesProxy",
    "Client",
    "Template",
    "ExecResult",
    "SandboxInfo",
    "SandLockerError",
    "ApiError",
    "NotFound",
    "ConnectionError",
    "__version__",
]
