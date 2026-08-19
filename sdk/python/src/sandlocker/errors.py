"""SandLocker SDK 异常层。

对齐 contracts/openapi.yaml 的错误约定：控制面出错时返回
``{"error": "..."}``（components.schemas.Error）。SDK 把 HTTP 状态码映射成
下列异常，调用方 ``except SandLockerError`` 即可兜底所有 SDK 错误。
"""


class SandLockerError(Exception):
    """所有 SDK 错误的基类。"""


class ConnectionError(SandLockerError):
    """连不上守护（sandlocker up / sl-node --serve 未起，或地址错）。"""


class ApiError(SandLockerError):
    """守护返回了非预期状态码。

    ``status`` 为 HTTP 状态码，``message`` 取自响应体的 ``error`` 字段（若有）。
    """

    def __init__(self, status, message):
        self.status = status
        self.message = message
        super().__init__("HTTP {}: {}".format(status, message))


class NotFound(ApiError):
    """沙箱 / 资源不存在（HTTP 404）。"""
