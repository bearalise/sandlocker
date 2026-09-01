"""手写极简 HTTP 客户端（stdlib http.client），对齐守护的传输约定。

守护（sl-node --serve）是手写 HTTP/1.1：仅 Content-Length + ``Connection: close``，
不支持 chunked/keep-alive（见 contracts/openapi.yaml 头注）。http.client 默认发
``Connection: close`` 之外也能正确读到带 Content-Length 的响应，够用；SDK 全程
零第三方依赖，延续项目「手写 HTTP」惯例（D1 fcapi.rs）。
"""

import http.client
from typing import Optional, Tuple

from .errors import ConnectionError

DEFAULT_ADDR = "127.0.0.1:7878"


def _split_addr(addr):
    """``host:port`` → ``(host, port)``；缺端口默认 7878。"""
    if ":" in addr:
        host, _, port = addr.rpartition(":")
        return host or "127.0.0.1", int(port)
    return addr, 7878


def request(
    method,
    path,
    body=None,
    content_type=None,
    addr=DEFAULT_ADDR,
    timeout=120.0,
    api_key=None,
):
    # type: (str, str, Optional[bytes], Optional[str], str, float, Optional[str]) -> Tuple[int, bytes]
    """发一个请求，返回 ``(status_code, body_bytes)``。

    body 传 bytes（调用方负责编码）；content_type 为空时不带该头。
    api_key 非空则加 ``Authorization: Bearer`` 头（M3 W6 多租户鉴权）。
    连接失败抛 ConnectionError（守护没起 / 地址错）。
    """
    host, port = _split_addr(addr)
    headers = {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    if api_key:
        headers["Authorization"] = "Bearer {}".format(api_key)
    # http.client 会按 body 长度自动补 Content-Length。
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, data
    except (OSError, http.client.HTTPException) as e:
        raise ConnectionError(
            "连接守护 {} 失败：{}（sandlocker up 是否已起？）".format(addr, e)
        )
    finally:
        conn.close()


def request_lines(
    method,
    path,
    body=None,
    content_type=None,
    addr=DEFAULT_ADDR,
    timeout=120.0,
    on_line=None,
    api_key=None,
):
    # type: (str, str, Optional[bytes], Optional[str], str, float, Optional[callable], Optional[str]) -> int
    """发一个请求，**增量**按行读响应体（NDJSON 流式 exec 用），每整行回调 ``on_line(line_str)``。

    守护以 ``Connection: close`` + 无 Content-Length 推流；``HTTPResponse.readline()`` 到 EOF
    即增量读，不像 :func:`request` 那样 ``read()`` 读满才返回。返回 ``status_code``
    （body 已由 on_line 消费）。连接失败抛 ConnectionError。
    """
    host, port = _split_addr(addr)
    headers = {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    if api_key:
        headers["Authorization"] = "Bearer {}".format(api_key)
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        while True:
            raw = resp.readline()
            if not raw:
                break  # EOF：连接关闭
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if line and on_line is not None:
                on_line(line)
        return status
    except (OSError, http.client.HTTPException) as e:
        raise ConnectionError(
            "连接守护 {} 失败：{}（sandlocker up 是否已起？）".format(addr, e)
        )
    finally:
        conn.close()
