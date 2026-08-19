#!/usr/bin/env python3
"""US-1（P1）——Python SDK 三行 create→run→取产物 + 空闲自动销毁。

对应 PRD 7.6 / US-1「数据科学家几行代码起沙箱跑分析、5 分钟无活动自动回收」。
M1 基座是 busybox（无 Python），故 `run` 里跑 shell 命令生成产物；真正的
「python analysis.py + pandas」需 M2 allow-network 构建的模板（见 sdk/python/README.md）。

前置：`sandlocker up` 已起守护。地址取环境变量 SANDLOCKER_ADDR（默认 127.0.0.1:7878）。
文件读写依赖 guest base64 applet；设 SL_SKIP_FILES=1 可跳过该段（e2e 探测缺失时用）。
"""
import os
import sys
import time

# 免安装直接从源码树跑：把 sdk/python/src 加进 sys.path。
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python", "src"))

from sandlocker import Sandbox  # noqa: E402

ADDR = os.environ.get("SANDLOCKER_ADDR", "127.0.0.1:7878")
SKIP_FILES = os.environ.get("SL_SKIP_FILES") == "1"


def main():
    # ① 三行手感：起沙箱 → 跑「分析」→ 取产物。idle=8s → 空闲后服务端自动回收。
    sbx = Sandbox.create(template="hello", timeout=120, idle=8, addr=ADDR)
    print("[US-1] 已创建沙箱 id={} total_ms={}".format(sbx.id, sbx.total_ms))

    # ② 跑「分析」：生成一个产物文件（busybox shell 代替 python analysis.py）。
    r = sbx.run("mkdir -p /work && echo 'analysis-result-42' > /work/out.txt && echo done")
    assert r.ok, "run 失败：exit={} stderr={}".format(r.exit_code, r.stderr)
    assert "done" in r.stdout, "run stdout 异常：{!r}".format(r.stdout)

    # ③ 取产物：优先经 exec 读回（不依赖 base64），再验 SDK 文件 API（依赖 base64 桥接）。
    got = sbx.run("cat /work/out.txt")
    assert "analysis-result-42" in got.stdout, "产物内容不符：{!r}".format(got.stdout)
    print("[US-1] 产物（经 run）：{}".format(got.stdout.strip()))

    if not SKIP_FILES:
        data = sbx.files.read("/work/out.txt")
        assert data.strip() == b"analysis-result-42", "files.read 内容不符：{!r}".format(data)
        sbx.files.write("/work/in.csv", b"col\n1\n2\n")
        back = sbx.files.read("/work/in.csv")
        assert back == b"col\n1\n2\n", "files 往返不符：{!r}".format(back)
        print("[US-1] 文件读写往返 OK（SDK files API）")
    else:
        print("[US-1] 跳过 SDK files API（SL_SKIP_FILES=1）")

    # ④ 空闲自动销毁：不手动 kill，轮询直到该沙箱从列表消失（服务端 idle 回收）。
    print("[US-1] 等待空闲自动回收（idle=8s）...")
    deadline = time.time() + 40
    reclaimed = False
    while time.time() < deadline:
        ids = {s.id for s in Sandbox.list(addr=ADDR)}
        if sbx.id not in ids:
            reclaimed = True
            break
        time.sleep(1)
    assert reclaimed, "沙箱 {} 未在 40s 内被空闲回收".format(sbx.id)

    print("US-1 PASS：create→run→取产物→空闲自动销毁 全通")


if __name__ == "__main__":
    main()
