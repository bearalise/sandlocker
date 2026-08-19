#!/usr/bin/env python3
"""US-4（P2）——团队模板 + 秒级就绪。

对应 US-4「团队把『Python + 依赖』固化成模板，成员秒级起就绪环境」。
M1 用 CLI `sandlocker build examples/hello.sandlocker.toml` 预烘焙模板（= 快照）；
本脚本验证：模板已注册（Template.list）+ 从模板起沙箱走快照恢复、秒级就绪。

M1 边界：hello 模板是 busybox（无第三方依赖）。真正的「Python + pandas」团队模板
需 M2 allow-network 构建（jailer-netns egress 让 RUN 阶段能 pip install）——见 README。

前置：`sandlocker up` + 已 build hello 模板。地址取 SANDLOCKER_ADDR（默认 127.0.0.1:7878）。
就绪阈值可用 SL_READY_MS_MAX 覆盖（默认 2000ms，含 CI 抖动余量；这是恢复路径而非冷启动）。
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python", "src"))

from sandlocker import Sandbox, Template  # noqa: E402

ADDR = os.environ.get("SANDLOCKER_ADDR", "127.0.0.1:7878")
READY_MS_MAX = int(os.environ.get("SL_READY_MS_MAX", "2000"))


def main():
    # ① 团队模板已注册（成员开箱即用，无需各自构建环境）。
    tpls = {t.name: t for t in Template.list(addr=ADDR)}
    print("[US-4] 已注册模板：{}".format(sorted(tpls)))
    assert "hello" in tpls, "模板 hello 未注册（先 `sandlocker build examples/hello.sandlocker.toml`）"
    print("[US-4] 模板 hello 版本（内容寻址）：{}".format(tpls["hello"].version))

    # ② 从模板起沙箱：秒级就绪（走快照恢复）。以服务端上报的 total_ms 为准，去掉客户端抖动。
    t0 = time.time()
    sbx = Sandbox.create(template="hello", timeout=120, addr=ADDR)
    wall_ms = int((time.time() - t0) * 1000)
    server_ms = sbx.total_ms
    print("[US-4] 就绪：server total_ms={} wall_ms={}".format(server_ms, wall_ms))
    try:
        # ③ 就绪即可用：立刻能 exec。
        r = sbx.run("echo ready && uname -a")
        assert r.ok and "ready" in r.stdout, "起后不可用：{!r}".format(r.stdout)

        # 秒级就绪断言（以服务端 total_ms 为准；缺失时退回墙钟）。
        measured = server_ms if isinstance(server_ms, int) else wall_ms
        assert measured < READY_MS_MAX, \
            "就绪耗时 {}ms 超阈值 {}ms".format(measured, READY_MS_MAX)
    finally:
        sbx.kill()

    print("US-4 PASS：团队模板已注册 + 从模板秒级就绪（{}ms < {}ms）".format(measured, READY_MS_MAX))


if __name__ == "__main__":
    main()
