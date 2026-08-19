#!/usr/bin/env python3
"""US-7（P4）——CI 里跑不可信 PR 测试，跑完即焚。

对应 US-7「GitHub Actions 用沙箱跑不可信 PR 的测试，跑完即销毁、退出码透传给 CI」。
用上下文管理器（`with Sandbox.create(...) as sbx:`）保证：无论测试通过与否，
退出 with 都自动销毁沙箱（跑完即焚）；沙箱内命令的退出码原样透传，CI 据此判红绿。

M1 基座 busybox（无 Python）：用 shell 命令模拟「测试套件」——一条故意失败、一条通过，
以证明退出码透传与失败隔离。真 pytest 需 M2 Python 模板（见 README）。

前置：`sandlocker up`。地址取 SANDLOCKER_ADDR（默认 127.0.0.1:7878）。
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python", "src"))

from sandlocker import Sandbox  # noqa: E402

ADDR = os.environ.get("SANDLOCKER_ADDR", "127.0.0.1:7878")


def main():
    leaked_id = None
    # 跑完即焚：with 退出自动 DELETE，即便中途 assert 抛错也会销毁。
    with Sandbox.create(template="hello", timeout=120, addr=ADDR) as sbx:
        leaked_id = sbx.id
        print("[US-7] CI 沙箱 id={}".format(sbx.id))

        # ① 不可信「测试」失败 → 退出码透传（CI 会据此判红）。
        failing = sbx.run("echo 'running suite' && exit 3")
        print("[US-7] 失败用例 exit_code={} stdout={!r}".format(failing.exit_code, failing.stdout.strip()))
        assert failing.exit_code == 3, "退出码未透传（期望 3，得 {}）".format(failing.exit_code)

        # ② 通过用例 → exit 0；失败不影响后续（隔离）。
        passing = sbx.run("echo 'all green' && exit 0")
        assert passing.ok and "all green" in passing.stdout, "通过用例异常：{!r}".format(passing.stdout)
        print("[US-7] 通过用例 OK")

    # ③ 跑完即焚：退出 with 后沙箱应已销毁，无残留。
    ids = {s.id for s in Sandbox.list(addr=ADDR)}
    assert leaked_id not in ids, "跑完未焚毁：{} 仍在列表".format(leaked_id)

    print("US-7 PASS：不可信测试退出码透传 + 上下文管理器跑完即焚（零残留）")


if __name__ == "__main__":
    main()
