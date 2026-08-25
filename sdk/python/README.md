# SandLocker Python SDK

SandLocker 微 VM 沙箱控制面的 **Python 薄客户端**。纯标准库实现，**零第三方依赖**。

契约权威描述见 [`contracts/openapi.yaml`](../../contracts/openapi.yaml)；本 SDK 逐一镜像其端点。

## 安装

需 Python ≥ 3.8。

```bash
# 方式一：可编辑安装
pip install -e sdk/python

# 方式二：免安装，直接把源码目录加进 PYTHONPATH（单测 / e2e 用这种）
export PYTHONPATH="$PWD/sdk/python/src"
```

## 快速上手

先起守护（另一终端）：

```bash
sandlocker up                                   # = sl-node --serve，默认 127.0.0.1:7878
sandlocker build examples/hello.sandlocker.toml # 预烘焙一个模板（M1：模板 = 快照）
```

然后三行起沙箱、跑命令、取产物（PRD 7.6 手感）：

```python
from sandlocker import Sandbox

with Sandbox.create(template="hello", timeout=300) as sbx:   # timeout → ttl（秒）
    r = sbx.run("echo hi && wc -c < /etc/hostname")          # ExecResult(exit_code, stdout, stderr)
    print(r.stdout, "exit", r.exit_code)

    sbx.files.write("/tmp/out.txt", b"payload")              # 写文件（bytes 或 str）
    data = sbx.files.read("/tmp/out.txt")                    # 读回 bytes

    print(sbx.logs())                                        # 引导/串口日志
# 退出 with 自动销毁（跑完即焚）
```

地址默认 `127.0.0.1:7878`，可用 `Sandbox.create(..., addr="host:port")` 或环境变量
`SANDLOCKER_ADDR`（示例脚本读它）覆盖。

## API 速览

| 调用 | 说明 | REST 端点 |
|---|---|---|
| `Sandbox.create(template, timeout=300, idle=None, cpu=None, mem=None, env=None, addr=...)` | 创建并启动（走快照恢复，秒级） | `POST /v1/sandboxes` |
| `Sandbox.list(addr=...) -> [SandboxInfo]` | 列出沙箱 | `GET /v1/sandboxes` |
| `Sandbox.connect(id, addr=..., verify=True)` | **附着**到已有沙箱拿句柄；`verify=False` 惰性绑定（不打网络，错误延迟到首个操作） | `GET /v1/sandboxes/{id}`（`verify=False` 时不发） |
| `Sandbox.get(id, addr=...)` / `sbx.info()` | 取元数据（`connect` 的校验式别名） | `GET /v1/sandboxes/{id}` |
| `sbx.run(cmd) -> ExecResult` | 跑命令（缓冲式，退出码透传） | `POST /v1/sandboxes/{id}/exec` |
| `sbx.files.write(path, data)` | 写文件 | `PUT /v1/sandboxes/{id}/files/{path}` |
| `sbx.files.read(path) -> bytes` | 读文件 | `GET /v1/sandboxes/{id}/files/{path}` |
| `sbx.logs() -> str` | 取日志 | `GET /v1/sandboxes/{id}/logs` |
| `sbx.kill()` / 退出 `with` | 销毁（幂等） | `DELETE /v1/sandboxes/{id}` |
| `Template.list(addr=...) -> [Template]` | 列模板 | `GET /v1/templates` |

异常：`SandLockerError`（基类）→ `ApiError(status, message)` → `NotFound`（404）；
连不上守护抛 `ConnectionError`。

## 端到端场景

`examples/sdk/` 下有三个用户故事脚本（纯 SDK 调用）：

```bash
sandlocker up &                                            # 起守护
sandlocker build examples/hello.sandlocker.toml
export SANDLOCKER_ADDR=127.0.0.1:7878 PYTHONPATH=sdk/python/src
python3 examples/sdk/us1_quickstart.py    # 创建→跑分析→取产物→空闲自动销毁
python3 examples/sdk/us4_template.py      # 团队模板 + 秒级就绪
python3 examples/sdk/us7_ci_ephemeral.py  # CI 跑不可信测试，退出码透传 + 跑完即焚
```

一键门禁（自动起守护、跑三场景、断言零残留；KVM/python3 缺失则跳过）：

```bash
scripts/verify-sdk-e2e.sh   # 输出 {"metric":"sdk_e2e","pass":true}
```

## M1 边界（诚实说明）

当前里程碑 **M1**，为守住「极简、可审计」的基座，有几处刻意的边界：

- **基座无 Python**：M1 基座 rootfs 是 Alpine busybox + `sl-envd`（PID 1），**不含 Python 解释器**。
  所以 `run("python analysis.py")` 在默认 `hello` 模板下不可用；示例用 busybox shell 命令演示 SDK 面。
- **模板构建离线（deny 网络）**：M1 模板构建 `build_network=deny`（真离线，无 egress），
  因此**无法 `pip install`**。真正的「Python + pandas」团队模板需 **M2** 的 allow-network
  构建（jailer-netns egress 让 RUN 阶段能装依赖），届时 `create(template="python-data")`
  即可直接 `run("python analysis.py")`。
- **`keep_alive`（续期）属 M2**：控制面尚未开 keepalive 端点，故 SDK 无 `keep_alive()`。
  US-1「无活动自动销毁」靠 `create(..., idle=<秒>)` 的**服务端空闲计时**实现（到期自动回收）。
- **exec 为缓冲式**：`run` 命令跑完才返回聚合 stdout/stderr；**流式输出 / PTY** 属 M2。
- **文件读写经 base64 桥接**：`files.write/read` 经守护 + guest `base64` applet 桥接
  （Alpine busybox 自带）；原生大文件 fs 属 M2。

## 契约漂移防线

不引 OpenAPI codegen（延续项目手写惯例）。`client.ROUTES` 收录 SDK 实际调用的
`(method, path)` 集合，`tests/test_sdk.py::test_contract_alignment` 断言它等于据
`openapi.yaml` 手抄的期望集合——契约与 SDK 任一侧改动而未同步，单测即红。

```bash
python3 -m unittest discover -s sdk/python/tests
```
