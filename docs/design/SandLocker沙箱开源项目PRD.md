# SandLocker — 安全代码执行沙箱开源项目 PRD

| 项目 | 内容 |
| --- | --- |
| 文档版本 | v1.2 |
| 状态 | 已评审，开放问题全部闭环（Ready for M0）；v1.2 为评审后实施性修订（见 14.1 第二轮） |
| 文档类型 | 产品需求文档（PRD） |
| 项目代号 | SandLocker（由 SandCore 更名——原名存在撞名；正式发布前仍需完成域名/商标检索，见 14.2） |
| 目标读者 | 核心贡献者、平台工程师、AI Infra 团队、潜在社区用户 |
| 日期 | 2026-08-01 |

> 说明：本项目定位为「自研隔离层 + 完整沙箱平台」双轨形态（类 gVisor 的运行时能力 + 类 e2b 的平台能力），技术路线在本文第 6 章做对比选型并给出推荐结论。

---

## 1. 背景与机遇

### 1.1 为什么是现在

2025–2026 年，AI Agent 与代码生成应用爆发，"安全地执行不可信代码"从边缘需求变成基础设施刚需：

- **AI 代码执行成为标准组件**：LLM 生成的代码需要一个受控环境运行。任何读取邮件、网页、文档的 Agent 都在执行"间接不可信输入"——攻击者可以通过提示注入让 Agent 生成恶意代码（如数据外传命令），如果执行环境只是普通 Docker 容器，共享内核意味着一次逃逸危及整台宿主机上的所有租户 [^23^][^19^]。
- **Linux 内核每年披露 300+ CVE**，共享内核容器模型在面对真正不可信代码时存在系统性风险；runc 逃逸漏洞 CVE-2019-5736 已在生产环境中被实际利用 [^23^]。
- **市场验证充分**：AWS Lambda/Fargate 跑在 Firecracker 上，Google Cloud Run/GKE 用 gVisor，e2b 以 Firecracker microVM 提供 78ms（p50，2026 年 1 月数据）的沙箱创建 [^1^]，Daytona 用 Docker 做到 sub-90ms 冷启动并获 2400 万美元 A 轮融资，Runloop 获 700 万美元种子轮，Cloudflare 于 2026 年 4 月将其 Sandbox 产品 GA [^21^][^12^]。Kubernetes 社区甚至出现了官方的 `agent-sandbox` 子项目（SIG Apps，2026 年 7 月已发布 v0.5.2） [^16^]。
- **但开源生态仍有明显空缺**：e2b 虽开源，但定位是"自家云服务的可自部署版本"，架构与自家编排深度耦合；gVisor 只是运行时，不提供平台层（模板、SDK、快照、调度）。**没有一个社区主导的、隔离层与平台层均一流、且以可插拔架构设计的开源沙箱项目。** 这正是 SandLocker 的机会窗口。

### 1.2 问题陈述

今天想安全运行不可信代码的团队，面临三个不满意的选择：

1. **自建**：直接基于 Firecracker 搭建需要"变成一家虚拟化公司"——内核镜像管理、网络编排、Jailer 配置、VM 生命周期工具全都要自己写 [^22^]。
2. **买 SaaS**：e2b/Modal/Runloop 等托管服务带来数据出境、合规、成本与供应商锁定问题。
3. **将就用容器**：普通 Docker/runc 共享宿主机内核，不满足多租户不可信代码的威胁模型 [^19^]。

### 1.3 产品愿景

> **让任何团队都能用一条命令，在自己的基础设施上启动毫秒级、内核级隔离的代码执行沙箱。**

SandLocker = **可插拔的强隔离运行时层** + **开发者友好的沙箱平台层**，全部开源、自部署优先（self-host first）、云中立。

---

## 2. 竞品分析

### 2.1 主要竞品全景

| 产品 | 隔离技术 | 冷启动 | 持久化 | 开源 | 定位 |
| --- | --- | --- | --- | --- | --- |
| **e2b** | Firecracker microVM | ~78ms（p50 创建） / ~150ms（第三方测量） | 短暂为主，Pro 最长 24h 会话 | 是（含基础设施，Terraform 化） | AI 代码执行沙箱云服务，SDK 成熟，Fortune 500 生产在用 [^1^][^12^][^24^] |
| **Daytona** | Docker 容器（共享内核） | sub-90ms | 有限 | 是 | 从开发环境管理转型 AI Agent 基础设施 [^12^] |
| **Modal** | gVisor 容器 | 300–500ms | 无（函数式） | 否 | Python 优先的 Serverless/GPU 工作负载 [^12^][^16^] |
| **Northflank** | microVM（Firecracker/Kata 可选） | 可调 | 有（有状态、会话时长无限） | 否 | 生产级 AI Infra，BYOC/VPC 完整支持 [^24^] |
| **Runloop** | —（企业级沙箱） | — | — | 否 | 面向 AI Coding Agent 的企业级沙箱 [^21^] |
| **Cloudflare Sandbox** | 容器（边缘网络） | 快 | — | 否 | 与 Workers/边缘生态绑定，2026 年 4 月 GA [^21^] |
| **Fly.io Sprites** | 持久化 VM | 1–2s | 完整文件系统 | 否 | 长运行有状态 Agent [^12^] |
| **Freestyle** | 完整 Linux VM | ~800ms | 磁盘休眠 | 否 | Root 权限、嵌套虚拟化场景 [^12^] |
| **gVisor**（组件） | 用户态内核 | 50–100ms | — | 是 | 运行时组件，无平台层 [^17^] |
| **Firecracker**（组件） | KVM microVM | <125ms，每实例 <5MiB 额外内存 | 快照/恢复 | 是 | VMM 组件，无平台层 [^16^][^17^] |
| **Kata Containers**（组件） | 完整 VMM（QEMU/Cloud Hypervisor/Firecracker） | 150–300ms | — | 是 | K8s 原生 VM 隔离 RuntimeClass [^17^][^16^] |
| **k8s agent-sandbox**（组件） | gVisor 默认，Kata 可插拔 | — | — | 是 | K8s SIG Apps 子项目，提供 Sandbox/SandboxTemplate/SandboxClaim CRD [^16^] |

### 2.2 竞品启示与差异化机会

1. **隔离强度与速度不是零和**：Firecracker 已证明 <125ms 冷启动 + 硬件级隔离可以兼得 [^17^]。Daytona 的 sub-90ms 是靠牺牲隔离（共享内核 Docker）换来的 [^12^]——SandLocker 不应在这条路上竞争。
2. **可插拔是被验证的方向**：Kubernetes 官方 agent-sandbox 项目默认 gVisor、Kata 可插拔 [^16^]，说明"运行时后端可替换"是行业共识。但目前没有项目把"可插拔隔离后端 + 完整平台（模板/SDK/快照）"做成一体。
3. **e2b 的留白**：e2b 开源版与自家云服务耦合，沙箱会话偏短（典型 5–10 分钟，Pro 最长 24h）[^24^]。长会话、有状态 Agent、GPU 工作负载是其弱项。
4. **GPU 是分水岭**：gVisor 原生支持 GPU/TPU，Firecracker 精简设备模型没有现成 PCI 直通 [^16^]。多数竞品中仅一家支持 GPU [^12^]。可插拔架构可以让 GPU 场景走 gVisor/Kata 后端，通用场景走 microVM 后端——这是 SandLocker 的独特卖点。

**SandLocker 差异化定位**：

| 维度 | e2b | gVisor | SandLocker |
| --- | --- | --- | --- |
| 隔离运行时 | 仅 Firecracker | 仅用户态内核 | **可插拔：Firecracker / gVisor / Kata（可自研扩展）** |
| 平台层（模板/SDK/快照/调度） | 有 | 无 | **有，且自部署一等公民** |
| 部署模式 | 云优先，开源自部署次之 | 组件嵌入 | **自部署优先，单机到集群** |
| GPU 工作负载 | 弱 | 强 | **按后端可选** |
| 治理 | 公司主导 | Google 主导 | **社区治理（目标捐赠基金会）** |

---

## 3. 目标用户与核心场景

### 3.1 用户画像（Persona）

| 画像 | 描述 | 核心诉求 |
| --- | --- | --- |
| **P1 Agent 开发者** | 构建 AI Coding Agent / 数据分析 Agent / RAG 应用的工程师 | SDK 好用、冷启动快、沙箱内能跑命令和读写文件、会话可暂停恢复 |
| **P2 平台/基础设施工程师** | 为团队搭建内部代码执行平台 | 自部署简单、可观测、多租户隔离、资源配额、API 完整 |
| **P3 安全合规团队** | 金融/医疗/政企，需运行不可信代码 | 硬件级隔离证明、网络出口管控、审计日志、私有化部署 |
| **P4 CI/CD 维护者** | PR 检查、不可信构建、AI 代码评审流水线 | 与 GitHub Actions 等集成、按量启停、成本可控 [^1^] |
| **P5 运行时研究者/嵌入式用户** | 只要隔离层，嵌入自己的系统（如 K8s RuntimeClass、CI Runner） | 组件可独立使用、OCI 兼容、文档清晰 |

### 3.2 核心场景（User Stories）

- **US-1（P1）**：作为 Agent 开发者，我用 Python SDK 三行代码创建沙箱，在里面执行 LLM 生成的代码并拿到 stdout/文件产物，沙箱 5 分钟无活动自动销毁。
- **US-2（P1）**：我的 Agent 任务跨多轮对话，我需要把沙箱快照暂停，用户回来后 100ms 内恢复到之前状态继续。
- **US-3（P2）**：我在公司 3 台裸金属机器上用 `sandlocker cluster init` 搭起沙箱集群，给每个团队分配 API Key 和 CPU/内存/并发配额。
- **US-4（P2）**：我用模板系统把"Python 3.12 + pandas + 内部私有包"构建成团队模板，团队成员创建沙箱直接基于该模板，秒级就绪。
- **US-5（P3）**：安全团队要求所有沙箱默认无网络出口，仅白名单域名可访问；所有 exec 与文件操作留存审计日志。
- **US-6（P3）**：合规要求"VM 级内核隔离"，我配置后端为 Firecracker，并能为 GPU 推理任务单独指定 gVisor 后端。
- **US-7（P4）**：GitHub Actions 工作流里调用 SandLocker 跑不可信 PR 的测试，跑完即焚。
- **US-8（P5）**：我把 SandLocker 的隔离运行时作为 OCI Runtime 接入自己的 containerd/K8s 集群，不使用平台层。

---

## 4. 产品范围与形态

### 4.1 双轨形态（对应"两者兼有"决策）

```
┌─────────────────────────────────────────────────────────────┐
│                    平台层（SandLocker Platform）                 │
│  API Server │ 调度编排 │ 模板构建 │ 快照服务 │ SDK │ CLI │ 控制台(V1外) │
├─────────────────────────────────────────────────────────────┤
│                 运行时层（SandLocker Runtime）                   │
│   统一沙箱抽象（Sandbox ABI）                                   │
│   ├── 后端：Firecracker（microVM，默认）                        │
│   ├── 后端：gVisor 风格用户态内核（第二阶段自研，见 6.3）          │
│   └── 后端：Kata（K8s 生态兼容）                                │
└─────────────────────────────────────────────────────────────┘
```

- **运行时层可独立使用**：提供 OCI Runtime 接口（`sandlocker-runsc`），可被 Docker/containerd/K8s RuntimeClass 直接调用（满足 P5）。
- **平台层构建在运行时层之上**：通过统一的 Sandbox ABI 与后端解耦（满足 P1–P4）。
- **控制台 M3 scoped 偏离（2026-08-31）**：上图 `控制台(V1外)` 指**完整操作面**（创建/销毁/Key/配额的图形化操作），仍留 GA 后/商业化。M3 部分回拉**只读监控看板**（Grafana 策展，骑可观测性 §7.8，支撑 M3「5 团队试用」体验），完整操作面不回拉。详见砍单预案第 2 项注、docs/design/M3技术计划.md §4 D6。

### 4.2 范围边界（V1 不做什么）

- ❌ 不做托管云服务（开源项目阶段；商业化是后续议题，见第 10 章）
- ❌ 不做 Windows/macOS 沙箱 guest（仅 Linux guest；宿主机 macOS 仅支持开发模式 + Linux 远程节点）
- ❌ 不做浏览器/桌面 Computer Use（列为 P2 远期探索，e2b 已有 Desktop 沙箱 [^1^]）
- ❌ **不支持沙箱内 Docker（DinD）**：虽然 microVM 后端的 guest 有真内核、技术上可行，但 DinD 会破坏快照语义（嵌套容器状态不可一致恢复）并放大攻击面；需要容器能力的场景通过"多沙箱组网"（FR-3.5）满足
- ❌ 不重造编排轮子：V1 自研轻量调度（单机→小集群），大规模调度通过 K8s RuntimeClass 对接而非自研

---

## 5. 隔离技术选型（对比分析 + 结论）

### 5.1 候选方案对比

| 维度 | Firecracker（microVM） | gVisor 风格（用户态内核） | Kata Containers | WASM/WASI |
| --- | --- | --- | --- | --- |
| 隔离模型 | KVM 硬件虚拟化，每负载独立 guest 内核 | 用户态拦截并重实现 syscall，不触达宿主内核 | 完整 VMM（QEMU/Cloud Hypervisor），Pod 语义 | 能力模型沙箱，非内核隔离 |
| 冷启动 | <125ms [^16^][^17^] | 50–100ms [^17^] | 150–300ms [^17^] | 微秒级 |
| 单实例内存开销 | <5 MiB [^16^] | Sentry 足迹，随负载变化（~18MB 实测参考 [^18^]） | 更高（完整 VMM 栈，~52MB 实测参考 [^18^]） | 极低 |
| 安全边界 | 最强（硬件强制）；攻破 guest 无法触达宿主内核 | 进程级逃逸面；缩减但未消除宿主内核攻击面 [^23^] | 强（完整 VM 边界） | 能力沙箱，无法运行任意 Linux 程序 |
| 系统调用兼容性 | 完整 Linux（真内核） | 约 70–80% Linux syscall，systemd/DinD 等可能不工作 [^23^] | 完整 Linux | 需应用改写，无持久文件系统 |
| GPU/设备 | 精简设备模型，无现成 PCI 直通 [^16^] | 原生 GPU/TPU [^16^] | VMM 支持设备直通 [^16^] | 不支持 |
| 快照/恢复 | 生产级支持 [^16^] | Checkpoint/restore + 文件系统快照 [^16^] | VMM 级快照 | — |
| 运行前提 | 需 KVM（裸金属或嵌套虚拟化） | 无需硬件虚拟化，任何 Linux 可跑 [^16^] | 需虚拟化扩展 | 任意环境 |
| syscall 开销 | 接近原生 | I/O 密集型负载 20–50% 开销；CPU 型 <1% [^23^][^22^][^17^] | 接近原生 | — |
| 生态/生产验证 | AWS Lambda/Fargate、e2b、Vercel Sandbox [^16^][^23^] | Google Cloud Run/GKE、Modal、k8s agent-sandbox 默认 [^16^] | CNCF 项目、K8s 原生 [^22^] | Cloudflare Workers |

### 5.2 选型结论（推荐架构）

**主决策：默认后端采用 Firecracker（microVM），架构上通过 Sandbox ABI 将后端可插拔化。**

理由：

1. **威胁模型匹配**：核心场景是"执行 LLM 生成的不可信代码"，属高危场景，决策框架一致指向硬件级隔离 [^19^][^23^]。gVisor 被攻破是进程级逃逸，Firecracker guest 被攻破无法触达宿主内核 [^23^]。
2. **性能已够用**：125ms 冷启动是 AWS 为 Lambda 验证过的"交互级延迟可行"阈值 [^18^]；e2b 实测 p50 创建 78ms（含快照池预热等优化）[^1^]。
3. **快照能力是平台层地基**：暂停/恢复、模板预烘焙、池化预热都依赖生产级快照 [^16^]。
4. **Rust 实现 + 极小攻击面**：精简设备模型（仅网络、块设备、串口）[^23^]。

**可插拔的理由（不一棵树上吊死）**：

- **GPU 场景**：指定 gVisor 后端（原生 GPU 直通）或 Kata 后端 [^16^]。
- **无 KVM 环境**（云上无嵌套虚拟化的 VM 实例）：退化到 gVisor 风格后端，任何 Linux 可跑 [^16^]。
- **K8s 原生团队**：通过 Kata/RuntimeClass 接入。
- **短任务（<1s）高密度场景**：gVisor 后端避免 VM 启动开销占比过高 [^19^]。

**自研边界声明**：V1 的 gVisor 风格后端直接复用上游 gVisor（runsc）封装，**不自研用户态内核**——重写 syscall 接口的兼容性工作量巨大（gVisor 仅覆盖 70–80% syscall [^23^]），不符合 MVP 原则。"自研隔离层"体现为 **Sandbox ABI + 后端驱动框架**（统一生命周期/网络/存储/快照抽象），这是 SandLocker 的核心技术资产；远期（R4 之后）再评估是否自研用户态内核分支。

### 5.3 关键技术决策记录（ADR 摘要）

| 编号 | 决策 | 结论 | 理由 |
| --- | --- | --- | --- |
| ADR-1 | 默认隔离后端 | Firecracker | 硬件隔离 + 125ms 启动 + 生产级快照 [^16^][^17^] |
| ADR-2 | 后端架构 | Sandbox ABI 可插拔（FC/gVisor/Kata） | GPU、无 KVM、K8s 场景的客观需求 [^16^] |
| ADR-3 | 实现语言 | Rust（运行时层）+ Go（控制面）；**M1 scoped 偏离：控制面用 Rust（单机单二进制、进程内），以契约先行/窄 store 接口/模块化框住返工，M2/M3 闸门复审是否转 Go（见 docs/M1技术计划.md D3，2026-08-04）** | 与 Firecracker 生态同栈（Rust），控制面复用 Go 云原生生态；M1 偏离理由：2 人团队最难阶段（快照引擎）不宜再加第三门语言，单机控制面小且 6.2 本就"进程内模块"，"M3 逼 Go"为弱强制可推迟 |
| ADR-4 | 沙箱内通信 | guest 内驻留轻量 agent（类 e2b envd 架构 [^1^]），vsock/gRPC | 低开销、与网络栈解耦 |
| ADR-5 | 编排 | V1 自研轻量调度（节点 agent）；K8s 通过 RuntimeClass 对接；**不自研 raft**——集群模式的元数据/选主/租约统一由 etcd 承担（见 ADR-17，本条修正原"raft 选主"结论） | 自部署优先，不重造 K8s；自研 raft 与引入 etcd 构成两套共识系统，是纯粹负债 |
| ADR-6 | 快照格式 | 复用 Firecracker snapshot；**V1 内存快照全量自包含，磁盘增量由 dm-thin 块层天然承担（ADR-23/25）**；增量内存 diff 列 P2 | 池化预热与秒级恢复的基础；全量内存使快照树无合并删除语义 |
| ADR-7 | 网络隔离 | 每沙箱独立 netns + tap，默认拒绝出口，白名单数据通路为 nftables（ADR-21） | 满足 P3 安全基线（"deny by default"是行业建议 [^20^]） |
| ADR-12 | 快照克隆状态防护 | 预烘焙点定义为"sl-envd 就绪、应用代码未运行"，该点之前禁止初始化随机性/身份；每次恢复（含 fork）强制执行 post-restore reinit 例程，ready 在其完成后才上报 | 同一预烘焙快照恢复的克隆沙箱内存完全一致：内核熵由 vmgenid reseed（需内核 ≥5.18），用户态 PRNG/身份状态必须由 reinit 例程换发，否则克隆沙箱共享 RNG 状态、machine-id 与会话密钥 |
| ADR-13 | 网络上线顺序与结构性 deny-by-default | 池化快照在 guest 侧无网络（网卡 down、无 IP/路由）；deny-by-default 实现为 allow 条目的缺席而非显式拒绝规则；统一恢复序列：恢复快照(vCPU 暂停) → 建 netns/tap → 写入实例 allow 条目 → reinit 配网 → ready，vCPU 启动永远在最后 | 预热池在创建时不知道实例级网络策略，若快照带网则恢复瞬间存在策略未生效窗口；结构性 deny + 固定时序使窗口在构造上不存在，且池无需按策略分池（策略注入为 ms 级，无预热必要） |
| ADR-14 | 后端能力模型 | 能力声明为 ABI 一等公民：后端注册时上报能力位集（pause_resume / snapshot_fork / prebake_snapshot / gpu_passthrough / persistent_volume 等）；创建请求可声明 required_capabilities，调度器将能力集作为放置约束，不满足即创建期返回 UNSUPPORTED_BY_BACKEND，禁止运行期静默降级；模板产物 = 可移植 rootfs + 每后端各一份预烘焙快照，模板元数据记录已构建后端 | 三个后端能力不齐（gVisor checkpoint/restore 成熟度低、Kata 排期 P1+），能力差异必须显式建模而非文档脚注；预烘焙快照后端特定，不建模则"按后端可选"在模板层断裂 |
| ADR-15 | 快照加密与密钥管理 | 信封加密：每快照随机 DEK（AES-256-GCM，4MiB 分块、独立 nonce，支持懒加载随机读）；DEK 由租户级 KEK 包裹后随元数据存放；KEK 存控制面，根密钥经 KMS 接口（V1 文件实现为开发级，Vault 插件 P1）；节点永不持久化明文 DEK；快照篡改 → AEAD 校验失败 → 拒绝恢复；pause 完成前 sl-envd 擦除自身密钥材料 | pause 落盘的 guest 内存含已注入 secret；快照与密钥同机存放则加密形同虚设；整文件加密与 userfaultfd 懒加载冲突，分块 AEAD 兼顾随机访问与完整性 |
| ADR-16 | 快照版本钉住与生命周期 | 快照按（模板版本, 内核版本, VMM 版本）三元组 key；预烘焙模板快照视为可再生缓存，内核/VMM 升级后 CI 自动重建（用户模板 `sandlocker build --rebuild-all`）；paused 用户快照版本钉住：仅可恢复到运行兼容版本的节点（节点保留 N-1 内核镜像与 FC 二进制），默认保留期 7 天（可配），过期回收；旧内核恢复返回"未打补丁 guest 内核"警告；跨版本快照升级（唤醒→新版本重打快照）列 P2 | FC 快照绑定内核/VMM 版本，48h 补丁 SLA 意味着作废事件必然反复发生；模板快照可重建而用户快照不可，两者合同必须分开；保留期使兼容负担天然有界 |
| ADR-17 | 控制面共识与状态存储 | 不自研 raft：集群模式元数据 + 选主 + 租约统一用 etcd（内嵌部署可选，参照 k3s embedded etcd），Orchestrator 多副本 active-standby、etcd election 选主；单机模式 SQLite + 进程内 orchestrator 无选主；元数据访问定义窄接口（Get/Put/Watch/Txn/Lease），SQLite 与 etcd 双实现，orchestrator 逻辑与存储解耦；状态分两类：持久态（沙箱/模板/配额/审计）走普通 KV，易失态（节点心跳、租约、池库存）走 etcd lease（TTL），节点失联租约过期即触发回收；`sandlocker cluster init` 内置 SQLite→etcd 一次性迁移（需停机窗口，文档明示为迁移事件）；弃用 PostgreSQL 选项 | etcd 本身即 raft 且自带 election/lease 原语，引入 etcd 后再自研选主是维护两套共识；lease TTL 使节点故障检测（8.4）无需自研；窄接口双实现让 M1 单机版平滑演进到 M3 集群版，避免两套代码路径 |
| ADR-18 | guest init 模型与 OCI 语义取舍 | sl-envd 作为 guest PID 1：负责基础挂载、僵尸回收（wait4 循环，孤儿进程 reparent 至 PID 1）、信号转发（持有全部 workload 进程跟踪表），随后启动 vsock 服务；OCI 镜像仅作 rootfs 与默认环境来源：ENV/WORKDIR/USER 在构建期物化为 envd 配置文件（运行期不解析 OCI manifest），ENTRYPOINT/CMD 不自动执行（常驻服务经模板 `start_cmd`），EXPOSE 仅元数据，systemd 依赖型镜像不支持；预烘焙点精确定义为"envd 完成挂载与 vsock 就绪、start_cmd（如有）已拉起、应用代码未运行" | 沙箱语义 ≠ 容器语义（机器 vs 单命令环境），完整模拟容器语义成本无底洞；PID 1 不做僵尸回收会在长寿沙箱中耗尽 PID；构建期物化使 guest 零 OCI 解析逻辑、攻击面最小 |
| ADR-19 | 构建期隔离与网络 | 构建即沙箱：模板 RUN 步骤在专用构建沙箱（节点 FC VM + sl-envd）内执行，不引入第二套构建环境；构建网络策略独立于运行时策略：`build_network` 三档 allow-all（默认）/ whitelist（仅镜像源）/ deny（全离线），于模板或 build API 声明；构建沙箱不进预热池、不暴露端口、独立 netns 仅出向、TTL 硬上限、全程审计、不持控制面凭据；产物内容寻址并签名；依赖锁定/可复现构建列 P2，文档明示 RUN + 网络不可复现 | 模板 RUN 步骤是不可信代码，威胁模型与运行时沙箱相同，用更低隔离跑构建自相矛盾；运行时 deny-by-default 直接套构建会使包安装不可用，两套策略必须分开建模 |
| ADR-20 | 域名级出口白名单机制 | 主机制（P1）：DNS 劫持 + 动态 IP 集合——节点级 resolver 应答沙箱全部 DNS 查询，允许域名的解析结果写入该沙箱独立 ipset/eBPF map（ADR-13 allow 条目由 resolver 动态维护），与 FR-3.4 DNS 审计共用同一组件；DoH/DoT 缓解：出口 53/853 仅放行至专用 resolver，知名公共 DoH 端点默认拒绝。严格模式（P2，面向 P3）：SNI 透明代理，代理侧解析域名后连接（防 SNI 伪造），ECH 流量默认拒绝；仅 TLS。数据通路（iptables REDIRECT / eBPF）为独立实现决策。已知限制须文档化：共享 CDN IP 会放大放行范围（P3 应用严格模式）、DoH 缓解不完全、TTL/CDN 漂移由 resolver 持续重解析消化 | "eBPF L7"实为重定向到用户态代理的转发管线，非独立机制，从选项中排除；SNI 仅覆盖 TLS 且 ECH 普及使其信号正在消失，不宜作唯一机制；DNS 解析器本就为 FR-3.4 所需，主机制是增量建设且协议无关 |
| ADR-21 | 网络数据通路选型 | V1 用 **nftables + 每沙箱独立 table**：内含命名 IP 集合（ADR-20 resolver 维护）+ 端口集合 + DNS 重定向规则（53 → 节点 resolver，853 拒绝）+ 默认 drop；规则更新走 nft 原子事务，杜绝中间态放行窗口；沙箱销毁 = 删 table 无残留；node agent 定义防火墙后端抽象（ensure_sandbox / add_allow / remove_allow / set_dns_redirect / teardown），nftables 为 V1 实现，**eBPF 降级为 P2 可选后端**（触发条件：每包遥测、SNI 严格模式重定向规模、单节点万级沙箱） | 500 沙箱 × 集合查找在 nftables 舒适区（kube-proxy 撞墙源于逐条规则而非规模本身）；`nft list ruleset` 可审计性是 P3 刚需，eBPF 对运维是黑盒；集合操作原子增删匹配 resolver 高频写 |
| ADR-22 | 数据面网关与流路由 | 控制面/数据面分离：API Server 保持无状态（不碰长连接），流式请求（WS PTY、exec stream、大文件、日志）经**一次性 ticket** 换网关地址后直连 sandlocker-gw；网关按 etcd 沙箱→节点映射中继，任一副本可服务任一沙箱、无需会话粘滞；node agent 向网关集群**主动外拨**保持持久 gRPC 流（多路复用，节点零入站端口），网关↔节点间窗口/ACK 背压；签名 URL（FR-3.3）= 控制面 HMAC 签名（sandbox-id, port, expiry），网关无状态验签、通配符证书终结 TLS、按 Host 路由；单机模式网关为进程内模块，集群模式独立副本 | "API 无状态"与 WS 长连接本质矛盾；拆出网关后两者各自成立；节点外拨使内网自部署（US-3）无需开入站防火墙；无状态验签使签名 URL 无需网关侧存储 |
| ADR-23 | 存储与内存栈 | rootfs CoW 用 **devicemapper thin pool**：模板 base 为 thin origin，每沙箱 thin snapshot 设备供 Firecracker 挂载（firecracker-containerd 先例）；内存恢复 = 快照文件 **mmap + 按需缺页**（FC 原生），P50 ≤100ms 的前提是内存文件在 page cache（同模板实例间天然共享）；预热池分两档——**温池（默认）**= 快照预置本地 + page cache 热 + 元数据预载，不占 guest 内存预算；**热池（可选，默认 0）**= 每模板 N 个已恢复 paused VM，恢复 <50ms，`pool.hot_per_template` 显式内存预算；编排按**快照本地性**放置亲和 + 节点预置热门模板；S3 远程懒加载（userfaultfd 流式取页）列 P2；dm-thin 池容量/metadata 监控入节点指标 | FC 仅 virtio-block（无 virtio-fs），CoW 必须在块层；qcow2/overlayfs/全量复制均不成立；mmap 缺页使恢复无需整读内存文件，page cache 命中是 SLO 的真正前提 |
| ADR-24 | OCI Runtime 形态定位（GA 后） | `sandlocker-runsc` = **Sandbox ABI 之上的薄 shim**：OCI 语义（create/start/kill/state/delete + runc 兼容 `exec` 扩展、containerd shim v2 ttrpc、IO FIFO、exit 事件）翻译为 ABI 调用，每容器一个沙箱，自动继承全部后端能力；能力收窄声明：pause/resume/fork 在 OCI 形态不可用；CNI 归 containerd/K8s 管（与 ADR-7/21 沙箱网络栈设模式开关）；镜像解包复用 ADR-23 dm thin；启动前提：v1.0 API 冻结 + ADR-14 契约测试套件就绪（复用为验收）；兼容 k8s agent-sandbox CRD 语义，争取做其可插拔后端 | OCI 与沙箱生命周期语义不匹配，做成独立运行时会造成安全属性分叉；薄 shim 约束现在钉死，避免 GA 后形成第二条技术栈 |
| ADR-25 | 快照存储模型与树语义 | **内存快照 V1 一律全量自包含**（默认规格单份 512MiB 量级，FR-7.2 配额 + FR-5.4 保留期双重兜底；FC diff snapshot 列 P2）；磁盘增量由 dm-thin 块级引用计数天然承担；**快照不可变**，树边在 pause/fork 时刻形成；删除语义：任意节点可独立删除、无合并操作，删中间节点仅释放其独有资源（内存文件 + dm 独有块），子分支不受影响；backing paused 沙箱的快照禁止直接删除（须先销毁沙箱或显式 `cascade=true`）；GC 统一路径：用户删除/保留期过期/配额强制均走"标记 → 异步 GC worker 回收"，节点重启对账元数据与磁盘产物回收孤儿；配额在 pause/fork 前置检查，超限 `QUOTA_EXCEEDED` | 增量内存 diff 使"删中间节点需合并 diff"成为全系统最复杂且测试覆盖最差的路径；全量 + dm-thin 使树语义一句话讲清（任何节点可删、子分支无影响），以可管存储成本换语义极简 |

---

## 6. 系统架构设计

### 6.1 总体架构

```
                        ┌──────────────┐
        SDK/CLI/CI ───▶ │  API Server   │  (REST + gRPC, 鉴权/配额/审计，无状态)
                        └──────┬───────┘
                               │ 流式请求发一次性 ticket
                        ┌──────▼───────┐       ┌───────────────┐
                        │ Orchestrator │◀─────▶│ 元数据存储      │
                        │ (调度/选主)   │       │ (SQLite→etcd) │
                        └──────┬───────┘       └───────────────┘
        客户端流/签名URL ──▶ ┌──────────┐  ◀── 节点主动外拨注册
                        │ Gateway    │  (数据面：WS/流中继/签名URL，ADR-22)
                        └──────┬───┘
                ┌──────────────┼──────────────┐
        ┌───────▼──────┐ ┌─────▼───────┐ ┌────▼────────┐
        │ Node Agent A  │ │ Node Agent B │ │ Node Agent C │  (每台宿主机)
        │ (sandlocker-nd) │ │              │ │              │
        └───┬──────┬───┘ └──────────────┘ └──────────────┘
            │      │
      ┌─────▼─┐ ┌──▼──────┐     ┌──────────────┐
      │ VM 1  │ │ VM 2    │     │ 模板/快照仓库  │ (本地→S3 兼容)
      │┌─────┐│ │┌───────┐│     └──────────────┘
      ││guest││ ││ guest ││
      ││agent││ ││ agent ││  (类 envd：exec/fs/pty/进程管理)
      │└─────┘│ │└───────┘│
      └───────┘ └─────────┘
```

### 6.2 核心组件

| 组件 | 职责 | 技术要点 |
| --- | --- | --- |
| **sandlocker-api** | 控制面入口：REST/gRPC API、API Key 鉴权、配额、审计日志；流式请求签发一次性 ticket | Go；无状态，水平扩展 |
| **sandlocker-gw** | 数据面网关（ADR-22）：WS/流式中继（pty/exec/文件/日志）、签名 URL 入口（无状态 HMAC 验签、通配符证书终结 TLS）；按 etcd 沙箱→节点映射中继，水平扩展无需会话粘滞 | Go；单机模式为进程内模块，集群模式独立副本 |
| **sandlocker-orchestrator** | 沙箱放置调度（资源感知 + 亲和性 + 后端能力约束，ADR-14）、节点健康、租约与超时回收、快照库存管理；集群模式多副本 active-standby（etcd election 选主），易失态经 lease 管理、节点失联自动回收（ADR-17） | Go；经窄 store 接口访问元数据（SQLite/etcd 双实现），单机模式退化为进程内模块 |
| **sandlocker-node (sandlocker-nd)** | 宿主机节点代理：驱动 Sandbox ABI 后端创建/销毁沙箱，管理网络（netns/tap）、磁盘层、快照 | Rust；直接对接 firecracker 进程 / runsc / kata |
| **Sandbox ABI** | 统一后端抽象：生命周期、exec、fs、网络、快照、资源限制五组接口 + 能力上报（ADR-14）；配套 ABI 契约测试套件，逐后端运行并生成官方兼容矩阵 | Rust trait + gRPC 双形态（进程内 or sidecar） |
| **guest agent (sl-envd)** | guest PID 1（ADR-18）：基础挂载、僵尸回收、信号转发，之上提供命令执行、文件读写、进程管理、PTY、端口转发、指标上报 | Rust 静态编译，<10MB；vsock 通信 |
| **模板构建器 (sc-build)** | 声明式模板（类 Dockerfile）→ 构建 rootfs + 按后端各构建一份预烘焙快照（ADR-14）→ 入库；RUN 步骤在专用构建沙箱内执行（ADR-19） | 复用 OCI 镜像生态：可直接 from OCI image；镜像 config（ENV/WORKDIR/USER/EXPOSE）构建期物化为 envd 配置（ADR-18），构建无需 Docker daemon；模板元数据记录已构建后端列表 |
| **SDK** | Python / JS-TS / Go；同步+异步；流式输出 | 与 API Server 的 OpenAPI/gRPC 契约自动生成 |
| **CLI (sandlocker)** | 模板构建、沙箱操作、集群初始化、本地开发模式 | 单二进制分发 |

### 6.3 沙箱创建热路径（性能关键）

借鉴 e2b 的优化思路（其 p50 创建 78ms 依赖快照池 [^1^]）：

1. 模板构建时完成"启动到可执行状态"并打**内存+磁盘快照**（预烘焙）。
2. 节点维护**预热池**（温池：模板快照预置本地 + 内存文件驻 page cache，池按模板 key、guest 侧无网络，ADR-23），创建请求 = 恢复快照（mmap 缺页，vCPU 暂停）→ 建 netns/tap → 写入实例网络策略 → post-restore reinit（注入身份/配网）→ ready（ADR-12/ADR-13）。可选热池（默认 0）保留已恢复 paused VM 换取 <50ms 恢复，内存预算显式配置。
3. 冷启动兜底路径：直接 boot microVM（Firecracker <125ms [^17^]）。
4. 文件系统采用 devicemapper thin pool 分层（base rootfs 为 thin origin + per-sandbox thin snapshot，ADR-23），模板共享降低磁盘占用。

---

## 7. 功能需求

优先级：**P0 = MVP 必须**；**P1 = GA 必须**；**P2 = 增强**。

### 7.1 沙箱生命周期（P0）

| ID | 需求 | 验收标准 |
| --- | --- | --- |
| FR-1.1 | 创建沙箱：指定模板、资源（vCPU/内存/磁盘）、超时、元数据 | API/SDK 调用返回沙箱 ID；默认 2 vCPU/512MiB（对齐行业默认 [^1^]）；预设规格含 micro（128MiB），配套官方极简模板（静态二进制/极简 runtime 场景，对应 8.1 密度声明）；P50 就绪时间 ≤150ms（预热池命中），≤1s（冷启动） |
| FR-1.2 | 自动超时销毁：TTL + 空闲超时，可续期 | 超时后资源完全回收；支持 `keepAlive` 心跳续期 |
| FR-1.3 | 手动销毁/强制回收 | 销毁后网络命名空间、磁盘层、内存无残留 |
| FR-1.4 | 暂停/恢复（快照） | `pause()` 落盘快照；`resume()` P50 ≤200ms 恢复到完全一致状态（含进程内存）；恢复后强制执行 post-restore reinit（ADR-12）：唯一 machine-id/hostname、全新 sl-envd 会话密钥、网络身份重配置、时钟校正、内核 reseed 校验（vmgenid），全部完成后才上报 ready |
| FR-1.5 | 沙箱列表与查询 | 按状态/标签/创建者过滤 |

### 7.2 沙箱内执行与文件系统（P0）

| ID | 需求 | 验收标准 |
| --- | --- | --- |
| FR-2.1 | 执行命令：同步/异步，流式 stdout/stderr，退出码 | SDK 提供 `run(cmd)` 阻塞式与流式两种；支持超时与信号转发 |
| FR-2.2 | 文件读写：上传/下载/列目录/监听变更 | 单文件 ≥1GB 支持；小文件写入 P95 ≤50ms |
| FR-2.3 | PTY 交互会话 | WebSocket 接入（ticket 模式经 sandlocker-gw，ADR-22），支持交互式 shell，窗口 resize |
| FR-2.4 | 后台进程管理 | 启动/查询/终止沙箱内服务进程；进程退出事件回调 |

### 7.3 网络（P0 = FR-3.1 / 3.2a / 3.3；其余 P1/P2）

| ID | 需求 | 验收标准 |
| --- | --- | --- |
| FR-3.1 | 默认网络策略：沙箱间隔离，出口默认拒绝（deny-by-default）[^20^] | 未配置时沙箱无法访问任何外部地址与邻居沙箱；恢复路径（池命中与 pause 恢复）任何时刻沙箱都无法在策略生效前发包（ADR-13 时序），基准 CI 加时序探针验证 |
| FR-3.2a | 出口白名单（IP/端口粒度，P0） | 模板级与实例级两级配置，动态生效；nftables 实现（ADR-21） |
| FR-3.2b | 出口白名单（域名粒度，P1） | DNS 劫持 + 动态 IP 集合（ADR-20）：允许域名解析结果动态写入沙箱 ipset；已知限制须文档化（共享 CDN IP 放大、DoH 缓解不完全）；P2 提供 SNI 代理严格模式（P3 场景） |
| FR-3.3 | 端口暴露：沙箱内服务对外映射签名 URL | 类似 e2b 的端口转发；URL 带过期签名（控制面 HMAC，网关无状态验签，ADR-22），防未授权访问；网关审计访问记录 |
| FR-3.4 | （P1）DNS 劫持审计：记录沙箱全部 DNS 查询 | 审计日志可查询；与 FR-3.2b 共用节点级 resolver 组件（ADR-20） |
| FR-3.5 | （P2）沙箱内网：同一用户多个沙箱组 VPC | 组内互通，组外隔离 |

### 7.4 模板系统（P0 简化版 / P1 完整）

| ID | 需求 | 验收标准 |
| --- | --- | --- |
| FR-4.1 | 声明式模板文件：MVP 采用**自定义简化 DSL**（`sandlocker.toml`），P1 增加 **Dockerfile 子集兼容**（FROM/RUN/COPY/ENV/WORKDIR/EXPOSE） | 支持 from（基础镜像，可直接引用 OCI image）、run、copy、env |
| FR-4.2 | 模板构建流水线：构建 rootfs → 预启动 → 打快照 → 入库（依赖快照引擎，M1 以内部能力交付） | `sandlocker build` 一键完成；构建产物含版本化 ID |
| FR-4.3 | 模板版本管理与回滚 | 创建沙箱可指定模板版本；默认 latest |
| FR-4.4 | （P1）模板 registry：团队内共享、权限控制 | push/pull 语义，S3 兼容存储后端 |
| FR-4.5 | 构建期网络与隔离（ADR-19） | RUN 步骤在构建沙箱内执行；`build_network` 三档（allow-all 默认 / whitelist 仅镜像源 / deny 全离线）可配；构建沙箱 TTL 硬上限、全程审计、不暴露端口；产物签名；P3 场景文档化"whitelist + 内网镜像源"合规构建模式 |

> OCI 语义映射（ADR-18）：沙箱语义 ≠ 容器语义。ENV/WORKDIR/USER 物化为 exec 默认环境；**ENTRYPOINT/CMD 不自动执行**——常驻服务经模板 DSL 的 `start_cmd` 显式声明（P1 Dockerfile 兼容时 ENTRYPOINT 映射为 `start_cmd`）；EXPOSE 仅为元数据；依赖 systemd 的镜像不支持，须在迁移文档置顶说明。

### 7.5 快照与持久化（P1）

| ID | 需求 | 验收标准 |
| --- | --- | --- |
| FR-5.1 | 全量快照（内存+磁盘） | 见 FR-1.4 |
| FR-5.2 | 增量快照与快照树 | 支持从任一快照分支新沙箱（fork 语义，对标 Morph 的 branch 能力 [^12^]）；V1 内存快照全量自包含、磁盘经 dm-thin 块级增量（ADR-25），增量内存 diff 列 P2 |
| FR-5.3 | （P1）持久卷：跨沙箱生命周期的数据卷挂载 | 沙箱销毁后卷保留，可挂载到新沙箱 |
| FR-5.4 | 快照生命周期（ADR-16） | 默认保留期 7 天（可配），过期自动回收；快照记录 {kernel_version, fc_version}，仅可恢复到兼容节点；恢复旧内核快照返回"未打补丁 guest 内核"警告；模板快照支持内核升级后一键重建（`sandlocker build --rebuild-all`） |
| FR-5.5 | 快照树删除与 GC（ADR-25） | 快照不可变；任意节点可独立删除，删中间节点不影响子分支（无合并操作）；backing paused 沙箱的快照禁止删除（`cascade=true` 除外）；删除/过期/配额强制统一走异步 GC；节点重启孤儿对账回收；pause/fork 前置配额检查，超限 `QUOTA_EXCEEDED` |

### 7.6 SDK 与 CLI（P0）

- **Python SDK**（P0）；**JS/TS SDK**（P1）：对齐 e2b 的 SDK 覆盖（JS/TS 与 Python 是行业标准配置 [^1^]），M2 先交付契约自动生成版，手工打磨版随 GA（见 11 章砍单预案）；**Go SDK**（社区轨道）。
- SDK 设计目标（对照 US-1）：
  ```python
  from sandlocker import Sandbox
  sbx = Sandbox.create(template="python-data", timeout=300)
  result = sbx.run("python analysis.py")      # 流式 stdout
  sbx.files.write("/tmp/out.csv", data)
  sbx.pause()                                  # 快照暂停
  ```
- CLI（P0）：`sandlocker build / run / ps / logs / exec / snapshot / cluster init`；本地开发模式（单机全组件合一，一条命令启动）。

### 7.7 鉴权、多租户与配额（P1）

| ID | 需求 |
| --- | --- |
| FR-7.1 | API Key 体系：组织 → 项目 → Key（作用域：读写/只读/构建） |
| FR-7.2 | 配额：CPU 总量、内存总量、并发沙箱数、模板存储量、**快照存储量**（paused 快照单份 512MiB 量级且可 fork 增殖，ADR-15/16），按项目维度 |
| FR-7.3 | 审计日志：全部 API 操作 + 沙箱内 exec/fs 事件，不可篡改存储（append-only） |
| FR-7.4 | （P2）OIDC/SSO 登录与 RBAC |

### 7.8 可观测性（P1）

- 指标：Prometheus 导出（沙箱创建延迟分位、池命中率、节点资源、exec 延迟）。
- 日志：结构化日志；沙箱 stdout/stderr 可转发至外部 sink（Loki/ES/stdout）。
- 追踪：OpenTelemetry，创建链路全 span（API→调度→节点→boot→ready）。

### 7.9 隔离运行时独立使用（GA 后 / v1.x 规划，对应 P5 画像）

- 提供 OCI Runtime 二进制 `sandlocker-runsc`：`docker run --runtime=sandlocker-runsc` 与 K8s RuntimeClass 可用。
- 该形态不依赖平台层任何组件，单独发布；定位为 **Sandbox ABI 之上的薄 shim**（ADR-24），pause/resume/fork 在 OCI 形态不可用。
- 复杂度构成（留档）：OCI CLI 子集 + runc 兼容 exec 扩展、containerd shim v2、CNI 模式开关；启动前提为 v1.0 API 冻结 + ABI 契约测试套件就绪。
- V1 期间 P5 用户以文档指引自行封装后端接入 containerd/K8s；独立形态为 11 章砍单预案第 1 顺位。

### 7.10 部署形态（P0 单机 / P1 集群）

- **单机一体化**：`sandlocker up` 一条命令，全部组件单进程，SQLite 元数据，快照仓库为本地文件系统（ADR-9），供个人开发与评测。
- **集群模式**：API Server 无状态多副本 + Orchestrator 多副本（etcd election 选主，active-standby）+ N 个 Node Agent + S3 兼容快照仓库（P1 引入，ADR-9）+ etcd 元数据（内嵌部署可选，ADR-17）。
- **K8s Helm Chart**（P1）：面向已有 K8s 的团队。
- 支持环境：Linux 宿主机（裸金属或开启嵌套虚拟化的 VM）；macOS 仅客户端/远程模式。

---

## 8. 非功能需求

### 8.1 性能指标（SLO）

| 指标 | 目标 | 行业参照 |
| --- | --- | --- |
| 沙箱创建 P50（池命中） | ≤ 100ms | e2b p50 78ms [^1^] |
| 沙箱创建 P99（冷启动） | ≤ 1.5s | Firecracker boot <125ms，叠加 rootfs/网络配置 [^17^] |
| 快照恢复 P50 | ≤ 200ms | Morph branch ~250ms [^12^] |
| exec 启动开销 | ≤ 20ms | guest agent 常驻 |
| 单节点沙箱密度（64C/128G 节点） | ≥ 200 实例 @ 默认规格（2vCPU/512MiB）；≥ 500 实例 @ micro 规格（128MiB） | 密度按规格声明：500 实例 × 默认规格需 256GiB guest 内存，超出节点物理内存，不可承诺 [^16^] |
| 稳态运行性能损耗 | ≤ 5%（microVM 后端） | 微基准显示稳态延迟开销可忽略 [^18^] |

> 密度指标的进一步说明：同模板恢复的多个沙箱可通过共享快照文件 page cache + 懒加载（脏页率低时）提升实际密度，但该收益取决于同模板占比与脏页率两个变量，**不作为 SLO 承诺**。M0 基准 CI 中增加密度实测项（N 实例同模板 / 混合模板各测一次），M2 评审时依据实测数据复审上述目标值。micro 规格面向静态二进制/极简 runtime 的高密度短任务场景，需提供对应官方 micro 模板。
>
> SLO 适用范围：除注明外，上表数值仅对 **Firecracker 后端**承诺。gVisor / Kata 后端暂不设 SLO，M3 接入时依据 ABI 契约测试与基准 CI 实测数据补各行目标值（ADR-14）。
>
> 创建/恢复延迟前提：P50 ≤100ms（池命中）以**温池命中**（快照本地 + page cache 热，ADR-23）为前提；page cache 冷时退化至 P99 冷启动档。M0 基准 CI 分热/冷两档实测，M2 闸门复审目标值，不达标以热池配置补充而非下调口径。

### 8.2 安全需求（这是产品的第一性需求）

- 隔离边界：默认硬件虚拟化级（microVM）；威胁模型文档化并随版本维护。
- 节点侧纵深防御：Jailer 式最小权限（seccomp、chroot、cgroup 隔离 VMM 进程）。
- 供应链：guest agent 与内核镜像可复现构建；全部发布产物签名（cosign）；SBOM 随发布。
- 安全响应：SECURITY.md、漏洞披露流程、CVE 跟踪；目标进入 CNCF 安全审查节奏。
- 默认安全：网络 deny-by-default [^20^]、无特权 guest agent、密钥不落沙箱（secret 通过 vsock 运行时注入）。
- 快照克隆状态防护（ADR-12）：自带内核 ≥5.18 并启用 vmgenid，恢复时自动 reseed 内核 CRNG；模板预烘焙点禁止初始化任何随机性/身份（构建器检测并拒绝违规模板）；每次恢复强制执行 post-restore reinit（换发 machine-id/会话密钥、网络身份重配置、时钟校正）；fork 语义不刷新安全边界——分叉沙箱可见源沙箱内存中已有状态，须在文档中明示。基准 CI 增加克隆熵回归测试（同快照恢复两实例，验证 RNG 输出与身份不同）。
- 快照加密（ADR-15）：全量快照信封加密落盘，节点不持久化明文密钥；分块 AEAD 保证篡改即恢复失败。威胁模型明示边界：**快照加密防静态数据失窃（快照仓库/磁盘被拷），不防持有密钥的节点被攻破**；**pause 会捕获 guest 内存中当时存在的一切 secret**，用户侧密钥轮换需在文档中指引。

### 8.3 兼容性与可移植性

- guest：Linux x86_64（V1），arm64（P1，Firecracker 与 gVisor 均支持）。
- 模板兼容 OCI 镜像生态，降低迁移成本。
- 后端兼容矩阵：由 ABI 契约测试套件逐后端实测生成，随版本发布（ADR-14），不引用上游文档数据代替实测。
- API 稳定性：v1 API 进入 GA 后遵守语义化版本，弃用周期 ≥2 个 minor 版本。

### 8.4 可靠性

- 节点故障：其上沙箱标记丢失并回收（V1 不做跨节点迁移，P2 评估）；控制面故障不影响已运行沙箱。
- 数据：快照仓库多副本依赖底层 S3；元数据定期备份。
- 快照版本兼容（ADR-16）：节点保留 N-1 内核镜像与 Firecracker 二进制以承接版本钉住的 paused 快照；快照恢复调度须匹配 {kernel_version, fc_version} 兼容矩阵，矩阵随发布维护。

---

## 9. API 设计草案（v1alpha）

```
GET    /v1/backends                  后端列表与能力集（ADR-14）
POST   /v1/sandboxes                 创建沙箱 {template, cpu, mem, ttl, env, network_policy, required_capabilities}
GET    /v1/sandboxes/{id}            查询状态
DELETE /v1/sandboxes/{id}            销毁
POST   /v1/sandboxes/{id}/pause      暂停（打快照）
POST   /v1/sandboxes/{id}/resume     恢复
POST   /v1/sandboxes/{id}/exec       执行命令（支持 stream）
WS     /v1/sandboxes/{id}/pty        交互式终端
PUT    /v1/sandboxes/{id}/files/*    文件读写（multipart/range）
POST   /v1/templates:build           构建模板（可指定目标后端集）
GET    /v1/templates                 模板列表（含已构建后端）
POST   /v1/snapshots/{id}/fork       从快照分支新沙箱
```

契约先行：OpenAPI + Protobuf 双描述，SDK 由契约生成，保证三语言 SDK 行为一致。

---

## 10. 开源策略

### 10.1 许可证

| 选项 | 评估 |
| --- | --- |
| **Apache 2.0（推荐）** | 云原生基础设施项目事实标准（Firecracker、gVisor、Kata 均为 Apache 2.0），企业采用顾虑最小，专利授权明确 |
| AGPL | 防云厂商白嫖，但会显著阻碍企业自部署采用——与"自部署优先"定位冲突 |
| BSL（Business Source License） | 延期开源，社区信任成本高，放弃 |

**结论：Apache 2.0，全量开源（含控制面与编排，学习 e2b "一切开源"的策略 [^1^]）。**

### 10.2 治理与社区

- 治理：MAINTAINERS 文件 + 懒共识；star 过 5k 后评估捐赠 CNCF Sandbox（与 Kata、Firecracker 同生态位）。
- 社区基建：GitHub Discussions、双周社区会、good-first-issue 标签体系、贡献者指南与架构文档（`docs/architecture/`）。
- 兼容性承诺：SDK/API 语义化版本。

### 10.3 商业化边界（open-core 预留，非本项目范围）

开源版包含完整功能；未来商业化仅做**控制面增值**（托管控制面、SSO、审计长留存、企业支持），绝不把隔离能力本身闭源——这是与社区的核心信任契约。

---

## 11. 里程碑与路线图

| 里程碑 | 时间（相对） | 范围 | 出口标准 |
| --- | --- | --- | --- |
| **M0 技术验证** | T+0 ~ T+6 周 | Firecracker 后端打通：boot→exec→销毁；guest agent 原型；冷启动基准 | 单节点 demo：`run` 一个命令端到端 ≤1.5s |
| **M1 MVP**（v0.1） | T+6 ~ T+16 周 | 单机一体化；生命周期 FR-1.1/1.2/1.3；exec/fs（FR-2.1/2.2）；模板 FR-4.1/4.2；**快照/恢复引擎（内部能力，支撑模板预烘焙，含 ADR-12 reinit 与 ADR-13 时序）**；Python SDK；CLI；deny-by-default 网络（FR-3.1/3.2a） | 发布 v0.1；US-1/US-4/US-7 场景可用；创建 P50 ≤500ms（预烘焙恢复路径，无池）；文档站上线；**闸门：对照砍单预案确认 M2 范围** |
| **M2 Alpha**（v0.2~0.4） | T+16 ~ T+28 周 | pause/resume 用户 API（FR-1.4）+ 快照加密与保留期管理（ADR-15/16）；预热池；**数据面网关 sandlocker-gw（ADR-22）**；JS/TS SDK（契约自动生成版）；PTY；端口暴露；Sandbox ABI 抽象落地 + gVisor 后端接入 | 池命中 P50 ≤100ms；两个后端可切换；**闸门：对照砍单预案确认 M3 范围** |
| **M3 Beta**（v0.5~0.8） | T+28 ~ T+40 周 | 集群编排；API Key/配额/审计；可观测性 + **只读监控看板**（Grafana 策展，scoped 偏离，见砍单预案第 2 项注）。（OCI Runtime 独立形态、Helm Chart、Go SDK、**控制台完整操作面** 移至 GA 后/社区轨道，见砍单预案） | 3 节点集群 SLO 达标；外部 5 个团队试用反馈闭环；**闸门：确认 GA 范围；启动安全审计采购（排期通常 8–10 周）** |
| **M4 GA**（v1.0） | T+40 ~ T+52 周 | 持久卷、快照 fork、arm64、API 冻结、安全审计（第三方） | v1.0 发布；通过外部安全审计；≥1000 GitHub star |

> 团队规模假设：2–4 名核心工程师，**计划按 2 人基线排期，4 人作为加速**。单人场景下建议只做运行时层（M0 + M1 子集），不宜承诺完整平台。

> **砍单预案**（触发条件：任一里程碑滑期 >25%，或平均人力 <2.5 人；按顺序执行，逐项确认后进入下一项）：
>
> | 顺序 | 砍除/降级项 | 处置 | 理由 |
> | --- | --- | --- | --- |
> | 1 | OCI Runtime 独立形态（sandlocker-runsc，7.9） | 移至 GA 后（v1.x 规划） | 事实上的第二个产品（shim/CNI/生命周期语义转换）；P5 画像 V1 期以文档指引自行封装后端顶着 |
> | 2 | 控制台 | 移出 V1 范围（4.1 图注）。**M3 scoped 偏离（2026-08-31）：只读监控看板部分回拉入 M3**（Grafana 策展，骑可观测性 §7.8，零自建前端；见 M3技术计划 §4 D6/M3-Q12）；**完整操作面（创建/销毁/Key/配额）仍留 GA 后/商业化** | 无任何里程碑认领；CLI 够用，留待社区或商业化阶段。M3 偏离理由：外部 5 团队试用（M3 出口）需可观测体验，Grafana 路线不自建前端、不触发「2 人无法维护前端」的原始砍因 |
> | 3 | Go SDK、Helm Chart | 转社区轨道（good-first-issue + 契约/模板就绪后开放认领） | 边界清晰、有契约可依，最适合社区贡献 |
> | 4 | JS/TS SDK 手工打磨 | M2 仅交契约生成版，打磨版随 GA（7.6 已降为 P1） | 2 人无法维护两个手工级 SDK |
> | 5 | Kata 后端 | 移至 GA 后 | ADR-14 能力模型允许后端不齐，Kata 接入成本最高 |

---

## 12. 成功指标

| 类别 | 指标 | 12 个月目标 |
| --- | --- | --- |
| 北极星 | 周活跃沙箱创建数（自愿上报遥测 + 公开部署调研的**估算口径**，见 14.1b 决策 24） | 100 万/周 |
| 采用 | GitHub star / 生产自部署团队数 | 5,000 star / 50 个团队 |
| 社区 | 外部贡献者 PR 占比 | ≥25% |
| 性能 | 创建 P50（池命中） | ≤100ms 保持 |
| 质量 | 安全漏洞中位修复时间 | 高危 ≤7 天 |
| SDK | Python/JS 包周下载 | 各 ≥5,000 |

---

## 13. 风险与缓解

| 风险 | 等级 | 缓解 |
| --- | --- | --- |
| Firecracker 生态绑定（KVM 依赖、无 GPU 直通） | 中 | ABI 可插拔架构本身即对冲；GPU 场景路由 gVisor/Kata 后端 [^16^] |
| 与 e2b 开源版正面竞争 | 高 | 差异化：可插拔后端、长会话/持久卷、GPU、自部署一等公民、社区治理；不拼"托管云" |
| K8s 官方 agent-sandbox 项目吃掉生态位 | 中 | 主动兼容其 CRD 语义，争取成为其可插拔后端之一，而非对抗 [^16^] |
| 快照/内存状态安全问题（快照含敏感数据） | 高 | 快照加密落盘；密钥运行时注入而非快照内；威胁模型文档 |
| 单机性能不达标（预热池复杂度高） | 中 | M0 即建立基准 CI，每 PR 跑冷启动/恢复/密度基准回归 |
| 维护者人力不足 | 高 | 严格按里程碑砍范围；V1 不做 K8s 大规模调度、不做 Windows guest |
| 上游 gVisor syscall 兼容性投诉转移至本项目 | 中 | 文档明确标注各后端兼容矩阵，gVisor 仅覆盖约 70–80% syscall 的事实前置告知 [^23^] |

---

## 14. 决策记录与遗留事项

### 14.1 已闭环决策（v1.1，2026-08-01）

原 6 个开放问题全部决策完毕，结论已并入正文对应章节：

| # | 问题 | 决策 | 落点 |
| --- | --- | --- | --- |
| 1 | 品牌与命名 | **更名 SandLocker**（原名 SandCore 存在撞名） | 全文；发布前仍需完成域名/商标检索（14.2） |
| 2 | guest 内核镜像策略 | **自带精简内核**（基于 Firecracker 推荐配置裁剪，随版本发布并签名；V1 不允许用户自带内核） | ADR-8；8.2 供应链条款 |
| 3 | 模板语法 | **MVP 自定义 DSL（sandlocker.toml），P1 增加 Dockerfile 子集兼容** | FR-4.1 |
| 4 | 快照仓库存储 | **本地文件系统起步，S3 兼容存储 P1 引入**；存储后端接口抽象可切换 | ADR-9；7.10 部署形态 |
| 5 | 遥测 | **默认开启匿名遥测，opt-out**；仅聚合指标，不收集命令/文件/环境变量内容；收集清单公开（**v1.2 由 14.1b 决策 24 修订为分形态 opt-in**） | ADR-10；第 12 章北极星指标 |
| 6 | 沙箱内 Docker（DinD） | **不支持**；替代方案为多沙箱组网（FR-3.5） | 4.2 范围边界；ADR-11 |

### 14.1b 已闭环决策（v1.2，2026-08-01，实施性评审第二轮）

| # | 问题 | 决策 | 落点 |
| --- | --- | --- | --- |
| 7 | 密度 SLO 与默认规格矛盾（500 实例 × 512MiB 超物理内存） | **密度按规格声明**：≥200 实例 @ 默认规格 / ≥500 实例 @ micro 规格（128MiB）；page cache 共享收益不作承诺，M0 基准 CI 实测、M2 复审 | 8.1；13 章风险表 |
| 8 | 快照克隆状态一致（RNG/machine-id/会话密钥被克隆） | **vmgenid 内核 reseed + post-restore reinit 强制例程**；预烘焙点禁止初始化随机性/身份；fork 不刷新安全边界需文档明示 | ADR-12；FR-1.4；8.2 |
| 9 | 预热池与 deny-by-default 网络矛盾（恢复瞬间策略未生效窗口） | **结构性 deny（allow 条目缺席即全拒）+ 固定恢复时序**（vCPU 启动最后）；池化快照 guest 侧无网络，池不按策略分池 | ADR-13；FR-3.1；6.3 |
| 10 | Sandbox ABI 跨后端能力不齐（gVisor checkpoint 成熟度低、Kata 排期 P1+） | **能力声明为 ABI 一等公民**：required_capabilities 创建期校验、禁止静默降级、模板按后端构建、SLO 按后端声明、兼容矩阵由契约测试实测生成 | ADR-14；6.2；第 9 章；8.1；8.3 |
| 11 | 52 周 × 2–4 人路线图超编（"严格砍范围"无预案） | **预先承诺砍单预案**：滑期 >25% 或人力 <2.5 人触发，顺序为 OCI Runtime → 控制台 → Go SDK/Helm 社区轨道 → JS/TS SDK 降级 P1 → Kata 后端；里程碑间设 go/no-go 闸门；安全审计采购 M3 启动；计划按 2 人基线排期 | 第 11 章；4.1；7.6；7.9 |
| 12 | 快照加密密钥管理缺失（快照与密钥同机 = 形同虚设） | **信封加密**：每快照 DEK（分块 AEAD，支持懒加载随机读）+ 租户 KEK 存控制面 + KMS 接口（Vault 插件 P1）；节点不持久化明文 DEK；篡改即恢复失败；sl-envd pause 前擦除自身密钥；威胁模型明示"防静态失窃、不防持钥节点被攻破" | ADR-15；8.2 |
| 13 | 内核/VMM 升级作废存量快照（48h 补丁 SLA 使其反复发生） | **两类快照分合同**：模板快照 = 可再生缓存（三元组 key、CI 自动重建）；paused 快照 = 版本钉住（N-1 兼容节点 + 默认 7 天保留期 + 旧内核恢复警告）；跨版本升级列 P2 | ADR-16；FR-5.4；FR-7.2；8.4 |
| 14 | 自研 raft 选主与引入 etcd 构成两套共识系统 | **不自研 raft**：集群统一用 etcd 承担元数据/选主/租约（内嵌可选），Orchestrator active-standby；store 窄接口双实现（SQLite/etcd）使 M1 平滑演进到 M3；易失态走 etcd lease 实现故障自动回收；`cluster init` 含一次性迁移；弃用 PostgreSQL 选项 | ADR-5（修正）；ADR-17；6.2；7.10 |
| 15 | OCI 镜像转 rootfs 的 init 归属与容器语义边界（谁是 PID 1） | **sl-envd 作为 PID 1**（挂载/僵尸回收/信号转发）；OCI 语义取舍：ENV/WORKDIR/USER 物化、ENTRYPOINT 不自动执行（映射 `start_cmd`）、EXPOSE 仅元数据、systemd 镜像不支持；构建期物化配置，guest 零 OCI 解析 | ADR-18；6.2；7.4 注记 |
| 16 | M1 依赖矛盾：FR-4.2 模板流水线依赖快照（排在 M2）；域名白名单阻塞于选型却挂在 P0 | **按内部引擎/用户 API 重新切分**：M1 交付快照/恢复引擎（内部能力，创建即走预烘焙恢复路径，P50 ≤500ms 无池），M2 交付 pause/resume 用户 API + 预热池；**FR-3.2 拆分**：3.2a IP/端口白名单（P0/M1，iptables），3.2b 域名粒度（P1，阻塞于 14.2-4） | 第 11 章；FR-4.2；FR-3.2a/b；7.3 |
| 17 | 构建期网络与隔离空白（RUN 需要出口 vs deny-by-default；构建本身执行不可信代码） | **构建即沙箱**：RUN 在专用构建沙箱执行，复用同一隔离栈；`build_network` 独立三档策略（allow-all 默认/whitelist/deny）；构建沙箱 TTL/审计/无端口暴露/不持凭据；产物签名；可复现构建列 P2 | ADR-19；FR-4.5；6.2 |
| 18 | 域名级白名单实现选型（原 14.2 遗留事项 4） | **DNS 劫持 + 动态 IP 集合为主机制（P1）**，与 FR-3.4 共用 resolver；**SNI 代理为 P3 严格模式（P2）**；"eBPF L7"为数据通路实现细节，从选项中排除；三条已知限制文档化 | ADR-20；FR-3.2b/3.4；14.2 删项 |
| 19 | 500 沙箱/节点下 iptables 与 eBPF 的数据通路选型 | **V1 用 nftables + 每沙箱 table/set**（原子事务、销毁即删表、运维可审计）；node agent 留防火墙后端抽象；eBPF 降级为 P2 可选后端，明确三个触发条件 | ADR-21；ADR-7；FR-3.2a |
| 20 | "API 无状态"与 WS 长连接矛盾；签名 URL 网关缺席 | **控制面/数据面分离**：新增 sandlocker-gw 组件承载全部长连接（ticket 模式、节点外拨、无状态 HMAC 验签、通配符 TLS）；单机为进程内模块、集群独立副本；M2 落地 | ADR-22；6.1/6.2；FR-2.3/3.3；第 11 章 |
| 21 | rootfs CoW 实现缺失；P50 ≤100ms 的恢复路径与池内存预算未定义 | **dm thin pool 做块层 CoW**（FC 无 virtio-fs，文件层方案不成立）；**恢复 = mmap 缺页**，SLO 前提是 page cache 热；池分温池（默认，不占 guest 内存）/热池（默认 0，显式内存预算）；快照本地性调度；uffd 远程懒加载 P2 | ADR-23；6.3；8.1 |
| 22 | OCI Runtime 形态复杂度低估（原 7.9 一句话带过） | 维持砍单预案（GA 后）；**定位为 ABI 之上的薄 shim**（能力收窄声明：OCI 形态无 pause/resume/fork）；复杂度构成与启动前提（API 冻结 + 契约测试套件）留档 | ADR-24；7.9 |
| 23 | 快照树删除/GC 语义空白（增量内存 diff 使删中间节点需合并） | **V1 内存快照全量自包含 + 磁盘 dm-thin 块级增量**：任意节点可独立删除、无合并操作；快照不可变；paused 沙箱 backing 保护；统一异步 GC + 孤儿对账；配额前置检查；增量内存 diff 列 P2 | ADR-25；ADR-6（修正）；FR-5.2/5.5 |
| 24 | 遥测默认开启（opt-out）与 P3 合规画像冲突（修订 14.1 决策 5 / ADR-10） | **分部署形态**：单机开发模式 opt-out（首次运行显式提示，一条命令关闭）；集群/生产模式 **opt-in**（默认关闭，需显式开启）；收集范围不变（仅聚合指标，不收集命令/文件/环境变量内容）；字段清单开启前可见；第 12 章北极星指标改为自愿上报 + 调研的估算口径 | 14.1 决策 5（修订）；第 12 章；14.2-3 |

### 14.2 遗留事项（不阻塞 M0 启动）

1. **域名/商标检索**：sandlocker.dev / sandlocker.io 可用性与商标冲突检索，M1 公开发布前完成。
2. **自带内核的版本跟进策略**：跟踪上游 LTS 内核的升级节奏（如每季度 rebase + 安全补丁 48h 内跟进），M0 期间确定并写入维护文档。
3. **遥测具体字段清单**：M1 发布前在文档站公开完整收集字段与样例 payload（用户开启遥测前可见，决策 24）。

---

## 15. 附录

### 15.1 术语表

| 术语 | 含义 |
| --- | --- |
| microVM | 精简设备模型的轻量虚拟机，Firecracker 为代表 |
| 用户态内核 | 在用户空间重实现 Linux syscall 接口的隔离方案，gVisor Sentry 为代表 |
| Sandbox ABI | SandLocker 的沙箱后端统一抽象接口 |
| 预烘焙快照 | 模板构建期完成启动并打快照，创建时直接恢复 |
| 预热池 | 预先创建并暂停的沙箱实例池，命中即毫秒级交付 |
| envd | e2b 沙箱内驻留 daemon 的架构模式，本项目对应组件为 sl-envd |

### 15.2 主要参考资料

- e2b 产品与架构（Firecracker 选型、p50 78ms、envd 模式、全栈开源）[^1^]
- 隔离技术对比：Firecracker <125ms / <5MiB；gVisor 50–100ms、GPU/TPU 原生、checkpoint-restore；Kata 150–300ms [^16^][^17^][^18^]
- 竞品冷启动与定位矩阵（Daytona/Modal/Northflank/Morph/Fly/Freestyle）[^12^][^24^]
- AI Agent 沙箱威胁模型与隔离层级决策框架 [^19^][^20^][^23^]
- Kubernetes agent-sandbox 子项目（gVisor 默认、Kata 可插拔、CRD 体系）[^16^]
- Firecracker 生产化改造的工程成本（"变成虚拟化公司"）[^22^]

---

[^1^]: https://checkthat.ai/brands/e2b
[^12^]: https://www.morphllm.com/comparisons/daytona-alternative
[^16^]: https://www.agenticwire.news/article/gvisor-vs-firecracker
[^17^]: https://eitt.academy/knowledge-base/container-cold-start-times-comparison-2024-2026/
[^18^]: https://github.com/copyleftdev/micro-containers
[^19^]: https://turion.ai/blog/agent-sandboxing-firecracker-gvisor-microvm-architecture/
[^20^]: https://ecosistemastartup.com/docker-sandbox-api-guia-para-founders-de-saas-2026/
[^21^]: https://zylos.ai/research/2026-06-13-remote-tool-execution-cloud-sandbox-platforms/
[^22^]: https://edera.dev/stories/kata-vs-firecracker-vs-gvisor-isolation-compared
[^23^]: https://www.softwareseni.com/firecracker-gvisor-containers-and-webassembly-comparing-isolation-technologies-for-ai-agents/
[^24^]: https://skywork.ai/skypage/en/ai-engineer-deep-dive/1978019564182491136
