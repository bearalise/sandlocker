# 裸金属 SLO 取证 Runbook（M3-Q9 / M3-Q10）

| 项目 | 内容 |
| --- | --- |
| 用途 | 按需租云裸金属，产出 PRD §8.1 的 SLO 取证，跑完即毁（计划 §4 D4） |
| 对应 | **M3-Q9**（单节点密度 + 创建/恢复分位）、**M3-Q10**（3 节点集群 SLO，硬出口） |
| 前提 | 本文档不含开户/预算——那是须**提前拉动**的非工程前置（计划 §5 前置依赖②） |

> **这笔债卡了三个里程碑**（M2-Q10 顺延两次）。根因不是工程没就绪，而是一直当成「买/常驻一台
> 64C/128G」（capex）。D4 已把它重构成**按小时租**（opex）：工程侧全部就位，缺的只是一台机器。

---

## 0. 先看这里：为什么不能「租了再说」

机器是按小时计费、跑完即毁的。**收工时必须拿到一个结论，而不是一份待人肉比对的 JSONL。**
为此已经补齐三处（2026-08-31）：

1. **`scripts/bench/slo-gate.sh`** —— §8.1 六行口径**集中编码在一处**，输出判定表 + 退出码表态。
   裸金属 job 用**严格档**（`SLO_STRICT=1`）：**任一行缺测即失败**。因为 M3-Q9 的判据是
   「创建/恢复分位在裸金属产出 SLO 口径」，缺一格就是没产出，不能当通过。
2. **密度分两档跑** —— §8.1 的密度是**两行**：≥200 @ 默认规格 2vCPU/512MiB，≥500 @ micro 128MiB。
   此前 `sl-node run` 把 machine-config 写死 `1 vCPU / 128MiB`，于是密度基准量的其实是 **micro 档，
   却被 `DENSITY_MIN=200` 当作「默认规格达标」**——内存差 4 倍，会得出偏乐观且贴错标签的结论。
   现在 `--vcpus/--mem-mib` 可配，两档各跑一趟，规格随实测一并写进 JSON。
3. **`bench-exec-overhead.sh`** —— §8.1 的「exec 启动开销 ≤20ms」此前**没有任何测量**，
   严格档下会直接缺一格。现已补上。

---

## 1. 机型选型

**硬要求：**

- **真裸金属 / 真 KVM，不能是嵌套虚拟化。** 嵌套虚拟化下 Firecracker 的冷启动与恢复数字对
  §8.1 毫无参考价值——这是整件事的前提，选型时第一个确认项。开机后先跑 §3 的自检。

  > **易踩的坑：把云厂商的「云服务器」当成裸金属。** 腾讯云 **CVM 是虚拟机**产品，其物理服务器
  > 叫**黑石（CBM）**；阿里云对应的是**神龙/弹性裸金属**；AWS 要选 `*.metal` 实例族而非普通 EC2。
  > 标准云 VM 多数根本不向 guest 暴露 VMX/SVM，`/dev/kvm` 压根不存在，基准会整批 skip；
  > 即便某机型支持嵌套，分位也不能当 §8.1 的绝对口径。
  >
  > **工具侧已经把这条钉死**：`run-all.sh` 把宿主类型（`host_kind`）写进结果的**每一行**，
  > `slo-gate.sh` 严格档对非 `bare-metal` 直接**拒收并退 3**。两份 JSONL 除了这个标记长得
  > 一模一样，不钉住就迟早有人拿虚拟机数据当出口证据。`host_kind` 采**必须有正面证据才判
  > bare-metal**的策略（容器 / systemd-detect-virt / hypervisor flag / DMI 厂商串逐级判定），
  > 判不出就是 `unknown`，严格档同样拒收。
  >
  > **只能用云 VM 时**走计划 §4 D4 的**逃生口**：去掉 `SLO_STRICT` 跑，产出**方法学 + 相对分位**，
  > 绝对 SLO 标「待补」并做 go/no-go 上报——**不作为计划，只作兜底**。
- **规格要对得上参考机型 64C/128G**——§8.1 的密度口径写的就是「64C/128G 节点」，**参考机型是
  判据的一部分，不是背景说明**。

  > **比参考机型小**：数字不能直接对口径，只能做方法学验证。
  >
  > **比参考机型大**（例如只能买到 96C/384G）：**密度两行不能直接用**。密度是内存约束
  > （`bench-density.sh` 的停因通常是 `mem-floor`），机器越大门线越容易跨过——384G 上
  > 200×512MiB 只占 26%、500×128MiB 只占 16%，必然 PASS，但**证明不了 64C/128G 节点上成立**。
  > 这与「micro 档冒充默认档」是同一类错误：数字对，理由错。
  >
  > **正确做法**：加内核启动参数重启，把机器**真的**约束成参考机型，再跑密度：
  >
  > ```
  > mem=128G maxcpus=64
  > ```
  >
  > 这样产出的数字直接对得上 §8.1，不需要任何折算或辩解。有余力可以再不约束跑一遍密度，
  > 记录该机器的真实容量上限**备查**（不作为取证）。
  >
  > **延迟四行不受影响**（池命中 P50 / 冷启动 P99 / 恢复 P50 / exec 开销）——那是每次操作的
  > 延迟，不是容量约束，大机器上跑完全有效。
  >
  > `slo-gate.sh` 会校核宿主规格：超出参考机型 20% 容差时，密度两行判为**不认**，严格档失败。
  > 确有理由在大机器上认这两行时须显式 `SLO_DENSITY_HOST_OK=1`，并在出口评审写明理由。
- **本地 NVMe**。存储栈用 reflink/CoW（ADR-23），网络盘会把 copy 段的分位彻底带偏。
- **按小时计费**（D4 的 opex 前提）。按月起租的产品要算清最短计费周期。

**候选**（具体规格/价格以当下官网为准，此处不列数字以免过期）：

| 供应商 | 备注 |
| --- | --- |
| 腾讯云**黑石 CBM** | 物理服务器。**不是 CVM**——CVM 是虚拟机，不满足硬要求 |
| 阿里云**弹性裸金属（神龙）** | 物理服务器 |
| Equinix Metal | 真裸金属、按小时，常用于此类基准 |
| AWS `*.metal`（如 `m5.metal` / `c5.metal`） | 按小时，裸金属实例族；注意区分普通 EC2（嵌套） |
| OVH / Hetzner 独服 | 更便宜，但常按月起租，算清最短周期 |

**要几台：**

- **M3-Q9（单节点）**：1 台。
- **M3-Q10（3 节点集群，硬出口）**：3 台 + 一个 etcd（可跑在其中一台上）。

---

## 2. 两枪怎么打

计划 §4 D4 原本安排两枪：W2–W3 单节点基线（de-risk），W12 三节点出口取证。
**第一枪没打成**，所以现在的建议是：

| 枪 | 时机 | 目的 | 机器 |
| --- | --- | --- | --- |
| 第一枪 | **尽早，不要等 W12** | 只回答「§8.1 口径够不够得着」。不达标要留出补救时间 | 1 台，几小时 |
| 第二枪 | W12 | M3-Q9 + M3-Q10 出口取证 | 3 台 |

把第一枪推到 W12 意味着：**如果密度或分位达不到，你会在出口评审当天才知道，零缓冲。**
这正是这笔债拖了三个里程碑之后最大的剩余风险。

---

## 3. 开机后：环境自检

```bash
# ① 真 KVM？（这一条不过，后面全部无意义）
ls -l /dev/kvm && grep -c -E 'vmx|svm' /proc/cpuinfo
# 嵌套虚拟化的判别：裸金属上 hypervisor flag 应当**不存在**
grep -q hypervisor /proc/cpuinfo && echo "⚠️ 检测到 hypervisor flag——很可能不是裸金属，停下确认" || echo "OK：无 hypervisor flag"

# ② 规格对得上口径？（要 ≥64C / ≥128G）
nproc && free -g

# ③ 仓库自带的环境检查
git clone https://github.com/bearalise/sandlocker && cd sandlocker
scripts/bench/check-env.sh

# ④ 让工具自己判一次——这是 slo-gate.sh 严格档用的**同一个函数**，
#    它说 bare-metal 才作数（说 unknown / virtualized / container 都会被拒收）。
( . scripts/bench/_common.sh; echo "host_kind=$(host_kind)" )
```

---

## 4. 接进 CI：注册 ephemeral self-hosted runner

`bench-density` job 的 `runs-on` 是 `[self-hosted, linux, x64, bare-metal]`，**四个标签都要打上**。

```bash
# GitHub → Settings → Actions → Runners → New self-hosted runner，取 TOKEN
mkdir actions-runner && cd actions-runner
curl -o r.tar.gz -L https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64.tar.gz
tar xzf r.tar.gz

# --ephemeral：跑完一个 job 就自动注销，正配「用完即毁」
./config.sh --url https://github.com/bearalise/sandlocker \
  --token <TOKEN> \
  --labels self-hosted,linux,x64,bare-metal \
  --ephemeral --unattended

./run.sh    # 前台跑；job 结束后自行退出
```

然后 **Actions → bench → Run workflow** 手动 dispatch（`bench.yml` 目前只保留手动触发）。

**不想装 runner 的替代路径**：直接在机器上跑，本地判定，把 `results.jsonl` 带走。

```bash
sudo apt-get update && sudo apt-get install -y build-essential flex bison libelf-dev libssl-dev bc
scripts/fetch-firecracker.sh && scripts/build-kernel.sh

# ① 默认规格档
BENCH_DENSITY=1 DENSITY_SPEC_LABEL=default DENSITY_VCPUS=2 DENSITY_MEM_MIB=512 \
  DENSITY_MAX=400 DENSITY_MIN=200 POOL_P50_BUDGET_MS=100 \
  scripts/bench/run-all.sh

# ② micro 规格档（只重跑密度）
BENCH_DENSITY=1 DENSITY_SPEC_LABEL=micro DENSITY_VCPUS=1 DENSITY_MEM_MIB=128 \
  DENSITY_MAX=900 DENSITY_MIN=500 BENCH_ONLY=density \
  scripts/bench/run-all.sh

# ③ 判定（严格档：缺测即失败）
SLO_STRICT=1 scripts/bench/slo-gate.sh build/bench/results.jsonl
```

---

## 5. 收工前必须带走的东西

- `build/bench/results.jsonl` —— 原始数据，**机器毁掉就再也拿不到了**。
- `slo-gate.sh` 的判定表输出（贴进 M3 出口评审）。
- 机器型号 / 核数 / 内存 / 磁盘 / 内核版本 / Firecracker 版本 —— 分位数脱离机型没有意义。
- 如果**不达标**：`density` 的 `stop_reason` 与 `curve` 字段（是撞内存地板还是启动失败），
  以及 `restore_create` 的分段 P50（copy / api-ready / load / resume 哪一段是大头）。
  这些决定了补救方向是配置还是实现。

**口径不下调**（计划 §4 D4）。不达标时的正确动作是配置/实现改进后重跑，或走 go/no-go 上报——
不是改 `SLO_*` 环境变量把线放低。那几个 env 是给实验用的，出口取证不得动。

---

## 6. 毁机 checklist

1. 确认 `results.jsonl` 与判定输出**已经拷走**。
2. 注销 runner（`./config.sh remove --token <TOKEN>`；`--ephemeral` 会自动注销，仍建议确认）。
3. 从 GitHub Runners 列表确认已消失。
4. 删机器 —— **确认计费已停**（有些供应商保留了预留 IP / 卷仍在计费）。
5. 机器上如果放过 `--snap-kms-key` 的根密钥，销毁前先抹掉（ADR-15）。

---

## 7. M3-Q10（3 节点集群 SLO）：**当前还没有 CI job**

**这是一个已知缺口，如实记录。** `bench.yml` 里只有单节点的 `bench-density`；三节点集群的
跨节点创建/调度/回收与分位 SLO 没有任何自动化承载。W12 之前需要补一个 `bench-cluster` job，
或按下面的手动步骤跑并人工记录。

手动路径（三台机器 A/B/C，etcd 跑在 A 上）：

```bash
# A：起 etcd + 控制面副本
sl-node --serve --etcd http://A:2379 --gw gw:7880 --gw-url http://gw:7879 --gw-tls-* ...
# B、C：同样接同一个 etcd（active-standby 由选主决定谁是 leader）
# 网关：sandlocker-gw --bind 0.0.0.0:7879 --node-bind 0.0.0.0:7880 --etcd http://A:2379 --tls-*
```

要产出的证据（对齐 M3-Q10 判据）：

- 跨节点创建/调度：沙箱落到非本副本的节点上，`/v1/sandboxes` 三副本视图一致。
- 创建/恢复分位达 §8.1 口径（同 `slo-gate.sh`，但样本来自跨节点路径）。
- 节点故障回收在 SLO 内：杀掉一台，心跳 lease 过期 → leader 回收其名下沙箱的耗时。
- 选主切换 / 网关副本切换不破坏 SLO。

部署细节见 `docs/design/部署指南.md` §4.5；集群机制的对账命令见
`docs/design/M3技术计划.md` 的 W1–W5 各周落地段。
