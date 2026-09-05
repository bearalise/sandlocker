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
- **本地 NVMe**，且**文件系统必须支持 reflink**（见下节）。网络盘会把 copy 段的分位彻底带偏。
- **按小时计费**（D4 的 opex 前提）。按月起租的产品要算清最短计费周期。

## 1.5 操作系统与文件系统

### 发行版：**Ubuntu 22.04 LTS**（别选 24.04）

理由有两条，都很具体：

- **apt 依赖与文档/CI 逐条对得上**——`bench.yml` 跑在 `ubuntu-latest`，部署指南 §1.1 的包名
  也是 Debian 系。换 RHEL 系要自己映射一遍包名，租机时间不该花在这上面。
- **24.04 默认拦非特权 user namespace**（`kernel.apparmor_restrict_unprivileged_userns=1`，
  Ubuntu 23.10 起）。本项目的网络与私有 rootfs 全走 rootless `unshare --map-root-user`，
  被拦住就直接跑不起来。虽然一条 sysctl 能关（部署指南 §5.1 有表），但没必要给自己埋雷。
  **22.04 没有这个限制。**

Debian 12 也可以，但历史上需要 `kernel.unprivileged_userns_clone=1`，同样见 §5.1。

**只有 Ubuntu 20.04 可选时：能用**，apt 依赖全齐（实测：gcc 9.4 / xfsprogs 5.3 / nftables 0.9.3 /
make 4.2.1），userns 默认开（没有 24.04 那个 AppArmor 限制），`mkfs.xfs` 也已默认 `reflink=1`
（xfsprogs ≥5.1 起）。两点差异：

- **GCC 9.4 建 6.6 guest 内核：已实测通过**（2026-08-31，Inspur SA5212M5 / 96C / Ubuntu 20.04，
  Linux 6.6.155，1m31s wall）。此前只能说「名义上够（6.6 最低要求 GCC 5.1）、大概率能过」，
  现在是确认的。仍建议上机第一件事就跑 `scripts/build-kernel.sh`——它是跑基准前的前置步骤，
  万一换了内核系列出问题也能早暴露、不浪费后续租机时间。两条兜底备用：

  ```bash
  # A. 换 GCC 10（20.04 仓库里有 10.5.0）
  sudo apt-get install -y gcc-10
  sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100
  # B. 换更老的内核系列（脚本第一个参数即主版本）
  scripts/build-kernel.sh 6.1
  ```

- **cgroup v1 默认，不是阻塞项**。`cgroup_v2()` 只是探测：检测到 v2 才给 jailer 传
  `--cgroup-version 2`，否则走 v1，优雅降级。想切 v2 可在 GRUB 顺手加
  `systemd.unified_cgroup_hierarchy=1`（反正要改 GRUB 加 `mem=128G maxcpus=64`）。

20.04 标准支持已于 2025-04 结束——临时基准机可接受，别拿它当长期节点。

开机后先自测一句，出 `OK` 再往下：

```bash
unshare --user --map-root-user true && echo OK || echo BLOCKED
```

### 文件系统：**XFS（reflink=1）或 Btrfs —— 不能是 ext4**

这一条会**静默**把创建分位带偏，务必当回事。

创建热路径每次都要拷一份私有 rootfs，走的是 `cp --reflink=auto`（`orch.rs` 的 `cp_reflink`）。
**ext4 不支持 reflink**，`--reflink=auto` 会**静默回退成全量拷贝**——密度爬坡起 200~500 个实例
就是 200~500 次全量拷贝。后果：`restore_create` 的 `copy` 分段与创建 P50 被显著抬高、密度爬坡
被拖慢，**而且全程没有任何报错**，事后看 JSONL 完全看不出是文件系统的锅。

Ubuntu 默认给你 ext4，所以要**手动把 NVMe 格成 XFS** 并挂到工作目录：

```bash
sudo mkfs.xfs -f /dev/nvme0n1          # mkfs.xfs 现默认 reflink=1
sudo mkdir -p /srv/bench && sudo mount /dev/nvme0n1 /srv/bench
sudo chown "$USER" /srv/bench
xfs_info /srv/bench | grep reflink     # 须为 reflink=1
cd /srv/bench && git clone https://github.com/bearalise/sandlocker && cd sandlocker
```

`scripts/bench/check-env.sh` 会**实测一次** reflink（真做一次 `cp --reflink=always`，
而不是看文件系统名），不支持时给出 WARN 并说明后果。

### 国内网络：三个下载点会慢

`build-rootfs.sh` 已内置阿里云/清华/中科大的 Alpine 镜像，但另外三处没有。都是「**文件已存在
就跳过下载**」，所以投喂即可：

| 下载点 | 现象 | 办法 |
| --- | --- | --- |
| rustup + crates.io | 装 rustup 慢；`cargo build` 拉百余 crate 更慢 | `RUSTUP_DIST_SERVER=https://rsproxy.cn` + `~/.cargo/config.toml` 换 sparse 源 |
| Firecracker 二进制 | release 资源在 `objects.githubusercontent.com`，与 API 不同域，常慢 | 经 GitHub 代理下到 `build/firecracker/firecracker-<V>-x86_64.tgz`，再 `scripts/fetch-firecracker.sh <V>`；或本地下好 scp（才十几 MB） |
| 内核源码 ~145MB | `cdn.kernel.org` 慢 | 先用脚本同款逻辑解析出版本号，从清华/中科大 `kernel/v6.x/` 下到 `build/kernel/linux-<V>.tar.xz`，再跑 `build-kernel.sh` |

版本解析那步只拉目录列表，很小很快，不用管。

### 内核

发行版自带即可（22.04 是 5.15，20.04 是 5.4）。KVM / device-mapper thin（ADR-23）/ nftables / netns /
XFS reflink 都在其中。**不要**为了追新去换内核——guest 内核由 `scripts/build-kernel.sh`
自己构建，与宿主内核版本无关。

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

# ③ 非特权 userns 是否可用（24.04 默认被拦；本项目 rootless 路径依赖它）
unshare --user --map-root-user true && echo OK || echo BLOCKED

# ④ 仓库自带的环境检查（含 reflink 实测——ext4 会静默回退全拷，抬高创建分位）
git clone https://github.com/bearalise/sandlocker && cd sandlocker
scripts/bench/check-env.sh

# ⑤ 让工具自己判一次——这是 slo-gate.sh 严格档用的**同一个函数**，
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

## 7. M3-Q10（3 节点集群 SLO）

`scripts/bench/bench-cluster.sh` 是这一枪的取证载体：拓扑/视图一致、跨节点生命周期分位、
节点失联回收、选主状态，四组指标一趟跑完，判定交 `slo-gate.sh`。

**先看清楚 mode。** 脚本给每一行结果打一个 `mode`：

| mode | 什么情况 | 算不算 M3-Q10 取证 |
| --- | --- | --- |
| `single-host` | 三个守护跑在同一台机器上 | **不算**。集群机制会真的动起来（etcd 眼里就是三个节点），但没有网络跳数、没有独立的内存/IO 竞争、杀一个"节点"也不是杀一台机器 |
| `multi-host` | 三台真机 | **算**，这才是出口证据 |

`slo-gate.sh` 严格档对 `single-host` 的集群行**直接拒收**——理由与它拒收非裸金属宿主完全相同：
两种数据在 JSONL 里长得一模一样，只差这个标记。`bench.yml` 的 `bench-cluster` job 跑的是
`single-host`，那是**机制回归**（跨节点路由/回收/选主还通不通），不是取证。

### 7.1 三台机器怎么起

三台 A/B/C，etcd 与网关跑在 A（或单独一台）：

```bash
# 网关（可多副本，前面挂 L4 LB）
sandlocker-gw --bind 0.0.0.0:7879 --node-bind 0.0.0.0:7880 --etcd http://A:2379 \
  --tls-cert gw.pem --tls-key gw.key --tls-ca ca.pem

# A / B / C 各起一个守护，接同一个 etcd（谁是 leader 由选主决定）
sl-node --serve --addr 0.0.0.0:7878 --etcd http://A:2379 \
  --gw gw:7880 --gw-url http://gw:7879 \
  --gw-tls-cert node.pem --gw-tls-key node.key --gw-tls-ca ca.pem --gw-tls-name sandlocker-gw
```

证书按部署指南 §4.5 造。三台都要有模板（`sl-node --build examples/hello.sandlocker.toml`）。

### 7.2 跑取证

在任意一台能同时够到三个副本的机器上：

```bash
BENCH_CLUSTER=1 BENCH_ONLY=cluster \
  CLUSTER_ETCD=http://A:2379 \
  CLUSTER_REPLICAS=http://A:7878,http://B:7878,http://C:7878 \
  CLUSTER_KILL_SSH=ubuntu@A,ubuntu@B,ubuntu@C \
  scripts/bench/run-all.sh

SLO_STRICT=1 scripts/bench/slo-gate.sh build/bench/results.jsonl
```

- `CLUSTER_REPLICAS` 里写副本的**对外地址**即可——脚本从各副本的 `/metrics`
  （`sandlocker_build_info{node="..."}`）问出它们真正的 node_id，不靠 URL 猜。守护绑
  `0.0.0.0` 或藏在 LB 后面都不影响。
- `CLUSTER_KILL_SSH` **与 `CLUSTER_REPLICAS` 同序**，用于「杀掉沙箱归属节点」那一步
  （`pkill -9 -x sl-node`）。条目数对不上脚本会拒绝执行，免得杀错机器。不给的话失联回收
  那一行会记成未测，严格档即失败。
- 分位样本量 `CLUSTER_N`（默认 10）；放置样本量 `CLUSTER_PLACE_N`（默认 3，须 ≥ 节点数才看得出铺开）。

### 7.3 收工前确认这几点

- `mode=multi-host`（不是 single-host——否则这趟白跑）
- `placement=scheduled` 且 `distinct_owners ≥ 2`。基准把创建**全部打给同一个副本**，所以
  这一行才是「跨节点调度成立」的证据；若是 `caller-local`（全落在一个节点上），多半是漏配
  `--gw-url`（没有它就没有放置）或节点没上报容量。`slo-gate.sh` 会把原因提示打出来。
- `cluster_reclaim.observed_s` 不是 `-1`（`-1` = 观测窗内没等到回收）。
- 顺手把 §7.4 的跨节点生命周期手测也跑一遍（脚本只覆盖 pause/resume，其余五个没覆盖）。

### 7.4 跨节点生命周期手测（M3 W4 余项的端到端）

`bench-cluster.sh` 只量了 pause/resume 两个动作的分位。另外六个控制面动作
（keepalive/fork/destroy/expose/unexpose/exposes）的端到端此前**只验到中继层**——票带着正确的
动作到了正确的节点，但节点侧真正调 `Orch::*` 那一段要 KVM + 多节点才跑得到。这是 M3 W4 余项
留下的唯一端到端缺口，三节点这一趟顺手带回来：

  ```bash
  SID=$(curl -sX POST http://B:7878/v1/sandboxes -d '{"template":"hello"}' | jq -r .id)
  # 归属只在 etcd 里（meta JSON 不含 node 字段）——确认归属**不是** C，再全程打 C。
  etcdctl --endpoints=http://A:2379 get --print-value-only "sandbox/$SID/node"
  for op in keepalive pause resume fork; do                        # 全部打到 **C**
    echo "== $op"; curl -si -X POST http://C:7878/v1/sandboxes/$SID/$op -d '{}' | head -1
  done
  curl -si -X DELETE http://C:7878/v1/sandboxes/$SID | head -1     # 期望 204，不是 404
  ```

  同时查 `GET /v1/audit`：跨节点的每一条变更都该在册（转发路径的审计此前是漏的，已修）。

部署细节见 `docs/design/部署指南.md` §4.5；集群机制的对账命令见
`docs/design/M3技术计划.md` 的 W1–W5 各周落地段。
