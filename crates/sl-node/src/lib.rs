//! sl-node — 宿主机节点代理原型（M0 W2 → M1 W1）。
//!
//! 启动 microVM 有三种形态（`--boot`）：
//!   - `api`（默认，M1 D1）：`firecracker --api-sock` + 经 HTTP API 逐段配置
//!     （machine-config/boot-source/drives/network/vsock）后 `PUT /actions InstanceStart`。
//!     这是快照 create/load 的前置（config-file 造不出快照），M1 起为正典。
//!   - `config-file`（M0 遗留，退役为对照）：`--no-api --config-file`，从零 boot、无快照。
//!   - `jailer`（M1 D1，需 root）：jailer 做 chroot+cgroup+降权后再拉起 FC（--api-sock），
//!     内核/rootfs/socket 落 chroot 内。最小权限沙箱，跑不可信代码的第一性需求。
//! 三者随后都经 vsock 与 guest 内 sl-envd 做 exec 往返（Q1）。
//!
//! CID 分配策略（ADR-4，M0 即记录）：
//!   W2 单 VM 固定 `guest_cid = 3`（2 为 host，0/1 保留）。
//!   M2 网关多路复用需要每节点 CID 空间管理（500 实例/节点），届时改为分配器发号；
//!   此处的固定值是那套分配器的退化特例。
//!
//! FC vsock host→guest 握手（Firecracker UDS 语义）：
//!   连接 uds_path → 发送 `CONNECT <port>\n` → 读回 `OK <hostport>\n` → 其后为裸流。

// FC HTTP API 客户端（D1）——api/jailer 启动路径经它逐段配置 microVM
mod fcapi;
use fcapi::FcApi;
// dm-thin 存储栈（ADR-23，W3）——base origin + per-sandbox thin snapshot 的 CoW 盘
mod dmthin;
// nftables 网络策略后端（ADR-21，W5）——per-sandbox table：默认 drop + IP/端口白名单
mod nftfw;
// live 网络拓扑（M2 W1）——具名 netns + veth + host NAT 出口 + tap，把 nftfw 门禁接进 live 出口
mod netlive;
// 模板构建引擎（ADR-19，W6）——sandlocker.toml → build-as-sandbox 跑 RUN → 预烘焙快照 + 签名入库
mod build;
// OCI 镜像当 rootfs 来源（M2-Q12 / ADR-18 / D5，W3）——host 侧薄 registry v2 拉取/tarball 加载 →
// 层展平 → bake ext4 交给 build.rs 当 base_rootfs。仅宿主 builder 用，guest sl-envd 零影响。
mod oci;
// M2 W10：数据面网关（ADR-22）——一次性 HMAC 签名 URL + 端口反代（FR-3.3）。
mod gateway;

mod expose;
// M2 W6：Sandbox ABI 契约（trait + 能力模型，ADR-14）+ Firecracker 后端实现。
mod backend;
mod fcbackend;
// M2 W7：gVisor(runsc) 第二后端（M2-Q4，短任务路径，能力空集）。
mod gvisorbackend;
// W7：进程内 orchestrator（生命周期 create/keepalive/destroy/tick + Q2/Q9）。
mod orch;
// M2 W4：预热池·温池（把 rootfs 拷贝/page-cache 预热移出 create 关键路径，M2-Q2）。
mod pool;
// W8：长驻守护 + 手写极简 REST server（--serve）——HTTP API + orchestrator + reaper 全进程内。
mod api;
mod auth;
mod quota;
mod audit;
mod metrics;
mod logsink;
// M3 W5 余项（ADR-22 / M3-Q3）：节点主动外拨持久流 + 网关无粘滞中继 + 集群内 mTLS。
// pub：`sandlocker-gw` 独立进程（src/bin/）要用同一套传输与 `gw_serve`。
pub mod dataplane;
// M3 W9（ADR-15 / M3-Q6）：快照信封加密——KMS 根密钥 → 租户 KEK → 每快照 DEK，4MiB 分块 AEAD。
mod snapcrypt;
// M3 W10（ADR-16 / M3-Q7）：快照保留期 GC + 版本钉住（模板/内核/VMM 三元组 + 兼容矩阵）。
mod retention;
// M3 W4 余项补完（M3-Q10）：多节点**放置**。W4 只做了跨节点可见性，创建路径从不查存活
// 节点集——沙箱落在哪全看客户端打给了谁。见模块头。
mod sched;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt; // pre_exec
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sl_proto::{read_msg, write_msg, Request, Response, ENVD_VSOCK_PORT};

const GUEST_CID: u32 = 3;
const READY_TIMEOUT: Duration = Duration::from_secs(20);

// 网络：每沙箱独立 netns + tap，rootless（unshare --net --map-root-user）。host 侧点对点
// 地址，无 NAT/无默认路由 → guest 出口天然为零（M0 结构性 deny-by-default）。W5 落地
// nftables per-sandbox table（ADR-21，见 nftfw.rs / --nftfw-reconcile 的 Q7 证据）：默认 drop
// + IP/端口白名单集合。把该 table 接进 live 运行路径（gate 真实出口）随 jailer --netns 落地。
const TAP_NAME: &str = "sltap0";
const HOST_CIDR: &str = "172.16.0.1/30";
const GUEST_MAC: &str = "AA:FC:00:00:00:01";
const NETNS_WRAPPER: &str = "scripts/netns-run.sh";

// microVM 内视角的 chroot 相对路径（jailer 模式下 FC 已 chroot 到 <jail>/root）。
// 非 jailer 模式 FC 不 chroot，用绝对 host 路径；两者由 boot 模式在 configure_via_api 里分派。
const JAIL_KERNEL: &str = "/vmlinux";
const JAIL_ROOTFS: &str = "/rootfs.ext4";
const JAIL_API_SOCK: &str = "/api.sock";
const JAIL_VSOCK: &str = "/vsock.sock";
const JAIL_ID: &str = "sl0"; // 单 VM 原型固定 id；多实例由分配器发号（M2）

/// microVM 启动形态（D1）。
#[derive(Clone, Copy, PartialEq)]
enum Boot {
    /// M0 遗留：`--no-api --config-file`，从零 boot、造不出快照。退役为对照。
    ConfigFile,
    /// M1 默认：`--api-sock` + HTTP API 逐段配置。快照 create/load 的前置。
    Api,
    /// M1：jailer chroot+cgroup+降权后再拉起 FC（--api-sock）。需 root。
    Jailer,
}

#[derive(Clone)]
struct Config {
    kernel: PathBuf,
    rootfs: PathBuf,
    fc_bin: PathBuf,
    jailer_bin: PathBuf,
    workdir: PathBuf,
    /// 启动形态（--boot api|config-file|jailer）。
    boot: Boot,
    /// --cmd "..."：即席执行单条命令并打印结果；缺省跑内置 demo 序列。
    cmd: Option<String>,
    /// --no-netns：退回 W3 无网络路径（对照/调试用）。
    netns: bool,
    /// --cycles N：反复 create/destroy N 次做销毁对账（Q6），不跑 demo 命令。
    cycles: usize,
    /// --json：boot→ready 后输出单行 JSON 计时并退出（供 bench 采集）。
    json: bool,
    /// --hold-secs N：就绪后保活 N 秒再干净销毁（供密度 bench 并发持有）。
    hold_secs: u64,
    /// jailer 降权目标 uid/gid（默认取当前用户，dev 内环文件属主一致即可）。
    jail_uid: u32,
    jail_gid: u32,
    /// --snap-create <dir>：API 启动→就绪→暂停→造快照到 <dir>，随后退出（W2）。
    snap_create: Option<PathBuf>,
    /// --snap-load <dir>：从 <dir> 恢复→resume→reinit→验一致性，随后退出（W2/W4）。
    snap_load: Option<PathBuf>,
    /// --clone-entropy-check <dir>：同快照恢复两实例，断言身份/熵皆异（Q3），随后退出（W4）。
    clone_entropy: Option<PathBuf>,
    /// --dmthin-reconcile：跑 dm-thin CoW 销毁对账（Q5），随后退出（W3）。
    dmthin_reconcile: bool,
    /// --nftfw-reconcile：跑 nftables 策略 Q7 对账（deny/allow/teardown），随后退出（W5，需 root）。
    nftfw_reconcile: bool,
    /// --thin：FC 挂 per-sandbox thin snapshot 为 rootfs 端到端跑（需 root，W3）。
    thin: bool,
    /// --build <sandlocker.toml>：模板构建引擎（ADR-19，W6）——解析 DSL→build-as-sandbox 跑 RUN→
    /// 预烘焙快照+内容寻址+签名入库，随后退出。W8 的 `sandlocker build` 包装它。
    build: Option<PathBuf>,
    /// --store <dir>：模板入库的 sl-store 目录（默认 build/templates），W6 构建产物注册用。
    store: Option<PathBuf>,
    /// --orch-reconcile <模板目录>：W7 生命周期 Q9 对账（create/keepalive/idle 回收/TTL 硬顶/
    /// 手动 destroy 零残留 + 并发双克隆隔离 + 模板不可变），随后退出。免 root（rootless mount-ns）。
    orch_reconcile: Option<PathBuf>,
    /// --orch-bench <模板目录>：W7 创建时延 Q2（进程内 create→destroy × --cycles，算 P50/P90+分段，
    /// P50≤500ms），随后退出。免 root。
    orch_bench: Option<PathBuf>,
    /// --serve：W8 长驻守护——起 HTTP REST API + 进程内 orchestrator + 后台 reaper tick，直到退出。
    serve: bool,
    /// --addr <host:port>：--serve 监听地址（默认 127.0.0.1:7878）。
    serve_addr: Option<String>,
    /// --tick-secs N：--serve 后台 reaper 周期（默认 5s）。
    tick_secs: u64,
    /// --template-root <dir>：--serve 模板仓库根（默认 build/templates；模板名→目录解析用）。
    template_root: Option<PathBuf>,
    /// --run-root <dir>：--serve 实例运行目录根（默认 <workdir>/instances）。
    run_root: Option<PathBuf>,
    /// --net-live：M2 live 网络门禁开关。开且 root 时，`--snap-load` 走**时序探针 live 化**档——
    /// 起 per-instance 具名 netns（[`netlive::ns_for`]）、恢复进该 netns、`apply_network_policy`
    /// 在其上 fail-closed ensure forward-hook 门禁（resume **之前**）→ `policy_margin_us` 真实非 0。
    /// 默认 false → 保 M1 匿名 `unshare --net` 无出口路径（rootless 降级，行为零回归）。
    /// 注：真流量 deny/allow 端到端证明走冷启动的 `--net-live-reconcile`（快照无网卡，恢复态发不出包）。
    net_live: bool,
    /// --uplink <iface>：live NAT masquerade 的出口网卡（缺省自动探测默认路由 dev）。
    uplink: Option<String>,
    /// --net-gate-reconcile：M2 W1 live 出口门禁对账（拓扑+门禁+NAT+无残留），随后退出（需 root）。
    net_gate_reconcile: bool,
    /// --net-live-reconcile <模板目录>：M2 W2 方案 A 真 microVM live e2e 对账——冷启动一台真 VM 进
    /// per-instance 具名 netns，forward-hook 门禁 resume 前 ensure（默认 drop）→ guest 侧 nc 到
    /// host：无 allow 被拒 / add_allow 后放行（allow 成功即正向证明 guest 真发包）→ 审计 ruleset +
    /// NAT masquerade → 拆干净无残留 → 单行 `{"metric":"net_live",...}`，随后退出（需 root+KVM+nft+ip）。
    net_live_reconcile: Option<PathBuf>,
    /// --oci-pull <ref|archive>：M2 W3 独立取证——拉取/加载 OCI 镜像 → 展平 → bake ext4，输出单行
    /// `{"metric":"oci_pull",...}`，随后退出。`<ref>` 接受远程引用（docker://python:3.12-slim /
    /// bare python:3.12-slim）或本地 tarball（docker-archive:./img.tar / oci-archive:./img.tar）。
    /// 不 boot（boot 起 Python 证明走 --build + --snap-load）。
    oci_pull: Option<String>,
    /// --oci-out <path>：--oci-pull 产出 ext4 的落点（缺省 build/oci-out/rootfs.ext4）。
    oci_out: Option<PathBuf>,
    /// --pool-bench <模板目录>：M2 W4 温池冷/热分档基准（M2-Q2 起步）——同模板各跑 --cycles 次，
    /// 对比无池（copy 在关键路径）vs 温池预填满（池命中 copy_ms=0），单行 `{"metric":"pool_bench",...}`，
    /// 随后退出。免 root。
    pool_bench: Option<PathBuf>,
    /// --pool-size N：M2 W4 --serve 温池目标水位（默认 2；0 关闭退冷路径）。
    pool_size: usize,
    /// --pool-template <name>：M2 W4 --serve 温池绑定的模板名（经 template_root 解析）。
    /// 缺省不建池（--serve 全走冷路径，零回归）。请求命中同模板走池命中路径。
    pool_template: Option<String>,
    /// --hot-size N：M2 W5 --serve 热池目标水位（默认 0=关；>0 预置暂停态 VM，命中优先于温池）。
    /// 模板复用 --pool-template。parked VM 常驻内存，故默认关、显式开启。
    hot_size: usize,
    /// --gvisor：M2 W7 注册 gVisor(runsc) 第二后端（且 runsc 探活成功时）。默认关。
    gvisor: bool,
    /// --gvisor-bin <path>：runsc 可执行路径（默认 "runsc"，取 PATH）。
    gvisor_bin: PathBuf,
    /// --gvisor-reconcile <模板目录>：M2-Q4 gVisor 后端对账（create/exec/fs/destroy + 能力 + 可切换 +
    /// 零残留），随后退出。rootless 无需 root/KVM；runsc 缺失则 skip。
    gvisor_reconcile: Option<PathBuf>,
    /// --abi-contract <模板目录>：M2 W8 硬出口② ABI 契约套件——同套场景对 fc/gvisor 逐后端跑 + 兼容
    /// 矩阵。fc 需 /dev/kvm、gvisor 需 runsc；两后端齐全全过即 pass。随后退出。
    abi_contract: Option<PathBuf>,
    /// --q5-reconcile <模板目录>：M2-Q5 pause/resume + fork 克隆熵复验（reinit 后身份必异 + 能力门控 +
    /// 零残留），随后退出。免 root（走恢复路径）。
    q5_reconcile: Option<PathBuf>,
    /// --gw-addr <host:port>：M2 W10 数据面网关监听地址（默认 127.0.0.1:7879，与控制面 7878 分离）。
    gw_addr: Option<String>,
    /// --gw-reconcile <模板目录>：M2-Q6 数据面网关对账（ticket 换直连 + 一次性/篡改/过期拒 + 端口暴露
    /// + 零残留），随后退出。免额外 root（走恢复路径）。
    gw_reconcile: Option<PathBuf>,
    /// --pty-reconcile <模板目录>：M2-Q7 交互式 PTY 对账（双向流 + 窗口 resize + 会话收敛 + 零残留），
    /// 随后退出。免 root（走恢复路径）。
    pty_reconcile: Option<PathBuf>,
    /// --exec-stream-reconcile <模板目录>：流式 exec 对账（逐块到达 + stdout/stderr 分离 + 退出码
    /// 透传 + 零残留），随后退出。免 root（走恢复路径）。
    exec_stream_reconcile: Option<PathBuf>,
    /// --net-egress-reconcile <模板目录>：运行时网络出口对账（network:egress 冷启动带 NIC + DNS/NAT
    /// 出站 + destroy 零残留），随后退出。需 root+KVM+nft（非 root skip）。
    net_egress_reconcile: Option<PathBuf>,
    /// --expose-reconcile <模板目录>：端口暴露 L4 透传对账（keep-alive/非 GET/流式/并发/拆除/零残留），
    /// 随后退出。免 root（走恢复路径）。
    expose_reconcile: Option<PathBuf>,
    /// --expose-allow-public：放行端口暴露 bind 到非回环地址（默认拒绝；纯 L4 透传无鉴权，仅可信网络）。
    expose_allow_public: bool,
    /// --store-contract：M3 W1 store 契约对账（M3-Q1）——恒对 SqliteStore（file+in-memory）跑
    /// 后端无关契约套件；若同时给 --etcd 且以 `--features cluster` 构建，则对 EtcdStore 再跑同一套。
    /// 随后退出。免 root（纯元数据）。
    store_contract: bool,
    /// --etcd <endpoint>：etcd v3 gateway 地址（如 http://127.0.0.1:2379）。--store-contract /
    /// --cluster-init / --election-reconcile 用；需以 `--features cluster` 构建，否则报错提示重建。
    etcd: Option<String>,
    /// --cluster-init：M3 W2 一次性迁移（ADR-17）——把 `--store <sqlite>` 全量键搬到 `--etcd <ep>`。
    /// 停机迁移事件（文档明示）；需 `--features cluster`。随后退出。
    cluster_init: bool,
    /// --election-reconcile：M3-Q2 选主对账——双竞选者证单 leader + resign failover + 无双主。
    /// 默认对 SQLite 临时文件跑；给 --etcd 且 cluster 构建则对真 etcd 跑同一套。随后退出。
    election_reconcile: bool,
    /// --node-reclaim-reconcile：M3-Q2 节点失联回收对账——节点心跳 + 失联节点名下沙箱被回收 +
    /// 存活节点不受影响 + 护栏不回收自身。默认 SQLite 临时文件；--etcd 则对真 etcd 跑同一套。随后退出。
    node_reclaim_reconcile: bool,
    /// --cluster-reconcile：M3 W4 集群合龙对账——跨副本共享态（A 写 B 见）+ 失联回收跨副本同步。
    /// 默认 SQLite 两句柄；--etcd 则对真 etcd 跑（真跨副本）。随后退出。
    cluster_reconcile: bool,
    /// --gw-cluster-reconcile：M3 W5 网关拆副本对账——共享 secret 使 A 签发 B 可验（无状态验签）+
    /// 一次性跨副本（B 用过 A 再用即拒）+ 篡改/过期拒。默认 SQLite 两句柄；--etcd 则真 etcd。随后退出。
    gw_cluster_reconcile: bool,
    /// --require-auth：M3 W6 多租户鉴权（FR-7.1）——`--serve` 开启后每 /v1 请求需 API Key + 作用域。
    /// --gw <host:port>：M3 W5 余项（ADR-22）——独立 `sandlocker-gw` 的**节点接入**地址。
    /// `--serve` 给了它就起节点侧外拨代理：预拨 `--gw-pool` 条持久连接停在网关上，供网关
    /// 反向借用做跨节点 exec/logs/文件/端口/流式 exec。**节点仍零入站端口**。
    gw_node_endpoint: Option<String>,
    /// --gw-url <base>：网关**面向客户端**的基址（如 `http://gw:7879`）。控制面副本据此签发
    /// 签名 URL，并在沙箱不在本节点时把 /v1 请求经网关转到 owning 节点。缺省则不做跨节点转发，
    /// **也不做跨节点放置**（调度器需要这条通道把创建转给选中的节点）。
    gw_url: Option<String>,
    /// --gw-pool <n>：节点维持的**空闲**外拨连接数（网关随时可借的余量，默认 8）。
    gw_pool: usize,
    /// --gw-max-streams <n>：本节点同时在跑的数据面流上限（默认 256）。超限后新流就地串行、
    /// 不再抢先补拨——对网关形成背压而非无限开线程。
    gw_max_streams: usize,
    /// --gw-tls-cert/--gw-tls-key/--gw-tls-ca/--gw-tls-name：集群内 **mTLS**（FR-7.1，M3 W6 余项）。
    /// 四项齐备才启用；否则须显式 --gw-insecure（明文，仅本机对账/开发）。
    gw_tls_cert: Option<PathBuf>,
    gw_tls_key: Option<PathBuf>,
    gw_tls_ca: Option<PathBuf>,
    gw_tls_name: Option<String>,
    /// --gw-insecure：显式放弃数据面 mTLS（明文外拨）。仅本机对账/开发，守护会打印告警。
    gw_insecure: bool,
    /// --gw-dataplane-reconcile：M3 W5 余项对账（M3-Q3）——起网关 + 两个假节点，验
    /// 「按归属路由 / 无会话粘滞 / 一次性跨副本 / 未接入节点 503 / 全双工流式 / mTLS 拒无证书」。
    /// 默认 SQLite 临时文件；--etcd 则对真 etcd 跑同一套。随后退出。
    gw_dataplane_reconcile: bool,
    /// --exec-bench <模板目录>：§8.1「exec 启动开销 ≤20ms」实测——单实例上串行跑 N 次
    /// `exec("true")` 端到端往返，出 `{"metric":"exec_overhead",...}`。随后退出。免 root。
    exec_bench: Option<PathBuf>,
    /// --vcpus N / --mem-mib N：`run` 路径 microVM 规格（默认 1 vCPU / 128MiB，即历史写死值，零回归）。
    ///
    /// 加这两个旋钮是为了 **M3-Q9 的口径正确性**：密度 SLO（PRD §8.1）分两档——「≥200 @ 默认规格
    /// 2vCPU/512MiB」与「≥500 @ micro 128MiB」。在此之前 `run` 把 machine-config 写死为 1/128，
    /// 于是密度基准量的其实是 micro 档，却被当作默认档 gate——内存差 4 倍，会得出偏乐观且贴错
    /// 标签的结论。现在两档各自可测。
    vcpus: u32,
    mem_mib: u32,
    /// --snap-kms-key <文件>：M3 W9（ADR-15）快照信封加密的**根密钥**（32 字节，权限 0600）。
    /// 给了才启用加密——显式开关，不静默生效（加密改变快照落盘格式，与既有明文快照不兼容）。
    snap_kms_key: Option<PathBuf>,
    /// --snap-kms-init <文件>：生成一把新的根密钥文件（0600）后退出。拒绝覆盖既有文件
    /// （覆盖 = 所有既有快照永久不可解）。
    snap_kms_init: Option<PathBuf>,
    /// --snapcrypt-reconcile：M3 W9 对账（M3-Q6）——密封/解封往返、篡改即拒、明文不落盘、
    /// 随机读分块、租户 KEK 隔离、根密钥轮换边界。默认 SQLite 临时文件；--etcd 则真 etcd。随后退出。
    snapcrypt_reconcile: bool,
    require_auth: bool,
    /// --apikey-create：创建 API Key（配 --org/--project/--scope）；用 --store/--etcd 指定的 store。
    /// 打印明文 token（仅此一次），随后退出。
    apikey_create: bool,
    /// --org / --project / --scope：--apikey-create 参数。scope ∈ readonly|readwrite|build。
    org: Option<String>,
    project: Option<String>,
    scope: Option<String>,
    /// --auth-reconcile：M3-Q4 鉴权对账——有效 key 放行 / 无或错 key 拒 / 作用域越权拒 / 跨项目隔离。
    /// 默认 SQLite 临时文件；--etcd 则真 etcd。随后退出。
    auth_reconcile: bool,
    /// --quota-set：设项目配额（配 --project + --max-sandboxes/--max-vcpus/--max-mem，0=不限）。
    /// 用 --store/--etcd 指定的 store。随后退出。
    quota_set: bool,
    max_sandboxes: u64,
    max_vcpus: u64,
    max_mem: u64,
    max_storage: u64,
    /// --quota-reconcile：M3-Q4 配额+审计对账——超限 QUOTA_EXCEEDED / 删后可再建 / 审计 append 可查。
    /// 默认 SQLite 临时文件；--etcd 则真 etcd。随后退出。
    quota_reconcile: bool,
    retention_reconcile: bool,
    sched_reconcile: bool,
    /// --sched-overcommit <n>：放置时的内存/CPU 超售倍数（默认 1 = 不超售）。
    ///
    /// >1 表示部署方**主动选择**吃 Firecracker 惰性缺页那份收益（M3-Q9 实测：配置 512MiB 的
    /// 空闲实例只落约 19MB 物理页）。PRD §8.1 脚注写明这份收益「不作为 SLO 承诺」——取决于
    /// 同模板占比与脏页率——所以它只能是显式选项，不能是默认。开了就要自己担 OOM 的风险。
    sched_overcommit: u32,
    /// --log-sink <url>：M3 W8 结构化日志转发 sink（Loki/ES/自建收集器）。--serve 时 create/destroy
    /// 生命周期事件以 JSON POST 转发。未设=不转发（零回归）。
    log_sink: Option<String>,
}

impl Config {
    /// 数据面 mTLS 材料（M3 W5 余项 / W6 余项，FR-7.1）：四项齐备 → `Some(TlsOpts)`；
    /// 一项没给且显式 `--gw-insecure` → `None`（明文，仅本机对账/开发）；否则报错。
    ///
    /// **默认不放行明文**：漏配证书会得到明确错误而非静默降级为无鉴权传输。
    fn gw_tls_opts(&self) -> Result<Option<dataplane::TlsOpts>, String> {
        match (&self.gw_tls_cert, &self.gw_tls_key, &self.gw_tls_ca) {
            (Some(cert), Some(key), Some(ca)) => Ok(Some(dataplane::TlsOpts {
                cert: cert.clone(),
                key: key.clone(),
                ca: ca.clone(),
                server_name: self.gw_tls_name.clone().unwrap_or_else(|| "sandlocker-gw".into()),
            })),
            (None, None, None) if self.gw_insecure => Ok(None),
            _ => Err("数据面传输须给全 --gw-tls-cert/--gw-tls-key/--gw-tls-ca（集群内 mTLS），\
                      或显式 --gw-insecure 走明文（仅限本机对账/开发）"
                .into()),
        }
    }
}

pub fn cli_main() {
    // 隐藏子命令 --fw-probe HOST:PORT：nftfw Q7 对账的探针进程（被 `ip netns exec` 从沙箱侧
    // netns 内拉起）。先于 parse_args 拦截，连上退 0、被 drop/超时退 1、参数错退 2。
    let raw: Vec<String> = std::env::args().collect();
    if let Some(i) = raw.iter().position(|a| a == "--fw-probe") {
        let target = raw.get(i + 1).cloned().unwrap_or_default();
        std::process::exit(nftfw::probe(&target));
    }

    let cfg = parse_args();

    // --nftfw-reconcile：W5 nftables 策略 Q7 对账（无策略拒绝/加 allow 放行/销毁删表）。
    if cfg.nftfw_reconcile {
        let root = unsafe { libc::geteuid() } == 0;
        let fcfg = nftfw::FwCfg { table: "sl_fw_recon".into(), root, netns: Some("sl-fwtest".into()), hook_forward: false };
        match nftfw::reconcile(fcfg, cfg.json) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[nftfw] Q7 对账 FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --net-gate-reconcile：M2 W1 live 出口门禁对账（拓扑+门禁+NAT+无残留，M2-Q1 起步，需 root）。
    if cfg.net_gate_reconcile {
        match netlive::reconcile(cfg.uplink.clone(), cfg.json) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[netlive] net_gate 对账 FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --net-live-reconcile <模板目录>：M2 W2 方案 A 真 microVM live e2e 对账（需 root+KVM+nft+ip）。
    if let Some(tpl) = cfg.net_live_reconcile.clone() {
        match net_live_reconcile(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[netlive] net_live 真 VM 对账 FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --orch-reconcile <模板目录>：W7 生命周期 Q9 对账（rootless，免 root）。
    if let Some(tpl) = cfg.orch_reconcile.clone() {
        match orch::reconcile(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[orch] Q9 对账 FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --orch-bench <模板目录>：W7 创建时延 Q2（rootless，免 root）。
    if let Some(tpl) = cfg.orch_bench.clone() {
        match orch::bench(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[orch] Q2 bench FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --exec-bench：§8.1「exec 启动开销 ≤20ms」实测（此前该行无任何测量）。
    if let Some(tpl) = cfg.exec_bench.clone() {
        match orch::exec_bench(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[exec-bench] FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --pool-bench：M2 W4 温池冷/热分档基准（M2-Q2 起步）。
    if let Some(tpl) = cfg.pool_bench.clone() {
        match orch::pool_bench(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[pool] M2-Q2 pool-bench FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --gvisor-reconcile：M2 W7 gVisor 第二后端对账（M2-Q4，rootless）。
    if let Some(tpl) = cfg.gvisor_reconcile.clone() {
        match orch::gvisor_reconcile(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[gvisor] M2-Q4 gvisor-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --abi-contract：M2 W8 硬出口② ABI 契约套件（两后端可切换验收）。
    if let Some(tpl) = cfg.abi_contract.clone() {
        match orch::abi_contract(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[abi] 硬出口② abi-contract FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --q5-reconcile：M2-Q5 pause/resume + fork 克隆熵复验。
    if let Some(tpl) = cfg.q5_reconcile.clone() {
        match orch::q5_reconcile(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[q5] M2-Q5 q5-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --gw-reconcile：M2-Q6 数据面网关对账（ticket/端口暴露）。
    if let Some(tpl) = cfg.gw_reconcile.clone() {
        match orch::gw_reconcile(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[gw] M2-Q6 gw-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --pty-reconcile：M2-Q7 交互式 PTY 对账（双向流 + resize）。
    if let Some(tpl) = cfg.pty_reconcile.clone() {
        match orch::pty_reconcile(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[pty] M2-Q7 pty-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --exec-stream-reconcile：流式 exec 对账（逐块到达 + stdout/stderr 分离 + 退出码透传 + 零残留）。
    if let Some(tpl) = cfg.exec_stream_reconcile.clone() {
        match orch::exec_stream_reconcile(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[exec-stream] exec-stream-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --net-egress-reconcile：运行时网络出口对账（冷启动带 NIC + DNS/NAT 出站 + destroy 零残留）。
    if let Some(tpl) = cfg.net_egress_reconcile.clone() {
        match orch::net_egress_reconcile(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[egress] net-egress-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --expose-reconcile：端口暴露 L4 透传对账（keep-alive/非 GET/流式/并发/拆除/零残留）。
    if let Some(tpl) = cfg.expose_reconcile.clone() {
        match orch::expose_reconcile(&cfg, &tpl) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[expose] expose-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --store-contract：M3 W1 store 契约对账（M3-Q1）——SqliteStore 恒跑；--etcd 时 EtcdStore 同跑。
    if cfg.store_contract {
        match run_store_contract(&cfg) {
            Ok(()) => println!("[store] M3-Q1 store-contract PASS"),
            Err(e) => {
                eprintln!("[store] M3-Q1 store-contract FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --election-reconcile：M3-Q2 选主对账（双竞选者 → 单 leader + resign failover + 无双主）。
    if cfg.election_reconcile {
        match run_election_reconcile(&cfg) {
            Ok(()) => println!("[election] M3-Q2 election-reconcile PASS"),
            Err(e) => {
                eprintln!("[election] M3-Q2 election-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --apikey-create：创建 API Key（--org/--project/--scope），打印明文 token 后退出。
    if cfg.apikey_create {
        match run_apikey_create(&cfg) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[apikey] 创建失败: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --quota-set：设项目配额，随后退出。
    if cfg.quota_set {
        match run_quota_set(&cfg) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[quota] 设置失败: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --quota-reconcile：M3-Q4 配额+审计对账（超限 QUOTA_EXCEEDED / 删后可再建 / 审计 append 可查）。
    if cfg.quota_reconcile {
        match run_quota_reconcile(&cfg) {
            Ok(()) => println!("[quota] M3-Q4 quota-reconcile PASS"),
            Err(e) => {
                eprintln!("[quota] M3-Q4 quota-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --retention-reconcile：M3-Q7 保留期+版本钉住对账（过期 GC / 版本兼容矩阵 / 存储配额）。
    if cfg.retention_reconcile {
        match run_retention_reconcile(&cfg) {
            Ok(()) => println!("[retention] M3-Q7 retention-reconcile PASS"),
            Err(e) => {
                eprintln!("[retention] M3-Q7 retention-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --sched-reconcile：M3-Q10 放置对账（盘点 → 选点 → 落账 → 再盘点，负载反馈闭合）。
    if cfg.sched_reconcile {
        match run_sched_reconcile(&cfg) {
            Ok(()) => println!("[sched] M3-Q10 sched-reconcile PASS"),
            Err(e) => {
                eprintln!("[sched] M3-Q10 sched-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --auth-reconcile：M3-Q4 鉴权对账（有效放行 / 无或错拒 / 越权拒 / 跨项目隔离）。
    if cfg.auth_reconcile {
        match run_auth_reconcile(&cfg) {
            Ok(()) => println!("[auth] M3-Q4 auth-reconcile PASS"),
            Err(e) => {
                eprintln!("[auth] M3-Q4 auth-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --gw-cluster-reconcile：M3 W5 网关拆副本对账（共享 secret 无状态验签 + 一次性跨副本）。
    // --snap-kms-init：生成一把新的快照加密根密钥（0600）后退出。
    if let Some(p) = &cfg.snap_kms_init {
        match snapcrypt::FileKms::init(p) {
            Ok(()) => println!("[snapcrypt] 根密钥已生成: {}（0600；丢失即所有快照不可解，请备份）", p.display()),
            Err(e) => {
                eprintln!("[snapcrypt] 生成根密钥失败: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --snapcrypt-reconcile：M3 W9 快照信封加密对账（M3-Q6）。
    if cfg.snapcrypt_reconcile {
        match run_snapcrypt_reconcile(&cfg) {
            Ok(()) => println!("[snapcrypt] M3 W9 snapcrypt-reconcile PASS"),
            Err(e) => {
                eprintln!("[snapcrypt] M3 W9 snapcrypt-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --gw-dataplane-reconcile：M3 W5 余项对账（M3-Q3 独立网关 + 外拨流 + 无粘滞中继）。
    if cfg.gw_dataplane_reconcile {
        match run_gw_dataplane_reconcile(&cfg) {
            Ok(()) => println!("[gw-dataplane] M3 W5 余项 gw-dataplane-reconcile PASS"),
            Err(e) => {
                eprintln!("[gw-dataplane] M3 W5 余项 gw-dataplane-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if cfg.gw_cluster_reconcile {
        match run_gw_cluster_reconcile(&cfg) {
            Ok(()) => println!("[gw-cluster] M3 W5 gw-cluster-reconcile PASS"),
            Err(e) => {
                eprintln!("[gw-cluster] M3 W5 gw-cluster-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --cluster-reconcile：M3 W4 集群合龙对账（跨副本共享态 + 失联回收跨副本同步）。
    if cfg.cluster_reconcile {
        match run_cluster_reconcile(&cfg) {
            Ok(()) => println!("[cluster] M3 W4 cluster-reconcile PASS"),
            Err(e) => {
                eprintln!("[cluster] M3 W4 cluster-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --node-reclaim-reconcile：M3-Q2 节点失联回收对账（心跳 + 孤儿回收 + 存活不动 + 护栏）。
    if cfg.node_reclaim_reconcile {
        match run_node_reclaim_reconcile(&cfg) {
            Ok(()) => println!("[reclaim] M3-Q2 node-reclaim-reconcile PASS"),
            Err(e) => {
                eprintln!("[reclaim] M3-Q2 node-reclaim-reconcile FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --cluster-init：M3 W2 SQLite→etcd 一次性迁移（ADR-17，停机事件）。
    if cfg.cluster_init {
        match run_cluster_init(&cfg) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[cluster-init] FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --serve：W8 长驻守护（HTTP REST API + orchestrator + reaper）。前台运行，Ctrl-C 退出。
    if cfg.serve {
        match api::serve(&cfg) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[sandlocker] 守护退出: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --dmthin-reconcile：W3 dm-thin CoW 销毁对账（Q5）。先于 --cycles 分派：
    // 两者都用 cfg.cycles 作轮数，此模式下 cycles 属于 dm-thin 而非 FC 销毁对账。
    if cfg.dmthin_reconcile {
        let root = unsafe { libc::geteuid() } == 0;
        let tcfg = dmthin::ThinCfg::new(cfg.workdir.join("dmthin"), root);
        match dmthin::reconcile(tcfg, cfg.cycles, cfg.json) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[dmthin] Q5 对账 FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --cycles N：FC 销毁对账模式（Q6）——反复 create/destroy，每轮后断言无残留。
    if cfg.cycles > 0 {
        match reconcile_cycles(&cfg) {
            Ok(()) => println!("[sl-node] W4 对账 PASS：{} 轮 create/destroy 后无残留（进程/tap/socket）", cfg.cycles),
            Err(e) => {
                eprintln!("[sl-node] W4 对账 FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --thin：FC 挂 per-sandbox thin snapshot 为 rootfs 端到端跑（需 root）
    if cfg.thin {
        match run_thin(&cfg) {
            Ok(()) => {
                if !cfg.json {
                    println!("[sl-node] W3 thin PASS：FC 挂 dm-thin CoW 盘为 rootfs，exec 链路正常，销毁无残留");
                }
            }
            Err(e) => {
                eprintln!("[sl-node] W3 thin FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --build <sandlocker.toml>：W6 模板构建引擎（ADR-19，build-as-sandbox→预烘焙快照+签名入库）
    if let Some(p) = cfg.build.clone() {
        match build::build(&cfg, &p) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[sl-node] 模板构建 FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --oci-pull <ref|archive>：W3 OCI 镜像当 rootfs 来源独立取证（拉取/加载→展平→bake ext4，不 boot）
    if let Some(from) = cfg.oci_pull.clone() {
        match oci_pull(&cfg, &from) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[oci] --oci-pull FAIL: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // --snap-create / --snap-load：W2 快照引擎（离线造/恢复单沙箱，无网络）
    if let Some(dir) = cfg.snap_create.clone() {
        match snapshot_create(&cfg, &dir) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[sl-node] 快照 create FAIL: {e}");
                eprintln!("[sl-node] 排查：查看 {}/console.log", dir.display());
                std::process::exit(1);
            }
        }
        return;
    }
    if let Some(dir) = cfg.snap_load.clone() {
        match snapshot_load(&cfg, &dir) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[sl-node] 快照 load FAIL: {e}");
                eprintln!("[sl-node] 排查：查看 {}/console.load.log", dir.display());
                std::process::exit(1);
            }
        }
        return;
    }
    // --clone-entropy-check：W4 克隆熵回归（Q3），同快照恢复两实例比对身份/熵
    if let Some(dir) = cfg.clone_entropy.clone() {
        match clone_entropy_check(&cfg, &dir) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[sl-node] 克隆熵回归 FAIL: {e}");
                eprintln!("[sl-node] 排查：查看 {}/console.load.log", dir.display());
                std::process::exit(1);
            }
        }
        return;
    }

    match run(&cfg) {
        Ok(()) => {
            if !cfg.json {
                println!("[sl-node] W4 demo PASS：沙箱有独立 netns/eth0（出口天然为零），exec 链路正常");
            }
        }
        Err(e) => {
            eprintln!("[sl-node] W4 demo FAIL: {e}");
            eprintln!("[sl-node] 排查：查看 {}/console.log（guest 串口 + sl-envd 日志）", cfg.workdir.display());
            std::process::exit(1);
        }
    }
}

fn run(cfg: &Config) -> Result<(), String> {
    for (label, p) in [("kernel", &cfg.kernel), ("rootfs", &cfg.rootfs), ("firecracker", &cfg.fc_bin)] {
        if !p.exists() {
            return Err(format!("{label} 不存在: {}", p.display()));
        }
    }
    if cfg.boot == Boot::Jailer && !cfg.jailer_bin.exists() {
        return Err(format!("jailer 不存在: {}（scripts/fetch-firecracker.sh 会一并取）", cfg.jailer_bin.display()));
    }
    std::fs::create_dir_all(&cfg.workdir).map_err(|e| format!("建 workdir 失败: {e}"))?;

    // socket 路径：jailer 模式落 chroot 内（root/ 下），其余落 workdir。
    // uds_path/api_host 为 host 侧连接用的绝对路径；FC 内视角路径由 configure 分派。
    let console_log = cfg.workdir.join("console.log");
    let (uds_path, api_host) = match cfg.boot {
        Boot::Jailer => {
            let root = jail_root(cfg);
            (root.join("vsock.sock"), root.join("api.sock"))
        }
        _ => (cfg.workdir.join("vsock.sock"), cfg.workdir.join("api.sock")),
    };

    // 清理上轮残留 socket（FC bind 已存在的 socket 会失败）
    let _ = std::fs::remove_file(&uds_path);
    let _ = std::fs::remove_file(&api_host);
    if let Ok(entries) = std::fs::read_dir(&cfg.workdir) {
        for e in entries.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().starts_with("vsock.sock_") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    // 启动 Firecracker（串口 + envd 日志重定向到 console.log；自成进程组便于整组回收）
    let cmd = build_spawn_cmd(cfg, &uds_path, &api_host)?;
    let spawn_at = Instant::now();
    let mut child: Child = spawn_with_log(cmd, &console_log)?;

    // 用 guard 确保任何路径退出都回收整个进程组
    let result = (|| {
        // api/jailer：spawn 后经 HTTP API 逐段配置并 InstanceStart（config-file 已在启动时装好）
        if cfg.boot != Boot::ConfigFile {
            configure_via_api(cfg, &api_host, &mut child)?;
        }
        drive_exec(cfg, &uds_path, &mut child, spawn_at)
    })();
    kill_group(&mut child);
    let _ = std::fs::remove_file(&uds_path);
    if cfg.boot == Boot::Jailer {
        // jailer chroot 整棵清掉（销毁对账口径：无残留 chroot/hardlink）
        let _ = std::fs::remove_dir_all(jail_instance_dir(cfg));
        // jailer 建的 cgroup 不自动回收，进程退出后 rmdir（best-effort；v2 布局 <parent>/<id>）
        let _ = std::fs::remove_dir(format!("/sys/fs/cgroup/firecracker/{JAIL_ID}"));
        let _ = std::fs::remove_dir("/sys/fs/cgroup/firecracker");
    }
    result
}

/// W3 thin（task 36）：建 pool + 从真 rootfs 建 base origin → per-sandbox thin snapshot →
/// FC 挂 /dev/mapper/sl-thin-0 为 rootfs 启动 → exec 验 rw CoW 盘可用 → 销毁 thin + pool。
/// 需 root（FC 打开 root 属主 dm 节点 + dd 灌 base 均需特权）；用户以 `sudo -E` 跑。
fn run_thin(cfg: &Config) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "thin 模式需 root：请以 `sudo -E target/release/sl-node --thin --cmd \"...\"` 运行\
             （FC 需打开 root 属主的 /dev/mapper 节点、dd 灌 base rootfs 均需特权；\
             免密白名单仅覆盖 --dmthin-reconcile 的分步 dmsetup 调用）"
            .into(),
        );
    }
    for (label, p) in [("kernel", &cfg.kernel), ("rootfs", &cfg.rootfs), ("firecracker", &cfg.fc_bin)] {
        if !p.exists() {
            return Err(format!("{label} 不存在: {}", p.display()));
        }
    }

    // thin 卷虚拟大小取 rootfs 镜像大小上取整（≥128MB），确保 dd 灌得下
    let img_bytes = std::fs::metadata(&cfg.rootfs).map_err(|e| format!("读 rootfs 大小失败: {e}"))?.len();
    let mut tcfg = dmthin::ThinCfg::new(cfg.workdir.join("dmthin"), true);
    tcfg.thin_mb = (img_bytes.div_ceil(1 << 20)).max(128);

    if !cfg.json {
        println!("[sl-node] thin：建 pool → 从 rootfs 建 base origin（dd {}MB）→ per-sandbox CoW 快照 → FC 挂载", tcfg.thin_mb);
    }
    let pool = dmthin::Pool::setup(tcfg)?;

    let dev = "/dev/mapper/sl-thin-0";
    let result = (|| -> Result<(), String> {
        pool.create_base_from_image(0, &cfg.rootfs)?;
        let dev_path = pool.snapshot(0, 1, "sl-thin-0")?; // per-sandbox CoW 派生

        // 以 thin 设备为 rootfs 起 VM（无网络，聚焦存储）；默认跑一段 rw 自证命令
        let mut vmcfg = clone_paths(cfg);
        vmcfg.rootfs = PathBuf::from(&dev_path);
        vmcfg.netns = false;
        vmcfg.cmd = Some(cfg.cmd.clone().unwrap_or_else(|| {
            // 写文件到 rw 根盘（落 CoW 独有块）+ 回读 + 确认根为 rw
            "echo thin-cow-ok > /root/thin-marker && cat /root/thin-marker && \
             (mount | grep ' / ' || cat /proc/mounts | grep ' / ')"
                .into()
        }));
        run(&vmcfg)
    })();

    // 销毁 per-sandbox thin（释放独有块）再拆 pool——无论成败都清干净
    let _ = pool.destroy_thin(1, "sl-thin-0");
    let _ = dev; // 名义引用
    pool.teardown();
    result
}

/// 起 FC 进程：串口/envd 日志重定向到 console_log，自成进程组（killpg 整组回收，Q6）。
///
/// stdin 必须置 /dev/null：我们经 vsock 驱动 guest，从不用串口输入。若继承控制终端，
/// FC 在 InstanceStart 把终端切 raw 模式（tcsetattr）——而 FC 已 setpgid 成独立进程组、
/// 相对该终端是**后台组**，tcsetattr 触发 SIGTTOU 默认动作=停整个 FC 进程（T 态冻死），
/// API 永不应答 → 前台跑必挂；stdin=/dev/null 时 is_tty()=false，FC 跳过切 raw，稳。
fn spawn_with_log(mut cmd: Command, console_log: &Path) -> Result<Child, String> {
    let log_file = std::fs::File::create(console_log).map_err(|e| format!("建 console.log 失败: {e}"))?;
    let log_err = log_file.try_clone().map_err(|e| format!("clone log fd 失败: {e}"))?;
    cmd.stdin(Stdio::null()).stdout(Stdio::from(log_file)).stderr(Stdio::from(log_err));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| format!("spawn microVM 失败: {e}"))
}

/// 等 api-sock 就绪；期间若 FC 提前退出（权限/配置失败）则立即报错，不空等到超时。
fn wait_api_ready(api: &FcApi, child: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("FC 在 API 就绪前退出（status={status}），见 console.log"));
        }
        match api.wait_ready(Duration::from_millis(100)) {
            Ok(()) => return Ok(()),
            Err(_) if Instant::now() < deadline => continue,
            Err(e) => return Err(e),
        }
    }
}

/// 重试 vsock 握手直到 guest 内 sl-envd 就绪（FC 提前退出则立即报错）。
fn wait_guest(uds_path: &Path, child: &mut Child) -> Result<UnixStream, String> {
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("microVM 提前退出（status={status}），见 console.log"));
        }
        match connect_guest(uds_path) {
            Ok(s) => return Ok(s),
            Err(_) if start.elapsed() < READY_TIMEOUT => thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("等待 guest sl-envd 就绪超时（{READY_TIMEOUT:?}）: {e}")),
        }
    }
}

/// W2 快照 create（task 31）：API 启动（无网络）→ 就绪 → 播种可验证状态 → Paused → snapshot/create。
///
/// 产物落 <dir>/{vmstate, mem, rootfs.ext4, expect}。约定：
///   - rootfs 每快照独立拷贝一份，快照内 `path_on_host` 锚定它，load 时须在原路径（dm-thin CoW 在 W3）。
///   - vsock uds_path 固定为 <dir>/vsock.sock（写进快照配置，load 时 FC 重新 bind）。
///   - expect 存 marker token + 快照点 guest uptime，供 load 校验「恢复≠重启」。
fn snapshot_create(cfg: &Config, snap_dir: &Path) -> Result<(), String> {
    for (label, p) in [("kernel", &cfg.kernel), ("rootfs", &cfg.rootfs), ("firecracker", &cfg.fc_bin)] {
        if !p.exists() {
            return Err(format!("{label} 不存在: {}", p.display()));
        }
    }
    std::fs::create_dir_all(snap_dir).map_err(|e| format!("建快照目录失败: {e}"))?;
    let dir = abspath(snap_dir)?; // FC 需绝对路径 bind/引用
    let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or("snap").to_string();
    let snap_rootfs = dir.join("rootfs.ext4");
    let vmstate = dir.join("vmstate");
    let mem = dir.join("mem");
    let vsock = dir.join("vsock.sock");
    let api_host = dir.join("api.sock");
    let console_log = dir.join("console.log");

    // 每快照独立 rootfs 拷贝（隔离；dm-thin CoW 在 W3）——快照内 path_on_host 锚定它
    std::fs::copy(&cfg.rootfs, &snap_rootfs).map_err(|e| format!("拷贝 rootfs 进快照目录失败: {e}"))?;
    for f in [&vmstate, &mem, &vsock, &api_host] {
        let _ = std::fs::remove_file(f);
    }

    if !cfg.json {
        println!("[sl-node] 快照 create：API 启动（无网络）→ 就绪 → Paused → snapshot/create");
    }
    let mut cmd = Command::new(&cfg.fc_bin);
    cmd.arg("--api-sock").arg(&api_host);
    let mut child = spawn_with_log(cmd, &console_log)?;

    let result = (|| -> Result<f64, String> {
        let api = FcApi::new(&api_host);
        wait_api_ready(&api, &mut child)?;
        // 逐段配置（内视角=绝对 host 路径，无网络）；machine-config 会随快照保存，load 时须一致
        api.put("/machine-config", r#"{"vcpu_count":1,"mem_size_mib":128}"#)?;
        api.put(
            "/boot-source",
            &format!(r#"{{"kernel_image_path":"{}","boot_args":"{}"}}"#, cfg.kernel.display(), boot_args()),
        )?;
        api.put(
            "/drives/rootfs",
            &format!(
                r#"{{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":false}}"#,
                snap_rootfs.display()
            ),
        )?;
        api.put("/vsock", &format!(r#"{{"guest_cid":{GUEST_CID},"uds_path":"{}"}}"#, vsock.display()))?;
        api.put("/actions", r#"{"action_type":"InstanceStart"}"#)?;

        // 等 guest sl-envd 就绪并自检
        let mut stream = wait_guest(&vsock, &mut child)?;
        stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| format!("设读超时失败: {e}"))?;
        match request(&mut stream, &Request::Ping { data: "snap".into() })? {
            Response::Pong { data } if data == "snap" => {}
            other => return Err(format!("Ping 自检失败: {other:?}")),
        }

        // 播种可验证状态：tmpfs marker（一致性）+ sleep 抬高 uptime（使「恢复≠重启」可判定）。
        // 快照点 uptime≥~2.5s，远高于冷 boot 的 ~0.5s；恢复后 uptime 应连续（暂停期冻结）。
        let token = format!("sl-snap-{name}");
        let (c, _, _) = exec(&mut stream, &format!("echo {token} > /tmp/sl-snap-marker"))?;
        if c != 0 {
            return Err("播种 marker 失败".into());
        }
        let _ = exec(&mut stream, "sleep 2")?;
        let (_, upt, _) = exec(&mut stream, "cat /proc/uptime")?;
        let snap_uptime = upt
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<f64>().ok())
            .ok_or("读 guest uptime 失败")?;

        // 暂停 → 造 Full 快照（自包含内存 + vmstate；D4/ADR-6）。put_long：大 rootfs 刷脏页可能超常规超时。
        api.patch("/vm", r#"{"state":"Paused"}"#)?;
        api.put_long(
            "/snapshot/create",
            &format!(
                r#"{{"snapshot_type":"Full","snapshot_path":"{}","mem_file_path":"{}"}}"#,
                vmstate.display(),
                mem.display()
            ),
        )?;

        // 持久化期望值供 load 校验
        std::fs::write(dir.join("expect"), format!("{token}\n{snap_uptime}\n"))
            .map_err(|e| format!("写 expect 失败: {e}"))?;
        Ok(snap_uptime)
    })();

    kill_group(&mut child);
    let _ = std::fs::remove_file(&api_host);
    let _ = std::fs::remove_file(&vsock); // 死 FC 遗留的 bind 文件，load 需重新 bind

    let uptime = result?;
    if !cfg.json {
        println!(
            "[sl-node] 快照就绪：{}（vmstate/mem/rootfs.ext4/expect），快照点 uptime≈{uptime:.2}s",
            dir.display()
        );
    }
    Ok(())
}

/// 一次恢复的度量与取样（供 snapshot_load 打印、clone-entropy 比对复用）。
struct LoadOutcome {
    api_ready_ms: u128,
    load_ms: u128,
    resume_ms: u128,
    total_ms: u128,
    marker: String,
    loaded_uptime: f64,
    want_token: String,
    want_uptime: f64,
    /// Q4：策略钩子在 resume 之前生效（结构上恒真，作为回归锚点显式暴露）。
    policy_before_resume: bool,
    /// Q4 时序探针：策略生效早于 resume 的余量（微秒）。host 侧两 Instant 间隔，
    /// 亚毫秒级——rootless 占位钩子仅记时刻，真实 nft gate 随 M2 jailer --netns 落地。
    policy_margin_us: u128,
    /// ADR-12 reinit 换发的克隆身份（Q3 比对用）。
    machine_id: String,
    rng_hex: String,
    session_key_hex: String,
}

/// 恢复上下文（W7）：模板目录（vmstate/mem/expect/rootfs 烘焙源）与实例目录（sockets/日志/私有
/// rootfs 副本）解耦，支持 rootless mount-ns bind（每沙箱私有 rootfs，见 orch.rs）与 keep-alive。
struct RestoreCtx<'a> {
    /// 模板目录：读 `expect` + 校验 `rootfs.ext4`（FC 从 vmstate 烘焙的绝对路径开 rootfs）。
    template_dir: &'a Path,
    /// 实例目录：vmstate/mem/vsock.sock/api.sock/console.load.log 落此。非 bind 时 == template_dir。
    instance_dir: &'a Path,
    /// `Some((idir, tpl))` → 于 `unshare --user --map-root-user --mount` 内 `mount --bind idir tpl`：
    /// FC 打开的**烘焙**绝对路径（rootfs、vsock uds）落进实例目录的私有副本——并发不撞、不脏模板。
    /// 实例目录须先备好私有 `rootfs.ext4` 副本 + `vmstate`/`mem`（硬链，见 orch::prepare_instance_dir）。
    bind: Option<(PathBuf, PathBuf)>,
    /// true → 恢复+校验通过后**不 kill**，返回 `Child` 交调用方持有（orchestrator create）。
    keep_alive: bool,
    /// `Some(ns)`（M2 W2，需 root）→ FC 恢复进具名 netns（`ip netns exec <ns> …`），且
    /// `apply_network_policy` 在该 netns 上 **fail-closed** ensure forward-hook 门禁（resume 之前）。
    /// `None`（默认）→ M1 路径逐字节不变（无 netns、门禁休眠）。
    /// 边界（Option A）：快照无网卡 → 恢复态 guest 无 eth0，本字段供**时序探针 live 化**（真 netns +
    /// 真 nft ensure + 真 resume，margin 真实非 0）；真流量出口证明走 `--net-live-reconcile` 冷启动。
    netns: Option<&'a str>,
}

/// 单引号包裹路径供 `sh -c` 使用（仓库内路径不含单引号，够用）。
fn sq(p: &Path) -> String {
    format!("'{}'", p.display())
}

/// 校验恢复度量三不变量；返回 `Some(错误)` 表示破坏，`None` 表示通过。
fn validate_outcome(o: &LoadOutcome) -> Option<String> {
    // ①：marker 一致 → 恢复到了快照时的 guest 状态
    if o.marker != o.want_token {
        return Some(format!("状态不一致：marker 期望 {:?} 实得 {:?}", o.want_token, o.marker));
    }
    // ②：uptime 连续（暂停期冻结）→ 是内存恢复而非重启。冷 boot uptime≈0.5s ≪ 快照点 ~2.5s。
    if o.loaded_uptime + 0.5 < o.want_uptime {
        return Some(format!(
            "疑似重启而非恢复：loaded uptime {:.2}s ≪ 快照点 {:.2}s",
            o.loaded_uptime, o.want_uptime
        ));
    }
    // ③（Q4）：策略钩子在 resume 之前生效。
    if !o.policy_before_resume {
        return Some("ADR-13 违背：策略钩子未在 resume 之前生效".into());
    }
    None
}

/// **park 段**（M2 W5 热池）：fresh FC → `snapshot/load{resume_vm:false}` **停在暂停态**（vCPU 不跑，
/// 构造上不可能发包）。此后可长期停放（热池），或立即 [`restore_activate`]。失败即杀 child + 清 socket。
/// **不打印**。全字段 `Send` → 可跨 refill 线程停放。
pub(crate) struct ParkedVm {
    pub child: Child,
    pub api_host: PathBuf,
    pub vsock: PathBuf,
    /// spawn 起点：组合路径（restore_core）用它算 `total_ms`；热池命中另在 activate 外测 wall-clock。
    pub spawn_at: Instant,
    pub api_ready_ms: u128,
    pub load_ms: u128,
    pub want_token: String,
    pub want_uptime: f64,
}

/// park 段实现：见 [`ParkedVm`]。参数化实例目录/bind/netns（与旧 restore_core 前半逐字节等价）。
pub(crate) fn restore_park(cfg: &Config, ctx: &RestoreCtx) -> Result<ParkedVm, String> {
    let tdir = abspath(ctx.template_dir)?;
    let idir = abspath(ctx.instance_dir)?;
    let vmstate = idir.join("vmstate");
    let mem = idir.join("mem");
    let vsock = idir.join("vsock.sock");
    let api_host = idir.join("api.sock");
    let console_log = idir.join("console.load.log");
    for (l, p) in [("vmstate", &vmstate), ("mem", &mem), ("rootfs.ext4", &tdir.join("rootfs.ext4"))] {
        if !p.exists() {
            return Err(format!("恢复缺 {l}: {}（先跑 --snap-create / --build）", p.display()));
        }
    }
    let _ = std::fs::remove_file(&vsock);
    let _ = std::fs::remove_file(&api_host);

    // 读期望值（marker token + 快照点 uptime）——从模板目录（expect 不入实例目录）。
    let expect = std::fs::read_to_string(tdir.join("expect")).map_err(|e| format!("读 expect 失败: {e}"))?;
    let mut lines = expect.lines();
    let want_token = lines.next().unwrap_or("").to_string();
    let want_uptime = lines.next().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);

    // bind 模式：`unshare` 建 用户+挂载 namespace，把实例目录 bind 到模板目录，令 FC 烘焙的
    // rootfs/vsock 绝对路径落进实例私有副本（免 sudo；spawn_with_log/kill_group 已按 unshare→FC 链设计）。
    // 否则直呼 FC（现行为，`--snap-load`/克隆熵 零回归）。
    let cmd = match (&ctx.bind, ctx.netns) {
        // 具名 netns + bind（root：进 netns 再开 mount-ns 遮蔽私有 rootfs）。本周 Option A 未走此
        // 组合（快照无网卡 → 恢复态 guest 无 eth0），留通路供后续 restore-path live 网卡落地。
        (Some((src, dst)), Some(ns)) => {
            let script = format!(
                "mount --bind {} {} && exec {} --api-sock {}",
                sq(src), sq(dst), sq(&cfg.fc_bin), sq(&api_host)
            );
            let mut c = Command::new("ip");
            c.arg("netns").arg("exec").arg(ns)
                .arg("unshare").arg("--mount").arg("--propagation").arg("private")
                .arg("sh").arg("-c").arg(script);
            c
        }
        // 具名 netns 直恢复（时序探针 live 化：无 bind，snap 目录直取；需 root）。
        (None, Some(ns)) => {
            let mut c = Command::new("ip");
            c.arg("netns").arg("exec").arg(ns).arg(&cfg.fc_bin).arg("--api-sock").arg(&api_host);
            c
        }
        // rootless mount-ns bind（M1 逐字节不变）。root 守护（egress 场景）下 user-ns 映射 root
        // 里 bind 挂载会 EPERM（mount 退 32）——root 本就有 CAP_SYS_ADMIN，直接 mount-ns，无需 user-ns。
        (Some((src, dst)), None) => {
            let script = format!(
                "mount --bind {} {} && exec {} --api-sock {}",
                sq(src), sq(dst), sq(&cfg.fc_bin), sq(&api_host)
            );
            let as_root = unsafe { libc::geteuid() } == 0;
            let mut c = Command::new("unshare");
            if as_root {
                c.arg("--mount").arg("--propagation").arg("private");
            } else {
                c.arg("--user").arg("--map-root-user").arg("--mount").arg("--propagation").arg("private");
            }
            c.arg("sh").arg("-c").arg(script);
            c
        }
        // 直呼 FC（M1 逐字节不变）。
        (None, None) => {
            let mut c = Command::new(&cfg.fc_bin);
            c.arg("--api-sock").arg(&api_host);
            c
        }
    };
    let spawn_at = Instant::now();
    let mut child = spawn_with_log(cmd, &console_log)?;

    // load 段（失败即杀 child + 清 socket，不泄漏暂停态 VM）。
    let load = (|| -> Result<(u128, u128), String> {
        let api = FcApi::new(&api_host);
        wait_api_ready(&api, &mut child)?;
        let api_ready_ms = spawn_at.elapsed().as_millis();

        // 恢复但**不 resume**（resume_vm=false）：vmstate + File 内存后端（惰性缺页 mmap，ADR-23/D4）。
        // 无需预配 machine/boot/drives——全部随快照恢复。此刻 vCPU 停摆，构造上无法发包。
        let load_at = Instant::now();
        api.put(
            "/snapshot/load",
            &format!(
                r#"{{"snapshot_path":"{}","mem_backend":{{"backend_type":"File","backend_path":"{}"}},"enable_diff_snapshots":false,"resume_vm":false}}"#,
                vmstate.display(),
                mem.display()
            ),
        )?;
        let load_ms = load_at.elapsed().as_millis();
        Ok((api_ready_ms, load_ms))
    })();
    let (api_ready_ms, load_ms) = match load {
        Ok(v) => v,
        Err(e) => {
            kill_group(&mut child);
            let _ = std::fs::remove_file(&api_host);
            let _ = std::fs::remove_file(&vsock);
            return Err(e);
        }
    };

    Ok(ParkedVm { child, api_host, vsock, spawn_at, api_ready_ms, load_ms, want_token, want_uptime })
}

/// **activate 段**（M2 W5 热池）：`apply_network_policy`（resume **之前**，ADR-13）→ `PATCH /vm Resumed`
/// → 连 vsock → Ping → **下发 Reinit**（ADR-12：换发 machine-id/hostname/会话密钥、混种子、校时钟）→
/// 一致性校验。暂停态 park 后策略仍恒在 resume 前，故"策略生效前无发包窗口"不存在。**不打印**。
///
/// `keep_alive` 且校验通过：返回 `Child` 交调用方持有；否则杀 VM + 清 socket。门禁句柄交调用方 teardown。
pub(crate) fn restore_activate(
    cfg: &Config,
    netns: Option<&str>,
    keep_alive: bool,
    parked: ParkedVm,
) -> Result<(LoadOutcome, Option<Child>, Option<nftfw::Sandbox>), String> {
    let ParkedVm { mut child, api_host, vsock, spawn_at, api_ready_ms, load_ms, want_token, want_uptime } = parked;

    // live 门禁句柄（Some 仅当 netns 且 root）：闭包内 ensure 成功后写入，供失败清理 / 成功返回。
    let mut gate: Option<nftfw::Sandbox> = None;
    let result = (|| -> Result<LoadOutcome, String> {
        let api = FcApi::new(&api_host);

        // ADR-13：策略钩子在 resume **之前**生效。live 档（netns Some + root）fail-closed
        // ensure forward-hook 门禁——失败即 `?` 抛出，下方 resume 不执行（无发包窗口）。
        let (policy_at, sb) = apply_network_policy(cfg, netns)?;
        gate = sb;

        // resume：此后 vCPU 才运行、guest 才可能发包——而策略已就位。
        let resume_at = Instant::now();
        api.patch("/vm", r#"{"state":"Resumed"}"#)?;
        let resume_ms = resume_at.elapsed().as_millis();
        let policy_before_resume = policy_at <= resume_at;
        let policy_margin_us = resume_at.saturating_duration_since(policy_at).as_micros();

        // 连 vsock（envd 监听状态随内存恢复，直接可接）
        let mut stream = wait_guest(&vsock, &mut child)?;
        let total_ms = spawn_at.elapsed().as_millis();
        stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| format!("设读超时失败: {e}"))?;
        match request(&mut stream, &Request::Ping { data: "restore".into() })? {
            Response::Pong { data } if data == "restore" => {}
            other => return Err(format!("恢复后 Ping 失败: {other:?}")),
        }

        // ADR-12：resume 后、用户代码前，下发 reinit 换发克隆身份（每恢复唯一种子 + 主机名 + 现刻墙钟）。
        let mut seed = [0u8; 32];
        host_random(&mut seed);
        let seed_hex = hex(&seed);
        let hostname = format!("sandlocker-{}", hex(&seed[..4]));
        let wall_time_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let (machine_id, rng_hex, session_key_hex) =
            send_reinit(&mut stream, &seed_hex, &hostname, wall_time_ns)?;

        // 一致性校验取值：marker 内容 + 当前 uptime
        let (_, marker, _) = exec(&mut stream, "cat /tmp/sl-snap-marker")?;
        let (_, upt, _) = exec(&mut stream, "cat /proc/uptime")?;
        let loaded_uptime = upt.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);
        Ok(LoadOutcome {
            api_ready_ms,
            load_ms,
            resume_ms,
            total_ms,
            marker: marker.trim().to_string(),
            loaded_uptime,
            want_token,
            want_uptime,
            policy_before_resume,
            policy_margin_us,
            machine_id,
            rng_hex,
            session_key_hex,
        })
    })();

    // 恢复/交互失败：无论模式都杀干净，勿泄漏 VM/socket；门禁若已 ensure 也拆掉（fail-closed 清理）。
    let outcome = match result {
        Ok(o) => o,
        Err(e) => {
            kill_group(&mut child);
            let _ = std::fs::remove_file(&api_host);
            let _ = std::fs::remove_file(&vsock);
            if let Some(sb) = gate.take() {
                let _ = sb.teardown();
            }
            return Err(e);
        }
    };

    // 断言失败 或 非 keep-alive：杀 VM + 清 socket。keep-alive 且断言通过：保留交调用方持有。
    let assert_err = validate_outcome(&outcome);
    if assert_err.is_some() || !keep_alive {
        kill_group(&mut child);
        let _ = std::fs::remove_file(&api_host);
        let _ = std::fs::remove_file(&vsock);
    }
    if let Some(msg) = assert_err {
        // 断言破坏也要拆门禁（不泄漏 nft 规则）。
        if let Some(sb) = gate.take() {
            let _ = sb.teardown();
        }
        return Err(msg);
    }
    let child_opt = if keep_alive { Some(child) } else { None };
    // 门禁句柄交调用方 teardown：keep-alive（orchestrator）随实例销毁拆；探针/单发档由调用方即刻拆。
    Ok((outcome, child_opt, gate))
}

/// W2 恢复核心 + W4 ADR-13 时序 + ADR-12 reinit（W7 抽出，参数化实例目录/bind/keep-alive）。**不打印**。
///
/// M2 W5 起为 [`restore_park`] + [`restore_activate`] 的**薄组合**（单发/warm/cold/net-timing-live 路径
/// 逐字节等价，签名与返回不变）；热池另路复用 park/activate 两段（park 后停放、命中即 activate）。
///
/// 时序（Q4）：fresh FC → `snapshot/load{resume_vm:false}`（load 后**暂停**，vCPU 不跑）
///   → `apply_network_policy` 策略钩子 → `PATCH /vm Resumed` → 连 vsock → Ping →
///   **下发 Reinit** → 一致性校验。暂停态构造上不可能发包，且策略钩子在 resume 之前。
fn restore_core(
    cfg: &Config,
    ctx: &RestoreCtx,
) -> Result<(LoadOutcome, Option<Child>, Option<nftfw::Sandbox>), String> {
    let parked = restore_park(cfg, ctx)?;
    restore_activate(cfg, ctx.netns, ctx.keep_alive, parked)
}

/// W2/W4 单发恢复：`restore_core` 之薄封装（实例目录==模板目录、无 bind、无 keep-alive）——
/// 与抽出前**路径等价**，`--snap-load`/`--clone-entropy-check`（Q3/Q4）零回归。
fn snapshot_load_run(cfg: &Config, snap_dir: &Path) -> Result<LoadOutcome, String> {
    if !snap_dir.is_dir() {
        return Err(format!("快照目录不存在: {}（先跑 --snap-create）", snap_dir.display()));
    }
    let root = unsafe { libc::geteuid() } == 0;
    // 时序探针 live 化档（M2 W2，M2-Q1 时序面）：`--net-live` 且 root → 真具名 netns + 真 nft
    // forward-hook 门禁 ensure（fail-closed，resume 之前）+ 真 resume → `policy_margin_us` 真实非 0、
    // `policy_before_resume` 恒真。**Option A 边界**：快照无网卡 → 恢复态 guest 无 eth0，本档只证
    // "门禁真被 ensure 且钉在 resume 前"，真流量出口 deny/allow 证明走 `--net-live-reconcile` 冷启动。
    if cfg.net_live && root {
        let uplink = cfg
            .uplink
            .clone()
            .or_else(|| netlive::detect_uplink(root))
            .ok_or_else(|| "未能确定上行网卡（--uplink <dev>）".to_string())?;
        let ns = netlive::ns_for("probe");
        let net = netlive::LiveNet::up("probe", &ns, &uplink, root)?;
        let ctx = RestoreCtx {
            template_dir: snap_dir,
            instance_dir: snap_dir,
            bind: None,
            keep_alive: false,
            netns: Some(&ns),
        };
        let result = restore_core(cfg, &ctx);
        // 门禁句柄回收：成功档 restore_core 把句柄交回（此处即刻拆）；失败档它已自拆。
        let out = match result {
            Ok((o, _child, gate)) => {
                if let Some(sb) = gate {
                    let _ = sb.teardown();
                }
                Ok(o)
            }
            Err(e) => Err(e),
        };
        net.down(); // 具名 netns/veth/NAT 显式回收（不自动清）——无论成败。
        return out;
    }
    let ctx = RestoreCtx {
        template_dir: snap_dir,
        instance_dir: snap_dir,
        bind: None,
        keep_alive: false,
        netns: None,
    };
    let (outcome, _none, _gate) = restore_core(cfg, &ctx)?;
    Ok(outcome)
}

/// W2/W4 快照 load：恢复 + reinit，打印一致性/时延/身份（人类或 --json）。
fn snapshot_load(cfg: &Config, snap_dir: &Path) -> Result<(), String> {
    if !cfg.json {
        println!("[sl-node] 快照 load：fresh FC → load(暂停) → 策略钩子 → resume → reinit（ADR-13/12）");
    }
    let o = snapshot_load_run(cfg, snap_dir)?;
    if cfg.json {
        println!(
            r#"{{"api_ready_ms":{},"load_ms":{},"resume_ms":{},"total_ms":{},"snap_uptime":{:.2},"loaded_uptime":{:.2},"policy_before_resume":{},"policy_margin_us":{},"machine_id":"{}"}}"#,
            o.api_ready_ms, o.load_ms, o.resume_ms, o.total_ms, o.want_uptime, o.loaded_uptime,
            o.policy_before_resume, o.policy_margin_us, o.machine_id
        );
    } else {
        println!(
            "[sl-node] 恢复 PASS：marker 一致（{}），uptime 连续（快照≈{:.2}s → 恢复≈{:.2}s，非重启）",
            o.marker, o.want_uptime, o.loaded_uptime
        );
        println!(
            "[sl-node] reinit（ADR-12）：machine-id={} rng[8]={}… session-key[8]={}…",
            o.machine_id, &o.rng_hex[..o.rng_hex.len().min(8)], &o.session_key_hex[..o.session_key_hex.len().min(8)]
        );
        println!("[sl-node] 时序（ADR-13/Q4）：load(暂停) → 策略钩子 → resume，策略先于 resume={}（余量 {}µs）", o.policy_before_resume, o.policy_margin_us);
        println!("[sl-node] ── 恢复时延分段（Q2，单次，非 SLO 口径）──");
        println!("[sl-node]   fresh FC spawn→api ready:   {} ms", o.api_ready_ms);
        println!("[sl-node]   snapshot/load(PUT) 往返:     {} ms", o.load_ms);
        println!("[sl-node]   PATCH Resumed 往返:          {} ms", o.resume_ms);
        println!("[sl-node]   总计(spawn→vsock 可交互):    {} ms", o.total_ms);
    }
    Ok(())
}

/// Q3 克隆熵回归：同一快照顺序 restore 两次，断言 machine-id/RNG/会话密钥三项**两两必不同**。
/// 两实例的分叉来自：内核 vmgenid reseed（rng_hex）+ 每恢复唯一 host 种子（身份）。
fn clone_entropy_check(cfg: &Config, snap_dir: &Path) -> Result<(), String> {
    if !cfg.json {
        println!("[sl-node] 克隆熵回归（Q3）：同快照恢复两实例，比对 machine-id/RNG/会话密钥");
    }
    let a = snapshot_load_run(cfg, snap_dir)?;
    let b = snapshot_load_run(cfg, snap_dir)?;

    let machine_id_distinct = a.machine_id != b.machine_id;
    let rng_distinct = a.rng_hex != b.rng_hex;
    let session_key_distinct = a.session_key_hex != b.session_key_hex;
    let pass = machine_id_distinct && rng_distinct && session_key_distinct;

    if cfg.json {
        println!(
            r#"{{"metric":"clone_entropy","machine_id_distinct":{machine_id_distinct},"rng_distinct":{rng_distinct},"session_key_distinct":{session_key_distinct},"pass":{pass}}}"#
        );
    } else {
        println!("[sl-node]   实例A machine-id={} rng[8]={}…", a.machine_id, &a.rng_hex[..a.rng_hex.len().min(8)]);
        println!("[sl-node]   实例B machine-id={} rng[8]={}…", b.machine_id, &b.rng_hex[..b.rng_hex.len().min(8)]);
        println!(
            "[sl-node]   machine-id 异={machine_id_distinct}  RNG 异={rng_distinct}（内核 vmgenid reseed）  会话密钥 异={session_key_distinct}"
        );
    }
    if !pass {
        return Err(format!(
            "克隆熵回归 FAIL：machine_id_distinct={machine_id_distinct} rng_distinct={rng_distinct} session_key_distinct={session_key_distinct}（克隆状态泄漏！）"
        ));
    }
    if !cfg.json {
        println!("[sl-node] 克隆熵回归 PASS：两实例 machine-id/RNG/会话密钥 皆异，无克隆状态泄漏（Q3）");
    }
    Ok(())
}

/// 非阻塞 drain：host 监听侧若有已完成握手的新连接则收下（随即 drop 关闭）返回 true，否则 false。
fn drain_accept(listener: &TcpListener) -> bool {
    let mut saw = false;
    // 排空所有 pending（nc 可能重试建多条）——任一成功即算 guest 真发包到达。
    while let Ok((_s, _)) = listener.accept() {
        saw = true;
    }
    saw
}

/// M2 W2 方案 A：**真 microVM** live 网络门禁 e2e 对账。冷启动一台真 VM 进 per-instance 具名 netns
/// （eth0→tap），forward-hook 门禁在 `InstanceStart` **之前** ensure（默认 drop）→ 由 **guest 侧**
/// 发起到 host veth 地址的 TCP 连接：无 allow **被拒** / `add_allow` 后**放行**（allow 成功即正向
/// 证明 guest 真发包，非"连不上"反证）→ 审计 ruleset（policy drop + 放行元素）+ NAT masquerade 已铺
/// → 拆干净无残留 → 单行 `{"metric":"net_live",...}`。需 root + KVM + nft + ip。FAIL 返 Err（退非 0）。
///
/// **为何冷启动而非走恢复**：`snapshot_create` 烘焙的快照**无网卡**（FC 不支持恢复时加 NIC），恢复态
/// guest 无 eth0 → 恢复路径发不出真流量。故真流量 gate 证明只能走 fresh boot（本函数）；orchestrator
/// 实例本周仍无网卡（出口天然为零，fail-safe）。restore-path live 网卡落地待后续。
///
/// **guest 侧接线**：不依赖内核 `ip=` autoconfig（未必编 CONFIG_IP_PNP），改经 vsock exec 显式
/// `ip addr/route` 配 eth0（静态 IP + 默认路由=tap 网关）——更确定、可观测。
fn net_live_reconcile(cfg: &Config, template_dir: &Path) -> Result<(), String> {
    let root = unsafe { libc::geteuid() } == 0;
    if !root {
        return Err("net_live 真 VM 对账需 root（ip netns exec / nft / KVM）；见 CI net-live job".into());
    }
    if !Path::new("/dev/kvm").exists() {
        return Err("/dev/kvm 不存在：net_live 需 KVM 起真 VM（无 KVM 的 runner 应 skip 本对账）".into());
    }
    for (l, p) in [("kernel", &cfg.kernel), ("firecracker", &cfg.fc_bin)] {
        if !p.exists() {
            return Err(format!("{l} 不存在: {}", p.display()));
        }
    }
    // rootfs：优先模板目录里的（冷启动可写根盘），退回 cfg.rootfs。
    let rootfs = {
        let t = template_dir.join("rootfs.ext4");
        if t.exists() {
            abspath(&t)?
        } else if cfg.rootfs.exists() {
            abspath(&cfg.rootfs)?
        } else {
            return Err(format!(
                "rootfs 不存在：模板 {} 无 rootfs.ext4 且 {} 也缺",
                template_dir.display(),
                cfg.rootfs.display()
            ));
        }
    };
    let kernel = abspath(&cfg.kernel)?;

    let uplink = cfg
        .uplink
        .clone()
        .or_else(|| netlive::detect_uplink(root))
        .unwrap_or_else(|| "lo".into()); // 隔离 runner 无默认路由时退 lo：masquerade 规则仍可建/审计
    let ns = netlive::ns_for("live");
    let table = netlive::table_for("live");
    let net = netlive::LiveNet::up("live", &ns, &uplink, root)?;
    let host_ip = net.host_ip().to_string();
    let guest_ip = net.guest_ip().to_string();
    let gateway_ip = net.gateway_ip().to_string();
    let tap = net.tap().to_string();

    // 实例目录（api/vsock/console 落此）。
    let inst = cfg.workdir.join("netlive");
    let _ = std::fs::remove_dir_all(&inst);
    std::fs::create_dir_all(&inst).map_err(|e| format!("建实例目录失败: {e}"))?;
    let inst = abspath(&inst)?;
    let api_host = inst.join("api.sock");
    let vsock = inst.join("vsock.sock");
    let console = inst.join("console.log");

    // host 监听（root netns 的 veth_h 地址；guest→此地址经门禁 forward 链），端口交内核分配。
    let listener = TcpListener::bind((host_ip.as_str(), 0)).map_err(|e| format!("bind 监听失败: {e}"))?;
    let port = listener.local_addr().map_err(|e| format!("取监听端口失败: {e}"))?.port();
    listener.set_nonblocking(true).map_err(|e| format!("设监听非阻塞失败: {e}"))?;

    if !cfg.json {
        eprintln!(
            "[netlive] net_live 真 VM 对账：netns={ns} tap={tap} guest={guest_ip}→gw {gateway_ip}→host {host_ip}:{port} NAT→{uplink}"
        );
    }

    // 内层闭包返回 (deny_ok, allow_ok, audit_ok, teardown_clean)；无论成败外层再 net.down() 兜底。
    let outcome = (|| -> Result<(bool, bool, bool, bool), String> {
        // ① 门禁：InstanceStart 之前 ensure forward-hook 默认 drop（allow 集合此刻为空）。
        let sb = netlive::gate_up(&ns, &table, root, /*hook_forward=*/ true)?;

        // ② 冷启动真 VM 进具名 netns（eth0→tap）。
        let _ = std::fs::remove_file(&api_host);
        let _ = std::fs::remove_file(&vsock);
        let mut c = Command::new("ip");
        c.arg("netns").arg("exec").arg(&ns).arg(&cfg.fc_bin).arg("--api-sock").arg(&api_host);
        let mut child = spawn_with_log(c, &console)?;

        let probed = (|| -> Result<(bool, bool, bool), String> {
            let api = FcApi::new(&api_host);
            wait_api_ready(&api, &mut child)?;
            api.put("/machine-config", r#"{"vcpu_count":1,"mem_size_mib":128}"#)?;
            api.put(
                "/boot-source",
                &format!(
                    r#"{{"kernel_image_path":"{}","boot_args":"{}"}}"#,
                    kernel.display(),
                    boot_args()
                ),
            )?;
            api.put(
                "/drives/rootfs",
                &format!(
                    r#"{{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":false}}"#,
                    rootfs.display()
                ),
            )?;
            api.put(
                "/network-interfaces/eth0",
                &format!(r#"{{"iface_id":"eth0","host_dev_name":"{tap}","guest_mac":"{GUEST_MAC}"}}"#),
            )?;
            api.put("/vsock", &format!(r#"{{"guest_cid":{GUEST_CID},"uds_path":"{}"}}"#, vsock.display()))?;
            api.put("/actions", r#"{"action_type":"InstanceStart"}"#)?;

            let mut stream = wait_guest(&vsock, &mut child)?;
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .map_err(|e| format!("设读超时失败: {e}"))?;
            match request(&mut stream, &Request::Ping { data: "netlive".into() })? {
                Response::Pong { data } if data == "netlive" => {}
                other => return Err(format!("guest Ping 自检失败: {other:?}")),
            }

            // guest 侧接线：静态配 eth0 + 默认路由（不依赖内核 IP autoconfig）。
            let netup = format!(
                "ip addr add {guest_ip}/30 dev eth0 && ip link set eth0 up && ip route add default via {gateway_ip}"
            );
            let (rc_net, _o, e_net) = exec(&mut stream, &netup)?;
            if rc_net != 0 {
                return Err(format!("guest 配网失败（rc={rc_net}）: {}", e_net.trim()));
            }

            // guest 侧探针：echo 一字节经 nc 连 host，打印退出码（最后一行）。
            let probe_cmd = format!("echo probe | nc -w 3 {host_ip} {port} >/dev/null 2>&1; echo rc=$?");
            let last_rc = |out: &str| -> String {
                out.lines().rev().find_map(|l| l.trim().strip_prefix("rc=").map(|s| s.to_string())).unwrap_or_default()
            };

            // ③ 无 allow：SYN 被 forward 链 drop → guest nc 失败、host 未见连接。
            let _ = drain_accept(&listener);
            let (_, out1, _) = exec(&mut stream, &probe_cmd)?;
            let deny_ok = last_rc(&out1) != "0" && !drain_accept(&listener);
            if !cfg.json {
                eprintln!("[netlive]   ① 无 allow：guest nc rc={} host_saw={} → deny_ok={deny_ok}", last_rc(&out1), false);
            }

            // ④ 加 allow(host_ip, port)：SYN 放行 → guest nc 成功、host 见连接（正向证明真发包）。
            sb.add_allow(&host_ip, port)?;
            let (_, out2, _) = exec(&mut stream, &probe_cmd)?;
            let guest_allow_ok = last_rc(&out2) == "0";
            let mut host_saw_allow = false;
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(3) {
                if drain_accept(&listener) {
                    host_saw_allow = true;
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            let allow_ok = guest_allow_ok && host_saw_allow;
            if !cfg.json {
                eprintln!("[netlive]   ② 加 allow {host_ip}:{port}：guest nc rc={} host_saw={host_saw_allow} → allow_ok={allow_ok}", last_rc(&out2));
            }

            // 审计：门禁含 policy drop + 放行元素；NAT masquerade 已铺。
            let ruleset = sb.list_ruleset()?;
            let gate_audit = ruleset.contains("policy drop")
                && ruleset.contains(&host_ip)
                && ruleset.contains(&port.to_string());
            let nat_audit = net.nat_masquerade_present();
            let audit_ok = gate_audit && nat_audit;
            if !cfg.json {
                eprintln!("[netlive]   审计：门禁 policy-drop+放行元素={gate_audit} NAT masquerade={nat_audit} → audit_ok={audit_ok}");
            }

            Ok((deny_ok, allow_ok, audit_ok))
        })();

        // 收 VM（无论探测成败）。
        kill_group(&mut child);
        let _ = std::fs::remove_file(&api_host);
        let _ = std::fs::remove_file(&vsock);

        let (deny_ok, allow_ok, audit_ok) = probed?;

        // ⑤ 拆门禁 + 拓扑 → 无残留。
        sb.teardown()?;
        net.down();
        let teardown_clean = !sb.exists() && net.is_clean();
        if !cfg.json {
            eprintln!("[netlive]   ③ 销毁：门禁+netns+veth+NAT → teardown_clean={teardown_clean}");
        }
        Ok((deny_ok, allow_ok, audit_ok, teardown_clean))
    })();

    net.down(); // 无论成败都拆拓扑（幂等）。
    let _ = std::fs::remove_dir_all(&inst);

    let (deny_ok, allow_ok, audit_ok, teardown_clean) = outcome?;
    let pass = deny_ok && allow_ok && audit_ok && teardown_clean;
    if cfg.json {
        println!(
            r#"{{"metric":"net_live","deny_ok":{deny_ok},"allow_ok":{allow_ok},"audit_ok":{audit_ok},"teardown_clean":{teardown_clean},"pass":{pass}}}"#
        );
    } else {
        eprintln!(
            "[netlive] {} net_live 真 VM：无策略拒绝={deny_ok} 加allow放行={allow_ok} 可审计(门禁+NAT)={audit_ok} 销毁无残留={teardown_clean}",
            if pass { "✅ PASS" } else { "❌ FAIL" }
        );
    }
    if !pass {
        return Err(format!(
            "net_live 真 VM 对账 FAIL：deny_ok={deny_ok} allow_ok={allow_ok} audit_ok={audit_ok} teardown_clean={teardown_clean}"
        ));
    }
    Ok(())
}

/// ADR-13 策略钩子：在具名 netns 上 ensure per-sandbox 门禁（默认 drop + 白名单），返回
/// `(策略生效时刻, 门禁句柄)`——时刻供上层断言"策略先于 resume"（Q4，钉死时序骨架），句柄交
/// 调用方线程化持有（teardown 归调用方，见 restore_core 失败清理 / snapshot_load_run live 档）。
///
/// **M2 W2（fail-closed）**：`netns` 为 `Some(ns)` 且 root → 经 [`netlive::gate_up`] 在该具名
/// netns 上 ensure nftfw 的 **forward-hook** 门禁（默认 drop），**失败即返回 `Err`**（上层
/// `?` 抛出 → 不 resume、不放 VM 跑，无发包窗口）。forward hook 咬住经 netns 转发的真 microVM
/// 流量（tap→veth）。返回 `Some(sb)` 交调用方 teardown。
///
/// `netns` 为 `None`（默认 / rootless / 普通 `--snap-load`）→ 门禁休眠，返回
/// `(Instant::now(), None)`，与 M1 逐字节一致，零回归。
fn apply_network_policy(
    cfg: &Config,
    netns: Option<&str>,
) -> Result<(Instant, Option<nftfw::Sandbox>), String> {
    let Some(ns) = netns else {
        // 默认路径：无具名 netns，门禁休眠（M1 行为逐字节不变）。
        return Ok((Instant::now(), None));
    };
    let root = unsafe { libc::geteuid() } == 0;
    if !root {
        // 具名 netns 恢复本就需 root（`ip netns exec`）；到此仍非 root 属调用方 bug，fail-closed。
        return Err("live 门禁需 root（ip netns exec / nft）".into());
    }
    // fail-closed：ensure forward-hook 门禁；失败即抛，调用方不 resume。
    let table = netlive::table_for(ns);
    let sb = netlive::gate_up(ns, &table, root, /*hook_forward=*/ true)
        .map_err(|e| format!("live 门禁 ensure 失败（fail-closed，不 resume）：{e}"))?;
    if !cfg.json {
        println!(
            "[sl-node] live 门禁：netns={ns} table={table} forward-hook 默认 drop 已就位（resume 之前）"
        );
    }
    Ok((Instant::now(), Some(sb)))
}

/// 下发 Reinit 请求，返回 (machine_id, rng_hex, session_key_hex)。
fn send_reinit(
    stream: &mut UnixStream,
    seed_hex: &str,
    hostname: &str,
    wall_time_ns: u64,
) -> Result<(String, String, String), String> {
    let req = Request::Reinit {
        seed_hex: seed_hex.into(),
        hostname: hostname.into(),
        wall_time_ns,
    };
    match request(stream, &req)? {
        Response::Reinit { machine_id, rng_hex, session_key_hex } => Ok((machine_id, rng_hex, session_key_hex)),
        Response::Error { message } => Err(format!("reinit 失败: {message}")),
        other => Err(format!("reinit 非预期响应: {other:?}")),
    }
}

/// 冷启动一台**带 NIC** 的 microVM 进 `net` 的 netns，到 sl-envd 就绪 → guest 配 eth0/默认路由/DNS →
/// Reinit 换发身份。返回 `(Child, machine_id, rng_hex, session_key_hex)`。供运行时 egress 沙箱
/// （[`crate::fcbackend`] `create_egress`）与 `--net-egress-reconcile` 共用。需 root（进 netns）。
///
/// 与恢复路径正交：egress 沙箱无快照可用（快照无网卡），故冷启动;身份天然全新（无克隆熵问题），
/// 仍下发 Reinit 以物化 machine-id/hostname/会话密钥并校时钟。开放出口由调用方（不挂 nftfw drop 门禁）决定。
#[allow(clippy::type_complexity)]
pub(crate) fn cold_boot_egress(
    cfg: &Config,
    instance_dir: &Path,
    net: &netlive::LiveNet,
    vcpus: u32,
    mem_mib: u32,
) -> Result<(Child, String, String, String), String> {
    let kernel = abspath(&cfg.kernel)?;
    let rootfs = instance_dir.join("rootfs.ext4");
    let api_host = instance_dir.join("api.sock");
    let vsock = instance_dir.join("vsock.sock");
    let console = instance_dir.join("console.load.log");
    let _ = std::fs::remove_file(&api_host);
    let _ = std::fs::remove_file(&vsock);

    let mut c = Command::new("ip");
    c.arg("netns").arg("exec").arg(&net.ns).arg(&cfg.fc_bin).arg("--api-sock").arg(&api_host);
    let mut child = spawn_with_log(c, &console)?;

    let boot = (|| -> Result<(String, String, String), String> {
        let api = FcApi::new(&api_host);
        wait_api_ready(&api, &mut child)?;
        api.put("/machine-config", &format!(r#"{{"vcpu_count":{vcpus},"mem_size_mib":{mem_mib}}}"#))?;
        api.put(
            "/boot-source",
            &format!(r#"{{"kernel_image_path":"{}","boot_args":"{}"}}"#, kernel.display(), boot_args()),
        )?;
        api.put(
            "/drives/rootfs",
            &format!(
                r#"{{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":false}}"#,
                rootfs.display()
            ),
        )?;
        api.put(
            "/network-interfaces/eth0",
            &format!(r#"{{"iface_id":"eth0","host_dev_name":"{}","guest_mac":"{GUEST_MAC}"}}"#, net.tap()),
        )?;
        api.put("/vsock", &format!(r#"{{"guest_cid":{GUEST_CID},"uds_path":"{}"}}"#, vsock.display()))?;
        api.put("/actions", r#"{"action_type":"InstanceStart"}"#)?;

        let mut stream = wait_guest(&vsock, &mut child)?;
        stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e| format!("设读超时失败: {e}"))?;
        match request(&mut stream, &Request::Ping { data: "egress".into() })? {
            Response::Pong { data } if data == "egress" => {}
            other => return Err(format!("guest Ping 自检失败: {other:?}")),
        }
        // guest 侧接线：静态 eth0 + 默认路由 + DNS（不依赖内核 IP autoconfig；DNS 走 NAT 出 uplink）。
        let dns = std::env::var("SL_EGRESS_DNS").unwrap_or_else(|_| "1.1.1.1".into());
        let netup = format!(
            "ip addr add {}/30 dev eth0 && ip link set eth0 up && ip route add default via {} && printf 'nameserver {dns}\\n' > /etc/resolv.conf",
            net.guest_ip(),
            net.gateway_ip()
        );
        let (rc, _o, e) = exec(&mut stream, &netup)?;
        if rc != 0 {
            return Err(format!("guest 配网失败（rc={rc}）: {}", e.trim()));
        }
        // Reinit：换发 machine-id/hostname/会话密钥 + 混种子 + 校时钟（冷启动身份物化）。
        let mut seed = [0u8; 32];
        host_random(&mut seed);
        let seed_hex = hex(&seed);
        let hostname = format!("sandlocker-{}", hex(&seed[..4]));
        let wall_time_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        send_reinit(&mut stream, &seed_hex, &hostname, wall_time_ns)
    })();

    match boot {
        Ok((mid, rng, sess)) => Ok((child, mid, rng, sess)),
        Err(e) => {
            kill_group(&mut child);
            Err(e)
        }
    }
}

/// host 侧填充随机字节（libc::getrandom；短读重试）。
fn host_random(buf: &mut [u8]) {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe {
            libc::getrandom(buf[off..].as_mut_ptr() as *mut libc::c_void, buf.len() - off, 0)
        };
        if n <= 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // 退化：不阻断（种子仅为安全带，vmgenid 仍保证 RNG 分叉）
            break;
        }
        off += n as usize;
    }
}

/// 小写 hex 编码。
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// chroot 根目录：jailer 约定 `<chroot-base>/<exec_file_name>/<id>/root`。
fn jail_root(cfg: &Config) -> PathBuf {
    jail_instance_dir(cfg).join("root")
}
fn jail_instance_dir(cfg: &Config) -> PathBuf {
    // exec-file 名为 firecracker，故中间层是 "firecracker"
    cfg.workdir.join("jail").join("firecracker").join(JAIL_ID)
}

/// 按 boot 形态构造 spawn 的 Command（含 netns 包装 / jailer 包装）。
fn build_spawn_cmd(cfg: &Config, uds_path: &Path, api_host: &Path) -> Result<Command, String> {
    // config-file 模式：先把 vm.json 写好（含内视角为绝对 host 路径）
    let vm_json = cfg.workdir.join("vm.json");
    if cfg.boot == Boot::ConfigFile {
        write_vm_config(cfg, &vm_json, uds_path)?;
    }

    // jailer 模式：预置 chroot（建目录 + 硬链内核/rootfs 进 root/），再由 jailer chroot 进入。
    if cfg.boot == Boot::Jailer {
        // jailer 需 root；且 sl-node 须整体为 root 才能 killpg 回收 jailer→FC 这棵 root 进程树
        // （普通用户 sudo 起 jailer 会造成 teardown EPERM 泄漏）。故此处硬要求 euid==0。
        if unsafe { libc::geteuid() } != 0 {
            return Err(
                "jailer 模式需 root：请以 `sudo -E target/release/sl-node --boot jailer ...` 运行\
                 （sudo sl-node 才能拥有并回收整棵 root 进程树；单独 sudo jailer 会致 teardown 泄漏）".into(),
            );
        }
        prepare_jail(cfg)?;
        if !cfg.json {
            println!(
                "[sl-node] 启动 microVM（jailer chroot+cgroup+降权 uid={} gid={}）",
                cfg.jail_uid, cfg.jail_gid
            );
        }
        let mut c = Command::new(&cfg.jailer_bin);
        c.arg("--id").arg(JAIL_ID)
            .arg("--uid").arg(cfg.jail_uid.to_string())
            .arg("--gid").arg(cfg.jail_gid.to_string())
            .arg("--exec-file").arg(abspath(&cfg.fc_bin)?)
            .arg("--chroot-base-dir").arg(abspath(&cfg.workdir)?.join("jail"));
        // v2-only 主机（如 WSL2）jailer 默认按 v1 装 cgroup 会失败，显式切 v2
        if cgroup_v2() {
            c.arg("--cgroup-version").arg("2");
        }
        c.arg("--").arg("--api-sock").arg(JAIL_API_SOCK);
        let _ = api_host; // jailer 下 api sock 由 JAIL_API_SOCK 决定，host 路径已在调用方算好
        return Ok(c);
    }

    // 非 jailer 的 FC 参数：api 模式给 --api-sock，config-file 给 --no-api --config-file
    let fc_args: Vec<PathBuf> = match cfg.boot {
        Boot::Api => vec![PathBuf::from("--api-sock"), api_host.to_path_buf()],
        Boot::ConfigFile => vec![PathBuf::from("--no-api"), PathBuf::from("--config-file"), vm_json.clone()],
        Boot::Jailer => unreachable!(),
    };

    // netns 模式：unshare --net --map-root-user 起独立 netns，包装脚本建 tap 后 exec FC；
    // --no-netns：直接起 FC（无网卡）。两种都放进独立进程组，便于整组回收。
    if cfg.netns {
        if !cfg.json {
            let how = if cfg.boot == Boot::Api { "API" } else { "config-file" };
            println!("[sl-node] 启动 microVM（独立 netns + tap {TAP_NAME}，rootless，{how} 启动）");
        }
        let mut c = Command::new("unshare");
        c.arg("--net").arg("--map-root-user").arg("--")
            .arg(NETNS_WRAPPER).arg(TAP_NAME).arg(HOST_CIDR).arg(&cfg.fc_bin)
            .args(&fc_args);
        Ok(c)
    } else {
        if !cfg.json {
            let how = if cfg.boot == Boot::Api { "API" } else { "config-file" };
            println!("[sl-node] 启动 microVM（--no-netns，无网卡，{how} 启动）");
        }
        let mut c = Command::new(&cfg.fc_bin);
        c.args(&fc_args);
        Ok(c)
    }
}

/// 预置 jailer chroot：建 root/ 目录，硬链内核/rootfs 进去（跨盘回退到拷贝），置属主/权限。
/// jailer 容忍已存在的 chroot 目录；内核/rootfs 它不搬，须我们放好。
fn prepare_jail(cfg: &Config) -> Result<(), String> {
    let root = jail_root(cfg);
    let _ = std::fs::remove_dir_all(jail_instance_dir(cfg)); // 清上轮
    std::fs::create_dir_all(&root).map_err(|e| format!("建 chroot root 失败: {e}"))?;
    link_or_copy(&cfg.kernel, &root.join("vmlinux"))?; // 只读，供 FC 读
    link_or_copy(&cfg.rootfs, &root.join("rootfs.ext4"))?; // rw 根盘
    // 属主置为降权目标 uid/gid，使 chroot 后的 FC 可读写（dev 内环默认取当前用户，天然一致）
    chown_tree(&jail_instance_dir(cfg), cfg.jail_uid, cfg.jail_gid);
    Ok(())
}

/// 硬链 src→dst，失败（跨文件系统等）回退到拷贝。
fn link_or_copy(src: &Path, dst: &Path) -> Result<(), String> {
    let _ = std::fs::remove_file(dst);
    let real = std::fs::canonicalize(src).unwrap_or_else(|_| src.to_path_buf());
    if std::fs::hard_link(&real, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(&real, dst).map(|_| ()).map_err(|e| format!("放置 {} 进 chroot 失败: {e}", src.display()))
}

/// 递归 chown（best-effort；非 root 时对自有文件设同 uid 会成功，跨用户降权需 root）。
fn chown_tree(dir: &Path, uid: u32, gid: u32) {
    use std::os::unix::ffi::OsStrExt;
    let c = |p: &Path| {
        if let Ok(cs) = std::ffi::CString::new(p.as_os_str().as_bytes()) {
            unsafe { libc::chown(cs.as_ptr(), uid, gid) };
        }
    };
    c(dir);
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() { chown_tree(&p, uid, gid); } else { c(&p); }
        }
    }
}

fn abspath(p: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(p).map_err(|e| format!("解析绝对路径失败 {}: {e}", p.display()))
}

/// cgroup v2（unified）主机探测：存在 /sys/fs/cgroup/cgroup.controllers 即 v2。
fn cgroup_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

/// api/jailer 启动：等 api-sock 就绪 → 逐段 PUT 配置 → InstanceStart。
/// 路径视角：jailer 下 FC 已 chroot，用 chroot 相对路径；否则用绝对 host 路径。
fn configure_via_api(cfg: &Config, api_host: &Path, child: &mut Child) -> Result<(), String> {
    let api = FcApi::new(api_host);
    // 等 api-sock 就绪（期间若 FC 已退出——如 jailer 权限失败——提前失败别空等）
    wait_api_ready(&api, child)?;

    // 视角路径：jailer 用 chroot 相对；api（不 chroot）用绝对 host 路径。
    let (kernel_v, rootfs_v, vsock_v) = match cfg.boot {
        Boot::Jailer => (JAIL_KERNEL.to_string(), JAIL_ROOTFS.to_string(), JAIL_VSOCK.to_string()),
        _ => (
            cfg.kernel.display().to_string(),
            cfg.rootfs.display().to_string(),
            cfg.workdir.join("vsock.sock").display().to_string(),
        ),
    };
    let boot_args = boot_args();

    // 规格来自 --vcpus/--mem-mib（默认 1/128 = 历史写死值，零回归）。密度基准据此分「默认档 /
    // micro 档」两次跑，才对得上 §8.1 的两行密度口径。
    api.put(
        "/machine-config",
        &format!(r#"{{"vcpu_count":{},"mem_size_mib":{}}}"#, cfg.vcpus, cfg.mem_mib),
    )?;
    api.put(
        "/boot-source",
        &format!(r#"{{"kernel_image_path":"{kernel_v}","boot_args":"{boot_args}"}}"#),
    )?;
    api.put(
        "/drives/rootfs",
        &format!(
            r#"{{"drive_id":"rootfs","path_on_host":"{rootfs_v}","is_root_device":true,"is_read_only":false}}"#
        ),
    )?;
    if cfg.netns {
        api.put(
            "/network-interfaces/eth0",
            &format!(
                r#"{{"iface_id":"eth0","host_dev_name":"{TAP_NAME}","guest_mac":"{GUEST_MAC}"}}"#
            ),
        )?;
    }
    api.put(
        "/vsock",
        &format!(r#"{{"guest_cid":{GUEST_CID},"uds_path":"{vsock_v}"}}"#),
    )?;
    api.put("/actions", r#"{"action_type":"InstanceStart"}"#)?;
    Ok(())
}

/// guest 启动参数（config-file 与 API 两路共用，避免漂移）。
fn boot_args() -> &'static str {
    "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux \
     i8042.nopnp i8042.dumbkbd init=/sbin/sl-envd root=/dev/vda rw"
}

/// 重试握手直到 guest 内 sl-envd 就绪，然后执行命令（--cmd 单条 / 缺省 demo 序列）。
fn drive_exec(cfg: &Config, uds_path: &Path, child: &mut Child, spawn_at: Instant) -> Result<(), String> {
    let mut stream = loop {
        // FC 若已退出则提前失败，别空等到超时
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("microVM 提前退出（status={status}），见 console.log"));
        }
        match connect_guest(uds_path) {
            Ok(s) => break s,
            Err(_) if spawn_at.elapsed() < READY_TIMEOUT => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("等待 guest sl-envd 就绪超时（{READY_TIMEOUT:?}）: {e}")),
        }
    };
    let ready_ms = spawn_at.elapsed().as_millis();
    let (pre_kernel_ms, guest_boot_ms) = timing_split(&cfg.workdir.join("console.log"), ready_ms);

    // --json：机器可读单行（供 bench 采集 P50/P99），不打人类日志、不跑 demo 命令
    if cfg.json {
        println!(
            r#"{{"total_ms":{ready_ms},"pre_kernel_ms":{},"guest_boot_ms":{},"netns":{}}}"#,
            pre_kernel_ms.map(|v| v.to_string()).unwrap_or("null".into()),
            guest_boot_ms.map(|v| v.to_string()).unwrap_or("null".into()),
            cfg.netns
        );
        return Ok(());
    }

    println!("[sl-node] guest sl-envd 就绪，耗时 ~{ready_ms}ms（含冷 boot，非 SLO 口径）");
    print_timing(ready_ms, pre_kernel_ms, guest_boot_ms, &cfg.workdir.join("console.log"));

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("设读超时失败: {e}"))?;

    // 连通性自检：Ping/Pong（沿用 W2 链路验证）
    match request(&mut stream, &Request::Ping { data: "sandlocker".into() })? {
        Response::Pong { data } if data == "sandlocker" => {}
        other => return Err(format!("Ping 自检失败: {other:?}")),
    }

    // 保活模式（密度 bench）：打 HELD 标记后保活 N 秒，再走既有 kill_group 干净销毁
    if cfg.hold_secs > 0 {
        println!("[sl-node] HELD ready={ready_ms}ms hold={}s", cfg.hold_secs);
        thread::sleep(Duration::from_secs(cfg.hold_secs));
        return Ok(());
    }

    // 即席模式：执行单条命令并原样透传输出/退出码
    if let Some(cmd) = &cfg.cmd {
        let (code, out, err) = exec(&mut stream, cmd)?;
        print!("{out}");
        eprint!("{err}");
        println!("[sl-node] 命令退出码: {code}");
        return Ok(());
    }

    // demo 序列：每条断言退出码，验证 stdout/退出码传播/stderr 分离
    struct Case {
        cmd: &'static str,
        want_code: i32,
        want_stdout_contains: Option<&'static str>,
        want_stderr_nonempty: bool,
    }
    let cases = [
        Case { cmd: "uname -a", want_code: 0, want_stdout_contains: Some("Linux"), want_stderr_nonempty: false },
        Case { cmd: "echo hello from sandbox", want_code: 0, want_stdout_contains: Some("hello from sandbox"), want_stderr_nonempty: false },
        Case { cmd: "cat /etc/hostname", want_code: 0, want_stdout_contains: Some("sandlocker-m0"), want_stderr_nonempty: false },
        Case { cmd: "ls /", want_code: 0, want_stdout_contains: Some("bin"), want_stderr_nonempty: false },
        Case { cmd: "exit 7", want_code: 7, want_stdout_contains: None, want_stderr_nonempty: false },
        Case { cmd: "ls /no-such-path", want_code: 1, want_stdout_contains: None, want_stderr_nonempty: true },
    ];

    for c in &cases {
        let (code, out, err) = exec(&mut stream, c.cmd)?;
        let out1 = out.lines().next().unwrap_or("").trim();
        println!(
            "[sl-node]   $ {:<20} → exit={code:<2} stdout={:?}{}",
            c.cmd,
            truncate(out1, 48),
            if err.trim().is_empty() { String::new() } else { format!(" stderr={:?}", truncate(err.trim(), 48)) }
        );
        if code != c.want_code {
            return Err(format!("`{}` 退出码期望 {} 实得 {code}", c.cmd, c.want_code));
        }
        if let Some(want) = c.want_stdout_contains {
            if !out.contains(want) {
                return Err(format!("`{}` stdout 未含 {:?}：{:?}", c.cmd, want, out));
            }
        }
        if c.want_stderr_nonempty && err.trim().is_empty() {
            return Err(format!("`{}` 期望有 stderr 但为空", c.cmd));
        }
    }

    // W4 网络断言：guest 有 eth0（NIC 已挂），但无默认路由 → 出口天然为零（ADR-13）
    if cfg.netns {
        let (_, nets, _) = exec(&mut stream, "ls /sys/class/net")?;
        if !nets.split_whitespace().any(|n| n == "eth0") {
            return Err(format!("guest 未见 eth0，实见: {:?}", nets.split_whitespace().collect::<Vec<_>>()));
        }
        // /proc/net/route：跳过表头，默认路由的 Destination 字段为 00000000
        let (_, route, _) = exec(&mut stream, "cat /proc/net/route")?;
        let has_default = route.lines().skip(1).any(|l| {
            let mut f = l.split_whitespace();
            let _iface = f.next();
            matches!(f.next(), Some("00000000"))
        });
        if has_default {
            return Err("guest 存在默认路由，出口未被结构性拒绝".into());
        }
        println!("[sl-node]   ✓ 网络：guest 有 eth0（NIC 已挂），无默认路由 → 出口天然为零（deny-by-default）");
    }
    Ok(())
}

/// 发一个 Exec 请求，返回 (exit_code, stdout, stderr)。
pub(crate) fn exec(stream: &mut UnixStream, cmd: &str) -> Result<(i32, String, String), String> {
    match request(stream, &Request::Exec { cmd: cmd.into() })? {
        Response::Exec { exit_code, stdout, stderr } => Ok((exit_code, stdout, stderr)),
        Response::Error { message } => Err(format!("envd 执行错误: {message}")),
        other => Err(format!("非预期响应: {other:?}")),
    }
}

/// 一次请求-响应往返。
fn request(stream: &mut UnixStream, req: &Request) -> Result<Response, String> {
    write_msg(stream, req).map_err(|e| format!("发请求失败: {e}"))?;
    read_msg(stream).map_err(|e| format!("收响应失败: {e}"))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// 走 FC vsock 握手连到 guest 的 ENVD_VSOCK_PORT。
fn connect_guest(uds_path: &Path) -> Result<UnixStream, String> {
    let mut stream = UnixStream::connect(uds_path).map_err(|e| e.to_string())?;
    stream
        .write_all(format!("CONNECT {ENVD_VSOCK_PORT}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    // 逐字节读回执行行，避免 BufReader 吞掉后续帧字节
    let line = read_line_raw(&mut stream).map_err(|e| e.to_string())?;
    if line.starts_with("OK") {
        Ok(stream)
    } else {
        Err(format!("握手未获 OK（guest 端口 {ENVD_VSOCK_PORT} 未就绪？）: {line:?}"))
    }
}

fn read_line_raw(stream: &mut UnixStream) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            break; // EOF
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn write_vm_config(cfg: &Config, vm_json: &Path, uds_path: &Path) -> Result<(), String> {
    // 单 rw 根盘（W2 简化）；ADR-23 的只读 base + tmpfs 写层随 M1 存储栈落地。
    let boot_args = boot_args();
    // netns 模式挂一块 virtio-net 到 host tap（tap 在 netns 内由 wrapper 创建）。
    let net_iface = if cfg.netns {
        format!(
            ",\n  \"network-interfaces\": [\n    {{\n      \"iface_id\": \"eth0\",\n      \"host_dev_name\": \"{TAP_NAME}\",\n      \"guest_mac\": \"{GUEST_MAC}\"\n    }}\n  ]"
        )
    } else {
        String::new()
    };
    let json = format!(
        r#"{{
  "boot-source": {{
    "kernel_image_path": "{kernel}",
    "boot_args": "{boot_args}"
  }},
  "drives": [
    {{
      "drive_id": "rootfs",
      "path_on_host": "{rootfs}",
      "is_root_device": true,
      "is_read_only": false
    }}
  ],
  "machine-config": {{
    "vcpu_count": 1,
    "mem_size_mib": 128
  }},
  "vsock": {{
    "guest_cid": {cid},
    "uds_path": "{uds}"
  }}{net_iface}
}}
"#,
        kernel = cfg.kernel.display(),
        rootfs = cfg.rootfs.display(),
        uds = uds_path.display(),
        cid = GUEST_CID,
    );
    std::fs::write(vm_json, json).map_err(|e| format!("写 vm.json 失败: {e}"))
}

/// killpg 整组回收（unshare→wrapper→FC 链），再 wait 收尸；netns 随进程消亡自动清理。
fn kill_group(child: &mut Child) {
    let pid = child.id() as i32;
    // 负 pid = 向整个进程组发信号（进程组 id == 组长 pid，见 setpgid(0,0)）
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// 时钟一致的两段分解（Q3）：从 console.log 读 guest 单调钟（/proc/uptime，kvm-clock），
/// 返回 (pre_kernel_ms, guest_boot_ms)。二者可安全相减；dmesg（VM 早期 printk 偏高）不参与。
fn timing_split(console_log: &Path, total_ms: u128) -> (Option<u128>, Option<u128>) {
    let Ok(log) = std::fs::read_to_string(console_log) else { return (None, None) };
    let ready_uptime = log
        .lines()
        .find(|l| l.contains("READY uptime="))
        .and_then(|l| l.split("uptime=").nth(1))
        .and_then(|s| s.split_whitespace().next()) // "0.57s"
        .and_then(|tok| tok.trim_end_matches('s').parse::<f64>().ok());
    match ready_uptime {
        Some(ru) => {
            let guest = (ru * 1000.0).round() as u128;
            let pre = total_ms.saturating_sub(guest);
            (Some(pre), Some(guest))
        }
        None => (None, None),
    }
}

/// 打印冷路径分段（Q3，人类可读）。
fn print_timing(total_ms: u128, pre_kernel: Option<u128>, guest_boot: Option<u128>, console_log: &Path) {
    println!("[sl-node] ── 冷路径分段（Q3，单次冷启动，非 SLO 口径）──");
    println!("[sl-node]   总计(spawn→envd ready, host):      {total_ms} ms");
    if let (Some(pre), Some(guest)) = (pre_kernel, guest_boot) {
        println!("[sl-node]   ├─ pre-kernel(host: unshare/tap/FC 加载内核前): ~{pre} ms");
        println!("[sl-node]   └─ guest boot→envd ready(guest 单调钟):         ~{guest} ms");
    }
    // dmesg 参考（VM 早期时钟偏高，仅供参考）
    if let Ok(log) = std::fs::read_to_string(console_log) {
        let dmesg_ts = |needle: &str| -> Option<f64> {
            log.lines().find(|l| l.contains(needle)).and_then(|l| {
                let open = l.find('[')?;
                let close = l.find(']')?;
                l.get(open + 1..close)?.trim().parse::<f64>().ok()
            })
        };
        if let (Some(rm), Some(is_)) = (dmesg_ts("Mounted root"), dmesg_ts("Run /sbin/sl-envd")) {
            println!(
                "[sl-node]   guest dmesg 参考（VM 早期时钟偏高）: 挂载 rootfs @{:.0}ms, init @{:.0}ms",
                rm * 1000.0,
                is_ * 1000.0
            );
        }
    }
}

/// 销毁对账（Q6）：反复 create/destroy，每轮后断言无残留。
/// 残留面：firecracker 进程、host 侧 tap 设备、vsock socket 文件。
fn reconcile_cycles(cfg: &Config) -> Result<(), String> {
    for i in 0..cfg.cycles {
        // 每轮跑一条最简命令，确保 VM 真正 boot 到可用再销毁
        let one = Config { cmd: Some("true".into()), cycles: 0, ..clone_paths(cfg) };
        run(&one).map_err(|e| format!("第 {} 轮 create/destroy 失败: {e}", i + 1))?;

        // 对账：三类残留都应为空
        let fc = count_proc("firecracker");
        let taps = count_host_tap();
        let sock = cfg.workdir.join("vsock.sock").exists();
        if fc != 0 || taps != 0 || sock {
            return Err(format!(
                "第 {} 轮后有残留: firecracker 进程={fc}, host tap={taps}, vsock.sock={sock}",
                i + 1
            ));
        }
        println!("[sl-node]   轮 {}/{}: 无残留 ✓", i + 1, cfg.cycles);
    }
    Ok(())
}

fn clone_paths(cfg: &Config) -> Config {
    Config {
        kernel: cfg.kernel.clone(),
        rootfs: cfg.rootfs.clone(),
        fc_bin: cfg.fc_bin.clone(),
        jailer_bin: cfg.jailer_bin.clone(),
        workdir: cfg.workdir.clone(),
        boot: cfg.boot,
        cmd: None,
        netns: cfg.netns,
        cycles: 0,
        json: false,
        hold_secs: 0,
        jail_uid: cfg.jail_uid,
        jail_gid: cfg.jail_gid,
        snap_create: None,
        snap_load: None,
        clone_entropy: None,
        dmthin_reconcile: false,
        nftfw_reconcile: false,
        thin: false,
        build: None,
        store: None,
        orch_reconcile: None,
        orch_bench: None,
        serve: false,
        serve_addr: None,
        tick_secs: 5,
        template_root: None,
        run_root: None,
        net_live: cfg.net_live,
        uplink: cfg.uplink.clone(),
        net_gate_reconcile: false,
        net_live_reconcile: None,
        oci_pull: None,
        oci_out: None,
        pool_bench: None,
        pool_size: 2,
        pool_template: None,
        hot_size: 0,
        gvisor: false,
        gvisor_bin: PathBuf::from("runsc"),
        gvisor_reconcile: None,
        abi_contract: None,
        q5_reconcile: None,
        gw_addr: None,
        exec_bench: None,
        vcpus: 1,
        mem_mib: 128,
        snap_kms_key: None,
        snap_kms_init: None,
        snapcrypt_reconcile: false,
        gw_node_endpoint: None,
        gw_url: None,
        gw_pool: 8,
        gw_max_streams: 256,
        gw_tls_cert: None,
        gw_tls_key: None,
        gw_tls_ca: None,
        gw_tls_name: None,
        gw_insecure: false,
        gw_dataplane_reconcile: false,
        gw_reconcile: None,
        pty_reconcile: None,
        exec_stream_reconcile: None,
        net_egress_reconcile: None,
        expose_reconcile: None,
        expose_allow_public: false,
        store_contract: false,
        etcd: None,
        cluster_init: false,
        election_reconcile: false,
        node_reclaim_reconcile: false,
        cluster_reconcile: false,
        gw_cluster_reconcile: false,
        require_auth: false,
        apikey_create: false,
        org: None,
        project: None,
        scope: None,
        auth_reconcile: false,
        quota_set: false,
        max_sandboxes: 0,
        max_vcpus: 0,
        max_mem: 0,
        max_storage: 0,
        quota_reconcile: false,
        retention_reconcile: false,
        sched_reconcile: false,
        sched_overcommit: 1,
        log_sink: None,
}
}

/// 统计名字含 needle 的进程数（读 /proc/*/comm，避免依赖 pgrep）。
fn count_proc(needle: &str) -> usize {
    let mut n = 0;
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let comm = e.path().join("comm");
            if let Ok(s) = std::fs::read_to_string(&comm) {
                if s.trim().contains(needle) {
                    n += 1;
                }
            }
        }
    }
    n
}

/// --oci-pull 实现（W3）：classify → source_to_rootfs（拉取/加载→展平→bake）→ 复制到 --oci-out
/// → 单行 JSON。不 boot（boot 起 Python 的 M2-Q12 判据走 --build + --snap-load）。
fn oci_pull(cfg: &Config, from: &str) -> Result<(), String> {
    let source = oci::classify(from)?;
    if let oci::Source::Local(_) = source {
        return Err(format!("--oci-pull 需要 OCI 引用或 tarball（docker://… / docker-archive:…），得到本地文件: {from}"));
    }
    let res = oci::source_to_rootfs(&source, cfg.json)?;
    let out = cfg
        .oci_out
        .clone()
        .unwrap_or_else(|| PathBuf::from("build/oci-out/rootfs.ext4"));
    if let Some(p) = out.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("建 --oci-out 目录失败: {e}"))?;
    }
    std::fs::copy(&res.rootfs_path, &out).map_err(|e| format!("复制 ext4 到 --oci-out 失败: {e}"))?;
    if cfg.json {
        println!(
            r#"{{"metric":"oci_pull","source":"{}","source_digest":"{}","layers":{},"rootfs_bytes":{},"out":"{}","pass":true}}"#,
            json_escape(&res.source),
            res.source_digest,
            res.layers,
            res.rootfs_bytes,
            json_escape(&out.to_string_lossy())
        );
    } else {
        println!(
            "[oci] PASS：{} → {}（digest={} {} 层 {} 字节）",
            res.source,
            out.display(),
            res.source_digest,
            res.layers,
            res.rootfs_bytes
        );
    }
    Ok(())
}

/// 极简 JSON 字符串转义（反斜杠 + 双引号）——OCI 来源/路径进 JSON 输出用。
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// host 网络命名空间里名为 TAP_NAME 的设备数（应为 0——tap 只存在于沙箱 netns）。
fn count_host_tap() -> usize {
    std::fs::read_dir("/sys/class/net")
        .map(|it| {
            it.flatten()
                .filter(|e| e.file_name().to_string_lossy() == TAP_NAME)
                .count()
        })
        .unwrap_or(0)
}

/// M3 W1 store 契约对账（M3-Q1）：对 SqliteStore（in-memory + file）恒跑后端无关契约套件；
/// 若给 `--etcd <ep>` 且以 `--features cluster` 构建，则对 EtcdStore 跑**同一套**——证双实现语义等价。
fn run_store_contract(cfg: &Config) -> Result<(), String> {
    use sl_store::{contract, SqliteStore};

    let mem = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    contract::run_all(&mem)?;
    println!("[store] SqliteStore(in-memory) 契约 PASS");

    let path = std::env::temp_dir().join(format!("sl-store-contract-{}.db", std::process::id()));
    let p = path.to_string_lossy().to_string();
    {
        let file = SqliteStore::open(&p).map_err(|e| e.to_string())?;
        contract::run_all(&file)?;
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    println!("[store] SqliteStore(file) 契约 PASS");

    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            let etcd = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            contract::run_all(&etcd)?;
            println!("[store] EtcdStore({ep}) 契约 PASS");
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--etcd {ep} 需以 `--features cluster` 构建 sl-node（当前未启用该特性）"));
        }
    }
    Ok(())
}

/// M3-Q2 选主对账：双竞选者跑「单 leader + 续租 + resign failover + 无双主」，两后端同一套。
fn run_election_reconcile(cfg: &Config) -> Result<(), String> {
    use sl_store::election::Election;
    use sl_store::SqliteStore;

    // 断言脚本（对任意 Store 后端成立）。
    fn asserts(a: &mut Election, b: &mut Election) -> Result<(), String> {
        macro_rules! want {
            ($c:expr, $m:expr) => {
                if !$c {
                    return Err($m.into());
                }
            };
        }
        want!(a.try_campaign().map_err(|e| e.to_string())?, "A 应当选");
        want!(!b.try_campaign().map_err(|e| e.to_string())?, "B 应落败（A 持有）");
        want!(a.is_leader() && !b.is_leader(), "任一时刻至多一个 leader");
        want!(a.try_campaign().map_err(|e| e.to_string())?, "A 续租应仍为 leader");
        want!(!b.try_campaign().map_err(|e| e.to_string())?, "B 仍应落败");
        a.resign().map_err(|e| e.to_string())?;
        want!(!a.is_leader(), "A resign 后应非 leader");
        want!(b.try_campaign().map_err(|e| e.to_string())?, "A 让位后 B 应夺主");
        want!(!a.try_campaign().map_err(|e| e.to_string())?, "此时 A 应落败（B 持有）");
        want!(b.is_leader() && !a.is_leader(), "至多一个 leader（换 B）");
        b.resign().map_err(|e| e.to_string())?; // 清理
        Ok(())
    }

    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            use sl_store::etcd::EtcdStore;
            use sl_store::{election::LEADER_KEY, Store};
            // 起点干净：清掉可能残留的 leader 键。
            let cleaner = EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            let _ = cleaner.delete(LEADER_KEY);
            let mut a = Election::new(Box::new(EtcdStore::connect(ep).map_err(|e| e.to_string())?), "node-a", 30);
            let mut b = Election::new(Box::new(EtcdStore::connect(ep).map_err(|e| e.to_string())?), "node-b", 30);
            asserts(&mut a, &mut b)?;
            println!("[election] EtcdStore({ep}) 双竞选者：单 leader + resign failover + 无双主 PASS");
            return Ok(());
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--election-reconcile --etcd {ep} 需以 `--features cluster` 构建"));
        }
    }

    // 默认：SQLite 文件（两句柄共享同一文件 → 可测双竞选者）。
    let path = std::env::temp_dir().join(format!("sl-election-reconcile-{}.db", std::process::id()));
    let p = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&p);
    let r = {
        let mut a = Election::new(Box::new(SqliteStore::open(&p).map_err(|e| e.to_string())?), "node-a", 30);
        let mut b = Election::new(Box::new(SqliteStore::open(&p).map_err(|e| e.to_string())?), "node-b", 30);
        asserts(&mut a, &mut b)
    };
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    r?;
    println!("[election] SqliteStore(file) 双竞选者：单 leader + resign failover + 无双主 PASS");
    Ok(())
}

/// 打开 daemon 用的持久 store：`--etcd` → EtcdStore（cluster feature）；否则 SQLite（--store 或默认路径）。
fn open_store_for(cfg: &Config) -> Result<Box<dyn sl_store::Store>, String> {
    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            return Ok(Box::new(sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?));
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--etcd {ep} 需以 `--features cluster` 构建"));
        }
    }
    let path = cfg
        .store
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("build/templates/sl.db"));
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let p = path.to_str().ok_or("store 路径非 UTF-8")?;
    Ok(Box::new(sl_store::SqliteStore::open(p).map_err(|e| e.to_string())?))
}

/// M3 W7：设项目配额（--project + --max-*，0=不限）。
fn run_quota_set(cfg: &Config) -> Result<(), String> {
    use crate::quota::{set_limits, Limits};
    let project = cfg.project.as_deref().ok_or("--quota-set 需 --project <项目>")?;
    let store = open_store_for(cfg)?;
    let l = Limits { max_sandboxes: cfg.max_sandboxes, max_vcpus: cfg.max_vcpus, max_mem_mib: cfg.max_mem, max_storage_mib: cfg.max_storage };
    set_limits(store.as_ref(), project, l)?;
    println!(
        "项目 {project} 配额已设：max_sandboxes={} max_vcpus={} max_mem_mib={} max_storage_mib={}（0=不限）",
        l.max_sandboxes, l.max_vcpus, l.max_mem_mib, l.max_storage_mib
    );
    Ok(())
}

/// M3-Q7 保留期 + 版本钉住对账：过期 paused 快照 GC / 版本兼容矩阵（精确/N-1/不兼容）/ 存储配额，
/// 后端无关同一套（SQLite 临时文件；--etcd 则真 etcd）。
fn run_retention_reconcile(cfg: &Config) -> Result<(), String> {
    use crate::quota::{check, set_limits, set_size, Limits, QUOTA_EXCEEDED};
    use crate::retention::{check_compat, gc_expired, get_pin, set_pin, set_retention, Compat, Pin};
    use sl_store::{SqliteStore, Store};

    fn asserts(store: &dyn Store) -> Result<(), String> {
        macro_rules! want {
            ($c:expr, $m:expr) => {
                if !$c {
                    return Err($m.into());
                }
            };
        }
        for pfx in ["sandbox/", "quota/"] {
            for kv in store.list(pfx).map_err(|e| e.to_string())? {
                let _ = store.delete(&kv.key);
            }
        }
        let now = 2_000_000i64;

        // ① 版本钉往返 + 兼容矩阵（精确 / N-1 警告 / VMM 不符 / 内核越界）。
        let pin = Pin { template_version: "t1".into(), kernel_version: "6.6.10".into(), vmm_version: "1.7.0".into() };
        set_pin(store, "sb1", &pin, None).map_err(|e| e.to_string())?;
        want!(get_pin(store, "sb1").map_err(|e| e.to_string())?.as_ref() == Some(&pin), "版本钉往返不符");
        want!(check_compat(&pin, "6.6.10", "1.7.0", &[]) == Compat::Ok, "精确匹配应 Ok");
        want!(check_compat(&pin, "6.6.11", "1.7.0", &["6.6.10".into()]) == Compat::OldKernelWarn, "N-1 应警告");
        want!(matches!(check_compat(&pin, "6.6.10", "1.8.0", &[]), Compat::Incompatible(_)), "VMM 不符应拒");
        want!(matches!(check_compat(&pin, "6.6.11", "1.7.0", &[]), Compat::Incompatible(_)), "内核越界应拒");

        // ② 保留期 GC：过期 paused → 回收；未过期 paused / running 不碰。
        store.put("sandbox/exp/meta", b"{}", None).map_err(|e| e.to_string())?;
        store.put("sandbox/exp/state", b"paused", None).map_err(|e| e.to_string())?;
        set_retention(store, "exp", now - 1, None).map_err(|e| e.to_string())?;
        store.put("sandbox/keep/state", b"paused", None).map_err(|e| e.to_string())?;
        set_retention(store, "keep", now + 3600, None).map_err(|e| e.to_string())?;
        let gced = gc_expired(store, now).map_err(|e| e.to_string())?;
        want!(gced == vec!["exp"], "应只 GC 过期的 exp");
        want!(store.get("sandbox/exp/meta").map_err(|e| e.to_string())?.is_none(), "exp 应被 GC");
        want!(store.get("sandbox/keep/state").map_err(|e| e.to_string())?.is_some(), "未过期 keep 应留");

        // ③ 存储配额：记录 size + 超限 QUOTA_EXCEEDED。
        set_limits(store, "projA", Limits { max_storage_mib: 1024, ..Default::default() }).map_err(|e| e.to_string())?;
        store.put("sandbox/s1/meta", br#"{"vcpus":1,"mem_mib":128}"#, None).map_err(|e| e.to_string())?;
        store.put("sandbox/s1/project", b"projA", None).map_err(|e| e.to_string())?;
        set_size(store, "s1", 600, None).map_err(|e| e.to_string())?;
        want!(check(store, "projA", 0, 0, 400).is_ok(), "1000<=1024 应放行");
        want!(check(store, "projA", 0, 0, 500).unwrap_err().starts_with(QUOTA_EXCEEDED), "1100>1024 应超限");

        for pfx in ["sandbox/", "quota/"] {
            for kv in store.list(pfx).map_err(|e| e.to_string())? {
                let _ = store.delete(&kv.key);
            }
        }
        Ok(())
    }

    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            let store = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            asserts(&store)?;
            println!("[retention] EtcdStore({ep}) 保留期 GC + 版本兼容矩阵 + 存储配额 PASS");
            return Ok(());
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--retention-reconcile --etcd {ep} 需以 `--features cluster` 构建"));
        }
    }

    let path = std::env::temp_dir().join(format!("sl-retention-{}.db", std::process::id()));
    let p = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&p);
    let r = {
        let store = SqliteStore::open(&p).map_err(|e| e.to_string())?;
        asserts(&store)
    };
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    r?;
    println!("[retention] SqliteStore(file) 保留期 GC + 版本兼容矩阵 + 存储配额 PASS");
    Ok(())
}

/// M3-Q10 放置对账（M3 调度器）：**盘点 → 选点 → 落账 → 再盘点** 这个闭环在真 store 上成立。
///
/// 单测用手搓的 `NodeLoad` 验排序，验不到闭环——而闭环才是「调度器」与「随机挑一个」的区别：
/// 上一次放置必须被下一次**看见**，否则实例照样会堆在同一台。这里在真 store（SQLite / 真 etcd）
/// 上跑完整循环：写心跳键（带容量）→ place → 按结果写 meta + 归属键 → 重新 survey → 再 place。
fn run_sched_reconcile(cfg: &Config) -> Result<(), String> {
    use crate::sched::{place, survey, Capacity, Policy};
    use sl_store::{SqliteStore, Store};

    fn asserts(store: &dyn Store) -> Result<(), String> {
        macro_rules! want {
            ($c:expr, $m:expr) => {
                if !$c {
                    return Err($m.into());
                }
            };
        }
        for pfx in ["sandbox/", "node/"] {
            for kv in store.list(pfx).map_err(|e| e.to_string())? {
                let _ = store.delete(&kv.key);
            }
        }

        // 三个等大的节点（8 vCPU / 8 GiB），外加一个**不自报容量**的老节点。
        for id in ["sc-a", "sc-b", "sc-c"] {
            let cap = Capacity { addr: id.into(), cpus: 8, mem_mib: 8192 };
            sl_store::cluster::register_node(store, id, cap.to_json().as_bytes(), 3600)
                .map_err(|e| e.to_string())?;
        }
        sl_store::cluster::register_node(store, "sc-legacy", br#"{"addr":"old"}"#, 3600)
            .map_err(|e| e.to_string())?;

        // ① 闭环：连放 6 个 2c/2048M 的沙箱，每次都从 store 重新盘点。
        //    每台放得下 4 个（8192/2048），6 个应铺开而不是全堆在发起副本头上。
        let (vcpus, mem) = (2u64, 2048u64);
        let mut placed: Vec<String> = Vec::new();
        for i in 0..6 {
            let nodes = survey(store)?;
            let target = place(&nodes, vcpus, mem, "sc-a", Policy::default())
                .ok_or_else(|| format!("第 {i} 个沙箱无处可放（不该发生）"))?;
            let sid = format!("sc-s{i}");
            store
                .put(&format!("sandbox/{sid}/meta"), format!(r#"{{"vcpus":{vcpus},"mem_mib":{mem}}}"#).as_bytes(), None)
                .map_err(|e| e.to_string())?;
            store
                .put(&sl_store::cluster::sandbox_node_key(&sid), target.as_bytes(), None)
                .map_err(|e| e.to_string())?;
            placed.push(target);
        }
        let distinct: std::collections::HashSet<&String> = placed.iter().collect();
        want!(
            distinct.len() == 3,
            format!("6 个沙箱应铺到 3 个节点上，实得 {:?}（闭环没闭上？）", placed)
        );
        // 均衡到每台 2 个：任一台超过 3 个就说明上一次放置没被下一次看见。
        for id in ["sc-a", "sc-b", "sc-c"] {
            let n = placed.iter().filter(|p| p.as_str() == id).count();
            want!(n == 2, format!("{id} 应分到 2 个，实得 {n}（{placed:?}）"));
        }

        // ② 老节点（未自报容量）自始至终没被选中——读不到容量不等于容量无限。
        want!(!placed.iter().any(|p| p == "sc-legacy"), "未自报容量的节点不该被选中");

        // ③ 用量确实记在了正确的节点头上（survey 从真 store 读回来的账）。
        let nodes = survey(store)?;
        for id in ["sc-a", "sc-b", "sc-c"] {
            let n = nodes.iter().find(|n| n.id == id).ok_or_else(|| format!("盘点里缺 {id}"))?;
            want!(
                n.sandboxes == 2 && n.used_mem_mib == 4096 && n.used_vcpus == 4,
                format!("{id} 用量应为 2 台/4c/4096M，实得 {}/{}c/{}M", n.sandboxes, n.used_vcpus, n.used_mem_mib)
            );
        }

        // ④ 放满即拒：再要一个 8 GiB 的，三台都放不下 → None（调用方据此退回本地或报错，
        //    绝不能悄悄塞给一台其实满了的机器）。
        want!(place(&nodes, 1, 8192, "sc-a", Policy::default()).is_none(), "放不下时应返回 None");
        // 但显式超售就放得下——超售是部署方的选择，不是默认。
        want!(place(&nodes, 1, 8192, "sc-a", Policy { overcommit: 2 }).is_some(), "超售后应放得下");

        // ⑤ 节点失联 → 心跳键消失 → 立刻退出候选（无需任何额外通知）。
        let _ = store.delete(&sl_store::cluster::node_key("sc-b"));
        let nodes = survey(store)?;
        want!(!nodes.iter().any(|n| n.id == "sc-b"), "失联节点应从盘点里消失");
        want!(
            place(&nodes, 2, 512, "sc-a", Policy::default()).as_deref() != Some("sc-b"),
            "失联节点不该再被选中"
        );

        for pfx in ["sandbox/", "node/"] {
            for kv in store.list(pfx).map_err(|e| e.to_string())? {
                let _ = store.delete(&kv.key);
            }
        }
        Ok(())
    }

    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            let store = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            asserts(&store)?;
            println!("[sched] EtcdStore({ep}) 盘点→选点→落账→再盘点闭环 + 容量准入 + 失联退出 PASS");
            return Ok(());
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--sched-reconcile --etcd {ep} 需以 `--features cluster` 构建"));
        }
    }

    let path = std::env::temp_dir().join(format!("sl-sched-{}.db", std::process::id()));
    let p = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&p);
    let r = {
        let store = SqliteStore::open(&p).map_err(|e| e.to_string())?;
        asserts(&store)
    };
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{p}{suffix}"));
    }
    r?;
    println!("[sched] SqliteStore(file) 盘点→选点→落账→再盘点闭环 + 容量准入 + 失联退出 PASS");
    Ok(())
}

/// M3-Q4 配额+审计对账：超限 QUOTA_EXCEEDED / 删后可再建 / 审计 append-only 可查，后端无关同一套。
fn run_quota_reconcile(cfg: &Config) -> Result<(), String> {
    use crate::quota::{check, set_limits, Limits, QUOTA_EXCEEDED};
    use sl_store::{SqliteStore, Store};

    fn asserts(store: &dyn Store) -> Result<(), String> {
        macro_rules! want {
            ($c:expr, $m:expr) => {
                if !$c {
                    return Err($m.into());
                }
            };
        }
        for kv in store.list("sandbox/").map_err(|e| e.to_string())? {
            let _ = store.delete(&kv.key);
        }
        for kv in store.list("quota/").map_err(|e| e.to_string())? {
            let _ = store.delete(&kv.key);
        }
        for kv in store.list("audit/").map_err(|e| e.to_string())? {
            let _ = store.delete(&kv.key);
        }
        // 造沙箱记录（meta+project）辅助。
        let put_sb = |id: &str, proj: &str, vcpu: u64, mem: u64| -> Result<(), String> {
            let meta = format!(r#"{{"id":"{id}","vcpus":{vcpu},"mem_mib":{mem}}}"#);
            store.put(&format!("sandbox/{id}/meta"), meta.as_bytes(), None).map_err(|e| e.to_string())?;
            store.put(&format!("sandbox/{id}/project"), proj.as_bytes(), None).map_err(|e| e.to_string())?;
            Ok(())
        };

        // 配额 max_sandboxes=2。
        set_limits(store, "projA", Limits { max_sandboxes: 2, ..Default::default() }).map_err(|e| e.to_string())?;
        want!(check(store, "projA", 1, 128, 0).is_ok(), "空项目应可建");
        put_sb("s1", "projA", 1, 128)?;
        put_sb("s2", "projA", 1, 128)?;
        // 已达上限：再建 → QUOTA_EXCEEDED。
        let e = check(store, "projA", 1, 128, 0).unwrap_err();
        want!(e.starts_with(QUOTA_EXCEEDED), "超限应 QUOTA_EXCEEDED");
        // 删一个 → 可再建（用量实时算）。
        for k in ["sandbox/s2/meta", "sandbox/s2/project"] {
            store.delete(k).map_err(|e| e.to_string())?;
        }
        want!(check(store, "projA", 1, 128, 0).is_ok(), "删后应可再建");
        // 其它项目不受 projA 配额影响。
        want!(check(store, "projB", 100, 100_000, 0).is_ok(), "projB 未设配额应不限");

        // 审计 append-only 可查。
        crate::audit::record(store, "projA", "create_sandbox", "s1", 201).map_err(|e| e.to_string())?;
        crate::audit::record(store, "projA", "delete_sandbox", "s2", 204).map_err(|e| e.to_string())?;
        let entries = crate::audit::list(store).map_err(|e| e.to_string())?;
        want!(entries.len() == 2, "应两条审计");
        want!(entries[0].contains("create_sandbox") && entries[1].contains("delete_sandbox"), "审计有序");

        for pfx in ["sandbox/", "quota/", "audit/"] {
            for kv in store.list(pfx).map_err(|e| e.to_string())? {
                let _ = store.delete(&kv.key);
            }
        }
        Ok(())
    }

    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            let store = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            asserts(&store)?;
            println!("[quota] EtcdStore({ep}) 配额+审计：超限拒 / 删后可建 / 项目隔离 / 审计 append 可查 PASS");
            return Ok(());
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--quota-reconcile --etcd {ep} 需以 `--features cluster` 构建"));
        }
    }

    let path = std::env::temp_dir().join(format!("sl-quota-{}.db", std::process::id()));
    let p = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&p);
    let r = {
        let store = SqliteStore::open(&p).map_err(|e| e.to_string())?;
        asserts(&store)
    };
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    r?;
    println!("[quota] SqliteStore(file) 配额+审计：超限拒 / 删后可建 / 项目隔离 / 审计 append 可查 PASS");
    Ok(())
}

/// M3 W6：创建 API Key（--org/--project/--scope），打印明文 token（仅此一次）。
fn run_apikey_create(cfg: &Config) -> Result<(), String> {
    use crate::auth::{create_key, Scope};
    let org = cfg.org.as_deref().ok_or("--apikey-create 需 --org <组织>")?;
    let project = cfg.project.as_deref().ok_or("--apikey-create 需 --project <项目>")?;
    let scope_s = cfg.scope.as_deref().unwrap_or("readwrite");
    let scope = Scope::from_str(scope_s).ok_or("--scope 取值 readonly|readwrite|build")?;
    let store = open_store_for(cfg)?;
    let token = create_key(store.as_ref(), org, project, scope)?;
    println!("API Key 已创建（token 仅此一次显示，请妥善保存）：");
    println!("  org={org}  project={project}  scope={scope_s}");
    println!("  token={token}");
    println!("用法：curl -H 'Authorization: Bearer {token}' http://<daemon-addr>/v1/sandboxes");
    Ok(())
}

/// M3-Q4 鉴权对账：key 有效性 + 作用域层级（只读/读写/构建）+ 项目归属，后端无关同一套。
fn run_auth_reconcile(cfg: &Config) -> Result<(), String> {
    use crate::auth::{create_key, lookup, Op, Scope};
    use sl_store::{SqliteStore, Store};

    fn asserts(store: &dyn Store) -> Result<(), String> {
        macro_rules! want {
            ($c:expr, $m:expr) => {
                if !$c {
                    return Err($m.into());
                }
            };
        }
        for kv in store.list("apikey/").map_err(|e| e.to_string())? {
            let _ = store.delete(&kv.key);
        }
        let ro = create_key(store, "acme", "projA", Scope::ReadOnly).map_err(|e| e.to_string())?;
        let rw = create_key(store, "acme", "projA", Scope::ReadWrite).map_err(|e| e.to_string())?;
        let bd = create_key(store, "acme", "projA", Scope::Build).map_err(|e| e.to_string())?;
        let rwb = create_key(store, "acme", "projB", Scope::ReadWrite).map_err(|e| e.to_string())?;

        // 有效 / 无效 key。
        want!(lookup(store, &ro).map_err(|e| e.to_string())?.is_some(), "有效 key 应查到");
        want!(lookup(store, "bad-token").map_err(|e| e.to_string())?.is_none(), "无效 key 应无记录");

        // 作用域层级：readonly 不能写；readwrite 能写不能构建；build 全能。
        let ro_r = lookup(store, &ro).map_err(|e| e.to_string())?.unwrap();
        want!(ro_r.scope.allows(Op::Read) && !ro_r.scope.allows(Op::Write), "readonly 应只读");
        let rw_r = lookup(store, &rw).map_err(|e| e.to_string())?.unwrap();
        want!(rw_r.scope.allows(Op::Write) && !rw_r.scope.allows(Op::Build), "readwrite 不应允许 build");
        let bd_r = lookup(store, &bd).map_err(|e| e.to_string())?.unwrap();
        want!(bd_r.scope.allows(Op::Build) && bd_r.scope.allows(Op::Write), "build 应全能");

        // 项目隔离（记录层面）：不同项目的 key 项目字段不同。
        let rwb_r = lookup(store, &rwb).map_err(|e| e.to_string())?.unwrap();
        want!(rw_r.project == "projA" && rwb_r.project == "projB", "项目归属应各自独立");
        want!(rw_r.project != rwb_r.project, "跨项目 key 项目应不同");

        for kv in store.list("apikey/").map_err(|e| e.to_string())? {
            let _ = store.delete(&kv.key);
        }
        Ok(())
    }

    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            let store = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            asserts(&store)?;
            println!("[auth] EtcdStore({ep}) 鉴权：key 有效性 + 作用域层级 + 项目隔离 PASS");
            return Ok(());
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--auth-reconcile --etcd {ep} 需以 `--features cluster` 构建"));
        }
    }

    let path = std::env::temp_dir().join(format!("sl-auth-{}.db", std::process::id()));
    let p = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&p);
    let r = {
        let store = SqliteStore::open(&p).map_err(|e| e.to_string())?;
        asserts(&store)
    };
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    r?;
    println!("[auth] SqliteStore(file) 鉴权：key 有效性 + 作用域层级 + 项目隔离 PASS");
    Ok(())
}

/// M3 W5 网关拆副本对账：共享 secret 使 A 签发 B 可验（无状态验签）+ 一次性跨副本 + 篡改/过期拒。
/// `--gw-dataplane-reconcile`：M3 W5 余项对账（M3-Q3）——**独立网关 + 节点主动外拨 + 无粘滞中继**。
///
/// 起一个真网关（`gw_serve`，临时端口）+ 两个真节点侧外拨代理（`start_node_agent`，即生产同一段
/// 代码），在 store 里写沙箱→节点归属键，然后以真 HTTP 客户端打网关，逐条验：
///
/// | # | 断言 | 对应 M3-Q3 判据 |
/// | - | --- | --- |
/// | ① | s1(属 A)→A、s2(属 B)→B | 按 etcd 映射路由 |
/// | ② | 同一网关交替服务 s1/s2/s1 均正确 | **任一副本服务任一沙箱、无会话粘滞** |
/// | ③ | 同一张票二次使用 → 403 | 一次性（跨副本，W5 已有，此处证经中继仍成立） |
/// | ④ | 篡改 sig → 403 | ticket 语义与 M2 一致 |
/// | ⑤ | 无归属键沙箱 → 404 | 不把请求转给不确定的节点 |
/// | ⑥ | 归属节点未接入 → 503 | 失联节点不静默挂死 |
/// | ⑦ | 分块响应**逐块**到达（非整体缓冲） | 流式 exec / PTY 依赖的全双工中继 |
///
/// mTLS 的活证（无证书客户端被握手拒）在 `scripts/verify-gw-dataplane.sh`——需 openssl 造证书，
/// 不适合进程内对账。
/// `--snapcrypt-reconcile`：M3 W9 对账（M3-Q6，ADR-15）——**快照信封加密**。
///
/// 走的是 pause/resume 真正调用的那两个函数（`fcbackend::seal_snapshot` / `unseal_snapshot`）
/// 与真正的租户 KEK 解析路径，只是把 FC 落盘的 `vmstate`/`mem` 换成同名的构造文件——
/// 加解密与密钥层级这一层不需要 KVM 就能取到证据。
///
/// | # | 断言 | 对应 M3-Q6 判据 |
/// | - | --- | --- |
/// | ① | 密封后明文 `vmstate`/`mem` 消失、`.enc` 出现且解回原文 | 落盘即密文 |
/// | ② | `.enc` 里搜不到明文特征串 | 确实加密 |
/// | ③ | 控制面 `kek/<project>` 存的是**密文**，搜不到明文 KEK | 不持久化明文密钥 |
/// | ④ | 快照头里存的是**被包裹的** DEK，搜不到明文 DEK | **节点不持久化明文 DEK** |
/// | ⑤ | 改一个密文字节 → 解封失败，且不留半成品明文 | **篡改即拒恢复** |
/// | ⑥ | 项目 A 的快照用项目 B 的 KEK 解不开 | 租户隔离 |
/// | ⑦ | 同一项目重复取 KEK 得同一把（CAS 收敛） | 跨副本一致，否则互相解不开 |
/// | ⑧ | 换一把根密钥 → KEK 解不开 | 信封层级成立 |
/// | ⑨ | 只解第 i 块与整解的对应切片一致 | 4MiB 分块**支持随机读**（懒加载前提） |
///
/// 端到端（真 FC pause → 密文落盘 → resume）依赖 KVM，随 `--q5-reconcile` 一类在 KVM 机器上取证。
fn run_snapcrypt_reconcile(cfg: &Config) -> Result<(), String> {
    use crate::fcbackend::{seal_snapshot, unseal_snapshot};
    use crate::snapcrypt::{decrypt_chunk, FileKms, Key, Kms, SnapKey, CHUNK_SIZE};
    use std::collections::BTreeMap;
    use sl_store::Store;

    macro_rules! want {
        ($c:expr, $m:expr) => {
            if !$c {
                return Err($m.into());
            }
        };
    }

    let work = std::env::temp_dir().join(format!("sl-snapcrypt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("建工作目录失败: {e}"))?;
    let cleanup = |w: &std::path::Path| {
        let _ = std::fs::remove_dir_all(w);
    };

    let run = (|| -> Result<String, String> {
        // —— 根密钥（文件 KMS）——
        let root_path = work.join("root.key");
        FileKms::init(&root_path)?;
        want!(
            FileKms::init(&root_path).is_err(),
            "重复 init 应被拒（覆盖根密钥 = 既有快照永久不可解）"
        );
        // 权限门：0644 的根密钥必须被拒（宁可起不来，也不要静默用一把人人可读的根密钥）。
        {
            use std::os::unix::fs::PermissionsExt;
            let loose = work.join("loose.key");
            std::fs::write(&loose, [0u8; 32]).map_err(|e| e.to_string())?;
            std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())?;
            want!(FileKms::open(&loose).is_err(), "0644 的根密钥应被拒绝");
        }
        let kms = FileKms::open(&root_path)?;

        // —— 控制面：租户 KEK 以密文存 `kek/<project>` ——
        let store: Box<dyn Store> = open_dp_store(&cfg.etcd, &work.join("store.db").to_string_lossy())?;
        for p in ["proj-a", "proj-b"] {
            let _ = store.delete(&format!("kek/{p}"));
        }
        let mut keks: BTreeMap<String, Key> = BTreeMap::new();
        for p in ["proj-a", "proj-b"] {
            let fresh = Key::random();
            let wrapped = kms.wrap_kek(&fresh)?;
            store.put(&format!("kek/{p}"), &wrapped, None).map_err(|e| e.to_string())?;
            keks.insert(p.to_string(), kms.unwrap_kek(&wrapped)?);
        }
        // ③ 控制面存的是密文
        for p in ["proj-a", "proj-b"] {
            let kv = store.get(&format!("kek/{p}")).map_err(|e| e.to_string())?.ok_or("KEK 未写入")?;
            let plain = keks.get(p).unwrap().expose_for_test();
            want!(
                !kv.value.windows(plain.len()).any(|w| w == plain),
                format!("控制面 kek/{p} 里出现了明文 KEK")
            );
        }
        // ⑦ 重复解裹得同一把（CAS 收敛后跨副本必须一致，否则互相解不开对方的快照）
        {
            let kv = store.get("kek/proj-a").map_err(|e| e.to_string())?.unwrap();
            let again = kms.unwrap_kek(&kv.value)?;
            want!(
                again.expose_for_test() == keks.get("proj-a").unwrap().expose_for_test(),
                "同一 KEK 密文两次解裹应得同一把"
            );
        }
        // ⑧ 换根密钥 → 解不开
        {
            let other_root = work.join("root2.key");
            FileKms::init(&other_root)?;
            let kms2 = FileKms::open(&other_root)?;
            let kv = store.get("kek/proj-a").map_err(|e| e.to_string())?.unwrap();
            want!(kms2.unwrap_kek(&kv.value).is_err(), "换根密钥不应能解出 KEK");
        }

        let key_a = SnapKey { kek: kms.unwrap_kek(&store.get("kek/proj-a").map_err(|e| e.to_string())?.unwrap().value)?, kek_id: "proj-a".into() };
        let key_b = SnapKey { kek: kms.unwrap_kek(&store.get("kek/proj-b").map_err(|e| e.to_string())?.unwrap().value)?, kek_id: "proj-b".into() };

        // —— 实例目录：造 vmstate/mem（mem 跨 2 块，逼出分块路径）——
        let inst = work.join("inst");
        std::fs::create_dir_all(&inst).map_err(|e| e.to_string())?;
        let needle = b"SECRET-IN-GUEST-MEMORY-4f3a9c";
        let mut mem = vec![0u8; CHUNK_SIZE as usize + 4096];
        for (i, b) in mem.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        mem[CHUNK_SIZE as usize - 10..CHUNK_SIZE as usize - 10 + needle.len()].copy_from_slice(needle);
        let vmstate = b"vmstate-blob".repeat(100);
        std::fs::write(inst.join("mem"), &mem).map_err(|e| e.to_string())?;
        std::fs::write(inst.join("vmstate"), &vmstate).map_err(|e| e.to_string())?;

        // ① 密封：明文消失、密文出现
        seal_snapshot(&inst, &key_a)?;
        want!(!inst.join("mem").exists(), "密封后明文 mem 仍在");
        want!(!inst.join("vmstate").exists(), "密封后明文 vmstate 仍在");
        want!(inst.join("mem.enc").exists() && inst.join("vmstate.enc").exists(), "密文未生成");

        // ② 密文里搜不到明文特征串
        let ct = std::fs::read(inst.join("mem.enc")).map_err(|e| e.to_string())?;
        want!(!ct.windows(needle.len()).any(|w| w == needle), "密文中出现了明文 guest 内存片段");

        // ④ 节点不持久化明文 DEK：快照头里是被 KEK 包裹的 DEK
        {
            let mut f = std::fs::File::open(inst.join("mem.enc")).map_err(|e| e.to_string())?;
            let hdr = crate::snapcrypt::Header::read_from(&mut f)?;
            let dek = hdr.unwrap_dek(&key_a.kek)?;
            let raw = dek.expose_for_test();
            want!(!ct.windows(raw.len()).any(|w| w == raw), "快照文件里出现了明文 DEK");
            want!(hdr.kek_id == "proj-a", "头部 kek_id 应记录租户");
        }

        // ⑨ 随机读：只解第 1 块，与原文对应切片一致
        {
            let c1 = decrypt_chunk(&inst.join("mem.enc"), &key_a.kek, 1)?;
            want!(c1 == mem[CHUNK_SIZE as usize..], "随机读第 1 块与原文不一致");
        }

        // ⑥ 租户隔离：B 的 KEK 解不开 A 的快照
        want!(unseal_snapshot(&inst, &key_b).is_err(), "别的项目的 KEK 不应能解开本项目快照");
        // 失败不得留下半成品明文
        want!(!inst.join("mem").exists(), "跨租户解封失败后不得留下明文 mem");

        // ① 解封往返：内容逐字节一致
        unseal_snapshot(&inst, &key_a)?;
        want!(std::fs::read(inst.join("mem")).map_err(|e| e.to_string())? == mem, "解封后 mem 与原文不一致");
        want!(
            std::fs::read(inst.join("vmstate")).map_err(|e| e.to_string())? == vmstate,
            "解封后 vmstate 与原文不一致"
        );

        // ⑤ 篡改即拒：改密文一个字节 → 解封失败且不留半成品
        {
            let _ = std::fs::remove_file(inst.join("mem"));
            let p = inst.join("mem.enc");
            let mut b = std::fs::read(&p).map_err(|e| e.to_string())?;
            let i = b.len() - 7;
            b[i] ^= 0xff;
            std::fs::write(&p, &b).map_err(|e| e.to_string())?;
            let err = unseal_snapshot(&inst, &key_a).unwrap_err();
            want!(err.contains("AEAD 校验失败"), format!("篡改应报 AEAD 失败，实得: {err}"));
            want!(!inst.join("mem").exists(), "篡改用例不得留下半解密的明文");
        }

        for p in ["proj-a", "proj-b"] {
            let _ = store.delete(&format!("kek/{p}"));
        }
        Ok(cfg.etcd.clone().unwrap_or_else(|| "SQLite(临时)".into()))
    })();

    cleanup(&work);
    let backend = run?;
    println!(
        "[snapcrypt] {backend}：密封/解封往返 + 密文无明文 + 控制面无明文 KEK + 节点无明文 DEK + \
篡改即拒 + 租户隔离 + KEK 收敛 + 换根密钥拒 + 分块随机读 PASS"
    );
    Ok(())
}

fn run_gw_dataplane_reconcile(cfg: &Config) -> Result<(), String> {
    use crate::dataplane::{gw_serve, start_node_agent, AgentCfg, GwCfg};
    use crate::gateway::{Action, Gateway};
    use sl_store::Store;
    use std::io::Write;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    macro_rules! want {
        ($c:expr, $m:expr) => {
            if !$c {
                return Err($m.into());
            }
        };
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);

    // —— store：默认 SQLite 临时文件；--etcd 则真 etcd（同一套断言跑两种后端）——
    let sqlite_path = std::env::temp_dir().join(format!("sl-gwdp-{}.db", std::process::id()));
    let open: Box<dyn Fn() -> Result<Box<dyn Store>, String> + Send + Sync> = match &cfg.etcd {
        Some(ep) => {
            #[cfg(feature = "cluster")]
            {
                let ep = ep.clone();
                Box::new(move || {
                    Ok(Box::new(sl_store::etcd::EtcdStore::connect(&ep).map_err(|e| e.to_string())?)
                        as Box<dyn Store>)
                })
            }
            #[cfg(not(feature = "cluster"))]
            {
                return Err(format!("--gw-dataplane-reconcile --etcd {ep} 需以 `--features cluster` 构建"));
            }
        }
        None => {
            let p = sqlite_path.to_string_lossy().to_string();
            Box::new(move || {
                Ok(Box::new(sl_store::SqliteStore::open(&p).map_err(|e| e.to_string())?)
                    as Box<dyn Store>)
            })
        }
    };

    // 起点干净：清 ticket secret / 残留 nonce / 本对账用的归属键。
    let admin = open()?;
    let _ = admin.delete("cluster/gw_secret");
    for kv in admin.list("gw/nonce/").map_err(|e| e.to_string())? {
        let _ = admin.delete(&kv.key);
    }
    for sid in ["dp-s1", "dp-s2", "dp-orphan"] {
        let _ = admin.delete(&sl_store::cluster::sandbox_node_key(sid));
    }

    // —— mTLS：给了 --gw-tls-* 就让①–⑦**整套跑在 mTLS 之上**（不是另起一套用例）；
    //    只给 --gw-insecure 则明文。默认两者都没给 → 报错，绝不静默降级。——
    let tls = cfg.gw_tls_opts()?;
    let secure = tls.is_some();

    // —— 起网关（临时端口）——
    let (tx, rx) = mpsc::channel::<(SocketAddr, SocketAddr)>();
    let tls_gw = tls.clone();
    let open_for_gw: Box<dyn Fn() -> Result<Box<dyn Store>, String> + Send + Sync> = {
        let e = cfg.etcd.clone();
        let p = sqlite_path.to_string_lossy().to_string();
        Box::new(move || open_dp_store(&e, &p))
    };
    std::thread::spawn(move || {
        let _ = gw_serve(GwCfg {
            bind: "127.0.0.1:0".into(),
            node_bind: "127.0.0.1:0".into(),
            open_store: open_for_gw,
            tls: tls_gw,
            take_wait: Duration::from_millis(1500),
            max_idle: Duration::from_secs(300),
            on_ready: Some(Box::new(move |c, n| {
                let _ = tx.send((c, n));
            })),
        });
    });
    let (client_addr, node_addr) =
        rx.recv_timeout(Duration::from_secs(10)).map_err(|_| "网关未在 10s 内就绪".to_string())?;

    // —— 起两个节点侧外拨代理（生产同一段代码）。stub 处理器回一个能认出自己是谁的响应 ——
    for node in ["dp-node-a", "dp-node-b"] {
        let who = node.to_string();
        start_node_agent(
            AgentCfg {
                gw_addr: node_addr.to_string(),
                node_id: who.clone(),
                pool: 4,
                max_streams: 64,
                tls: tls.clone(),
            },
            Arc::new(move |ticket, ch| {
                let mut ch = ch;
                let (_m, _p, _k, _b) = match crate::api::read_request(&mut ch) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                // 分块 + 间隔写：⑦ 要据此判定中继是**逐块**转发而非整体缓冲。
                // 回显里带上 **action/port**：⑨ 据此判定控制面票带着「哪个操作、哪个端口」
                // 原样到了 owning 节点（两者都在签名里）。
                let head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n";
                let _ = ch.write_all(head.as_bytes());
                let _ = ch.flush();
                for i in 0..3 {
                    let _ = ch.write_all(
                        format!("{who}:{}:{}:{}:{i}\n", ticket.sid, ticket.action.as_str(), ticket.port)
                            .as_bytes(),
                    );
                    let _ = ch.flush();
                    if i < 2 {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
                ch.0.shutdown_write();
            }),
        )?;
    }

    // 归属键：s1→A、s2→B、orphan→未接入的 C。
    admin
        .put(&sl_store::cluster::sandbox_node_key("dp-s1"), b"dp-node-a", None)
        .map_err(|e| e.to_string())?;
    admin
        .put(&sl_store::cluster::sandbox_node_key("dp-s2"), b"dp-node-b", None)
        .map_err(|e| e.to_string())?;
    admin
        .put(&sl_store::cluster::sandbox_node_key("dp-orphan"), b"dp-node-c", None)
        .map_err(|e| e.to_string())?;

    // 等节点把连接拨满（外拨是异步的）。
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if http_get(&client_addr, "/gw/exec?sid=dp-s1&action=exec&port=0&exp=0&nonce=x&sig=y")
            .map(|(c, _, _)| c == 403)
            .unwrap_or(false)
        {
            break; // 网关在应答了（403=验签拒，说明客户端面已通）
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 本对账自己签票：与网关共享同一 store → 同一 secret（W5 的跨副本验签）。
    let signer = Gateway::new_shared(format!("http://{client_addr}"), open()?)?;
    let rel = |url: String| -> String {
        url.split_once("/gw/").map(|(_, r)| format!("/gw/{r}")).unwrap_or_default()
    };

    // ① 按归属路由 + ② 无粘滞：同一网关交替服务两节点的沙箱，各归各位。
    for (sid, want_node) in [("dp-s1", "dp-node-a"), ("dp-s2", "dp-node-b"), ("dp-s1", "dp-node-a")] {
        let (code, body, _) = http_get(&client_addr, &rel(signer.mint(sid, Action::Exec, 0, 60, now)))?;
        want!(code == 200, format!("{sid} 应 200，实得 {code}: {body}"));
        want!(
            body.contains(&format!("{want_node}:{sid}:")),
            format!("{sid} 应由 {want_node} 服务，实得: {body}")
        );
    }

    // ③ 一次性：同一张票二次使用被拒。
    let once = rel(signer.mint("dp-s1", Action::Exec, 0, 60, now));
    let (c1, _, _) = http_get(&client_addr, &once)?;
    want!(c1 == 200, format!("首次使用应 200，实得 {c1}"));
    let (c2, _, _) = http_get(&client_addr, &once)?;
    want!(c2 == 403, format!("二次使用应 403（一次性），实得 {c2}"));

    // ④ 篡改 sig → 403。
    let tampered = {
        let u = rel(signer.mint("dp-s1", Action::Exec, 0, 60, now));
        let (l, _) = u.rsplit_once("&sig=").ok_or("ticket 无 sig")?;
        format!("{l}&sig=deadbeef")
    };
    let (c3, _, _) = http_get(&client_addr, &tampered)?;
    want!(c3 == 403, format!("篡改 sig 应 403，实得 {c3}"));

    // ⑤ 无归属键 → 404（不猜节点）。
    let (c4, _, _) = http_get(&client_addr, &rel(signer.mint("dp-nosuch", Action::Exec, 0, 60, now)))?;
    want!(c4 == 404, format!("未知沙箱应 404，实得 {c4}"));

    // ⑥ 归属节点未接入 → 503（有界等待后明确失败，不挂死）。
    let t0 = Instant::now();
    let (c5, _, _) = http_get(&client_addr, &rel(signer.mint("dp-orphan", Action::Exec, 0, 60, now)))?;
    want!(c5 == 503, format!("未接入节点应 503，实得 {c5}"));
    want!(t0.elapsed() < Duration::from_secs(5), "未接入节点应有界失败（≤5s）");

    // ⑦ 全双工：三块间隔 200ms 写出 → 客户端应**逐块**收到（首块远早于末块），证明未被整体缓冲。
    let (code, body, spans) = http_get(&client_addr, &rel(signer.mint("dp-s2", Action::Exec, 0, 60, now)))?;
    want!(code == 200, format!("流式用例应 200，实得 {code}"));
    want!(body.matches("dp-node-b:dp-s2:").count() == 3, format!("应收齐 3 块，实得: {body}"));
    want!(
        spans >= Duration::from_millis(250),
        format!("首末块间隔应 ≥250ms（逐块中继），实得 {:?}——疑似被整体缓冲", spans)
    );

    // ⑧ mTLS（FR-7.1，M3 W6 余项）：**明文**连节点接入端口 → 握手不成立、不得进池。
    //    以「冒充 dp-node-c 的明文连接」验证：若它进了池，dp-orphan 就不再是 503。
    if secure {
        if let Ok(mut raw) = TcpStream::connect(node_addr) {
            let _ = raw.write_all(format!("{} data dp-node-c\n", crate::dataplane::PROTO).as_bytes());
            let _ = raw.flush();
        }
        std::thread::sleep(Duration::from_millis(300));
        let (c6, _, _) = http_get(&client_addr, &rel(signer.mint("dp-orphan", Action::Exec, 0, 60, now)))?;
        want!(
            c6 == 503,
            format!("明文连接不得被 mTLS 接入端口收编（dp-orphan 应仍 503），实得 {c6}")
        );
    }

    // ⑨ **控制面跨节点**（M3 W4 余项）：pause/resume/fork/destroy/keepalive/expose/unexpose/
    //    exposes 八条同样按归属路由，且**动作与端口是签名里的那个**原样抵达 owning 节点。
    //    此前这些路由压根不转发——落到收请求的副本自己的 `live` 表上，一律 404。
    for (action, port) in [
        (Action::Pause, 0),
        (Action::Resume, 0),
        (Action::Fork, 0),
        (Action::Destroy, 0),
        (Action::Keepalive, 0),
        (Action::Expose, 0),
        (Action::Unexpose, 8080),
        (Action::Exposes, 0),
    ] {
        let name = action.as_str();
        let (code, body, _) =
            http_get(&client_addr, &rel(signer.mint("dp-s1", action, port, 60, now)))?;
        want!(code == 200, format!("控制面 {name} 应 200，实得 {code}: {body}"));
        want!(
            body.contains(&format!("dp-node-a:dp-s1:{name}:{port}:")),
            format!("控制面 {name} 应带 (action={name}, port={port}) 抵达 dp-node-a，实得: {body}")
        );
    }

    // ⑩ **动作不可替换**：拿一张 pause 票改写 action=destroy → 签名覆盖 action，403。
    //    这是「每个操作各占一个动作」而非「一个笼统 ctl 动作 + 未签名路径」的理由。
    let swapped = {
        let u = rel(signer.mint("dp-s1", Action::Pause, 0, 60, now));
        u.replace("action=pause", "action=destroy")
    };
    let (c7, _, _) = http_get(&client_addr, &swapped)?;
    want!(c7 == 403, format!("pause 票改写成 destroy 应 403，实得 {c7}"));

    // ⑪ **创建票直投节点**（M3 调度器）：创建时还没有沙箱，票的 sid 装 `node:<id>`，
    //    网关据此直接路由，**不查归属键**。这里刻意用一个从未写过归属键的 id 来证明这点。
    for want_node in ["dp-node-b", "dp-node-a"] {
        let sid = format!("{}{want_node}", crate::gateway::NODE_TARGET_PREFIX);
        let (code, body, _) = http_get(&client_addr, &rel(signer.mint(&sid, Action::Create, 0, 60, now)))?;
        want!(code == 200, format!("创建票投 {want_node} 应 200，实得 {code}: {body}"));
        want!(
            body.contains(&format!("{want_node}:{sid}:create:0:")),
            format!("创建票应直达 {want_node}（且不经归属键），实得: {body}")
        );
    }
    // 目标节点未接入 → 503（与沙箱路径同样有界失败，不挂死、也不悄悄换一台建）。
    let (c8, _, _) = http_get(
        &client_addr,
        &rel(signer.mint(&format!("{}dp-node-c", crate::gateway::NODE_TARGET_PREFIX), Action::Create, 0, 60, now)),
    )?;
    want!(c8 == 503, format!("创建票投未接入节点应 503，实得 {c8}"));

    // 收尾清理。
    for sid in ["dp-s1", "dp-s2", "dp-orphan"] {
        let _ = admin.delete(&sl_store::cluster::sandbox_node_key(sid));
    }
    let _ = admin.delete("cluster/gw_secret");
    for kv in admin.list("gw/nonce/").map_err(|e| e.to_string())? {
        let _ = admin.delete(&kv.key);
    }
    if cfg.etcd.is_none() {
        let _ = std::fs::remove_file(&sqlite_path);
    }

    let backend = cfg.etcd.clone().unwrap_or_else(|| "SQLite(临时)".into());
    let transport = if secure { "mTLS" } else { "明文" };
    println!(
        "[gw-dataplane] {backend} / {transport}：按归属路由 + 无粘滞 + 一次性 + 篡改拒 + 未知 404 + \
未接入 503 + 逐块全双工 + 控制面八动作按归属路由 + 动作不可替换 + 创建票直投节点{} PASS",
        if secure { " + 明文连接被拒" } else { "" }
    );
    Ok(())
}

/// 对账用 store 工厂（`--etcd` → EtcdStore；否则 SQLite 路径）。
fn open_dp_store(etcd: &Option<String>, sqlite: &str) -> Result<Box<dyn sl_store::Store>, String> {
    match etcd {
        Some(_ep) => {
            #[cfg(feature = "cluster")]
            {
                Ok(Box::new(sl_store::etcd::EtcdStore::connect(_ep).map_err(|e| e.to_string())?))
            }
            #[cfg(not(feature = "cluster"))]
            {
                Err("需以 `--features cluster` 构建".into())
            }
        }
        None => Ok(Box::new(
            sl_store::SqliteStore::open(sqlite).map_err(|e| e.to_string())?,
        )),
    }
}

/// 极简 HTTP GET 客户端（对账用）：返回 (状态码, 响应体, 首块到末块的间隔)。
///
/// 记录**首块与末块的到达间隔**是 ⑦ 的关键——中继若把响应整体缓冲再吐，这个间隔会塌成 ~0。
fn http_get(addr: &std::net::SocketAddr, path: &str) -> Result<(u16, String, std::time::Duration), String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).map_err(|e| format!("连网关失败: {e}"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(15))).ok();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| format!("写请求失败: {e}"))?;
    s.flush().ok();
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    let (mut first, mut last) = (None, std::time::Instant::now());
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let t = std::time::Instant::now();
                if first.is_none() {
                    first = Some(t);
                }
                last = t;
                raw.extend_from_slice(&buf[..n]);
            }
            Err(e) => return Err(format!("读响应失败: {e}")),
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let code: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("响应无状态码: {text}"))?;
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    let span = first.map(|f| last.duration_since(f)).unwrap_or_default();
    Ok((code, body, span))
}

fn run_gw_cluster_reconcile(cfg: &Config) -> Result<(), String> {
    use crate::gateway::{parse_query, Action, Gateway};
    use sl_store::{SqliteStore, Store};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);

    // 两副本共享同一后端：各建一个 Gateway（new_shared 从 store 收敛同一 secret）。
    fn asserts(sa: Box<dyn Store>, sb: Box<dyn Store>, cleaner: &dyn Store, now: i64) -> Result<(), String> {
        macro_rules! want {
            ($c:expr, $m:expr) => {
                if !$c {
                    return Err($m.into());
                }
            };
        }
        // 起点干净：清 gw_secret + 残留 nonce。
        let _ = cleaner.delete("cluster/gw_secret");
        for kv in cleaner.list("gw/nonce/").map_err(|e| e.to_string())? {
            let _ = cleaner.delete(&kv.key);
        }

        let gwa = Gateway::new_shared("http://gw".into(), sa)?;
        let gwb = Gateway::new_shared("http://gw".into(), sb)?;

        // A 签发 → B 无状态验签通过（跨副本，共享 secret）。
        let url = gwa.mint("sb1", Action::Exec, 0, 60, now);
        let q = parse_query(&url);
        gwb.verify(&q, now).map_err(|e| format!("B 应能验 A 签发的 ticket: {e}"))?;

        // 一次性跨副本：B 已用 → A 再用即拒（nonce 经 store 消费）。
        want!(gwa.verify(&q, now).is_err(), "跨副本重用应被拒（一次性）");
        want!(gwb.verify(&q, now).is_err(), "同副本重用应被拒（一次性）");

        // 篡改 sig → 拒。
        let mut q2 = parse_query(&gwa.mint("sb2", Action::Exec, 0, 60, now));
        q2.insert("sig".into(), "deadbeef".into());
        want!(gwb.verify(&q2, now).is_err(), "篡改 sig 应被拒");

        // 过期 → 拒。
        let q3 = parse_query(&gwa.mint("sb3", Action::Exec, 0, 1, now));
        want!(gwb.verify(&q3, now + 10).is_err(), "过期 ticket 应被拒");

        // 收尾清理。
        let _ = cleaner.delete("cluster/gw_secret");
        for kv in cleaner.list("gw/nonce/").map_err(|e| e.to_string())? {
            let _ = cleaner.delete(&kv.key);
        }
        Ok(())
    }

    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            let a = Box::new(sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?);
            let b = Box::new(sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?);
            let cleaner = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            asserts(a, b, &cleaner, now)?;
            println!("[gw-cluster] EtcdStore({ep}) 跨副本：A 签 B 验 + 一次性跨副本 + 篡改/过期拒 PASS");
            return Ok(());
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--gw-cluster-reconcile --etcd {ep} 需以 `--features cluster` 构建"));
        }
    }

    let path = std::env::temp_dir().join(format!("sl-gwcluster-{}.db", std::process::id()));
    let p = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&p);
    let r = {
        let a = Box::new(SqliteStore::open(&p).map_err(|e| e.to_string())?);
        let b = Box::new(SqliteStore::open(&p).map_err(|e| e.to_string())?);
        let cleaner = SqliteStore::open(&p).map_err(|e| e.to_string())?;
        asserts(a, b, &cleaner, now)
    };
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    r?;
    println!("[gw-cluster] SqliteStore(file) 两句柄：A 签 B 验 + 一次性跨副本 + 篡改/过期拒 PASS");
    Ok(())
}

/// M3 W4 集群合龙对账：**跨副本共享态**——一副本写入的沙箱/节点，另一副本立即可见；
/// 且失联节点的沙箱被（另一副本充当的）leader 回收、跨副本同步消失。两后端同一套（etcd 才有真跨副本；
/// SQLite 用同文件两句柄模拟共享后端）。
fn run_cluster_reconcile(cfg: &Config) -> Result<(), String> {
    use sl_store::cluster::{live_nodes, reclaim_orphans, register_node, sandbox_node_key};
    use sl_store::{SqliteStore, Store};

    // 两个 store 句柄 = 两个副本，共享同一后端。
    fn asserts(rep_a: &dyn Store, rep_b: &dyn Store) -> Result<(), String> {
        macro_rules! want {
            ($c:expr, $m:expr) => {
                if !$c {
                    return Err($m.into());
                }
            };
        }
        // 起点干净（经 A）。
        for kv in rep_a.list("node/").map_err(|e| e.to_string())? {
            rep_a.delete(&kv.key).map_err(|e| e.to_string())?;
        }
        for kv in rep_a.list("sandbox/").map_err(|e| e.to_string())? {
            rep_a.delete(&kv.key).map_err(|e| e.to_string())?;
        }
        // 副本 A：注册节点 repA + 写一个属 repA 的沙箱（meta/node 同租约）。
        register_node(rep_a, "repA", b"a", 30).map_err(|e| e.to_string())?;
        let l = rep_a.lease_grant(30).map_err(|e| e.to_string())?;
        rep_a.put("sandbox/s1/meta", br#"{"id":"s1"}"#, Some(l)).map_err(|e| e.to_string())?;
        rep_a.put(&sandbox_node_key("s1"), b"repA", Some(l)).map_err(|e| e.to_string())?;

        // 副本 B：**立即可见**（跨副本共享态，W4 核心）。
        want!(
            live_nodes(rep_b).map_err(|e| e.to_string())?.contains(&"repA".to_string()),
            "B 应见到 A 注册的节点 repA（跨副本共享）"
        );
        want!(
            rep_b.get("sandbox/s1/meta").map_err(|e| e.to_string())?.is_some(),
            "B 应见到 A 创建的沙箱 s1（跨副本共享）"
        );

        // repA 失联（经 A 撤心跳）→ 副本 B 充当 leader 回收（护栏保自己 repB）。
        let ids: Vec<i64> = rep_b
            .list("node/")
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter_map(|kv| kv.lease)
            .collect();
        for id in ids {
            // 撤销 repA 的心跳租约（这里 repA 是唯一注册节点）
            rep_a.lease_revoke(id).map_err(|e| e.to_string())?;
        }
        want!(live_nodes(rep_b).map_err(|e| e.to_string())?.is_empty(), "repA 撤心跳后应无存活节点");
        let reclaimed = reclaim_orphans(rep_b, Some("repB")).map_err(|e| e.to_string())?;
        want!(reclaimed == vec!["s1"], "B 作 leader 应回收失联 repA 的 s1");
        // 跨副本同步消失（经 A 看）。
        want!(rep_a.get("sandbox/s1/meta").map_err(|e| e.to_string())?.is_none(), "s1 应跨副本同步消失");

        // 收尾（经 A）。
        for kv in rep_a.list("sandbox/").map_err(|e| e.to_string())? {
            rep_a.delete(&kv.key).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            let a = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            let b = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            asserts(&a, &b)?;
            println!("[cluster] EtcdStore({ep}) 跨副本：A 写 B 见 + 失联回收跨副本同步 PASS");
            return Ok(());
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--cluster-reconcile --etcd {ep} 需以 `--features cluster` 构建"));
        }
    }

    let path = std::env::temp_dir().join(format!("sl-cluster-{}.db", std::process::id()));
    let p = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&p);
    let r = {
        let a = SqliteStore::open(&p).map_err(|e| e.to_string())?;
        let b = SqliteStore::open(&p).map_err(|e| e.to_string())?;
        asserts(&a, &b)
    };
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    r?;
    println!("[cluster] SqliteStore(file) 两句柄共享：A 写 B 见 + 失联回收同步 PASS");
    Ok(())
}

/// M3-Q2 节点失联回收对账：心跳 + 失联节点沙箱被回收 + 存活节点不动 + 护栏不回收自身，两后端同一套。
fn run_node_reclaim_reconcile(cfg: &Config) -> Result<(), String> {
    use sl_store::cluster::{live_nodes, reclaim_orphans, register_node, sandbox_node_key};
    use sl_store::{SqliteStore, Store};

    fn asserts(store: &dyn Store) -> Result<(), String> {
        macro_rules! want {
            ($c:expr, $m:expr) => {
                if !$c {
                    return Err($m.into());
                }
            };
        }
        let e = |r: sl_store::Result<()>| r.map_err(|e| e.to_string());
        // 起点干净
        for kv in store.list("node/").map_err(|e| e.to_string())? {
            e(store.delete(&kv.key).map(|_| ()))?;
        }
        for kv in store.list("sandbox/").map_err(|e| e.to_string())? {
            e(store.delete(&kv.key).map(|_| ()))?;
        }
        // 两节点心跳存活
        let la = register_node(store, "node-a", b"a", 30).map_err(|e| e.to_string())?;
        let _lb = register_node(store, "node-b", b"b", 30).map_err(|e| e.to_string())?;
        want!(live_nodes(store).map_err(|e| e.to_string())?.len() == 2, "两节点应存活");
        // s1→A、s2→B（meta/node 同租约）
        let put = |k: &str, v: &[u8], l: sl_store::LeaseId| -> Result<(), String> {
            store.put(k, v, Some(l)).map(|_| ()).map_err(|e| e.to_string())
        };
        let l1 = store.lease_grant(30).map_err(|e| e.to_string())?;
        put("sandbox/s1/meta", b"{}", l1)?;
        put(&sandbox_node_key("s1"), b"node-a", l1)?;
        let l2 = store.lease_grant(30).map_err(|e| e.to_string())?;
        put("sandbox/s2/meta", b"{}", l2)?;
        put(&sandbox_node_key("s2"), b"node-b", l2)?;
        want!(reclaim_orphans(store, None).map_err(|e| e.to_string())?.is_empty(), "都存活时不应回收");
        // A 失联 → 回收 s1，s2 不动
        store.lease_revoke(la).map_err(|e| e.to_string())?;
        want!(live_nodes(store).map_err(|e| e.to_string())? == vec!["node-b"], "仅 B 存活");
        let r = reclaim_orphans(store, None).map_err(|e| e.to_string())?;
        want!(r == vec!["s1"], "应只回收失联 A 的 s1");
        want!(store.get("sandbox/s1/meta").map_err(|e| e.to_string())?.is_none(), "s1 应被清");
        want!(store.get("sandbox/s2/meta").map_err(|e| e.to_string())?.is_some(), "s2 应保留");
        // 护栏：B 也失联，但 protect=node-b → 绝不回收自身 s2
        store.lease_revoke(_lb).map_err(|e| e.to_string())?;
        want!(reclaim_orphans(store, Some("node-b")).map_err(|e| e.to_string())?.is_empty(), "护栏应保住自身 s2");
        want!(store.get("sandbox/s2/meta").map_err(|e| e.to_string())?.is_some(), "护栏后 s2 仍在");
        // 收尾清理
        for kv in store.list("node/").map_err(|e| e.to_string())? {
            e(store.delete(&kv.key).map(|_| ()))?;
        }
        for kv in store.list("sandbox/").map_err(|e| e.to_string())? {
            e(store.delete(&kv.key).map(|_| ()))?;
        }
        Ok(())
    }

    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            let store = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
            asserts(&store)?;
            println!("[reclaim] EtcdStore({ep}) 节点失联回收：心跳 + 孤儿回收 + 存活不动 + 护栏 PASS");
            return Ok(());
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--node-reclaim-reconcile --etcd {ep} 需以 `--features cluster` 构建"));
        }
    }

    let path = std::env::temp_dir().join(format!("sl-reclaim-{}.db", std::process::id()));
    let p = path.to_string_lossy().to_string();
    let _ = std::fs::remove_file(&p);
    let r = {
        let store = SqliteStore::open(&p).map_err(|e| e.to_string())?;
        asserts(&store)
    };
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    r?;
    println!("[reclaim] SqliteStore(file) 节点失联回收：心跳 + 孤儿回收 + 存活不动 + 护栏 PASS");
    Ok(())
}

/// M3 W2 `cluster init`：把 `--store <sqlite>` 全量键一次性迁移到 `--etcd <ep>`（ADR-17）。
#[cfg(feature = "cluster")]
fn run_cluster_init(cfg: &Config) -> Result<(), String> {
    use sl_store::{migrate_all, SqliteStore};
    let src_path = cfg.store.as_ref().ok_or("--cluster-init 需 --store <sqlite 路径>")?;
    let ep = cfg.etcd.as_ref().ok_or("--cluster-init 需 --etcd <endpoint>")?;
    let src = SqliteStore::open(src_path.to_str().ok_or("store 路径非 UTF-8")?).map_err(|e| e.to_string())?;
    let dst = sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?;
    let n = migrate_all(&src, &dst).map_err(|e| e.to_string())?;
    println!("[cluster-init] 迁移完成：{n} 键  SQLite({}) → etcd({ep})", src_path.display());
    println!("[cluster-init] 注意：这是停机迁移事件（ADR-17）——迁移期间不应有在跑沙箱或并发写入。");
    Ok(())
}

#[cfg(not(feature = "cluster"))]
fn run_cluster_init(_cfg: &Config) -> Result<(), String> {
    Err("--cluster-init 需以 `--features cluster` 构建 sl-node（当前未启用该特性）".into())
}

fn parse_args() -> Config {
    let mut cfg = Config {
        kernel: PathBuf::from("build/kernel/vmlinux"),
        rootfs: PathBuf::from("build/rootfs/rootfs.ext4"),
        fc_bin: PathBuf::from("build/firecracker/firecracker"),
        jailer_bin: PathBuf::from("build/firecracker/jailer"),
        workdir: PathBuf::from("build/run"),
        boot: Boot::Api, // M1 D1：API 启动为默认；config-file 退役为对照
        cmd: None,
        netns: true,
        cycles: 0,
        json: false,
        hold_secs: 0,
        // sudo 下 getuid()==0 会使 jailer 降权到 root（等于不降权）；优先取 SUDO_UID/GID 降回真实用户
        jail_uid: env_u32("SUDO_UID").unwrap_or_else(|| unsafe { libc::getuid() }),
        jail_gid: env_u32("SUDO_GID").unwrap_or_else(|| unsafe { libc::getgid() }),
        snap_create: None,
        snap_load: None,
        clone_entropy: None,
        dmthin_reconcile: false,
        nftfw_reconcile: false,
        thin: false,
        build: None,
        store: None,
        orch_reconcile: None,
        orch_bench: None,
        serve: false,
        serve_addr: None,
        tick_secs: 5,
        template_root: None,
        run_root: None,
        net_live: false,
        uplink: None,
        net_gate_reconcile: false,
        net_live_reconcile: None,
        oci_pull: None,
        oci_out: None,
        pool_bench: None,
        pool_size: 2,
        pool_template: None,
        hot_size: 0,
        gvisor: false,
        gvisor_bin: PathBuf::from("runsc"),
        gvisor_reconcile: None,
        abi_contract: None,
        q5_reconcile: None,
        gw_addr: None,
        exec_bench: None,
        vcpus: 1,
        mem_mib: 128,
        snap_kms_key: None,
        snap_kms_init: None,
        snapcrypt_reconcile: false,
        gw_node_endpoint: None,
        gw_url: None,
        gw_pool: 8,
        gw_max_streams: 256,
        gw_tls_cert: None,
        gw_tls_key: None,
        gw_tls_ca: None,
        gw_tls_name: None,
        gw_insecure: false,
        gw_dataplane_reconcile: false,
        gw_reconcile: None,
        pty_reconcile: None,
        exec_stream_reconcile: None,
        net_egress_reconcile: None,
        expose_reconcile: None,
        expose_allow_public: false,
        store_contract: false,
        etcd: None,
        cluster_init: false,
        election_reconcile: false,
        node_reclaim_reconcile: false,
        cluster_reconcile: false,
        gw_cluster_reconcile: false,
        require_auth: false,
        apikey_create: false,
        org: None,
        project: None,
        scope: None,
        auth_reconcile: false,
        quota_set: false,
        max_sandboxes: 0,
        max_vcpus: 0,
        max_mem: 0,
        max_storage: 0,
        quota_reconcile: false,
        retention_reconcile: false,
        sched_reconcile: false,
        sched_overcommit: 1,
        log_sink: None,
};
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut take = || args.next().unwrap_or_else(|| { eprintln!("缺少 {a} 的参数值"); std::process::exit(2); });
        match a.as_str() {
            "--kernel" => cfg.kernel = PathBuf::from(take()),
            "--rootfs" => cfg.rootfs = PathBuf::from(take()),
            "--fc" => cfg.fc_bin = PathBuf::from(take()),
            "--jailer" => cfg.jailer_bin = PathBuf::from(take()),
            "--workdir" => cfg.workdir = PathBuf::from(take()),
            "--boot" => {
                cfg.boot = match take().as_str() {
                    "api" => Boot::Api,
                    "config-file" => Boot::ConfigFile,
                    "jailer" => Boot::Jailer,
                    o => { eprintln!("--boot 取值 api|config-file|jailer，得到 {o:?}"); std::process::exit(2); }
                }
            }
            "--uid" => cfg.jail_uid = take().parse().unwrap_or_else(|_| { eprintln!("--uid 需整数"); std::process::exit(2); }),
            "--gid" => cfg.jail_gid = take().parse().unwrap_or_else(|_| { eprintln!("--gid 需整数"); std::process::exit(2); }),
            "--cmd" => cfg.cmd = Some(take()),
            "--snap-create" => cfg.snap_create = Some(PathBuf::from(take())),
            "--snap-load" => cfg.snap_load = Some(PathBuf::from(take())),
            "--clone-entropy-check" => cfg.clone_entropy = Some(PathBuf::from(take())),
            "--dmthin-reconcile" => cfg.dmthin_reconcile = true,
            "--nftfw-reconcile" => cfg.nftfw_reconcile = true,
            "--net-gate-reconcile" => cfg.net_gate_reconcile = true,
            "--net-live-reconcile" => cfg.net_live_reconcile = Some(PathBuf::from(take())),
            "--net-live" => cfg.net_live = true,
            "--uplink" => cfg.uplink = Some(take()),
            "--thin" => cfg.thin = true,
            "--oci-pull" => cfg.oci_pull = Some(take()),
            "--oci-out" => cfg.oci_out = Some(PathBuf::from(take())),
            "--build" => cfg.build = Some(PathBuf::from(take())),
            "--store" => cfg.store = Some(PathBuf::from(take())),
            "--orch-reconcile" => cfg.orch_reconcile = Some(PathBuf::from(take())),
            "--orch-bench" => cfg.orch_bench = Some(PathBuf::from(take())),
            "--pool-bench" => cfg.pool_bench = Some(PathBuf::from(take())),
            "--pool-size" => {
                cfg.pool_size = take().parse().unwrap_or_else(|_| { eprintln!("--pool-size 需整数"); std::process::exit(2); })
            }
            "--pool-template" => cfg.pool_template = Some(take()),
            "--hot-size" => {
                cfg.hot_size = take().parse().unwrap_or_else(|_| { eprintln!("--hot-size 需整数"); std::process::exit(2); })
            }
            "--gvisor" => cfg.gvisor = true,
            "--gvisor-bin" => cfg.gvisor_bin = PathBuf::from(take()),
            "--gvisor-reconcile" => cfg.gvisor_reconcile = Some(PathBuf::from(take())),
            "--abi-contract" => cfg.abi_contract = Some(PathBuf::from(take())),
            "--q5-reconcile" => cfg.q5_reconcile = Some(PathBuf::from(take())),
            "--gw-addr" => cfg.gw_addr = Some(take()),
            "--exec-bench" => cfg.exec_bench = Some(PathBuf::from(take())),
            "--vcpus" => cfg.vcpus = take().parse().unwrap_or(1),
            "--mem-mib" => cfg.mem_mib = take().parse().unwrap_or(128),
            "--snap-kms-key" => cfg.snap_kms_key = Some(PathBuf::from(take())),
            "--snap-kms-init" => cfg.snap_kms_init = Some(PathBuf::from(take())),
            "--snapcrypt-reconcile" => cfg.snapcrypt_reconcile = true,
            "--gw" => cfg.gw_node_endpoint = Some(take()),
            "--gw-url" => cfg.gw_url = Some(take()),
            "--gw-pool" => cfg.gw_pool = take().parse().unwrap_or(8),
            "--gw-max-streams" => cfg.gw_max_streams = take().parse().unwrap_or(256),
            "--gw-tls-cert" => cfg.gw_tls_cert = Some(PathBuf::from(take())),
            "--gw-tls-key" => cfg.gw_tls_key = Some(PathBuf::from(take())),
            "--gw-tls-ca" => cfg.gw_tls_ca = Some(PathBuf::from(take())),
            "--gw-tls-name" => cfg.gw_tls_name = Some(take()),
            "--gw-insecure" => cfg.gw_insecure = true,
            "--gw-dataplane-reconcile" => cfg.gw_dataplane_reconcile = true,
            "--gw-reconcile" => cfg.gw_reconcile = Some(PathBuf::from(take())),
            "--pty-reconcile" => cfg.pty_reconcile = Some(PathBuf::from(take())),
            "--exec-stream-reconcile" => cfg.exec_stream_reconcile = Some(PathBuf::from(take())),
            "--net-egress-reconcile" => cfg.net_egress_reconcile = Some(PathBuf::from(take())),
            "--expose-reconcile" => cfg.expose_reconcile = Some(PathBuf::from(take())),
            "--expose-allow-public" => cfg.expose_allow_public = true,
            "--store-contract" => cfg.store_contract = true,
            "--etcd" => cfg.etcd = Some(take()),
            "--cluster-init" => cfg.cluster_init = true,
            "--election-reconcile" => cfg.election_reconcile = true,
            "--node-reclaim-reconcile" => cfg.node_reclaim_reconcile = true,
            "--cluster-reconcile" => cfg.cluster_reconcile = true,
            "--gw-cluster-reconcile" => cfg.gw_cluster_reconcile = true,
            "--require-auth" => cfg.require_auth = true,
            "--apikey-create" => cfg.apikey_create = true,
            "--org" => cfg.org = Some(take()),
            "--project" => cfg.project = Some(take()),
            "--scope" => cfg.scope = Some(take()),
            "--auth-reconcile" => cfg.auth_reconcile = true,
            "--quota-set" => cfg.quota_set = true,
            "--max-sandboxes" => cfg.max_sandboxes = take().parse().unwrap_or(0),
            "--max-vcpus" => cfg.max_vcpus = take().parse().unwrap_or(0),
            "--max-mem" => cfg.max_mem = take().parse().unwrap_or(0),
            "--max-storage" => cfg.max_storage = take().parse().unwrap_or(0),
            "--quota-reconcile" => cfg.quota_reconcile = true,
            "--retention-reconcile" => cfg.retention_reconcile = true,
            "--sched-reconcile" => cfg.sched_reconcile = true,
            "--sched-overcommit" => {
                cfg.sched_overcommit = take().parse().unwrap_or_else(|_| {
                    eprintln!("--sched-overcommit 需正整数");
                    std::process::exit(2);
                })
            }
            "--log-sink" => cfg.log_sink = Some(take()),
            "--serve" => cfg.serve = true,
            "--addr" => cfg.serve_addr = Some(take()),
            "--tick-secs" => {
                cfg.tick_secs = take().parse().unwrap_or_else(|_| { eprintln!("--tick-secs 需整数"); std::process::exit(2); })
            }
            "--template-root" => cfg.template_root = Some(PathBuf::from(take())),
            "--run-root" => cfg.run_root = Some(PathBuf::from(take())),
            "--no-netns" => cfg.netns = false,
            "--json" => cfg.json = true,
            "--hold-secs" => {
                cfg.hold_secs = take().parse().unwrap_or_else(|_| { eprintln!("--hold-secs 需整数"); std::process::exit(2); })
            }
            "--cycles" => {
                cfg.cycles = take().parse().unwrap_or_else(|_| { eprintln!("--cycles 需整数"); std::process::exit(2); })
            }
            "run" => {}
            other => {
                eprintln!("未知参数: {other}");
                eprintln!("用法: sl-node [run] [--boot api|config-file|jailer] [--kernel P] [--rootfs P] [--fc P] [--jailer P] [--workdir P] [--cmd \"命令\"] [--snap-create DIR] [--snap-load DIR] [--clone-entropy-check DIR] [--dmthin-reconcile] [--nftfw-reconcile] [--net-gate-reconcile] [--net-live-reconcile 模板DIR] [--net-live] [--uplink IFACE] [--thin] [--oci-pull ref|archive] [--oci-out PATH] [--build sandlocker.toml] [--store DIR] [--orch-reconcile 模板DIR] [--orch-bench 模板DIR] [--pool-bench 模板DIR] [--gvisor-reconcile 模板DIR] [--abi-contract 模板DIR] [--q5-reconcile 模板DIR] [--gw-reconcile 模板DIR] [--pty-reconcile 模板DIR] [--exec-stream-reconcile 模板DIR] [--net-egress-reconcile 模板DIR] [--serve] [--gw-addr host:port] [--addr host:port] [--tick-secs N] [--template-root DIR] [--run-root DIR] [--pool-size N] [--pool-template NAME] [--hot-size N] [--gvisor] [--gvisor-bin PATH] [--no-netns] [--uid N] [--gid N] [--cycles N] [--json] [--hold-secs N]");
                std::process::exit(2);
            }
        }
    }
    // jailer 的 netns 集成走 jailer --netns（W5 与 nftables 一起接）；W1 起步先只验 chroot 降权，
    // 故 jailer 模式强制关网络，避免配置 eth0 时找不到 tap。
    if cfg.boot == Boot::Jailer && cfg.netns {
        cfg.netns = false;
    }
    cfg
}
