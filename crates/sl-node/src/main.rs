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
// M2 W6：Sandbox ABI 契约（trait + 能力模型，ADR-14）+ Firecracker 后端实现。
mod backend;
mod fcbackend;
// W7：进程内 orchestrator（生命周期 create/keepalive/destroy/tick + Q2/Q9）。
mod orch;
// M2 W4：预热池·温池（把 rootfs 拷贝/page-cache 预热移出 create 关键路径，M2-Q2）。
mod pool;
// W8：长驻守护 + 手写极简 REST server（--serve）——HTTP API + orchestrator + reaper 全进程内。
mod api;

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
}

fn main() {
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
        // rootless mount-ns bind（M1 逐字节不变）。
        (Some((src, dst)), None) => {
            let script = format!(
                "mount --bind {} {} && exec {} --api-sock {}",
                sq(src), sq(dst), sq(&cfg.fc_bin), sq(&api_host)
            );
            let mut c = Command::new("unshare");
            c.arg("--user").arg("--map-root-user").arg("--mount").arg("--propagation").arg("private")
                .arg("sh").arg("-c").arg(script);
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

    api.put("/machine-config", r#"{"vcpu_count":1,"mem_size_mib":128}"#)?;
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
fn exec(stream: &mut UnixStream, cmd: &str) -> Result<(i32, String, String), String> {
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
                eprintln!("用法: sl-node [run] [--boot api|config-file|jailer] [--kernel P] [--rootfs P] [--fc P] [--jailer P] [--workdir P] [--cmd \"命令\"] [--snap-create DIR] [--snap-load DIR] [--clone-entropy-check DIR] [--dmthin-reconcile] [--nftfw-reconcile] [--net-gate-reconcile] [--net-live-reconcile 模板DIR] [--net-live] [--uplink IFACE] [--thin] [--oci-pull ref|archive] [--oci-out PATH] [--build sandlocker.toml] [--store DIR] [--orch-reconcile 模板DIR] [--orch-bench 模板DIR] [--pool-bench 模板DIR] [--serve] [--addr host:port] [--tick-secs N] [--template-root DIR] [--run-root DIR] [--pool-size N] [--pool-template NAME] [--hot-size N] [--no-netns] [--uid N] [--gid N] [--cycles N] [--json] [--hold-secs N]");
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
