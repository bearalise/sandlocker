//! build.rs — W6 模板构建引擎（`sl-node --build <sandlocker.toml>`）。
//!
//! ADR-19 build-as-sandbox：RUN 步骤在一个**专用构建沙箱**（FC VM + guest 内 sl-envd）里经
//! vsock exec 执行，而非在宿主另起构建环境。产物 = 可移植 rootfs + 一份预烘焙快照
//! （ADR-14/16），**内容寻址 + ed25519 签名**入 sl-store（Q6）。
//!
//! 两阶段（关键设计）：
//!   ① 构建沙箱：从基座 rootfs 的可写副本 boot（无网），注入 COPY、依次跑 RUN（写落盘持久化到
//!      镜像文件本身——rootfs drive 就是 rw 单盘），materialize ADR-18 构建期 env/workdir/user，
//!      `sync` 刷盘后关机。
//!   ② 预烘焙沙箱：从**已构建**的 rootfs **新鲜** boot 到 D5 点（sl-envd 就绪、start_cmd 若有则
//!      已拉起、应用代码未跑）→ Paused → snapshot/create。干净的预烘焙内存态，不含构建期残留。
//!
//! 目录键（版本）：FC 的 `snapshot/load{resume_vm:false}` 从 vmstate 里**烘焙的绝对 path_on_host**
//! 恢复 rootfs（见 main.rs snapshot_load_run），故产物**必须直接建在最终目录**、不可先建后 rename。
//! 因此 version 缺省时由**构建输入**派生（base rootfs/kernel/vmm/run/copy/env/... 的 sha256 前缀，
//! 与 ADR-16「快照按 模板版本×内核×VMM 键」一致），而 manifest 另记**输出内容摘要** content_digest
//! （rootfs+vmstate+mem 的 sha256）并由签名覆盖——产物仍是内容可验证 + 已签名。
//!
//! build_network（FR-3.3/ADR-19，三档可配）：本周**解析/校验/入 manifest**。`deny`（默认）= 构建
//! 沙箱无 netns、真离线，端到端可跑；`allow-all`/`whitelist` = 记录白名单元数据。真实出口 gate
//! （veth+NAT + W5 nftfw 策略表接进 live 路径）随 jailer-netns 落地——与 W5 同一延后块；本周构建
//! 沙箱一律无 egress，故 RUN 步骤不得依赖联网（示例模板走离线命令）。

use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fcapi::FcApi;
use crate::{
    abspath, exec, hex, host_random, kill_group, request, spawn_with_log, wait_api_ready,
    wait_guest, Config, GUEST_CID, GUEST_MAC,
};
use crate::netlive;
use sl_proto::{Request, Response};
use sl_store::{SqliteStore, Store};

// ── DSL（sandlocker.toml，FR-4.1）──────────────────────────────────────────

/// 单条 COPY：把宿主 `src`（相对 toml 所在目录，即构建上下文）注入 guest `dst`。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CopySpec {
    src: String,
    dst: String,
    /// 八进制权限串（chmod 直传），缺省 "0644"。
    mode: Option<String>,
}

/// `sandlocker.toml` 模板声明。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Template {
    name: String,
    /// 缺省由构建输入哈希派生（见模块头）。
    version: Option<String>,
    /// 基座 rootfs 镜像；缺省用 --rootfs（基座 rootfs.ext4）。
    from: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    workdir: Option<String>,
    user: Option<String>,
    #[serde(default)]
    copy: Vec<CopySpec>,
    #[serde(default)]
    run: Vec<String>,
    /// 常驻服务入口（ADR-18：ENTRYPOINT/CMD 不自动跑，仅 start_cmd）。预烘焙点前拉起。
    start_cmd: Option<String>,
    /// "deny"(默认) | "allow-all" | "whitelist"
    #[serde(default = "default_build_network")]
    build_network: String,
    /// 仅 whitelist 档：允许的 host:port 列表（入 manifest；M2-Q8 本 PR 未强制，真 gate 待独立 PR）。
    #[serde(default)]
    whitelist: Vec<String>,
    /// 构建/预烘焙 microVM 的 vCPU 数（默认 1）。大镜像可调高（1..=32）。
    #[serde(default = "default_vcpu")]
    vcpu: u32,
    /// 构建/预烘焙 microVM 的内存 MiB（默认 128）。大镜像（python/node 等）boot 到预烘焙点易 128M
    /// OOM，调高即可；注意快照 mem 文件随之变大、build_id 随之变。
    #[serde(default = "default_mem_mib")]
    mem_mib: u32,
}

fn default_build_network() -> String {
    "deny".into()
}

fn default_vcpu() -> u32 {
    1
}

fn default_mem_mib() -> u32 {
    128
}

// ── manifest（产物元数据，被签名覆盖）───────────────────────────────────────

/// ADR-16 快照键：模板版本 × 内核 × VMM。
#[derive(Debug, Serialize)]
struct Adr16Key {
    template_version: String,
    kernel_version: String,
    vmm_version: String,
}

#[derive(Debug, Serialize)]
struct Manifest {
    name: String,
    version: String,
    /// 输出内容摘要 = sha256(rootfs_digest || vmstate_digest || mem_digest)。
    content_digest: String,
    rootfs_sha256: String,
    vmstate_sha256: String,
    mem_sha256: String,
    adr16_key: Adr16Key,
    build_network: String,
    whitelist: Vec<String>,
    /// 构建/预烘焙 microVM 规格（进版本键；恢复时快照自带内存尺寸，无需再指定）。
    vcpu: u32,
    mem_mib: u32,
    env: BTreeMap<String, String>,
    workdir: Option<String>,
    user: Option<String>,
    start_cmd: Option<String>,
    /// RUN 步骤序列的 sha256（可复现性追溯）。
    run_digest: String,
    run_steps: usize,
    /// M2 W3：OCI 基座来源（引用 / archive 路径），非 OCI 时省略。
    #[serde(skip_serializing_if = "Option::is_none")]
    oci_source: Option<String>,
    /// M2 W3：OCI 稳定摘要（远程 manifest digest / archive image id），版本键的输入之一。
    #[serde(skip_serializing_if = "Option::is_none")]
    oci_source_digest: Option<String>,
    /// M2 W3：镜像 Cmd（ADR-18 记录不自动跑），非 OCI 或空时省略。
    #[serde(skip_serializing_if = "Option::is_none")]
    image_cmd: Option<Vec<String>>,
    /// M2 W3：镜像 Entrypoint（ADR-18 记录不自动跑），非 OCI 或空时省略。
    #[serde(skip_serializing_if = "Option::is_none")]
    image_entrypoint: Option<Vec<String>>,
    /// 签名公钥（hex，ed25519），供离线验签。
    pubkey_hex: String,
    created_at: u64,
}

// ── 入口 ────────────────────────────────────────────────────────────────

/// `sl-node --build <sandlocker.toml>`：解析 DSL → 两阶段 build-as-sandbox → 预烘焙快照 →
/// 内容寻址 + ed25519 签名 → 入 sl-store。成功后 --json 出单行度量；失败退非 0。
pub fn build(cfg: &Config, toml_path: &Path) -> Result<(), String> {
    // 1) 解析 + 校验 DSL
    let text = std::fs::read_to_string(toml_path)
        .map_err(|e| format!("读模板失败 {}: {e}", toml_path.display()))?;
    let tmpl: Template = toml::from_str(&text).map_err(|e| format!("解析 sandlocker.toml 失败: {e}"))?;
    validate_name(&tmpl.name, "name")?;
    if !matches!(tmpl.build_network.as_str(), "deny" | "allow-all" | "whitelist") {
        return Err(format!(
            "build_network 取值 deny|allow-all|whitelist，得到 {:?}",
            tmpl.build_network
        ));
    }
    if !(1..=32).contains(&tmpl.vcpu) {
        return Err(format!("vcpu 取值 1..=32，得到 {}", tmpl.vcpu));
    }
    if tmpl.mem_mib < 128 {
        return Err(format!("mem_mib 至少 128（MiB），得到 {}", tmpl.mem_mib));
    }
    if let Some(v) = &tmpl.version {
        validate_name(v, "version")?;
    }

    // 2) base rootfs 来源分类（M2 W3）：Local ext4（向后兼容）| Remote registry | Archive tarball。
    for (label, p) in [("kernel", &cfg.kernel), ("firecracker", &cfg.fc_bin)] {
        if !p.exists() {
            return Err(format!("{label} 不存在: {}", p.display()));
        }
    }
    let from_str = tmpl
        .from
        .clone()
        .unwrap_or_else(|| cfg.rootfs.to_string_lossy().into_owned());
    let source = crate::oci::classify(&from_str)?;
    // OCI 源：先拉取/加载 → 展平 → bake 成缓存 ext4，当作 base_rootfs 交给下游（逐字节复用）。
    // base_key = 版本派生的基座输入：Local 用 ext4 内容 digest；OCI 用 source_digest（mke2fs 输出
    // 非字节确定，不能靠生成 ext4 的 sha256，否则同镜像跨拉取版本漂移）。
    let (base_rootfs, base_key, oci_res): (PathBuf, Vec<u8>, Option<crate::oci::OciResult>) =
        match &source {
            crate::oci::Source::Local(p) => {
                if !p.exists() {
                    return Err(format!("base rootfs(from) 不存在: {}", p.display()));
                }
                let d = sha256_file(p)?;
                (p.clone(), d.to_vec(), None)
            }
            _ => {
                let res = crate::oci::source_to_rootfs(&source, cfg.json)?;
                let key = res.source_digest.as_bytes().to_vec();
                (res.rootfs_path.clone(), key, Some(res))
            }
        };

    // 3) 预读 COPY 上下文文件（相对 toml 目录）——一次读入，输入哈希与注入复用
    let ctx_dir = toml_path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let mut copies: Vec<(String, String, Vec<u8>)> = Vec::new(); // (dst, mode, data)
    for c in &tmpl.copy {
        if c.dst.contains('\'') {
            return Err(format!("COPY dst 含单引号，暂不支持: {:?}", c.dst));
        }
        let mode = c.mode.clone().unwrap_or_else(|| "0644".into());
        let src = {
            let p = PathBuf::from(&c.src);
            if p.is_absolute() { p } else { ctx_dir.join(&p) }
        };
        let data = std::fs::read(&src).map_err(|e| format!("读 COPY 源失败 {}: {e}", src.display()))?;
        copies.push((c.dst.clone(), mode, data));
    }

    // 4) VMM 版本 + 内核指纹（ADR-16 键 & 输入哈希）
    let vmm_version = firecracker_version(&cfg.fc_bin);
    let kernel_digest = sha256_file(&cfg.kernel)?;

    // 5) 版本：显式优先，否则由构建输入哈希派生（前 12 hex）
    let run_digest = {
        let mut h = Sha256::new();
        for step in &tmpl.run {
            h.update(step.as_bytes());
            h.update([0u8]);
        }
        h.finalize()
    };
    let build_id = compute_build_id(
        &tmpl,
        &base_key,
        &kernel_digest,
        &vmm_version,
        &copies,
    );
    let version = tmpl.version.clone().unwrap_or_else(|| hex(&build_id)[..12].to_string());

    // 6) 产物目录（直接建在最终目录，见模块头）；store DB 路径
    let templates_root = PathBuf::from("build/templates");
    let out_dir = templates_root.join(&tmpl.name).join(&version);
    if out_dir.exists() {
        // 同键重建（ADR-16 可再生缓存）：清旧产物再造，避免 rootfs 自拷贝/陈旧 path_on_host
        std::fs::remove_dir_all(&out_dir).map_err(|e| format!("清理旧产物失败: {e}"))?;
    }
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("建产物目录失败: {e}"))?;
    let dir = abspath(&out_dir)?;
    let db_path = cfg.store.clone().unwrap_or_else(|| templates_root.join("sl.db"));

    let rootfs = dir.join("rootfs.ext4");
    let vmstate = dir.join("vmstate");
    let mem = dir.join("mem");
    let console_build = dir.join("console.build.log");
    let console_bake = dir.join("console.bake.log");

    // rootfs 可写工作副本（RUN 写直接落这份镜像 → 即模板 rootfs）
    std::fs::copy(&base_rootfs, &rootfs).map_err(|e| format!("拷贝 base rootfs 失败: {e}"))?;

    if !cfg.json {
        println!(
            "[build] {}@{}：build_network={} | RUN×{} COPY×{} | 输出 {}",
            tmpl.name, version, tmpl.build_network, tmpl.run.len(), copies.len(), dir.display()
        );
        // 网络生效/未强制的提示由 setup_build_net 在 run_build_phase 内按档打印（deny 静默）。
    }

    // ADR-18 env/workdir/user 物化：镜像默认铺底，模板同键覆盖（仅 OCI 源有镜像默认）。
    let mut merged_env: BTreeMap<String, String> = BTreeMap::new();
    if let Some(o) = &oci_res {
        for (k, v) in &o.config.env {
            merged_env.insert(k.clone(), v.clone());
        }
    }
    for (k, v) in &tmpl.env {
        merged_env.insert(k.clone(), v.clone());
    }
    let merged_workdir = tmpl
        .workdir
        .clone()
        .or_else(|| oci_res.as_ref().and_then(|o| o.config.workdir.clone()));
    let merged_user = tmpl
        .user
        .clone()
        .or_else(|| oci_res.as_ref().and_then(|o| o.config.user.clone()));

    // ── 阶段① 构建沙箱：COPY + RUN + 构建期配置 + sync ──
    run_build_phase(
        cfg,
        &dir,
        &rootfs,
        &console_build,
        &tmpl,
        &copies,
        &merged_env,
        &merged_workdir,
        &merged_user,
    )?;

    // ── 阶段② 预烘焙沙箱：新鲜 boot → D5 → Paused → snapshot ──
    run_prebake_phase(cfg, &dir, &rootfs, &vmstate, &mem, &console_bake, &tmpl)?;

    // ── 内容寻址 ──
    let rootfs_d = sha256_file(&rootfs)?;
    let vmstate_d = sha256_file(&vmstate)?;
    let mem_d = sha256_file(&mem)?;
    let content_digest = {
        let mut h = Sha256::new();
        h.update(rootfs_d);
        h.update(vmstate_d);
        h.update(mem_d);
        hex(&h.finalize())
    };

    // ── 签名（ed25519，本地密钥）──
    let signer = load_or_create_key()?;
    let pubkey_hex = hex(&signer.verifying_key().to_bytes());

    let manifest = Manifest {
        name: tmpl.name.clone(),
        version: version.clone(),
        content_digest: content_digest.clone(),
        rootfs_sha256: hex(&rootfs_d),
        vmstate_sha256: hex(&vmstate_d),
        mem_sha256: hex(&mem_d),
        adr16_key: Adr16Key {
            template_version: version.clone(),
            kernel_version: hex(&kernel_digest)[..12].to_string(),
            vmm_version: vmm_version.clone(),
        },
        build_network: tmpl.build_network.clone(),
        whitelist: tmpl.whitelist.clone(),
        vcpu: tmpl.vcpu,
        mem_mib: tmpl.mem_mib,
        env: merged_env.clone(),
        workdir: merged_workdir.clone(),
        user: merged_user.clone(),
        start_cmd: tmpl.start_cmd.clone(),
        run_digest: hex(&run_digest),
        run_steps: tmpl.run.len(),
        oci_source: oci_res.as_ref().map(|o| o.source.clone()),
        oci_source_digest: oci_res.as_ref().map(|o| o.source_digest.clone()),
        image_cmd: oci_res
            .as_ref()
            .map(|o| o.config.cmd.clone())
            .filter(|c| !c.is_empty()),
        image_entrypoint: oci_res
            .as_ref()
            .map(|o| o.config.entrypoint.clone())
            .filter(|c| !c.is_empty()),
        pubkey_hex,
        created_at: now_unix(),
    };
    // 签名对象 = 写盘的 manifest 精确字节（sig 与文件字节一一对应）
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| format!("序列化 manifest 失败: {e}"))?;
    std::fs::write(dir.join("manifest.json"), &manifest_bytes)
        .map_err(|e| format!("写 manifest.json 失败: {e}"))?;
    let sig = sign(&signer, &manifest_bytes);
    std::fs::write(dir.join("manifest.sig"), hex(&sig)).map_err(|e| format!("写 manifest.sig 失败: {e}"))?;

    // ── 入库（sl-store，template/ 前缀）──
    let db_str = db_path.to_str().ok_or("store 路径非 UTF-8")?;
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("建 store 目录失败: {e}"))?;
    }
    let store = SqliteStore::open(db_str).map_err(|e| format!("打开 store 失败: {e}"))?;
    store
        .put(&format!("template/{}/{}", tmpl.name, version), &manifest_bytes, None)
        .map_err(|e| format!("写 store（版本）失败: {e}"))?;
    store
        .put(&format!("template/{}/latest", tmpl.name), version.as_bytes(), None)
        .map_err(|e| format!("写 store（latest）失败: {e}"))?;

    // ── 输出 ──
    if cfg.json {
        println!(
            r#"{{"metric":"template_build","name":"{}","version":"{}","content_digest":"{}","signed":true,"build_network":"{}","run_steps":{},"pass":true}}"#,
            tmpl.name, version, content_digest, tmpl.build_network, tmpl.run.len()
        );
    } else {
        println!(
            "[build] PASS：{}@{} 已入库（content={}…，ed25519 已签），产物 {}（rootfs.ext4/vmstate/mem/manifest.json/manifest.sig）",
            tmpl.name, version, &content_digest[..12], dir.display()
        );
    }
    Ok(())
}

// ── 阶段实现 ─────────────────────────────────────────────────────────────

/// M2-Q8：按 `build_network` 为构建沙箱准备出口。
/// - `deny` → None（离线，rootless，现行为）。
/// - `whitelist` → None + 警告（本 PR 未强制，构建期仍离线；需真出口用 allow-all）。
/// - `allow-all` → `LiveNet::up`（netns+veth+tap+host NAT 全出口，**不建 nftfw drop 门禁** = 全放行）；
///   非 root fail-closed（不静默退回离线，避免 RUN 联网步骤诡异失败）。
/// build_network × root → 出口决策（纯逻辑，无 root/shell 副作用，便于单测）。
#[derive(Debug, PartialEq, Eq)]
enum NetPlan {
    Offline,      // deny / whitelist：构建期离线
    Egress,       // allow-all + root：拉起真出口
    RootRequired, // allow-all 但非 root：fail-closed
}

fn net_plan(build_network: &str, root: bool) -> Result<NetPlan, String> {
    match build_network {
        "deny" | "whitelist" => Ok(NetPlan::Offline),
        "allow-all" if root => Ok(NetPlan::Egress),
        "allow-all" => Ok(NetPlan::RootRequired),
        other => Err(format!("build_network 未知取值: {other:?}")),
    }
}

fn setup_build_net(cfg: &Config, tmpl: &Template, id: &str) -> Result<Option<netlive::LiveNet>, String> {
    let root = unsafe { libc::geteuid() } == 0;
    match net_plan(&tmpl.build_network, root)? {
        NetPlan::Offline => {
            if tmpl.build_network == "whitelist" {
                eprintln!(
                    "[build] 注意：build_network=whitelist 本 PR 未强制（构建期仍离线）；需真出口请用 allow-all。\
                     白名单已记入 manifest，真 gate 待独立 PR。"
                );
            }
            Ok(None)
        }
        NetPlan::RootRequired => {
            Err("build_network=allow-all 需 root（ip/nft/netns 建 netns+NAT）；请 sudo，或改用 deny".into())
        }
        NetPlan::Egress => {
            let uplink = cfg
                .uplink
                .clone()
                .or_else(|| netlive::detect_uplink(root))
                .ok_or_else(|| "未能确定上行网卡（--uplink <dev>）".to_string())?;
            let ns = netlive::ns_for(id);
            let net = netlive::LiveNet::up(id, &ns, &uplink, root)?;
            if !cfg.json {
                eprintln!(
                    "[build] allow-all 出口：netns={ns} tap={} guest={}→gw {} NAT→{uplink}",
                    net.tap(),
                    net.guest_ip(),
                    net.gateway_ip()
                );
            }
            Ok(Some(net))
        }
    }
}

/// allow-all：eth0/默认路由由内核 IP autoconfig（boot_args `ip=`）配好，guest 内无需任何网络工具；
/// 这里只补 `/etc/resolv.conf`（内核 autoconfig 不设 DNS）。默认 1.1.1.1，`SL_BUILD_DNS` 可覆盖；
/// NAT 会把 UDP53 masquerade 出 uplink。只用 `/bin/sh` + `printf`（重定向）——minimal 镜像亦具备。
fn configure_guest_dns(stream: &mut UnixStream) -> Result<(), String> {
    let dns = std::env::var("SL_BUILD_DNS").unwrap_or_else(|_| "1.1.1.1".into());
    let resolv = format!("printf 'nameserver %s\\n' '{dns}' > /etc/resolv.conf");
    let (rc, _o, e) = exec(stream, &resolv)?;
    if rc != 0 {
        return Err(format!("guest 写 resolv.conf 失败（rc={rc}）: {}", e.trim()));
    }
    Ok(())
}

/// 阶段①：boot 构建沙箱（deny 无网 / allow-all 真出口）→ D5 预检 → 配网 → COPY →
/// 写构建期 env（RUN 前，令 RUN 吃到镜像 PATH）→ RUN（fail-fast）→ sync → 关机。
#[allow(clippy::too_many_arguments)]
fn run_build_phase(
    cfg: &Config,
    dir: &Path,
    rootfs: &Path,
    console_log: &Path,
    tmpl: &Template,
    copies: &[(String, String, Vec<u8>)],
    merged_env: &BTreeMap<String, String>,
    merged_workdir: &Option<String>,
    merged_user: &Option<String>,
) -> Result<(), String> {
    let vsock = dir.join("vsock.sock");
    let api_host = dir.join("api.sock");
    // M2-Q8：allow-all 构建拉起真出口（netns+veth+tap+NAT）；deny/whitelist → None（离线）。失败 fail-closed。
    // id = 产物目录（name/version 唯一），netlive 内部会 hash 成短名，天然避免并发构建的 netns/iface 撞名。
    let build_id = dir.to_string_lossy();
    let net = setup_build_net(cfg, tmpl, &build_id)?;
    let (mut child, _api, mut stream) = boot_and_connect(
        cfg,
        &api_host,
        console_log,
        rootfs,
        &vsock,
        tmpl.vcpu,
        tmpl.mem_mib,
        net.as_ref(),
    )?;

    // RUN 步骤可能很慢（pip/npm/apt/编译；联网下载尤甚）——放宽 vsock exec 读超时（boot_and_connect 默认 30s
    // 对构建太紧）。默认 600s，SL_BUILD_EXEC_TIMEOUT_SECS 可调。prebake 阶段的 exec 快，保持 30s 不放宽。
    let exec_secs = std::env::var("SL_BUILD_EXEC_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(600);
    stream
        .set_read_timeout(Some(Duration::from_secs(exec_secs)))
        .map_err(|e| format!("设 RUN 读超时失败: {e}"))?;

    let result = (|| -> Result<(), String> {
        // D5 不变量（前）：base rootfs 不得预置 machine-id（ADR-12，否则克隆共享身份）
        assert_no_identity(&mut stream, "构建前 base rootfs")?;

        // allow-all：eth0/路由已由内核 ip= autoconfig 配好；这里补 DNS（须在 RUN 之前，令联网 RUN 可解析）。
        if net.is_some() {
            configure_guest_dns(&mut stream)?;
        }

        // COPY（base64 分块经 exec 注入，避开 ARG_MAX）
        for (dst, mode, data) in copies {
            inject_file(&mut stream, dst, mode, data)
                .map_err(|e| format!("COPY → {dst} 失败: {e}"))?;
        }

        // 构建期 env/workdir/user materialize（ADR-18）——**必须在 RUN 之前**：sl-envd 的 exec 会施加
        // /etc/sl-envd/env（镜像 PATH/WORKDIR），RUN 步骤才能像 Docker 那样吃到镜像环境（node/python
        // 在镜像 PATH 里才找得到）。写在 RUN 之后则 RUN 拿不到镜像 PATH。
        write_build_env(&mut stream, merged_env, merged_workdir, merged_user)?;

        // RUN（依次执行，任一非 0 即 fail-fast；此时已可用镜像 PATH/WORKDIR）
        for (i, step) in tmpl.run.iter().enumerate() {
            let (code, out, err) = exec(&mut stream, step)?;
            if !cfg.json && !out.trim().is_empty() {
                print!("{out}");
            }
            if code != 0 {
                eprint!("{err}");
                return Err(format!("RUN 第 {} 步失败（exit={code}）: {step}", i + 1));
            }
        }

        // D5 不变量（后）：RUN 不得烘焙固定身份（machine-id 仍应为空，恢复后靠 W4 reinit 换发）
        assert_no_identity(&mut stream, "RUN 之后")?;

        // 刷盘：ext4 写落镜像文件持久化（否则 kill 后可能丢写）
        let (c, _, _) = exec(&mut stream, "sync")?;
        if c != 0 {
            return Err("sync 刷盘失败".into());
        }
        Ok(())
    })();

    kill_group(&mut child);
    let _ = std::fs::remove_file(&api_host);
    let _ = std::fs::remove_file(&vsock);
    // 兜底清 netns（成功/失败都清；LiveNet::up 自身也幂等 down 兜底）。
    if let Some(n) = &net {
        n.down();
    }
    result
}

/// 阶段②：从已构建 rootfs 新鲜 boot → 拉起 start_cmd（D5）→ 播种 marker → Paused → snapshot/create。
/// 快照格式与 --snap-create 一致（含 expect），故 `--snap-load <产物目录>` 可直接验证可恢复。
fn run_prebake_phase(
    cfg: &Config,
    dir: &Path,
    rootfs: &Path,
    vmstate: &Path,
    mem: &Path,
    console_log: &Path,
    tmpl: &Template,
) -> Result<(), String> {
    let vsock = dir.join("vsock.sock");
    let api_host = dir.join("api.sock");
    let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or("tmpl").to_string();
    for f in [vmstate, mem, &vsock, &api_host] {
        let _ = std::fs::remove_file(f);
    }
    // 预烘焙不联网（快照干净、无 NIC 状态）——net=None。
    let (mut child, api, mut stream) = boot_and_connect(
        cfg,
        &api_host,
        console_log,
        rootfs,
        &vsock,
        tmpl.vcpu,
        tmpl.mem_mib,
        None,
    )?;

    let result = (|| -> Result<(), String> {
        // D5：start_cmd 若有则拉起（后台、脱离会话）——「已拉起、应用未跑」的近似。
        // sl-envd 托管 start_cmd 的干净版留后续；本周用 setsid 后台起。
        if let Some(sc) = &tmpl.start_cmd {
            if sc.contains('\'') {
                return Err("start_cmd 含单引号，暂不支持".into());
            }
            let (c, _, err) = exec(&mut stream, &format!("setsid sh -c '{sc}' >/dev/null 2>&1 &"))?;
            if c != 0 {
                return Err(format!("拉起 start_cmd 失败（exit={c}）: {err}"));
            }
        }

        // 播种可验证状态（与 snapshot_create 同构：marker 一致性 + sleep 抬高 uptime）
        let token = format!("sl-tmpl-{name}");
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

        // Paused → Full 快照（自包含内存 + vmstate）。用 put_long：大镜像（>1GB rootfs）刷脏页 +
        // 落内存可能远超常规 5s 超时，慢超时（默认 300s，SL_FC_SNAPSHOT_TIMEOUT_SECS 可调）避免假失败。
        api.patch("/vm", r#"{"state":"Paused"}"#)?;
        api.put_long(
            "/snapshot/create",
            &format!(
                r#"{{"snapshot_type":"Full","snapshot_path":"{}","mem_file_path":"{}"}}"#,
                vmstate.display(),
                mem.display()
            ),
        )?;
        std::fs::write(dir.join("expect"), format!("{token}\n{snap_uptime}\n"))
            .map_err(|e| format!("写 expect 失败: {e}"))?;
        Ok(())
    })();

    kill_group(&mut child);
    let _ = std::fs::remove_file(&api_host);
    let _ = std::fs::remove_file(&vsock); // 死 FC 遗留 bind 文件，load 需重新 bind
    result
}

/// 起 FC（无网，--api-sock）→ 逐段配置 → InstanceStart → 等 sl-envd 就绪 → Ping 自检。
/// 返回 (child, api, stream)；调用方负责 kill_group。
fn boot_and_connect(
    cfg: &Config,
    api_host: &Path,
    console_log: &Path,
    rootfs: &Path,
    vsock: &Path,
    vcpu: u32,
    mem_mib: u32,
    net: Option<&netlive::LiveNet>,
) -> Result<(Child, FcApi, UnixStream), String> {
    // net Some（allow-all 构建）：FC 起进具名 netns（照 main.rs net_live_reconcile 冷启动）；否则直呼。
    let cmd = match net {
        Some(n) => {
            let mut c = Command::new("ip");
            c.arg("netns").arg("exec").arg(&n.ns).arg(&cfg.fc_bin).arg("--api-sock").arg(api_host);
            c
        }
        None => {
            let mut c = Command::new(&cfg.fc_bin);
            c.arg("--api-sock").arg(api_host);
            c
        }
    };
    let mut child = spawn_with_log(cmd, console_log)?;

    let boot = (|| -> Result<(FcApi, UnixStream), String> {
        let api = FcApi::new(api_host);
        wait_api_ready(&api, &mut child)?;
        api.put(
            "/machine-config",
            &format!(r#"{{"vcpu_count":{vcpu},"mem_size_mib":{mem_mib}}}"#),
        )?;
        // allow-all：走内核 IP autoconfig（CONFIG_IP_PNP=y）——boot 时内核配 eth0，guest 内**零工具依赖**
        // （debian/ubuntu 等 minimal 镜像常无 `ip`/iproute2）。格式 ip=<客户端>::<网关>:<掩码>::eth0:off。
        let boot_args = match net {
            Some(n) => format!(
                "{} ip={}::{}:255.255.255.252::eth0:off",
                crate::boot_args(),
                n.guest_ip(),
                n.gateway_ip()
            ),
            None => crate::boot_args().to_string(),
        };
        api.put(
            "/boot-source",
            &format!(
                r#"{{"kernel_image_path":"{}","boot_args":"{}"}}"#,
                cfg.kernel.display(),
                boot_args
            ),
        )?;
        api.put(
            "/drives/rootfs",
            &format!(
                r#"{{"drive_id":"rootfs","path_on_host":"{}","is_root_device":true,"is_read_only":false}}"#,
                rootfs.display()
            ),
        )?;
        // allow-all 构建：把 netns 内 tap 接给 FC 作 eth0（guest 侧地址/路由在 run_build_phase 里配）。
        if let Some(n) = net {
            api.put(
                "/network-interfaces/eth0",
                &format!(
                    r#"{{"iface_id":"eth0","host_dev_name":"{}","guest_mac":"{GUEST_MAC}"}}"#,
                    n.tap()
                ),
            )?;
        }
        api.put("/vsock", &format!(r#"{{"guest_cid":{GUEST_CID},"uds_path":"{}"}}"#, vsock.display()))?;
        api.put("/actions", r#"{"action_type":"InstanceStart"}"#)?;

        let mut stream = wait_guest(vsock, &mut child)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("设读超时失败: {e}"))?;
        match request(&mut stream, &Request::Ping { data: "build".into() })? {
            Response::Pong { data } if data == "build" => {}
            other => return Err(format!("Ping 自检失败: {other:?}")),
        }
        Ok((api, stream))
    })();

    match boot {
        Ok((api, stream)) => Ok((child, api, stream)),
        Err(e) => {
            kill_group(&mut child);
            Err(e)
        }
    }
}

// ── guest 侧原语 ─────────────────────────────────────────────────────────

/// 把 `data` 注入 guest `dst`（chmod `mode`）。base64 分块 append 到临时文件再解码——
/// 单条 exec 的 argv 受 ARG_MAX 限，故按 60000B/块拼；busybox 有 base64/printf。
fn inject_file(stream: &mut UnixStream, dst: &str, mode: &str, data: &[u8]) -> Result<(), String> {
    let b64 = base64_encode(data);
    let tmp = format!("{dst}.slb64");
    // 建父目录 + 清临时
    let dir = parent_dir(dst);
    let (c, _, err) = exec(stream, &format!("mkdir -p '{dir}' && rm -f '{tmp}'"))?;
    if c != 0 {
        return Err(format!("建目录/清临时失败: {err}"));
    }
    for chunk in b64.as_bytes().chunks(60_000) {
        let s = std::str::from_utf8(chunk).unwrap(); // base64 恒为 ASCII
        let (c, _, err) = exec(stream, &format!("printf %s '{s}' >> '{tmp}'"))?;
        if c != 0 {
            return Err(format!("写 base64 分块失败: {err}"));
        }
    }
    let (c, _, err) = exec(
        stream,
        &format!("base64 -d '{tmp}' > '{dst}' && chmod {mode} '{dst}' && rm -f '{tmp}'"),
    )?;
    if c != 0 {
        return Err(format!("解码/落盘失败: {err}"));
    }
    Ok(())
}

/// 写 ADR-18 构建期配置到 `/etc/sl-envd/env`（KEY=VALUE 行 + SL_WORKDIR/SL_USER）。
/// 值可含任意字符，故整文件走 inject_file（base64），不做 shell 拼装。
fn write_build_env(
    stream: &mut UnixStream,
    env: &BTreeMap<String, String>,
    workdir: &Option<String>,
    user: &Option<String>,
) -> Result<(), String> {
    if env.is_empty() && workdir.is_none() && user.is_none() {
        return Ok(());
    }
    let mut body = String::from("# sl-envd 构建期环境（ADR-18，sl-node --build 生成）\n");
    for (k, v) in env {
        body.push_str(&format!("{k}={v}\n"));
    }
    if let Some(w) = workdir {
        body.push_str(&format!("SL_WORKDIR={w}\n"));
    }
    if let Some(u) = user {
        body.push_str(&format!("SL_USER={u}\n"));
    }
    inject_file(stream, "/etc/sl-envd/env", "0644", body.as_bytes())
        .map_err(|e| format!("写构建期 env 失败: {e}"))
}

/// D5 不变量：guest 不得已有非空 /etc/machine-id（预置身份会使所有克隆共享，ADR-12）。
fn assert_no_identity(stream: &mut UnixStream, when: &str) -> Result<(), String> {
    let (_, out, _) = exec(stream, "cat /etc/machine-id 2>/dev/null || true")?;
    if !out.trim().is_empty() {
        return Err(format!(
            "D5 违背（{when}）：/etc/machine-id 非空（={:?}）——预烘焙点前禁固定身份，\
             否则克隆共享 machine-id（ADR-12）。请勿在 base/RUN 里预置 machine-id。",
            out.trim()
        ));
    }
    Ok(())
}

// ── 内容寻址 / 输入键 ─────────────────────────────────────────────────────

fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("打开 {} 失败: {e}", path.display()))?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).map_err(|e| format!("哈希 {} 失败: {e}", path.display()))?;
    Ok(h.finalize().into())
}

/// 构建输入键（version 缺省时的来源）：涵盖决定产物的一切输入。与 ADR-16「模板版本×内核×VMM」同旨。
fn compute_build_id(
    tmpl: &Template,
    base_key: &[u8],
    kernel_digest: &[u8; 32],
    vmm_version: &str,
    copies: &[(String, String, Vec<u8>)],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sl-build-id-v1\0");
    h.update(tmpl.name.as_bytes());
    h.update([0]);
    // base_key：Local = 基座 ext4 内容 digest；OCI = source_digest 串（长度不定，先记长度防歧义）。
    h.update((base_key.len() as u64).to_le_bytes());
    h.update(base_key);
    h.update(kernel_digest);
    h.update(vmm_version.as_bytes());
    h.update([0]);
    h.update(tmpl.build_network.as_bytes());
    h.update([0]);
    // vcpu/mem 影响预烘焙快照（mem 文件大小、vmstate），故进版本键——改配置即换版本。
    h.update(tmpl.vcpu.to_le_bytes());
    h.update(tmpl.mem_mib.to_le_bytes());
    for w in &tmpl.whitelist {
        h.update(w.as_bytes());
        h.update([0]);
    }
    for step in &tmpl.run {
        h.update(step.as_bytes());
        h.update([0]);
    }
    for (dst, mode, data) in copies {
        h.update(dst.as_bytes());
        h.update([0]);
        h.update(mode.as_bytes());
        h.update([0]);
        h.update((data.len() as u64).to_le_bytes());
        h.update(data);
    }
    for (k, v) in &tmpl.env {
        h.update(k.as_bytes());
        h.update([b'=']);
        h.update(v.as_bytes());
        h.update([0]);
    }
    for opt in [&tmpl.workdir, &tmpl.user, &tmpl.start_cmd] {
        if let Some(s) = opt {
            h.update(s.as_bytes());
        }
        h.update([0]);
    }
    h.finalize().into()
}

// ── 签名（ed25519）────────────────────────────────────────────────────────

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// 加载 ~/.sandlocker/signing.key（32 裸字节）；缺失则生成并 0600 落盘。
fn load_or_create_key() -> Result<SigningKey, String> {
    let dir = key_dir()?;
    let path = dir.join("signing.key");
    if let Ok(bytes) = std::fs::read(&path) {
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("签名密钥长度非 32 字节: {}", path.display()))?;
        return Ok(SigningKey::from_bytes(&arr));
    }
    // 生成新密钥（复用宿主 CSPRNG：libc getrandom）
    let mut secret = [0u8; 32];
    host_random(&mut secret);
    std::fs::create_dir_all(&dir).map_err(|e| format!("建密钥目录失败: {e}"))?;
    std::fs::write(&path, secret).map_err(|e| format!("写签名密钥失败: {e}"))?;
    set_mode_600(&path);
    let key = SigningKey::from_bytes(&secret);
    eprintln!(
        "[build] 生成新签名密钥 {}（公钥 {}）",
        path.display(),
        hex(&key.verifying_key().to_bytes())
    );
    Ok(key)
}

fn key_dir() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "未设置 HOME，无法定位签名密钥".to_string())?;
    Ok(PathBuf::from(home).join(".sandlocker"))
}

fn set_mode_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

fn sign(key: &SigningKey, msg: &[u8]) -> [u8; 64] {
    key.sign(msg).to_bytes()
}

/// 离线验签（供单测 / 外部工具复用）：pubkey_hex + sig_hex 对 msg 验证。
#[allow(dead_code)]
pub fn verify(pubkey_hex: &str, sig_hex: &str, msg: &[u8]) -> bool {
    let Some(pk) = unhex32(pubkey_hex) else { return false };
    let Some(sig) = unhex64(sig_hex) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify(msg, &Signature::from_bytes(&sig)).is_ok()
}

// ── 小工具 ───────────────────────────────────────────────────────────────

fn validate_name(s: &str, what: &str) -> Result<(), String> {
    if s.is_empty()
        || s.contains('/')
        || s.contains("..")
        || s.contains(char::is_whitespace)
        || s.starts_with('.')
    {
        return Err(format!("{what} 非法（不得含 / .. 空白或以 . 开头）: {s:?}"));
    }
    Ok(())
}

fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => ".".to_string(),
    }
}

fn firecracker_version(fc_bin: &Path) -> String {
    Command::new(fc_bin)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        out.push(B64[b0 >> 2] as char);
        out.push(B64[((b0 & 0x3) << 4) | (b1 >> 4)] as char);
        out.push(if chunk.len() > 1 { B64[((b1 & 0xf) << 2) | (b2 >> 6)] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[b2 & 0x3f] as char } else { '=' });
    }
    out
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let v = unhex(s)?;
    v.as_slice().try_into().ok()
}
fn unhex64(s: &str) -> Option<[u8; 64]> {
    let v = unhex(s)?;
    let a: Result<[u8; 64], _> = v.as_slice().try_into();
    a.ok()
}
fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsl_parse_ok() {
        let t: Template = toml::from_str(
            r#"
            name = "hello"
            from = "base.ext4"
            run = ["echo hi", "true"]
            env = { FOO = "bar", PATH = "/usr/bin" }
            start_cmd = "sleep 999"
            build_network = "deny"
            [[copy]]
            src = "a.txt"
            dst = "/opt/a.txt"
            mode = "0600"
            "#,
        )
        .expect("parse");
        assert_eq!(t.name, "hello");
        assert_eq!(t.run.len(), 2);
        assert_eq!(t.env.get("FOO").unwrap(), "bar");
        assert_eq!(t.copy[0].dst, "/opt/a.txt");
        assert_eq!(t.build_network, "deny");
    }

    #[test]
    fn dsl_default_build_network() {
        let t: Template = toml::from_str(r#"name = "x""#).unwrap();
        assert_eq!(t.build_network, "deny");
        assert!(t.run.is_empty());
    }

    #[test]
    fn dsl_vcpu_mem_default_and_override() {
        // 缺省 = 1 vCPU / 128 MiB（保持既有行为）
        let d: Template = toml::from_str(r#"name = "x""#).unwrap();
        assert_eq!((d.vcpu, d.mem_mib), (1, 128));
        // 可显式调高（大镜像 boot OOM 时）
        let o: Template = toml::from_str("name = \"x\"\nvcpu = 2\nmem_mib = 1024").unwrap();
        assert_eq!((o.vcpu, o.mem_mib), (2, 1024));
    }

    #[test]
    fn net_plan_by_mode_and_root() {
        // deny / whitelist：无论 root 与否都离线
        assert_eq!(net_plan("deny", false).unwrap(), NetPlan::Offline);
        assert_eq!(net_plan("deny", true).unwrap(), NetPlan::Offline);
        assert_eq!(net_plan("whitelist", true).unwrap(), NetPlan::Offline);
        // allow-all：root → 拉出口；非 root → fail-closed（RootRequired）
        assert_eq!(net_plan("allow-all", true).unwrap(), NetPlan::Egress);
        assert_eq!(net_plan("allow-all", false).unwrap(), NetPlan::RootRequired);
        // 未知取值 → Err（DSL 校验也拦，双保险）
        assert!(net_plan("bogus", true).is_err());
    }

    #[test]
    fn build_id_sensitive_to_vcpu_mem() {
        // vcpu/mem 影响预烘焙快照 → 必须进版本键
        let base: Template = toml::from_str(r#"name = "x""#).unwrap();
        let more_mem: Template = toml::from_str("name = \"x\"\nmem_mib = 512").unwrap();
        let more_cpu: Template = toml::from_str("name = \"x\"\nvcpu = 4").unwrap();
        let k = [0u8; 32];
        let id = |t: &Template| compute_build_id(t, b"base", &k, "fc-1", &[]);
        assert_ne!(id(&base), id(&more_mem), "改 mem_mib 应换版本");
        assert_ne!(id(&base), id(&more_cpu), "改 vcpu 应换版本");
    }

    #[test]
    fn dsl_unknown_field_rejected() {
        let e = toml::from_str::<Template>(r#"name = "x"
        bogus = 1"#);
        assert!(e.is_err(), "未知字段应被拒绝");
    }

    #[test]
    fn base64_matches_reference() {
        // 与 RFC 4648 向量对齐（busybox base64 -d 会逆此编码）
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn build_id_deterministic() {
        let t: Template = toml::from_str(r#"name = "x"
        run = ["a", "b"]"#).unwrap();
        let br = [1u8; 32];
        let kd = [2u8; 32];
        let a = compute_build_id(&t, &br, &kd, "fc-1.0", &[]);
        let b = compute_build_id(&t, &br, &kd, "fc-1.0", &[]);
        assert_eq!(a, b, "同输入同 build_id");
        // 改一个输入 → 变
        let t2: Template = toml::from_str(r#"name = "x"
        run = ["a", "c"]"#).unwrap();
        let c = compute_build_id(&t2, &br, &kd, "fc-1.0", &[]);
        assert_ne!(a, c, "输入变则 build_id 变");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let mut secret = [0u8; 32];
        secret[0] = 7;
        secret[31] = 42;
        let key = SigningKey::from_bytes(&secret);
        let pk = hex(&key.verifying_key().to_bytes());
        let msg = b"{\"name\":\"hello\"}";
        let sig = hex(&sign(&key, msg));
        assert!(verify(&pk, &sig, msg), "正确签名应验通过");
        assert!(!verify(&pk, &sig, b"tampered"), "篡改消息应验败");
        // 篡改签名一字节
        let mut bad = sig.clone().into_bytes();
        bad[0] = if bad[0] == b'a' { b'b' } else { b'a' };
        assert!(!verify(&pk, &String::from_utf8(bad).unwrap(), msg), "篡改签名应验败");
    }

    #[test]
    fn validate_name_rules() {
        assert!(validate_name("hello", "name").is_ok());
        assert!(validate_name("v1.2.3", "version").is_ok());
        assert!(validate_name("a/b", "name").is_err());
        assert!(validate_name("..", "name").is_err());
        assert!(validate_name(".hidden", "name").is_err());
        assert!(validate_name("has space", "name").is_err());
        assert!(validate_name("", "name").is_err());
    }

    #[test]
    fn parent_dir_cases() {
        assert_eq!(parent_dir("/opt/a.txt"), "/opt");
        assert_eq!(parent_dir("/a"), "/");
        assert_eq!(parent_dir("rel"), ".");
    }
}
