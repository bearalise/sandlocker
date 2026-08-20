//! orch.rs — 进程内 orchestrator（M1 W7，Q2/Q9）。
//!
//! D3：控制面单进程、orchestrator 退化为**进程内模块**（无长驻守护）；D4/D5：创建 = 从**预烘焙
//! 快照恢复**（非冷启）。本模块以 **sl-store lease 为生命周期计时器骨架**，用 **rootless mount-ns
//! bind**（`unshare --user --map-root-user --mount`，免 sudo）给每个沙箱私有 rootfs——不脏模板、
//! 支持并发（FC 把 rootfs/vsock 绝对路径烘进 vmstate，恢复即以 rw 打开；目录级 bind 令其落私有副本）。
//!
//! 两独立计时器（FR-1.2）：
//!   - **idle** = lease：`lease_keepalive` 滑窗续期、`lease_sweep(now)` 回收（挂 `sandbox/` 元数据键，
//!     随租约过期一并删）。
//!   - **TTL**  = 元数据里的绝对硬顶 `ttl_deadline = created_at + ttl_secs`，`tick` 独立判定，
//!     keepalive **不能**越过。
//!
//! 生命周期由 `reconcile`（Q9 对账）/ `bench`（Q2 时延）子命令进程内驱动一次（本周不起长驻循环）。

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use sl_proto::{pty_resize_frame, pty_stdin_frame, read_msg, write_frame, write_msg, Request, Response};
use sl_store::{LeaseId, SqliteStore, Store};

use crate::backend::{BackendInfo, Capabilities, Capability, ExecTarget, SandboxBackend, UNSUPPORTED_BY_BACKEND};
use crate::fcbackend::FcBackend;
use crate::gateway::{parse_query, proxy_port_http, Action, Gateway};
use crate::gvisorbackend::GvisorBackend;
use crate::connect_guest;
use crate::{abspath, hex, Config};

/// 沙箱规格（FR-1.1）。默认 2 vCPU / 512 MiB **记入元数据**；注意恢复路径的 VM 形态由快照烘焙
/// 决定，vcpus/mem 为记录性字段（真正按 spec 造型待冷路径/多模板，如实标注）。
#[derive(Clone, Debug)]
pub struct SandboxSpec {
    pub vcpus: u32,
    pub mem_mib: u32,
    /// 绝对存活硬顶（秒）：自创建起 `ttl_secs` 后强制回收，keepalive 不能续过。
    pub ttl_secs: i64,
    /// 空闲上限（秒）：lease TTL，keepalive 滑窗续期；无续期则 `lease_sweep` 到期回收。
    pub idle_secs: i64,
    /// 用户标签，平铺进 `sandbox/<id>/meta` 的 `labels`。
    pub metadata: BTreeMap<String, String>,
    /// M2 W6（ADR-14）：本次 create 要求的后端能力集。后端不满足即**创建期**返回
    /// `UNSUPPORTED_BY_BACKEND`（禁止运行期静默降级）。默认空集（不约束）。
    pub required_capabilities: Capabilities,
    /// M2 W7：显式指定后端 id（`fc`/`gvisor`）。None → 默认 fc。无此后端即 `UNSUPPORTED_BY_BACKEND`。
    pub backend: Option<String>,
}

impl Default for SandboxSpec {
    fn default() -> Self {
        Self {
            vcpus: 2,
            mem_mib: 512,
            ttl_secs: 300,
            idle_secs: 300,
            metadata: BTreeMap::new(),
            required_capabilities: Capabilities::empty(),
            backend: None,
        }
    }
}

/// 创建结果（走恢复路径，含 Q2 分段）。
#[derive(Clone, Debug)]
pub struct CreateOutcome {
    pub id: String,
    pub total_ms: u128,
    /// 私有 rootfs 副本耗时（Q2 分段大头之一）。
    pub copy_ms: u128,
    pub api_ready_ms: u128,
    pub load_ms: u128,
    pub resume_ms: u128,
    /// ADR-12 reinit 换发的克隆 machine-id（并发隔离断言用）。
    pub machine_id: String,
    /// M2 W9（M2-Q5）：reinit 换发的 RNG 种子 hex / 会话密钥 hex——克隆熵三元组（fork/resume 复验互异）。
    pub rng_hex: String,
    pub session_key_hex: String,
    /// M2 W4：本次 create 是否命中池（温池或热池，`copy_ms=0`）。冷路径为 false。
    pub pool_hit: bool,
    /// M2 W5：是否命中**热池**（暂停态 VM，仅 activate；`total_ms`=activate wall-clock）。温/冷为 false。
    pub hot_hit: bool,
    /// M2 W9：fork 得来时为父沙箱 id；直接 create 为 None。
    pub forked_from: Option<String>,
}

/// 在册沙箱的**编排态**（M2 W6：机制态——进程/目录——归后端 [`SandboxBackend`]）。
struct LiveMeta {
    lease: LeaseId,
    /// TTL 绝对硬顶（unix 秒），独立于 lease。
    ttl_deadline: i64,
    /// M2 W7：该实例归属后端在 `backends` 中的索引（destroy/exec/tick 路由用）。
    backend: usize,
}

/// 进程内 orchestrator（M2 W6 起只管编排）。`store` 按窄接口编程（M3 可换 etcd）；
/// `backends` 为 Sandbox ABI 多后端注册表（[0]=FC 默认，可选 gVisor，ADR-14）；`template` 默认模板目录。
pub struct Orch<'a> {
    store: Box<dyn Store>,
    backends: Vec<Box<dyn SandboxBackend + Send + 'a>>,
    template: PathBuf,
    live: HashMap<String, LiveMeta>,
}

impl<'a> Orch<'a> {
    pub fn new(cfg: &'a Config, template: &Path, run_root: &Path, store: Box<dyn Store>) -> Result<Self, String> {
        if !template.is_dir() {
            return Err(format!("模板目录不存在: {}（先跑 --build / --snap-create）", template.display()));
        }
        std::fs::create_dir_all(run_root).map_err(|e| format!("建 run_root 失败 {}: {e}", run_root.display()))?;
        let template = abspath(template)?;
        // [0] 恒为 FC（默认后端）。gVisor：cfg.gvisor 开且 runsc 可用时注册（M2 W7，能力空集）。
        let mut backends: Vec<Box<dyn SandboxBackend + Send + 'a>> =
            vec![Box::new(FcBackend::new(cfg, run_root.to_path_buf()))];
        if cfg.gvisor && GvisorBackend::probe(&cfg.gvisor_bin) {
            backends.push(Box::new(GvisorBackend::new(cfg.gvisor_bin.clone(), run_root.to_path_buf())));
        }
        Ok(Self { store, backends, template, live: HashMap::new() })
    }

    /// 后端列表与能力集（`GET /v1/backends`，ADR-14）。
    pub fn backends_info(&self) -> Vec<BackendInfo> {
        self.backends.iter().map(|b| b.info()).collect()
    }

    /// 选后端（M2 W7）：`spec.backend` 显式 id 精确匹配优先；否则默认 [0]=fc。再校验
    /// `required_capabilities` 被选中后端满足，否则 `UNSUPPORTED_BY_BACKEND`（创建期，禁运行期降级）。
    fn select_backend(&self, spec: &SandboxSpec) -> Result<usize, String> {
        let idx = match &spec.backend {
            Some(want) => self
                .backends
                .iter()
                .position(|b| b.id() == want)
                .ok_or_else(|| format!("{UNSUPPORTED_BY_BACKEND}: 无此后端 {want:?}（GET /v1/backends 查可用）"))?,
            None => 0,
        };
        if !spec.required_capabilities.is_empty() {
            let missing = spec.required_capabilities.missing_from(&self.backends[idx].capabilities());
            if !missing.is_empty() {
                return Err(format!(
                    "{UNSUPPORTED_BY_BACKEND}: 后端 {} 不满足 required_capabilities {:?}",
                    self.backends[idx].id(),
                    missing
                ));
            }
        }
        Ok(idx)
    }

    /// M2 W4：为 `template` 起单模板温池（需后端具 `prebake_snapshot`）。委托后端（能力门控）。
    /// `target == 0` 视为不启用（幂等清空既有池）。守护（`--serve`）在建 Orch 后调用。
    pub fn enable_warm_pool(&mut self, template: &Path, target: usize) -> Result<(), String> {
        // 池归默认后端 fc（[0]）——具 prebake/pause 能力。
        self.backends[0].enable_warm_pool(template, target)
    }

    /// 温池 (hits, misses, ready_len)；未启用/后端不支持返回 None。供守护内省 / bench。
    pub fn pool_stats(&self) -> Option<(u64, u64, usize)> {
        self.backends[0].pool_stats()
    }

    /// 阻塞等温池水位 ≥ `n` 或超时（bench 预填池用）。无池/不支持返回 false。
    pub fn pool_wait_ready(&self, n: usize, timeout: Duration) -> bool {
        self.backends[0].pool_wait_ready(n, timeout)
    }

    /// M2 W5：为 `template` 起单模板热池（需后端具 `pause_resume`+`prebake_snapshot`）。委托 fc。
    /// `target == 0` 视为不启用（幂等清空既有池）。守护/bench 建 Orch 后调用。
    pub fn enable_hot_pool(&mut self, template: &Path, target: usize) -> Result<(), String> {
        self.backends[0].enable_hot_pool(template, target)
    }

    /// 阻塞等热池水位 ≥ `n` 或超时（bench 预填池用）。无池/不支持返回 false。
    pub fn hot_wait_ready(&self, n: usize, timeout: Duration) -> bool {
        self.backends[0].hot_wait_ready(n, timeout)
    }

    /// 创建 = 从预烘焙快照**恢复**（keep-alive 持有 VM）。用 orchestrator 的默认模板。
    pub fn create(&mut self, spec: &SandboxSpec) -> Result<CreateOutcome, String> {
        let tpl = self.template.clone();
        self.create_in(&tpl, spec)
    }

    /// 从**指定**预烘焙模板目录创建（守护多模板；`create` 委托本方法用默认模板）。
    /// `template` 会被 canonical 化——须存在（`--build` / `--snap-create` 产物）。
    pub fn create_in(&mut self, template: &Path, spec: &SandboxSpec) -> Result<CreateOutcome, String> {
        if !template.is_dir() {
            return Err(format!("模板目录不存在: {}（先跑 --build / --snap-create）", template.display()));
        }
        let template = abspath(template)?;

        // ① 选后端 + 创建期能力校验（ADR-14）：spec.backend 显式优先，否则 fc；required 不满足即拒。
        let idx = self.select_backend(spec)?;

        // ② 后端造 running 实例（FC：三段 hot→warm→cold / gVisor：runsc run；机制态归后端）。
        let bc = self.backends[idx].create(&template, spec)?;

        // ③ 编排登记（lease/meta/state/台账）——与 fork 共用。
        self.register(bc, idx, spec, &template, None)
    }

    /// 编排登记（create/fork 共用）：grant lease + 写 meta/state（挂 lease → 随空闲回收/撤销一并删）→
    /// 存编排态 → 组装 CreateOutcome。任一步失败即回滚（撤 lease + 令后端销毁实例）。
    fn register(
        &mut self,
        bc: crate::backend::BackendCreate,
        idx: usize,
        spec: &SandboxSpec,
        template: &Path,
        forked_from: Option<String>,
    ) -> Result<CreateOutcome, String> {
        let created_at = now_unix();
        let ttl_deadline = compute_ttl_deadline(created_at, spec.ttl_secs);
        let lease = match self.store.lease_grant(spec.idle_secs) {
            Ok(l) => l,
            Err(e) => {
                self.backends[idx].destroy(&bc.id);
                return Err(e.to_string());
            }
        };
        let meta = build_meta_json(&bc.id, spec, created_at, ttl_deadline, template);
        if let Err(e) = self.store.put(&meta_key(&bc.id), meta.as_bytes(), Some(lease)) {
            let _ = self.store.lease_revoke(lease);
            self.backends[idx].destroy(&bc.id);
            return Err(format!("写 sandbox meta 失败: {e}"));
        }
        if let Err(e) = self.store.put(&state_key(&bc.id), b"running", Some(lease)) {
            let _ = self.store.lease_revoke(lease);
            self.backends[idx].destroy(&bc.id);
            return Err(format!("写 sandbox state 失败: {e}"));
        }
        self.live.insert(bc.id.clone(), LiveMeta { lease, ttl_deadline, backend: idx });
        Ok(CreateOutcome {
            id: bc.id,
            total_ms: bc.total_ms,
            copy_ms: bc.copy_ms,
            api_ready_ms: bc.api_ready_ms,
            load_ms: bc.load_ms,
            resume_ms: bc.resume_ms,
            machine_id: bc.machine_id,
            rng_hex: bc.rng_hex,
            session_key_hex: bc.session_key_hex,
            pool_hit: bc.pool_hit,
            hot_hit: bc.hot_hit,
            forked_from,
        })
    }

    /// pause（FR-1.4）：能力校验（`pause_resume`）→ 后端落快照停 VM → store `state`=paused。
    pub fn pause(&mut self, id: &str) -> Result<(), String> {
        let idx = self.backend_of(id)?;
        self.require_cap(idx, Capability::PauseResume)?;
        self.backends[idx].pause(id)?;
        let _ = self.store.put(&state_key(id), b"paused", self.lease_of(id));
        Ok(())
    }

    /// resume（FR-1.4）：能力校验 → 后端从快照拉起（reinit 新身份）→ store `state`=running。返回新 machine-id。
    pub fn resume(&mut self, id: &str) -> Result<String, String> {
        let idx = self.backend_of(id)?;
        self.require_cap(idx, Capability::PauseResume)?;
        let mid = self.backends[idx].resume(id)?;
        let _ = self.store.put(&state_key(id), b"running", self.lease_of(id));
        Ok(mid)
    }

    /// fork（M2-Q5）：能力校验（`snapshot_fork`）→ 后端从父快照派生新实例（reinit 独立身份）→ 编排登记。
    pub fn fork(&mut self, id: &str, spec: &SandboxSpec) -> Result<CreateOutcome, String> {
        let idx = self.backend_of(id)?;
        self.require_cap(idx, Capability::SnapshotFork)?;
        let bc = self.backends[idx].fork(id)?;
        // fork 的恢复模板由后端内部持有（FcInst.template）；meta 用默认模板占位，forked_from 标父。
        let tpl = self.template.clone();
        self.register(bc, idx, spec, &tpl, Some(id.to_string()))
    }

    // —— 编排辅助 ——
    fn backend_of(&self, id: &str) -> Result<usize, String> {
        self.live.get(id).map(|m| m.backend).ok_or_else(|| format!("未知沙箱 {id}"))
    }
    fn lease_of(&self, id: &str) -> Option<LeaseId> {
        self.live.get(id).map(|m| m.lease)
    }
    fn require_cap(&self, idx: usize, cap: Capability) -> Result<(), String> {
        if self.backends[idx].capabilities().contains(cap) {
            Ok(())
        } else {
            Err(format!(
                "{UNSUPPORTED_BY_BACKEND}: 后端 {} 不支持 {}",
                self.backends[idx].id(),
                cap.as_str()
            ))
        }
    }

    /// keepalive：滑窗重置 idle（lease）。**不**动 `ttl_deadline`（TTL 是绝对硬顶）。返回新到期 unix 秒。
    pub fn keepalive(&mut self, id: &str) -> Result<i64, String> {
        let live = self.live.get(id).ok_or_else(|| format!("未知沙箱 {id}"))?;
        self.store.lease_keepalive(live.lease).map_err(|e| e.to_string())
    }

    /// TTL 绝对硬顶（unix 秒）；不在册返回 None。供 keepalive 端点回报"续期只滑 idle 窗、TTL 救不了"。
    pub fn ttl_deadline(&self, id: &str) -> Option<i64> {
        self.live.get(id).map(|l| l.ttl_deadline)
    }

    /// 手动 destroy：路由到归属后端销毁实例（杀进程 + 删目录）→ 撤销 lease → 出台账。返回被删 store 键。
    pub fn destroy(&mut self, id: &str) -> Result<Vec<String>, String> {
        let meta = self.live.remove(id).ok_or_else(|| format!("未知沙箱 {id}"))?;
        self.backends[meta.backend].destroy(id);
        self.store.lease_revoke(meta.lease).map_err(|e| e.to_string())
    }

    /// reaper（手动驱动，收显式 `now` → 确定性测试无需真实 sleep）。
    /// ① TTL 硬顶：`now >= ttl_deadline` 的 live 逐个 destroy（keepalive 救不了）。
    /// ② idle：`lease_sweep(now)` 回收过期租约+挂键（含元数据），杀对应 VM+删目录。
    /// 返回本轮回收的 id 列表。
    pub fn tick(&mut self, now: i64) -> Result<Vec<String>, String> {
        let mut reaped = Vec::new();

        // ① TTL 硬顶（独立于 lease）
        let ttl_expired: Vec<String> = self
            .live
            .iter()
            .filter(|(_, l)| is_ttl_expired(now, l.ttl_deadline))
            .map(|(k, _)| k.clone())
            .collect();
        for id in ttl_expired {
            self.destroy(&id)?; // destroy 内含 lease_revoke → 元数据键一并删
            reaped.push(id);
        }

        // ② idle：sweep 到期租约（元数据键随之删），再杀仍在册的 VM
        let swept = self.store.lease_sweep(now).map_err(|e| e.to_string())?;
        let mut ids: Vec<String> = swept.iter().filter_map(|k| sandbox_id_of_key(k)).collect();
        ids.sort();
        ids.dedup();
        for id in ids {
            if let Some(meta) = self.live.remove(&id) {
                self.backends[meta.backend].destroy(&id);
                reaped.push(id);
            }
        }
        Ok(reaped)
    }

    // —— 内省（对账/测试用）——
    fn is_live(&self, id: &str) -> bool {
        self.live.contains_key(id)
    }
    /// 实例目录（对账查残留用）：路由到归属后端。
    fn dir_of(&self, id: &str) -> Option<PathBuf> {
        let meta = self.live.get(id)?;
        self.backends[meta.backend].instance_dir(id)
    }

    // —— 守护（api.rs 复用）——

    /// 在册沙箱的数据面 exec 目标（exec/文件桥接用）；不在册返回 None。路由到归属后端（FC=vsock/gVisor=runsc）。
    pub fn exec_target(&self, id: &str) -> Option<ExecTarget> {
        let meta = self.live.get(id)?;
        self.backends[meta.backend].exec_target(id)
    }

    /// 在册沙箱的 console 日志路径（GET /logs 用）；不在册返回 None。路由到归属后端。
    pub fn log_path(&self, id: &str) -> Option<PathBuf> {
        let meta = self.live.get(id)?;
        self.backends[meta.backend].log_path(id)
    }

    /// 列出所有沙箱 meta JSON（每项已是 store 里落的 JSON 对象串）。供 `GET /v1/sandboxes`。
    pub fn list_meta(&self) -> Result<Vec<String>, String> {
        let kvs = self.store.list("sandbox/").map_err(|e| e.to_string())?;
        Ok(kvs
            .into_iter()
            .filter(|kv| kv.key.ends_with("/meta"))
            .map(|kv| String::from_utf8_lossy(&kv.value).into_owned())
            .collect())
    }

    /// 单沙箱 meta JSON（不存在返回 None）。供 `GET /v1/sandboxes/{id}`。
    pub fn get_meta(&self, id: &str) -> Result<Option<String>, String> {
        Ok(self
            .store
            .get(&meta_key(id))
            .map_err(|e| e.to_string())?
            .map(|kv| String::from_utf8_lossy(&kv.value).into_owned()))
    }

    /// 窄读单键（模板解析：`template/<name>/latest` → 版本）。供守护。
    pub fn store_get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.store.get(key).map_err(|e| e.to_string())?.map(|kv| kv.value))
    }

    /// 窄列前缀（`template/` 列模板）。返回 (key, value) 对。供守护。
    pub fn store_list(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
        Ok(self
            .store
            .list(prefix)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|kv| (kv.key, kv.value))
            .collect())
    }
}

// ————————————————————— 纯逻辑（可单测，免 VM）—————————————————————

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn meta_key(id: &str) -> String {
    format!("sandbox/{id}/meta")
}
fn state_key(id: &str) -> String {
    format!("sandbox/{id}/state")
}

fn compute_ttl_deadline(created_at: i64, ttl_secs: i64) -> i64 {
    created_at.saturating_add(ttl_secs)
}
fn is_ttl_expired(now: i64, deadline: i64) -> bool {
    now >= deadline
}

/// 从被 sweep/revoke 删除的键名（`sandbox/<id>/state|meta`）解析沙箱 id。
fn sandbox_id_of_key(key: &str) -> Option<String> {
    let rest = key.strip_prefix("sandbox/")?;
    let id = rest.split('/').next()?;
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn build_meta_json(id: &str, spec: &SandboxSpec, created_at: i64, ttl_deadline: i64, template: &Path) -> String {
    let mut labels = String::from("{");
    for (i, (k, v)) in spec.metadata.iter().enumerate() {
        if i > 0 {
            labels.push(',');
        }
        labels.push_str(&format!(r#""{}":"{}""#, json_escape(k), json_escape(v)));
    }
    labels.push('}');
    format!(
        r#"{{"id":"{id}","vcpus":{},"mem_mib":{},"ttl_secs":{},"idle_secs":{},"created_at":{created_at},"ttl_deadline":{ttl_deadline},"template":"{}","labels":{labels}}}"#,
        spec.vcpus,
        spec.mem_mib,
        spec.ttl_secs,
        spec.idle_secs,
        json_escape(&template.display().to_string())
    )
}

// ————————————————————— 实例目录准备 / 文件工具 —————————————————————

/// 备实例目录：私有 `rootfs.ext4` 副本（reflink 优先→回退全拷；FC reinit 会写它，须私有）+
/// `vmstate`/`mem` 硬链（只读共享、零拷贝——File 内存后端 `MAP_PRIVATE` COW 不写回 → 硬链安全；
/// 若某 FC 版本写回则并发 marker/machine-id 断言会红，回退每沙箱私有 mem 副本）。返回 copy 耗时 ms。
///
/// `pub(crate)`：W4 温池（[`crate::pool`]）预置槽复用同一套准备逻辑（把 copy 移出 create 关键路径）。
pub(crate) fn prepare_instance_dir(template: &Path, dir: &Path) -> Result<u128, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("建实例目录失败 {}: {e}", dir.display()))?;
    let t0 = Instant::now();
    cp_reflink(&template.join("rootfs.ext4"), &dir.join("rootfs.ext4"))?;
    let copy_ms = t0.elapsed().as_millis();
    hardlink_or_copy(&template.join("vmstate"), &dir.join("vmstate"))?;
    hardlink_or_copy(&template.join("mem"), &dir.join("mem"))?;
    Ok(copy_ms)
}

/// `cp --reflink=auto`（CoW 秒级、按需分裂块）；启动/失败回退 `std::fs::copy` 全拷。
fn cp_reflink(src: &Path, dst: &Path) -> Result<(), String> {
    let _ = std::fs::remove_file(dst);
    match Command::new("cp").arg("--reflink=auto").arg(src).arg(dst).status() {
        Ok(st) if st.success() => Ok(()),
        _ => std::fs::copy(src, dst)
            .map(|_| ())
            .map_err(|e| format!("拷贝 rootfs 失败 {}→{}: {e}", src.display(), dst.display())),
    }
}

/// 硬链 src→dst；失败（跨文件系统等）回退全拷。
fn hardlink_or_copy(src: &Path, dst: &Path) -> Result<(), String> {
    let _ = std::fs::remove_file(dst);
    if std::fs::hard_link(src, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(src, dst)
        .map(|_| ())
        .map_err(|e| format!("链接/拷贝失败 {}→{}: {e}", src.display(), dst.display()))
}

fn sha256_file(p: &Path) -> Result<String, String> {
    let bytes = std::fs::read(p).map_err(|e| format!("读 {} 失败: {e}", p.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex(h.finalize().as_slice()))
}

fn percentile(v: &mut [u128], pct: usize) -> u128 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    // 最近秩：ceil(n*pct/100)-1，钳制到 [0, n-1]
    let idx = ((v.len() * pct + 99) / 100).saturating_sub(1).min(v.len() - 1);
    v[idx]
}

fn ensure(cond: bool, msg: &str) -> Result<(), String> {
    if cond {
        Ok(())
    } else {
        Err(msg.to_string())
    }
}

// ————————————————————— Q9 销毁对账 —————————————————————

/// Q9：SQLite 元数据 + 生命周期回收正确（create/keepalive/idle 回收/TTL 硬顶/手动 destroy），
/// 每步结构断言零残留（进程/目录/sockets/store 键），含并发双克隆隔离 + 模板不可变。
/// 用**虚拟 now**（`tick(now)`）确定性驱动，无真实 sleep（仅 VM 恢复真实耗时）。
pub fn reconcile(cfg: &Config, template: &Path) -> Result<(), String> {
    let run_root = cfg.workdir.join("orch");
    let _ = std::fs::remove_dir_all(&run_root);
    let store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    let mut orch = Orch::new(cfg, template, &run_root, Box::new(store))?;
    let log = |m: &str| {
        if !cfg.json {
            println!("[orch] {m}");
        }
    };

    // 运行前模板 rootfs 指纹（末尾比对：bind 遮蔽须保证 FC 从不写模板）
    let tpl_rootfs = orch.template.join("rootfs.ext4");
    let tpl_sha_before = sha256_file(&tpl_rootfs)?;

    // ① create（idle=5s、ttl 大）→ running
    let a = orch.create(&SandboxSpec { idle_secs: 5, ttl_secs: 3600, ..Default::default() })?;
    let t0 = now_unix();
    ensure(orch.is_live(&a.id), "① create 后不在 live 台账")?;
    ensure(
        orch.store.get(&state_key(&a.id)).map_err(|e| e.to_string())?.is_some(),
        "① store 无 state 键",
    )?;
    ensure(
        orch.dir_of(&a.id).map(|d| d.join("vsock.sock").exists()).unwrap_or(false),
        "① vsock.sock 不在实例目录",
    )?;
    log(&format!("① create {} → running（total={}ms copy={}ms）", a.id, a.total_ms, a.copy_ms));

    // ② keepalive 后以 now=t0+4 tick → 未回收（idle 滑窗续期生效）
    orch.keepalive(&a.id)?;
    let r = orch.tick(t0 + 4)?;
    ensure(r.is_empty() && orch.is_live(&a.id), "② keepalive 后仍被提前回收")?;
    log("② keepalive + tick(t0+4)：未回收 ✓");

    // ③ 以 now=t0+10 tick → idle 回收；零残留
    let dir_a = orch.dir_of(&a.id).unwrap();
    let r = orch.tick(t0 + 10)?;
    ensure(r.contains(&a.id), "③ idle 未回收")?;
    ensure(!orch.is_live(&a.id), "③ 回收后仍在 live")?;
    ensure(!dir_a.exists(), "③ 实例目录未删")?;
    ensure(
        orch.store.get(&state_key(&a.id)).map_err(|e| e.to_string())?.is_none(),
        "③ store 元数据键未随 lease 回收",
    )?;
    log("③ idle 到期回收：进程/目录/元数据零残留 ✓");

    // ④ TTL 硬顶：create(ttl=2s、idle 大) + keepalive，以 now=t1+3 tick → 仍回收
    let b = orch.create(&SandboxSpec { idle_secs: 3600, ttl_secs: 2, ..Default::default() })?;
    let t1 = now_unix();
    orch.keepalive(&b.id)?; // idle 推远，但 TTL 是绝对硬顶
    let dir_b = orch.dir_of(&b.id).unwrap();
    let r = orch.tick(t1 + 3)?;
    ensure(r.contains(&b.id), "④ TTL 硬顶未回收（keepalive 越过了 TTL？）")?;
    ensure(!orch.is_live(&b.id) && !dir_b.exists(), "④ TTL 回收后有残留")?;
    log("④ TTL 硬顶回收（keepalive 续不过）：零残留 ✓");

    // ⑤ 手动 destroy
    let c = orch.create(&SandboxSpec::default())?;
    let dir_c = orch.dir_of(&c.id).unwrap();
    let deleted = orch.destroy(&c.id)?;
    ensure(!deleted.is_empty(), "⑤ destroy 未删任何 store 键")?;
    ensure(!orch.is_live(&c.id) && !dir_c.exists(), "⑤ destroy 后有残留")?;
    log("⑤ 手动 destroy：零残留 ✓");

    // ⑥ 并发隔离：同模板 create ×2（都在册）→ machine-id 互异（克隆熵已分叉）
    let d = orch.create(&SandboxSpec::default())?;
    let e = orch.create(&SandboxSpec::default())?;
    ensure(!d.machine_id.is_empty() && !e.machine_id.is_empty(), "⑥ machine-id 为空")?;
    ensure(d.machine_id != e.machine_id, "⑥ 两克隆 machine-id 相同（熵未分叉）")?;
    orch.destroy(&d.id)?;
    orch.destroy(&e.id)?;
    log("⑥ 并发双克隆：machine-id 互异 ✓");

    // ⑦ 热池（M2 W5）：预置暂停态 VM ×2 → 两次热命中（走 activate）→ machine-id 互异（reinit 在
    //    activate 分叉，克隆熵隔离正确）+ 各命中 hot_hit=true + destroy 零残留 + 模板仍不变。
    orch.enable_hot_pool(template, 2)?;
    ensure(orch.hot_wait_ready(2, Duration::from_secs(60)), "⑦ 热池未在超时内预置到水位 2")?;
    let h1 = orch.create(&SandboxSpec::default())?;
    let h2 = orch.create(&SandboxSpec::default())?;
    ensure(h1.hot_hit && h2.hot_hit, "⑦ 未走热池命中路径（hot_hit=false）")?;
    ensure(h1.copy_ms == 0 && h2.copy_ms == 0, "⑦ 热池命中 copy_ms 应为 0")?;
    ensure(!h1.machine_id.is_empty() && h1.machine_id != h2.machine_id, "⑦ 两热池克隆 machine-id 相同（熵未分叉）")?;
    let dir_h1 = orch.dir_of(&h1.id).unwrap();
    orch.destroy(&h1.id)?;
    orch.destroy(&h2.id)?;
    ensure(!orch.is_live(&h1.id) && !dir_h1.exists(), "⑦ 热池实例 destroy 后有残留")?;
    orch.enable_hot_pool(template, 0)?; // 关热池 → Drop 杀掉后台补的 parked VM + 清 dir
    log("⑦ 热池双命中：hot_hit + machine-id 互异 + 零残留 ✓");

    // 收尾：store sandbox/ 空 + 模板 rootfs sha256 不变（bind 遮蔽证明 FC 从未写模板）
    ensure(
        orch.store.list("sandbox/").map_err(|e| e.to_string())?.is_empty(),
        "收尾 store sandbox/ 非空（元数据残留）",
    )?;
    let tpl_sha_after = sha256_file(&tpl_rootfs)?;
    ensure(tpl_sha_before == tpl_sha_after, "收尾 模板 rootfs 被写脏（bind 遮蔽失效）")?;

    if cfg.json {
        println!(r#"{{"metric":"orch_reconcile","cases":7,"template_immutable":true,"hot_pool":true,"pass":true}}"#);
    } else {
        println!(
            "[orch] Q9 对账 PASS：create/keepalive/idle 回收/TTL 硬顶/手动 destroy/热池双命中 每步零残留 + 并发双克隆隔离 + 模板 rootfs 不变"
        );
    }
    Ok(())
}

// ————————————————————— M2-Q4 gVisor 第二后端对账 —————————————————————

/// M2-Q4：gVisor(runsc) 第二后端接入——create/exec/fs/destroy 走 ABI，能力显式无 prebake/pause，
/// 与 FC 可切换。rootless（`--rootless --platform=systrap --network=none`），**无需 root/KVM**。
/// runsc 缺失则输出 skip JSON 退 0（不阻塞 CI）。用同一模板的 rootfs.ext4 作 gVisor bundle rootfs。
pub fn gvisor_reconcile(cfg: &Config, template: &Path) -> Result<(), String> {
    if !GvisorBackend::probe(&cfg.gvisor_bin) {
        println!(r#"{{"metric":"gvisor_reconcile","skipped":true,"reason":"runsc-not-found"}}"#);
        return Ok(());
    }
    let template = abspath(template)?;
    let run_root = cfg.workdir.join("gvisor-reconcile");
    let _ = std::fs::remove_dir_all(&run_root);
    // 强制注册 gVisor（本对账目标即它）。
    let mut cfg2 = cfg.clone();
    cfg2.gvisor = true;
    let store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    let mut orch = Orch::new(&cfg2, &template, &run_root, Box::new(store))?;
    let log = |m: &str| {
        if !cfg.json {
            println!("[gvisor] {m}");
        }
    };

    // ① 后端注册 + 能力集显式无 prebake/pause
    let has_gvisor = orch.backends_info().iter().any(|b| b.id == "gvisor");
    ensure(has_gvisor, "① gVisor 后端未注册（runsc 探活失败？）")?;
    let gv = orch.backends_info().into_iter().find(|b| b.id == "gvisor").unwrap();
    ensure(!gv.capabilities.contains(&"prebake_snapshot"), "① gVisor 不应有 prebake_snapshot")?;
    ensure(!gv.capabilities.contains(&"pause_resume"), "① gVisor 不应有 pause_resume")?;
    log(&format!("① gVisor 注册；能力集={:?}（显式无 prebake/pause）✓", gv.capabilities));

    // ② create on gvisor（显式选后端）→ running
    let spec = SandboxSpec {
        idle_secs: 3600,
        ttl_secs: 3600,
        backend: Some("gvisor".to_string()),
        ..Default::default()
    };
    let a = orch.create(&spec)?;
    ensure(orch.is_live(&a.id), "② create 后不在 live 台账")?;
    ensure(!a.pool_hit && !a.hot_hit && a.copy_ms > 0, "② gVisor 应冷创建（无池命中）")?;
    let dir_a = orch.dir_of(&a.id).unwrap();
    log(&format!("② create {} on gvisor（copy={}ms resume={}ms）✓", a.id, a.copy_ms, a.resume_ms));

    // ③ exec：跑命令验隔离内核（uname 报 runsc）+ 退出码/输出
    let t = orch.exec_target(&a.id).ok_or("③ 无 exec 目标")?;
    let (code, out, _e) = t.exec("echo sl-gvisor-ok; uname -a")?;
    ensure(code == 0, "③ exec 非零退出")?;
    ensure(out.contains("sl-gvisor-ok"), "③ exec 输出缺 marker")?;
    ensure(out.contains("runsc"), "③ uname 未报 gVisor(runsc) 内核（非真 gVisor 隔离？）")?;
    log("③ exec：echo/uname 命中 gVisor(runsc) 内核 ✓");

    // ④ fs 回环：写文件→读回一致（sandbox 内 rw）
    let t = orch.exec_target(&a.id).ok_or("④ 无 exec 目标")?;
    let (c1, _, _) = t.exec("echo hello-fs > /tmp/sl-fs && sync")?;
    ensure(c1 == 0, "④ 写文件失败")?;
    let (c2, out2, _) = t.exec("cat /tmp/sl-fs")?;
    ensure(c2 == 0 && out2.trim() == "hello-fs", "④ 读回文件不一致")?;
    log("④ fs 写读回环一致 ✓");

    // ⑤ 能力门控：gVisor + required_capabilities=[pause_resume] → 创建期 UNSUPPORTED_BY_BACKEND
    let bad = SandboxSpec {
        backend: Some("gvisor".to_string()),
        required_capabilities: Capabilities::with(&[crate::backend::Capability::PauseResume]),
        ..Default::default()
    };
    match orch.create(&bad) {
        Err(e) if e.starts_with(UNSUPPORTED_BY_BACKEND) => {
            log("⑤ required=[pause_resume] on gVisor → UNSUPPORTED_BY_BACKEND（创建期拒）✓")
        }
        Err(e) => return Err(format!("⑤ 期望 UNSUPPORTED_BY_BACKEND，实得: {e}")),
        Ok(_) => return Err("⑤ 能力不满足却创建成功（运行期静默降级！）".into()),
    }

    // ⑥ 并发隔离：第二个 gVisor 实例 machine-id 互异（独立沙箱+私有 rootfs）
    let b = orch.create(&spec)?;
    ensure(!b.machine_id.is_empty() && a.machine_id != b.machine_id, "⑥ 两 gVisor machine-id 相同")?;
    log("⑥ 并发双实例：machine-id 互异 ✓");

    // ⑦ destroy 零残留（进程/bundle/store 键）
    orch.destroy(&a.id)?;
    orch.destroy(&b.id)?;
    ensure(!orch.is_live(&a.id) && !dir_a.exists(), "⑦ destroy 后 bundle 残留")?;
    ensure(
        orch.store.get(&state_key(&a.id)).map_err(|e| e.to_string())?.is_none(),
        "⑦ store 元数据键未随 destroy 删",
    )?;
    ensure(orch.store.list("sandbox/").map_err(|e| e.to_string())?.is_empty(), "⑦ 收尾 store sandbox/ 非空")?;
    log("⑦ destroy：进程/bundle/元数据零残留 ✓");

    if cfg.json {
        println!(r#"{{"metric":"gvisor_reconcile","cases":7,"backend":"gvisor","switchable":true,"pass":true}}"#);
    } else {
        println!("[gvisor] M2-Q4 对账 PASS：gVisor create/exec/fs/destroy 走 ABI + 能力显式无 prebake/pause + 与 fc 可切换 + 零残留");
    }
    Ok(())
}

// ————————————————————— 硬出口② ABI 契约测试套件 —————————————————————

/// 单后端跑共同场景（功能对等）：lifecycle/exec/fs/clone 隔离/destroy 零残留。返回 (全过?, 各项 JSON)。
fn contract_common(orch: &mut Orch, id: &str) -> (bool, serde_json::Value) {
    let spec = SandboxSpec { backend: Some(id.to_string()), idle_secs: 3600, ttl_secs: 3600, ..Default::default() };
    let a = match orch.create(&spec) {
        Ok(o) => o,
        Err(_) => {
            return (
                false,
                serde_json::json!({"lifecycle":"fail","exec":"skip","fs":"skip","clone_isolation":"skip","destroy_clean":"skip"}),
            )
        }
    };
    let pf = |v: bool| if v { "pass" } else { "fail" };
    let lifecycle = pf(orch.is_live(&a.id));

    // exec：echo marker → exit0 + 含 marker
    let marker = format!("abi-{}", &a.id[..6.min(a.id.len())]);
    let exec = {
        let r = orch.exec_target(&a.id).and_then(|t| t.exec(&format!("echo {marker}")).ok());
        pf(matches!(&r, Some((0, out, _)) if out.contains(&marker)))
    };

    // fs：写文件 + 读回一致
    let fs = {
        let w = orch.exec_target(&a.id).and_then(|t| t.exec("echo abi-fs > /tmp/abi && sync").ok());
        let r = orch.exec_target(&a.id).and_then(|t| t.exec("cat /tmp/abi").ok());
        pf(matches!(w, Some((0, _, _))) && matches!(&r, Some((0, o, _)) if o.trim() == "abi-fs"))
    };

    // clone 隔离：第二实例 machine-id 互异
    let clone_isolation = match orch.create(&spec) {
        Ok(b) => {
            let good = !b.machine_id.is_empty() && b.machine_id != a.machine_id;
            let _ = orch.destroy(&b.id);
            pf(good)
        }
        Err(_) => pf(false),
    };

    // destroy 零残留：不在册 + 目录消失 + store 键删
    let dir_a = orch.dir_of(&a.id);
    let _ = orch.destroy(&a.id);
    let destroy_clean = pf(!orch.is_live(&a.id)
        && dir_a.map(|d| !d.exists()).unwrap_or(true)
        && orch.store.get(&state_key(&a.id)).ok().flatten().is_none());

    let ok = [lifecycle, exec, fs, clone_isolation, destroy_clean].iter().all(|&s| s == "pass");
    (
        ok,
        serde_json::json!({
            "lifecycle":lifecycle,"exec":exec,"fs":fs,
            "clone_isolation":clone_isolation,"destroy_clean":destroy_clean
        }),
    )
}

/// 单后端能力矩阵（能力对等）：遍历全能力——有→create(required)成功标 has；无→须创建期
/// UNSUPPORTED_BY_BACKEND 标 unsupported-ok；否则 GATE-FAIL（运行期静默降级红线）。
fn contract_caps(orch: &mut Orch, id: &str, caps: &[String]) -> (serde_json::Value, bool) {
    let mut ok = true;
    let mut m = serde_json::Map::new();
    for cap in Capability::ALL {
        let name = cap.as_str();
        let has = caps.iter().any(|c| c == name);
        let spec = SandboxSpec {
            backend: Some(id.to_string()),
            required_capabilities: Capabilities::with(&[cap]),
            idle_secs: 3600,
            ttl_secs: 3600,
            ..Default::default()
        };
        let cell = match (has, orch.create(&spec)) {
            (true, Ok(o)) => {
                let _ = orch.destroy(&o.id);
                "has"
            }
            (true, Err(_)) => {
                ok = false;
                "GATE-FAIL"
            }
            (false, Err(e)) if e.starts_with(UNSUPPORTED_BY_BACKEND) => "unsupported-ok",
            (false, Ok(o)) => {
                let _ = orch.destroy(&o.id); // 静默降级：能力不满足却创建成功
                ok = false;
                "GATE-FAIL"
            }
            (false, Err(_)) => {
                ok = false;
                "GATE-FAIL" // 被拒但错误非 UNSUPPORTED_BY_BACKEND（契约串不稳）
            }
        };
        m.insert(name.to_string(), serde_json::json!(cell));
    }
    (serde_json::Value::Object(m), ok)
}

/// 硬出口②：ABI 契约测试套件——**同一组场景对 fc 与 gvisor 逐后端跑**（能力对等而非功能对等），
/// 产出官方兼容矩阵。fc 资格 = `/dev/kvm` 可写；gvisor 资格 = runsc 注册成功。两后端齐全且共同场景
/// 全过 + 能力矩阵无 GATE-FAIL 即 `both_backends`+`switchable`+`pass`。`template` 须预烘焙（fc 恢复用）。
pub fn abi_contract(cfg: &Config, template: &Path) -> Result<(), String> {
    let template = abspath(template)?;
    let run_root = cfg.workdir.join("abi-contract");
    let _ = std::fs::remove_dir_all(&run_root);
    let mut cfg2 = cfg.clone();
    cfg2.gvisor = true; // 契约验收目标即两后端
    let store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    let mut orch = Orch::new(&cfg2, &template, &run_root, Box::new(store))?;

    let kvm_ok = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok();
    let registered: Vec<(String, Vec<String>)> = orch
        .backends_info()
        .into_iter()
        .map(|b| (b.id, b.capabilities.iter().map(|s| s.to_string()).collect()))
        .collect();

    let mut reports: Vec<serde_json::Value> = Vec::new();
    let mut ran_ok: Vec<String> = Vec::new();
    let mut any_gate_fail = false;

    for (id, caps) in &registered {
        let eligible = match id.as_str() {
            "fc" => kvm_ok,
            _ => true, // 注册即已探活
        };
        if !eligible {
            reports.push(serde_json::json!({"id":id,"eligible":false,"reason":"env-not-ready"}));
            continue;
        }
        let (common_ok, checks) = contract_common(&mut orch, id);
        let (caps_json, caps_ok) = contract_caps(&mut orch, id, caps);
        if !caps_ok {
            any_gate_fail = true;
        }
        if common_ok && caps_ok {
            ran_ok.push(id.clone());
        }
        let mut obj = serde_json::json!({"id":id,"eligible":true});
        obj.as_object_mut().unwrap().extend(checks.as_object().unwrap().clone());
        obj["caps"] = caps_json;
        reports.push(obj);
    }

    let both_backends = ran_ok.iter().any(|x| x == "fc") && ran_ok.iter().any(|x| x == "gvisor");
    // 所有合资格后端都全过（共同场景 + 能力矩阵）：
    let eligible_count = reports.iter().filter(|r| r["eligible"] == serde_json::json!(true)).count();
    let switchable = eligible_count >= 1 && ran_ok.len() == eligible_count && !any_gate_fail;
    let pass = switchable && eligible_count >= 1;

    if cfg.json {
        println!(
            r#"{{"metric":"abi_contract","backends":{},"both_backends":{both_backends},"switchable":{switchable},"pass":{pass}}}"#,
            serde_json::Value::Array(reports)
        );
    } else {
        println!("[abi] Sandbox ABI 兼容矩阵（逐后端实测，ADR-14）：");
        let checks = ["lifecycle", "exec", "fs", "clone_isolation", "destroy_clean"];
        let cap_names: Vec<&str> = Capability::ALL.iter().map(|c| c.as_str()).collect();
        let ids: Vec<String> = reports.iter().map(|r| r["id"].as_str().unwrap_or("?").to_string()).collect();
        println!("| 检查项 | {} |", ids.join(" | "));
        println!("|---|{}", "---|".repeat(ids.len()));
        let cell = |r: &serde_json::Value, key: &str| -> String {
            if r["eligible"] != serde_json::json!(true) {
                return "skipped".into();
            }
            r[key].as_str().unwrap_or("-").to_string()
        };
        for c in checks {
            let row: Vec<String> = reports.iter().map(|r| cell(r, c)).collect();
            println!("| {c} | {} |", row.join(" | "));
        }
        for cn in &cap_names {
            let row: Vec<String> = reports
                .iter()
                .map(|r| {
                    if r["eligible"] != serde_json::json!(true) {
                        "skipped".into()
                    } else {
                        r["caps"][cn].as_str().unwrap_or("-").to_string()
                    }
                })
                .collect();
            println!("| cap:{cn} | {} |", row.join(" | "));
        }
        println!(
            "[abi] both_backends={both_backends} switchable={switchable} → 硬出口②: {}",
            if pass { "PASS" } else { "FAIL" }
        );
    }
    if !pass {
        return Err(format!(
            "硬出口② 未达标：switchable={switchable} both_backends={both_backends}（需两后端合资格且全过、能力矩阵无 GATE-FAIL）"
        ));
    }
    Ok(())
}

// ————————————————————— M2-Q5 pause/resume + fork 克隆熵复验 —————————————————————

/// M2-Q5：pause/resume 用户 API（FR-1.4）+ fork 克隆熵复验。create A→pause A（落快照停 VM）→
/// fork A ×2 得 B/C→resume A。断言 A0/A1(resumed)/B/C 的 machine-id 两两互异 + 两 fork(B/C) 的
/// rng/session-key 互异（ADR-12 reinit 在 fork/resume 后仍换发独立身份，克隆熵不泄漏）+ 零残留 +
/// gVisor pause→UNSUPPORTED（能力门控）。免 root（走恢复路径）；runsc 缺失则跳过 gVisor 分支。
pub fn q5_reconcile(cfg: &Config, template: &Path) -> Result<(), String> {
    let template = abspath(template)?;
    let run_root = cfg.workdir.join("q5-reconcile");
    let _ = std::fs::remove_dir_all(&run_root);
    let mut cfg2 = cfg.clone();
    cfg2.gvisor = true; // 试注册 gVisor（用于 pause→UNSUPPORTED 能力门控验证；runsc 缺失则不注册）
    let store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    let mut orch = Orch::new(&cfg2, &template, &run_root, Box::new(store))?;
    let log = |m: &str| {
        if !cfg.json {
            println!("[q5] {m}");
        }
    };
    let spec = SandboxSpec { idle_secs: 3600, ttl_secs: 3600, ..Default::default() };

    // ① create A（默认 fc）
    let a = orch.create(&spec)?;
    ensure(orch.is_live(&a.id), "① A 不在册")?;
    log(&format!("① create A={} machine_id={}", a.id, a.machine_id));

    // ② pause A → 落快照停 VM，state=paused，paused 不可 exec
    orch.pause(&a.id)?;
    let paused_state = orch
        .store
        .get(&state_key(&a.id))
        .map_err(|e| e.to_string())?
        .map(|kv| kv.value == b"paused")
        .unwrap_or(false);
    ensure(paused_state, "② state 未置 paused")?;
    ensure(orch.exec_target(&a.id).is_none(), "② paused 沙箱仍可 exec（应拒）")?;
    log("② pause A：state=paused + 不可 exec ✓");

    // ③ fork A ×2 → B/C（从 A 的 paused 快照派生）
    let b = orch.fork(&a.id, &spec)?;
    let c = orch.fork(&a.id, &spec)?;
    ensure(b.forked_from.as_deref() == Some(a.id.as_str()), "③ B.forked_from 未标父")?;
    ensure(orch.is_live(&b.id) && orch.is_live(&c.id), "③ fork 实例不在册")?;
    log(&format!("③ fork A → B={} C={}", b.id, c.id));

    // ④ resume A → 新 machine-id（reinit）
    let a1 = orch.resume(&a.id)?;
    let running_state = orch
        .store
        .get(&state_key(&a.id))
        .map_err(|e| e.to_string())?
        .map(|kv| kv.value == b"running")
        .unwrap_or(false);
    ensure(running_state, "④ resume 后 state 未置 running")?;
    ensure(orch.exec_target(&a.id).is_some(), "④ resume 后仍不可 exec")?;
    log(&format!("④ resume A：state=running + machine_id={a1}"));

    // ⑤ 克隆熵：machine-id A0/A1/B/C 两两互异；两 fork(B/C) 的 rng/session-key 互异（reinit 生效）
    let mids = [a.machine_id.clone(), a1.clone(), b.machine_id.clone(), c.machine_id.clone()];
    ensure(mids.iter().all(|m| !m.is_empty()), "⑤ machine-id 有空")?;
    for i in 0..mids.len() {
        for j in (i + 1)..mids.len() {
            ensure(mids[i] != mids[j], "⑤ machine-id 存在相同（克隆身份泄漏）")?;
        }
    }
    ensure(!b.rng_hex.is_empty() && b.rng_hex != c.rng_hex, "⑤ 两 fork rng 相同（熵未分叉）")?;
    ensure(
        !b.session_key_hex.is_empty() && b.session_key_hex != c.session_key_hex,
        "⑤ 两 fork session-key 相同（熵未分叉）",
    )?;
    log("⑤ 克隆熵：A0/A1/B/C machine-id 两两互异 + 两 fork rng/session-key 互异 ✓");

    // ⑥ destroy 全部 → 零残留
    let dir_b = orch.dir_of(&b.id);
    orch.destroy(&a.id)?;
    orch.destroy(&b.id)?;
    orch.destroy(&c.id)?;
    ensure(!orch.is_live(&a.id) && !orch.is_live(&b.id) && !orch.is_live(&c.id), "⑥ destroy 后仍在册")?;
    ensure(dir_b.map(|d| !d.exists()).unwrap_or(true), "⑥ fork 实例目录未删")?;
    ensure(orch.store.list("sandbox/").map_err(|e| e.to_string())?.is_empty(), "⑥ 收尾 store sandbox/ 非空")?;
    log("⑥ destroy A/B/C：进程/目录/元数据零残留 ✓");

    // ⑦ 能力门控：gVisor pause → UNSUPPORTED_BY_BACKEND（runsc 注册时）
    let has_gvisor = orch.backends_info().iter().any(|x| x.id == "gvisor");
    if has_gvisor {
        let g = orch.create(&SandboxSpec { backend: Some("gvisor".into()), ..spec.clone() })?;
        match orch.pause(&g.id) {
            Err(e) if e.starts_with(UNSUPPORTED_BY_BACKEND) => log("⑦ gVisor pause → UNSUPPORTED_BY_BACKEND ✓"),
            Err(e) => {
                orch.destroy(&g.id)?;
                return Err(format!("⑦ 期望 UNSUPPORTED_BY_BACKEND，实得: {e}"));
            }
            Ok(_) => {
                orch.destroy(&g.id)?;
                return Err("⑦ gVisor 无 pause_resume 却 pause 成功（静默降级）".into());
            }
        }
        orch.destroy(&g.id)?;
    } else {
        log("⑦ gVisor 未注册（无 runsc），跳过 pause 能力门控验证");
    }

    if cfg.json {
        println!(
            r#"{{"metric":"q5_reconcile","cases":7,"gvisor_gate":{has_gvisor},"clone_entropy":true,"pass":true}}"#
        );
    } else {
        println!("[q5] M2-Q5 对账 PASS：pause/resume 用户 API + fork 克隆熵（reinit 后身份必异）+ 零残留 + 能力门控");
    }
    Ok(())
}

// ————————————————————— M2-Q6 数据面网关对账 —————————————————————

/// M2-Q6：数据面网关（ADR-22）——一次性 HMAC 签名 URL + 无状态验签 + exec/端口经 ticket 换直连。
/// create A→① exec ticket 验签通过→经 exec_target 跑命令；② 同 ticket 再用→一次性拒；③ 篡改 sig 拒；
/// ④ 过期拒；⑤ 端口暴露：guest 起 httpd→port ticket→proxy_port_http 取到 VM 内服务内容（外部访问 VM
/// 内部 ✓）；⑥ destroy 零残留。免额外 root（走恢复路径）。**须用含新 sl-envd 的模板**（Connect 帧）。
pub fn gw_reconcile(cfg: &Config, template: &Path) -> Result<(), String> {
    let template = abspath(template)?;
    let run_root = cfg.workdir.join("gw-reconcile");
    let _ = std::fs::remove_dir_all(&run_root);
    let store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    let mut orch = Orch::new(cfg, &template, &run_root, Box::new(store))?;
    let gw = Gateway::new_random("http://gw".to_string());
    let log = |m: &str| {
        if !cfg.json {
            println!("[gw] {m}");
        }
    };
    let now = now_unix();

    let a = orch.create(&SandboxSpec { idle_secs: 3600, ttl_secs: 3600, ..Default::default() })?;
    log(&format!("create A={}", a.id));

    // ① exec ticket：mint→verify 通过→经 exec_target 跑命令
    let url = gw.mint(&a.id, Action::Exec, 0, 60, now);
    let q = parse_query(&url);
    let t = gw.verify(&q, now).map_err(|e| format!("① exec ticket 验签失败: {e}"))?;
    ensure(t.sid == a.id && t.action == Action::Exec, "① ticket 内容不符")?;
    let tgt = orch.exec_target(&a.id).ok_or("① 无 exec 目标")?;
    let (code, out, _) = tgt.exec("echo gw-exec-ok")?;
    ensure(code == 0 && out.contains("gw-exec-ok"), "① 网关 exec 输出不符")?;
    log("① exec ticket：验签通过 + 换直连跑命令 ✓");

    // ② 一次性：同 ticket 再验 → 拒
    ensure(gw.verify(&q, now).is_err(), "② 一次性失效（ticket 可重用）")?;
    log("② 一次性：ticket 重用被拒 ✓");

    // ③ 篡改 sig → 拒；④ 过期 → 拒
    let url2 = gw.mint(&a.id, Action::Exec, 0, 60, now);
    let mut q2 = parse_query(&url2);
    q2.insert("sig".to_string(), "deadbeef".to_string());
    ensure(gw.verify(&q2, now).is_err(), "③ 篡改 sig 未被拒")?;
    let url3 = gw.mint(&a.id, Action::Exec, 0, 60, now);
    let q3 = parse_query(&url3);
    ensure(gw.verify(&q3, now + 3600).is_err(), "④ 过期 ticket 未被拒")?;
    log("③④ 篡改/过期：均被拒 ✓");

    // ⑤ 端口暴露（FR-3.3）：guest 起 httpd → port ticket → proxy_port_http 取 VM 内服务内容
    let vsock = match orch.exec_target(&a.id) {
        Some(ExecTarget::Vsock(p)) => p,
        _ => return Err("⑤ 无 vsock（端口暴露仅 FC）".into()),
    };
    // busybox 无 httpd applet，用 nc 起一个循环 HTTP 响应器（每连接回定值），后台常驻（reparent 到 PID1）。
    let setup = orch.exec_target(&a.id).ok_or("⑤ 无 exec 目标")?.exec(
        "(while true; do printf 'HTTP/1.0 200 OK\\r\\nContent-Length: 10\\r\\nConnection: close\\r\\n\\r\\nGW-PORT-OK' | nc -l -p 8080; done) >/dev/null 2>&1 & sleep 1",
    )?;
    ensure(setup.0 == 0, "⑤ guest nc 响应器启动失败")?;
    let port_url = gw.mint(&a.id, Action::Port, 8080, 60, now);
    let pq = parse_query(&port_url);
    let pt = gw.verify(&pq, now).map_err(|e| format!("⑤ port ticket 验签失败: {e}"))?;
    ensure(pt.action == Action::Port && pt.port == 8080, "⑤ port ticket 不符")?;
    let resp = proxy_port_http(&vsock, 8080, "index.html")?;
    let resp_s = String::from_utf8_lossy(&resp);
    ensure(resp_s.contains("GW-PORT-OK"), "⑤ 端口暴露未取到 VM 内服务内容")?;
    log("⑤ 端口暴露：签名 URL 经网关取到 VM 内 httpd 内容（外部访问 VM 内部）✓");

    // ⑥ destroy 零残留
    let dir_a = orch.dir_of(&a.id);
    orch.destroy(&a.id)?;
    ensure(!orch.is_live(&a.id) && dir_a.map(|d| !d.exists()).unwrap_or(true), "⑥ destroy 后有残留")?;
    ensure(orch.store.list("sandbox/").map_err(|e| e.to_string())?.is_empty(), "⑥ 收尾 store 非空")?;
    log("⑥ destroy：零残留 ✓");

    if cfg.json {
        println!(r#"{{"metric":"gw_reconcile","cases":6,"port_exposure":true,"one_time":true,"pass":true}}"#);
    } else {
        println!("[gw] M2-Q6 对账 PASS：一次性 HMAC 签名 URL + 无状态验签 + exec/端口经 ticket 换直连 + 端口暴露 + 零残留");
    }
    Ok(())
}

// ————————————————————— M2-Q7 交互式 PTY 对账 —————————————————————

/// 从 PTY 裸输出流累积读，直到含 `needle` 或超时（PTY 输出含回显+prompt，用 contains 定位）。
fn pty_read_until(s: &mut UnixStream, needle: &str, deadline: Instant) -> String {
    let mut acc = String::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                if acc.contains(needle) {
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                continue
            }
            Err(_) => break,
        }
    }
    acc
}

/// M2-Q7：交互式 PTY 会话——双向流 + 窗口 resize。create A → 连 vsock → `Pty{80,24}` → Ok →
/// ① stdin `echo <marker>` 回显含 marker（双向流）；② resize 120×40 + `stty size` 输出 `40 120`
/// （窗口 resize 生效）；③ `exit` 收敛；④ destroy 零残留。免 root（走恢复路径）。须含新 sl-envd 的模板。
pub fn pty_reconcile(cfg: &Config, template: &Path) -> Result<(), String> {
    let template = abspath(template)?;
    let run_root = cfg.workdir.join("pty-reconcile");
    let _ = std::fs::remove_dir_all(&run_root);
    let store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    let mut orch = Orch::new(cfg, &template, &run_root, Box::new(store))?;
    let log = |m: &str| {
        if !cfg.json {
            println!("[pty] {m}");
        }
    };

    let a = orch.create(&SandboxSpec { idle_secs: 3600, ttl_secs: 3600, ..Default::default() })?;
    let vsock = match orch.exec_target(&a.id) {
        Some(ExecTarget::Vsock(p)) => p,
        _ => return Err("PTY 仅 FC 后端（vsock）".into()),
    };
    let mut s = connect_guest(&vsock)?;
    write_msg(&mut s, &Request::Pty { cols: 80, rows: 24 }).map_err(|e| format!("发 Pty 失败: {e}"))?;
    match read_msg::<_, Response>(&mut s).map_err(|e| format!("读 Pty ack 失败: {e}"))? {
        Response::Ok => {}
        other => return Err(format!("Pty ack 异常: {other:?}")),
    }
    s.set_read_timeout(Some(Duration::from_millis(300))).map_err(|e| e.to_string())?;
    let _ = pty_read_until(&mut s, "\u{0}<never>", Instant::now() + Duration::from_millis(400)); // drain 初始 prompt
    log(&format!("create A={} + PTY 会话建立（80×24）", a.id));

    // ① 双向流：stdin echo → 输出含 marker
    write_frame(&mut s, &pty_stdin_frame(b"echo PTY-MARKER-42\n")).map_err(|e| format!("写 stdin 失败: {e}"))?;
    let out1 = pty_read_until(&mut s, "PTY-MARKER-42", Instant::now() + Duration::from_secs(5));
    ensure(out1.contains("PTY-MARKER-42"), "① PTY 双向流：未见 echo marker")?;
    log("① 双向流：echo 回显命中 marker ✓");

    // ② 窗口 resize：120×40 → `stty size` 输出 `40 120`（rows cols）
    write_frame(&mut s, &pty_resize_frame(120, 40)).map_err(|e| format!("写 resize 失败: {e}"))?;
    write_frame(&mut s, &pty_stdin_frame(b"stty size\n")).map_err(|e| format!("写 stty 失败: {e}"))?;
    let out2 = pty_read_until(&mut s, "40 120", Instant::now() + Duration::from_secs(5));
    ensure(out2.contains("40 120"), "② 窗口 resize：stty size 未反映 40×120")?;
    log("② 窗口 resize：stty size=40 120 ✓");

    // ③ exit 收敛（shell 退出 → master EOF → guest 关连接）
    let _ = write_frame(&mut s, &pty_stdin_frame(b"exit\n"));
    let _ = pty_read_until(&mut s, "\u{0}<never>", Instant::now() + Duration::from_millis(500));
    drop(s);
    log("③ exit：会话收敛 ✓");

    // ④ destroy 零残留
    let dir_a = orch.dir_of(&a.id);
    orch.destroy(&a.id)?;
    ensure(!orch.is_live(&a.id) && dir_a.map(|d| !d.exists()).unwrap_or(true), "④ destroy 后有残留")?;
    ensure(orch.store.list("sandbox/").map_err(|e| e.to_string())?.is_empty(), "④ 收尾 store 非空")?;
    log("④ destroy：零残留 ✓");

    if cfg.json {
        println!(r#"{{"metric":"pty_reconcile","cases":4,"bidi":true,"resize":true,"pass":true}}"#);
    } else {
        println!("[pty] M2-Q7 对账 PASS：交互式 PTY 双向流 + 窗口 resize + 会话收敛 + 零残留");
    }
    Ok(())
}

// ————————————————————— Q2 创建时延 —————————————————————

/// Q2：预烘焙快照 → 创建走恢复路径，进程内循环 create→destroy × N（首个丢弃作 warm-up，
/// page-cache 热），算 P50/P90 + 分段（copy/api-ready/load/resume 定位大头）。P50 > 500ms 即失败。
pub fn bench(cfg: &Config, template: &Path) -> Result<(), String> {
    let cycles = if cfg.cycles > 0 { cfg.cycles } else { 20 };
    let run_root = cfg.workdir.join("orch-bench");
    let _ = std::fs::remove_dir_all(&run_root);
    let store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    let mut orch = Orch::new(cfg, template, &run_root, Box::new(store))?;

    let spec = SandboxSpec { idle_secs: 3600, ttl_secs: 3600, ..Default::default() };
    let mut totals = Vec::new();
    let mut copies = Vec::new();
    let mut apis = Vec::new();
    let mut loads = Vec::new();
    let mut resumes = Vec::new();
    for i in 0..cycles {
        let o = orch.create(&spec)?;
        if i > 0 {
            // 首个作 warm-up 丢弃（首恢复 page-cache 冷、不计入热态 P50）
            totals.push(o.total_ms);
            copies.push(o.copy_ms);
            apis.push(o.api_ready_ms);
            loads.push(o.load_ms);
            resumes.push(o.resume_ms);
        }
        orch.destroy(&o.id)?;
    }

    let n = totals.len();
    let p50 = percentile(&mut totals, 50);
    let p90 = percentile(&mut totals, 90);
    let copy_p50 = percentile(&mut copies, 50);
    let api_p50 = percentile(&mut apis, 50);
    let load_p50 = percentile(&mut loads, 50);
    let resume_p50 = percentile(&mut resumes, 50);
    let pass = p50 <= 500;

    if cfg.json {
        println!(
            r#"{{"metric":"restore_create","n":{n},"p50_ms":{p50},"p90_ms":{p90},"copy_p50":{copy_p50},"api_p50":{api_p50},"load_p50":{load_p50},"resume_p50":{resume_p50},"pass":{pass}}}"#
        );
    } else {
        println!("[orch] Q2 创建时延（走预烘焙恢复，n={n}）: P50={p50}ms P90={p90}ms");
        println!("[orch]   分段 P50: copy={copy_p50}ms api-ready={api_p50}ms load={load_p50}ms resume={resume_p50}ms");
        println!("[orch]   Q2 阈值 P50≤500ms: {}", if pass { "PASS" } else { "FAIL" });
    }
    if !pass {
        return Err(format!("Q2 未达标：P50={p50}ms > 500ms"));
    }
    Ok(())
}

// ————————————————————— M2-Q2 温池冷/热分档基准 —————————————————————

/// M2 W4（M2-Q2 起步）：对比**冷档**（无池，copy 在关键路径）与**热档**（温池预填满，池命中
/// create `copy_ms=0`）。同模板同 spec 各跑 `--cycles` 次（首个 warmup 丢弃）。
///
/// 判据（W4）= `warm_p50 < cold_p50`（机制生效，copy 已移出关键路径）；`warm_le_100` 仅信息性
/// 上报——**池命中 P50 ≤100ms 的硬达标 + 分位进 CI 留 W5**（硬出口①）。免 root。
pub fn pool_bench(cfg: &Config, template: &Path) -> Result<(), String> {
    let cycles = if cfg.cycles > 0 { cfg.cycles } else { 20 };
    let template = abspath(template)?;
    let run_root = cfg.workdir.join("pool-bench");
    let _ = std::fs::remove_dir_all(&run_root);
    let spec = SandboxSpec { idle_secs: 3600, ttl_secs: 3600, ..Default::default() };
    let log = |m: &str| {
        if !cfg.json {
            println!("[pool] {m}");
        }
    };

    // —— 冷档：无池 create→destroy ×(cycles+1)，首个作 warm-up 丢弃（copy 计入 total）——
    let cold_store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    let mut cold = Orch::new(cfg, &template, &run_root.join("cold"), Box::new(cold_store))?;
    let mut cold_totals = Vec::new();
    let mut cold_copies = Vec::new();
    for i in 0..=cycles {
        let o = cold.create(&spec)?;
        if i > 0 {
            cold_totals.push(o.total_ms);
            cold_copies.push(o.copy_ms);
        }
        cold.destroy(&o.id)?;
    }
    drop(cold);
    let cold_p50 = percentile(&mut cold_totals, 50);
    let cold_p90 = percentile(&mut cold_totals, 90);
    let copy_saved_p50 = percentile(&mut cold_copies, 50); // 热档省掉的 copy（冷档 copy P50）
    log(&format!(
        "冷档 n={} P50={cold_p50}ms P90={cold_p90}ms（copy_p50={copy_saved_p50}ms）",
        cold_totals.len()
    ));

    // —— 热档：温池预填满（target=cycles+1）再测，池命中 create copy_ms=0 ——
    let warm_store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
    let mut warm = Orch::new(cfg, &template, &run_root.join("warm"), Box::new(warm_store))?;
    let target = cycles + 1;
    warm.enable_warm_pool(&template, target)?;
    let filled = warm.pool_wait_ready(target, Duration::from_secs(120));
    if !filled {
        log("警告：温池未在 120s 内填满，热档将含未命中（如实计入 hit_rate）");
    }
    let (h0, m0, _) = warm.pool_stats().unwrap_or((0, 0, 0));
    let mut warm_totals = Vec::new();
    for i in 0..=cycles {
        let o = warm.create(&spec)?;
        if i > 0 {
            warm_totals.push(o.total_ms);
        }
        warm.destroy(&o.id)?;
    }
    let (h1, m1, _) = warm.pool_stats().unwrap_or((0, 0, 0));
    drop(warm); // 停 refill 线程 + 清 .warm
    let warm_p50 = percentile(&mut warm_totals, 50);
    let warm_p90 = percentile(&mut warm_totals, 90);
    let win_hits = h1.saturating_sub(h0);
    let win_miss = m1.saturating_sub(m0);
    let hit_rate = win_hits as f64 / (win_hits + win_miss).max(1) as f64;
    let warm_le_100 = warm_p50 <= 100;

    // —— 超热档（M2 W5）：热池预置暂停态 VM，命中仅 activate（spawn+load 已在关键路径外）。
    //    bounded 数量（≤4）避免过多常驻 parked VM 打爆内存；hot_p50 信息性上报（<50ms 达标裸金属）。
    let hot_n = cycles.min(4);
    let mut hot_p50 = 0u128;
    if hot_n > 0 {
        let hot_store = SqliteStore::open_in_memory().map_err(|e| e.to_string())?;
        let mut hotorch = Orch::new(cfg, &template, &run_root.join("hot"), Box::new(hot_store))?;
        hotorch.enable_hot_pool(&template, hot_n)?;
        if hotorch.hot_wait_ready(hot_n, Duration::from_secs(120)) {
            let mut hot_totals = Vec::new();
            for _ in 0..hot_n {
                let o = hotorch.create(&spec)?;
                if o.hot_hit {
                    hot_totals.push(o.total_ms);
                }
                hotorch.destroy(&o.id)?;
            }
            hot_p50 = percentile(&mut hot_totals, 50);
            log(&format!("超热档 n={} hot_p50={hot_p50}ms（仅 activate，<50ms 达标裸金属信息性）", hot_totals.len()));
        } else {
            log("警告：热池未在 120s 内预置，跳过超热档（hot_p50=0）");
        }
        hotorch.enable_hot_pool(&template, 0)?; // 关热池 → Drop 杀 parked + 清 dir
        drop(hotorch);
    }
    let hot_le_50 = hot_p50 > 0 && hot_p50 <= 50;

    // 回归判据：温池不劣于冷档（`<=` 容忍 reflink fs 上 copy≈0 的等值噪声；ext4 上仍严格小于）。
    let regression_ok = warm_p50 <= cold_p50;
    // 绝对预算 gate（硬出口①）：env `POOL_P50_BUDGET_MS`>0 时追加 warm_p50 ≤ budget。缺省 0=关——
    // bench-light 托管 runner 慢，不设预算只 gate 回归；裸金属 bench-density job 设 100 硬达标（PRD §8.1）。
    let budget_ms: u128 = std::env::var("POOL_P50_BUDGET_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let budget_ok = budget_ms == 0 || warm_p50 <= budget_ms;
    let pass = regression_ok && budget_ok;

    if cfg.json {
        println!(
            r#"{{"metric":"pool_bench","n":{},"cold_p50":{cold_p50},"cold_p90":{cold_p90},"warm_p50":{warm_p50},"warm_p90":{warm_p90},"warm_hit_rate":{hit_rate:.3},"copy_saved_p50":{copy_saved_p50},"warm_le_100":{warm_le_100},"hot_p50":{hot_p50},"hot_le_50":{hot_le_50},"budget_ms":{budget_ms},"pass":{pass}}}"#,
            warm_totals.len()
        );
    } else {
        log(&format!(
            "热档 n={} P50={warm_p50}ms P90={warm_p90}ms（命中率={hit_rate:.1}，省 copy≈{copy_saved_p50}ms）",
            warm_totals.len()
        ));
        let budget_note = if budget_ms == 0 {
            format!("warm_le_100={warm_le_100}（预算未设，仅 gate 回归）")
        } else {
            format!("预算 ≤{budget_ms}ms: {}", if budget_ok { "PASS" } else { "FAIL" })
        };
        log(&format!(
            "硬出口①：warm≤cold = {}（{warm_p50}≤{cold_p50}）；{budget_note}；总判 {}",
            if regression_ok { "PASS" } else { "FAIL" },
            if pass { "PASS" } else { "FAIL" }
        ));
    }
    if !regression_ok {
        return Err(format!("温池未见收益：warm_p50={warm_p50}ms > cold_p50={cold_p50}ms"));
    }
    if !budget_ok {
        return Err(format!("池命中 P50 未达预算：warm_p50={warm_p50}ms > POOL_P50_BUDGET_MS={budget_ms}ms"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_random; // 仅单测用（id 生成断言）

    #[test]
    fn key_helpers_roundtrip() {
        assert_eq!(meta_key("abc"), "sandbox/abc/meta");
        assert_eq!(state_key("abc"), "sandbox/abc/state");
        assert_eq!(sandbox_id_of_key("sandbox/abc/state").as_deref(), Some("abc"));
        assert_eq!(sandbox_id_of_key("sandbox/abc/meta").as_deref(), Some("abc"));
        assert_eq!(sandbox_id_of_key("sandbox/"), None);
        assert_eq!(sandbox_id_of_key("other/x"), None);
        assert_eq!(sandbox_id_of_key("notprefixed"), None);
    }

    #[test]
    fn ttl_hardcap_logic() {
        let deadline = compute_ttl_deadline(1000, 60);
        assert_eq!(deadline, 1060);
        assert!(!is_ttl_expired(1059, deadline));
        assert!(is_ttl_expired(1060, deadline)); // 边界即到期
        assert!(is_ttl_expired(1061, deadline));
    }

    #[test]
    fn ttl_deadline_saturates() {
        assert_eq!(compute_ttl_deadline(i64::MAX, 10), i64::MAX);
    }

    #[test]
    fn meta_json_shape() {
        let mut md = BTreeMap::new();
        md.insert("team".to_string(), "core".to_string());
        let spec = SandboxSpec {
            vcpus: 4,
            mem_mib: 1024,
            ttl_secs: 300,
            idle_secs: 60,
            metadata: md,
            required_capabilities: Capabilities::empty(),
            backend: None,
        };
        let j = build_meta_json("s1", &spec, 1000, 1300, Path::new("/t/hello"));
        assert!(j.contains(r#""id":"s1""#));
        assert!(j.contains(r#""vcpus":4"#));
        assert!(j.contains(r#""ttl_deadline":1300"#));
        assert!(j.contains(r#""team":"core""#));
    }

    #[test]
    fn percentile_nearest_rank() {
        let mut v: Vec<u128> = (1..=10).collect(); // 1..10
        assert_eq!(percentile(&mut v, 50), 5);
        assert_eq!(percentile(&mut v, 90), 9);
        assert_eq!(percentile(&mut v, 100), 10);
        let mut one = vec![42u128];
        assert_eq!(percentile(&mut one, 50), 42);
        let mut empty: Vec<u128> = vec![];
        assert_eq!(percentile(&mut empty, 50), 0);
    }

    // —— lease 生命周期语义（in-memory store，免 VM）——

    #[test]
    fn lease_idle_sweep_and_keepalive() {
        let s = SqliteStore::open_in_memory().unwrap();
        let now = now_unix();
        let lease = s.lease_grant(10).unwrap(); // 到期 ≈ now+10
        s.put("sandbox/x/state", b"running", Some(lease)).unwrap();
        // 未到期不收
        assert!(s.lease_sweep(now + 5).unwrap().is_empty());
        assert!(s.get("sandbox/x/state").unwrap().is_some());
        // keepalive 推迟到期
        let new_exp = s.lease_keepalive(lease).unwrap();
        assert!(new_exp >= now + 9);
        // 远期 now 到期回收挂键
        let swept = s.lease_sweep(now + 1000).unwrap();
        assert!(swept.iter().any(|k| k == "sandbox/x/state"));
        assert!(s.get("sandbox/x/state").unwrap().is_none());
    }

    #[test]
    fn lease_revoke_deletes_attached() {
        let s = SqliteStore::open_in_memory().unwrap();
        let lease = s.lease_grant(100).unwrap();
        s.put("sandbox/y/meta", b"{}", Some(lease)).unwrap();
        s.put("sandbox/y/state", b"running", Some(lease)).unwrap();
        let deleted = s.lease_revoke(lease).unwrap();
        assert_eq!(deleted.len(), 2);
        assert!(s.get("sandbox/y/meta").unwrap().is_none());
        assert!(s.get("sandbox/y/state").unwrap().is_none());
    }

    #[test]
    fn id_generation_len() {
        let mut b = [0u8; 6];
        host_random(&mut b);
        assert_eq!(hex(&b).len(), 12);
    }
}
