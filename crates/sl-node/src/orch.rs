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
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use sl_store::{LeaseId, SqliteStore, Store};

use crate::pool::WarmPool;
use crate::{abspath, hex, host_random, kill_group, restore_core, Config, RestoreCtx};

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
}

impl Default for SandboxSpec {
    fn default() -> Self {
        Self { vcpus: 2, mem_mib: 512, ttl_secs: 300, idle_secs: 300, metadata: BTreeMap::new() }
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
    /// M2 W4：本次 create 是否命中温池（走池命中路径，`copy_ms=0`）。冷路径为 false。
    pub pool_hit: bool,
}

/// 在册运行中的沙箱句柄。`id` 即 `live` 映射键，不重复存。
struct Live {
    child: Child,
    /// 实例目录（绝对）：私有 rootfs 副本 + vmstate/mem 硬链 + sockets/日志。
    dir: PathBuf,
    lease: LeaseId,
    /// TTL 绝对硬顶（unix 秒），独立于 lease。
    ttl_deadline: i64,
}

/// 进程内 orchestrator。`store` 按窄接口编程（M3 可换 etcd）；`template` 为预烘焙快照目录（绝对）。
pub struct Orch<'a> {
    cfg: &'a Config,
    store: Box<dyn Store>,
    template: PathBuf,
    run_root: PathBuf,
    live: HashMap<String, Live>,
    /// M2 W4：单模板温池（可选）。仅当请求模板 == `pool.template()` 时走池命中路径；
    /// 其它模板/无池均走冷路径（零回归）。
    pool: Option<WarmPool>,
}

impl<'a> Orch<'a> {
    pub fn new(cfg: &'a Config, template: &Path, run_root: &Path, store: Box<dyn Store>) -> Result<Self, String> {
        if !template.is_dir() {
            return Err(format!("模板目录不存在: {}（先跑 --build / --snap-create）", template.display()));
        }
        std::fs::create_dir_all(run_root).map_err(|e| format!("建 run_root 失败 {}: {e}", run_root.display()))?;
        let template = abspath(template)?;
        Ok(Self {
            cfg,
            store,
            template,
            run_root: run_root.to_path_buf(),
            live: HashMap::new(),
            pool: None,
        })
    }

    /// M2 W4：为 `template` 起单模板温池（水位 `target`），后续 create 命中同模板走池命中路径。
    /// `target == 0` 视为不启用（幂等清空既有池）。守护（`--serve`）在建 Orch 后调用。
    pub fn enable_warm_pool(&mut self, template: &Path, target: usize) -> Result<(), String> {
        if target == 0 {
            self.pool = None;
            return Ok(());
        }
        self.pool = Some(WarmPool::new(template, &self.run_root, target)?);
        Ok(())
    }

    /// 温池 (hits, misses, ready_len)；未启用返回 None。供守护内省 / bench。
    pub fn pool_stats(&self) -> Option<(u64, u64, usize)> {
        self.pool.as_ref().map(|p| p.stats())
    }

    /// 阻塞等温池水位 ≥ `n` 或超时（bench 预填池用）。无池返回 false。
    pub fn pool_wait_ready(&self, n: usize, timeout: Duration) -> bool {
        self.pool.as_ref().map(|p| p.wait_ready(n, timeout)).unwrap_or(false)
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

        // 1-2) 备实例目录。**池命中路径**（M2 W4）：请求模板 == 温池模板且弹到热槽 →
        //      槽已备妥私有 rootfs/vmstate/mem（copy 在池 refill 线程锁外完成）→ `copy_ms=0`。
        //      否则**冷路径**：现场生成 id + `prepare_instance_dir`（copy 计入关键路径），零回归。
        let (id, dir_abs, copy_ms, pool_hit) = match self.try_pool_hit(&template) {
            Some(slot) => (slot.id, slot.dir, 0u128, true),
            None => {
                let mut idb = [0u8; 6];
                host_random(&mut idb);
                let id = hex(&idb);
                let dir = self.run_root.join(&id);
                let copy_ms = prepare_instance_dir(&template, &dir)?;
                let dir_abs = abspath(&dir)?;
                (id, dir_abs, copy_ms, false)
            }
        };
        let dir = dir_abs.clone();

        // 3) lease（idle 计时器）+ sandbox/ 元数据（挂 lease → 随空闲回收/撤销一并删）
        let created_at = now_unix();
        let ttl_deadline = compute_ttl_deadline(created_at, spec.ttl_secs);
        let lease = self.store.lease_grant(spec.idle_secs).map_err(|e| e.to_string())?;
        let meta = build_meta_json(&id, spec, created_at, ttl_deadline, &template);
        if let Err(e) = self.store.put(&meta_key(&id), meta.as_bytes(), Some(lease)) {
            let _ = self.store.lease_revoke(lease);
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!("写 sandbox meta 失败: {e}"));
        }
        if let Err(e) = self.store.put(&state_key(&id), b"running", Some(lease)) {
            let _ = self.store.lease_revoke(lease);
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!("写 sandbox state 失败: {e}"));
        }

        // 4) 恢复（keep-alive）：目录级 bind（实例目录 → 模板目录）令 FC 烘焙的 rootfs/vsock 绝对
        //    路径落进实例私有副本——并发不撞、不脏模板。vmstate/mem 从实例目录（未被 bind 遮蔽）直取。
        let ctx = RestoreCtx {
            template_dir: &template,
            instance_dir: &dir,
            bind: Some((dir_abs.clone(), template.clone())),
            keep_alive: true,
            // Option A（M2 W2）：快照无网卡 → 恢复态 guest 无 eth0，orchestrator 实例本周保持无网卡
            // （出口天然为零，仍 fail-safe）。真流量 live gate 证明走 `--net-live-reconcile` 冷启动；
            // restore-path live 网卡落地待后续（届时此处传 `Some(&ns)` 并线程化门禁句柄）。
            netns: None,
        };
        let (o, child) = match restore_core(self.cfg, &ctx) {
            Ok((o, Some(c), _gate)) => (o, c),
            Ok((_, None, _gate)) => {
                let _ = self.store.lease_revoke(lease);
                let _ = std::fs::remove_dir_all(&dir);
                return Err("恢复未返回 VM 句柄（keep_alive 语义异常）".into());
            }
            Err(e) => {
                let _ = self.store.lease_revoke(lease);
                let _ = std::fs::remove_dir_all(&dir);
                return Err(format!("创建走恢复失败: {e}"));
            }
        };

        // 5) 登记 Live（持有 Child，不 kill）
        self.live.insert(id.clone(), Live { child, dir: dir_abs, lease, ttl_deadline });
        // 创建总时延 = 私有 rootfs 副本（restore 前）+ 恢复（spawn→ready）；分段另报以定位大头。
        Ok(CreateOutcome {
            id,
            total_ms: copy_ms.saturating_add(o.total_ms),
            copy_ms,
            api_ready_ms: o.api_ready_ms,
            load_ms: o.load_ms,
            resume_ms: o.resume_ms,
            machine_id: o.machine_id,
            pool_hit,
        })
    }

    /// 池命中判定：请求模板 == 温池模板（均 canonical）且弹到热槽即返回槽；否则 None（走冷路径）。
    fn try_pool_hit(&self, template: &Path) -> Option<crate::pool::WarmSlot> {
        let pool = self.pool.as_ref()?;
        if pool.template() != template {
            return None;
        }
        pool.try_pop()
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

    /// 手动 destroy：杀 VM 进程组 → 撤销 lease（删 lease+挂键）→ 删实例目录 → 出台账。返回被删 store 键。
    pub fn destroy(&mut self, id: &str) -> Result<Vec<String>, String> {
        let mut live = self.live.remove(id).ok_or_else(|| format!("未知沙箱 {id}"))?;
        kill_group(&mut live.child);
        let deleted = self.store.lease_revoke(live.lease).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_dir_all(&live.dir);
        Ok(deleted)
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
            if let Some(mut live) = self.live.remove(&id) {
                kill_group(&mut live.child);
                let _ = std::fs::remove_dir_all(&live.dir);
                reaped.push(id);
            }
        }
        Ok(reaped)
    }

    // —— 内省（对账/测试用）——
    fn is_live(&self, id: &str) -> bool {
        self.live.contains_key(id)
    }
    fn dir_of(&self, id: &str) -> Option<PathBuf> {
        self.live.get(id).map(|l| l.dir.clone())
    }

    // —— 守护（api.rs 复用）——

    /// 在册沙箱的 vsock uds 路径（连 guest 执行 exec/文件桥接用）；不在册返回 None。
    pub fn vsock_path(&self, id: &str) -> Option<PathBuf> {
        self.live.get(id).map(|l| l.dir.join("vsock.sock"))
    }

    /// 在册沙箱的 console 日志路径（GET /logs 用）；不在册返回 None。
    pub fn log_path(&self, id: &str) -> Option<PathBuf> {
        self.live.get(id).map(|l| l.dir.join("console.load.log"))
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

    // 收尾：store sandbox/ 空 + 模板 rootfs sha256 不变（bind 遮蔽证明 FC 从未写模板）
    ensure(
        orch.store.list("sandbox/").map_err(|e| e.to_string())?.is_empty(),
        "收尾 store sandbox/ 非空（元数据残留）",
    )?;
    let tpl_sha_after = sha256_file(&tpl_rootfs)?;
    ensure(tpl_sha_before == tpl_sha_after, "收尾 模板 rootfs 被写脏（bind 遮蔽失效）")?;

    if cfg.json {
        println!(r#"{{"metric":"orch_reconcile","cases":6,"template_immutable":true,"pass":true}}"#);
    } else {
        println!(
            "[orch] Q9 对账 PASS：create/keepalive/idle 回收/TTL 硬顶/手动 destroy 每步零残留 + 并发双克隆隔离 + 模板 rootfs 不变"
        );
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

    // 回归判据：温池不劣于冷档（`<=` 容忍 reflink fs 上 copy≈0 的等值噪声；ext4 上仍严格小于）。
    let regression_ok = warm_p50 <= cold_p50;
    // 绝对预算 gate（硬出口①）：env `POOL_P50_BUDGET_MS`>0 时追加 warm_p50 ≤ budget。缺省 0=关——
    // bench-light 托管 runner 慢，不设预算只 gate 回归；裸金属 bench-density job 设 100 硬达标（PRD §8.1）。
    let budget_ms: u128 = std::env::var("POOL_P50_BUDGET_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let budget_ok = budget_ms == 0 || warm_p50 <= budget_ms;
    let pass = regression_ok && budget_ok;

    if cfg.json {
        println!(
            r#"{{"metric":"pool_bench","n":{},"cold_p50":{cold_p50},"cold_p90":{cold_p90},"warm_p50":{warm_p50},"warm_p90":{warm_p90},"warm_hit_rate":{hit_rate:.3},"copy_saved_p50":{copy_saved_p50},"warm_le_100":{warm_le_100},"budget_ms":{budget_ms},"pass":{pass}}}"#,
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
        let spec = SandboxSpec { vcpus: 4, mem_mib: 1024, ttl_secs: 300, idle_secs: 60, metadata: md };
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
