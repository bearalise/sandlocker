//! fcbackend.rs — Firecracker 后端（M2 W6，ADR-14）。
//!
//! 实现 [`SandboxBackend`]：把 FC 机制（三段 hot→warm→cold 恢复创建、温/热池、销毁、数据面 vsock
//! 端点）收到 trait 之后。编排（store/lease/TTL/tick）留在 [`crate::orch::Orch`]。
//! 能力集 = {`pause_resume`, `prebake_snapshot`, `snapshot_fork`}（gpu/persistent_volume 无）——
//! 故 FC 支持温/热池（能力门控）；gVisor(runsc，W7)无这些能力 → 走默认实现，只冷创建。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use crate::backend::{BackendCreate, Capabilities, Capability, SandboxBackend};
use crate::orch::{prepare_instance_dir, SandboxSpec};
use crate::pool::{HotPool, HotSlot, WarmPool};
use crate::{abspath, hex, host_random, kill_group, restore_activate, restore_core, Config, LoadOutcome, RestoreCtx};

/// 后端独占的在册实例：FC 进程 + 实例目录 + ADR-12 克隆身份。
struct FcInst {
    child: Child,
    dir: PathBuf,
    #[allow(dead_code)]
    machine_id: String,
}

/// Firecracker 后端。持 cfg（借用，serve 侧 `'static`）+ run_root + 自有在册表 + 温/热池。
pub struct FcBackend<'a> {
    cfg: &'a Config,
    run_root: PathBuf,
    live: HashMap<String, FcInst>,
    pool: Option<WarmPool>,
    hot: Option<HotPool>,
}

impl<'a> FcBackend<'a> {
    pub fn new(cfg: &'a Config, run_root: PathBuf) -> Self {
        Self { cfg, run_root, live: HashMap::new(), pool: None, hot: None }
    }

    /// 温池命中判定：请求模板 == 温池模板（均 canonical）且弹到热槽即返回槽；否则 None（走冷路径）。
    fn try_pool_hit(&self, template: &Path) -> Option<crate::pool::WarmSlot> {
        let pool = self.pool.as_ref()?;
        if pool.template() != template {
            return None;
        }
        pool.try_pop()
    }

    /// 热池命中判定：请求模板 == 热池模板（均 canonical）且弹到暂停态槽即返回；否则 None。
    fn try_hot_hit(&self, template: &Path) -> Option<HotSlot> {
        let hot = self.hot.as_ref()?;
        if hot.template() != template {
            return None;
        }
        hot.try_pop()
    }

    /// 热池命中：暂停态槽 `restore_activate` 拉起（netns=None、keep_alive）。`total_ms`=activate wall-clock
    /// （park 的 spawn+load 已在关键路径外）；`copy_ms=0`。活化失败即杀 parked child + 删 dir。
    fn create_from_hot(&mut self, slot: HotSlot) -> Result<BackendCreate, String> {
        let HotSlot { id, dir, parked } = slot;
        let t = Instant::now();
        let (o, child) = match restore_activate(self.cfg, None, true, parked) {
            Ok((o, Some(c), _gate)) => (o, c),
            Ok((_, None, _gate)) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err("热池活化未返回 VM 句柄（keep_alive 语义异常）".into());
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(format!("热池活化失败: {e}"));
            }
        };
        let activate_ms = t.elapsed().as_millis();
        Ok(self.register_inst(id, dir, child, o, 0, activate_ms, true, true))
    }

    /// 存 `FcInst` 到自有在册表，组装 `BackendCreate`（编排 lease/meta 由 Orch 依此包装）。
    #[allow(clippy::too_many_arguments)]
    fn register_inst(
        &mut self,
        id: String,
        dir: PathBuf,
        child: Child,
        o: LoadOutcome,
        copy_ms: u128,
        total_ms: u128,
        pool_hit: bool,
        hot_hit: bool,
    ) -> BackendCreate {
        let machine_id = o.machine_id.clone();
        self.live.insert(id.clone(), FcInst { child, dir, machine_id: machine_id.clone() });
        BackendCreate {
            id,
            machine_id,
            total_ms,
            copy_ms,
            api_ready_ms: o.api_ready_ms,
            load_ms: o.load_ms,
            resume_ms: o.resume_ms,
            pool_hit,
            hot_hit,
        }
    }
}

impl SandboxBackend for FcBackend<'_> {
    fn id(&self) -> &str {
        "fc"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::with(&[Capability::PauseResume, Capability::PrebakeSnapshot, Capability::SnapshotFork])
    }

    fn create(&mut self, template: &Path, _spec: &SandboxSpec) -> Result<BackendCreate, String> {
        if !template.is_dir() {
            return Err(format!("模板目录不存在: {}（先跑 --build / --snap-create）", template.display()));
        }
        let template = abspath(template)?;

        // 三段式（M2 W5）：hot → warm → cold。命中**热池**最快——暂停态 VM 只 activate（resume+reinit），
        // FC spawn + snapshot load 已在关键路径外；其次**温池**（省 copy）；再次**冷路径**（现场 copy）。
        if let Some(slot) = self.try_hot_hit(&template) {
            return self.create_from_hot(slot);
        }

        // 温池命中（copy_ms=0，refill 线程锁外备好私有 rootfs/vmstate/mem）或冷路径（现场 copy，零回归）。
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

        // 恢复（keep-alive）：目录级 bind（实例目录 → 模板目录）令 FC 烘焙的 rootfs/vsock 绝对路径落进
        // 实例私有副本——并发不撞、不脏模板。vmstate/mem 从实例目录（未被 bind 遮蔽）直取。
        let ctx = RestoreCtx {
            template_dir: &template,
            instance_dir: &dir_abs,
            bind: Some((dir_abs.clone(), template.clone())),
            keep_alive: true,
            // Option A：快照无网卡 → 恢复态 guest 无 eth0（出口天然为零，仍 fail-safe）。真流量 live gate
            // 证明走 `--net-live-reconcile` 冷启动；restore-path live 网卡落地待后续。
            netns: None,
        };
        let (o, child) = match restore_core(self.cfg, &ctx) {
            Ok((o, Some(c), _gate)) => (o, c),
            Ok((_, None, _gate)) => {
                let _ = std::fs::remove_dir_all(&dir_abs);
                return Err("恢复未返回 VM 句柄（keep_alive 语义异常）".into());
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir_abs);
                return Err(format!("创建走恢复失败: {e}"));
            }
        };
        // 总时延 = 私有 rootfs 副本（restore 前）+ 恢复（spawn→ready）；分段另报以定位大头。
        let total_ms = copy_ms.saturating_add(o.total_ms);
        Ok(self.register_inst(id, dir_abs, child, o, copy_ms, total_ms, pool_hit, false))
    }

    fn destroy(&mut self, id: &str) {
        if let Some(mut inst) = self.live.remove(id) {
            kill_group(&mut inst.child);
            let _ = std::fs::remove_dir_all(&inst.dir);
        }
    }

    fn control_path(&self, id: &str) -> Option<PathBuf> {
        self.live.get(id).map(|i| i.dir.join("vsock.sock"))
    }

    fn log_path(&self, id: &str) -> Option<PathBuf> {
        self.live.get(id).map(|i| i.dir.join("console.load.log"))
    }

    fn enable_warm_pool(&mut self, template: &Path, target: usize) -> Result<(), String> {
        if target == 0 {
            self.pool = None;
            return Ok(());
        }
        self.pool = Some(WarmPool::new(template, &self.run_root, target)?);
        Ok(())
    }

    fn enable_hot_pool(&mut self, template: &Path, target: usize) -> Result<(), String> {
        if target == 0 {
            self.hot = None;
            return Ok(());
        }
        self.hot = Some(HotPool::new(self.cfg, template, &self.run_root, target)?);
        Ok(())
    }

    fn pool_wait_ready(&self, n: usize, timeout: Duration) -> bool {
        self.pool.as_ref().map(|p| p.wait_ready(n, timeout)).unwrap_or(false)
    }

    fn hot_wait_ready(&self, n: usize, timeout: Duration) -> bool {
        self.hot.as_ref().map(|h| h.wait_ready(n, timeout)).unwrap_or(false)
    }

    fn pool_stats(&self) -> Option<(u64, u64, usize)> {
        self.pool.as_ref().map(|p| p.stats())
    }
}
