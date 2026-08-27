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

use crate::backend::{BackendCreate, Capabilities, Capability, ExecTarget, SandboxBackend};
use crate::fcapi::FcApi;
use crate::netlive::{self, LiveNet};
use crate::orch::{cp_reflink, prepare_instance_dir, NetworkMode, SandboxSpec};
use crate::pool::{HotPool, HotSlot, WarmPool};
use crate::{
    abspath, cold_boot_egress, hex, host_random, kill_group, restore_activate, restore_core, Config, LoadOutcome,
    RestoreCtx,
};

/// 后端独占的在册实例：FC 进程 + 实例目录 + 原始模板 + ADR-12 克隆身份 + 暂停态标记。
struct FcInst {
    /// 运行中持有 FC 进程；pause 后 VM 已停（child 已亡，仅占位）。
    child: Child,
    dir: PathBuf,
    /// 原始模板目录（canonical）：resume/fork 以此做 bind（快照烘焙的是模板绝对路径，非实例路径）。
    template: PathBuf,
    #[allow(dead_code)]
    machine_id: String,
    /// M2 W9：已暂停（快照落盘 + VM 停）。paused 时不可 exec；resume 从快照拉起。
    paused: bool,
    /// 运行时 egress（冷启动带 NIC）：持 live 网络句柄，销毁时 `down()` 拆 netns/veth/nft/iptables。
    /// None = 普通（无网卡）恢复态沙箱。
    net: Option<LiveNet>,
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
    fn create_from_hot(&mut self, template: &Path, slot: HotSlot) -> Result<BackendCreate, String> {
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
        Ok(self.register_inst(id, dir, template.to_path_buf(), child, o, 0, activate_ms, true, true))
    }

    /// 运行时 egress 创建（开放出口 MVP）：冷启动一台带 NIC 的 VM 进 per-instance netns，可出站
    /// （npm/pip install）。与恢复路径正交——egress 沙箱无快照可用（快照无网卡）。步骤：
    /// ① 私有 rootfs 副本（冷启动会写，须私有；vmstate/mem 不需要）→ ② `LiveNet::up`（netns+veth+tap+NAT，
    /// **不挂 nftfw drop 门禁** = 开放出口）→ ③ `cold_boot_egress`（boot+配网+DNS+Reinit）→ ④ 登记（挂 net 供拆网）。
    /// 需 root（capabilities() 已门控）；失败即拆网 + 删目录，零残留。
    fn create_egress(&mut self, template: &Path, spec: &SandboxSpec) -> Result<BackendCreate, String> {
        let t = Instant::now();
        let mut idb = [0u8; 6];
        host_random(&mut idb);
        let id = hex(&idb);
        let dir = self.run_root.join(&id);
        std::fs::create_dir_all(&dir).map_err(|e| format!("建实例目录失败: {e}"))?;
        let dir = abspath(&dir)?;
        // 私有 rootfs 副本（reflink 优先→回退全拷）；冷启动只需 rootfs（无 vmstate/mem）。
        if let Err(e) = cp_reflink(&template.join("rootfs.ext4"), &dir.join("rootfs.ext4")) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
        // live 网络：per-instance netns + tap + NAT masquerade（开放出口=不调 gate_up）。
        let root = unsafe { libc::geteuid() } == 0;
        let uplink = self.cfg.uplink.clone().or_else(|| netlive::detect_uplink(root)).unwrap_or_else(|| "lo".into());
        let ns = netlive::ns_for(&id);
        let net = match LiveNet::up(&id, &ns, &uplink, root) {
            Ok(n) => n,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(format!("egress 起 live 网络失败: {e}"));
            }
        };
        // 冷启动带 NIC + 配网 + DNS + Reinit。失败即拆网 + 删目录。
        let (child, machine_id, rng_hex, session_key_hex) =
            match cold_boot_egress(self.cfg, &dir, &net, spec.vcpus, spec.mem_mib) {
                Ok(v) => v,
                Err(e) => {
                    net.down();
                    let _ = std::fs::remove_dir_all(&dir);
                    return Err(format!("egress 冷启动失败: {e}"));
                }
            };
        let total_ms = t.elapsed().as_millis();
        self.live.insert(
            id.clone(),
            FcInst { child, dir, template: template.to_path_buf(), machine_id: machine_id.clone(), paused: false, net: Some(net) },
        );
        Ok(BackendCreate {
            id,
            machine_id,
            rng_hex,
            session_key_hex,
            total_ms,
            copy_ms: 0,
            api_ready_ms: 0,
            load_ms: 0,
            resume_ms: 0,
            pool_hit: false,
            hot_hit: false,
        })
    }

    /// 存 `FcInst` 到自有在册表，组装 `BackendCreate`（编排 lease/meta 由 Orch 依此包装）。
    /// `template` 记入 FcInst——resume/fork 须以**原始模板**做 bind（快照烘焙的是模板绝对路径）。
    #[allow(clippy::too_many_arguments)]
    fn register_inst(
        &mut self,
        id: String,
        dir: PathBuf,
        template: PathBuf,
        child: Child,
        o: LoadOutcome,
        copy_ms: u128,
        total_ms: u128,
        pool_hit: bool,
        hot_hit: bool,
    ) -> BackendCreate {
        let machine_id = o.machine_id.clone();
        self.live
            .insert(id.clone(), FcInst { child, dir, template, machine_id: machine_id.clone(), paused: false, net: None });
        BackendCreate {
            id,
            machine_id,
            rng_hex: o.rng_hex,
            session_key_hex: o.session_key_hex,
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
        let mut caps =
            Capabilities::with(&[Capability::PauseResume, Capability::PrebakeSnapshot, Capability::SnapshotFork]);
        // 运行时 egress 需 netns/nft/ip（root）→ 仅 root 守护报告 NetworkEgress。非 root 请求 egress 在
        // orch::select_backend 以 UNSUPPORTED_BY_BACKEND 清晰拒绝（不静默降级为无网）。
        if unsafe { libc::geteuid() } == 0 {
            caps.insert(Capability::NetworkEgress);
        }
        caps
    }

    fn create(&mut self, template: &Path, spec: &SandboxSpec) -> Result<BackendCreate, String> {
        if !template.is_dir() {
            return Err(format!("模板目录不存在: {}（先跑 --build / --snap-create）", template.display()));
        }
        let template = abspath(template)?;

        // 运行时 egress：无快照可用（快照无网卡）→ 冷启动带 NIC 路径，不进池。
        if spec.network == NetworkMode::Egress {
            return self.create_egress(&template, spec);
        }

        // 三段式（M2 W5）：hot → warm → cold。命中**热池**最快——暂停态 VM 只 activate（resume+reinit），
        // FC spawn + snapshot load 已在关键路径外；其次**温池**（省 copy）；再次**冷路径**（现场 copy）。
        if let Some(slot) = self.try_hot_hit(&template) {
            return self.create_from_hot(&template, slot);
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
        Ok(self.register_inst(id, dir_abs, template.clone(), child, o, copy_ms, total_ms, pool_hit, false))
    }

    fn destroy(&mut self, id: &str) {
        if let Some(mut inst) = self.live.remove(id) {
            kill_group(&mut inst.child);
            // egress 沙箱：拆 live 网络（netns/veth/nft/iptables，幂等）——先杀 VM 再拆网。
            if let Some(net) = &inst.net {
                net.down();
            }
            let _ = std::fs::remove_dir_all(&inst.dir);
        }
    }

    fn exec_target(&self, id: &str) -> Option<ExecTarget> {
        let i = self.live.get(id)?;
        if i.paused {
            return None; // 暂停态 VM 已停，不可 exec（resume 后复通）
        }
        Some(ExecTarget::Vsock(i.dir.join("vsock.sock")))
    }

    fn instance_dir(&self, id: &str) -> Option<PathBuf> {
        self.live.get(id).map(|i| i.dir.clone())
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

    /// pause（FR-1.4）：断实例 vmstate/mem 硬链（防写穿模板）→ `PATCH Paused` → `PUT /snapshot/create Full`
    /// 落 `dir/`（自包含内存快照）→ 停 VM。guest 现存 `/tmp/sl-snap-marker`（建模板时播种）随快照捕获，
    /// resume/fork 仍据**模板 expect** 校验一致性。幂等（已 paused 直接返 Ok）。
    fn pause(&mut self, id: &str) -> Result<(), String> {
        let (dir, already) = {
            let i = self.live.get(id).ok_or_else(|| format!("未知沙箱 {id}"))?;
            (i.dir.clone(), i.paused)
        };
        if already {
            return Ok(());
        }
        // 断硬链：dir/vmstate、dir/mem 是 create 时从模板硬链来的；snapshot/create 会覆写，先 unlink
        // 令 FC 建独立文件——否则写穿共享 inode 会脏模板。
        let _ = std::fs::remove_file(dir.join("vmstate"));
        let _ = std::fs::remove_file(dir.join("mem"));
        let api = FcApi::new(dir.join("api.sock"));
        api.patch("/vm", r#"{"state":"Paused"}"#)?;
        api.put_long(
            "/snapshot/create",
            &format!(
                r#"{{"snapshot_type":"Full","snapshot_path":"{}","mem_file_path":"{}"}}"#,
                dir.join("vmstate").display(),
                dir.join("mem").display()
            ),
        )?;
        let i = self.live.get_mut(id).unwrap();
        kill_group(&mut i.child);
        i.paused = true;
        Ok(())
    }

    /// resume（FR-1.4）：从 paused 快照**就地**恢复（instance=dir 读快照 vmstate/mem；bind dir→模板，
    /// 因 FC 烘焙的是**模板**绝对路径）。经 restore_core → reinit 换发**新** machine-id（克隆熵不泄漏）。
    fn resume(&mut self, id: &str) -> Result<String, String> {
        let (dir, template, paused) = {
            let i = self.live.get(id).ok_or_else(|| format!("未知沙箱 {id}"))?;
            (i.dir.clone(), i.template.clone(), i.paused)
        };
        if !paused {
            return Err(format!("resume: 沙箱 {id} 未暂停"));
        }
        let ctx = RestoreCtx {
            template_dir: &template,
            instance_dir: &dir,
            bind: Some((dir.clone(), template.clone())),
            keep_alive: true,
            netns: None,
        };
        let (o, child) = match restore_core(self.cfg, &ctx) {
            Ok((o, Some(c), _gate)) => (o, c),
            Ok((_, None, _gate)) => return Err("resume 未返回 VM 句柄（keep_alive 语义异常）".into()),
            Err(e) => return Err(format!("resume 失败: {e}")),
        };
        let mid = o.machine_id.clone();
        let i = self.live.get_mut(id).unwrap();
        i.child = child;
        i.machine_id = mid.clone();
        i.paused = false;
        Ok(mid)
    }

    /// fork（M2-Q5）：从**已 paused** 父的快照派生新实例——拷父 paused vmstate/mem + rootfs（reflink）到
    /// 新 dir，restore（bind 新 dir→模板）→ reinit 换发**独立**身份（克隆熵不泄漏）。父 rootfs/快照复用，
    /// **不刷新安全边界**（同代码/数据）。父须先 pause（快照来源）。
    fn fork(&mut self, id: &str) -> Result<BackendCreate, String> {
        let (parent_dir, template, paused) = {
            let i = self.live.get(id).ok_or_else(|| format!("未知沙箱 {id}"))?;
            (i.dir.clone(), i.template.clone(), i.paused)
        };
        if !paused {
            return Err(format!("fork: 需先 pause 父沙箱 {id}（fork 快照来源）"));
        }
        let mut idb = [0u8; 6];
        host_random(&mut idb);
        let new_id = hex(&idb);
        let new_dir = self.run_root.join(&new_id);
        // 拷父 paused 快照（vmstate/mem 硬链 + rootfs reflink）到新实例目录。
        let copy_ms = prepare_instance_dir(&parent_dir, &new_dir)?;
        let new_dir = abspath(&new_dir)?;
        let ctx = RestoreCtx {
            template_dir: &template,
            instance_dir: &new_dir,
            bind: Some((new_dir.clone(), template.clone())),
            keep_alive: true,
            netns: None,
        };
        let (o, child) = match restore_core(self.cfg, &ctx) {
            Ok((o, Some(c), _gate)) => (o, c),
            Ok((_, None, _gate)) => {
                let _ = std::fs::remove_dir_all(&new_dir);
                return Err("fork 未返回 VM 句柄（keep_alive 语义异常）".into());
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&new_dir);
                return Err(format!("fork 失败: {e}"));
            }
        };
        let total_ms = copy_ms.saturating_add(o.total_ms);
        Ok(self.register_inst(new_id, new_dir, template, child, o, copy_ms, total_ms, false, false))
    }
}
