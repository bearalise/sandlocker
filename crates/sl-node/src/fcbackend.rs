//! fcbackend.rs — Firecracker 后端（M2 W6，ADR-14）。
//!
//! 实现 [`SandboxBackend`]：把 FC 机制（三段 hot→warm→cold 恢复创建、温/热池、销毁、数据面 vsock
//! 端点）收到 trait 之后。编排（store/lease/TTL/tick）留在 [`crate::orch::Orch`]。
//! 能力集 = {`pause_resume`, `prebake_snapshot`, `snapshot_fork`}（gpu/persistent_volume 无）——
//! 故 FC 支持温/热池（能力门控）；gVisor(runsc，W7)无这些能力 → 走默认实现，只冷创建。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::process::Child;
use std::time::{Duration, Instant};

use crate::backend::{BackendCreate, Capabilities, Capability, ExecTarget, SandboxBackend};
use crate::fcapi::FcApi;
use crate::netlive::{self, LiveNet};
use crate::orch::{cp_reflink, prepare_instance_dir, NetworkMode, SandboxSpec};
use crate::snapcrypt::{self, SnapKey};
use crate::pool::{HotPool, HotSlot, WarmPool};
use crate::{
    abspath, cold_boot_egress, connect_guest, hex, host_random, kill_group, restore_activate, restore_core, Config,
    LoadOutcome, RestoreCtx,
};
use sl_proto::{read_msg, write_msg, Request, Response};

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
    /// M3 W9（ADR-15）：本次快照操作的密钥材料。`None` = 未启用加密，快照明文落盘（M2 行为，零回归）。
    snap_key: Option<Arc<SnapKey>>,
}

impl<'a> FcBackend<'a> {
    pub fn new(cfg: &'a Config, run_root: PathBuf) -> Self {
        Self { cfg, run_root, live: HashMap::new(), pool: None, hot: None, snap_key: None }
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
            // M3 W9：加密开启时，销毁前先抹掉解出来的明文快照（`remove_dir_all` 只是 unlink，
            // 块内容还在）。未启用加密时跳过——对 512MiB 量级文件逐个覆写会直接压垮销毁吞吐。
            if self.snap_key.is_some() {
                let _ = snapcrypt::shred(&inst.dir.join("vmstate"));
                let _ = snapcrypt::shred(&inst.dir.join("mem"));
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
    fn set_snapshot_key(&mut self, key: Option<Arc<SnapKey>>) {
        self.snap_key = key;
    }

    fn pause(&mut self, id: &str) -> Result<(), String> {
        let (dir, already) = {
            let i = self.live.get(id).ok_or_else(|| format!("未知沙箱 {id}"))?;
            (i.dir.clone(), i.paused)
        };
        if already {
            return Ok(());
        }
        let api = FcApi::new(dir.join("api.sock"));
        // M3 W9（ADR-15）：**在冻结之前**让 guest 擦掉自己的会话密钥——pause 落盘的是整份 guest
        // 内存，密钥若还在，快照里就带着钥匙，外面再怎么加密也白搭。resume/fork 必经 reinit，
        // 那里本就会换发新会话密钥，故无损。best-effort：擦不掉不阻断 pause（见 sl-envd run_wipe_keys）。
        if self.snap_key.is_some() {
            if let Some(ExecTarget::Vsock(vsock)) = self.exec_target(id) {
                if let Err(e) = wipe_guest_keys(&vsock) {
                    eprintln!("[sl-node][WARN] pause {id}: guest 擦密钥失败: {e}（继续）");
                }
            }
        }
        // 断硬链：dir/vmstate、dir/mem 是 create 时从模板硬链来的；snapshot/create 会覆写，先 unlink
        // 令 FC 建独立文件——否则写穿共享 inode 会脏模板。
        let _ = std::fs::remove_file(dir.join("vmstate"));
        let _ = std::fs::remove_file(dir.join("mem"));
        api.patch("/vm", r#"{"state":"Paused"}"#)?;
        api.put_long(
            "/snapshot/create",
            &format!(
                r#"{{"snapshot_type":"Full","snapshot_path":"{}","mem_file_path":"{}"}}"#,
                dir.join("vmstate").display(),
                dir.join("mem").display()
            ),
        )?;
        // M3 W9：FC 只会写明文（它不认识密文，也没有插存储层的口子），所以加密是**落盘后**的一步：
        // 加密 → fsync → 抹明文。顺序不能反，掉电时宁可留明文也不能两头皆空。
        if let Some(k) = self.snap_key.clone() {
            if let Err(e) = seal_snapshot(&dir, &k) {
                // **fail closed**：密封不了就绝不留明文的 guest 内存在盘上。抹掉半成品，
                // 把 VM 放回运行态（沙箱不丢，只是这次 pause 失败），错误如实上报。
                let _ = snapcrypt::shred(&dir.join("vmstate"));
                let _ = snapcrypt::shred(&dir.join("mem"));
                let _ = snapcrypt::shred(&dir.join("vmstate.enc"));
                let _ = snapcrypt::shred(&dir.join("mem.enc"));
                if api.patch("/vm", r#"{"state":"Resumed"}"#).is_err() {
                    let i = self.live.get_mut(id).unwrap();
                    kill_group(&mut i.child); // 连放回运行态都失败 → 只能杀，绝不留半死不活的 VM
                }
                return Err(format!("pause {id}: 快照密封失败，已抹除明文并回滚: {e}"));
            }
        }
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
        // M3 W9：FC 只能 load 明文（`mem` 还要全程 mmap），故恢复前先解出明文。
        // 任一块 AEAD 校验失败即在此中止——被篡改的快照绝不会走到 FC 面前。
        if let Some(k) = self.snap_key.clone() {
            unseal_snapshot(&dir, &k)?;
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
        // 恢复成功 → 密文快照已被消费（实例回到运行态，内存以明文 mmap 在跑）。删掉它，
        // 免得盘上留一份**过期**的加密内存镜像；下次 pause 会重新密封。
        if self.snap_key.is_some() {
            let _ = std::fs::remove_file(dir.join("vmstate.enc"));
            let _ = std::fs::remove_file(dir.join("mem.enc"));
        }
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
        // 拷父 paused 快照到新实例目录。加密开启时父目录里只有密文（明文在 pause 时已抹除），
        // 故改拷 `.enc` 再解到子目录——父的密文原封不动（fork 不消费父快照，父仍是 paused）。
        let copy_ms = match self.snap_key.clone() {
            None => prepare_instance_dir(&parent_dir, &new_dir)?,
            Some(k) => {
                let ms = prepare_instance_dir_sealed(&parent_dir, &new_dir)?;
                unseal_snapshot(&new_dir, &k).inspect_err(|_| {
                    let _ = std::fs::remove_dir_all(&new_dir);
                })?;
                ms
            }
        };
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

// ————————————————————— 快照密封 / 解封（M3 W9，ADR-15）—————————————————————

/// 密封实例目录里的明文快照：`vmstate|mem` → `vmstate.enc|mem.enc`，随后抹除明文。
///
/// 两个文件各自独立成一个 `SLSNAP1` 容器、各自一把 DEK——`vmstate` 只有几十 KB 而 `mem` 是
/// 512MiB 量级，混在一个容器里会让「只解 vmstate」也得付 mem 的代价。
pub(crate) fn seal_snapshot(dir: &Path, k: &SnapKey) -> Result<(), String> {
    for name in ["vmstate", "mem"] {
        let plain = dir.join(name);
        let enc = dir.join(format!("{name}.enc"));
        snapcrypt::encrypt_file(&plain, &enc, &k.kek, &k.kek_id)?;
        // 先 encrypt（内部 fsync）再抹明文——顺序保证任一时刻至少有一份完整数据。
        snapcrypt::shred(&plain)?;
    }
    Ok(())
}

/// 解封：`vmstate.enc|mem.enc` → `vmstate|mem`。任一块 AEAD 失败即整体失败，且不留半成品。
pub(crate) fn unseal_snapshot(dir: &Path, k: &SnapKey) -> Result<(), String> {
    for name in ["vmstate", "mem"] {
        let enc = dir.join(format!("{name}.enc"));
        if !enc.exists() {
            return Err(format!("加密快照 {} 不存在（快照是否用别的密钥密封？）", enc.display()));
        }
        snapcrypt::decrypt_file(&enc, &dir.join(name), &k.kek)?;
    }
    Ok(())
}

/// fork 用：拷父实例目录的 **密文** 快照（+ rootfs reflink）到新目录。
/// 与 `prepare_instance_dir` 同形，只是搬的是 `.enc`——父的 paused 快照不被消费。
fn prepare_instance_dir_sealed(parent: &Path, dir: &Path) -> Result<u128, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("建实例目录失败 {}: {e}", dir.display()))?;
    let t0 = std::time::Instant::now();
    cp_reflink(&parent.join("rootfs.ext4"), &dir.join("rootfs.ext4"))?;
    let copy_ms = t0.elapsed().as_millis();
    for name in ["vmstate.enc", "mem.enc"] {
        let (src, dst) = (parent.join(name), dir.join(name));
        let _ = std::fs::remove_file(&dst);
        // 硬链即可：密文只读，双方都不会写它（各自 pause 时先 unlink 再重建）。
        if std::fs::hard_link(&src, &dst).is_err() {
            std::fs::copy(&src, &dst)
                .map(|_| ())
                .map_err(|e| format!("拷贝 {} 失败: {e}", src.display()))?;
        }
    }
    Ok(copy_ms)
}

/// pause 前请 guest 擦掉自己的会话密钥（`Request::WipeKeys`，ADR-15）。
fn wipe_guest_keys(vsock: &Path) -> Result<(), String> {
    let mut s = connect_guest(vsock)?;
    write_msg(&mut s, &Request::WipeKeys).map_err(|e| format!("发 WipeKeys 失败: {e}"))?;
    match read_msg::<_, Response>(&mut s).map_err(|e| format!("读 WipeKeys ack 失败: {e}"))? {
        Response::Ok => Ok(()),
        Response::Error { message } => Err(format!("guest 擦密钥失败: {message}")),
        other => Err(format!("WipeKeys ack 异常: {other:?}")),
    }
}
