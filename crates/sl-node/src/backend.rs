//! backend.rs — Sandbox ABI 契约（M2 W6，ADR-14）。
//!
//! **能力声明为 ABI 一等公民**：后端注册时上报能力位集；create 可声明 `required_capabilities`，
//! 不满足即**创建期**返回 [`UNSUPPORTED_BY_BACKEND`]（**禁止运行期静默降级**）。`GET /v1/backends`
//! 列后端与能力集。本模块只定契约（trait + 能力模型）；FC 实现见 [`crate::fcbackend`]，
//! gVisor(runsc) 第二后端 W7 接入（M2-Q4），两后端由契约测试套件 W8 验收（硬出口②）。
//!
//! 「先抽象再接第二后端」（M2技术计划 §4）：Orch 只经本 trait 触达后端机制（生命周期/数据面/池），
//! 编排（store/lease/TTL/tick）留在 Orch。池由能力位门控——gVisor 无 `prebake_snapshot`/`pause_resume`
//! → 默认实现返回不支持，天然只冷创建。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::orch::SandboxSpec;
use crate::{connect_guest, exec};

/// `required_capabilities` 不满足时错误串前缀（稳定契约，SDK/CLI 可据此判类）。
pub const UNSUPPORTED_BY_BACKEND: &str = "UNSUPPORTED_BY_BACKEND";

/// 后端能力（ADR-14）。位索引即枚举序，`Capabilities` 位集据此置位。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// 用户级 pause/resume（FR-1.4）。
    PauseResume,
    /// 快照 fork（同快照派生多实例，克隆熵防护）。
    SnapshotFork,
    /// 预烘焙快照（模板恢复创建 + 温/热池的前提）。
    PrebakeSnapshot,
    /// GPU 直通（MVP 无）。
    GpuPassthrough,
    /// 持久卷（MVP 无）。
    PersistentVolume,
    /// 运行时网络出口（FR-3.3）：沙箱冷启动进 per-instance netns + tap + NAT，可出站（npm/pip install）。
    /// 仅 FC 后端且守护以 root 运行时具备（netns/nft/ip 需 root）。
    NetworkEgress,
}

impl Capability {
    /// 全部能力（`from_names` 校验 + 遍历用）。
    pub const ALL: [Capability; 6] = [
        Capability::PauseResume,
        Capability::SnapshotFork,
        Capability::PrebakeSnapshot,
        Capability::GpuPassthrough,
        Capability::PersistentVolume,
        Capability::NetworkEgress,
    ];

    /// 契约用 snake_case 名（API/能力集串）。
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::PauseResume => "pause_resume",
            Capability::SnapshotFork => "snapshot_fork",
            Capability::PrebakeSnapshot => "prebake_snapshot",
            Capability::GpuPassthrough => "gpu_passthrough",
            Capability::PersistentVolume => "persistent_volume",
            Capability::NetworkEgress => "network_egress",
        }
    }

    /// 从 snake_case 名解析；未知名返回 None（调用方按 `UNSUPPORTED_BY_BACKEND` 处置）。
    pub fn from_str(s: &str) -> Option<Capability> {
        Capability::ALL.into_iter().find(|c| c.as_str() == s)
    }

    fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}

/// 能力位集（ADR-14）。后端注册其支持集；create 声明 `required_capabilities`。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capabilities(u32);

impl Capabilities {
    pub const fn empty() -> Self {
        Capabilities(0)
    }

    /// 从能力列表构造（后端注册用）。
    pub fn with(caps: &[Capability]) -> Self {
        let mut s = Capabilities(0);
        for &c in caps {
            s.insert(c);
        }
        s
    }

    pub fn insert(&mut self, c: Capability) {
        self.0 |= c.bit();
    }

    pub fn contains(&self, c: Capability) -> bool {
        self.0 & c.bit() != 0
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// `self` 中不被 `other` 覆盖的能力（创建期校验：required.missing_from(backend) 非空即拒）。
    pub fn missing_from(&self, other: &Capabilities) -> Vec<&'static str> {
        Capability::ALL
            .into_iter()
            .filter(|&c| self.contains(c) && !other.contains(c))
            .map(|c| c.as_str())
            .collect()
    }

    /// 已置位能力的 snake_case 名（稳定枚举序）。
    pub fn names(&self) -> Vec<&'static str> {
        Capability::ALL.into_iter().filter(|&c| self.contains(c)).map(|c| c.as_str()).collect()
    }

    /// 从 snake_case 名列表解析；含未知名即 `Err`（未知能力恒不被任何后端满足）。
    pub fn from_names<S: AsRef<str>>(names: &[S]) -> Result<Capabilities, String> {
        let mut s = Capabilities(0);
        for n in names {
            let n = n.as_ref();
            match Capability::from_str(n) {
                Some(c) => s.insert(c),
                None => return Err(format!("{UNSUPPORTED_BY_BACKEND}: 未知能力 {n:?}")),
            }
        }
        Ok(s)
    }
}

/// 后端信息（`GET /v1/backends`）。
#[derive(Clone, Debug)]
pub struct BackendInfo {
    pub id: String,
    pub capabilities: Vec<&'static str>,
}

/// 后端 create 返回：running 实例 id（后端定——池槽预分配或新生）+ machine-id + Q2 分段 + 池命中标记。
/// 编排（lease/meta/state）由 Orch 依此包装为 `CreateOutcome`。
#[derive(Clone, Debug)]
pub struct BackendCreate {
    pub id: String,
    pub machine_id: String,
    /// M2 W9（M2-Q5）：ADR-12 reinit 换发的 RNG 种子 hex——克隆熵三元组之一（fork/resume 复验须互异）。
    pub rng_hex: String,
    /// M2 W9（M2-Q5）：ADR-12 reinit 换发的会话密钥 hex——克隆熵三元组之一。
    pub session_key_hex: String,
    pub total_ms: u128,
    pub copy_ms: u128,
    pub api_ready_ms: u128,
    pub load_ms: u128,
    pub resume_ms: u128,
    pub pool_hit: bool,
    pub hot_hit: bool,
}

/// 数据面 exec 目标（ADR-14 exec 组抽象）：后端各自提供其触达方式，`Send` 以便 api.rs **取出后
/// 释放 Orch 锁再执行**（慢 IO 不阻塞 create/reaper）。put_file/get_file/logs 由 `exec` 派生（base64）。
pub enum ExecTarget {
    /// FC：guest sl-envd 的 vsock uds（`connect_guest` + [`crate::exec`]，逐字节复用 M1 数据面）。
    Vsock(PathBuf),
    /// gVisor：`runsc <global_args> exec <id> /bin/sh -c <cmd>` 子进程（无 vsock/sl-envd）。
    Runsc { bin: PathBuf, global_args: Vec<String>, id: String },
}

impl ExecTarget {
    /// 在沙箱内跑一条 `sh -c` 命令，返回 (exit_code, stdout, stderr)。**调用方须已释放 Orch 锁。**
    pub fn exec(&self, cmd: &str) -> Result<(i32, String, String), String> {
        match self {
            ExecTarget::Vsock(uds) => {
                let mut stream = connect_guest(uds)?;
                exec(&mut stream, cmd)
            }
            ExecTarget::Runsc { bin, global_args, id } => {
                let out = Command::new(bin)
                    .args(global_args)
                    .arg("exec")
                    .arg(id)
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg(cmd)
                    .output()
                    .map_err(|e| format!("runsc exec 启动失败: {e}"))?;
                let code = out.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
                Ok((code, stdout, stderr))
            }
        }
    }
}

/// Sandbox ABI：后端机制统一抽象（ADR-14）。Orch 只经本 trait 触达后端。对象安全（`Box<dyn>`）。
///
/// W6 覆盖：生命周期（create/destroy）+ 数据面 endpoint（control/log path）+ 能力上报 + 池（能力门控）。
/// exec/fs/network/snapshot 经数据面 endpoint（vsock uds）由控制面直连；完整五组接口随 gVisor W7 细化。
pub trait SandboxBackend {
    /// 后端标识（`fc` / `gvisor`）。
    fn id(&self) -> &str;

    /// 注册的能力位集（ADR-14）。
    fn capabilities(&self) -> Capabilities;

    /// `GET /v1/backends` 单条。
    fn info(&self) -> BackendInfo {
        BackendInfo { id: self.id().to_string(), capabilities: self.capabilities().names() }
    }

    /// 从预烘焙模板 + spec 造一台 running 实例（后端独占其进程/目录）。
    fn create(&mut self, template: &Path, spec: &SandboxSpec) -> Result<BackendCreate, String>;

    /// 幂等销毁：杀进程 + 删实例目录（不在册即 no-op）。
    fn destroy(&mut self, id: &str);

    /// 数据面 exec 目标（exec/fs 桥接，ADR-14 exec 组）：FC=vsock；gVisor=runsc exec。不在册返回 None。
    fn exec_target(&self, id: &str) -> Option<ExecTarget>;

    /// 实例目录（对账查残留 / 内省）；不在册返回 None。
    fn instance_dir(&self, id: &str) -> Option<PathBuf>;

    /// console 日志路径（`GET /logs`）；不在册返回 None。
    fn log_path(&self, id: &str) -> Option<PathBuf>;

    // —— 池（能力门控：默认不支持；仅具 prebake/pause 的后端覆盖）——

    /// 启用温池（需 `PrebakeSnapshot`）。默认后端不支持。
    fn enable_warm_pool(&mut self, _template: &Path, _target: usize) -> Result<(), String> {
        Err(format!("{UNSUPPORTED_BY_BACKEND}: 后端 {} 无 prebake_snapshot，不支持温池", self.id()))
    }

    /// 启用热池（需 `PrebakeSnapshot` + `PauseResume`）。默认后端不支持。
    fn enable_hot_pool(&mut self, _template: &Path, _target: usize) -> Result<(), String> {
        Err(format!("{UNSUPPORTED_BY_BACKEND}: 后端 {} 无 pause_resume，不支持热池", self.id()))
    }

    /// 阻塞等温池水位（bench 预填）。无池默认 false。
    fn pool_wait_ready(&self, _n: usize, _timeout: Duration) -> bool {
        false
    }

    /// 阻塞等热池水位（bench 预填）。无池默认 false。
    fn hot_wait_ready(&self, _n: usize, _timeout: Duration) -> bool {
        false
    }

    /// 温池 (hits, misses, ready_len)；无池默认 None。
    fn pool_stats(&self) -> Option<(u64, u64, usize)> {
        None
    }

    // —— pause/resume/fork（M2 W9 / FR-1.4 / M2-Q5；能力门控，默认不支持）——

    /// 暂停：落快照 + 停 VM（需 `pause_resume`）。默认后端不支持。
    fn pause(&mut self, _id: &str) -> Result<(), String> {
        Err(format!("{UNSUPPORTED_BY_BACKEND}: 后端 {} 无 pause_resume，不支持 pause", self.id()))
    }

    /// 恢复：从快照拉起（需 `pause_resume`）。返回 reinit 换发的新 machine-id。默认后端不支持。
    fn resume(&mut self, _id: &str) -> Result<String, String> {
        Err(format!("{UNSUPPORTED_BY_BACKEND}: 后端 {} 无 pause_resume，不支持 resume", self.id()))
    }

    /// fork：从父快照派生新实例（需 `snapshot_fork`）。新实例经 reinit 得**独立身份**（克隆熵不泄漏），
    /// 但复用父 rootfs/快照——**不刷新安全边界**。默认后端不支持。
    fn fork(&mut self, _id: &str) -> Result<BackendCreate, String> {
        Err(format!("{UNSUPPORTED_BY_BACKEND}: 后端 {} 无 snapshot_fork，不支持 fork", self.id()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_name_roundtrip() {
        for c in Capability::ALL {
            assert_eq!(Capability::from_str(c.as_str()), Some(c));
        }
        assert_eq!(Capability::from_str("nope"), None);
    }

    #[test]
    fn capabilities_contains_and_missing() {
        let fc = Capabilities::with(&[
            Capability::PauseResume,
            Capability::PrebakeSnapshot,
            Capability::SnapshotFork,
        ]);
        assert!(fc.contains(Capability::PauseResume));
        assert!(!fc.contains(Capability::GpuPassthrough));
        // required 全被满足 → 无缺失
        let req_ok = Capabilities::with(&[Capability::PauseResume]);
        assert!(req_ok.missing_from(&fc).is_empty());
        // required 含后端没有的 → 缺失非空（创建期拒）
        let req_bad = Capabilities::with(&[Capability::GpuPassthrough, Capability::PauseResume]);
        assert_eq!(req_bad.missing_from(&fc), vec!["gpu_passthrough"]);
    }

    #[test]
    fn from_names_and_names() {
        let caps = Capabilities::from_names(&["pause_resume", "snapshot_fork"]).unwrap();
        assert_eq!(caps.names(), vec!["pause_resume", "snapshot_fork"]);
        // 未知名 → Err（含 UNSUPPORTED_BY_BACKEND 前缀）
        let e = Capabilities::from_names(&["bogus"]).unwrap_err();
        assert!(e.starts_with(UNSUPPORTED_BY_BACKEND));
    }

    #[test]
    fn empty_default() {
        assert!(Capabilities::empty().is_empty());
        assert!(Capabilities::default().is_empty());
        assert!(Capabilities::empty().missing_from(&Capabilities::empty()).is_empty());
    }
}
