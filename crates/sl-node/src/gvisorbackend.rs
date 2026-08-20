//! gvisorbackend.rs — gVisor(runsc) 后端（M2 W7，ADR-14 / M2-Q4）。
//!
//! 第二后端，短任务高密度定位。实现 [`SandboxBackend`]，能力集**空**（无 prebake/pause/fork/gpu/pv）
//! → 池由 trait 默认实现门控（只冷创建）。数据面 exec = `runsc exec`（无 vsock/sl-envd）。
//!
//! **rootless 生命周期**（本机探活）：`create` 在 rootless 下不支持 → 用 `run --detach`
//! （stdio 重定向到 `init.log`，否则 init 立退）保持常驻沙箱；`runsc exec` 命中运行中沙箱；
//! `kill KILL` + `delete --force` 拆除。全局 flags `--rootless --platform=systrap --network=none`
//! （默认 net 需 root 建 veth）。OCI bundle 的 rootfs 由 `debugfs rdump` 从模板 `rootfs.ext4` 抽出
//! （无 root），模板级懒抽一次 + 每实例 reflink 私有副本；config.json 由 `runsc spec` 生成后打补丁。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::backend::{BackendCreate, Capabilities, ExecTarget, SandboxBackend};
use crate::orch::SandboxSpec;
use crate::{abspath, hex, host_random};

struct GvInst {
    /// OCI bundle 目录（`run_root/<id>`，内含 rootfs/ + config.json + init.log）。destroy 删它。
    bundle: PathBuf,
}

/// gVisor(runsc) 后端。全局 flags 固定 rootless/systrap/no-net；state root 共享（`--root`）。
pub struct GvisorBackend {
    runsc_bin: PathBuf,
    run_root: PathBuf,
    /// 模板 rootfs 抽取缓存根（`run_root/.gvisor-rootfs/<template-hash>`）。
    rootfs_cache: PathBuf,
    /// runsc 全局 flags（含 `--root <state>`），run/exec/kill/delete 共用。
    global_args: Vec<String>,
    live: HashMap<String, GvInst>,
}

impl GvisorBackend {
    pub fn new(runsc_bin: PathBuf, run_root: PathBuf) -> Self {
        let state_root = run_root.join(".gvisor-state");
        let rootfs_cache = run_root.join(".gvisor-rootfs");
        let global_args = vec![
            "--root".to_string(),
            state_root.to_string_lossy().into_owned(),
            "--rootless".to_string(),
            "--platform=systrap".to_string(),
            "--network=none".to_string(),
        ];
        Self { runsc_bin, run_root, rootfs_cache, global_args, live: HashMap::new() }
    }

    /// runsc 是否可用（`runsc --version` 成功）。供 Orch 决定是否注册本后端。
    pub fn probe(runsc_bin: &Path) -> bool {
        Command::new(runsc_bin)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// 模板 rootfs 懒抽取到缓存（`debugfs rdump`，无 root），返回缓存 rootfs 目录。已抽则复用。
    fn ensure_rootfs_cache(&self, template: &Path) -> Result<PathBuf, String> {
        let key = {
            let mut h = Sha256::new();
            h.update(template.to_string_lossy().as_bytes());
            hex(&h.finalize()[..8])
        };
        let dst = self.rootfs_cache.join(&key);
        let rootfs = dst.join("rootfs");
        // 完成标记：避免半成品缓存被复用。
        let done = dst.join(".done");
        if done.exists() && rootfs.join("bin/busybox").exists() {
            return Ok(rootfs);
        }
        let _ = std::fs::remove_dir_all(&dst);
        std::fs::create_dir_all(&rootfs).map_err(|e| format!("建 gVisor rootfs 缓存失败: {e}"))?;
        let ext4 = template.join("rootfs.ext4");
        // debugfs rdump 从 ext4 抽整树（chown 警告无害，非 root）。
        let out = Command::new("debugfs")
            .arg("-R")
            .arg(format!("rdump / {}", rootfs.display()))
            .arg(&ext4)
            .output()
            .map_err(|e| format!("debugfs 启动失败（装 e2fsprogs?）: {e}"))?;
        if !rootfs.join("bin/busybox").exists() {
            return Err(format!(
                "debugfs 抽取 rootfs 失败: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        std::fs::write(&done, b"ok").ok();
        Ok(rootfs)
    }

    /// 生成 bundle：私有 rootfs（reflink 缓存）+ config.json（runsc spec → 打补丁：sleep init/no-tty）。
    fn prepare_bundle(&self, id: &str, cache_rootfs: &Path) -> Result<PathBuf, String> {
        let bundle = self.run_root.join(id);
        let _ = std::fs::remove_dir_all(&bundle);
        std::fs::create_dir_all(&bundle).map_err(|e| format!("建 gVisor bundle 失败: {e}"))?;
        // 私有 rootfs（reflink→回退全拷），令实例写不互串。
        let dst_rootfs = bundle.join("rootfs");
        let cp = Command::new("cp")
            .arg("-a")
            .arg("--reflink=auto")
            .arg(cache_rootfs)
            .arg(&dst_rootfs)
            .status()
            .map_err(|e| format!("拷贝 gVisor rootfs 失败: {e}"))?;
        if !cp.success() {
            return Err("拷贝 gVisor rootfs 非零退出".into());
        }
        // 生成 OCI spec（runsc 自身的规范默认），再打补丁。
        let spec_ok = Command::new(&self.runsc_bin)
            .arg("spec")
            .arg("--bundle")
            .arg(&bundle)
            .status()
            .map_err(|e| format!("runsc spec 启动失败: {e}"))?;
        if !spec_ok.success() {
            return Err("runsc spec 生成 config.json 失败".into());
        }
        let cfg_path = bundle.join("config.json");
        let raw = std::fs::read(&cfg_path).map_err(|e| format!("读 config.json 失败: {e}"))?;
        let mut cfg: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| format!("解析 config.json 失败: {e}"))?;
        // 补丁：init = 长驻 sleep（保持常驻沙箱供 exec）；关 tty（无 console-socket）。
        cfg["process"]["terminal"] = serde_json::json!(false);
        cfg["process"]["args"] = serde_json::json!(["/bin/sh", "-c", "sleep 2147483647"]);
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap())
            .map_err(|e| format!("写 config.json 失败: {e}"))?;
        Ok(bundle)
    }
}

impl SandboxBackend for GvisorBackend {
    fn id(&self) -> &str {
        "gvisor"
    }

    fn capabilities(&self) -> Capabilities {
        // 短任务路径：显式不承诺 prebake/pause/fork/gpu/pv（ADR-14「能力对等而非功能对等」）。
        Capabilities::empty()
    }

    fn create(&mut self, template: &Path, _spec: &SandboxSpec) -> Result<BackendCreate, String> {
        if !template.is_dir() {
            return Err(format!("模板目录不存在: {}", template.display()));
        }
        let template = abspath(template)?;
        let t0 = Instant::now();
        let cache_rootfs = self.ensure_rootfs_cache(&template)?;

        let mut idb = [0u8; 6];
        host_random(&mut idb);
        let id = hex(&idb);
        let bundle = self.prepare_bundle(&id, &cache_rootfs)?;
        let copy_ms = t0.elapsed().as_millis();

        // run --detach（stdio 重定向到 init.log，否则 rootless init 立退）。
        let log = std::fs::File::create(bundle.join("init.log"))
            .map_err(|e| format!("建 gVisor init.log 失败: {e}"))?;
        let run_at = Instant::now();
        let status = Command::new(&self.runsc_bin)
            .args(&self.global_args)
            .arg("run")
            .arg("--detach")
            .arg("--bundle")
            .arg(&bundle)
            .arg(&id)
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log)
            .status()
            .map_err(|e| format!("runsc run 启动失败: {e}"))?;
        if !status.success() {
            let _ = self.destroy_by_bundle(&id, &bundle);
            let tail = std::fs::read_to_string(bundle.join("init.log")).unwrap_or_default();
            return Err(format!(
                "runsc run --detach 失败（rc={:?}）: {}",
                status.code(),
                tail.lines().last().unwrap_or("")
            ));
        }
        let resume_ms = run_at.elapsed().as_millis();

        // gVisor 无 reinit/machine-id 机制；每实例独立沙箱+私有 rootfs 天然隔离，用随机 token 充 machine_id。
        let mut mid = [0u8; 16];
        host_random(&mut mid);
        let machine_id = hex(&mid);

        self.live.insert(id.clone(), GvInst { bundle });
        Ok(BackendCreate {
            id,
            machine_id,
            total_ms: copy_ms.saturating_add(resume_ms),
            copy_ms,
            api_ready_ms: 0,
            load_ms: 0,
            resume_ms,
            pool_hit: false,
            hot_hit: false,
        })
    }

    fn destroy(&mut self, id: &str) {
        if let Some(inst) = self.live.remove(id) {
            let _ = self.destroy_by_bundle(id, &inst.bundle);
        }
    }

    fn exec_target(&self, id: &str) -> Option<ExecTarget> {
        self.live.get(id).map(|_| ExecTarget::Runsc {
            bin: self.runsc_bin.clone(),
            global_args: self.global_args.clone(),
            id: id.to_string(),
        })
    }

    fn instance_dir(&self, id: &str) -> Option<PathBuf> {
        self.live.get(id).map(|i| i.bundle.clone())
    }

    fn log_path(&self, id: &str) -> Option<PathBuf> {
        self.live.get(id).map(|i| i.bundle.join("init.log"))
    }
}

impl GvisorBackend {
    /// 幂等拆除：kill KILL → delete --force → 删 bundle（忽略各步错误）。
    fn destroy_by_bundle(&self, id: &str, bundle: &Path) -> Result<(), String> {
        let _ = Command::new(&self.runsc_bin).args(&self.global_args).arg("kill").arg(id).arg("KILL").output();
        let _ = Command::new(&self.runsc_bin).args(&self.global_args).arg("delete").arg("--force").arg(id).output();
        let _ = std::fs::remove_dir_all(bundle);
        Ok(())
    }
}
