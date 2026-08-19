//! dmthin — device-mapper thin provisioning 存储栈（ADR-23，M1 W3）。
//!
//! 模型：一个 thin-pool（dev/CI 走 loopback，生产走真块设备/LVM）；模板 base rootfs 载入
//! 一个 thin 卷作 **CoW origin**；每沙箱一个 base 的 **thin snapshot** 供 FC 挂 rootfs。
//! 沙箱写落 CoW 独有块、不污染 base；销毁 = `dmsetup remove` + pool `delete <dev_id>` 释放独有块。
//!
//! 特权模型（承 D2「node agent 转特权」）：device-mapper ioctl 需 CAP_SYS_ADMIN。
//!   - euid==0（生产 / 用户 `sudo -E`）：直呼 dmsetup/losetup/mkfs.ext4。
//!   - 非 root（dev/CI-light）：走 `sudo -n <工具>`，依赖 scoped NOPASSWD 白名单
//!     （dmsetup/losetup/modprobe/mkfs.ext4 均在内）——故 Q5 对账可非交互自助跑。
//!
//! thin-pool 表：`0 <data_sectors> thin-pool <meta> <data> <block_sectors> <low_water>`。
//! dmsetup status thin-pool：`… <meta_used>/<meta_total> <data_used>/<data_total> …`（字段 4/5）。

use std::path::PathBuf;
use std::process::Command;

const BLOCK_SECTORS: u64 = 128; // 64KiB CoW 块（与 verify-dmthin.sh 一致）

/// 每 MiB 对应扇区数（512B/扇区）。
fn mb_sectors(mb: u64) -> u64 {
    mb * 1024 * 1024 / 512
}

#[derive(Clone)]
pub struct ThinCfg {
    pub pool: String,      // pool 的 dm 名，如 "sl-pool"
    pub workdir: PathBuf,  // loop 镜像所在目录（build/dmthin）
    pub data_mb: u64,      // pool data 容量
    pub meta_mb: u64,      // pool metadata 容量
    pub thin_mb: u64,      // 每卷虚拟大小（thin provisioning，可超 pool）
    pub root: bool,        // euid==0 → 直呼工具；否则 sudo -n
}

impl ThinCfg {
    pub fn new(workdir: PathBuf, root: bool) -> Self {
        Self { pool: "sl-pool".into(), workdir, data_mb: 256, meta_mb: 16, thin_mb: 128, root }
    }
}

/// 起一个特权工具进程：root 直呼，否则 `sudo -n`（白名单免密）。
fn priv_run(root: bool, tool: &str, args: &[&str]) -> Result<String, String> {
    let mut c = if root {
        Command::new(tool)
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(tool);
        c
    };
    c.args(args);
    let out = c.output().map_err(|e| format!("执行 {tool} 失败: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!(
            "{tool} {:?} 失败（code={:?}）: {}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// 已建好的 thin pool（持有 loop 设备句柄供拆除）。
pub struct Pool {
    cfg: ThinCfg,
    data_loop: String,
    meta_loop: String,
    data_img: PathBuf,
    meta_img: PathBuf,
}

impl Pool {
    /// 建 pool：稀疏镜像 → loopback → dmsetup thin-pool。新建镜像天然全零 = 空 metadata。
    pub fn setup(cfg: ThinCfg) -> Result<Pool, String> {
        let _ = priv_run(cfg.root, "modprobe", &["dm_thin_pool"]); // 已内建则忽略
        std::fs::create_dir_all(&cfg.workdir).map_err(|e| format!("建 dmthin workdir 失败: {e}"))?;
        let data_img = cfg.workdir.join(format!("{}.data.img", cfg.pool));
        let meta_img = cfg.workdir.join(format!("{}.meta.img", cfg.pool));

        // 清上轮同名残留（best-effort）：先拆 pool 再 detach 可能占用的 loop
        let _ = priv_run(cfg.root, "dmsetup", &["remove", "--retry", &cfg.pool]);
        for img in [&data_img, &meta_img] {
            if let Ok(existing) = loop_for_backing(cfg.root, img) {
                let _ = priv_run(cfg.root, "losetup", &["-d", &existing]);
            }
        }

        // 稀疏镜像（set_len 不占实际块，metadata 读作全零 → pool 视为空）
        for (img, mb) in [(&data_img, cfg.data_mb), (&meta_img, cfg.meta_mb)] {
            let _ = std::fs::remove_file(img);
            let f = std::fs::File::create(img).map_err(|e| format!("建镜像 {} 失败: {e}", img.display()))?;
            f.set_len(mb * 1024 * 1024).map_err(|e| format!("truncate 镜像失败: {e}"))?;
        }

        let data_loop = priv_run(cfg.root, "losetup", &["--find", "--show", &data_img.to_string_lossy()])?;
        let meta_loop = priv_run(cfg.root, "losetup", &["--find", "--show", &meta_img.to_string_lossy()])?;

        let table = format!(
            "0 {} thin-pool {meta_loop} {data_loop} {BLOCK_SECTORS} 0",
            mb_sectors(cfg.data_mb)
        );
        if let Err(e) = priv_run(cfg.root, "dmsetup", &["create", &cfg.pool, "--table", &table]) {
            // 建 pool 失败也要回收已占用的 loop
            let _ = priv_run(cfg.root, "losetup", &["-d", &data_loop]);
            let _ = priv_run(cfg.root, "losetup", &["-d", &meta_loop]);
            return Err(format!("建 thin-pool 失败: {e}"));
        }
        Ok(Pool { cfg, data_loop, meta_loop, data_img, meta_img })
    }

    pub fn pool_dev(&self) -> String {
        format!("/dev/mapper/{}", self.cfg.pool)
    }
    pub fn thin_dev(name: &str) -> String {
        format!("/dev/mapper/{name}")
    }

    /// pool 已用 data 块数（Q5 对账口径：销毁应使其回到 base 建立后的 baseline）。
    pub fn data_used(&self) -> Result<u64, String> {
        let s = priv_run(self.cfg.root, "dmsetup", &["status", &self.pool_dev()])?;
        // "0 <len> thin-pool <txid> <m_used>/<m_total> <d_used>/<d_total> …"
        let f: Vec<&str> = s.split_whitespace().collect();
        f.get(5)
            .and_then(|x| x.split('/').next())
            .and_then(|x| x.parse::<u64>().ok())
            .ok_or_else(|| format!("解析 pool status 失败: {s:?}"))
    }

    /// 建模板 base origin：pool 内新建 thin 卷 <dev_id>，激活后 mkfs 布 ext4，再停用（dev_id 留在 pool）。
    /// 停用后其 snapshot 无需 suspend origin 即可一致创建。
    pub fn create_base(&self, dev_id: u64) -> Result<(), String> {
        priv_run(self.cfg.root, "dmsetup", &["message", &self.pool_dev(), "0", &format!("create_thin {dev_id}")])?;
        let name = format!("{}-base", self.cfg.pool);
        let table = format!("0 {} thin {} {dev_id}", mb_sectors(self.cfg.thin_mb), self.pool_dev());
        priv_run(self.cfg.root, "dmsetup", &["create", &name, "--table", &table])?;
        priv_run(self.cfg.root, "mkfs.ext4", &["-q", "-F", &Pool::thin_dev(&name)])?;
        priv_run(self.cfg.root, "dmsetup", &["remove", "--retry", &name])?; // dev_id 留在 pool metadata
        Ok(())
    }

    /// 从真 rootfs 镜像建 base origin：新建 thin 卷 <dev_id>，激活后 dd 灌入镜像，再停用。
    /// dd 非白名单，仅 root 直呼可用 → `--thin` 全流程需 root（用户 sudo -E 跑）。
    pub fn create_base_from_image(&self, dev_id: u64, image: &std::path::Path) -> Result<(), String> {
        priv_run(self.cfg.root, "dmsetup", &["message", &self.pool_dev(), "0", &format!("create_thin {dev_id}")])?;
        let name = format!("{}-base", self.cfg.pool);
        let table = format!("0 {} thin {} {dev_id}", mb_sectors(self.cfg.thin_mb), self.pool_dev());
        priv_run(self.cfg.root, "dmsetup", &["create", &name, "--table", &table])?;
        let dev = Pool::thin_dev(&name);
        let r = priv_run(
            self.cfg.root,
            "dd",
            &[&format!("if={}", image.display()), &format!("of={dev}"), "bs=4M", "conv=fsync"],
        );
        let _ = priv_run(self.cfg.root, "dmsetup", &["remove", "--retry", &name]); // dev_id 留在 pool
        r.map(|_| ())
    }

    /// 建 per-sandbox thin snapshot（origin_id 的 CoW 派生）并激活为 /dev/mapper/<name>。
    pub fn snapshot(&self, origin_id: u64, snap_id: u64, name: &str) -> Result<String, String> {
        priv_run(
            self.cfg.root,
            "dmsetup",
            &["message", &self.pool_dev(), "0", &format!("create_snap {snap_id} {origin_id}")],
        )?;
        let table = format!("0 {} thin {} {snap_id}", mb_sectors(self.cfg.thin_mb), self.pool_dev());
        priv_run(self.cfg.root, "dmsetup", &["create", name, "--table", &table])?;
        Ok(Pool::thin_dev(name))
    }

    /// 销毁 per-sandbox thin：停用 dm 设备 + pool 删除 dev_id（释放其独有块，无孤儿）。
    pub fn destroy_thin(&self, snap_id: u64, name: &str) -> Result<(), String> {
        priv_run(self.cfg.root, "dmsetup", &["remove", "--retry", name])?;
        priv_run(self.cfg.root, "dmsetup", &["message", &self.pool_dev(), "0", &format!("delete {snap_id}")])?;
        Ok(())
    }

    /// dm 设备是否存在（对账残留用）。
    pub fn dev_exists(&self, name: &str) -> bool {
        priv_run(self.cfg.root, "dmsetup", &["info", name]).is_ok()
    }

    /// 拆除 pool + detach loop + 删镜像（best-effort，吞错）。消费 self。
    pub fn teardown(self) {
        let _ = priv_run(self.cfg.root, "dmsetup", &["remove", "--retry", &self.cfg.pool]);
        let _ = priv_run(self.cfg.root, "losetup", &["-d", &self.data_loop]);
        let _ = priv_run(self.cfg.root, "losetup", &["-d", &self.meta_loop]);
        let _ = std::fs::remove_file(&self.data_img);
        let _ = std::fs::remove_file(&self.meta_img);
    }
}

/// 查某镜像文件当前绑定的 loop 设备（无则 Err）。用于清理上轮残留。
fn loop_for_backing(root: bool, img: &std::path::Path) -> Result<String, String> {
    let out = priv_run(root, "losetup", &["-j", &img.to_string_lossy()])?;
    // "/dev/loop3: [2049]:12345 (/path/img)"
    out.split(':').next().filter(|s| !s.is_empty()).map(|s| s.to_string()).ok_or_else(|| "无绑定".into())
}

/// Q5 销毁对账（task 35）：反复 create per-sandbox thin snapshot → mkfs 写工作负载 → destroy，
/// 断言 ① 写使 used_data 上升（CoW 分配新块，未原地改 base）② 销毁后回到 baseline（释放独有块）
/// ③ 无残留 dm 设备 ④ base 全程完好。返回 JSON metric。
pub fn reconcile(cfg: ThinCfg, cycles: usize, json: bool) -> Result<(), String> {
    let cycles = if cycles == 0 { 3 } else { cycles };
    if !json {
        println!(
            "[dmthin] Q5 对账：pool={} data={}MB thin={}MB cycles={} 特权={}",
            cfg.pool,
            cfg.data_mb,
            cfg.thin_mb,
            cycles,
            if cfg.root { "root 直呼" } else { "sudo -n 白名单" }
        );
    }
    let pool = Pool::setup(cfg)?;

    let outcome = (|| -> Result<u64, String> {
        pool.create_base(0)?;
        let baseline = pool.data_used()?; // base 建立后的基准占用
        if !json {
            println!("[dmthin]   base origin(dev_id=0) 就绪，baseline used_data={baseline} 块");
        }
        for i in 0..cycles {
            let snap_id = 100 + i as u64;
            let name = format!("sl-thin-{i}");
            let dev = pool.snapshot(0, snap_id, &name)?;
            let after_snap = pool.data_used()?; // 应≈baseline（共享 base 块，create_snap 不分配）

            // 写工作负载：给 snapshot 布全新 ext4 → CoW 为被覆盖/新块分配独有块
            priv_run(pool.cfg.root, "mkfs.ext4", &["-q", "-F", &dev])?;
            let after_write = pool.data_used()?;
            if after_write <= baseline {
                return Err(format!(
                    "cycle {i}: 写后 used_data={after_write} 未超 baseline={baseline}——CoW 未分配独有块？"
                ));
            }

            pool.destroy_thin(snap_id, &name)?;
            let after_destroy = pool.data_used()?;
            // ① 块释放：回到 baseline（独有块全数释放，无孤儿块）
            if after_destroy != baseline {
                return Err(format!(
                    "cycle {i}: 销毁后 used_data={after_destroy} != baseline={baseline}——独有块未释放（残留块）"
                ));
            }
            // ② 无残留 dm 设备
            if pool.dev_exists(&name) {
                return Err(format!("cycle {i}: 残留 dm 设备 {name}"));
            }
            if !json {
                println!(
                    "[dmthin]   轮 {}/{}: snap={after_snap} 写后={after_write}(+{}) 销毁后={after_destroy} ✓",
                    i + 1,
                    cycles,
                    after_write - baseline
                );
            }
        }

        // ③ base 完好：再派生+mkfs+销毁一次应仍成功，且 used_data 复位
        let dev = pool.snapshot(0, 999, "sl-thin-final")?;
        priv_run(pool.cfg.root, "mkfs.ext4", &["-q", "-F", &dev])?;
        pool.destroy_thin(999, "sl-thin-final")?;
        let final_used = pool.data_used()?;
        if final_used != baseline {
            return Err(format!("末轮后 used_data={final_used} != baseline={baseline}——base 受损或残留"));
        }
        Ok(baseline)
    })();

    pool.teardown(); // 无论成败都拆干净

    let baseline = outcome?;
    // 拆除后断言无残留 pool 设备
    let resid = priv_run(false, "dmsetup", &["ls"]).unwrap_or_default();
    let leaked: Vec<&str> = resid.lines().filter(|l| l.contains("sl-pool") || l.contains("sl-thin")).collect();
    if !leaked.is_empty() {
        return Err(format!("拆除后残留 dm 设备: {leaked:?}"));
    }

    if json {
        println!(r#"{{"metric":"dmthin_reconcile","cycles":{cycles},"baseline_blocks":{baseline},"cow_correct":true,"blocks_released":true,"orphans":0}}"#);
    } else {
        println!("[dmthin] ✅ Q5 PASS：{cycles} 轮 CoW 写→销毁，独有块全数释放、无残留设备、base 完好");
    }
    Ok(())
}
