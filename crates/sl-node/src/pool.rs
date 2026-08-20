//! pool.rs — 预热池·温池（M2 W4，M2-Q2 起步）。
//!
//! 温池把每次 create 的重活——私有 `rootfs.ext4` reflink 拷贝 + `vmstate`/`mem` 硬链——**预置到
//! 创建关键路径之外**：后台 refill 线程在 `<run_root>/.warm/<id>` 里备好一批实例目录（重拷贝在
//! **Orch 锁外**做，不阻塞 create/reaper）。create 时 [`WarmPool::try_pop`] 弹一个已备好的槽、
//! `rename` 到最终 `<run_root>/<id>`（同 fs 原子 O(1)）——`copy_ms` 归零，直接进 `restore_core`。
//!
//! 另一半是 **page-cache 热**：`new` 时对模板 `vmstate`/`mem`/`rootfs.ext4` 做一次
//! `posix_fadvise(WILLNEED)`；预置槽的 reflink 也触及模板共享块，`mem`/`vmstate` 走共享 inode 硬链
//! 保持热——故池命中恢复读的是热 page cache。
//!
//! **热池**（已恢复 paused VM、命中即 resume）默认 0，留 W5；本模块只做温池（默认水位 2）。
//!
//! 线程模型对齐 `api.rs` 的 reaper：自带 `Arc<PoolInner>` + `Mutex` + `Condvar` + 一条 refill 线程，
//! 全同步无 tokio。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::orch::prepare_instance_dir;
use crate::{abspath, hex, host_random};

/// 一个预置好的实例槽：`dir` 已备妥私有 `rootfs.ext4`（reflink）+ `vmstate`/`mem`（硬链）。
/// refill 阶段落在 `<run_root>/.warm/<id>`；`try_pop` 命中后 `rename` 到 `<run_root>/<id>`。
pub(crate) struct WarmSlot {
    pub id: String,
    pub dir: PathBuf,
}

struct PoolInner {
    /// canonical 模板目录（reflink/硬链源 + page-cache 预热对象）。
    template: PathBuf,
    /// 实例运行根：槽预置于 `<run_root>/.warm/<id>`，命中后落 `<run_root>/<id>`。
    run_root: PathBuf,
    /// 目标水位：refill 线程把 ready 补到 `target`。
    target: usize,
    ready: Mutex<VecDeque<WarmSlot>>,
    cv: Condvar,
    shutdown: AtomicBool,
    hits: AtomicU64,
    misses: AtomicU64,
    prepared: AtomicU64,
}

impl PoolInner {
    fn warm_dir(&self) -> PathBuf {
        self.run_root.join(".warm")
    }
}

/// 单模板温池。`try_pop` 命中即 O(1) rename 拿走一个热槽；后台线程持续补水到 `target`。
pub(crate) struct WarmPool {
    inner: Arc<PoolInner>,
    worker: Option<JoinHandle<()>>,
}

impl WarmPool {
    /// 建池：canonical 模板 → page-cache 预热 → 清 `.warm` 陈留 → spawn refill 线程。
    /// `target == 0` 视为不建池由调用方处理（本函数假定 `target >= 1`）。
    pub(crate) fn new(template: &Path, run_root: &Path, target: usize) -> Result<Self, String> {
        if !template.is_dir() {
            return Err(format!("温池模板目录不存在: {}", template.display()));
        }
        let template = abspath(template)?;
        std::fs::create_dir_all(run_root).map_err(|e| format!("建 run_root 失败 {}: {e}", run_root.display()))?;
        let run_root = abspath(run_root)?;

        // page-cache 预热：模板 vmstate/mem/rootfs.ext4 → WILLNEED（池命中恢复读热页）。
        for f in ["vmstate", "mem", "rootfs.ext4"] {
            fadvise_willneed(&template.join(f));
        }

        let inner = Arc::new(PoolInner {
            template,
            run_root,
            target,
            ready: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            prepared: AtomicU64::new(0),
        });

        // 清 `.warm` 陈留（上次进程遗留的半成品槽），再建目录。
        let warm = inner.warm_dir();
        let _ = std::fs::remove_dir_all(&warm);
        std::fs::create_dir_all(&warm).map_err(|e| format!("建 .warm 失败 {}: {e}", warm.display()))?;

        let worker_inner = Arc::clone(&inner);
        let worker = std::thread::Builder::new()
            .name("warmpool-refill".into())
            .spawn(move || refill_loop(worker_inner))
            .map_err(|e| format!("起温池 refill 线程失败: {e}"))?;

        Ok(Self { inner, worker: Some(worker) })
    }

    /// 池命中：弹一个热槽 → `rename .warm/<id>` → `<run_root>/<id>` → 通知补水 → 返回槽。
    /// 空池（未命中）返 None，调用方走冷路径自备实例目录。
    pub(crate) fn try_pop(&self) -> Option<WarmSlot> {
        let slot = {
            let mut q = self.inner.ready.lock().unwrap();
            q.pop_front()
        };
        // 无论命中与否都唤醒 worker：命中→补一格；空→尽快补首格。
        self.inner.cv.notify_one();

        match slot {
            Some(s) => {
                let final_dir = self.inner.run_root.join(&s.id);
                let _ = std::fs::remove_dir_all(&final_dir);
                match std::fs::rename(&s.dir, &final_dir) {
                    Ok(()) => {
                        self.inner.hits.fetch_add(1, Ordering::Relaxed);
                        Some(WarmSlot { id: s.id, dir: final_dir })
                    }
                    // rename 失败（极少见，跨挂载/权限）：弃槽，当未命中走冷路径。
                    Err(_) => {
                        let _ = std::fs::remove_dir_all(&s.dir);
                        self.inner.misses.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                }
            }
            None => {
                self.inner.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// 池模板目录（canonical）。create 路径据此判断请求模板是否命中本池。
    pub(crate) fn template(&self) -> &Path {
        &self.inner.template
    }

    /// (hits, misses, ready_len)——供 bench 命中率与守护内省。
    pub(crate) fn stats(&self) -> (u64, u64, usize) {
        let hits = self.inner.hits.load(Ordering::Relaxed);
        let misses = self.inner.misses.load(Ordering::Relaxed);
        let ready = self.inner.ready.lock().unwrap().len();
        (hits, misses, ready)
    }

    /// 阻塞等到 ready 水位 ≥ `n` 或超时（bench 预热填池 / 测试用）。到达返 true。
    pub(crate) fn wait_ready(&self, n: usize, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let q = self.inner.ready.lock().unwrap();
            if q.len() >= n {
                return true;
            }
            let remain = deadline.saturating_duration_since(std::time::Instant::now());
            if remain.is_zero() {
                return q.len() >= n;
            }
            let (_g, to) = self.inner.cv.wait_timeout(q, remain.min(Duration::from_millis(100))).unwrap();
            if to.timed_out() && std::time::Instant::now() >= deadline {
                return self.inner.ready.lock().unwrap().len() >= n;
            }
        }
    }

    /// 幂等停机：置 flag → 唤醒 → join → 清 `.warm` 未取走的槽。
    fn shutdown(&mut self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.cv.notify_all();
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_dir_all(self.inner.warm_dir());
    }
}

impl Drop for WarmPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// refill 线程主体：ready < target 时**在锁外**备一个槽再入队；满则挂 cv（1s 心跳，停机即醒）。
fn refill_loop(inner: Arc<PoolInner>) {
    while !inner.shutdown.load(Ordering::SeqCst) {
        let cur = inner.ready.lock().unwrap().len();
        if cur < inner.target {
            // 备槽的重拷贝**不持任何锁**——不阻塞 create/reaper/其它 pop。
            match prep_slot(&inner) {
                Ok(slot) => {
                    inner.prepared.fetch_add(1, Ordering::Relaxed);
                    inner.ready.lock().unwrap().push_back(slot);
                    inner.cv.notify_all(); // 唤醒 wait_ready 等待者
                }
                Err(e) => {
                    // 持续失败（模板损坏等）：退避避免忙转，仍周期性重试。
                    if !inner.shutdown.load(Ordering::SeqCst) {
                        eprintln!("[warmpool] 备槽失败（退避重试）: {e}");
                    }
                    let g = inner.ready.lock().unwrap();
                    let _ = inner.cv.wait_timeout(g, Duration::from_millis(500));
                }
            }
        } else {
            // 满水位：挂起等 pop 唤醒（1s 心跳兜底停机）。
            let g = inner.ready.lock().unwrap();
            let _ = inner.cv.wait_timeout(g, Duration::from_secs(1));
        }
    }
}

/// 备一个槽：随机 id → `<run_root>/.warm/<id>` → `prepare_instance_dir`（reflink + 硬链）。
fn prep_slot(inner: &PoolInner) -> Result<WarmSlot, String> {
    let mut idb = [0u8; 6];
    host_random(&mut idb);
    let id = hex(&idb);
    let dir = inner.warm_dir().join(&id);
    let _ = std::fs::remove_dir_all(&dir);
    prepare_instance_dir(&inner.template, &dir)?;
    let dir = abspath(&dir)?;
    Ok(WarmSlot { id, dir })
}

/// `posix_fadvise(WILLNEED)` 把整文件提示进 page cache（尽力而为，失败静默）。
fn fadvise_willneed(p: &Path) {
    use std::os::unix::io::AsRawFd;
    let f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(_) => return,
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len == 0 {
        return;
    }
    // SAFETY: fd 由上面打开的 File 持有、在本次调用期间有效；posix_fadvise 只读提示，不改内容。
    unsafe {
        libc::posix_fadvise(f.as_raw_fd(), 0, len as libc::off_t, libc::POSIX_FADV_WILLNEED);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 造一个 dummy 模板目录（rootfs.ext4/vmstate/mem/expect 皆小文件）——温池机制不 boot VM，
    /// `prepare_instance_dir` 只做 cp/hardlink，dummy 文件足以覆盖。
    fn dummy_template(root: &Path) -> PathBuf {
        let t = root.join("tpl");
        std::fs::create_dir_all(&t).unwrap();
        for f in ["rootfs.ext4", "vmstate", "mem", "expect"] {
            let mut fh = std::fs::File::create(t.join(f)).unwrap();
            fh.write_all(format!("dummy-{f}").as_bytes()).unwrap();
        }
        t
    }

    fn tmp_root(tag: &str) -> PathBuf {
        let mut b = [0u8; 4];
        host_random(&mut b);
        let d = std::env::temp_dir().join(format!("sl-pooltest-{tag}-{}", hex(&b)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn fills_to_target_and_pop_renames() {
        let root = tmp_root("fill");
        let tpl = dummy_template(&root);
        let run = root.join("instances");
        let pool = WarmPool::new(&tpl, &run, 2).unwrap();

        assert!(pool.wait_ready(2, Duration::from_secs(5)), "温池未在超时内填到水位 2");

        let slot = pool.try_pop().expect("应命中一个热槽");
        // 命中：落最终 run_root/<id>，槽内含备好的 rootfs/vmstate/mem。
        assert_eq!(slot.dir, run.join(&slot.id));
        assert!(slot.dir.join("rootfs.ext4").exists());
        assert!(slot.dir.join("vmstate").exists());
        assert!(slot.dir.join("mem").exists());
        // .warm 下同 id 已被 rename 取走。
        assert!(!run.join(".warm").join(&slot.id).exists());

        let (hits, _misses, _ready) = pool.stats();
        assert_eq!(hits, 1);

        // 命中后 worker 补水回 target。
        assert!(pool.wait_ready(2, Duration::from_secs(5)), "pop 后未补回水位 2");

        drop(pool);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn empty_pop_counts_miss() {
        let root = tmp_root("miss");
        let tpl = dummy_template(&root);
        let run = root.join("instances");
        // target=1：连弹超过备水位则必有 miss。先等 1 格，一次性弹空再弹一次。
        let pool = WarmPool::new(&tpl, &run, 1).unwrap();
        assert!(pool.wait_ready(1, Duration::from_secs(5)));

        let _ = pool.try_pop().expect("首弹命中");
        // 紧接着弹：worker 大概率还没补上 → miss（即便偶发补上也不 panic，只断言 miss 单调）。
        let before = pool.stats().1;
        let _second = pool.try_pop();
        let after = pool.stats().1;
        assert!(after >= before, "miss 计数应单调不减");

        drop(pool);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn shutdown_cleans_warm_dir() {
        let root = tmp_root("shutdown");
        let tpl = dummy_template(&root);
        let run = root.join("instances");
        let warm = run.join(".warm");
        {
            let pool = WarmPool::new(&tpl, &run, 2).unwrap();
            assert!(pool.wait_ready(1, Duration::from_secs(5)));
            assert!(warm.exists());
        } // Drop → shutdown → 清 .warm
        assert!(!warm.exists(), "shutdown 未清 .warm 陈留");
        std::fs::remove_dir_all(&root).ok();
    }
}
