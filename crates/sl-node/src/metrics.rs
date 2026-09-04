//! metrics.rs — 可观测性指标（M3 W8，§7.8，M3-Q5）。手写 Prometheus 文本曝露格式，**零依赖**
//! （std only，守全同步+精简依赖哲学）。进程内全局 registry，`GET /metrics` 渲染。
//!
//! 覆盖 §7.8 要点：沙箱创建延迟分位（histogram）、池命中率（hits/misses）、exec 延迟、当前沙箱数、
//! API 请求量。分位由 Prometheus 端 `histogram_quantile()` 从 bucket 算（本端只出 bucket/sum/count）。

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// 延迟直方图桶上界（毫秒）。含 +Inf（用 f64::INFINITY 渲染）。
const BUCKETS_MS: [f64; 10] = [10.0, 25.0, 50.0, 75.0, 100.0, 150.0, 250.0, 500.0, 1000.0, 2000.0];

#[derive(Default)]
struct Hist {
    /// 各桶累计计数（cumulative 在渲染时算）。
    counts: [u64; 11], // BUCKETS_MS.len() + 1 (+Inf)
    sum_ms: f64,
    count: u64,
}

impl Hist {
    fn observe(&mut self, ms: f64) {
        self.sum_ms += ms;
        self.count += 1;
        let mut idx = BUCKETS_MS.len(); // 默认落 +Inf 桶
        for (i, b) in BUCKETS_MS.iter().enumerate() {
            if ms <= *b {
                idx = i;
                break;
            }
        }
        self.counts[idx] += 1;
    }
    /// 渲染为 Prometheus histogram（le bucket 累计 + _sum + _count）。
    fn render(&self, name: &str, help: &str, out: &mut String) {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
        let mut cum = 0u64;
        for (i, b) in BUCKETS_MS.iter().enumerate() {
            cum += self.counts[i];
            out.push_str(&format!("{name}_bucket{{le=\"{b}\"}} {cum}\n"));
        }
        cum += self.counts[BUCKETS_MS.len()];
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {cum}\n"));
        out.push_str(&format!("{name}_sum {}\n", self.sum_ms));
        out.push_str(&format!("{name}_count {}\n", self.count));
    }
}

/// 进程内指标 registry。
pub struct Metrics {
    created: AtomicU64,
    destroyed: AtomicU64,
    current: AtomicI64,
    pool_hits: AtomicU64,
    pool_misses: AtomicU64,
    exec_total: AtomicU64,
    api_total: AtomicU64,
    api_errors: AtomicU64, // code >= 400
    create_hist: Mutex<Hist>,
    exec_hist: Mutex<Hist>,
    /// 本副本的 node id（`addr#pid`，与 `node/<id>` 心跳键、`sandbox/<sid>/node` 归属键同值）。
    /// 空 = 未设（单机 `run` 路径不起 serve，没有身份）。
    node_id: Mutex<String>,
}

impl Metrics {
    fn new() -> Self {
        Metrics {
            created: AtomicU64::new(0),
            destroyed: AtomicU64::new(0),
            current: AtomicI64::new(0),
            pool_hits: AtomicU64::new(0),
            pool_misses: AtomicU64::new(0),
            exec_total: AtomicU64::new(0),
            api_total: AtomicU64::new(0),
            api_errors: AtomicU64::new(0),
            create_hist: Mutex::new(Hist::default()),
            exec_hist: Mutex::new(Hist::default()),
            node_id: Mutex::new(String::new()),
        }
    }

    /// 记一次创建：延迟入直方图 + 命中/未命中计数 + created/current++。
    pub fn record_create(&self, total_ms: u128, pool_hit: bool) {
        self.created.fetch_add(1, Ordering::Relaxed);
        self.current.fetch_add(1, Ordering::Relaxed);
        if pool_hit {
            self.pool_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.pool_misses.fetch_add(1, Ordering::Relaxed);
        }
        self.create_hist.lock().unwrap().observe(total_ms as f64);
    }

    /// 记一次销毁：destroyed++ / current--（下限 0）。
    pub fn record_destroy(&self) {
        self.destroyed.fetch_add(1, Ordering::Relaxed);
        let prev = self.current.fetch_sub(1, Ordering::Relaxed);
        if prev <= 0 {
            self.current.store(0, Ordering::Relaxed); // 防 reaper/显式删双减到负
        }
    }

    /// 记一次 exec：计数 + 延迟入直方图。
    pub fn record_exec(&self, ms: u128) {
        self.exec_total.fetch_add(1, Ordering::Relaxed);
        self.exec_hist.lock().unwrap().observe(ms as f64);
    }

    /// 记一次 API 请求（附状态码：>=400 计入错误）。
    pub fn record_api(&self, code: u16) {
        self.api_total.fetch_add(1, Ordering::Relaxed);
        if code >= 400 {
            self.api_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 记本副本的 node id（`serve()` 启动时调一次）。
    pub fn set_node_id(&self, id: &str) {
        *self.node_id.lock().unwrap() = id.to_string();
    }

    /// 渲染 Prometheus 文本曝露格式。
    pub fn render(&self) -> String {
        let mut o = String::with_capacity(2048);
        let counter = |o: &mut String, name: &str, help: &str, v: u64| {
            o.push_str(&format!("# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}\n"));
        };
        counter(&mut o, "sandlocker_sandboxes_created_total", "沙箱创建累计", self.created.load(Ordering::Relaxed));
        counter(&mut o, "sandlocker_sandboxes_destroyed_total", "沙箱销毁累计", self.destroyed.load(Ordering::Relaxed));
        counter(&mut o, "sandlocker_pool_hits_total", "池命中累计", self.pool_hits.load(Ordering::Relaxed));
        counter(&mut o, "sandlocker_pool_misses_total", "池未命中（冷路径）累计", self.pool_misses.load(Ordering::Relaxed));
        counter(&mut o, "sandlocker_exec_total", "exec 累计", self.exec_total.load(Ordering::Relaxed));
        counter(&mut o, "sandlocker_api_requests_total", "API 请求累计", self.api_total.load(Ordering::Relaxed));
        counter(&mut o, "sandlocker_api_errors_total", "API 错误（>=400）累计", self.api_errors.load(Ordering::Relaxed));
        let cur = self.current.load(Ordering::Relaxed).max(0);
        o.push_str("# HELP sandlocker_sandboxes_current 当前存活沙箱数\n# TYPE sandlocker_sandboxes_current gauge\n");
        o.push_str(&format!("sandlocker_sandboxes_current {cur}\n"));
        // build_info：恒为 1 的 gauge，信息全在标签上——Prometheus 的惯用法。
        // 有它，看板才能按 node 拆分（M3-Q12），集群基准也才有办法**问一个副本"你是谁"**：
        // 除此之外副本的身份只出现在启动日志和 etcd 键里，跨机取证时两者都够不着。
        let nid = self.node_id.lock().unwrap().clone();
        if !nid.is_empty() {
            o.push_str("# HELP sandlocker_build_info 本副本身份（值恒为 1，信息在标签上）\n");
            o.push_str("# TYPE sandlocker_build_info gauge\n");
            o.push_str(&format!("sandlocker_build_info{{node=\"{}\",version=\"{}\"}} 1\n", nid, env!("CARGO_PKG_VERSION")));
        }
        self.create_hist.lock().unwrap().render("sandlocker_create_latency_ms", "沙箱创建延迟(ms)", &mut o);
        self.exec_hist.lock().unwrap().render("sandlocker_exec_latency_ms", "exec 延迟(ms)", &mut o);
        o
    }
}

/// 进程内全局 registry（首次访问初始化；std OnceLock，无依赖）。
pub fn metrics() -> &'static Metrics {
    static M: OnceLock<Metrics> = OnceLock::new();
    M.get_or_init(Metrics::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_has_expected_series() {
        let m = Metrics::new();
        m.record_create(70, true);
        m.record_create(120, false);
        m.record_exec(5);
        m.record_api(200);
        m.record_api(404);
        m.record_destroy();
        let txt = m.render();
        assert!(txt.contains("sandlocker_sandboxes_created_total 2"));
        assert!(txt.contains("sandlocker_pool_hits_total 1"));
        assert!(txt.contains("sandlocker_pool_misses_total 1"));
        assert!(txt.contains("sandlocker_api_errors_total 1"));
        assert!(txt.contains("sandlocker_sandboxes_current 1")); // 2 created - 1 destroyed = 1
        assert!(txt.contains("sandlocker_create_latency_ms_bucket{le=\"100\"}"));
        assert!(txt.contains("sandlocker_create_latency_ms_count 2"));
        assert!(txt.contains("sandlocker_exec_latency_ms_count 1"));
    }

    /// `build_info` 是集群基准问出「哪个副本拥有这个沙箱」的唯一途径（副本身份此外只存在于
    /// 启动日志与 etcd 键里，跨机取证时两者都够不着）。标签名/形状变了，基准会静默地把
    /// owning 副本当成远端——那时整组"跨节点"分位量的其实是本地路径。
    #[test]
    fn build_info_carries_node_label() {
        let m = Metrics::new();
        assert!(!m.render().contains("sandlocker_build_info"), "未设身份时不该出这条");
        m.set_node_id("10.0.0.7:7878#4242");
        let txt = m.render();
        assert!(txt.contains("# TYPE sandlocker_build_info gauge"));
        assert!(txt.contains("sandlocker_build_info{node=\"10.0.0.7:7878#4242\",version="));
        assert!(txt.trim_end().ends_with(" 1") || txt.contains("\"} 1\n"), "值应恒为 1");
    }

    #[test]
    fn histogram_buckets_cumulative() {
        let m = Metrics::new();
        m.record_create(5, false); // le=10
        m.record_create(60, false); // le=75
        m.record_create(3000, false); // +Inf
        let txt = m.render();
        // le=10 累计 1；le=75 累计 2；+Inf 累计 3
        assert!(txt.contains("sandlocker_create_latency_ms_bucket{le=\"10\"} 1"));
        assert!(txt.contains("sandlocker_create_latency_ms_bucket{le=\"75\"} 2"));
        assert!(txt.contains("sandlocker_create_latency_ms_bucket{le=\"+Inf\"} 3"));
        assert!(txt.contains("sandlocker_create_latency_ms_count 3"));
    }
}
