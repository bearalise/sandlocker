//! trace.rs — **OTLP/HTTP-JSON 分布式追踪导出**（M3 W8 余项，§7.8，M3-Q5）。
//!
//! M3-Q5 的判据里有一条是「**一次创建产出全链路 trace**（API→调度→节点→boot→ready）」。
//! W8 交的是指标 + 日志 sink：创建的分段时序进了直方图、也进了 sink 事件，但那是**一台机器上
//! 的一条日志**，不是链路——尤其在调度器落地之后，一次创建会跨两台机器（收请求的副本负责
//! API 与放置，被选中的节点负责真正建 VM），分段时序落在两边，没有 trace 就拼不起来。
//!
//! ————————————————————— 为什么手写 —————————————————————
//!
//! OpenTelemetry 的官方 Rust SDK 拖 tokio 异步栈。本项目从 M1 起就是**全同步**（ADR-3/D2 的
//! 「异步隔离区」：单机模式不拉起 tokio），为一条遥测线引入异步运行时，代价与收益完全不成比例。
//!
//! OTLP 有 HTTP/JSON 编码（`POST {endpoint}/v1/traces`，`Content-Type: application/json`），
//! 是规范的一等公民，Collector 默认端口 4318 就收这个。手写它只需要 serde_json + ureq，
//! **两者都已在依赖树里**（ureq ← OCI 拉取；serde_json ← 全局）。**零新增 crate**。
//!
//! ————————————————————— 形状 —————————————————————
//!
//! - `SpanCtx`：trace_id(16B) + span_id(8B)，以 W3C `traceparent` 头/查询串跨进程传递。
//! - `Span`：`start()` 拿到，`end()` 时入队。**不用 Drop 自动结束**——本项目的关键路径要么
//!   显式 `end`，要么带上错误状态，隐式行为在这里只会让人读不懂时序。
//! - 导出：**有界队列 + 单后台线程批量 POST**。队列满就丢，并计数（`otlp_dropped`）——
//!   遥测拖垮主流程是本末倒置，但**丢了要能看见**，否则 trace 缺一段会被当成"没发生"。
//! - 未配 `--otlp-endpoint` → `enabled()` 恒 false，`start()` 返回一个不入队的空 span，
//!   开销只有一次原子读（零回归）。

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{hex, host_random};

/// 一条 trace 上的位置。跨进程时编码成 W3C `traceparent`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanCtx {
    /// 32 位十六进制。
    pub trace_id: String,
    /// 16 位十六进制。
    pub span_id: String,
}

impl SpanCtx {
    /// 新 trace 的根上下文。
    pub fn root() -> SpanCtx {
        SpanCtx { trace_id: rand_hex(16), span_id: rand_hex(8) }
    }
    /// W3C traceparent：`00-<trace_id>-<span_id>-01`（01 = sampled）。
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-01", self.trace_id, self.span_id)
    }
    /// 解析 W3C traceparent。格式不合规一律返回 None——**宁可另起一条 trace，也不要把
    /// 半个 id 拼进去**，那会产出一条永远对不上的链路，比没有更难查。
    pub fn from_traceparent(s: &str) -> Option<SpanCtx> {
        let mut it = s.trim().split('-');
        let ver = it.next()?;
        let trace_id = it.next()?;
        let span_id = it.next()?;
        let _flags = it.next()?;
        if ver != "00" || trace_id.len() != 32 || span_id.len() != 16 {
            return None;
        }
        if !trace_id.bytes().chain(span_id.bytes()).all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        // 全零 id 在 W3C 规范里是非法的（表示"无效"）。
        if trace_id.bytes().all(|b| b == b'0') || span_id.bytes().all(|b| b == b'0') {
            return None;
        }
        Some(SpanCtx { trace_id: trace_id.to_lowercase(), span_id: span_id.to_lowercase() })
    }
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    host_random(&mut b);
    // 极小概率的全零：换成 1，免得产出规范里非法的 id。
    if b.iter().all(|x| *x == 0) {
        b[n - 1] = 1;
    }
    hex(&b)
}

fn now_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

/// 一个进行中的 span。`end()` 才入队。
pub struct Span {
    ctx: SpanCtx,
    parent: Option<String>,
    name: String,
    kind: SpanKind,
    start_ns: u128,
    attrs: Vec<(String, String)>,
    /// 未启用追踪时为 true：一切方法都是 no-op。
    noop: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanKind {
    /// 收到一个请求（API 入口）。
    Server = 2,
    /// 发出一个请求（跨节点中继）。
    Client = 3,
    /// 进程内的一段工作。
    Internal = 1,
}

impl Span {
    /// 起一个 span。`parent=None` 则自成一条新 trace 的根。
    pub fn start(name: &str, kind: SpanKind, parent: Option<&SpanCtx>) -> Span {
        let noop = !enabled();
        let ctx = match parent {
            Some(p) => SpanCtx { trace_id: p.trace_id.clone(), span_id: if noop { String::new() } else { rand_hex(8) } },
            None if noop => SpanCtx { trace_id: String::new(), span_id: String::new() },
            None => SpanCtx::root(),
        };
        Span {
            ctx,
            parent: parent.map(|p| p.span_id.clone()),
            name: name.to_string(),
            kind,
            start_ns: if noop { 0 } else { now_ns() },
            attrs: Vec::new(),
            noop,
        }
    }

    /// 本 span 的上下文——用来做子 span 的 parent，或编码成 traceparent 跨进程传。
    pub fn ctx(&self) -> &SpanCtx {
        &self.ctx
    }

    pub fn attr(&mut self, k: &str, v: impl ToString) -> &mut Span {
        if !self.noop {
            self.attrs.push((k.to_string(), v.to_string()));
        }
        self
    }

    /// 结束并入队。`err=Some(msg)` 记为 ERROR 状态。
    pub fn end(self, err: Option<&str>) {
        if self.noop {
            return;
        }
        let end_ns = now_ns();
        exporter().push(Finished {
            ctx: self.ctx,
            parent: self.parent,
            name: self.name,
            kind: self.kind,
            start_ns: self.start_ns,
            end_ns,
            attrs: self.attrs,
            error: err.map(|e| e.to_string()),
        });
    }

    /// 补一个**已经发生过**的子段：只有耗时、没有独立的起止时刻（`CreateOutcome` 的
    /// copy/api_ready/load/resume 就是这样量出来的）。
    ///
    /// 按给定起点顺序铺开——这些段在恢复路径上**本就是顺序执行**的，所以铺开如实反映了时序；
    /// 但它们是**由时长推算出的时刻**，不是各自打点得来的。返回下一段的起点。
    pub fn child_segment(parent: &SpanCtx, name: &str, at_ns: u128, dur_ms: u128) -> u128 {
        if !enabled() {
            return at_ns;
        }
        let end = at_ns + dur_ms * 1_000_000;
        exporter().push(Finished {
            ctx: SpanCtx { trace_id: parent.trace_id.clone(), span_id: rand_hex(8) },
            parent: Some(parent.span_id.clone()),
            name: name.to_string(),
            kind: SpanKind::Internal,
            start_ns: at_ns,
            end_ns: end,
            attrs: vec![("sandlocker.segment_from_duration".into(), "true".into())],
            error: None,
        });
        end
    }
}

struct Finished {
    ctx: SpanCtx,
    parent: Option<String>,
    name: String,
    kind: SpanKind,
    start_ns: u128,
    end_ns: u128,
    attrs: Vec<(String, String)>,
    error: Option<String>,
}

// ————————————————————— 导出器 —————————————————————

/// 队列上限。满了就丢新的并计数：遥测不该把内存吃光，也不该悄悄地吃。
const QUEUE_MAX: usize = 4096;
/// 一批最多带多少 span。
const BATCH_MAX: usize = 256;
/// 攒批窗口——攒够 BATCH_MAX 或等满这么久就发。
const FLUSH_EVERY: Duration = Duration::from_secs(2);

struct Exporter {
    q: Mutex<VecDeque<Finished>>,
    cv: Condvar,
    dropped: AtomicU64,
}

impl Exporter {
    fn push(&self, s: Finished) {
        let mut q = self.q.lock().unwrap();
        if q.len() >= QUEUE_MAX {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        q.push_back(s);
        if q.len() >= BATCH_MAX {
            self.cv.notify_one();
        }
    }
}

static EXPORTER: OnceLock<Exporter> = OnceLock::new();
static ENDPOINT: OnceLock<Option<String>> = OnceLock::new();
/// 资源属性 `service.instance.id`：本副本的 node id，用来在 Collector 侧分辨是哪台机器。
static NODE_ID: OnceLock<String> = OnceLock::new();

fn exporter() -> &'static Exporter {
    EXPORTER.get_or_init(|| Exporter { q: Mutex::new(VecDeque::new()), cv: Condvar::new(), dropped: AtomicU64::new(0) })
}

/// 追踪是否启用（`--otlp-endpoint` 给了才启用）。
pub fn enabled() -> bool {
    ENDPOINT.get().map(|o| o.is_some()).unwrap_or(false)
}

/// 已丢弃的 span 数（队列满）。供 `/metrics` 曝出——丢了要能看见。
pub fn dropped() -> u64 {
    EXPORTER.get().map(|e| e.dropped.load(Ordering::Relaxed)).unwrap_or(0)
}

/// 在 `serve()` 启动时初始化。`endpoint=None` → 全程 no-op（零回归）。
///
/// `endpoint` 是 OTLP/HTTP 的基址（如 `http://collector:4318`）；导出打到 `{endpoint}/v1/traces`。
/// 已经带 `/v1/traces` 的也接受——写全路径是很自然的手误，不值得让人配错一次才发现。
pub fn init(endpoint: Option<String>, node_id: &str) {
    let ep = endpoint.map(|e| {
        let e = e.trim_end_matches('/').to_string();
        if e.ends_with("/v1/traces") { e } else { format!("{e}/v1/traces") }
    });
    let on = ep.is_some();
    let _ = ENDPOINT.set(ep);
    let _ = NODE_ID.set(node_id.to_string());
    if !on {
        return;
    }
    std::thread::spawn(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build();
        let url = ENDPOINT.get().and_then(|o| o.clone()).unwrap_or_default();
        loop {
            let batch: Vec<Finished> = {
                let e = exporter();
                let mut q = e.q.lock().unwrap();
                if q.is_empty() {
                    let (g, _) = e.cv.wait_timeout(q, FLUSH_EVERY).unwrap();
                    q = g;
                }
                let n = q.len().min(BATCH_MAX);
                q.drain(..n).collect()
            };
            if batch.is_empty() {
                continue;
            }
            // best-effort：Collector 挂了不该影响沙箱。失败就丢这一批并计数。
            if agent
                .post(&url)
                .set("Content-Type", "application/json")
                .send_string(&encode(&batch))
                .is_err()
            {
                exporter().dropped.fetch_add(batch.len() as u64, Ordering::Relaxed);
            }
        }
    });
}

/// 编码成 OTLP/HTTP-JSON。
///
/// 注意 **nanos 是字符串**：OTLP JSON 规定 64 位整数用 string 表达（JSON number 只有 double，
/// 装不下纳秒时间戳而不失精度）。这里写错的话 Collector 会静默丢掉 span。
fn encode(batch: &[Finished]) -> String {
    let mut spans = String::new();
    for (i, s) in batch.iter().enumerate() {
        if i > 0 {
            spans.push(',');
        }
        let mut attrs = String::new();
        for (j, (k, v)) in s.attrs.iter().enumerate() {
            if j > 0 {
                attrs.push(',');
            }
            attrs.push_str(&format!(r#"{{"key":{},"value":{{"stringValue":{}}}}}"#, jstr(k), jstr(v)));
        }
        let parent = s.parent.as_deref().unwrap_or("");
        // status: 未设 = UNSET(0)，出错 = ERROR(2)。
        let status = match &s.error {
            Some(m) => format!(r#","status":{{"code":2,"message":{}}}"#, jstr(m)),
            None => String::new(),
        };
        spans.push_str(&format!(
            r#"{{"traceId":"{}","spanId":"{}","parentSpanId":"{parent}","name":{},"kind":{},"startTimeUnixNano":"{}","endTimeUnixNano":"{}","attributes":[{attrs}]{status}}}"#,
            s.ctx.trace_id,
            s.ctx.span_id,
            jstr(&s.name),
            s.kind as u8,
            s.start_ns,
            s.end_ns,
        ));
    }
    let node = NODE_ID.get().map(|s| s.as_str()).unwrap_or("");
    format!(
        r#"{{"resourceSpans":[{{"resource":{{"attributes":[{{"key":"service.name","value":{{"stringValue":"sandlocker"}}}},{{"key":"service.version","value":{{"stringValue":"{}"}}}},{{"key":"service.instance.id","value":{{"stringValue":{}}}}}]}},"scopeSpans":[{{"scope":{{"name":"sl-node"}},"spans":[{spans}]}}]}}]}}"#,
        env!("CARGO_PKG_VERSION"),
        jstr(node),
    )
}

/// JSON 字符串字面量（手写转义，守零依赖；serde_json 也在，但为一个字段拉进来不值当）。
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_roundtrip() {
        let c = SpanCtx::root();
        let tp = c.to_traceparent();
        assert!(tp.starts_with("00-") && tp.ends_with("-01"));
        assert_eq!(SpanCtx::from_traceparent(&tp).unwrap(), c);
    }

    /// 半个 id 拼进来会产出一条永远对不上的链路——比没有 trace 更难查。宁可另起一条。
    #[test]
    fn traceparent_rejects_malformed() {
        for bad in [
            "",
            "00-abc-def-01",                                                  // 长度不对
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",        // 版本不认识
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",           // 缺 flags
            "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01",        // 非 hex
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",        // 全零 trace_id（规范里非法）
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",        // 全零 span_id
        ] {
            assert!(SpanCtx::from_traceparent(bad).is_none(), "{bad:?} 不该被接受");
        }
        // 大小写混写的合法值应被规范化成小写。
        let c = SpanCtx::from_traceparent("00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01").unwrap();
        assert_eq!(c.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(c.span_id, "00f067aa0ba902b7");
    }

    /// OTLP/JSON 的时间戳**必须是字符串**——写成 JSON number 会失精度，Collector 静默丢 span。
    #[test]
    fn otlp_json_shape() {
        let f = Finished {
            ctx: SpanCtx { trace_id: "a".repeat(32), span_id: "b".repeat(16) },
            parent: Some("c".repeat(16)),
            name: "sandbox.create".into(),
            kind: SpanKind::Server,
            start_ns: 1_700_000_000_000_000_000,
            end_ns: 1_700_000_000_400_000_000,
            attrs: vec![("sandlocker.node".into(), "10.0.0.1:7878#42".into())],
            error: None,
        };
        let j = encode(&[f]);
        assert!(j.contains(r#""startTimeUnixNano":"1700000000000000000""#), "纳秒须是字符串: {j}");
        assert!(j.contains(r#""traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#));
        assert!(j.contains(r#""parentSpanId":"cccccccccccccccc""#));
        assert!(j.contains(r#""kind":2"#));
        assert!(j.contains(r#""service.name""#) && j.contains(r#""sandlocker""#));
        assert!(j.contains(r#""sandlocker.node""#));
        assert!(!j.contains(r#""status""#), "无错误时不该带 status");
        // 合法 JSON（用 serde_json 复核，免得手写编码悄悄写歪）。
        let v: serde_json::Value = serde_json::from_str(&j).expect("OTLP 载荷须是合法 JSON");
        assert_eq!(v["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"], "sandbox.create");
    }

    #[test]
    fn error_status_is_recorded() {
        let f = Finished {
            ctx: SpanCtx::root(),
            parent: None,
            name: "n".into(),
            kind: SpanKind::Internal,
            start_ns: 1,
            end_ns: 2,
            attrs: vec![],
            error: Some("模板不存在\"x\"".into()),
        };
        let j = encode(&[f]);
        assert!(j.contains(r#""status":{"code":2"#), "{j}");
        let _: serde_json::Value = serde_json::from_str(&j).expect("含转义字符时仍须是合法 JSON");
    }

    /// 未启用时 span 全程 no-op：不生成 id、不入队。
    #[test]
    fn disabled_spans_are_inert() {
        assert!(!enabled(), "本测试进程不该配 OTLP endpoint");
        let mut s = Span::start("x", SpanKind::Server, None);
        s.attr("k", "v");
        assert!(s.ctx().trace_id.is_empty());
        s.end(None);
        assert_eq!(dropped(), 0);
    }

    #[test]
    fn endpoint_normalisation() {
        // init 只能调一次（OnceLock），所以这里只验规范化逻辑本身的写法与 init 一致。
        let norm = |e: &str| {
            let e = e.trim_end_matches('/').to_string();
            if e.ends_with("/v1/traces") { e } else { format!("{e}/v1/traces") }
        };
        assert_eq!(norm("http://c:4318"), "http://c:4318/v1/traces");
        assert_eq!(norm("http://c:4318/"), "http://c:4318/v1/traces");
        assert_eq!(norm("http://c:4318/v1/traces"), "http://c:4318/v1/traces");
    }
}
