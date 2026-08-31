//! logsink.rs — 结构化日志事件转发（M3 W8，§7.8）。生命周期事件（create/destroy）以结构化 JSON
//! 转发到外部 sink（Loki/ES/自建收集器），经 `--log-sink <url>` 配置；未配置则 no-op（零回归）。
//!
//! 转发用**已有依赖 ureq**（sync + rustls，OCI 已引入）；POST 在**后台线程**发，不阻塞 create/destroy
//! 关键路径（best-effort，失败静默——可观测日志不应拖垮主流程）。
//!
//! create 事件带**分段时序**（total/copy/load/resume ms）——即创建链路 span 分解（tracing-lite）；
//! 完整 OTLP 分布式追踪 exporter（避免重异步 SDK）为后续。

use std::sync::OnceLock;
use std::time::Duration;

/// 进程内 sink URL（None=未配置=不转发）。
static SINK: OnceLock<Option<String>> = OnceLock::new();

/// 在 serve() 启动时设 sink（--log-sink）。
pub fn init(url: Option<String>) {
    let _ = SINK.set(url);
}

fn sink_url() -> Option<&'static String> {
    SINK.get().and_then(|o| o.as_ref())
}

/// 转发一条结构化 JSON 事件（best-effort，后台线程 POST，不阻塞调用者）。
pub fn emit(event_json: String) {
    let url = match sink_url() {
        Some(u) => u.clone(),
        None => return, // 未配置 sink → no-op
    };
    std::thread::spawn(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .build();
        let _ = agent.post(&url).set("Content-Type", "application/json").send_string(&event_json);
    });
}
