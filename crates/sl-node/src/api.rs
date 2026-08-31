//! api.rs — 长驻守护 + 手写极简 REST server（M1 W8，PRD §9 v1alpha / 7.10）。
//!
//! D3：控制面单进程、全组件进程内。`sl-node --serve` 起长驻守护——HTTP API + orchestrator
//! （[`crate::orch::Orch`]）+ 后台 reaper tick 全在一进程，SQLite 元数据（PRD 7.10 单机一体化）。
//! 用户面 `sandlocker` CLI（`crates/sandlocker`）作为 REST 客户端连本守护。
//!
//! **REST-only + 手写 HTTP/1.1**（延续 D1 `fcapi.rs`「无重依赖 + 全同步 std」风格；不引 tokio/tonic）。
//! gRPC 服务端延后 M2（本周仅出 `contracts/sandlocker.proto` 双描述）。契约先行：路由/字段与
//! `contracts/openapi.yaml` 逐一对齐，W9 Python SDK 据此生成。
//!
//! 边界（如实标注）：仅支持 `Content-Length` + `Connection: close`（不支持 chunked/keep-alive）；
//! 守护级操作（create/destroy/tick）在 `orch.lock()` 内**串行**（单机 MVP，密度/并发吞吐属 M2 池化）；
//! exec/文件/日志的慢 IO 在**取路径后释放锁**再做，不阻塞 reaper/create。

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sl_store::SqliteStore;

use sl_proto::{parse_exec_output, read_frame, read_msg, write_msg, ExecOutput, Request, Response};

use crate::backend::{Capabilities, ExecTarget, UNSUPPORTED_BY_BACKEND};
use crate::expose::{self, ExposeHandle};
use crate::gateway::{parse_query, proxy_port_http, Action, Gateway};
use crate::orch::{NetworkMode, Orch, SandboxSpec};
use crate::{connect_guest, Config};

/// 守护共享态：orchestrator（互斥）+ 模板仓库根（模板名→目录解析）。
type Shared = Arc<Mutex<Orch<'static>>>;
/// 数据面网关（ADR-22）：控制面签发 + 网关验签共用（单机进程内）。
type SharedGw = Arc<Gateway>;

/// 端口暴露（L4 透传）共享态：sid→guest_port→监听器句柄 + 对外 bind 放行开关。
/// 打包进一个 Arc 避免在 handle_conn/dispatch/reaper 到处加参数。
struct ExposeState {
    registry: Mutex<HashMap<String, HashMap<u32, ExposeHandle>>>,
    /// `--expose-allow-public`：未开启时拒绝非回环 bind（对外暴露须显式选择）。
    allow_public: bool,
}
type Exposes = Arc<ExposeState>;

/// 停止并移除某沙箱的全部暴露监听器（destroy/回收路径调用，防悬挂/线程泄漏）。
fn drop_exposes(exposes: &Exposes, id: &str) {
    if let Some(m) = exposes.registry.lock().unwrap().remove(id) {
        for (_gp, h) in m {
            h.stop();
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 解析守护三路径（默认与 `--build` 产出一致：store=build/templates/sl.db，模板根=build/templates）。
fn resolve_paths(cfg: &Config) -> (PathBuf, PathBuf, PathBuf) {
    let store_path = cfg.store.clone().unwrap_or_else(|| PathBuf::from("build/templates/sl.db"));
    let template_root = cfg.template_root.clone().unwrap_or_else(|| PathBuf::from("build/templates"));
    let run_root = cfg.run_root.clone().unwrap_or_else(|| cfg.workdir.join("instances"));
    (store_path, template_root, run_root)
}

/// 起守护：打开 store → 建 Orch（`Box::leak` cfg 得 `'static`）→ reaper 线程 → TCP accept 循环。
pub fn serve(cfg: &Config) -> Result<(), String> {
    let addr = cfg.serve_addr.clone().unwrap_or_else(|| "127.0.0.1:7878".to_string());
    let (store_path, template_root, run_root) = resolve_paths(cfg);

    if let Some(parent) = store_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("建 store 目录失败: {e}"))?;
    }
    std::fs::create_dir_all(&template_root).map_err(|e| format!("建模板根失败: {e}"))?;
    std::fs::create_dir_all(&run_root).map_err(|e| format!("建 run_root 失败: {e}"))?;
    let db_str = store_path.to_str().ok_or("store 路径非 UTF-8")?;
    let store = SqliteStore::open(db_str).map_err(|e| format!("打开 store 失败: {e}"))?;

    // Orch<'a> 借 &Config；守护存活全程 → leak 得 'static（无需改 Orch 生命周期）。
    let cfg_s: &'static Config = Box::leak(Box::new(cfg.clone()));
    // 默认模板占位：守护恒走 create_in（显式模板），此占位不被 create() 使用；取模板根（存在即合法）。
    let mut orch = Orch::new(cfg_s, &template_root, &run_root, Box::new(store))?;

    // M2 W4 温池：--pool-size>0 且指定 --pool-template 时，解析该模板→建单模板温池。请求命中同
    // 模板走池命中路径（copy_ms=0），其它模板/未启用均走冷路径（零回归）。模板解析失败仅告警不阻塞。
    // M2 W5 热池：--pool-template 解析成功且 --hot-size>0 时，为该模板预置暂停态 VM（命中优先于温池）。
    if (cfg.pool_size > 0 || cfg.hot_size > 0) && cfg.pool_template.is_some() {
        let name = cfg.pool_template.clone().unwrap();
        match resolve_template(&orch, &template_root, &name) {
            Ok(dir) => {
                if cfg.pool_size > 0 {
                    orch.enable_warm_pool(&dir, cfg.pool_size)?;
                    println!("[sandlocker] 温池已启用：template={name} size={} dir={}", cfg.pool_size, dir.display());
                }
                if cfg.hot_size > 0 {
                    orch.enable_hot_pool(&dir, cfg.hot_size)?;
                    println!("[sandlocker] 热池已启用：template={name} size={}（暂停态 VM 常驻内存）", cfg.hot_size);
                }
            }
            Err(e) => eprintln!("[sandlocker] 池未启用（模板解析失败，走冷路径）: {e}"),
        }
    }
    // M3 W3（M3-Q2）：本节点 id（addr#pid）。设入 Orch → 创建的沙箱写归属键 `sandbox/<id>/node`，
    // 供失联节点的沙箱被 leader 回收。
    let node_id = format!("{addr}#{}", std::process::id());
    orch.set_node_id(&node_id);
    let shared: Shared = Arc::new(Mutex::new(orch));

    // 端口暴露注册表（L4 透传监听器）。allow_public 由 --expose-allow-public 控制。
    let exposes: Exposes = Arc::new(ExposeState {
        registry: Mutex::new(HashMap::new()),
        allow_public: cfg.expose_allow_public,
    });

    // M3 W2（M3-Q2）：leader 选举门控。**单机模式 SQLite 无选主，本节点恒 leader**（ADR-17：
    // 「单机模式 SQLite + 进程内 orchestrator 无选主」）——故此处恒 true，reaper 照常跑（零回归）。
    // active-standby 真选主是 etcd 多副本的事：当 Orch 迁至 etcd（W3/W4 多节点调度）后，改由
    // `sl_store::election::Election`（本 W2 已交付并对真 etcd 验证：`--election-reconcile --etcd`）
    // 驱动此标志——leader 跑 reaper、standby 置 false 不 tick（下方门控已就位，防双写）。
    let is_leader = Arc::new(AtomicBool::new(true));

    // M3 W3（M3-Q2）：节点心跳（易失态走 lease TTL，ADR-17）。本节点在 `node/<id>` 写存活键并周期
    // 续租；崩溃/失联 → 租约到期 → 键消失 → leader 回收其名下沙箱。用独立 store 句柄（同文件另一连接）。
    // 单机：仅本节点、恒存活、无孤儿（回收含护栏，绝不回收自己名下沙箱）。
    {
        let hb_store = SqliteStore::open(db_str).map_err(|e| format!("打开心跳 store 失败: {e}"))?;
        let node_id_hb = node_id.clone();
        let meta = format!(r#"{{"addr":"{addr}"}}"#);
        // 心跳租约窗 max(tick*3, 15s)；续租周期 ~ttl/3。
        let ttl = std::cmp::max(cfg.tick_secs as i64 * 3, 15);
        let period = std::cmp::max((ttl / 3) as u64, 1);
        thread::spawn(move || {
            let mut lease = sl_store::cluster::register_node(&hb_store, &node_id_hb, meta.as_bytes(), ttl).ok();
            loop {
                thread::sleep(Duration::from_secs(period));
                let alive = match lease {
                    Some(l) => sl_store::cluster::heartbeat(&hb_store, l).is_ok(),
                    None => false,
                };
                if !alive {
                    // 租约丢失（被 sweep/首次注册失败）→ 重新注册，恢复存活。
                    lease = sl_store::cluster::register_node(&hb_store, &node_id_hb, meta.as_bytes(), ttl).ok();
                }
            }
        });
    }

    // 后台 reaper：周期 tick(now)（TTL 硬顶 + idle sweep）+ 回收失联节点的孤儿沙箱。回收的沙箱须
    // 同步拆掉其暴露监听器。仅 leader 执行——standby 不 tick/回收（active-standby 无双写；单机恒 leader）。
    let tick_secs = if cfg.tick_secs > 0 { cfg.tick_secs } else { 5 };
    let reaper = Arc::clone(&shared);
    let reaper_ex = Arc::clone(&exposes);
    let reaper_leader = Arc::clone(&is_leader);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(tick_secs));
        if !reaper_leader.load(Ordering::SeqCst) {
            continue; // standby：不回收，避免与 leader 双写
        }
        let now = now_unix();
        if let Ok(mut o) = reaper.lock() {
            if let Ok(reaped) = o.tick(now) {
                for id in reaped {
                    drop_exposes(&reaper_ex, &id);
                }
            }
            // M3 W3：回收失联节点（心跳 lease 过期→node 键消失）名下的孤儿沙箱（护栏不碰自己的）。
            if let Ok(orphans) = o.reclaim_orphans() {
                if !orphans.is_empty() {
                    for id in &orphans {
                        drop_exposes(&reaper_ex, id);
                    }
                    println!("[sandlocker] 回收失联节点的孤儿沙箱: {orphans:?}");
                }
            }
        }
    });

    // M2 W10 数据面网关（ADR-22）：独立监听（默认 127.0.0.1:7879），与控制面同进程共享 orch + secret。
    let gw_addr = cfg.gw_addr.clone().unwrap_or_else(|| "127.0.0.1:7879".to_string());
    let gw: SharedGw = Arc::new(Gateway::new_random(format!("http://{gw_addr}")));
    {
        let gw_l = Arc::clone(&gw);
        let sh_l = Arc::clone(&shared);
        let bind = gw_addr.clone();
        match TcpListener::bind(&bind) {
            Ok(gwl) => {
                println!("[sandlocker] 数据面网关就绪 http://{bind}（一次性 HMAC 签名 URL；/gw/*）");
                thread::spawn(move || {
                    for conn in gwl.incoming().flatten() {
                        let (g, s) = (Arc::clone(&gw_l), Arc::clone(&sh_l));
                        thread::spawn(move || {
                            if let Err(e) = handle_gw_conn(conn, &s, &g) {
                                eprintln!("[sandlocker] 网关连接错误: {e}");
                            }
                        });
                    }
                });
            }
            Err(e) => eprintln!("[sandlocker] 网关 bind {bind} 失败（数据面不可用）: {e}"),
        }
    }

    let listener = TcpListener::bind(&addr).map_err(|e| format!("bind {addr} 失败: {e}"))?;
    println!(
        "[sandlocker] API 守护就绪 http://{addr}（store={} templates={} run={} tick={tick_secs}s）",
        store_path.display(),
        template_root.display(),
        run_root.display()
    );

    let troot: &'static Path = Box::leak(template_root.into_boxed_path());
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let sh = Arc::clone(&shared);
                let g = Arc::clone(&gw);
                let e = Arc::clone(&exposes);
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, &sh, troot, &g, &e) {
                        eprintln!("[sandlocker] 连接处理错误: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[sandlocker] accept 失败: {e}"),
        }
    }
    Ok(())
}

// ————————————————————— HTTP 请求解析 / 响应封装（手写，照 fcapi.rs）—————————————————————

/// 读一个请求：解析请求行 `(method, path)` + 按 `Content-Length` 精确读 body。
fn read_request(stream: &mut TcpStream) -> Result<(String, String, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(p) = find_crlfcrlf(&buf) {
            break p;
        }
        let n = stream.read(&mut chunk).map_err(|e| format!("读请求头失败: {e}"))?;
        if n == 0 {
            return Err("请求未含完整 header（连接过早关闭）".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err("请求头过大".into());
        }
    };
    let head = &buf[..head_end];
    let (method, path) = parse_request_line(head)?;
    let want = head_end + 4 + content_length(head);
    while buf.len() < want {
        let n = stream.read(&mut chunk).map_err(|e| format!("读请求体失败: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = buf[head_end + 4..].to_vec();
    Ok((method, path, body))
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 解析请求行首行："METHOD /path HTTP/1.1" → (METHOD, /path)。
fn parse_request_line(head: &[u8]) -> Result<(String, String), String> {
    let first = head.split(|&b| b == b'\n').next().unwrap_or(head);
    let line = String::from_utf8_lossy(first);
    let mut it = line.split_whitespace();
    let method = it.next().ok_or("请求行无方法")?.to_string();
    let path = it.next().ok_or("请求行无路径")?.to_string();
    Ok((method, path))
}

fn content_length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "OK",
    }
}

fn write_response(stream: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> Result<(), String> {
    let head = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(code),
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|e| format!("写响应头失败: {e}"))?;
    stream.write_all(body).map_err(|e| format!("写响应体失败: {e}"))?;
    stream.flush().map_err(|e| format!("flush 失败: {e}"))
}

/// JSON 错误体（application/json）。
fn err_json(msg: &str) -> Vec<u8> {
    format!(r#"{{"error":"{}"}}"#, msg.replace('\\', "\\\\").replace('"', "\\\"")).into_bytes()
}

// ————————————————————— 路由（纯逻辑，单测）—————————————————————

#[derive(Debug, PartialEq, Eq)]
enum Route {
    CreateSandbox,
    ListSandboxes,
    GetSandbox(String),
    DeleteSandbox(String),
    Keepalive(String),
    Pause(String),
    Resume(String),
    Fork(String),
    Ticket(String),
    Expose(String),
    Unexpose(String, u32),
    ListExposes(String),
    Exec(String),
    PutFile(String, String),
    GetFile(String, String),
    Logs(String),
    ListTemplates,
    BuildTemplate,
    ListBackends,
    NotFound,
}

/// 纯路由：`(method, path)` → `Route`。path 去 query；`/files/` 后整段（含 `/`）作文件路径。
fn parse_route(method: &str, path: &str) -> Route {
    let path = path.split('?').next().unwrap_or(path);
    let trimmed = path.trim_matches('/');
    let segs: Vec<&str> = if trimmed.is_empty() { vec![] } else { trimmed.split('/').collect() };
    match (method, segs.as_slice()) {
        ("POST", ["v1", "sandboxes"]) => Route::CreateSandbox,
        ("GET", ["v1", "sandboxes"]) => Route::ListSandboxes,
        ("GET", ["v1", "templates"]) => Route::ListTemplates,
        ("GET", ["v1", "backends"]) => Route::ListBackends,
        ("POST", ["v1", "templates:build"]) => Route::BuildTemplate,
        ("GET", ["v1", "sandboxes", id]) => Route::GetSandbox((*id).to_string()),
        ("DELETE", ["v1", "sandboxes", id]) => Route::DeleteSandbox((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "keepalive"]) => Route::Keepalive((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "pause"]) => Route::Pause((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "resume"]) => Route::Resume((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "fork"]) => Route::Fork((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "ticket"]) => Route::Ticket((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "expose"]) => Route::Expose((*id).to_string()),
        ("GET", ["v1", "sandboxes", id, "exposes"]) => Route::ListExposes((*id).to_string()),
        ("DELETE", ["v1", "sandboxes", id, "expose", gp]) => match gp.parse() {
            Ok(p) => Route::Unexpose((*id).to_string(), p),
            Err(_) => Route::NotFound,
        },
        ("POST", ["v1", "sandboxes", id, "exec"]) => Route::Exec((*id).to_string()),
        ("GET", ["v1", "sandboxes", id, "logs"]) => Route::Logs((*id).to_string()),
        (m, [.., ]) if segs.len() >= 5 && segs[0] == "v1" && segs[1] == "sandboxes" && segs[3] == "files" => {
            let id = segs[2].to_string();
            let fpath = segs[4..].join("/");
            match m {
                "PUT" => Route::PutFile(id, fpath),
                "GET" => Route::GetFile(id, fpath),
                _ => Route::NotFound,
            }
        }
        _ => Route::NotFound,
    }
}

// ————————————————————— 分派 / handler —————————————————————

fn handle_conn(
    mut stream: TcpStream,
    shared: &Shared,
    template_root: &Path,
    gw: &SharedGw,
    exposes: &Exposes,
) -> Result<(), String> {
    let (method, path, body) = read_request(&mut stream)?;
    // 流式 exec：需劫持本连接（NDJSON 边收边发、无 Content-Length），不进 dispatch/write_response 一次性路径。
    if let Some(id) = parse_exec_stream(&method, &path) {
        return exec_stream_hijack(stream, &id, &body, shared);
    }
    let (code, ctype, resp) = dispatch(&method, &path, &body, shared, template_root, gw, exposes);
    write_response(&mut stream, code, ctype, &resp)
}

fn dispatch(
    method: &str,
    path: &str,
    body: &[u8],
    shared: &Shared,
    template_root: &Path,
    gw: &SharedGw,
    exposes: &Exposes,
) -> (u16, &'static str, Vec<u8>) {
    let route = parse_route(method, path);
    let json = "application/json";
    match route {
        Route::Ticket(id) => match mint_ticket(&id, body, gw) {
            Ok(v) => (200, json, v),
            Err(e) => (400, json, err_json(&e)),
        },
        Route::CreateSandbox => match create_sandbox(body, shared, template_root) {
            Ok(v) => (201, json, v),
            Err(e) => (400, json, err_json(&e)),
        },
        Route::ListSandboxes => match shared.lock().unwrap().list_meta() {
            Ok(metas) => (200, json, format!("[{}]", metas.join(",")).into_bytes()),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::GetSandbox(id) => match shared.lock().unwrap().get_meta(&id) {
            Ok(Some(m)) => (200, json, m.into_bytes()),
            Ok(None) => (404, json, err_json("未知沙箱")),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::DeleteSandbox(id) => {
            let r = shared.lock().unwrap().destroy(&id);
            match r {
                Ok(_) => {
                    drop_exposes(exposes, &id); // 拆掉该沙箱的暴露监听器，防悬挂
                    (204, json, Vec::new())
                }
                Err(_) => (404, json, err_json("未知沙箱")),
            }
        }
        Route::Keepalive(id) => {
            // 续期只滑 idle lease 窗；**不**动 TTL 绝对硬顶（过硬顶 keepalive 救不了，M2-Q9）。
            let mut orch = shared.lock().unwrap();
            match orch.keepalive(&id) {
                Ok(lease_deadline) => {
                    let ttl = orch.ttl_deadline(&id).map(|v| v.to_string()).unwrap_or_else(|| "null".into());
                    let body = format!(
                        r#"{{"id":"{id}","lease_deadline":{lease_deadline},"ttl_deadline":{ttl}}}"#
                    );
                    (200, json, body.into_bytes())
                }
                Err(_) => (404, json, err_json("未知沙箱")),
            }
        }
        Route::Pause(id) => {
            let r = shared.lock().unwrap().pause(&id);
            match r {
                Ok(()) => (200, json, format!(r#"{{"id":"{id}","state":"paused"}}"#).into_bytes()),
                Err(e) if e.starts_with(UNSUPPORTED_BY_BACKEND) => (409, json, err_json(&e)),
                Err(e) => (404, json, err_json(&e)),
            }
        }
        Route::Resume(id) => {
            let r = shared.lock().unwrap().resume(&id);
            match r {
                Ok(mid) => {
                    (200, json, format!(r#"{{"id":"{id}","state":"running","machine_id":"{mid}"}}"#).into_bytes())
                }
                Err(e) if e.starts_with(UNSUPPORTED_BY_BACKEND) => (409, json, err_json(&e)),
                Err(e) => (404, json, err_json(&e)),
            }
        }
        Route::Fork(id) => match fork_sandbox(&id, body, shared) {
            Ok(v) => (201, json, v),
            Err(e) if e.starts_with(UNSUPPORTED_BY_BACKEND) => (409, json, err_json(&e)),
            Err(e) => (400, json, err_json(&e)),
        },
        Route::Expose(id) => match expose_port(&id, body, shared, exposes) {
            Ok(v) => (201, json, v),
            Err(e) => (400, json, err_json(&e)),
        },
        Route::Unexpose(id, gp) => {
            let removed = exposes.registry.lock().unwrap().get_mut(&id).and_then(|m| m.remove(&gp));
            match removed {
                Some(h) => {
                    h.stop();
                    (204, json, Vec::new())
                }
                None => (404, json, err_json("未暴露该端口")),
            }
        }
        Route::ListExposes(id) => (200, json, list_exposes(&id, exposes)),
        Route::Exec(id) => match exec_in(&id, body, shared) {
            Ok(v) => (200, json, v),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::PutFile(id, fpath) => match put_file(&id, &fpath, body, shared) {
            Ok(()) => (204, json, Vec::new()),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::GetFile(id, fpath) => match get_file(&id, &fpath, shared) {
            Ok(bytes) => (200, "application/octet-stream", bytes),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::Logs(id) => match read_logs(&id, shared) {
            Ok(bytes) => (200, "text/plain; charset=utf-8", bytes),
            Err(e) => (404, json, err_json(&e)),
        },
        Route::ListTemplates => match list_templates(shared) {
            Ok(v) => (200, json, v),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::ListBackends => (200, json, list_backends(shared)),
        Route::BuildTemplate => (
            501,
            json,
            err_json("M1 单机版 templates:build 未实现，请用 `sandlocker build <file.toml>`"),
        ),
        Route::NotFound => (404, json, err_json("no such route")),
    }
}

/// 模板名 → 目录：`template/<name>/latest` → 版本 → `<template_root>/<name>/<version>`。
fn resolve_template(orch: &Orch, template_root: &Path, name: &str) -> Result<PathBuf, String> {
    let latest = orch
        .store_get(&format!("template/{name}/latest"))?
        .ok_or_else(|| format!("模板未注册: {name}（先 `sandlocker build`）"))?;
    let version = String::from_utf8_lossy(&latest).trim().to_string();
    let dir = template_root.join(name).join(&version);
    if !dir.is_dir() {
        return Err(format!("模板目录缺失: {}", dir.display()));
    }
    Ok(dir)
}

fn create_sandbox(body: &[u8], shared: &Shared, template_root: &Path) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("请求体非 JSON: {e}"))?;
    let name = v.get("template").and_then(|x| x.as_str()).ok_or("缺 template 字段")?;
    let ttl = v.get("ttl").and_then(|x| x.as_i64()).unwrap_or(300);
    let idle = v.get("idle").and_then(|x| x.as_i64()).unwrap_or(ttl);
    let cpu = v.get("cpu").and_then(|x| x.as_i64()).unwrap_or(2) as u32;
    let mem = v.get("mem").and_then(|x| x.as_i64()).unwrap_or(512) as u32;
    let mut metadata = BTreeMap::new();
    if let Some(env) = v.get("env").and_then(|x| x.as_object()) {
        for (k, val) in env {
            if let Some(s) = val.as_str() {
                metadata.insert(k.clone(), s.to_string());
            }
        }
    }
    // M2 W6（ADR-14）：可选 required_capabilities:[..] snake_case 名列表 → 创建期校验（后端不满足即
    // UNSUPPORTED_BY_BACKEND）。未知能力名恒不被满足，from_names 直接返错。
    let required_capabilities = match v.get("required_capabilities").and_then(|x| x.as_array()) {
        Some(arr) => {
            let names: Vec<String> = arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
            Capabilities::from_names(&names)?
        }
        None => Capabilities::empty(),
    };
    // M2 W7：可选 backend 字段（"fc"/"gvisor"）显式选后端；缺省 fc。
    let backend = v.get("backend").and_then(|x| x.as_str()).map(|s| s.to_string());
    // 运行时网络（FR-3.3）：可选 network 字段 "none"（默认）| "egress"。egress → 冷启动带 NIC 可出站
    // （npm/pip install），仅 FC+root（能力门控，非法值/非支持后端 create 期报错）。
    let network = match v.get("network").and_then(|x| x.as_str()) {
        None | Some("none") => NetworkMode::None,
        Some("egress") => NetworkMode::Egress,
        Some(other) => return Err(format!("network 取值 none|egress，得到 {other:?}")),
    };
    let spec = SandboxSpec {
        vcpus: cpu,
        mem_mib: mem,
        ttl_secs: ttl,
        idle_secs: idle,
        metadata,
        required_capabilities,
        backend,
        network,
    };

    // 建走恢复（~130ms），全程持锁——单机 MVP 串行（如实标注）。
    let mut o = shared.lock().unwrap();
    let dir = resolve_template(&o, template_root, name)?;
    let out = o.create_in(&dir, &spec)?;
    Ok(format!(
        r#"{{"id":"{}","state":"running","machine_id":"{}","template":"{}","total_ms":{},"copy_ms":{},"api_ready_ms":{},"load_ms":{},"resume_ms":{},"pool_hit":{},"hot_hit":{}}}"#,
        out.id, out.machine_id, name, out.total_ms, out.copy_ms, out.api_ready_ms, out.load_ms, out.resume_ms, out.pool_hit, out.hot_hit
    )
    .into_bytes())
}

/// 控制面签发一次性 HMAC 签名 URL（M2-Q6）：body{action, port?, ttl?}→gateway::mint→{url}。
fn mint_ticket(id: &str, body: &[u8], gw: &SharedGw) -> Result<Vec<u8>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(if body.is_empty() { b"{}" } else { body }).map_err(|e| format!("请求体非 JSON: {e}"))?;
    let action = v
        .get("action")
        .and_then(|x| x.as_str())
        .and_then(Action::from_str)
        .ok_or("缺/非法 action（exec|file|logs|port）")?;
    let port = v.get("port").and_then(|x| x.as_i64()).unwrap_or(0) as u32;
    let ttl = v.get("ttl").and_then(|x| x.as_i64()).unwrap_or(300);
    let url = gw.mint(id, action, port, ttl, now_unix());
    Ok(format!(r#"{{"url":"{url}"}}"#).into_bytes())
}

/// 暴露结果 JSON（稳定地址 `http://<bind>:<host_port>/` + 端口映射）。
fn expose_json(bind: &str, host_port: u16, guest_port: u32) -> Vec<u8> {
    format!(r#"{{"url":"http://{bind}:{host_port}/","bind":"{bind}","host_port":{host_port},"guest_port":{guest_port}}}"#)
        .into_bytes()
}

/// 端口暴露（L4 透传）：`body{port, host_port?, bind?}` → 起持久监听器把外部连接裸字节透传到 guest
/// `127.0.0.1:port`。返回稳定地址（`http://bind:host_port/`），支持任意方法/流式/WS/keep-alive。
/// 仅 FC（vsock）后端；同 guest_port 幂等；非回环 bind 需 `--expose-allow-public`。
fn expose_port(id: &str, body: &[u8], shared: &Shared, exposes: &Exposes) -> Result<Vec<u8>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(if body.is_empty() { b"{}" } else { body }).map_err(|e| format!("请求体非 JSON: {e}"))?;
    let guest_port = v.get("port").and_then(|x| x.as_u64()).ok_or("缺/非法 port")? as u32;
    let host_port = v.get("host_port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
    let bind = v.get("bind").and_then(|x| x.as_str()).unwrap_or("127.0.0.1").to_string();

    // 幂等：同沙箱同 guest_port 已暴露则直接回既有地址（不重复起监听）。
    {
        let reg = exposes.registry.lock().unwrap();
        if let Some(h) = reg.get(id).and_then(|m| m.get(&guest_port)) {
            return Ok(expose_json(&h.bind, h.host_port, guest_port));
        }
    }

    // 对外 bind（非回环）门禁：纯 L4 透传无鉴权，须 --expose-allow-public 显式放行。
    let loopback = bind == "127.0.0.1" || bind == "localhost" || bind == "::1";
    if !loopback {
        if !exposes.allow_public {
            return Err(format!(
                "bind={bind} 为非回环地址，纯 L4 透传无鉴权；如确需对外暴露，守护须带 --expose-allow-public"
            ));
        }
        eprintln!("[sandlocker][WARN] expose bind={bind}:{host_port} → guest {id}:{guest_port}：无鉴权 L4 透传，仅限可信网络");
    }

    // 端口暴露仅 FC（vsock）；锁内取 vsock 路径，锁外起监听（不阻塞 create/reaper）。
    let tgt = shared.lock().unwrap().exec_target(id).ok_or("未知沙箱或已回收")?;
    let vsock = match tgt {
        ExecTarget::Vsock(p) => p,
        _ => return Err("端口暴露仅 FC 后端（vsock）支持".into()),
    };

    let h = expose::start_listener(&bind, host_port, vsock, guest_port)?;
    let out = expose_json(&h.bind, h.host_port, guest_port);
    exposes.registry.lock().unwrap().entry(id.to_string()).or_default().insert(guest_port, h);
    Ok(out)
}

/// 列出某沙箱已暴露端口 → JSON 数组 `[{bind,host_port,guest_port,url}, ..]`。
fn list_exposes(id: &str, exposes: &Exposes) -> Vec<u8> {
    let reg = exposes.registry.lock().unwrap();
    let items: Vec<String> = reg
        .get(id)
        .map(|m| {
            m.values()
                .map(|h| String::from_utf8(expose_json(&h.bind, h.host_port, h.guest_port)).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    format!("[{}]", items.join(",")).into_bytes()
}

/// 数据面网关连接（M2-Q6）：验签一次性 ticket → 路由到 exec/file/logs/端口反代。端口反代把 guest
/// HTTP 响应**原样**写回外部客户端；其余走 write_response。验签失败 403。
fn handle_gw_conn(mut stream: TcpStream, shared: &Shared, gw: &SharedGw) -> Result<(), String> {
    let (method, path, body) = read_request(&mut stream)?;
    let json = "application/json";
    let q = parse_query(&path);
    let ticket = match gw.verify(&q, now_unix()) {
        Ok(t) => t,
        Err(e) => return write_response(&mut stream, 403, json, &err_json(&format!("ticket 无效: {e}"))),
    };
    let base = path.split('?').next().unwrap_or("");
    match (base, ticket.action) {
        ("/gw/exec", Action::Exec) => match exec_in(&ticket.sid, &body, shared) {
            Ok(v) => write_response(&mut stream, 200, json, &v),
            Err(e) => write_response(&mut stream, 500, json, &err_json(&e)),
        },
        ("/gw/file", Action::File) => {
            let p = q.get("p").cloned().unwrap_or_default();
            if method == "PUT" {
                match put_file(&ticket.sid, &p, &body, shared) {
                    Ok(()) => write_response(&mut stream, 204, json, &[]),
                    Err(e) => write_response(&mut stream, 500, json, &err_json(&e)),
                }
            } else {
                match get_file(&ticket.sid, &p, shared) {
                    Ok(b) => write_response(&mut stream, 200, "application/octet-stream", &b),
                    Err(e) => write_response(&mut stream, 500, json, &err_json(&e)),
                }
            }
        }
        ("/gw/logs", Action::Logs) => match read_logs(&ticket.sid, shared) {
            Ok(b) => write_response(&mut stream, 200, "text/plain; charset=utf-8", &b),
            Err(e) => write_response(&mut stream, 404, json, &err_json(&e)),
        },
        ("/gw/p", Action::Port) => {
            let gpath = q.get("p").cloned().unwrap_or_default();
            // 端口反代仅 FC 后端（vsock）；取裸 vsock 路径（锁内），锁外做代理。
            let tgt = shared.lock().unwrap().exec_target(&ticket.sid);
            match tgt {
                Some(ExecTarget::Vsock(vsock)) => match proxy_port_http(&vsock, ticket.port, &gpath) {
                    Ok(raw) => {
                        stream.write_all(&raw).map_err(|e| format!("写客户端失败: {e}"))?;
                        stream.flush().ok();
                        Ok(())
                    }
                    Err(e) => write_response(&mut stream, 502, json, &err_json(&e)),
                },
                Some(_) => write_response(&mut stream, 400, json, &err_json("端口暴露仅 FC 后端（vsock）支持")),
                None => write_response(&mut stream, 404, json, &err_json("未知沙箱或已回收")),
            }
        }
        _ => write_response(&mut stream, 403, json, &err_json("ticket 动作与路径不符")),
    }
}

/// fork（M2-Q5）：从（已 pause 的）父沙箱派生新实例，reinit 得独立身份。ttl/idle 可选（缺省 300）；
/// 后端继承父（经 orch 内部路由），无需 template。返回新 sandbox JSON（含 forked_from）。
fn fork_sandbox(id: &str, body: &[u8], shared: &Shared) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(if body.is_empty() { b"{}" } else { body })
        .map_err(|e| format!("请求体非 JSON: {e}"))?;
    let ttl = v.get("ttl").and_then(|x| x.as_i64()).unwrap_or(300);
    let idle = v.get("idle").and_then(|x| x.as_i64()).unwrap_or(ttl);
    let spec = SandboxSpec { ttl_secs: ttl, idle_secs: idle, ..Default::default() };
    let mut o = shared.lock().unwrap();
    let out = o.fork(id, &spec)?;
    let forked = out.forked_from.as_deref().unwrap_or("");
    Ok(format!(
        r#"{{"id":"{}","state":"running","machine_id":"{}","forked_from":"{forked}","total_ms":{},"copy_ms":{}}}"#,
        out.id, out.machine_id, out.total_ms, out.copy_ms
    )
    .into_bytes())
}

/// 若为流式 exec 路由（`POST /v1/sandboxes/{id}/exec/stream`）返回 sandbox id，否则 None。
fn parse_exec_stream(method: &str, path: &str) -> Option<String> {
    if method != "POST" {
        return None;
    }
    let path = path.split('?').next().unwrap_or(path);
    let trimmed = path.trim_matches('/');
    let segs: Vec<&str> = if trimmed.is_empty() { vec![] } else { trimmed.split('/').collect() };
    match segs.as_slice() {
        ["v1", "sandboxes", id, "exec", "stream"] => Some((*id).to_string()),
        _ => None,
    }
}

/// 流式 exec（NDJSON）：劫持本连接，把 guest 的 exec 输出帧边收边转成 NDJSON 事件推给客户端。
/// 事件逐行：`{"stream":"stdout"|"stderr","data":"<base64>"}` 逐块，末尾 `{"exit_code":N}`。仅 FC/vsock。
/// 传输：`HTTP/1.1 200` + `Connection: close` + **无 Content-Length**（客户端读到连接关闭为止，可增量收）。
/// 错误在写响应头之前用一次性 `write_response` 报（400/404/500/502）；头写出后只能中断连接。
fn exec_stream_hijack(mut stream: TcpStream, id: &str, body: &[u8], shared: &Shared) -> Result<(), String> {
    let json = "application/json";
    let v: serde_json::Value = match serde_json::from_slice(if body.is_empty() { b"{}" } else { body }) {
        Ok(v) => v,
        Err(e) => return write_response(&mut stream, 400, json, &err_json(&format!("请求体非 JSON: {e}"))),
    };
    let cmd = match v.get("cmd").and_then(|x| x.as_str()) {
        Some(c) => c.to_string(),
        None => return write_response(&mut stream, 400, json, &err_json("缺 cmd 字段")),
    };
    // 取 target（锁内）后立即释放锁；仅 FC/vsock 支持流式 exec。
    let tgt = shared.lock().unwrap().exec_target(id);
    let vsock = match tgt {
        Some(ExecTarget::Vsock(p)) => p,
        Some(_) => return write_response(&mut stream, 400, json, &err_json("流式 exec 仅 FC 后端（vsock）支持")),
        None => return write_response(&mut stream, 404, json, &err_json("未知沙箱或已回收")),
    };
    // 连 guest、发 ExecStream、等 Ok ack（此前的错误都还能回规范 HTTP 响应）。
    let mut g = match connect_guest(&vsock) {
        Ok(s) => s,
        Err(e) => return write_response(&mut stream, 502, json, &err_json(&format!("连 guest 失败: {e}"))),
    };
    if let Err(e) = write_msg(&mut g, &Request::ExecStream { cmd }) {
        return write_response(&mut stream, 502, json, &err_json(&format!("发 ExecStream 失败: {e}")));
    }
    match read_msg::<_, Response>(&mut g) {
        Ok(Response::Ok) => {}
        Ok(Response::Error { message }) => {
            return write_response(&mut stream, 500, json, &err_json(&format!("guest 执行错误: {message}")))
        }
        Ok(other) => return write_response(&mut stream, 502, json, &err_json(&format!("非预期 ack: {other:?}"))),
        Err(e) => return write_response(&mut stream, 502, json, &err_json(&format!("读 ack 失败: {e}"))),
    }
    // ack 成功 → 写 NDJSON 响应头（无 Content-Length），随后边收帧边发事件。
    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).map_err(|e| format!("写响应头失败: {e}"))?;
    stream.flush().ok();
    loop {
        let payload = match read_frame(&mut g) {
            Ok(p) => p,
            Err(_) => break, // guest EOF/错误：命令结束或连接断
        };
        // base64 字符集 [A-Za-z0-9+/=] 无需 JSON 转义，手拼行避免每块 serde 开销。
        let line = match parse_exec_output(&payload) {
            Some(ExecOutput::Stdout(b)) => format!("{{\"stream\":\"stdout\",\"data\":\"{}\"}}\n", b64_encode(&b)),
            Some(ExecOutput::Stderr(b)) => format!("{{\"stream\":\"stderr\",\"data\":\"{}\"}}\n", b64_encode(&b)),
            Some(ExecOutput::Exit(code)) => {
                let _ = stream.write_all(format!("{{\"exit_code\":{code}}}\n").as_bytes());
                stream.flush().ok();
                break;
            }
            None => continue, // 非法帧忽略
        };
        if stream.write_all(line.as_bytes()).is_err() {
            break; // 客户端断开
        }
        stream.flush().ok();
    }
    Ok(())
}

/// 取 exec 目标（持锁）→ 释放锁 → 后端各自执行（慢 IO 不阻塞 create/reaper）。FC=vsock/gVisor=runsc。
fn exec_in(id: &str, body: &[u8], shared: &Shared) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("请求体非 JSON: {e}"))?;
    let cmd = v.get("cmd").and_then(|x| x.as_str()).ok_or("缺 cmd 字段")?;
    let target = shared.lock().unwrap().exec_target(id).ok_or("未知沙箱或已回收")?;
    let (code, out, err) = target.exec(cmd)?;
    Ok(serde_json::json!({"exit_code": code, "stdout": out, "stderr": err}).to_string().into_bytes())
}

/// 文件写：body → base64 → guest `base64 -d` 落盘（后端无关，走 exec 目标）。
fn put_file(id: &str, fpath: &str, body: &[u8], shared: &Shared) -> Result<(), String> {
    let target = shared.lock().unwrap().exec_target(id).ok_or("未知沙箱或已回收")?;
    let b64 = b64_encode(body);
    let path = single_quote(&format!("/{}", fpath.trim_start_matches('/')));
    let cmd = format!("printf %s '{b64}' | base64 -d > {path}");
    let (code, _out, err) = target.exec(&cmd)?;
    if code != 0 {
        return Err(format!("写文件失败（exit={code}）: {}", err.trim()));
    }
    Ok(())
}

/// 文件读：guest `base64 <path>` → 解码回原始字节（后端无关）。
fn get_file(id: &str, fpath: &str, shared: &Shared) -> Result<Vec<u8>, String> {
    let target = shared.lock().unwrap().exec_target(id).ok_or("未知沙箱或已回收")?;
    let path = single_quote(&format!("/{}", fpath.trim_start_matches('/')));
    let (code, out, err) = target.exec(&format!("base64 {path}"))?;
    if code != 0 {
        return Err(format!("读文件失败（exit={code}）: {}", err.trim()));
    }
    b64_decode(&out)
}

fn read_logs(id: &str, shared: &Shared) -> Result<Vec<u8>, String> {
    let p = shared.lock().unwrap().log_path(id).ok_or("未知沙箱或已回收")?;
    std::fs::read(&p).map_err(|e| format!("读日志失败: {e}"))
}

fn list_templates(shared: &Shared) -> Result<Vec<u8>, String> {
    let o = shared.lock().unwrap();
    let kvs = o.store_list("template/")?;
    let mut items = Vec::new();
    for (k, v) in kvs {
        // 仅取 `template/<name>/latest` → {name, version}
        if let Some(rest) = k.strip_prefix("template/") {
            if let Some(name) = rest.strip_suffix("/latest") {
                let version = String::from_utf8_lossy(&v).trim().to_string();
                items.push(format!(r#"{{"name":"{name}","version":"{version}"}}"#));
            }
        }
    }
    Ok(format!("[{}]", items.join(",")).into_bytes())
}

/// `GET /v1/backends`（ADR-14）：后端列表与能力集。W6 单后端（fc）；W7 gVisor 落地时增。
fn list_backends(shared: &Shared) -> Vec<u8> {
    let o = shared.lock().unwrap();
    let items: Vec<String> = o
        .backends_info()
        .into_iter()
        .map(|b| {
            let caps = b.capabilities.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(",");
            format!(r#"{{"id":"{}","capabilities":[{caps}]}}"#, b.id)
        })
        .collect();
    format!("[{}]", items.join(",")).into_bytes()
}

/// 单引号包裹（仓库内路径不含单引号，够用；与 main.rs `sq` 同策略）。
fn single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ————————————————————— base64（无依赖，标准字母表）—————————————————————

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut val = [255u8; 256];
    for (i, &c) in B64.iter().enumerate() {
        val[c as usize] = i as u8;
    }
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        if chunk.len() == 1 {
            return Err("base64 长度非法".into());
        }
        let mut acc = 0u32;
        for i in 0..4 {
            let d = if i < chunk.len() {
                let d = val[chunk[i] as usize];
                if d == 255 {
                    return Err(format!("非法 base64 字符: {}", chunk[i] as char));
                }
                d
            } else {
                0
            };
            acc = (acc << 6) | d as u32;
        }
        let nbytes = chunk.len() - 1; // 4→3, 3→2, 2→1
        let bytes = [(acc >> 16) as u8, (acc >> 8) as u8, acc as u8];
        out.extend_from_slice(&bytes[..nbytes]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_sandbox_crud() {
        assert_eq!(parse_route("POST", "/v1/sandboxes"), Route::CreateSandbox);
        assert_eq!(parse_route("GET", "/v1/sandboxes"), Route::ListSandboxes);
        assert_eq!(parse_route("GET", "/v1/sandboxes?limit=10"), Route::ListSandboxes);
        assert_eq!(parse_route("GET", "/v1/sandboxes/abc"), Route::GetSandbox("abc".into()));
        assert_eq!(parse_route("DELETE", "/v1/sandboxes/abc"), Route::DeleteSandbox("abc".into()));
        assert_eq!(parse_route("POST", "/v1/sandboxes/abc/keepalive"), Route::Keepalive("abc".into()));
        assert_eq!(parse_route("POST", "/v1/sandboxes/abc/exec"), Route::Exec("abc".into()));
        assert_eq!(parse_route("GET", "/v1/sandboxes/abc/logs"), Route::Logs("abc".into()));
    }

    #[test]
    fn route_files_captures_nested_path() {
        assert_eq!(
            parse_route("PUT", "/v1/sandboxes/abc/files/tmp/out.csv"),
            Route::PutFile("abc".into(), "tmp/out.csv".into())
        );
        assert_eq!(
            parse_route("GET", "/v1/sandboxes/abc/files/etc/hostname"),
            Route::GetFile("abc".into(), "etc/hostname".into())
        );
    }

    #[test]
    fn route_expose() {
        assert_eq!(parse_route("POST", "/v1/sandboxes/abc/expose"), Route::Expose("abc".into()));
        assert_eq!(parse_route("GET", "/v1/sandboxes/abc/exposes"), Route::ListExposes("abc".into()));
        assert_eq!(parse_route("DELETE", "/v1/sandboxes/abc/expose/8080"), Route::Unexpose("abc".into(), 8080));
        // 非数字端口 → NotFound（不 panic）。
        assert_eq!(parse_route("DELETE", "/v1/sandboxes/abc/expose/xx"), Route::NotFound);
    }

    #[test]
    fn route_templates_and_unknown() {
        assert_eq!(parse_route("GET", "/v1/templates"), Route::ListTemplates);
        assert_eq!(parse_route("POST", "/v1/templates:build"), Route::BuildTemplate);
        assert_eq!(parse_route("GET", "/"), Route::NotFound);
        assert_eq!(parse_route("PATCH", "/v1/sandboxes/abc"), Route::NotFound);
    }

    #[test]
    fn request_line_and_content_length() {
        let head = b"POST /v1/sandboxes HTTP/1.1\r\nContent-Length: 12\r\nHost: x\r\n";
        let (m, p) = parse_request_line(head).unwrap();
        assert_eq!(m, "POST");
        assert_eq!(p, "/v1/sandboxes");
        assert_eq!(content_length(head), 12);
        assert_eq!(content_length(b"GET / HTTP/1.1\r\nHost: x\r\n"), 0);
    }

    #[test]
    fn base64_roundtrip() {
        for case in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", &[0u8, 255, 16, 128, 3]] {
            let enc = b64_encode(case);
            let dec = b64_decode(&enc).unwrap();
            assert_eq!(dec, case, "roundtrip failed for {case:?} → {enc}");
        }
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_decode("Zm9vYmFy").unwrap(), b"foobar");
        // 容忍换行（guest `base64` 可能换行）
        assert_eq!(b64_decode("Zm9v\nYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn base64_rejects_bad_char() {
        assert!(b64_decode("****").is_err());
    }
}
