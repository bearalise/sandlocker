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

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sl_store::SqliteStore;

use crate::backend::Capabilities;
use crate::orch::{Orch, SandboxSpec};
use crate::{connect_guest, exec, Config};

/// 守护共享态：orchestrator（互斥）+ 模板仓库根（模板名→目录解析）。
type Shared = Arc<Mutex<Orch<'static>>>;

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
    let shared: Shared = Arc::new(Mutex::new(orch));

    // 后台 reaper：周期 tick(now)（TTL 硬顶 + idle sweep）。
    let tick_secs = if cfg.tick_secs > 0 { cfg.tick_secs } else { 5 };
    let reaper = Arc::clone(&shared);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(tick_secs));
        let now = now_unix();
        if let Ok(mut o) = reaper.lock() {
            let _ = o.tick(now);
        }
    });

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
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, &sh, troot) {
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

fn handle_conn(mut stream: TcpStream, shared: &Shared, template_root: &Path) -> Result<(), String> {
    let (method, path, body) = read_request(&mut stream)?;
    let (code, ctype, resp) = dispatch(&method, &path, &body, shared, template_root);
    write_response(&mut stream, code, ctype, &resp)
}

fn dispatch(
    method: &str,
    path: &str,
    body: &[u8],
    shared: &Shared,
    template_root: &Path,
) -> (u16, &'static str, Vec<u8>) {
    let route = parse_route(method, path);
    let json = "application/json";
    match route {
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
                Ok(_) => (204, json, Vec::new()),
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
    let spec = SandboxSpec {
        vcpus: cpu,
        mem_mib: mem,
        ttl_secs: ttl,
        idle_secs: idle,
        metadata,
        required_capabilities,
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

/// 取 vsock 路径（持锁）→ 释放锁 → 连 guest 执行（慢 IO 不阻塞 create/reaper）。
fn exec_in(id: &str, body: &[u8], shared: &Shared) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("请求体非 JSON: {e}"))?;
    let cmd = v.get("cmd").and_then(|x| x.as_str()).ok_or("缺 cmd 字段")?;
    let vsock = shared.lock().unwrap().vsock_path(id).ok_or("未知沙箱或已回收")?;
    let mut stream = connect_guest(&vsock)?;
    let (code, out, err) = exec(&mut stream, cmd)?;
    Ok(serde_json::json!({"exit_code": code, "stdout": out, "stderr": err}).to_string().into_bytes())
}

/// 文件写：body → base64 → guest `base64 -d` 落盘（复用 build.rs COPY 桥接思路）。
fn put_file(id: &str, fpath: &str, body: &[u8], shared: &Shared) -> Result<(), String> {
    let vsock = shared.lock().unwrap().vsock_path(id).ok_or("未知沙箱或已回收")?;
    let mut stream = connect_guest(&vsock)?;
    let b64 = b64_encode(body);
    let path = single_quote(&format!("/{}", fpath.trim_start_matches('/')));
    let cmd = format!("printf %s '{b64}' | base64 -d > {path}");
    let (code, _out, err) = exec(&mut stream, &cmd)?;
    if code != 0 {
        return Err(format!("写文件失败（exit={code}）: {}", err.trim()));
    }
    Ok(())
}

/// 文件读：guest `base64 <path>` → 解码回原始字节。
fn get_file(id: &str, fpath: &str, shared: &Shared) -> Result<Vec<u8>, String> {
    let vsock = shared.lock().unwrap().vsock_path(id).ok_or("未知沙箱或已回收")?;
    let mut stream = connect_guest(&vsock)?;
    let path = single_quote(&format!("/{}", fpath.trim_start_matches('/')));
    let (code, out, err) = exec(&mut stream, &format!("base64 {path}"))?;
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
