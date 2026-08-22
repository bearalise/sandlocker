//! sandlocker — 用户面 CLI（PRD 7.6），M1 W8。
//!
//! 纯 REST 客户端：run/ps/exec/logs/snapshot 走 HTTP 连 `sandlocker up` 起的守护
//! （`sl-node --serve`，默认 `127.0.0.1:7878`）。`up`/`build` 转发到同目录的兄弟 `sl-node`
//! 二进制（`up` = `sl-node --serve` 前台跑；`build` = `sl-node --build` 单发）。
//!
//! 手写极简 HTTP/1.1 客户端（`TcpStream` + `Content-Length` + `Connection: close`，
//! 照 sl-node `fcapi.rs` 口径）。不依赖 sl-node 内部实现——契约即耦合边界（openapi.yaml）。
//! 边界：不支持 chunked/keep-alive（守护也不发）；无鉴权/TLS（M1 单机本地环回，M3 再加）。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const DEFAULT_ADDR: &str = "127.0.0.1:7878";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(&args));
}

/// 顶层分派。返回进程退出码（`run`/`exec` 透传 guest 退出码）。
fn run(args: &[String]) -> i32 {
    let (opts, rest) = match parse_global(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let Some((cmd, sub)) = rest.split_first() else {
        usage();
        return 2;
    };
    let r = match cmd.as_str() {
        "up" => cmd_up(&opts, sub),
        "build" => cmd_build(sub),
        "run" => cmd_run(&opts, sub),
        "ps" => cmd_ps(&opts),
        "exec" => cmd_exec(&opts, sub),
        "expose" => cmd_expose(&opts, sub),
        "unexpose" => cmd_unexpose(&opts, sub),
        "logs" => cmd_logs(&opts, sub),
        "snapshot" => cmd_snapshot(&opts, sub),
        "help" | "-h" | "--help" => {
            usage();
            return 0;
        }
        other => {
            eprintln!("未知子命令: {other}");
            usage();
            return 2;
        }
    };
    match r {
        Ok(code) => code,
        Err(e) => {
            eprintln!("错误: {e}");
            1
        }
    }
}

fn usage() {
    eprintln!(
        "sandlocker — SandLocker 沙箱 CLI\n\
         \n用法: sandlocker [--addr host:port] [--json] <命令> [参数]\n\
         \n命令:\n\
         \x20 up [--addr H:P] [--db F] [--template-root D] [--run-root D]  起本地守护（前台，Ctrl-C 退出）\n\
         \x20 build <file.sandlocker.toml> [--json]                        构建模板（预烘焙快照入库）\n\
         \x20 run <template> [--ttl N] [--idle N] -- <cmd...>              建沙箱→执行→打印→销毁（跑完即焚）\n\
         \x20 ps [--json]                                                  列运行中沙箱\n\
         \x20 exec <id> -- <cmd...>                                        在沙箱内执行命令\n\
         \x20 expose <id> <guest-port> [--host-port N] [--bind ADDR]       暴露 VM 内端口（稳定地址 L4 透传）\n\
         \x20 unexpose <id> <guest-port>                                   撤销端口暴露\n\
         \x20 logs <id>                                                    打印沙箱串口/引导日志\n\
         \x20 snapshot ls [--json]                                         列预烘焙快照（M1：模板=快照）\n"
    );
}

// ————————————————————— 全局参数 —————————————————————

struct Opts {
    addr: String,
    json: bool,
}

/// 剥离全局 `--addr`/`--json`，其余按序返回给子命令。
fn parse_global(args: &[String]) -> Result<(Opts, Vec<String>), String> {
    let mut addr = std::env::var("SANDLOCKER_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let mut json = false;
    let mut rest = Vec::new();
    let mut i = 0;
    // 只在遇到子命令前解析全局标志；子命令之后的一律透传（避免吃掉 run/exec 的 `--`）。
    let mut seen_cmd = false;
    while i < args.len() {
        let a = &args[i];
        if !seen_cmd {
            match a.as_str() {
                "--addr" => {
                    i += 1;
                    addr = args.get(i).ok_or("--addr 缺少参数值")?.clone();
                }
                "--json" => json = true,
                _ => {
                    seen_cmd = true;
                    rest.push(a.clone());
                }
            }
        } else {
            rest.push(a.clone());
        }
        i += 1;
    }
    Ok((Opts { addr, json }, rest))
}

/// 取形如 `--flag value` 的值；命中则移除这两项。
fn take_flag(args: &mut Vec<String>, flag: &str) -> Option<String> {
    if let Some(pos) = args.iter().position(|a| a == flag) {
        if pos + 1 < args.len() {
            let val = args.remove(pos + 1);
            args.remove(pos);
            return Some(val);
        }
    }
    None
}

/// 分离 `-- <cmd...>` 之后的命令向量，返回 (前置位置参数, cmd 向量)。
fn split_double_dash(args: &[String]) -> (Vec<String>, Vec<String>) {
    if let Some(pos) = args.iter().position(|a| a == "--") {
        (args[..pos].to_vec(), args[pos + 1..].to_vec())
    } else {
        (args.to_vec(), Vec::new())
    }
}

// ————————————————————— 兄弟 sl-node 定位（up/build）—————————————————————

/// 与当前 `sandlocker` 二进制同目录找 `sl-node`（cargo 产物二者同出 target/<profile>/）。
fn locate_sl_node() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("取自身路径失败: {e}"))?;
    let dir = exe.parent().ok_or("自身无父目录")?;
    let cand = dir.join("sl-node");
    if cand.is_file() {
        return Ok(cand);
    }
    Err(format!(
        "同目录未找到 sl-node（期望 {}）；请先 `cargo build` 出两二进制",
        cand.display()
    ))
}

// ————————————————————— 子命令 —————————————————————

/// `up`：前台起守护（`sl-node --serve`）。stdio 继承；Ctrl-C 直达子进程干净退出。
fn cmd_up(opts: &Opts, sub: &[String]) -> Result<i32, String> {
    let mut a = sub.to_vec();
    let db = take_flag(&mut a, "--db");
    let template_root = take_flag(&mut a, "--template-root");
    let run_root = take_flag(&mut a, "--run-root");
    let tick = take_flag(&mut a, "--tick-secs");

    let sl_node = locate_sl_node()?;
    let mut cmd = Command::new(&sl_node);
    cmd.arg("--serve").arg("--addr").arg(&opts.addr);
    if let Some(v) = db {
        cmd.arg("--store").arg(v);
    }
    if let Some(v) = template_root {
        cmd.arg("--template-root").arg(v);
    }
    if let Some(v) = run_root {
        cmd.arg("--run-root").arg(v);
    }
    if let Some(v) = tick {
        cmd.arg("--tick-secs").arg(v);
    }
    let status = cmd.status().map_err(|e| format!("起守护失败: {e}"))?;
    Ok(status.code().unwrap_or(0))
}

/// `build`：转发 `sl-node --build <file> [--json]`（单发直跑，非走守护）。
fn cmd_build(sub: &[String]) -> Result<i32, String> {
    let file = sub.first().ok_or("用法: sandlocker build <file.sandlocker.toml> [--json]")?;
    let sl_node = locate_sl_node()?;
    let mut cmd = Command::new(&sl_node);
    cmd.arg("--build").arg(file);
    if sub.iter().any(|a| a == "--json") {
        cmd.arg("--json");
    }
    let status = cmd.status().map_err(|e| format!("起构建失败: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

/// `run <template> [--ttl N --idle N] -- <cmd...>`：建→exec→打印→销毁（US-7 跑完即焚）。
fn cmd_run(opts: &Opts, sub: &[String]) -> Result<i32, String> {
    let (head, cmdv) = split_double_dash(sub);
    let mut head = head;
    let ttl = take_flag(&mut head, "--ttl");
    let idle = take_flag(&mut head, "--idle");
    let template = head.first().ok_or("用法: sandlocker run <template> [--ttl N --idle N] -- <cmd...>")?;
    if cmdv.is_empty() {
        return Err("缺少要执行的命令（`-- <cmd...>`）".into());
    }

    // 建沙箱
    let body = build_create_body(template, ttl.as_deref(), idle.as_deref());
    let (code, resp) = http(&opts.addr, "POST", "/v1/sandboxes", Some(&body), "application/json")?;
    if code != 201 {
        return Err(format!("创建沙箱失败（HTTP {code}）: {resp}"));
    }
    let id = json_str(&resp, "id").ok_or_else(|| format!("创建响应无 id: {resp}"))?;

    // 执行 → 打印 → 无论成败都销毁
    let result = exec_once(&opts.addr, &id, &cmdv);
    let _ = http(&opts.addr, "DELETE", &format!("/v1/sandboxes/{id}"), None, "application/json");

    let (exit, out, err) = result?;
    print!("{out}");
    eprint!("{err}");
    Ok(exit)
}

/// `ps`：`GET /v1/sandboxes` → 表格或原始 JSON。
fn cmd_ps(opts: &Opts) -> Result<i32, String> {
    let (code, resp) = http(&opts.addr, "GET", "/v1/sandboxes", None, "application/json")?;
    if code != 200 {
        return Err(format!("列举失败（HTTP {code}）: {resp}"));
    }
    if opts.json {
        println!("{resp}");
        return Ok(0);
    }
    let items = json_array_objects(&resp);
    println!("{:<26} {:<10} {:<16} {:>10}", "ID", "STATE", "TEMPLATE", "TTL_DDL");
    for obj in items {
        let id = obj_field(&obj, "id").unwrap_or_default();
        let state = obj_field(&obj, "state").unwrap_or_else(|| "-".into());
        let tpl = obj_field(&obj, "template").unwrap_or_else(|| "-".into());
        let ttl = obj_field(&obj, "ttl_deadline").unwrap_or_else(|| "-".into());
        println!("{id:<26} {state:<10} {tpl:<16} {ttl:>10}");
    }
    Ok(0)
}

/// `exec <id> -- <cmd...>`：在已存在沙箱内执行。
fn cmd_exec(opts: &Opts, sub: &[String]) -> Result<i32, String> {
    let (head, cmdv) = split_double_dash(sub);
    let id = head.first().ok_or("用法: sandlocker exec <id> -- <cmd...>")?;
    if cmdv.is_empty() {
        return Err("缺少要执行的命令（`-- <cmd...>`）".into());
    }
    let (exit, out, err) = exec_once(&opts.addr, id, &cmdv)?;
    print!("{out}");
    eprint!("{err}");
    Ok(exit)
}

/// `expose <id> <guest-port> [--host-port N] [--bind ADDR]`：暴露 VM 内端口为稳定地址（L4 透传）。
/// 打印生成的 URL。非回环 bind 需守护带 --expose-allow-public。
fn cmd_expose(opts: &Opts, sub: &[String]) -> Result<i32, String> {
    let mut a = sub.to_vec();
    let host_port = take_flag(&mut a, "--host-port");
    let bind = take_flag(&mut a, "--bind");
    let id = a.first().ok_or("用法: sandlocker expose <id> <guest-port> [--host-port N] [--bind ADDR]")?;
    let gp: u32 = a.get(1).ok_or("缺 guest-port")?.parse().map_err(|_| "guest-port 非数字")?;
    let mut obj = serde_json::Map::new();
    obj.insert("port".into(), serde_json::Value::from(gp));
    if let Some(p) = host_port.and_then(|s| s.parse::<u16>().ok()) {
        obj.insert("host_port".into(), serde_json::Value::from(p));
    }
    if let Some(b) = bind {
        obj.insert("bind".into(), serde_json::Value::String(b));
    }
    let body = serde_json::Value::Object(obj).to_string();
    let (code, resp) = http(&opts.addr, "POST", &format!("/v1/sandboxes/{id}/expose"), Some(&body), "application/json")?;
    if code != 201 {
        return Err(format!("expose 失败（HTTP {code}）: {resp}"));
    }
    if opts.json {
        println!("{resp}");
    } else {
        println!("{}", json_str(&resp, "url").unwrap_or(resp));
    }
    Ok(0)
}

/// `unexpose <id> <guest-port>`：撤销端口暴露（停止监听器）。
fn cmd_unexpose(opts: &Opts, sub: &[String]) -> Result<i32, String> {
    let id = sub.first().ok_or("用法: sandlocker unexpose <id> <guest-port>")?;
    let gp: u32 = sub.get(1).ok_or("缺 guest-port")?.parse().map_err(|_| "guest-port 非数字")?;
    let (code, resp) = http(&opts.addr, "DELETE", &format!("/v1/sandboxes/{id}/expose/{gp}"), None, "application/json")?;
    if code != 204 {
        return Err(format!("unexpose 失败（HTTP {code}）: {resp}"));
    }
    Ok(0)
}

/// `logs <id>`：打印守护读回的实例引导/串口日志。
fn cmd_logs(opts: &Opts, sub: &[String]) -> Result<i32, String> {
    let id = sub.first().ok_or("用法: sandlocker logs <id>")?;
    let (code, resp) = http(&opts.addr, "GET", &format!("/v1/sandboxes/{id}/logs"), None, "text/plain")?;
    if code != 200 {
        return Err(format!("取日志失败（HTTP {code}）: {resp}"));
    }
    print!("{resp}");
    Ok(0)
}

/// `snapshot ls`：列预烘焙快照（M1 语义：模板即快照）。裸 `snapshot` 打印用法。
fn cmd_snapshot(opts: &Opts, sub: &[String]) -> Result<i32, String> {
    match sub.first().map(|s| s.as_str()) {
        Some("ls") => {
            let (code, resp) = http(&opts.addr, "GET", "/v1/templates", None, "application/json")?;
            if code != 200 {
                return Err(format!("列快照失败（HTTP {code}）: {resp}"));
            }
            if opts.json {
                println!("{resp}");
                return Ok(0);
            }
            println!("{:<20} {:<16}", "TEMPLATE", "VERSION");
            for obj in json_array_objects(&resp) {
                let name = obj_field(&obj, "name").unwrap_or_default();
                let ver = obj_field(&obj, "version").unwrap_or_default();
                println!("{name:<20} {ver:<16}");
            }
            Ok(0)
        }
        _ => {
            eprintln!(
                "用法: sandlocker snapshot ls [--json]\n\
                 （M1：模板=预烘焙快照；pause/resume/fork 运行时快照属 M2）"
            );
            Ok(2)
        }
    }
}

// ————————————————————— HTTP 客户端 + exec 便捷 —————————————————————

/// exec 一条命令：`POST /v1/sandboxes/{id}/exec {cmd}` → (exit, stdout, stderr)。
fn exec_once(addr: &str, id: &str, cmdv: &[String]) -> Result<(i32, String, String), String> {
    let cmd = cmdv.join(" ");
    let body = serde_json::json!({ "cmd": cmd }).to_string();
    let (code, resp) = http(addr, "POST", &format!("/v1/sandboxes/{id}/exec"), Some(&body), "application/json")?;
    if code != 200 {
        return Err(format!("exec 失败（HTTP {code}）: {resp}"));
    }
    let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| format!("exec 响应非 JSON: {e}"))?;
    let exit = v.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(-1) as i32;
    let out = v.get("stdout").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let err = v.get("stderr").and_then(|x| x.as_str()).unwrap_or("").to_string();
    Ok((exit, out, err))
}

/// 建沙箱请求体（纯逻辑，单测）。
fn build_create_body(template: &str, ttl: Option<&str>, idle: Option<&str>) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("template".into(), serde_json::Value::String(template.to_string()));
    if let Some(t) = ttl.and_then(|s| s.parse::<i64>().ok()) {
        obj.insert("ttl".into(), serde_json::Value::from(t));
    }
    if let Some(i) = idle.and_then(|s| s.parse::<i64>().ok()) {
        obj.insert("idle".into(), serde_json::Value::from(i));
    }
    serde_json::Value::Object(obj).to_string()
}

/// 手写 HTTP/1.1 请求：返回 (状态码, body 文本)。TcpStream + Content-Length + Connection: close。
fn http(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    ctype: &str,
) -> Result<(u16, String), String> {
    let mut s = TcpStream::connect(addr)
        .map_err(|e| format!("连守护失败 {addr}: {e}（是否已 `sandlocker up`？）"))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\
         Content-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    s.write_all(req.as_bytes()).map_err(|e| format!("写请求失败: {e}"))?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = find_crlfcrlf(&buf) {
            break p;
        }
        let n = s.read(&mut chunk).map_err(|e| format!("读响应头失败: {e}"))?;
        if n == 0 {
            return Err("响应未含完整 header（连接过早关闭）".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let want = head_end + 4 + content_length(&buf[..head_end]);
    while buf.len() < want {
        let n = s.read(&mut chunk).map_err(|e| format!("读响应体失败: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    parse_http_response(&buf)
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
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

fn parse_http_response(buf: &[u8]) -> Result<(u16, String), String> {
    let sep = find_crlfcrlf(buf).ok_or("响应无完整 header")?;
    let head = &buf[..sep];
    let body = &buf[sep + 4..];
    let first_line = head.split(|&b| b == b'\n').next().unwrap_or(head);
    let line = String::from_utf8_lossy(first_line);
    let code = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("状态行无法解析: {line:?}"))?;
    Ok((code, String::from_utf8_lossy(body).to_string()))
}

// ————————————————————— 轻量 JSON 取值（依赖 serde_json）—————————————————————

/// 从 JSON 文本取顶层字符串字段。
fn json_str(text: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

/// 顶层 JSON 数组 → 各元素（Value）。非数组返回空。
fn json_array_objects(text: &str) -> Vec<serde_json::Value> {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Array(a)) => a,
        _ => Vec::new(),
    }
}

/// 取对象字段并转字符串（字符串原样；数字/布尔用 to_string）。
fn obj_field(v: &serde_json::Value, key: &str) -> Option<String> {
    let f = v.get(key)?;
    match f {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn global_addr_and_json_stripped_before_cmd() {
        let (o, rest) = parse_global(&sv(&["--addr", "1.2.3.4:9", "--json", "ps"])).unwrap();
        assert_eq!(o.addr, "1.2.3.4:9");
        assert!(o.json);
        assert_eq!(rest, sv(&["ps"]));
    }

    #[test]
    fn global_flags_after_cmd_passthrough() {
        // run 的 `--` 段与其内标志不被全局解析吃掉
        let (o, rest) = parse_global(&sv(&["run", "hello", "--", "echo", "--json"])).unwrap();
        assert_eq!(o.addr, DEFAULT_ADDR);
        assert!(!o.json);
        assert_eq!(rest, sv(&["run", "hello", "--", "echo", "--json"]));
    }

    #[test]
    fn split_double_dash_splits() {
        let (head, cmd) = split_double_dash(&sv(&["hello", "--ttl", "60", "--", "echo", "hi"]));
        assert_eq!(head, sv(&["hello", "--ttl", "60"]));
        assert_eq!(cmd, sv(&["echo", "hi"]));
    }

    #[test]
    fn split_double_dash_no_dash() {
        let (head, cmd) = split_double_dash(&sv(&["id123"]));
        assert_eq!(head, sv(&["id123"]));
        assert!(cmd.is_empty());
    }

    #[test]
    fn take_flag_removes_pair() {
        let mut a = sv(&["hello", "--ttl", "60", "--idle", "30"]);
        assert_eq!(take_flag(&mut a, "--ttl"), Some("60".into()));
        assert_eq!(a, sv(&["hello", "--idle", "30"]));
        assert_eq!(take_flag(&mut a, "--missing"), None);
    }

    #[test]
    fn create_body_minimal_and_full() {
        assert_eq!(build_create_body("hello", None, None), r#"{"template":"hello"}"#);
        let full = build_create_body("hello", Some("300"), Some("120"));
        let v: serde_json::Value = serde_json::from_str(&full).unwrap();
        assert_eq!(v["template"], "hello");
        assert_eq!(v["ttl"], 300);
        assert_eq!(v["idle"], 120);
    }

    #[test]
    fn parse_response_status_and_body() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Length: 20\r\n\r\n{\"id\":\"abc\",\"x\":1}xx";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 201);
        assert!(body.starts_with("{\"id\":\"abc\""));
        assert_eq!(json_str(&body[..18], "id"), Some("abc".into()));
    }

    #[test]
    fn content_length_parse() {
        assert_eq!(content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 42"), 42);
        assert_eq!(content_length(b"HTTP/1.1 204 No Content\r\nConnection: close"), 0);
    }

    #[test]
    fn ps_json_array_parse() {
        let items = json_array_objects(r#"[{"id":"a","state":"running","ttl_deadline":123}]"#);
        assert_eq!(items.len(), 1);
        assert_eq!(obj_field(&items[0], "id"), Some("a".into()));
        assert_eq!(obj_field(&items[0], "ttl_deadline"), Some("123".into()));
        assert_eq!(obj_field(&items[0], "missing"), None);
    }
}
