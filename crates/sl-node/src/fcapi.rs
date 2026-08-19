//! fcapi — Firecracker HTTP API 客户端（手写极简 HTTP/1.1-over-UDS，D1 决议）。
//!
//! 仅覆盖 M1 用到的端点，契约锚定 firecracker_spec-v1.16.1.yaml：
//!   PUT  /machine-config /boot-source /drives/{id} /network-interfaces/{id} /vsock
//!   PUT  /actions {action_type:"InstanceStart"}
//!   PATCH /vm     {state:"Paused"|"Resumed"}
//!   PUT  /snapshot/create {mem_file_path, snapshot_path, snapshot_type?}
//!   PUT  /snapshot/load   {snapshot_path, mem_file_path|mem_backend, resume_vm?}
//!
//! 每请求一条连接。FC 的 micro-http 恒回 `Connection: keep-alive`、无视我们的 close 头，
//! 故不能 read-to-EOF（会挂到超时）——按 `Content-Length` 精确读 body（204 无该头 → body 空）。
//! 对少数几个建 VM 调用开销可忽略。仅依赖 std。

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

pub struct FcApi {
    sock: PathBuf,
    timeout: Duration,
    slow_timeout: Duration,
}

impl FcApi {
    pub fn new(sock: impl Into<PathBuf>) -> Self {
        // 默认 5s；SL_FC_API_TIMEOUT_SECS 可调大以区分「真挂死」与「首次访问慢」
        // （如 dm 块设备 rootfs：InstanceStart 若只是慢，调大后能完成；仍超时则是真挂）。
        let secs = std::env::var("SL_FC_API_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(5);
        // 慢操作（snapshot/create）单独放宽：Full 快照要把 guest 内存落盘 + 刷 rootfs 脏页，
        // 大镜像（>1GB rootfs）在慢/嵌套存储上远超 5s——用 slow_timeout 而非紧超时，避免大镜像假失败。
        // SL_FC_SNAPSHOT_TIMEOUT_SECS 可调，默认 300s。
        let slow = std::env::var("SL_FC_SNAPSHOT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(300)
            .max(secs); // 慢超时不得小于常规超时
        Self {
            sock: sock.into(),
            timeout: Duration::from_secs(secs),
            slow_timeout: Duration::from_secs(slow),
        }
    }

    /// 等 api-sock 出现且可连（FC spawn 后短暂延迟才建 socket）。
    pub fn wait_ready(&self, timeout: Duration) -> Result<(), String> {
        let start = Instant::now();
        loop {
            if self.sock.exists() && UnixStream::connect(&self.sock).is_ok() {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(format!("api-sock 未就绪（{timeout:?}）: {}", self.sock.display()));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn put(&self, path: &str, json: &str) -> Result<(), String> {
        self.expect_2xx("PUT", path, Some(json))
    }
    /// 慢操作 PUT（如 snapshot/create）：读超时用 slow_timeout（默认 300s）而非紧超时。
    /// 大镜像 Full 快照刷脏页可能远超常规 5s，用此避免假「读响应头失败」。
    pub fn put_long(&self, path: &str, json: &str) -> Result<(), String> {
        let (code, resp) = self.raw_with_timeout("PUT", path, Some(json), self.slow_timeout)?;
        if (200..300).contains(&code) {
            Ok(())
        } else {
            Err(format!("FC PUT {path} -> {code}: {resp}"))
        }
    }
    /// W2 快照用：`PATCH /vm {state:Paused|Resumed}`。
    pub fn patch(&self, path: &str, json: &str) -> Result<(), String> {
        self.expect_2xx("PATCH", path, Some(json))
    }
    /// W2 用：`GET /vm` 读实例状态等。
    #[allow(dead_code)]
    pub fn get(&self, path: &str) -> Result<String, String> {
        let (code, body) = self.raw("GET", path, None)?;
        if (200..300).contains(&code) { Ok(body) } else { Err(format!("FC GET {path} -> {code}: {body}")) }
    }

    fn expect_2xx(&self, method: &str, path: &str, body: Option<&str>) -> Result<(), String> {
        let (code, resp) = self.raw(method, path, body)?;
        if (200..300).contains(&code) {
            Ok(())
        } else {
            Err(format!("FC {method} {path} -> {code}: {resp}"))
        }
    }

    fn raw(&self, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String), String> {
        self.raw_with_timeout(method, path, body, self.timeout)
    }

    fn raw_with_timeout(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        timeout: Duration,
    ) -> Result<(u16, String), String> {
        let mut s = UnixStream::connect(&self.sock)
            .map_err(|e| format!("连 api-sock 失败 {}: {e}", self.sock.display()))?;
        let _ = s.set_read_timeout(Some(timeout));
        let _ = s.set_write_timeout(Some(timeout));
        let body = body.unwrap_or("");
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        s.write_all(req.as_bytes()).map_err(|e| format!("写请求失败: {e}"))?;

        // 读满 header（首个 \r\n\r\n），再按 Content-Length 精确读 body——不 read-to-EOF。
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        let head_end = loop {
            if let Some(p) = find_crlfcrlf(&buf) {
                break p;
            }
            let n = s.read(&mut chunk).map_err(|e| format!("读响应头失败: {e}"))?;
            if n == 0 {
                return Err("响应未含完整 header（连接过早关闭）".to_string());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let want = head_end + 4 + content_length(&buf[..head_end]);
        while buf.len() < want {
            let n = s.read(&mut chunk).map_err(|e| format!("读响应体失败: {e}"))?;
            if n == 0 {
                break; // 连接关闭，按已读到的算（防御性）
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        parse_http_response(&buf)
    }
}

/// 定位首个 `\r\n\r\n`，返回其起始下标。
fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 从 header 区解析 Content-Length（大小写不敏感），缺省 0（如 204）。
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

/// 解析 HTTP/1.1 响应：返回 (状态码, body 文本)。
fn parse_http_response(buf: &[u8]) -> Result<(u16, String), String> {
    // 分割 header/body（首个 \r\n\r\n）
    let sep = find_crlfcrlf(buf).ok_or_else(|| "响应无完整 header".to_string())?;
    let head = &buf[..sep];
    let body = &buf[sep + 4..];
    // 状态行："HTTP/1.1 204 No Content"
    let first_line = head.split(|&b| b == b'\n').next().unwrap_or(head);
    let line = String::from_utf8_lossy(first_line);
    let code = line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("状态行无法解析: {line:?}"))?;
    Ok((code, String::from_utf8_lossy(body).trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_204_no_body() {
        let raw = b"HTTP/1.1 204 No Content\r\nServer: Firecracker\r\n\r\n";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 204);
        assert_eq!(body, "");
    }

    #[test]
    fn parse_400_with_body() {
        let raw = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\n\r\n{\"fault_message\":\"bad cfg\"}";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 400);
        assert!(body.contains("bad cfg"));
    }

    #[test]
    fn parse_malformed_errors() {
        assert!(parse_http_response(b"garbage without crlfcrlf").is_err());
    }

    #[test]
    fn content_length_case_insensitive_and_default_zero() {
        // FC 的 204 无 Content-Length → 0（否则读 body 会等到超时，正是 keep-alive 那个 bug）
        assert_eq!(content_length(b"HTTP/1.1 204 \r\nServer: Firecracker API\r\nConnection: keep-alive"), 0);
        // 大小写不敏感
        assert_eq!(content_length(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 27"), 27);
        assert_eq!(content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 96"), 96);
    }

    #[test]
    fn find_crlfcrlf_locates_header_end() {
        assert_eq!(find_crlfcrlf(b"HTTP/1.1 204 \r\nA: b\r\n\r\nbody"), Some(19));
        assert_eq!(find_crlfcrlf(b"no terminator here"), None);
    }
}
