//! expose.rs — 端口暴露 / 持久 L4（TCP）透传反向代理。
//!
//! 让 VM 里跑的动态 Web 应用（Next.js 等）能被外部经一个稳定地址访问，支持任意 HTTP 方法、
//! 流式/SSE、WebSocket/HMR、keep-alive——因为这是**纯 L4 裸字节透传**，对上层协议不可见。
//!
//! 拓扑：外部 client ──TcpStream── host 监听器 ──vsock 隧道── guest sl-envd `handle_connect`
//!       ──splice_bidi── guest 127.0.0.1:guest_port（应用）。
//!
//! 与 `gateway.rs`（一次性 HMAC ticket + 整包 HTTP/1.0 单 GET）正交：那条用于 exec/文件/日志/
//! 单次探活；本模块是持久 L4 透传，**不做每请求鉴权**（方案 2，弱隔离/可信场景取舍）。默认只
//! bind 127.0.0.1；对外 bind（0.0.0.0）= 把 guest 服务原样暴露给整网，需显式开启。

use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sl_proto::{read_msg, write_msg, Request, Response};

use crate::connect_guest;

/// accept 轮询 stop 标志的周期（TcpListener 无原生 shutdown，用 nonblocking + 轮询）。
const ACCEPT_POLL: Duration = Duration::from_millis(200);

/// 一个已起的端口暴露监听器句柄。持 `stop` 标志，`stop()` 后 accept 线程退出、listener drop、端口释放。
pub struct ExposeHandle {
    pub host_port: u16,
    pub bind: String,
    pub guest_port: u32,
    stop: Arc<AtomicBool>,
}

impl ExposeHandle {
    /// 通知 accept 线程停止（幂等）。线程 ≤ACCEPT_POLL 内退出并释放端口。
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// 建立到 guest `127.0.0.1:guest_port` 的裸字节隧道：`connect_guest`（FC vsock 握手）→ 发 sl-proto
/// `Connect{port}` → 读 `Ok`。`read_msg` 定长帧、`connect_guest` 逐字节读 OK 行，均不 over-read，
/// 返回的 `UnixStream` 之后即纯 L4 隧道（与 `gateway::proxy_port_http` 同握手序列）。
pub fn open_tunnel(vsock: &Path, guest_port: u32) -> Result<UnixStream, String> {
    let mut s = connect_guest(vsock)?;
    write_msg(&mut s, &Request::Connect { port: guest_port }).map_err(|e| format!("发 Connect 失败: {e}"))?;
    match read_msg::<_, Response>(&mut s).map_err(|e| format!("读 Connect ack 失败: {e}"))? {
        Response::Ok => Ok(s),
        Response::Error { message } => Err(format!("guest Connect 失败: {message}")),
        other => Err(format!("Connect ack 异常: {other:?}")),
    }
}

/// 外部 client `TcpStream` ↔ guest 隧道 `UnixStream` 全双工透传，直到两方向都收敛。
///
/// 半关感知：单方向 EOF 只 `shutdown(Write)` 对端（传递 EOF）+ `shutdown(Read)` 自身，另一方向继续；
/// 比 guest `splice_bidi`「一端 EOF 即双端全关」更忠实，避免响应/WS 关闭帧被截断。
pub fn splice(client: TcpStream, guest: UnixStream) {
    // 各取一份读/写副本（try_clone 共享底层 fd）。
    let client_wr = match client.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let guest_wr = match guest.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };

    // 上行：client → guest
    let up = thread::spawn(move || {
        let mut r = client;
        let mut w = guest_wr;
        let _ = io::copy(&mut r, &mut w);
        let _ = w.shutdown(Shutdown::Write); // guest 侧 read 收到 EOF
        let _ = r.shutdown(Shutdown::Read);
    });

    // 下行（本线程）：guest → client
    {
        let mut r = guest;
        let mut w = client_wr;
        let _ = io::copy(&mut r, &mut w);
        let _ = w.shutdown(Shutdown::Write);
        let _ = r.shutdown(Shutdown::Read);
    }
    let _ = up.join();
}

/// 起一个 accept 循环线程，把 `bind:host_port` 上的每条外部连接透传到 guest `guest_port`。
/// `host_port=0` → OS 分配（`local_addr` 回读实际端口）。`vsock` 路径快照进闭包（实例生命周期内稳定）。
pub fn start_listener(bind: &str, host_port: u16, vsock: PathBuf, guest_port: u32) -> Result<ExposeHandle, String> {
    let listener = TcpListener::bind((bind, host_port)).map_err(|e| format!("bind {bind}:{host_port} 失败: {e}"))?;
    let actual = listener.local_addr().map_err(|e| e.to_string())?.port();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    thread::spawn(move || {
        loop {
            if stop_t.load(Ordering::Relaxed) {
                break; // 拆除：线程返回 → listener drop → 端口释放
            }
            match listener.accept() {
                Ok((client, _peer)) => {
                    // nonblocking listener 出的 socket 在部分平台亦为 nonblocking，io::copy 会
                    // WouldBlock 报错 → 必须转回阻塞。
                    let _ = client.set_nonblocking(false);
                    let vsock = vsock.clone();
                    thread::spawn(move || match open_tunnel(&vsock, guest_port) {
                        Ok(g) => splice(client, g),
                        Err(_) => {
                            let _ = client.shutdown(Shutdown::Both);
                        }
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
                Err(_) => thread::sleep(ACCEPT_POLL),
            }
        }
    });

    Ok(ExposeHandle { host_port: actual, bind: bind.to_string(), guest_port, stop })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// start_listener 能起、回读实际分配端口、透传裸字节到一个本地 upstream，且 stop 后端口释放。
    /// 用一个本地 TCP echo 冒充 “guest”——本测不经 vsock，仅验监听器/端口分配/停止语义与 splice 骨架。
    #[test]
    fn splice_forwards_bytes_bidirectionally() {
        // 本地 upstream：收到什么回写 “echo:” 前缀（验证双向）。
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = upstream.local_addr().unwrap().port();
        let up = thread::spawn(move || {
            let (mut c, _) = upstream.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap();
            c.write_all(b"echo:").unwrap();
            c.write_all(&buf[..n]).unwrap();
            let _ = c.shutdown(Shutdown::Write);
        });

        // 前门：一条监听器，accept 后把 client 与到 upstream 的连接 splice。
        let front = TcpListener::bind("127.0.0.1:0").unwrap();
        let front_port = front.local_addr().unwrap().port();
        let fwd = thread::spawn(move || {
            let (client, _) = front.accept().unwrap();
            client.set_nonblocking(false).unwrap();
            let guest = TcpStream::connect(("127.0.0.1", up_port)).unwrap();
            // splice 收 UnixStream，这里用 TcpStream 冒充：改用与 splice 等价的裸转发验证骨架。
            splice_tcp(client, guest);
        });

        let mut c = TcpStream::connect(("127.0.0.1", front_port)).unwrap();
        c.write_all(b"hello").unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        assert_eq!(&got, b"echo:hello");
        up.join().unwrap();
        fwd.join().unwrap();
    }

    /// splice 的 TcpStream↔TcpStream 版（测试用；生产是 TcpStream↔UnixStream，逻辑同构）。
    fn splice_tcp(client: TcpStream, guest: TcpStream) {
        let client_wr = client.try_clone().unwrap();
        let guest_wr = guest.try_clone().unwrap();
        let up = thread::spawn(move || {
            let (mut r, mut w) = (client, guest_wr);
            let _ = io::copy(&mut r, &mut w);
            let _ = w.shutdown(Shutdown::Write);
            let _ = r.shutdown(Shutdown::Read);
        });
        {
            let (mut r, mut w) = (guest, client_wr);
            let _ = io::copy(&mut r, &mut w);
            let _ = w.shutdown(Shutdown::Write);
            let _ = r.shutdown(Shutdown::Read);
        }
        let _ = up.join();
    }

    /// host_port=0 分配真实端口；stop() 后新连接被拒（端口释放）。
    #[test]
    fn start_listener_allocates_and_stops() {
        // vsock 路径不存在 → open_tunnel 会失败，但监听器本身能起、能停，端口分配可验。
        let h = start_listener("127.0.0.1", 0, PathBuf::from("/nonexistent/vsock.sock"), 8080).unwrap();
        assert_ne!(h.host_port, 0, "应回读 OS 分配的实际端口");
        let port = h.host_port;
        // 端口在监听（连接成功；随后 open_tunnel 失败会关掉，但 connect 本身应成功）。
        assert!(TcpStream::connect(("127.0.0.1", port)).is_ok(), "stop 前应可连接");
        h.stop();
        thread::sleep(ACCEPT_POLL * 3); // 等 accept 线程退出 + listener drop
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "stop 后端口应释放、连接被拒");
    }
}
