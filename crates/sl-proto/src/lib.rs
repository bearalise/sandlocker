//! sl-proto — host↔guest vsock 线路协议（ADR-4）
//!
//! M0 帧格式最小化：`u32 大端长度前缀 + 载荷字节`。
//! 载荷语义 W2 仅为回显（不解释内容）；W3 exec 落地时在此之上定 JSON 契约，
//! M1 再评估切 protobuf（ADR-4：先 JSON，M1 定契约）。
//!
//! 帧编解码基于 `std::io::{Read, Write}`，host 侧可直接用于 `UnixStream`，
//! guest 侧用 [`FdStream`] 包裹裸 vsock fd。

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::os::fd::RawFd;

/// guest 内 sl-envd 监听的 vsock 端口。
pub const ENVD_VSOCK_PORT: u32 = 1024;

/// host→guest 请求（W3 起启用 JSON 契约，ADR-4；M1 再评估切 protobuf）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// W2 连通性自检：原样回显 data。
    Ping { data: String },
    /// W3 同步执行：经 `/bin/sh -c cmd` 运行，阻塞到结束回传全部输出。
    Exec { cmd: String },
    /// W4 ADR-12：恢复后重置克隆身份。host 在 resume 之后、用户代码之前下发一次。
    /// 快照被同一模板反复 restore，若不换发则所有克隆共享身份/熵——安全红线。
    ///   seed_hex：host 生成的每恢复唯一 32B 熵（hex），guest 混入 /dev/urandom，
    ///             使身份分叉不单赖内核 vmgenid reseed 的时序（安全带）。
    ///   hostname：该实例唯一主机名。
    ///   wall_time_ns：host 当前 UNIX 纪元纳秒，校正快照冻结的 CLOCK_REALTIME。
    Reinit { seed_hex: String, hostname: String, wall_time_ns: u64 },
    /// W10（FR-3.3 端口暴露）：guest 内 dial `127.0.0.1:port`。成功回 [`Response::Ok`] 后，**此连接转为
    /// 裸字节双向管道**（不再走帧）——host 网关据此把外部流量中继进 VM 内服务。
    Connect { port: u32 },
    /// W11（M2-Q7 交互式 PTY）：guest `forkpty` 起 shell（初始窗口 cols×rows）。回 [`Response::Ok`] 后：
    /// **host→guest** 走 PTY 输入帧（[`pty_stdin_frame`]/[`pty_resize_frame`]）；**guest→host** 为裸 PTY 输出。
    Pty { cols: u16, rows: u16 },
}

/// PTY 输入帧种类（host→guest，装进 [`write_frame`] 的 payload 首字节）。
pub const PTY_KIND_STDIN: u8 = 0;
pub const PTY_KIND_RESIZE: u8 = 1;

/// host 编码：一段 stdin 键入字节 → PTY 输入帧（payload = [0] ++ data）。
pub fn pty_stdin_frame(data: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(1 + data.len());
    p.push(PTY_KIND_STDIN);
    p.extend_from_slice(data);
    p
}

/// host 编码：窗口 resize → PTY 输入帧（payload = [1, cols_be(2), rows_be(2)]）。
pub fn pty_resize_frame(cols: u16, rows: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(5);
    p.push(PTY_KIND_RESIZE);
    p.extend_from_slice(&cols.to_be_bytes());
    p.extend_from_slice(&rows.to_be_bytes());
    p
}

/// guest 解析：一个 PTY 输入帧 payload → 语义。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtyInput {
    Stdin(Vec<u8>),
    Resize { cols: u16, rows: u16 },
}

/// guest 解析 PTY 输入帧 payload（`read_frame` 得到的字节）；格式非法返回 None。
pub fn parse_pty_input(payload: &[u8]) -> Option<PtyInput> {
    match payload.first().copied()? {
        PTY_KIND_STDIN => Some(PtyInput::Stdin(payload[1..].to_vec())),
        PTY_KIND_RESIZE if payload.len() == 5 => Some(PtyInput::Resize {
            cols: u16::from_be_bytes([payload[1], payload[2]]),
            rows: u16::from_be_bytes([payload[3], payload[4]]),
        }),
        _ => None,
    }
}

/// guest→host 响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Pong { data: String },
    /// exit_code：正常退出为进程退出码；被信号终止为 128+signo（shell 约定）。
    /// stdout/stderr 为 UTF-8 有损转换（M0 契约；二进制精确传输留 M1）。
    Exec {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    /// W4：reinit 结果 + 供 host 做克隆熵回归比对的取样（Q3：两实例三项必不同）。
    ///   machine_id：新写入 /etc/machine-id。
    ///   rng_hex：混种子**之前**从 getrandom 取的样本 hex（专验内核 vmgenid reseed 已使克隆分叉）。
    ///   session_key_hex：新会话密钥 hex。
    Reinit { machine_id: String, rng_hex: String, session_key_hex: String },
    /// 请求无法执行（如 spawn 失败）。
    Error { message: String },
    /// W10：通用成功 ack（[`Request::Connect`] dial 成功后回此，随后连接转裸字节管道）。
    Ok,
}

/// 写一条消息 = JSON 序列化后装帧。
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(w, &bytes)
}

/// 读一条消息 = 收帧后 JSON 反序列化。
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let bytes = read_frame(r)?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// 单帧载荷上限（防御性，避免恶意长度前缀导致大额分配）。
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// 写一帧：`u32 大端长度 + 载荷`。
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() as u64 > MAX_FRAME as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// 读一帧；EOF 在读长度前缀时表现为 `UnexpectedEof`（调用方据此判连接关闭）。
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// 裸 fd 之上的 `Read + Write`（guest 侧 vsock accept fd 用；host 侧用 std `UnixStream`）。
/// 不拥有 fd 的关闭责任由调用方决定；`Drop` 主动 `close` 避免泄漏。
pub struct FdStream(pub RawFd);

impl Read for FdStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

impl Write for FdStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.0, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for FdStream {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello vsock").unwrap();
        let mut cur = Cursor::new(buf);
        assert_eq!(read_frame(&mut cur).unwrap(), b"hello vsock");
    }

    #[test]
    fn empty_frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"").unwrap();
        let mut cur = Cursor::new(buf);
        assert_eq!(read_frame(&mut cur).unwrap(), b"");
    }

    #[test]
    fn eof_before_len_is_error() {
        let mut cur = Cursor::new(Vec::new());
        assert!(read_frame(&mut cur).is_err());
    }

    #[test]
    fn msg_roundtrip() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &Request::Exec { cmd: "echo hi".into() }).unwrap();
        let mut cur = Cursor::new(buf);
        match read_msg::<_, Request>(&mut cur).unwrap() {
            Request::Exec { cmd } => assert_eq!(cmd, "echo hi"),
            other => panic!("解析错误: {other:?}"),
        }
    }

    #[test]
    fn reinit_request_roundtrip() {
        let mut buf = Vec::new();
        let req = Request::Reinit {
            seed_hex: "deadbeef".into(),
            hostname: "sandlocker-abcd1234".into(),
            wall_time_ns: 1_722_800_000_000_000_000,
        };
        write_msg(&mut buf, &req).unwrap();
        let mut cur = Cursor::new(buf);
        match read_msg::<_, Request>(&mut cur).unwrap() {
            Request::Reinit { seed_hex, hostname, wall_time_ns } => {
                assert_eq!(seed_hex, "deadbeef");
                assert_eq!(hostname, "sandlocker-abcd1234");
                assert_eq!(wall_time_ns, 1_722_800_000_000_000_000);
            }
            other => panic!("解析错误: {other:?}"),
        }
    }

    #[test]
    fn reinit_response_roundtrip() {
        let mut buf = Vec::new();
        let resp = Response::Reinit {
            machine_id: "0123456789abcdef0123456789abcdef".into(),
            rng_hex: "aa".into(),
            session_key_hex: "bb".into(),
        };
        write_msg(&mut buf, &resp).unwrap();
        let mut cur = Cursor::new(buf);
        match read_msg::<_, Response>(&mut cur).unwrap() {
            Response::Reinit { machine_id, rng_hex, session_key_hex } => {
                assert_eq!(machine_id, "0123456789abcdef0123456789abcdef");
                assert_eq!(rng_hex, "aa");
                assert_eq!(session_key_hex, "bb");
            }
            other => panic!("解析错误: {other:?}"),
        }
    }

    #[test]
    fn response_exec_roundtrip() {
        let mut buf = Vec::new();
        let resp = Response::Exec { exit_code: 7, stdout: "out".into(), stderr: "err".into() };
        write_msg(&mut buf, &resp).unwrap();
        let mut cur = Cursor::new(buf);
        match read_msg::<_, Response>(&mut cur).unwrap() {
            Response::Exec { exit_code, stdout, stderr } => {
                assert_eq!(exit_code, 7);
                assert_eq!(stdout, "out");
                assert_eq!(stderr, "err");
            }
            other => panic!("解析错误: {other:?}"),
        }
    }

    #[test]
    fn pty_input_frames_roundtrip() {
        // stdin 帧：payload[0]=0，其余为数据
        let f = pty_stdin_frame(b"echo hi\n");
        assert_eq!(f[0], PTY_KIND_STDIN);
        assert_eq!(parse_pty_input(&f), Some(PtyInput::Stdin(b"echo hi\n".to_vec())));
        // resize 帧：cols/rows 大端
        let r = pty_resize_frame(120, 40);
        assert_eq!(parse_pty_input(&r), Some(PtyInput::Resize { cols: 120, rows: 40 }));
        // 非法
        assert_eq!(parse_pty_input(&[]), None);
        assert_eq!(parse_pty_input(&[PTY_KIND_RESIZE, 1, 2]), None);
    }

    #[test]
    fn pty_request_roundtrip() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &Request::Pty { cols: 80, rows: 24 }).unwrap();
        let mut cur = Cursor::new(buf);
        match read_msg::<_, Request>(&mut cur).unwrap() {
            Request::Pty { cols, rows } => {
                assert_eq!((cols, rows), (80, 24));
            }
            other => panic!("解析错误: {other:?}"),
        }
    }
}
