//! sl-envd — guest 内驻留 agent，作为 PID 1（ADR-18）。
//!
//! M0 职责：
//!   1. 作为 PID 1：挂载 /proc /sys /dev /tmp。
//!   2. 僵尸回收：收割线程独占 wait4(-1)，退出状态入 (pid→status) 表（ADR-18）。
//!   3. vsock 服务：Ping（W2 连通性）+ Exec（W3 同步执行命令，回传 stdout/stderr/退出码）。
//!
//! 铁律：PID 1 绝不退出——退出会触发内核 panic（boot_args 里 panic=1 会重启）。
//! 任何致命错误都记录到串口后进入长眠，把诊断信息留给 host 侧 console.log。

use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::mem;
use std::os::fd::RawFd;
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::{Condvar, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use sl_proto::{read_msg, write_msg, FdStream, Request, Response, ENVD_VSOCK_PORT};

fn log(msg: &str) {
    // 直接写 stderr → 串口 ttyS0（FC console），host 侧 console.log 可见
    let _ = writeln!(std::io::stderr(), "[sl-envd] {msg}");
}

fn main() {
    let pid = unsafe { libc::getpid() };
    log(&format!("starting, pid={pid}"));

    if pid == 1 {
        mount_all();
    } else {
        log("warning: 非 PID 1，跳过挂载（开发/测试运行）");
    }

    spawn_reaper();
    bring_lo_up(); // W10 端口暴露：Connect dial 127.0.0.1:port 需 loopback up

    // 永不返回；若 serve 因致命错误退出，进入长眠而非 exit（PID 1 退出 = 内核 panic）
    if let Err(e) = serve_vsock() {
        log(&format!("fatal: vsock 服务退出: {e}；进入长眠保持 PID 1 存活"));
    }
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

/// PID 1 基础挂载。逐项尝试，失败仅记录不中断——
/// 例如 CONFIG_DEVTMPFS_MOUNT=y 时内核已自动挂 /dev，重复挂载得 EBUSY，属正常。
fn mount_all() {
    mount("proc", "/proc", "proc");
    mount("sysfs", "/sys", "sysfs");
    mount("devtmpfs", "/dev", "devtmpfs");
    mount("tmpfs", "/tmp", "tmpfs");
}

fn mount(source: &str, target: &str, fstype: &str) {
    let src = cstr(source);
    let tgt = cstr(target);
    let fst = cstr(fstype);
    let r = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fst.as_ptr(),
            0,
            ptr::null(),
        )
    };
    if r == 0 {
        log(&format!("mounted {fstype} -> {target}"));
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EBUSY) {
            log(&format!("{target} 已挂载（EBUSY，内核自动挂载），跳过"));
        } else {
            log(&format!("mount {fstype} -> {target} 失败: {err}（继续）"));
        }
    }
}

/// 已回收子进程的退出状态表：收割线程写入，exec 侧按 pid 取。
/// tracked pid（exec 派生）会被 wait_reaped 毫秒级取走；孤儿进程（reparent 到
/// PID1）无人认领，若只增不删会随长寿沙箱无界增长——故 order 记插入序，超 CAP
/// 逐出最旧。CAP 远大于并发 exec 数，正常路径不会误逐 tracked pid（Q2 压测受益）。
struct Reaped {
    inner: Mutex<ReapedInner>,
    cv: Condvar,
}
struct ReapedInner {
    map: HashMap<i32, i32>,
    order: VecDeque<i32>,
}
const REAPED_CAP: usize = 4096;
static REAPED: OnceLock<Reaped> = OnceLock::new();
fn reaped() -> &'static Reaped {
    REAPED.get_or_init(|| Reaped {
        inner: Mutex::new(ReapedInner {
            map: HashMap::new(),
            order: VecDeque::new(),
        }),
        cv: Condvar::new(),
    })
}

/// 僵尸回收线程（ADR-18）：**独占** wait4(-1) 回收全部子进程（含孤儿），
/// 退出状态记入表并唤醒等待方。exec 侧绝不自行 waitpid，避免与本线程抢子进程。
fn spawn_reaper() {
    let _ = reaped(); // 确保表在收割前已初始化
    thread::spawn(|| loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::wait4(-1, &mut status, 0, ptr::null_mut()) };
        if pid > 0 {
            let r = reaped();
            let mut g = r.inner.lock().unwrap();
            if g.map.insert(pid, status).is_none() {
                g.order.push_back(pid);
            }
            // 有界逐出最旧的未认领项，防孤儿状态无界堆积
            while g.order.len() > REAPED_CAP {
                if let Some(old) = g.order.pop_front() {
                    g.map.remove(&old);
                }
            }
            r.cv.notify_all();
        } else {
            // ECHILD（无子进程）或被信号打断：退避，避免忙转
            thread::sleep(Duration::from_millis(50));
        }
    });
}

/// 阻塞等待指定 pid 被收割，返回其 raw wait status（并从表中移除）。
fn wait_reaped(pid: i32) -> i32 {
    let r = reaped();
    let mut g = r.inner.lock().unwrap();
    loop {
        if let Some(status) = g.map.remove(&pid) {
            g.order.retain(|&p| p != pid);
            return status;
        }
        g = r.cv.wait(g).unwrap();
    }
}

/// AF_VSOCK 监听（CID_ANY:ENVD_VSOCK_PORT），逐连接回显帧，直到对端关闭。
fn serve_vsock() -> std::io::Result<()> {
    let listen_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if listen_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_vm = unsafe { mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_port = ENVD_VSOCK_PORT;
    addr.svm_cid = libc::VMADDR_CID_ANY;

    let rc = unsafe {
        libc::bind(
            listen_fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(listen_fd) };
        return Err(e);
    }

    if unsafe { libc::listen(listen_fd, 8) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(listen_fd) };
        return Err(e);
    }

    // 就绪锚点（Q3 分段计时）：记录内核 uptime，host 侧据此拆分 pre-kernel/boot/init 各段
    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(String::from))
        .unwrap_or_else(|| "?".into());
    log(&format!("READY uptime={uptime}s vsock 监听 CID_ANY:{ENVD_VSOCK_PORT}"));

    loop {
        let conn_fd: RawFd = unsafe { libc::accept(listen_fd, ptr::null_mut(), ptr::null_mut()) };
        if conn_fd < 0 {
            log(&format!("accept 失败: {}（继续）", std::io::Error::last_os_error()));
            continue;
        }
        log("host 已连接");
        handle_conn(conn_fd);
        log("连接关闭");
    }
}

/// 单连接：逐条读请求、处理、写响应，直到对端 EOF 或出错。
fn handle_conn(conn_fd: RawFd) {
    let mut stream = FdStream(conn_fd); // Drop 时 close
    loop {
        let req: Request = match read_msg(&mut stream) {
            Ok(r) => r,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => {
                log(&format!("读请求失败: {e}"));
                break;
            }
        };
        // W10 端口暴露：Connect 脱离 req/resp——dial + Ok ack 后本连接转裸字节双向管道，占用至 EOF。
        if let Request::Connect { port } = req {
            handle_connect(conn_fd, &mut stream, port);
            break;
        }
        let resp = dispatch(req);
        if let Err(e) = write_msg(&mut stream, &resp) {
            log(&format!("写响应失败: {e}"));
            break;
        }
    }
}

fn dispatch(req: Request) -> Response {
    match req {
        Request::Ping { data } => Response::Pong { data },
        Request::Exec { cmd } => run_exec(&cmd),
        Request::Reinit { seed_hex, hostname, wall_time_ns } => {
            run_reinit(&seed_hex, &hostname, wall_time_ns)
        }
        // Connect 由 handle_conn 特判（脱离 dispatch 的 req/resp 模型）；到此属逻辑错误。
        Request::Connect { .. } => Response::Error { message: "Connect 应由 handle_conn 处理".into() },
    }
}

/// 带起 loopback（Connect dial 127.0.0.1 需 lo up）。busybox `ip`/`ifconfig` 皆可；失败仅记录。
fn bring_lo_up() {
    let ok = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    log(if ok { "loopback up" } else { "loopback up 失败（端口暴露可能不可用）" });
}

/// W10：dial guest 内 `127.0.0.1:port`，成功回 `Ok` 后把 vsock 连接与 TCP 连接**双向 splice**。
fn handle_connect(vsock_fd: RawFd, stream: &mut FdStream, port: u32) {
    let tcp_fd = match dial_loopback(port) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = write_msg(stream, &Response::Error { message: format!("connect 127.0.0.1:{port} 失败: {e}") });
            return;
        }
    };
    if write_msg(stream, &Response::Ok).is_err() {
        unsafe { libc::close(tcp_fd) };
        return;
    }
    splice_bidi(vsock_fd, tcp_fd);
    unsafe { libc::close(tcp_fd) };
}

/// dial 127.0.0.1:port（短重试，容 guest 服务刚起未 bind）。返回已连 TCP fd。
fn dial_loopback(port: u32) -> std::io::Result<RawFd> {
    let mut last = std::io::Error::new(ErrorKind::Other, "no attempt");
    for _ in 0..20 {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = (port as u16).to_be();
        addr.sin_addr.s_addr = libc::INADDR_LOOPBACK.to_be();
        let r = unsafe {
            libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if r == 0 {
            return Ok(fd);
        }
        last = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
}

/// 双向裸字节 splice：一方 EOF 即 shutdown 两端解阻另一线程，join 收敛。
fn splice_bidi(a: RawFd, b: RawFd) {
    let h = thread::spawn(move || pipe_one(a, b));
    pipe_one(b, a);
    unsafe {
        libc::shutdown(a, libc::SHUT_RDWR);
        libc::shutdown(b, libc::SHUT_RDWR);
    }
    let _ = h.join();
}

fn pipe_one(from: RawFd, to: RawFd) {
    let mut buf = [0u8; 16384];
    loop {
        let n = unsafe { libc::read(from, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        while off < n as usize {
            let w = unsafe { libc::write(to, buf[off..].as_ptr() as *const libc::c_void, n as usize - off) };
            if w <= 0 {
                return;
            }
            off += w as usize;
        }
    }
}

/// ADR-12 恢复后 reinit（W4）：换发克隆身份 + 校时钟。host 在 resume 后、用户代码前下发一次。
///
/// 顺序有讲究——**先取 rng 样本再混种子**：rng_hex 专门检验内核 vmgenid reseed 是否已让
/// 两克隆的 CRNG 分叉（Q3 最强证据，不被 host 种子污染）；随后混入 host 每恢复唯一种子作
/// 安全带，再换发 machine-id/会话密钥（保证分叉，即便内核 vmgenid 时序不理想）。
fn run_reinit(seed_hex: &str, hostname: &str, wall_time_ns: u64) -> Response {
    log(&format!("reinit: hostname={hostname} wall_time_ns={wall_time_ns}"));

    // ① 混种子之前取样：验内核 vmgenid reseed（快照 restore 时内核自动 reseed CRNG）。
    let mut rng_sample = [0u8; 32];
    getrandom(&mut rng_sample);
    let rng_hex = hex(&rng_sample);

    // ② 混 host 种子进 /dev/urandom（安全带：身份分叉不单赖 vmgenid 时序）。best-effort。
    if let Some(seed) = unhex(seed_hex) {
        match std::fs::OpenOptions::new().write(true).open("/dev/urandom") {
            Ok(mut f) => {
                if let Err(e) = f.write_all(&seed) {
                    log(&format!("reinit: 写 /dev/urandom 失败: {e}（继续）"));
                }
            }
            Err(e) => log(&format!("reinit: 打开 /dev/urandom 失败: {e}（继续）")),
        }
    } else {
        log("reinit: seed_hex 非法 hex，跳过种子混入（继续）");
    }

    // ③ 换发 machine-id（16B → 32 hex），reseed+种子之后取，保证克隆分叉。
    let mut mid_bytes = [0u8; 16];
    getrandom(&mut mid_bytes);
    let machine_id = hex(&mid_bytes);
    if let Err(e) = std::fs::write("/etc/machine-id", format!("{machine_id}\n")) {
        log(&format!("reinit: 写 /etc/machine-id 失败: {e}（继续）"));
    }

    // ④ 换发主机名：sethostname + 覆写 /etc/hostname。
    let hn = cstr(hostname);
    let rc = unsafe { libc::sethostname(hn.as_ptr(), hostname.len()) };
    if rc != 0 {
        log(&format!("reinit: sethostname 失败: {}（继续）", std::io::Error::last_os_error()));
    }
    if let Err(e) = std::fs::write("/etc/hostname", format!("{hostname}\n")) {
        log(&format!("reinit: 写 /etc/hostname 失败: {e}（继续）"));
    }

    // ⑤ 换发会话密钥（32B → 64 hex），0600。
    let mut sk_bytes = [0u8; 32];
    getrandom(&mut sk_bytes);
    let session_key_hex = hex(&sk_bytes);
    write_private("/etc/sl-session-key", &format!("{session_key_hex}\n"));

    // ⑥ 校正墙钟：快照冻结了 CLOCK_REALTIME，用 host 现刻回填（best-effort）。
    // as _：由 timeval 字段推断类型，避免直接命名 musl 已弃用的 time_t/suseconds_t 别名
    let tv = libc::timeval {
        tv_sec: (wall_time_ns / 1_000_000_000) as _,
        tv_usec: ((wall_time_ns % 1_000_000_000) / 1_000) as _,
    };
    let rc = unsafe { libc::settimeofday(&tv, ptr::null()) };
    if rc != 0 {
        log(&format!("reinit: settimeofday 失败: {}（继续）", std::io::Error::last_os_error()));
    }

    log(&format!("reinit done: machine_id={machine_id}"));
    Response::Reinit { machine_id, rng_hex, session_key_hex }
}

/// 填满 buf（getrandom；短读重试）。CRNG 恢复后已初始化，不阻塞。
fn getrandom(buf: &mut [u8]) {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe {
            libc::getrandom(buf[off..].as_mut_ptr() as *mut libc::c_void, buf.len() - off, 0)
        };
        if n <= 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            log(&format!("getrandom 失败: {e}（用已填充字节，可能全零）"));
            break;
        }
        off += n as usize;
    }
}

/// 小写 hex 编码。
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 解析小写/大写 hex；奇数长度或非 hex 字符返回 None。
fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// 写文件并置 0600（会话密钥用）。best-effort，失败仅记录。
fn write_private(path: &str, content: &str) {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(content.as_bytes()) {
                log(&format!("reinit: 写 {path} 失败: {e}（继续）"));
            }
        }
        Err(e) => log(&format!("reinit: 打开 {path} 失败: {e}（继续）")),
    }
}

/// 读 `/etc/sl-envd/env`（ADR-18 构建期物化：`# 注释` / `KEY=VALUE` / `SL_WORKDIR` / `SL_USER`），
/// 施加到子进程：`KEY=VALUE` → 环境变量（尤其镜像 PATH，node/python 才找得到）；`SL_WORKDIR` → cwd
/// （目录存在才 cd，避免 workdir 尚未建时 spawn 失败）；`SL_USER` 暂忽略（切用户需 setuid/gid，留后续）。
/// 按首个 `=` 切分、值原样取用（与 build.rs write_build_env 对齐）。缺文件即 no-op（非 OCI 基座向后兼容）。
fn apply_env_file(cmd: &mut Command) {
    let text = match std::fs::read_to_string("/etc/sl-envd/env") {
        Ok(t) => t,
        Err(_) => return,
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        match k {
            "SL_WORKDIR" => {
                if !v.is_empty() && std::path::Path::new(v).is_dir() {
                    cmd.current_dir(v);
                }
            }
            "SL_USER" => {} // 切用户暂不实现（需 setuid/gid）
            _ => {
                cmd.env(k, v);
            }
        }
    }
}

/// 同步执行 `/bin/sh -c cmd`：管道捕获 stdout/stderr（并发读防管道填满死锁），
/// 经收割表拿退出状态（不自行 waitpid，避免与收割线程抢）。
fn run_exec(cmd: &str) -> Response {
    log(&format!("exec: {cmd}"));
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // ADR-18：施加构建期物化的镜像环境（/etc/sl-envd/env）——PATH/WORKDIR 等对**所有** exec 生效
    // （构建 RUN + 运行时 sandlocker run/exec）。缺文件即 no-op（向后兼容非 OCI 基座）。
    apply_env_file(&mut command);
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Response::Error {
                message: format!("spawn /bin/sh 失败: {e}（rootfs 缺 /bin/sh？）"),
            }
        }
    };

    let pid = child.id() as i32;
    let mut out = child.stdout.take().expect("stdout piped");
    let mut err = child.stderr.take().expect("stderr piped");

    // stderr 用独立线程排空，避免与 stdout 互相阻塞（任一管道填满都会卡住子进程）
    let err_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err.read_to_end(&mut buf);
        buf
    });
    let mut out_buf = Vec::new();
    let _ = out.read_to_end(&mut out_buf);
    let err_buf = err_handle.join().unwrap_or_default();

    // 收割线程会回收该 pid；此处仅等状态，绝不调用 child.wait()（std Child::drop 不收割，安全）
    let status = wait_reaped(pid);
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    };

    Response::Exec {
        exit_code,
        stdout: String::from_utf8_lossy(&out_buf).into_owned(),
        stderr: String::from_utf8_lossy(&err_buf).into_owned(),
    }
}

/// 构造以 NUL 结尾的 C 字符串字节（避免拉入 std::ffi 的额外样板）。
fn cstr(s: &str) -> Vec<i8> {
    let mut v: Vec<i8> = s.bytes().map(|b| b as i8).collect();
    v.push(0);
    v
}
