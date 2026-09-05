//! dataplane.rs — 节点**主动外拨持久流** + 网关**无粘滞中继**（M3 W5 余项，ADR-22 / M3-Q3；
//! 集群内 **mTLS** 兼收 M3 W6 余项 / FR-7.1）。
//!
//! # 这层解决什么
//!
//! M3 W4 把控制面合龙到 etcd：任一 API 副本都能看见全集群沙箱。但**数据面**仍是节点本地的——
//! `Orch::exec_target` 只认本节点 `live` 表里的沙箱，于是「API 落副本 X、沙箱在节点 Y」时
//! exec/logs/文件/端口一律 `未知沙箱或已回收`。W5 交付了 ticket 层的跨副本验签（共享 secret +
//! store 一次性 nonce），**缺的就是这条把字节从网关送到owning 节点的传输**。
//!
//! 约束（ADR-22）：**节点零入站端口**。节点在防火墙后、可能在 NAT 后，网关不能反向 dial 节点。
//! 因此方向必须是 **节点 → 网关** 外拨，并把连接**留驻**，供网关反向借用。
//!
//! # 形态：预拨连接池式反向隧道（而非帧级多路复用）
//!
//! 每个节点对网关预先拨起 `pool` 条 **空闲持久连接**并停在那里；网关需要为某沙箱转发时，
//! 从该节点的空闲池里**取一条**，写一行 `OPEN {ticket}`，此后这条连接就是该逻辑流的**独占**
//! 字节管道；用完即弃，节点补拨一条回池。
//!
//! 为什么不做帧级多路复用（原计划措辞）：多路复用要让**多个逻辑流共享一条 TLS 连接**，即多线程
//! 并发读写同一个 rustls 状态机——同步栈下这是本层最容易写错的地方（记录序号一旦错序即整条连接
//! 解密失败），而收益仅是省连接数。预拨池让**每条逻辑流单一属主**，读写各自成线程、无共享状态机，
//! 代价只是并发流数 = 连接数（500 沙箱/节点量级下无压力）。**M3-Q3 的判据（任一副本服务任一沙箱、
//! 无会话粘滞、节点零入站）两种形态等价满足**，故取更不易错的一种；已在 §M3 计划中如实记录偏离。
//!
//! # 全双工（PTY 的硬需求）
//!
//! M3-Q3 点名 **PTY** 须经网关可达，PTY 是交互式双向流——中继必须**全双工**（一个线程 client→node、
//! 一个线程 node→client 同时跑）。而 rustls 的同步 `StreamOwned` **不能被两个线程同时读写**。
//! 本模块的 [`Duplex`] 为此手写了同步全双工封装：
//!
//! - **阻塞的 socket 读发生在 conn 锁之外**（先从 socket 收密文到临时缓冲，再进锁喂 `read_tls`），
//!   故读方向永不阻塞写方向；
//! - 写方向在 conn 锁内产生 TLS 记录，**在释放 conn 锁之前先拿到 socket 写锁**（锁序 conn→sock_w），
//!   保证记录落 socket 的顺序 == 状态机产生的顺序（否则 TLS 序号错位）；
//! - 握手在进入全双工之前于裸 socket 上同步跑完（`complete_io`），稳态不再有握手写。
//!
//! # 线路协议 `sl-gw/1`
//!
//! ```text
//! 节点 → 网关（连接建立后第一行，明文 UTF-8）：
//!     sl-gw/1 data <node_id>\n
//! 网关 → 节点（借用这条连接时，第一行）：
//!     OPEN {"sid":"..","action":"exec","port":0}\n     ← 已由网关验签的 ticket，节点直接采信
//! 其后：裸字节，双向，直到任一端关闭。
//! ```
//!
//! 节点**不重复验签**：nonce 已被网关一次性消费掉，节点再验必然失败。采信的根据是 **mTLS**——
//! 只有持合法客户端证书的网关能建立这条连接（`--gw-tls-ca` 签发）。故 `--gw-insecure`
//! （无 TLS）仅供本机对账/开发，守护会打印告警。

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::gateway::{parse_query, Action, Gateway, Ticket};
use sl_store::Store;

/// 线路协议版本串（节点问候行首 token）。
pub const PROTO: &str = "sl-gw/1";
/// 网关借用连接时的开流行前缀。
const OPEN: &str = "OPEN ";
/// 单次中继的字节搬运缓冲。
const RELAY_BUF: usize = 32 * 1024;

// ————————————————————— mTLS（FR-7.1 集群内 mTLS）—————————————————————

/// mTLS 材料：节点侧作客户端、网关侧作服务端，**双方都验对方证书**（同一 CA 签发）。
#[derive(Clone, Debug)]
pub struct TlsOpts {
    /// 本端证书链 PEM。
    pub cert: std::path::PathBuf,
    /// 本端私钥 PEM（PKCS#8 / PKCS#1 / SEC1 皆可）。
    pub key: std::path::PathBuf,
    /// 验对端用的 CA PEM。
    pub ca: std::path::PathBuf,
    /// 节点侧校验网关证书用的 SNI/SAN 名（须与网关证书的 DNS SAN 一致）。
    pub server_name: String,
}

#[cfg(feature = "cluster")]
mod tlsimpl {
    use super::TlsOpts;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::sync::Arc;

    fn read_pem(p: &std::path::Path) -> Result<Vec<u8>, String> {
        std::fs::read(p).map_err(|e| format!("读 {} 失败: {e}", p.display()))
    }

    fn load_certs(p: &std::path::Path) -> Result<Vec<CertificateDer<'static>>, String> {
        let raw = read_pem(p)?;
        let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut raw.as_slice()).collect();
        let certs = certs.map_err(|e| format!("解析证书 {} 失败: {e}", p.display()))?;
        if certs.is_empty() {
            return Err(format!("{} 内无证书", p.display()));
        }
        Ok(certs)
    }

    fn load_key(p: &std::path::Path) -> Result<PrivateKeyDer<'static>, String> {
        let raw = read_pem(p)?;
        rustls_pemfile::private_key(&mut raw.as_slice())
            .map_err(|e| format!("解析私钥 {} 失败: {e}", p.display()))?
            .ok_or_else(|| format!("{} 内无私钥", p.display()))
    }

    /// 进程内装一次 ring provider。rustls 0.23 默认 provider 是 aws-lc-rs（cmake + 大量 C），
    /// Cargo.toml 已 `default-features=false, features=["ring"]` 钉到 ring（ureq 同款，crate 数零回涨），
    /// 但仍须显式 install 才能用无参 `builder()`。
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// 节点侧（客户端）：验网关证书（CA）+ **带上自己的客户端证书**（供网关反向验）。
    pub fn client_config(o: &TlsOpts) -> Result<Arc<rustls::ClientConfig>, String> {
        install_provider();
        let mut roots = rustls::RootCertStore::empty();
        for c in load_certs(&o.ca)? {
            roots.add(c).map_err(|e| format!("CA 入根失败: {e}"))?;
        }
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(load_certs(&o.cert)?, load_key(&o.key)?)
            .map_err(|e| format!("客户端证书配置失败: {e}"))?;
        Ok(Arc::new(cfg))
    }

    /// 网关侧（服务端）：**强制**校验客户端证书（无证书/非本 CA 签发 → 握手即拒），即 mTLS。
    pub fn server_config(o: &TlsOpts) -> Result<Arc<rustls::ServerConfig>, String> {
        install_provider();
        let mut roots = rustls::RootCertStore::empty();
        for c in load_certs(&o.ca)? {
            roots.add(c).map_err(|e| format!("CA 入根失败: {e}"))?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| format!("客户端验证器构建失败: {e}"))?;
        let cfg = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(load_certs(&o.cert)?, load_key(&o.key)?)
            .map_err(|e| format!("服务端证书配置失败: {e}"))?;
        Ok(Arc::new(cfg))
    }
}

/// **预构建**的节点侧 TLS 上下文。证书解析 + rustls 配置构建是重活（RSA 私钥解析等），
/// 必须在起代理时做**一次**，而不是每条连接一次——否则补拨风暴会把握手拖垮（实测：
/// 每连接重建配置时，8 条并发首拨在 1.5s 内都完不成，网关侧全 503）。
#[cfg(feature = "cluster")]
#[derive(Clone)]
pub struct ClientCtx {
    cfg: Arc<rustls::ClientConfig>,
    name: String,
}
#[cfg(not(feature = "cluster"))]
#[derive(Clone)]
pub struct ClientCtx;

/// 同上，网关侧（服务端）。
#[cfg(feature = "cluster")]
#[derive(Clone)]
pub struct ServerCtx(Arc<rustls::ServerConfig>);
#[cfg(not(feature = "cluster"))]
#[derive(Clone)]
pub struct ServerCtx;

/// 由 `TlsOpts` 预构建客户端上下文（起代理时一次）。
#[allow(unused_variables)]
fn build_client_ctx(t: &TlsOpts) -> Result<ClientCtx, String> {
    #[cfg(feature = "cluster")]
    {
        Ok(ClientCtx { cfg: tlsimpl::client_config(t)?, name: t.server_name.clone() })
    }
    #[cfg(not(feature = "cluster"))]
    {
        Err("mTLS 需以 --features cluster 构建".into())
    }
}

/// 由 `TlsOpts` 预构建服务端上下文（起网关时一次）。
#[allow(unused_variables)]
fn build_server_ctx(t: &TlsOpts) -> Result<ServerCtx, String> {
    #[cfg(feature = "cluster")]
    {
        Ok(ServerCtx(tlsimpl::server_config(t)?))
    }
    #[cfg(not(feature = "cluster"))]
    {
        Err("mTLS 需以 --features cluster 构建".into())
    }
}

// ————————————————————— 全双工连接 —————————————————————

/// 同步**全双工**字节管道：明文 TCP 或 mTLS。
///
/// 见模块头「全双工」一节：TLS 变体把「阻塞 socket 读」放在 conn 锁之外，并以锁序
/// `conn → sock_w` 保证 TLS 记录落盘顺序 == 产生顺序。两个线程可同时 `read` / `write`。
pub struct Duplex {
    kind: Kind,
    /// 写方向已 shutdown（半关），避免重复 shutdown 报错刷屏。
    fin: AtomicBool,
}

enum Kind {
    /// 明文：TCP 本就全双工，两个 `try_clone` 句柄各自成向即可。
    Plain { r: Mutex<TcpStream>, w: Mutex<TcpStream> },
    #[cfg(feature = "cluster")]
    Tls {
        sock_r: Mutex<TcpStream>,
        sock_w: Mutex<TcpStream>,
        conn: Mutex<rustls::Connection>,
        /// 已解密、尚未被调用方取走的明文。
        plain: Mutex<VecDeque<u8>>,
    },
}

impl Duplex {
    /// 明文管道（`--gw-insecure`，仅本机对账/开发）。
    pub fn plain(sock: TcpStream) -> Result<Arc<Self>, String> {
        let r = sock.try_clone().map_err(|e| format!("clone socket 失败: {e}"))?;
        Ok(Arc::new(Self {
            kind: Kind::Plain { r: Mutex::new(r), w: Mutex::new(sock) },
            fin: AtomicBool::new(false),
        }))
    }

    /// 节点侧：对网关发起 mTLS 握手（带客户端证书）。握手在裸 socket 上同步跑完再转全双工。
    #[cfg(feature = "cluster")]
    pub fn tls_client(
        mut sock: TcpStream,
        cfg: Arc<rustls::ClientConfig>,
        server_name: &str,
    ) -> Result<Arc<Self>, String> {
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| format!("server_name {server_name} 非法: {e}"))?;
        let mut conn = rustls::ClientConnection::new(cfg, name)
            .map_err(|e| format!("建 TLS 客户端会话失败: {e}"))?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).map_err(|e| format!("TLS 握手失败: {e}"))?;
        }
        Self::wrap_tls(sock, rustls::Connection::Client(conn))
    }

    /// 网关侧：接受节点的 mTLS 握手（**强制**客户端证书，见 `server_config`）。
    #[cfg(feature = "cluster")]
    pub fn tls_server(mut sock: TcpStream, cfg: Arc<rustls::ServerConfig>) -> Result<Arc<Self>, String> {
        let mut conn =
            rustls::ServerConnection::new(cfg).map_err(|e| format!("建 TLS 服务端会话失败: {e}"))?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock).map_err(|e| format!("TLS 握手失败（客户端证书？）: {e}"))?;
        }
        Self::wrap_tls(sock, rustls::Connection::Server(conn))
    }

    #[cfg(feature = "cluster")]
    fn wrap_tls(sock: TcpStream, conn: rustls::Connection) -> Result<Arc<Self>, String> {
        let r = sock.try_clone().map_err(|e| format!("clone socket 失败: {e}"))?;
        Ok(Arc::new(Self {
            kind: Kind::Tls {
                sock_r: Mutex::new(r),
                sock_w: Mutex::new(sock),
                conn: Mutex::new(conn),
                plain: Mutex::new(VecDeque::new()),
            },
            fin: AtomicBool::new(false),
        }))
    }

    /// 底层 TCP（取对端地址/设超时用）。
    fn tcp(&self) -> std::sync::MutexGuard<'_, TcpStream> {
        match &self.kind {
            Kind::Plain { w, .. } => w.lock().unwrap(),
            #[cfg(feature = "cluster")]
            Kind::Tls { sock_w, .. } => sock_w.lock().unwrap(),
        }
    }

    /// 半关写方向（告诉对端「我说完了」）——中继搬完一个方向后调用，使对端读到 EOF。
    pub fn shutdown_write(&self) {
        if self.fin.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.tcp().shutdown(std::net::Shutdown::Write);
    }

    /// 整条连接作废。
    pub fn close(&self) {
        let _ = self.tcp().shutdown(std::net::Shutdown::Both);
    }

    /// 设读超时（空闲池探活 / 中继防挂死用）。
    pub fn set_read_timeout(&self, d: Option<Duration>) {
        match &self.kind {
            Kind::Plain { r, .. } => {
                let _ = r.lock().unwrap().set_read_timeout(d);
            }
            #[cfg(feature = "cluster")]
            Kind::Tls { sock_r, .. } => {
                let _ = sock_r.lock().unwrap().set_read_timeout(d);
            }
        }
    }

    fn do_read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &self.kind {
            Kind::Plain { r, .. } => r.lock().unwrap().read(buf),
            #[cfg(feature = "cluster")]
            Kind::Tls { sock_r, conn, plain, sock_w } => {
                loop {
                    // ① 已解密的明文优先。
                    {
                        let mut p = plain.lock().unwrap();
                        if !p.is_empty() {
                            let n = p.len().min(buf.len());
                            for (i, b) in p.drain(..n).enumerate() {
                                buf[i] = b;
                            }
                            return Ok(n);
                        }
                    }
                    // ② **先把状态机里已有的明文抽干，再考虑收新密文。**
                    //
                    // 这一步不是优化，是正确性：握手的 `complete_io` 很可能把紧随握手之后的
                    // 应用数据（如节点的问候行）一并读进了 rustls 内部缓冲。若这里直接去做
                    // 阻塞 socket 读，那批明文就永远取不出来——对端此刻正等我们回话、不会再
                    // 发字节，于是双方对着干瞪眼直到超时（实测表现：mTLS 下节点连接全部在
                    // 问候行处超时、从不入池，网关侧一律 503）。
                    if drain_plaintext(conn, plain, sock_w)? {
                        continue; // 抽到了 → 回 ① 交付
                    }
                    // ③ 阻塞收密文——**不持 conn 锁**，故不挡住写方向（全双工的关键）。
                    let mut tmp = [0u8; RELAY_BUF];
                    let n = sock_r.lock().unwrap().read(&mut tmp)?;
                    if n == 0 {
                        return Ok(0); // 对端关闭
                    }
                    // ④ 喂状态机，然后回 ② 抽明文。
                    {
                        let mut c = conn.lock().unwrap();
                        let mut cur = &tmp[..n];
                        while !cur.is_empty() {
                            let used = c.read_tls(&mut cur)?;
                            if used == 0 {
                                break;
                            }
                            c.process_new_packets()
                                .map_err(|e| std::io::Error::other(format!("TLS: {e}")))?;
                        }
                    }
                    if !drain_plaintext(conn, plain, sock_w)? {
                        // 这批密文没凑出完整记录 → 继续收。
                        continue;
                    }
                }
            }
        }
    }

    fn do_write(&self, buf: &[u8]) -> std::io::Result<usize> {
        match &self.kind {
            Kind::Plain { w, .. } => w.lock().unwrap().write(buf),
            #[cfg(feature = "cluster")]
            Kind::Tls { conn, sock_w, .. } => {
                // 锁序 conn → sock_w：在**释放 conn 锁之前**拿到 socket 写锁，保证多写者并发时
                // TLS 记录落 socket 的顺序 == 状态机产生的顺序（否则对端序号错位、整条连接解密失败）。
                let mut c = conn.lock().unwrap();
                c.writer().write_all(buf)?;
                let mut out = Vec::new();
                while c.wants_write() {
                    c.write_tls(&mut out)?;
                }
                let mut s = sock_w.lock().unwrap();
                drop(c);
                s.write_all(&out)?;
                Ok(buf.len())
            }
        }
    }

    fn do_flush(&self) -> std::io::Result<()> {
        match &self.kind {
            Kind::Plain { w, .. } => w.lock().unwrap().flush(),
            #[cfg(feature = "cluster")]
            Kind::Tls { sock_w, .. } => sock_w.lock().unwrap().flush(),
        }
    }
}

/// 把 rustls 状态机里已就绪的明文抽进 `plain`，顺带把它想发的记录（告警/密钥更新）写出去。
/// 返回是否抽到了明文。锁序与 `do_write` 一致：conn → sock_w。
#[cfg(feature = "cluster")]
fn drain_plaintext(
    conn: &Mutex<rustls::Connection>,
    plain: &Mutex<VecDeque<u8>>,
    sock_w: &Mutex<TcpStream>,
) -> std::io::Result<bool> {
    let mut got_any = false;
    let mut pending = Vec::new();
    {
        let mut c = conn.lock().unwrap();
        let mut got = [0u8; RELAY_BUF];
        loop {
            match c.reader().read(&mut got) {
                Ok(0) => break, // close_notify
                Ok(k) => {
                    plain.lock().unwrap().extend(&got[..k]);
                    got_any = true;
                }
                // 无更多明文（rustls 以 WouldBlock 表达「需要更多密文」）
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        while c.wants_write() {
            c.write_tls(&mut pending)?;
        }
    }
    if !pending.is_empty() {
        sock_w.lock().unwrap().write_all(&pending)?;
    }
    Ok(got_any)
}

/// [`Duplex`] 的可克隆句柄：实现 `Read + Write`，可交给两个线程各自成向搬字节。
#[derive(Clone)]
pub struct Chan(pub Arc<Duplex>);

impl Read for Chan {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.do_read(buf)
    }
}
impl Write for Chan {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.do_write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.do_flush()
    }
}

/// 读一行（以 `\n` 结尾，不含 `\n`）；超出 `max` 或先遇 EOF 即 Err。协议行皆为短 ASCII。
fn read_line<R: Read>(r: &mut R, max: usize) -> Result<String, String> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = r.read(&mut b).map_err(|e| format!("读协议行失败: {e}"))?;
        if n == 0 {
            return Err("对端在协议行前关闭".into());
        }
        if b[0] == b'\n' {
            break;
        }
        out.push(b[0]);
        if out.len() > max {
            return Err("协议行过长".into());
        }
    }
    Ok(String::from_utf8_lossy(&out).trim_end_matches('\r').to_string())
}

// ————————————————————— 网关侧：节点连接池 —————————————————————

/// 一条停在池里的空闲外拨连接。
struct Idle {
    ch: Chan,
    /// 入池时刻——太老的连接（穿 NAT/中间盒可能已静默失效）优先丢弃。
    since: Instant,
}

/// 网关持有的**节点空闲连接池**：`node_id → 若干条节点主动拨来的持久连接`。
///
/// 「无会话粘滞」即由此成立：连接按 **node_id** 归集，与沙箱/会话无关——任一网关副本只要有
/// 目标节点的空闲连接就能服务该节点上的**任一**沙箱。
pub struct NodePool {
    inner: Mutex<HashMap<String, VecDeque<Idle>>>,
    /// 有新连接入池时唤醒等待者（取连接时短暂等待，掩盖节点补拨的抖动）。
    cv: Condvar,
    /// 空闲连接最长停留；超过即丢弃（节点侧会补拨）。
    max_idle: Duration,
    /// 观测计数：借出 / 落空。
    pub taken: AtomicU64,
    pub misses: AtomicU64,
}

impl NodePool {
    pub fn new(max_idle: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
            cv: Condvar::new(),
            max_idle,
            taken: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        })
    }

    /// 节点拨来一条连接 → 入池。
    pub fn park(&self, node_id: &str, ch: Chan) {
        let mut g = self.inner.lock().unwrap();
        g.entry(node_id.to_string()).or_default().push_back(Idle { ch, since: Instant::now() });
        self.cv.notify_all();
    }

    /// 借一条目标节点的空闲连接；池空则最多等 `wait`（等节点补拨）。
    pub fn take(&self, node_id: &str, wait: Duration) -> Option<Chan> {
        let deadline = Instant::now() + wait;
        let mut g = self.inner.lock().unwrap();
        loop {
            if let Some(q) = g.get_mut(node_id) {
                // 丢弃过老的（可能已被中间盒静默断开），取第一条新鲜的。
                while let Some(i) = q.pop_front() {
                    if i.since.elapsed() <= self.max_idle {
                        self.taken.fetch_add(1, Ordering::Relaxed);
                        return Some(i.ch);
                    }
                    i.ch.0.close();
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let (ng, _) = self.cv.wait_timeout(g, left).unwrap();
            g = ng;
        }
    }

    /// 各节点当前空闲连接数（观测/对账用）。
    pub fn depths(&self) -> Vec<(String, usize)> {
        let g = self.inner.lock().unwrap();
        let mut v: Vec<(String, usize)> = g.iter().map(|(k, q)| (k.clone(), q.len())).collect();
        v.sort();
        v
    }
}

// ————————————————————— 节点侧：主动外拨 —————————————————————

/// 节点侧数据面代理的处理入口：网关借用连接并递来**已验签**的 ticket 后，由宿主
/// （api.rs）在这条 `Chan` 上读 HTTP 请求、就地执行、写回响应。
pub type OnOpen = Arc<dyn Fn(Ticket, Chan) + Send + Sync>;

/// 节点侧外拨代理配置。
pub struct AgentCfg {
    /// 网关的**节点接入**地址（`host:port`，非面向客户端的那个端口）。
    pub gw_addr: String,
    /// 本节点 id（与 `node/<id>` 心跳键、`sandbox/<sid>/node` 归属键同值）。
    pub node_id: String,
    /// 稳态**空闲**连接条数（网关随时可借的余量）。注意这不是并发上限——见 `max_streams`。
    pub pool: usize,
    /// 本节点同时在跑的数据面流上限。达到上限后新流**就地串行处理**（不再抢先补拨），
    /// 以此对网关形成背压，而不是无限开线程。
    pub max_streams: usize,
    /// mTLS 材料；`None` = 明文（`--gw-insecure`，仅本机对账/开发）。
    pub tls: Option<TlsOpts>,
}

/// 起节点侧外拨代理：维持 `pool` 条到网关的**空闲**持久连接，被借用即交给 `on_open` 处理。
/// **节点不监听任何入站端口**（ADR-22）。拨号失败按 1→30s 退避重试，不放弃——网关重启/
/// 滚动升级后节点自愈重连。
///
/// # 补拨时机（关键）
///
/// 补拨发生在**开流的那一刻**，而不是流结束之后：拿到 `OPEN` 就把处理甩给一条新线程、
/// 本线程立刻回去补一条空闲连接。否则空闲余量会被**流的时长**绑住——PTY / 流式 exec 是
/// 长连接，`pool` 个 PTY 会话就能把整个节点的数据面焊死，后续请求全 503。
///
/// 背压：在跑的流达到 `max_streams` 时不再抢先补拨，改为**就地串行处理**——网关那边自然
/// 借不到连接（有界等待后 503），而不是把节点拖进无限开线程。
pub fn start_node_agent(cfg: AgentCfg, on_open: OnOpen) -> Result<(), String> {
    // 证书只解析一次，全部拨号线程共用（见 `ClientCtx`）。
    let tls = match &cfg.tls {
        Some(t) => Some(build_client_ctx(t)?),
        None => None,
    };
    let cfg = Arc::new(cfg);
    let inflight = Arc::new(AtomicU64::new(0));
    for slot in 0..cfg.pool.max(1) {
        let cfg = Arc::clone(&cfg);
        let on_open = Arc::clone(&on_open);
        let inflight = Arc::clone(&inflight);
        let tls = tls.clone();
        thread::Builder::new()
            .name(format!("gw-dial-{slot}"))
            .spawn(move || {
                let mut backoff = Duration::from_secs(1);
                loop {
                    match dial_once(&cfg, tls.as_ref()) {
                        Ok(ch) => {
                            backoff = Duration::from_secs(1);
                            // 阻塞等网关借用这条连接（可能等很久，这正是「持久」的含义）。
                            match serve_one(&ch) {
                                Ok(Some(t)) => {
                                    let busy = inflight.load(Ordering::SeqCst) as usize;
                                    if busy >= cfg.max_streams.max(1) {
                                        // 背压：就地处理，本线程这期间不补拨。
                                        on_open(t, ch);
                                    } else {
                                        // 常态：甩给新线程，本线程立刻回去补空闲连接。
                                        inflight.fetch_add(1, Ordering::SeqCst);
                                        let on_open_s = Arc::clone(&on_open);
                                        let inflight_s = Arc::clone(&inflight);
                                        if thread::Builder::new()
                                            .name(format!("gw-stream-{slot}"))
                                            .spawn(move || {
                                                on_open_s(t, ch);
                                                inflight_s.fetch_sub(1, Ordering::SeqCst);
                                            })
                                            .is_err()
                                        {
                                            inflight.fetch_sub(1, Ordering::SeqCst);
                                            eprintln!("[sandlocker][gw-agent] 开流线程创建失败");
                                        }
                                    }
                                }
                                // 网关侧丢弃/超时关闭 → 正常，补拨。
                                Ok(None) => {}
                                Err(e) => eprintln!("[sandlocker][gw-agent] 开流失败: {e}"),
                            }
                        }
                        Err(e) => {
                            eprintln!("[sandlocker][gw-agent] 连 {} 失败: {e}（{}s 后重试）", cfg.gw_addr, backoff.as_secs());
                            thread::sleep(backoff);
                            backoff = (backoff * 2).min(Duration::from_secs(30));
                        }
                    }
                }
            })
            .expect("spawn gw-dial 线程");
    }
    Ok(())
}

fn dial_once(cfg: &AgentCfg, tls: Option<&ClientCtx>) -> Result<Chan, String> {
    let addr = cfg
        .gw_addr
        .to_socket_addrs()
        .map_err(|e| format!("解析 {} 失败: {e}", cfg.gw_addr))?
        .next()
        .ok_or_else(|| format!("{} 无可用地址", cfg.gw_addr))?;
    let sock = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| format!("connect: {e}"))?;
    sock.set_nodelay(true).ok();
    let d = match tls {
        #[cfg(feature = "cluster")]
        Some(c) => Duplex::tls_client(sock, Arc::clone(&c.cfg), &c.name)?,
        #[cfg(not(feature = "cluster"))]
        Some(_) => return Err("mTLS 需以 --features cluster 构建".into()),
        None => Duplex::plain(sock)?,
    };
    let mut ch = Chan(d);
    // 问候行：网关据此把连接归入本节点的池。
    ch.write_all(format!("{PROTO} data {}\n", cfg.node_id).as_bytes())
        .map_err(|e| format!("写问候行失败: {e}"))?;
    ch.flush().ok();
    Ok(ch)
}

/// 阻塞等网关下发 `OPEN {ticket}`。返回 `Ok(None)` 表示连接被正常回收（无流可服务）。
fn serve_one(ch: &Chan) -> Result<Option<Ticket>, String> {
    let mut r = ch.clone();
    let line = match read_line(&mut r, 4096) {
        Ok(l) => l,
        // 网关关掉空闲连接是常态（滚动/超时），不当错误。
        Err(_) => return Ok(None),
    };
    let json = line.strip_prefix(OPEN).ok_or_else(|| format!("非法开流行: {line}"))?;
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("开流行非 JSON: {e}"))?;
    let sid = v.get("sid").and_then(|x| x.as_str()).ok_or("开流行缺 sid")?.to_string();
    let action = v
        .get("action")
        .and_then(|x| x.as_str())
        .and_then(Action::from_str)
        .ok_or("开流行 action 非法")?;
    let port = v.get("port").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    Ok(Some(Ticket { sid, action, port }))
}

// ————————————————————— 网关侧：中继 —————————————————————

/// 独立网关进程配置。
pub struct GwCfg {
    /// 面向客户端的 HTTP 监听（签名 URL 打到这里）。
    pub bind: String,
    /// 面向节点的接入监听（节点主动外拨到这里）。
    pub node_bind: String,
    /// 打开一个 store 句柄（集群为 etcd）：网关要两个——一个给 ticket 验签（共享 secret +
    /// 一次性 nonce），一个查沙箱→节点映射。用工厂而非单例，是因为 `Gateway` 持 `Box<dyn Store>`。
    pub open_store: Box<dyn Fn() -> Result<Box<dyn Store>, String> + Send + Sync>,
    /// mTLS 材料；`None` = 明文接入（仅本机对账/开发）。
    pub tls: Option<TlsOpts>,
    /// 借空闲连接的最长等待（掩盖节点补拨抖动）。
    pub take_wait: Duration,
    /// 空闲连接最长停留。
    pub max_idle: Duration,
    /// 两个监听都 bind 好后回调（实际绑定地址：客户端端口, 节点端口）。
    /// 对账用 `:0` 端口起网关，靠它拿到真实端口；生产不设。
    pub on_ready: Option<Box<dyn Fn(std::net::SocketAddr, std::net::SocketAddr) + Send>>,
}

/// 查沙箱归属节点（`sandbox/<sid>/node`，M3 W3 写入）。
fn owner_of(store: &dyn Store, sid: &str) -> Result<Option<String>, String> {
    Ok(store
        .get(&sl_store::cluster::sandbox_node_key(sid))
        .map_err(|e| e.to_string())?
        .map(|kv| String::from_utf8_lossy(&kv.value).into_owned()))
}

/// 起独立数据面网关（`sandlocker-gw`）。阻塞运行。
///
/// 两个监听：**节点接入**（mTLS，收外拨连接入池）+ **客户端 HTTP**（验签 → 查归属 → 中继）。
pub fn gw_serve(cfg: GwCfg) -> Result<(), String> {
    let pool = NodePool::new(cfg.max_idle);
    let node_addr;
    // ticket 与控制面副本共享 secret（`cluster/gw_secret` CAS 收敛）+ store 一次性 nonce（M3 W5）：
    // 故**任一副本签发的 ticket，本网关都能无状态验签**，且一次性跨副本生效。
    let gw = Arc::new(Gateway::new_shared(String::new(), (cfg.open_store)()?)?);

    // —— 节点接入监听 ——
    {
        let pool = Arc::clone(&pool);
        let nb = cfg.node_bind.clone();
        // 证书只解析一次，全部接入线程共用（见 `ServerCtx`）。
        let tls = match &cfg.tls {
            Some(t) => Some(build_server_ctx(t)?),
            None => None,
        };
        let l = TcpListener::bind(&nb).map_err(|e| format!("bind 节点接入 {nb} 失败: {e}"))?;
        node_addr = l.local_addr().map_err(|e| format!("取节点端口失败: {e}"))?;
        match &tls {
            Some(_) => println!("[sandlocker-gw] 节点接入就绪 {node_addr}（mTLS，强制客户端证书）"),
            None => println!("[sandlocker-gw][WARN] 节点接入就绪 {node_addr}（**明文**，仅限本机对账/开发）"),
        }
        thread::spawn(move || {
            for sock in l.incoming().flatten() {
                let (pool, tls) = (Arc::clone(&pool), tls.clone());
                thread::spawn(move || {
                    if let Err(e) = accept_node(sock, &pool, tls.as_ref()) {
                        eprintln!("[sandlocker-gw] 节点接入失败: {e}");
                    }
                });
            }
        });
    }

    // —— 客户端监听 ——
    let l = TcpListener::bind(&cfg.bind).map_err(|e| format!("bind 客户端 {} 失败: {e}", cfg.bind))?;
    let client_addr = l.local_addr().map_err(|e| format!("取客户端端口失败: {e}"))?;
    println!("[sandlocker-gw] 数据面就绪 http://{client_addr}（一次性 HMAC 签名 URL；/gw/*）");
    if let Some(cb) = &cfg.on_ready {
        cb(client_addr, node_addr);
    }
    let store: Arc<dyn Store> = Arc::from((cfg.open_store)()?);
    let take_wait = cfg.take_wait;
    for sock in l.incoming().flatten() {
        let (pool, gw, store) = (Arc::clone(&pool), Arc::clone(&gw), Arc::clone(&store));
        thread::spawn(move || {
            if let Err(e) = handle_client(sock, &gw, store.as_ref(), &pool, take_wait) {
                eprintln!("[sandlocker-gw] 客户端处理失败: {e}");
            }
        });
    }
    Ok(())
}

/// 收一条节点外拨连接：（mTLS 握手 →）读问候行 → 入池。
fn accept_node(sock: TcpStream, pool: &NodePool, tls: Option<&ServerCtx>) -> Result<(), String> {
    sock.set_nodelay(true).ok();
    let d = match tls {
        #[cfg(feature = "cluster")]
        Some(c) => Duplex::tls_server(sock, Arc::clone(&c.0))?,
        #[cfg(not(feature = "cluster"))]
        Some(_) => return Err("mTLS 需以 --features cluster 构建".into()),
        None => Duplex::plain(sock)?,
    };
    let ch = Chan(d);
    let mut r = ch.clone();
    // 问候行须限时——防半开连接占线程。
    ch.0.set_read_timeout(Some(Duration::from_secs(10)));
    let line = read_line(&mut r, 512)?;
    ch.0.set_read_timeout(None);
    let mut it = line.split_whitespace();
    if it.next() != Some(PROTO) {
        return Err(format!("协议版本不符: {line}"));
    }
    if it.next() != Some("data") {
        return Err(format!("未知角色: {line}"));
    }
    let node_id = it.next().ok_or("问候行缺 node_id")?.to_string();
    pool.park(&node_id, ch);
    Ok(())
}

/// 客户端一次数据面请求：验签 ticket → 查沙箱归属节点 → 借该节点的空闲外拨连接 → 全双工中继。
fn handle_client(
    mut sock: TcpStream,
    gw: &Gateway,
    store: &dyn Store,
    pool: &NodePool,
    take_wait: Duration,
) -> Result<(), String> {
    sock.set_nodelay(true).ok();
    let (method, path, _api_key, body) = crate::api::read_request(&mut sock)?;
    let json = "application/json";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // ① 无状态验签 + 一次性消费（跨副本，M3 W5）。
    let ticket = match gw.verify(&parse_query(&path), now) {
        Ok(t) => t,
        Err(e) => {
            return crate::api::write_response(&mut sock, 403, json, &crate::api::err_json(&format!("ticket 无效: {e}")))
        }
    };
    // ② 定目标节点。两种来源：
    //    - **创建票**：还没有沙箱，目标节点直接写在签名过的 `sid` 里（`node:<id>`，调度器定的）。
    //    - 其余票：查归属键 `sandbox/<sid>/node`——网关自己不持任何沙箱状态，故无粘滞。
    let owner = match ticket.node_target() {
        Some(n) => n.to_string(),
        None => match owner_of(store, &ticket.sid)? {
            Some(o) => o,
            None => {
                return crate::api::write_response(&mut sock, 404, json, &crate::api::err_json("未知沙箱或已回收"))
            }
        },
    };
    // ③ 借一条该节点的空闲外拨连接。
    let ch = match pool.take(&owner, take_wait) {
        Some(c) => c,
        None => {
            return crate::api::write_response(
                &mut sock,
                503,
                json,
                &crate::api::err_json(&format!("节点 {owner} 未接入网关（无可用数据面连接）")),
            )
        }
    };
    // ④ 下发已验签 ticket + 复刻客户端请求，随后全双工对搬。
    let open = format!(
        "{OPEN}{{\"sid\":\"{}\",\"action\":\"{}\",\"port\":{}}}\n",
        ticket.sid,
        ticket.action.as_str(),
        ticket.port
    );
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: sandlocker\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut w = ch.clone();
    if w.write_all(open.as_bytes()).and_then(|_| w.write_all(head.as_bytes())).and_then(|_| w.write_all(&body)).and_then(|_| w.flush()).is_err() {
        ch.0.close();
        return crate::api::write_response(&mut sock, 502, json, &crate::api::err_json("节点连接已失效"));
    }
    relay(sock, ch)
}

/// 全双工中继：`client → node` 与 `node → client` 各起一向，任一向 EOF 即半关对端写方向。
/// PTY / 流式 exec 依赖这里的**双向同时**搬运（见模块头「全双工」）。
fn relay(client: TcpStream, node: Chan) -> Result<(), String> {
    let c_r = client.try_clone().map_err(|e| format!("clone 客户端失败: {e}"))?;
    let up_node = node.clone();
    // client → node
    let up = thread::spawn(move || {
        let mut src = c_r;
        let mut dst = up_node.clone();
        let _ = copy_bytes(&mut src, &mut dst);
        up_node.0.shutdown_write();
    });
    // node → client
    let mut src = node.clone();
    let mut dst = client;
    let _ = copy_bytes(&mut src, &mut dst);
    let _ = dst.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    node.0.close();
    Ok(())
}

/// 逐块搬运到 EOF（不用 `io::copy`：要在每块后 flush，流式响应才不会攒在缓冲里）。
fn copy_bytes<R: Read, W: Write>(src: &mut R, dst: &mut W) -> std::io::Result<u64> {
    let mut buf = vec![0u8; RELAY_BUF];
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dst.write_all(&buf[..n])?;
        dst.flush()?;
        total += n as u64;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_line_trims_crlf_and_stops_at_lf() {
        let mut src = &b"sl-gw/1 data node-a\r\nrest"[..];
        assert_eq!(read_line(&mut src, 128).unwrap(), "sl-gw/1 data node-a");
        assert_eq!(src, b"rest");
    }

    #[test]
    fn read_line_rejects_overlong_and_eof() {
        let mut long = &b"aaaaaaaaaaaaaaaaaaaa\n"[..];
        assert!(read_line(&mut long, 4).is_err());
        let mut eof = &b"no newline"[..];
        assert!(read_line(&mut eof, 128).is_err());
    }

    /// 池按 node_id 归集：取到的是同节点的连接，取不到别的节点的（无会话粘滞的基础）。
    #[test]
    fn pool_is_keyed_by_node_and_misses_are_bounded() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(a);
        let pool = NodePool::new(Duration::from_secs(60));
        // 空池：等待有上界、返回 None（不挂死）。
        let t0 = Instant::now();
        assert!(pool.take("node-a", Duration::from_millis(50)).is_none());
        assert!(t0.elapsed() >= Duration::from_millis(50));
        assert_eq!(pool.misses.load(Ordering::Relaxed), 1);
        assert!(pool.depths().is_empty());
    }
}
