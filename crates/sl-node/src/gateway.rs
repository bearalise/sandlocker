//! gateway.rs — 数据面网关 ticket + HMAC 签名 URL + 端口反代（M2 W10，ADR-22 / FR-3.3 / M2-Q6）。
//!
//! 控制面用进程内 `secret` 签发**一次性 HMAC 签名 URL**（ticket）：payload `v1:{sid}:{action}:{port}:
//! {exp}:{nonce}`，`sig=hex(HMAC_SHA256(secret,payload))`。网关**无状态验签**（HMAC 自包含）+ 检查
//! 未过期 + **一次性**（单机 nonce 集，ADR-22 单机；M3 拆分随网关副本）。exec/文件/日志/端口经 ticket
//! 换网关直连——控制面不持数据连接态，M3 拆独立副本零语义变更。
//!
//! 端口暴露（FR-3.3）：网关 `connect_guest` + `Request::Connect{port}` → guest dial 127.0.0.1:port →
//! 裸字节双向管道；网关做简单 HTTP/1.0 GET 反向代理，把 VM 内服务经签名 URL 暴露给外部。

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use sl_proto::{read_msg, write_msg, Request, Response};
use sl_store::Store;

use crate::{connect_guest, hex, host_random};

/// 共享网关密钥键（集群模式，M3 W5）：所有网关/控制面副本从 store 收敛到同一 HMAC secret，
/// 使**任一副本签发的 ticket 可被任一副本无状态验签**（ADR-22 拆分零语义变更的前提）。
const GW_SECRET_KEY: &str = "cluster/gw_secret";
/// 一次性 nonce 键前缀（集群模式）：验签消费经 store CAS，使「一次性」跨副本成立。
fn nonce_key(nonce: &str) -> String {
    format!("gw/nonce/{nonce}")
}

/// ticket 授权的动作。
///
/// 前五个是**数据面**（M2 起）：最终都落到 guest 的 vsock 通道上。
/// 后八个是**控制面**（M3 W4 余项）：落到 owning 节点的 `Orch::live` 表与后端进程上——
/// 同样只有 owning 节点能受理，故同样经网关中继。**每个操作各占一个动作、动作进签名**，
/// 于是一张 pause 票不能被改写成 destroy 票（若只用一个笼统的 `ctl` 动作，具体操作就只能
/// 走未签名的路径/查询串，替换即提权）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Exec,
    File,
    Logs,
    Port,
    /// 流式 exec（NDJSON，M2 流式特性）。M3 W5 余项新增：跨节点时控制面副本据此签票、
    /// 经网关把**未定长的增量响应**中继回客户端（中继全双工，故流不被缓冲住）。
    Stream,
    // —— 控制面（M3 W4 余项，跨节点生命周期）——
    Pause,
    Resume,
    Fork,
    Destroy,
    Keepalive,
    Expose,
    /// 取消暴露。guest 端口走 ticket 的 **`port` 字段**（已进签名），不走未签名查询串。
    Unexpose,
    /// 列暴露（读，但暴露注册表是**节点进程内**状态，别的副本看不到）。
    Exposes,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Exec => "exec",
            Action::File => "file",
            Action::Logs => "logs",
            Action::Port => "port",
            Action::Stream => "stream",
            Action::Pause => "pause",
            Action::Resume => "resume",
            Action::Fork => "fork",
            Action::Destroy => "destroy",
            Action::Keepalive => "keepalive",
            Action::Expose => "expose",
            Action::Unexpose => "unexpose",
            Action::Exposes => "exposes",
        }
    }
    pub fn from_str(s: &str) -> Option<Action> {
        match s {
            "exec" => Some(Action::Exec),
            "file" => Some(Action::File),
            "logs" => Some(Action::Logs),
            "port" => Some(Action::Port),
            "stream" => Some(Action::Stream),
            "pause" => Some(Action::Pause),
            "resume" => Some(Action::Resume),
            "fork" => Some(Action::Fork),
            "destroy" => Some(Action::Destroy),
            "keepalive" => Some(Action::Keepalive),
            "expose" => Some(Action::Expose),
            "unexpose" => Some(Action::Unexpose),
            "exposes" => Some(Action::Exposes),
            _ => None,
        }
    }
    /// 是否**控制面**动作。控制面票只由副本在转发时自签，**绝不签发给客户端**
    /// （`POST /v1/sandboxes/{id}/ticket` 拒之，见 `api::mint_ticket`）——否则客户端可拿票
    /// 直连网关执行生命周期操作，绕开配额前置检查与审计落账（FR-7.2/7.3）。
    pub fn is_control(self) -> bool {
        !matches!(self, Action::Exec | Action::File | Action::Logs | Action::Port | Action::Stream)
    }
}

/// 验签成功的 ticket 内容。
#[derive(Debug, Clone)]
pub struct Ticket {
    pub sid: String,
    pub action: Action,
    pub port: u32,
}

/// HMAC-SHA256（手写，复用 sha2；守精简依赖不引 hmac crate）。
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    outer.finalize().into()
}

fn payload(sid: &str, action: Action, port: u32, exp: i64, nonce: &str) -> String {
    format!("v1:{sid}:{}:{port}:{exp}:{nonce}", action.as_str())
}

/// 常数时间比较（防时序侧信道）。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

/// 一次性 nonce 的看护：单机进程内集合 / 集群经 store（CAS 消费，跨副本一次性）。
enum NonceGuard {
    /// 单机：进程内 HashSet（M2 行为，零回归）。
    Local(Mutex<HashSet<String>>),
    /// 集群（M3 W5）：nonce 消费经 store CAS（挂租约按 ticket 到期自动清理，有界）。
    Shared(Box<dyn Store>),
}

/// 网关：持签发密钥 + 一次性 nonce 看护。控制面签发、网关验签共用同 secret。
/// 单机进程内（`new_random`）secret 随机、nonce 进程内；集群（`new_shared`）secret + nonce 走 store，
/// **任一副本可验任一副本签发的 ticket、一次性跨副本生效**（ADR-22）。
pub struct Gateway {
    secret: [u8; 32],
    /// 网关外部基址（`http://host:port`），mint 拼全 URL 用。
    base: String,
    nonces: NonceGuard,
}

impl Gateway {
    /// 单机：启动时随机 32B 密钥 + 进程内 nonce 集。`base` = 网关外部基址（M2 行为，零回归）。
    pub fn new_random(base: String) -> Self {
        let mut s = [0u8; 32];
        host_random(&mut s);
        Self { secret: s, base, nonces: NonceGuard::Local(Mutex::new(HashSet::new())) }
    }

    /// 集群（M3 W5）：secret 从 store 收敛（`cluster/gw_secret`，CAS 首写者定，余副本读同值），
    /// nonce 经 store CAS 消费（跨副本一次性）。`store` 为本副本的独立 store 句柄。
    pub fn new_shared(base: String, store: Box<dyn Store>) -> Result<Self, String> {
        let secret = ensure_gw_secret(store.as_ref())?;
        Ok(Self { secret, base, nonces: NonceGuard::Shared(store) })
    }

    /// 签发签名 URL：`{base}/gw/{path}?sid=..&action=..&port=..&exp=..&nonce=..&sig=..`。
    /// path 是网关路由段（port→`p`，其余同 action 名），须与 api.rs `handle_gw_conn` 路由表一致。
    /// 操作参数（exec 的 cmd / file|port 的路径）在使用时随请求带，不入签名（ticket = 该动作通道能力）。
    pub fn mint(&self, sid: &str, action: Action, port: u32, ttl_secs: i64, now: i64) -> String {
        let exp = now.saturating_add(ttl_secs);
        let mut nb = [0u8; 12];
        host_random(&mut nb);
        let nonce = hex(&nb);
        let sig = hex(&hmac_sha256(&self.secret, payload(sid, action, port, exp, &nonce).as_bytes()));
        let path = match action {
            Action::Port => "p",
            a => a.as_str(),
        };
        format!(
            "{}/gw/{}?sid={sid}&action={}&port={port}&exp={exp}&nonce={nonce}&sig={sig}",
            self.base,
            path,
            action.as_str()
        )
    }

    /// 验签 + 未过期 + 一次性消费。返回授权的 (sid, action, port)。任一不满足即 Err。
    pub fn verify(&self, q: &HashMap<String, String>, now: i64) -> Result<Ticket, String> {
        let sid = q.get("sid").ok_or("缺 sid")?;
        let action = q.get("action").and_then(|s| Action::from_str(s)).ok_or("action 非法")?;
        let port: u32 = q.get("port").and_then(|s| s.parse().ok()).ok_or("port 非法")?;
        let exp: i64 = q.get("exp").and_then(|s| s.parse().ok()).ok_or("exp 非法")?;
        let nonce = q.get("nonce").ok_or("缺 nonce")?;
        let sig = q.get("sig").ok_or("缺 sig")?;
        // 无状态验签
        let want = hex(&hmac_sha256(&self.secret, payload(sid, action, port, exp, nonce).as_bytes()));
        if !ct_eq(want.as_bytes(), sig.as_bytes()) {
            return Err("签名不匹配".into());
        }
        if now >= exp {
            return Err("ticket 已过期".into());
        }
        // 一次性消费（在 sig/exp 校验之后，避免坏 ticket 污染 nonce 集）：
        match &self.nonces {
            // 单机：进程内集合。
            NonceGuard::Local(used) => {
                if !used.lock().unwrap().insert(nonce.clone()) {
                    return Err("ticket 已使用（一次性）".into());
                }
            }
            // 集群：store CAS（nonce 不存在→写入并挂租约；已存在→拒）。跨副本一次性。
            NonceGuard::Shared(store) => {
                let ttl = (exp - now).max(1);
                let lease = store.lease_grant(ttl).map_err(|e| e.to_string())?;
                let r = store
                    .compare_and_swap(&nonce_key(nonce), None, b"1", Some(lease))
                    .map_err(|e| e.to_string())?;
                if !r.succeeded {
                    let _ = store.lease_revoke(lease); // 让出刚 grant 的租约
                    return Err("ticket 已使用（一次性）".into());
                }
            }
        }
        Ok(Ticket { sid: sid.clone(), action, port })
    }
}

/// 集群网关密钥收敛：读 `cluster/gw_secret`；无则随机生成并 CAS（首写者定），输者读回同值。
/// 保证所有副本用同一 secret → 任一副本可无状态验签任一副本签发的 ticket。
fn ensure_gw_secret(store: &dyn Store) -> Result<[u8; 32], String> {
    if let Some(kv) = store.get(GW_SECRET_KEY).map_err(|e| e.to_string())? {
        if kv.value.len() == 32 {
            let mut s = [0u8; 32];
            s.copy_from_slice(&kv.value);
            return Ok(s);
        }
    }
    let mut mine = [0u8; 32];
    host_random(&mut mine);
    let r = store
        .compare_and_swap(GW_SECRET_KEY, None, &mine, None)
        .map_err(|e| e.to_string())?;
    if r.succeeded {
        return Ok(mine);
    }
    // 输给别的副本 → 读它写入的 secret。
    let kv = store
        .get(GW_SECRET_KEY)
        .map_err(|e| e.to_string())?
        .ok_or("gw_secret CAS 失败后仍读不到")?;
    if kv.value.len() != 32 {
        return Err("gw_secret 长度异常".into());
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&kv.value);
    Ok(s)
}

/// 端口反代（FR-3.3）：`connect_guest` → `Connect{port}` → guest dial 127.0.0.1:port → 发 HTTP/1.0 GET
/// `guest_path` → 回读 guest 完整 HTTP 响应原样返回（供网关直接写回外部客户端）。
pub fn proxy_port_http(vsock: &Path, port: u32, guest_path: &str) -> Result<Vec<u8>, String> {
    let mut s = connect_guest(vsock)?;
    write_msg(&mut s, &Request::Connect { port }).map_err(|e| format!("发 Connect 失败: {e}"))?;
    match read_msg::<_, Response>(&mut s).map_err(|e| format!("读 Connect ack 失败: {e}"))? {
        Response::Ok => {}
        Response::Error { message } => return Err(format!("guest Connect 失败: {message}")),
        other => return Err(format!("Connect ack 异常: {other:?}")),
    }
    // 连接已转裸字节管道：发一个简单 HTTP/1.0 GET，Connection: close → guest 响应完即关。
    let path = format!("/{}", guest_path.trim_start_matches('/'));
    let req = format!("GET {path} HTTP/1.0\r\nHost: sandbox\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| format!("写 guest 请求失败: {e}"))?;
    s.flush().ok();
    // HTTP/1.0 Connection: close：读到 EOF；容忍 splice 收尾的 RST（guest shutdown 经 vsock 代理为 reset），
    // 已收到数据即视为完整响应。
    let mut resp = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => return Err(format!("读 guest 响应失败: {e}")),
        }
    }
    if resp.is_empty() {
        return Err("guest 服务无响应".into());
    }
    Ok(resp)
}

/// 解析 URL query（`a=b&c=d`）→ map。值不做 percent-decode（本地 ticket 参数为 hex/数字/id，无需）。
pub fn parse_query(path: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(q) = path.split('?').nth(1) {
        for kv in q.split('&') {
            if let Some((k, v)) = kv.split_once('=') {
                m.insert(k.to_string(), v.to_string());
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test case 2：key="Jefe", data="what do ya want for nothing?"
    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex(&mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn mint_verify_roundtrip() {
        let gw = Gateway::new_random(String::new());
        let url = gw.mint("sb1", Action::Exec, 0, 60, 1000);
        let q = parse_query(&url);
        let t = gw.verify(&q, 1000).unwrap();
        assert_eq!(t.sid, "sb1");
        assert_eq!(t.action, Action::Exec);
    }

    #[test]
    fn mint_url_path_matches_gw_route_table() {
        // 路由段契约（api.rs handle_gw_conn）：port→/gw/p，其余与 action 同名。
        let gw = Gateway::new_random(String::new());
        assert!(gw.mint("sb1", Action::Port, 3000, 60, 1000).contains("/gw/p?"));
        assert!(gw.mint("sb1", Action::Exec, 0, 60, 1000).contains("/gw/exec?"));
        assert!(gw.mint("sb1", Action::File, 0, 60, 1000).contains("/gw/file?"));
        assert!(gw.mint("sb1", Action::Logs, 0, 60, 1000).contains("/gw/logs?"));
    }

    #[test]
    fn verify_rejects_tampered_and_expired_and_reused() {
        let gw = Gateway::new_random(String::new());
        // 篡改 sig
        let url = gw.mint("sb1", Action::Port, 8080, 60, 1000);
        let mut q = parse_query(&url);
        q.insert("sig".into(), "deadbeef".into());
        assert!(gw.verify(&q, 1000).is_err());
        // 过期
        let url2 = gw.mint("sb2", Action::Exec, 0, 60, 1000);
        let q2 = parse_query(&url2);
        assert!(gw.verify(&q2, 2000).is_err());
        // 一次性：首用成功，再用被拒
        let url3 = gw.mint("sb3", Action::Logs, 0, 60, 1000);
        let q3 = parse_query(&url3);
        assert!(gw.verify(&q3, 1000).is_ok());
        assert!(gw.verify(&q3, 1000).is_err());
    }

    #[test]
    fn action_str_roundtrip_and_control_split() {
        use Action::*;
        // 每个动作都能原样往返——`from_str` 漏一个，节点侧就把该动作的开流行判为非法。
        for a in [Exec, File, Logs, Port, Stream, Pause, Resume, Fork, Destroy, Keepalive, Expose, Unexpose, Exposes] {
            assert_eq!(Action::from_str(a.as_str()), Some(a), "{} 未双向", a.as_str());
        }
        // 数据面/控制面的划分：数据面票可签发给客户端，控制面票绝不。
        for a in [Exec, File, Logs, Port, Stream] {
            assert!(!a.is_control(), "{} 不该是控制面", a.as_str());
        }
        for a in [Pause, Resume, Fork, Destroy, Keepalive, Expose, Unexpose, Exposes] {
            assert!(a.is_control(), "{} 应是控制面", a.as_str());
        }
    }

    #[test]
    fn verify_rejects_action_tamper() {
        // **控制面动作进签名**的意义：拿到一张 pause 票，改 action=destroy 用不了。
        // 若当初用一个笼统的 `ctl` 动作 + 未签名路径来区分操作，这里就会通过。
        let gw = Gateway::new_random(String::new());
        let url = gw.mint("sb1", Action::Pause, 0, 60, 1000);
        let mut q = parse_query(&url);
        q.insert("action".into(), "destroy".into());
        assert!(gw.verify(&q, 1000).is_err());
    }

    #[test]
    fn control_mint_url_path_matches_action() {
        // 控制面同样遵守「路由段 == action 名」的契约（api.rs serve_gw_ticket 按此匹配）。
        let gw = Gateway::new_random(String::new());
        for (a, seg) in [
            (Action::Pause, "/gw/pause?"),
            (Action::Resume, "/gw/resume?"),
            (Action::Fork, "/gw/fork?"),
            (Action::Destroy, "/gw/destroy?"),
            (Action::Keepalive, "/gw/keepalive?"),
            (Action::Expose, "/gw/expose?"),
            (Action::Unexpose, "/gw/unexpose?"),
            (Action::Exposes, "/gw/exposes?"),
        ] {
            assert!(gw.mint("sb1", a, 0, 60, 1000).contains(seg), "{} 路由段不符", a.as_str());
        }
    }

    #[test]
    fn verify_rejects_port_tamper() {
        // 改 port（越权到别的端口）→ 签名覆盖 port，必失配。
        let gw = Gateway::new_random(String::new());
        let url = gw.mint("sb1", Action::Port, 8080, 60, 1000);
        let mut q = parse_query(&url);
        q.insert("port".into(), "22".into());
        assert!(gw.verify(&q, 1000).is_err());
    }
}
