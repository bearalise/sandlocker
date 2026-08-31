//! EtcdStore（集群模式，M3 W1）——`Store` trait 的 etcd v3 实现。
//!
//! 设计（D2 精化，2026-08-31）：走 etcd 自带的 **gRPC-gateway HTTP/JSON API**
//! （`/v3/kv/*`、`/v3/lease/*`、`/v3/watch`），用**全同步 `ureq`+rustls**（复用 M2 OCI 依赖）
//! 打请求——**零 tokio/tonic**，守 M2 D5「全同步·精简依赖」哲学。`Store` trait 保持同步签名，
//! 不引入异步隔离区（那留给 W5 网关的持久 gRPC 流）。
//!
//! 语义对齐（与 SqliteStore 跑同一套 `contract::run_all`）：
//!   - revision / create_revision / mod_revision 直接映射 etcd 的全局 revision。
//!   - CAS = etcd Txn（compare mod_revision，或 create_revision=0 表「键不存在」）。
//!   - lease grant/keepalive/revoke 映射 etcd lease；**sweep 为 no-op**——etcd 服务端按 TTL
//!     自动过期，无需外部清扫器（契约只校验「过期后键消失」这一可观测不变量，故收敛）。
//!   - watch = `/v3/watch` 流（后台线程转发到进程内 mpsc）；changes_since = 带 start_revision
//!     的有界历史回放。
//!
//! gRPC-gateway 约定：键/值一律 **base64**；int64（revision/lease/ttl）一律 **JSON 字符串**。
//!
//! 注：kv/lease/CAS/current_revision 为高置信直映；**watch 与 changes_since 的流式行为
//! 依赖 live etcd 验证**（本机无 etcd，随 `--store-contract --etcd`/CI service 容器对账，
//! 类比 net-live/dmthin 的 runner 门控）。

use std::io::{BufRead, BufReader};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};

use crate::{CasResult, Event, EventKind, KeyValue, LeaseId, Result, Revision, Store, StoreError};

/// etcd 后端：base URL（如 `http://127.0.0.1:2379`）+ 复用连接的 ureq Agent。
pub struct EtcdStore {
    base: String,
    agent: ureq::Agent,
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn unb64(v: &Value) -> Result<Vec<u8>> {
    let s = v.as_str().unwrap_or("");
    B64.decode(s).map_err(|e| StoreError::Backend(format!("base64 解码: {e}")))
}

/// int64 字段：gateway 编为字符串，防御性兼容数字形。
fn as_i64(v: &Value) -> i64 {
    if let Some(s) = v.as_str() {
        s.parse().unwrap_or(0)
    } else {
        v.as_i64().unwrap_or(0)
    }
}

/// 前缀 range_end（etcd 约定：末个 <0xFF 字节 +1；空前缀 → "\0" 表全量）。
fn range_end_for_prefix(prefix: &[u8]) -> Vec<u8> {
    if prefix.is_empty() {
        return vec![0]; // key="\0" + range_end="\0" ⇒ 全部键
    }
    let mut end = prefix.to_vec();
    while let Some(&last) = end.last() {
        if last < 0xff {
            *end.last_mut().unwrap() = last + 1;
            return end;
        }
        end.pop();
    }
    vec![0]
}

/// etcd KeyValue JSON → 本仓 KeyValue。
fn kv_from_json(v: &Value) -> Result<KeyValue> {
    let key = String::from_utf8_lossy(&unb64(&v["key"])?).into_owned();
    let value = unb64(&v["value"])?;
    let lease = as_i64(&v["lease"]);
    Ok(KeyValue {
        key,
        value,
        create_revision: as_i64(&v["create_revision"]),
        mod_revision: as_i64(&v["mod_revision"]),
        lease: if lease == 0 { None } else { Some(lease) },
    })
}

impl EtcdStore {
    /// 连接 etcd（不建长连接，仅记 base + Agent），并探活一次（current_revision）。
    pub fn connect(endpoint: &str) -> Result<Self> {
        let base = endpoint.trim_end_matches('/').to_string();
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10))
            .build();
        let s = EtcdStore { base, agent };
        s.current_revision()?; // 探活：连不上/非 etcd 立即失败
        Ok(s)
    }

    /// POST 一个 JSON（非流式），校验 2xx，返回响应 JSON。
    /// 注：ureq 未开 `json` feature（守 sl-node 既有依赖口径），手动 serde_json 编解码。
    fn post(&self, path: &str, body: Value) -> Result<Value> {
        let url = format!("{}{path}", self.base);
        match self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
        {
            Ok(resp) => {
                let text = resp
                    .into_string()
                    .map_err(|e| StoreError::Backend(format!("{path} 读响应: {e}")))?;
                serde_json::from_str(&text)
                    .map_err(|e| StoreError::Backend(format!("{path} 响应非 JSON: {e}")))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let msg = resp.into_string().unwrap_or_default();
                Err(StoreError::Backend(format!("{path} HTTP {code}: {msg}")))
            }
            Err(e) => Err(StoreError::Backend(format!("{path} 传输错误: {e}"))),
        }
    }

    /// POST 一个 JSON 并返回流式 body 的读取器（watch/keepalive 用）。
    fn post_stream(&self, path: &str, body: Value) -> Result<Box<dyn std::io::Read + Send + Sync>> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .map_err(|e| StoreError::Backend(format!("{path} 传输: {e}")))?;
        Ok(resp.into_reader())
    }

    /// range 请求体：单键（range_end=None）或前缀（range_end=Some）。
    fn range_body(key: &[u8], range_end: Option<&[u8]>) -> Value {
        match range_end {
            Some(end) => json!({ "key": b64(key), "range_end": b64(end) }),
            None => json!({ "key": b64(key) }),
        }
    }
}

impl Store for EtcdStore {
    fn get(&self, key: &str) -> Result<Option<KeyValue>> {
        let resp = self.post("/v3/kv/range", Self::range_body(key.as_bytes(), None))?;
        match resp["kvs"].as_array().and_then(|a| a.first()) {
            Some(kv) => Ok(Some(kv_from_json(kv)?)),
            None => Ok(None),
        }
    }

    fn list(&self, prefix: &str) -> Result<Vec<KeyValue>> {
        let (key, end): (Vec<u8>, Vec<u8>) = if prefix.is_empty() {
            (vec![0], vec![0])
        } else {
            (prefix.as_bytes().to_vec(), range_end_for_prefix(prefix.as_bytes()))
        };
        let resp = self.post("/v3/kv/range", Self::range_body(&key, Some(&end)))?;
        let mut out = Vec::new();
        if let Some(kvs) = resp["kvs"].as_array() {
            for kv in kvs {
                out.push(kv_from_json(kv)?);
            }
        }
        // etcd 已按 key 升序返回；契约依赖有序
        Ok(out)
    }

    fn put(&self, key: &str, value: &[u8], lease: Option<LeaseId>) -> Result<Revision> {
        let mut body = json!({ "key": b64(key.as_bytes()), "value": b64(value) });
        if let Some(id) = lease {
            body["lease"] = json!(id.to_string());
        }
        let resp = self.post("/v3/kv/put", body)?;
        // 不存在的 lease：etcd 返 HTTP 错误（已在 post 映射为 Backend）；此处仅取 revision
        Ok(as_i64(&resp["header"]["revision"]))
    }

    fn delete(&self, key: &str) -> Result<bool> {
        let resp = self.post("/v3/kv/deleterange", Self::range_body(key.as_bytes(), None))?;
        Ok(as_i64(&resp["deleted"]) > 0)
    }

    fn compare_and_swap(
        &self,
        key: &str,
        expect_mod_rev: Option<Revision>,
        value: &[u8],
        lease: Option<LeaseId>,
    ) -> Result<CasResult> {
        let k = b64(key.as_bytes());
        // compare：Some(rev) → MOD == rev；None → CREATE == 0（即键不存在）
        let compare = match expect_mod_rev {
            Some(rev) => json!({ "key": k, "target": "MOD", "result": "EQUAL", "mod_revision": rev.to_string() }),
            None => json!({ "key": k, "target": "CREATE", "result": "EQUAL", "create_revision": "0" }),
        };
        let mut put_req = json!({ "key": k, "value": b64(value) });
        if let Some(id) = lease {
            put_req["lease"] = json!(id.to_string());
        }
        let body = json!({
            "compare": [compare],
            "success": [{ "request_put": put_req }],
            "failure": [{ "request_range": { "key": k } }],
        });
        let resp = self.post("/v3/kv/txn", body)?;
        let revision = as_i64(&resp["header"]["revision"]);
        let succeeded = resp["succeeded"].as_bool().unwrap_or(false);
        if succeeded {
            Ok(CasResult { succeeded: true, revision, current: None })
        } else {
            // failure 分支的 request_range 回带当前值（用于重试）
            let current = resp["responses"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|r| r["response_range"]["kvs"].as_array())
                .and_then(|a| a.first())
                .map(kv_from_json)
                .transpose()?;
            Ok(CasResult { succeeded: false, revision, current })
        }
    }

    fn lease_grant(&self, ttl_secs: i64) -> Result<LeaseId> {
        // etcd 最小有效 TTL 通常 >0；契约用 >=1。ID=0 让服务端分配。
        let resp = self.post("/v3/lease/grant", json!({ "TTL": ttl_secs.to_string(), "ID": "0" }))?;
        let id = as_i64(&resp["ID"]);
        if id == 0 {
            return Err(StoreError::Backend(format!("lease grant 未返回 ID: {resp}")));
        }
        Ok(id)
    }

    fn lease_keepalive(&self, id: LeaseId) -> Result<i64> {
        // keepalive 是流式；读首帧即可。TTL<=0 表租约不存在/已过期。
        let reader = self.post_stream("/v3/lease/keepalive", json!({ "ID": id.to_string() }))?;
        let mut buf = BufReader::new(reader);
        let mut line = String::new();
        buf.read_line(&mut line).map_err(|e| StoreError::Backend(format!("keepalive 读帧: {e}")))?;
        let frame: Value = serde_json::from_str(line.trim())
            .map_err(|e| StoreError::Backend(format!("keepalive 帧非 JSON: {e}")))?;
        let ttl = as_i64(&frame["result"]["TTL"]);
        if ttl <= 0 {
            return Err(StoreError::NoSuchLease(id));
        }
        Ok(now_unix() + ttl)
    }

    fn lease_revoke(&self, id: LeaseId) -> Result<Vec<String>> {
        // 先取挂载键（timetolive keys=true），再撤销——以对齐 trait「返回被删键」语义。
        let ttl_resp = self.post("/v3/lease/timetolive", json!({ "ID": id.to_string(), "keys": true }))?;
        let keys: Vec<String> = ttl_resp["keys"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|k| unb64(k).ok())
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        self.post("/v3/lease/revoke", json!({ "ID": id.to_string() }))?;
        Ok(keys)
    }

    fn lease_sweep(&self, _now_unix: i64) -> Result<Vec<String>> {
        // etcd 服务端按 TTL 自动过期，无需外部清扫器；no-op（键消失由服务端保证）。
        Ok(Vec::new())
    }

    fn current_revision(&self) -> Result<Revision> {
        // 任意 range 都回带 header.revision（全局）；用一个不太可能命中的探针键 + count_only。
        let body = json!({ "key": b64(b"_sl_rev_probe"), "count_only": true });
        let resp = self.post("/v3/kv/range", body)?;
        Ok(as_i64(&resp["header"]["revision"]))
    }

    fn changes_since(&self, since: Revision, prefix: &str) -> Result<Vec<Event>> {
        // 有界历史回放：watch(start_revision=since+1) 从头回放历史事件。
        // 停条件（关键，live 验证得来）：
        //   - etcd 先发一个 `created` ack 帧（header.revision 已=当前，**无 events**），
        //     绝不能据此 break——否则漏掉随后到达的历史事件帧；
        //   - 见到 revision>=target 的事件 → 已收全，break；
        //   - 否则历史耗尽后 etcd 阻塞等未来事件 → 用**短空闲读超时**探知「已 drain」，break。
        let target = self.current_revision()?;
        if since >= target {
            return Ok(Vec::new());
        }
        let (key, end): (Vec<u8>, Vec<u8>) = if prefix.is_empty() {
            (vec![0], vec![0])
        } else {
            (prefix.as_bytes().to_vec(), range_end_for_prefix(prefix.as_bytes()))
        };
        let create_req = json!({
            "key": b64(&key),
            "range_end": b64(&end),
            "start_revision": (since + 1).to_string(),
        });
        // 专用短空闲超时 agent：历史 drain 后 read 超时即视作「已追平」。
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_millis(1500))
            .build();
        let url = format!("{}/v3/watch", self.base);
        let body = json!({ "create_request": create_req }).to_string();
        let resp = agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| StoreError::Backend(format!("watch(历史) 传输: {e}")))?;
        let mut buf = BufReader::new(resp.into_reader());
        let mut out = Vec::new();
        let mut caught_up = false;
        let mut line = String::new();
        while !caught_up {
            line.clear();
            match buf.read_line(&mut line) {
                Ok(0) => break, // 流关闭
                Ok(_) => {}
                // 读超时 = 历史已 drain（etcd 转入等未来事件）→ 收全，停。
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => break,
                Err(e) => return Err(StoreError::Backend(format!("watch 读帧: {e}"))),
            }
            let frame: Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let result = &frame["result"];
            if let Some(evs) = result["events"].as_array() {
                for ev in evs {
                    let kv = &ev["kv"];
                    let rev = as_i64(&kv["mod_revision"]);
                    if rev <= since || rev > target {
                        continue;
                    }
                    let kind = if ev["type"].as_str() == Some("DELETE") {
                        EventKind::Delete
                    } else {
                        EventKind::Put
                    };
                    let k = String::from_utf8_lossy(&unb64(&kv["key"])?).into_owned();
                    let value = if kind == EventKind::Delete { Vec::new() } else { unb64(&kv["value"])? };
                    out.push(Event { kind, key: k, value, revision: rev });
                    if rev >= target {
                        caught_up = true; // 收到最末一次变更 → 收全
                    }
                }
            }
        }
        out.sort_by_key(|e| e.revision);
        Ok(out)
    }

    fn watch(&self, prefix: &str) -> Receiver<Event> {
        let (tx, rx) = channel();
        let base = self.base.clone();
        // 独立**无读超时** agent：watch 是长连接，空闲期须一直阻塞等未来事件
        // （不可复用 self.agent——它带 10s 读超时，空闲即误杀 watch 线程）。
        let agent = ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(5)).build();
        let (key, end): (Vec<u8>, Vec<u8>) = if prefix.is_empty() {
            (vec![0], vec![0])
        } else {
            (prefix.as_bytes().to_vec(), range_end_for_prefix(prefix.as_bytes()))
        };
        // 后台线程：开 /v3/watch 流（从当前起，仅未来事件），转发到 mpsc。
        // receiver 释放 → send 失败 → 线程退出。
        std::thread::spawn(move || {
            let create_req = json!({ "key": b64(&key), "range_end": b64(&end) });
            let body = json!({ "create_request": create_req }).to_string();
            let url = format!("{base}/v3/watch");
            let resp = match agent.post(&url).set("Content-Type", "application/json").send_string(&body) {
                Ok(r) => r,
                Err(_) => return,
            };
            let mut buf = BufReader::new(resp.into_reader());
            let mut line = String::new();
            loop {
                line.clear();
                match buf.read_line(&mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                let frame: Value = match serde_json::from_str(line.trim()) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(evs) = frame["result"]["events"].as_array() {
                    for ev in evs {
                        let kv = &ev["kv"];
                        let kind = if ev["type"].as_str() == Some("DELETE") {
                            EventKind::Delete
                        } else {
                            EventKind::Put
                        };
                        let k = match unb64(&kv["key"]) {
                            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
                            Err(_) => continue,
                        };
                        let value = if kind == EventKind::Delete {
                            Vec::new()
                        } else {
                            unb64(&kv["value"]).unwrap_or_default()
                        };
                        let out = Event { kind, key: k, value, revision: as_i64(&kv["mod_revision"]) };
                        if tx.send(out).is_err() {
                            return; // receiver 已释放
                        }
                    }
                }
            }
        });
        rx
    }

    fn compact(&self, below: Revision) -> Result<usize> {
        // etcd compaction 不回计数；对齐返回类型返回 0（契约不断言绝对计数）。
        self.post("/v3/kv/compaction", json!({ "revision": below.to_string() }))?;
        Ok(0)
    }
}
