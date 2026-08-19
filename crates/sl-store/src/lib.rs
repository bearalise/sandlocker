//! sl-store — 控制面窄元数据接口（M1 W1，D3 护栏②）。
//!
//! 形状照 etcd 收敛（revision / CAS / lease / watch），M1 用 SQLite 落地、单机进程内；
//! M3 若换 etcd，替换实现即可，控制面调用方按本 trait 编程、改动有界。
//!
//! 语义要点：
//!   - **revision**：全局单调计数，每次 put/delete/cas 成功 +1；每个键记 create_revision/mod_revision。
//!   - **CAS**：按 mod_revision 比对的比较-交换，是并发状态迁移的原子基元（etcd Txn 的最小子集）。
//!   - **lease**：TTL 键，`sweep(now)` 回收过期租约及其挂载的键——直接服务 Q9 的 TTL/idle/keepalive。
//!   - **watch**：`changes_since(rev, prefix)` 回放（含删除，靠有界 events 日志）+ 进程内 `watch()` mpsc 实时广播。
//!
//! 依赖仅 rusqlite（bundled sqlite），无系统库依赖。

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

pub type LeaseId = i64;
pub type Revision = i64;

/// 一个键值及其版本元数据（etcd KeyValue 的窄子集）。
#[derive(Debug, Clone, PartialEq)]
pub struct KeyValue {
    pub key: String,
    pub value: Vec<u8>,
    pub create_revision: Revision,
    pub mod_revision: Revision,
    pub lease: Option<LeaseId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Put,
    Delete,
}

/// 一次变更事件（watch / changes_since 的载荷）。删除事件的 value 为空。
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub kind: EventKind,
    pub key: String,
    pub value: Vec<u8>,
    pub revision: Revision,
}

/// CAS 结果：succeeded=false 时 current 为键当前值（比对失败方可据此重试）。
#[derive(Debug, Clone, PartialEq)]
pub struct CasResult {
    pub succeeded: bool,
    pub revision: Revision,
    pub current: Option<KeyValue>,
}

#[derive(Debug)]
pub enum StoreError {
    /// 底层存储错误（SQLite）。
    Backend(String),
    /// 引用了不存在的 lease。
    NoSuchLease(LeaseId),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Backend(e) => write!(f, "store backend: {e}"),
            StoreError::NoSuchLease(id) => write!(f, "no such lease: {id}"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Backend(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// 窄 store 接口。控制面按此编程；M1=SQLite，M3 可替换为 etcd 实现。
pub trait Store: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<KeyValue>>;
    fn list(&self, prefix: &str) -> Result<Vec<KeyValue>>;
    /// 写入并返回本次 revision。lease=Some 时该键随租约过期被回收。
    fn put(&self, key: &str, value: &[u8], lease: Option<LeaseId>) -> Result<Revision>;
    /// 删除，返回是否确有删除。
    fn delete(&self, key: &str) -> Result<bool>;
    /// 按 mod_revision 的比较-交换。expect=None 表示“键当前不存在”。
    fn compare_and_swap(
        &self,
        key: &str,
        expect_mod_rev: Option<Revision>,
        value: &[u8],
        lease: Option<LeaseId>,
    ) -> Result<CasResult>;

    fn lease_grant(&self, ttl_secs: i64) -> Result<LeaseId>;
    /// 续期，返回新的到期 unix 秒。
    fn lease_keepalive(&self, id: LeaseId) -> Result<i64>;
    /// 撤销租约并删除其挂载的所有键，返回被删的键。
    fn lease_revoke(&self, id: LeaseId) -> Result<Vec<String>>;
    /// 回收所有 expires_at <= now 的租约及其键，返回被删的键。
    fn lease_sweep(&self, now_unix: i64) -> Result<Vec<String>>;

    fn current_revision(&self) -> Result<Revision>;
    /// 回放 revision > since 且 key 以 prefix 起头的事件（含删除），按 revision 升序。
    fn changes_since(&self, since: Revision, prefix: &str) -> Result<Vec<Event>>;
    /// 订阅 prefix 前缀的实时变更（进程内 mpsc）。发送端随本次变更广播。
    fn watch(&self, prefix: &str) -> Receiver<Event>;
    /// 压实：删除 revision <= below 的 events 日志行（有界化，防无限增长）。
    fn compact(&self, below: Revision) -> Result<usize>;
}

struct Watcher {
    prefix: String,
    tx: Sender<Event>,
}

pub struct SqliteStore {
    conn: Mutex<Connection>,
    watchers: Mutex<Vec<Watcher>>,
}

impl SqliteStore {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS meta (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                current_rev INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO meta (id, current_rev) VALUES (0, 0);

            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                create_rev INTEGER NOT NULL,
                mod_rev INTEGER NOT NULL,
                lease_id INTEGER
            );

            CREATE TABLE IF NOT EXISTS leases (
                id INTEGER PRIMARY KEY,
                ttl_secs INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                rev INTEGER PRIMARY KEY,
                key TEXT NOT NULL,
                kind INTEGER NOT NULL,   -- 0=put 1=delete
                value BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_key ON events(key);
            "#,
        )?;
        Ok(Self { conn: Mutex::new(conn), watchers: Mutex::new(Vec::new()) })
    }

    /// 向匹配前缀的 watcher 广播；顺带清理已断开的 watcher。
    fn broadcast(&self, ev: &Event) {
        let mut ws = self.watchers.lock().unwrap();
        ws.retain(|w| {
            if ev.key.starts_with(&w.prefix) {
                w.tx.send(ev.clone()).is_ok()
            } else {
                true // 前缀不匹配的 watcher 保留（未断开）
            }
        });
    }
}

/// 下一个 revision（在给定连接/事务内自增 meta）。
fn bump_rev(conn: &Connection) -> rusqlite::Result<Revision> {
    conn.execute("UPDATE meta SET current_rev = current_rev + 1 WHERE id = 0", [])?;
    conn.query_row("SELECT current_rev FROM meta WHERE id = 0", [], |r| r.get(0))
}

fn append_event(conn: &Connection, rev: Revision, key: &str, kind: EventKind, value: &[u8]) -> rusqlite::Result<()> {
    let k = match kind {
        EventKind::Put => 0,
        EventKind::Delete => 1,
    };
    conn.execute(
        "INSERT INTO events (rev, key, kind, value) VALUES (?1, ?2, ?3, ?4)",
        params![rev, key, k, value],
    )?;
    Ok(())
}

fn row_to_kv(row: &rusqlite::Row<'_>) -> rusqlite::Result<KeyValue> {
    Ok(KeyValue {
        key: row.get(0)?,
        value: row.get(1)?,
        create_revision: row.get(2)?,
        mod_revision: row.get(3)?,
        lease: row.get(4)?,
    })
}

/// prefix 的 LIKE 上界（把 prefix 变成范围扫描，避免 LIKE 通配转义问题）。
/// 空 prefix → 全量。
fn prefix_range(prefix: &str) -> (String, Option<String>) {
    if prefix.is_empty() {
        return (String::new(), None);
    }
    // 末字节 +1 得到严格上界；若末字节是 0xFF 交界则退化为无上界（罕见）
    let mut end = prefix.as_bytes().to_vec();
    while let Some(last) = end.last().copied() {
        if last < 0xFF {
            *end.last_mut().unwrap() = last + 1;
            return (prefix.to_string(), Some(String::from_utf8_lossy(&end).into_owned()));
        }
        end.pop();
    }
    (prefix.to_string(), None)
}

impl Store for SqliteStore {
    fn get(&self, key: &str) -> Result<Option<KeyValue>> {
        let conn = self.conn.lock().unwrap();
        let kv = conn
            .query_row(
                "SELECT key, value, create_rev, mod_rev, lease_id FROM kv WHERE key = ?1",
                params![key],
                row_to_kv,
            )
            .optional()?;
        Ok(kv)
    }

    fn list(&self, prefix: &str) -> Result<Vec<KeyValue>> {
        let conn = self.conn.lock().unwrap();
        let (lo, hi) = prefix_range(prefix);
        let mut out = Vec::new();
        match hi {
            Some(hi) => {
                let mut stmt = conn.prepare(
                    "SELECT key, value, create_rev, mod_rev, lease_id FROM kv \
                     WHERE key >= ?1 AND key < ?2 ORDER BY key",
                )?;
                let rows = stmt.query_map(params![lo, hi], row_to_kv)?;
                for r in rows {
                    out.push(r?);
                }
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT key, value, create_rev, mod_rev, lease_id FROM kv \
                     WHERE key >= ?1 ORDER BY key",
                )?;
                let rows = stmt.query_map(params![lo], row_to_kv)?;
                for r in rows {
                    out.push(r?);
                }
            }
        }
        Ok(out)
    }

    fn put(&self, key: &str, value: &[u8], lease: Option<LeaseId>) -> Result<Revision> {
        let rev = {
            let conn = self.conn.lock().unwrap();
            if let Some(id) = lease {
                let exists: bool = conn
                    .query_row("SELECT 1 FROM leases WHERE id = ?1", params![id], |_| Ok(true))
                    .optional()?
                    .unwrap_or(false);
                if !exists {
                    return Err(StoreError::NoSuchLease(id));
                }
            }
            let rev = bump_rev(&conn)?;
            // create_rev：新键取本 rev，既有键沿用旧 create_rev
            conn.execute(
                "INSERT INTO kv (key, value, create_rev, mod_rev, lease_id) VALUES (?1, ?2, ?3, ?3, ?4) \
                 ON CONFLICT(key) DO UPDATE SET value = ?2, mod_rev = ?3, lease_id = ?4",
                params![key, value, rev, lease],
            )?;
            append_event(&conn, rev, key, EventKind::Put, value)?;
            rev
        };
        self.broadcast(&Event { kind: EventKind::Put, key: key.to_string(), value: value.to_vec(), revision: rev });
        Ok(rev)
    }

    fn delete(&self, key: &str) -> Result<bool> {
        let (removed, rev) = {
            let conn = self.conn.lock().unwrap();
            let n = conn.execute("DELETE FROM kv WHERE key = ?1", params![key])?;
            if n == 0 {
                return Ok(false);
            }
            let rev = bump_rev(&conn)?;
            append_event(&conn, rev, key, EventKind::Delete, &[])?;
            (true, rev)
        };
        if removed {
            self.broadcast(&Event { kind: EventKind::Delete, key: key.to_string(), value: Vec::new(), revision: rev });
        }
        Ok(removed)
    }

    fn compare_and_swap(
        &self,
        key: &str,
        expect_mod_rev: Option<Revision>,
        value: &[u8],
        lease: Option<LeaseId>,
    ) -> Result<CasResult> {
        let (result, ev) = {
            let conn = self.conn.lock().unwrap();
            let current: Option<KeyValue> = conn
                .query_row(
                    "SELECT key, value, create_rev, mod_rev, lease_id FROM kv WHERE key = ?1",
                    params![key],
                    row_to_kv,
                )
                .optional()?;
            let cur_mod = current.as_ref().map(|kv| kv.mod_revision);
            if cur_mod != expect_mod_rev {
                let cur_rev: Revision =
                    conn.query_row("SELECT current_rev FROM meta WHERE id = 0", [], |r| r.get(0))?;
                return Ok(CasResult { succeeded: false, revision: cur_rev, current });
            }
            let rev = bump_rev(&conn)?;
            let create_rev = current.as_ref().map(|kv| kv.create_revision).unwrap_or(rev);
            conn.execute(
                "INSERT INTO kv (key, value, create_rev, mod_rev, lease_id) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(key) DO UPDATE SET value = ?2, mod_rev = ?4, lease_id = ?5",
                params![key, value, create_rev, rev, lease],
            )?;
            append_event(&conn, rev, key, EventKind::Put, value)?;
            (
                CasResult { succeeded: true, revision: rev, current: None },
                Event { kind: EventKind::Put, key: key.to_string(), value: value.to_vec(), revision: rev },
            )
        };
        if result.succeeded {
            self.broadcast(&ev);
        }
        Ok(result)
    }

    fn lease_grant(&self, ttl_secs: i64) -> Result<LeaseId> {
        let conn = self.conn.lock().unwrap();
        let expires = now_unix() + ttl_secs;
        // id 用自增（取 max+1，避免依赖 rowid 语义）
        let id: LeaseId = conn
            .query_row("SELECT COALESCE(MAX(id), 0) + 1 FROM leases", [], |r| r.get(0))?;
        conn.execute(
            "INSERT INTO leases (id, ttl_secs, expires_at) VALUES (?1, ?2, ?3)",
            params![id, ttl_secs, expires],
        )?;
        Ok(id)
    }

    fn lease_keepalive(&self, id: LeaseId) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let ttl: Option<i64> = conn
            .query_row("SELECT ttl_secs FROM leases WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?;
        let ttl = ttl.ok_or(StoreError::NoSuchLease(id))?;
        let expires = now_unix() + ttl;
        conn.execute("UPDATE leases SET expires_at = ?1 WHERE id = ?2", params![expires, id])?;
        Ok(expires)
    }

    fn lease_revoke(&self, id: LeaseId) -> Result<Vec<String>> {
        self.reap_leases("SELECT id FROM leases WHERE id = ?1", Some(id))
    }

    fn lease_sweep(&self, now_unix: i64) -> Result<Vec<String>> {
        self.reap_leases("SELECT id FROM leases WHERE expires_at <= ?1", Some(now_unix))
    }

    fn current_revision(&self) -> Result<Revision> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT current_rev FROM meta WHERE id = 0", [], |r| r.get(0))?)
    }

    fn changes_since(&self, since: Revision, prefix: &str) -> Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
        let (lo, hi) = prefix_range(prefix);
        let mut out = Vec::new();
        let map = |row: &rusqlite::Row<'_>| -> rusqlite::Result<Event> {
            let kind = if row.get::<_, i64>(2)? == 0 { EventKind::Put } else { EventKind::Delete };
            Ok(Event { revision: row.get(0)?, key: row.get(1)?, kind, value: row.get(3)? })
        };
        match hi {
            Some(hi) => {
                let mut stmt = conn.prepare(
                    "SELECT rev, key, kind, value FROM events \
                     WHERE rev > ?1 AND key >= ?2 AND key < ?3 ORDER BY rev",
                )?;
                for r in stmt.query_map(params![since, lo, hi], map)? {
                    out.push(r?);
                }
            }
            None if prefix.is_empty() => {
                let mut stmt =
                    conn.prepare("SELECT rev, key, kind, value FROM events WHERE rev > ?1 ORDER BY rev")?;
                for r in stmt.query_map(params![since], map)? {
                    out.push(r?);
                }
            }
            None => {
                let mut stmt = conn.prepare(
                    "SELECT rev, key, kind, value FROM events WHERE rev > ?1 AND key >= ?2 ORDER BY rev",
                )?;
                for r in stmt.query_map(params![since, lo], map)? {
                    out.push(r?);
                }
            }
        }
        Ok(out)
    }

    fn watch(&self, prefix: &str) -> Receiver<Event> {
        let (tx, rx) = channel();
        self.watchers.lock().unwrap().push(Watcher { prefix: prefix.to_string(), tx });
        rx
    }

    fn compact(&self, below: Revision) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute("DELETE FROM events WHERE rev <= ?1", params![below])?;
        Ok(n)
    }
}

impl SqliteStore {
    /// 撤销/清扫共用：删除选中的 lease 及其挂载的键，广播删除事件，返回被删键。
    fn reap_leases(&self, select_sql: &str, arg: Option<i64>) -> Result<Vec<String>> {
        let mut deleted_keys: Vec<(String, Revision)> = Vec::new();
        {
            let conn = self.conn.lock().unwrap();
            let ids: Vec<LeaseId> = {
                let mut stmt = conn.prepare(select_sql)?;
                let rows = stmt.query_map(params![arg], |r| r.get::<_, LeaseId>(0))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for id in ids {
                let keys: Vec<String> = {
                    let mut stmt = conn.prepare("SELECT key FROM kv WHERE lease_id = ?1")?;
                    let rows = stmt.query_map(params![id], |r| r.get::<_, String>(0))?;
                    rows.collect::<rusqlite::Result<Vec<_>>>()?
                };
                for k in keys {
                    conn.execute("DELETE FROM kv WHERE key = ?1", params![k])?;
                    let rev = bump_rev(&conn)?;
                    append_event(&conn, rev, &k, EventKind::Delete, &[])?;
                    deleted_keys.push((k, rev));
                }
                conn.execute("DELETE FROM leases WHERE id = ?1", params![id])?;
            }
        }
        let out: Vec<String> = deleted_keys.iter().map(|(k, _)| k.clone()).collect();
        for (k, rev) in deleted_keys {
            self.broadcast(&Event { kind: EventKind::Delete, key: k, value: Vec::new(), revision: rev });
        }
        Ok(out)
    }
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SqliteStore {
        SqliteStore::open_in_memory().unwrap()
    }

    #[test]
    fn put_get_delete_and_revision_monotonic() {
        let s = store();
        assert_eq!(s.current_revision().unwrap(), 0);
        let r1 = s.put("sandbox/a", b"1", None).unwrap();
        let r2 = s.put("sandbox/b", b"2", None).unwrap();
        assert!(r2 > r1);
        let a = s.get("sandbox/a").unwrap().unwrap();
        assert_eq!(a.value, b"1");
        assert_eq!(a.create_revision, r1);
        assert_eq!(a.mod_revision, r1);
        // 覆盖写：create_rev 不变，mod_rev 前进
        let r3 = s.put("sandbox/a", b"1b", None).unwrap();
        let a = s.get("sandbox/a").unwrap().unwrap();
        assert_eq!(a.create_revision, r1);
        assert_eq!(a.mod_revision, r3);
        assert!(s.delete("sandbox/a").unwrap());
        assert!(!s.delete("sandbox/a").unwrap());
        assert!(s.get("sandbox/a").unwrap().is_none());
    }

    #[test]
    fn list_prefix_is_scoped() {
        let s = store();
        s.put("sandbox/a", b"1", None).unwrap();
        s.put("sandbox/b", b"2", None).unwrap();
        s.put("template/x", b"9", None).unwrap();
        let got: Vec<String> = s.list("sandbox/").unwrap().into_iter().map(|kv| kv.key).collect();
        assert_eq!(got, vec!["sandbox/a", "sandbox/b"]);
        assert_eq!(s.list("").unwrap().len(), 3);
    }

    #[test]
    fn cas_guards_concurrent_transition() {
        let s = store();
        // 期望键不存在（None）→ 首次创建成功
        let r = s.compare_and_swap("state", None, b"creating", None).unwrap();
        assert!(r.succeeded);
        let mod_rev = s.get("state").unwrap().unwrap().mod_revision;
        // 用过期的 expect（None）→ 失败并回带当前值
        let r = s.compare_and_swap("state", None, b"running", None).unwrap();
        assert!(!r.succeeded);
        assert_eq!(r.current.unwrap().value, b"creating");
        // 用正确 mod_rev → 成功
        let r = s.compare_and_swap("state", Some(mod_rev), b"running", None).unwrap();
        assert!(r.succeeded);
        assert_eq!(s.get("state").unwrap().unwrap().value, b"running");
    }

    #[test]
    fn lease_sweep_reaps_attached_keys() {
        let s = store();
        let lease = s.lease_grant(0).unwrap(); // ttl=0 → 立刻可过期
        s.put("sandbox/ephemeral", b"x", Some(lease)).unwrap();
        s.put("sandbox/persistent", b"y", None).unwrap();
        // put 到不存在的 lease 应报错
        assert!(matches!(s.put("k", b"v", Some(9999)), Err(StoreError::NoSuchLease(9999))));
        // sweep（now 远大于到期）回收挂载键，不动无租约键
        let reaped = s.lease_sweep(now_unix() + 10).unwrap();
        assert_eq!(reaped, vec!["sandbox/ephemeral"]);
        assert!(s.get("sandbox/ephemeral").unwrap().is_none());
        assert!(s.get("sandbox/persistent").unwrap().is_some());
    }

    #[test]
    fn lease_keepalive_defers_expiry() {
        let s = store();
        let lease = s.lease_grant(3600).unwrap();
        s.put("k", b"v", Some(lease)).unwrap();
        let new_exp = s.lease_keepalive(lease).unwrap();
        assert!(new_exp >= now_unix());
        // 未到期 → sweep 不回收
        let reaped = s.lease_sweep(now_unix()).unwrap();
        assert!(reaped.is_empty());
        assert!(s.get("k").unwrap().is_some());
        assert!(matches!(s.lease_keepalive(9999), Err(StoreError::NoSuchLease(9999))));
    }

    #[test]
    fn changes_since_replays_puts_and_deletes() {
        let s = store();
        let r0 = s.current_revision().unwrap();
        s.put("sandbox/a", b"1", None).unwrap();
        s.put("template/x", b"9", None).unwrap();
        s.delete("sandbox/a").unwrap();
        // 仅 sandbox/ 前缀，从 r0 起
        let evs = s.changes_since(r0, "sandbox/").unwrap();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].kind, EventKind::Put);
        assert_eq!(evs[1].kind, EventKind::Delete);
        assert!(evs[0].revision < evs[1].revision);
        // 全量前缀看到 3 个事件
        assert_eq!(s.changes_since(r0, "").unwrap().len(), 3);
    }

    #[test]
    fn watch_broadcasts_matching_prefix_only() {
        let s = store();
        let rx = s.watch("sandbox/");
        s.put("sandbox/a", b"1", None).unwrap();
        s.put("template/x", b"9", None).unwrap(); // 不该收到
        s.delete("sandbox/a").unwrap();
        let e1 = rx.try_recv().unwrap();
        assert_eq!((e1.kind, e1.key.as_str()), (EventKind::Put, "sandbox/a"));
        let e2 = rx.try_recv().unwrap();
        assert_eq!(e2.kind, EventKind::Delete);
        assert!(rx.try_recv().is_err()); // template/x 未广播给本 watcher
    }

    #[test]
    fn compact_prunes_old_events() {
        let s = store();
        s.put("a", b"1", None).unwrap();
        let cut = s.current_revision().unwrap();
        s.put("b", b"2", None).unwrap();
        let pruned = s.compact(cut).unwrap();
        assert_eq!(pruned, 1);
        // 压实后从头回放只剩 cut 之后的事件
        assert_eq!(s.changes_since(0, "").unwrap().len(), 1);
    }
}
