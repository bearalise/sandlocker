//! 后端无关的 leader 选举（M3 W2，M3-Q2）——建在 `Store` trait 之上（CAS + lease）。
//!
//! 目标：orchestrator 多副本 active-standby。**同一套代码**在两后端成立：
//!   - 单机 SQLite：单竞选者，首次 CAS 即当选（退化为「恒 leader」，零行为变化）。
//!   - 集群 etcd：多副本竞争同一 `cluster/leader` 键，仅一胜；leader 崩溃后其 lease 过期
//!     → 键自动释放（etcd 服务端 TTL / SQLite `lease_sweep`）→ standby 夺主。
//!
//! 机制（etcd election 原语的窄接口投影）：
//!   - 竞选 = `lease_grant(ttl)` + `compare_and_swap(key, expect=None, node_id, lease)`；
//!     `expect=None` 语义「键当前不存在」→ 天然互斥，只有一个 CAS 成功。
//!   - 保持 = 周期 `lease_keepalive`（调用方驱动，见 [`Election::try_campaign`]）。
//!   - 让位/崩溃 = `lease_revoke`（主动）或 lease 过期（被动）→ 键消失 → 他人可夺。
//!
//! 失位后夺主如何发生：
//!   - **etcd（真多副本）**：leader 崩溃 → 其 lease 由 etcd 服务端按 TTL **自动过期** →
//!     leader 键被服务端删除 → standby 的 `CAS(expect=None)` 随即成功。无需任何清扫器。
//!   - **SQLite（单机单副本）**：PRD 定单机无选主——唯一参与者首次即恒当选、不发生 failover。
//!
//! ⚠️ **本模块刻意不调用 `lease_sweep`**：选举常与 orchestrator 共享同一 store，全局 sweep 会误扫
//! **沙箱租约键**、与 reaper（`Orch::tick`）抢清扫、破坏 Orch 的内存态一致性。leader 键的释放
//! 交给 etcd 服务端自动过期（多副本）或不发生（单机）。
//!
//! 无内部线程：调用方周期调 `try_campaign`（续租或夺主），便于测试与两后端一致。

use crate::{LeaseId, Result, Store};

/// 选主键（控制面元数据命名空间；与 sandbox/template 前缀不冲突）。
pub const LEADER_KEY: &str = "cluster/leader";

/// 一个选举参与者。持有自己的 store 句柄（etcd：独立连接；SQLite：同文件另一连接）。
pub struct Election {
    store: Box<dyn Store>,
    key: String,
    node_id: String,
    ttl_secs: i64,
    /// Some(lease) 表当前持有 leadership。
    lease: Option<LeaseId>,
}

impl Election {
    /// `node_id` 建议全局唯一（如 host:pid）；`ttl_secs` 为 leader 租约窗（崩溃后至多这么久失联）。
    pub fn new(store: Box<dyn Store>, node_id: &str, ttl_secs: i64) -> Self {
        Election { store, key: LEADER_KEY.to_string(), node_id: node_id.to_string(), ttl_secs, lease: None }
    }

    /// 自定义选主键（多组独立选举时用）。
    pub fn with_key(mut self, key: &str) -> Self {
        self.key = key.to_string();
        self
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// 当前是否为 leader（上次 `try_campaign` 的结论）。
    pub fn is_leader(&self) -> bool {
        self.lease.is_some()
    }

    /// 竞选一次（非阻塞）：已是 leader 则续租，否则尝试夺主。返回「本次结束后是否为 leader」。
    ///
    /// 调用方应以约 `ttl/3` 周期调用：既及时续租（防自身租约过期误失位），
    /// 又在旧 leader 失联后（其键过期释放）及时夺主。
    pub fn try_campaign(&mut self) -> Result<bool> {
        // 注意：**不**调用全局 lease_sweep（见模块文档）——避免误扫与 orchestrator 共享 store 的
        // 沙箱租约键。崩溃 leader 键的释放由 etcd 服务端 TTL 自动过期承担（多副本），单机不发生。

        // 已是 leader：续租 + 确认键仍属己。
        if let Some(lease) = self.lease {
            match self.store.lease_keepalive(lease) {
                Ok(_) if self.holds_leadership()? => return Ok(true),
                _ => self.lease = None, // 租约没了 / 键被别人占 → 失位，转入竞选
            }
        }

        // 竞选：grant 新租约 + CAS(键不存在 → 写入 node_id 并挂租约)。
        let lease = self.store.lease_grant(self.ttl_secs)?;
        let r = self.store.compare_and_swap(&self.key, None, self.node_id.as_bytes(), Some(lease))?;
        if r.succeeded {
            self.lease = Some(lease);
            Ok(true)
        } else {
            // 没抢到（已有 leader）→ 撤销刚 grant 的租约，避免泄漏。
            let _ = self.store.lease_revoke(lease);
            Ok(false)
        }
    }

    /// 键当前是否存在且值为本节点 id。
    fn holds_leadership(&self) -> Result<bool> {
        Ok(self
            .store
            .get(&self.key)?
            .map(|kv| kv.value == self.node_id.as_bytes())
            .unwrap_or(false))
    }

    /// 主动让位：撤租 → 删键 → 他人可立即夺主。幂等。
    pub fn resign(&mut self) -> Result<()> {
        if let Some(lease) = self.lease.take() {
            self.store.lease_revoke(lease)?;
        }
        Ok(())
    }

    /// 读当前 leader 的 node_id（用于观测/路由；None=当前无 leader）。
    pub fn current_leader(&self) -> Result<Option<String>> {
        Ok(self.store.get(&self.key)?.map(|kv| String::from_utf8_lossy(&kv.value).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteStore;

    /// 双竞选者共享同一 SQLite 文件：只有一个当选；resign 后另一个可夺主（无双主）。
    #[test]
    fn single_leader_and_resign_failover() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sl-election-{}.db", std::process::id()));
        let p = path.to_string_lossy().to_string();
        // 预清理
        let _ = std::fs::remove_file(&p);

        let sa = Box::new(SqliteStore::open(&p).unwrap());
        let sb = Box::new(SqliteStore::open(&p).unwrap());
        let mut a = Election::new(sa, "node-a", 30);
        let mut b = Election::new(sb, "node-b", 30);

        // A 先竞选 → 当选；B 竞选 → 落败。任一时刻至多一个 leader。
        assert!(a.try_campaign().unwrap(), "A 应当选");
        assert!(!b.try_campaign().unwrap(), "B 应落败（A 持有）");
        assert!(a.is_leader() && !b.is_leader(), "至多一个 leader");
        assert_eq!(b.current_leader().unwrap().as_deref(), Some("node-a"));

        // A 续租仍为 leader；B 仍落败。
        assert!(a.try_campaign().unwrap(), "A 续租应仍为 leader");
        assert!(!b.try_campaign().unwrap(), "B 仍应落败");

        // A 让位 → B 夺主。
        a.resign().unwrap();
        assert!(!a.is_leader());
        assert!(b.try_campaign().unwrap(), "A 让位后 B 应夺主");
        assert!(!a.try_campaign().unwrap(), "此时 A 应落败（B 持有）");
        assert!(b.is_leader() && !a.is_leader(), "至多一个 leader（换 B）");

        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(format!("{p}-wal"));
        let _ = std::fs::remove_file(format!("{p}-shm"));
    }

    /// 回归护栏：选举与「沙箱」共享同一 store 时，`try_campaign` **不得**清扫沙箱租约键
    /// （否则与 orchestrator 的 reaper 抢清扫、破坏其内存态）。这是选举刻意不做全局 sweep 的约束。
    #[test]
    fn campaign_does_not_reap_colocated_sandbox_leases() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sl-election-noreap-{}.db", std::process::id()));
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&p);

        // 一个句柄扮演 orchestrator：放一个**已可过期**（ttl=0）的沙箱租约键。
        let sandbox = SqliteStore::open(&p).unwrap();
        let lease = sandbox.lease_grant(0).unwrap();
        sandbox.put("sandbox/x/meta", b"m", Some(lease)).unwrap();

        // 另一个句柄跑选举并当选。
        let mut e = Election::new(Box::new(SqliteStore::open(&p).unwrap()), "node-a", 30);
        assert!(e.try_campaign().unwrap(), "应当选");
        // 再续租一次（触发 keepalive 路径），仍不得触碰沙箱键。
        assert!(e.try_campaign().unwrap(), "续租应仍为 leader");

        // 关键断言：沙箱租约键即便已过期，也**没被选举清扫**（交给 reaper）。
        assert!(
            sandbox.get("sandbox/x/meta").unwrap().is_some(),
            "选举竞选不得清扫共享 store 上的沙箱租约键"
        );

        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(format!("{p}-wal"));
        let _ = std::fs::remove_file(format!("{p}-shm"));
    }
}
