//! 节点心跳 + 失联自动回收（M3 W3，M3-Q2）——建在 `Store` trait 之上（lease + list）。
//!
//! 易失态（PRD 7.10 / ADR-17）：**节点心跳走 lease TTL**。节点在 `node/<id>` 写一个挂租约的
//! 存活键并周期续租（心跳）；崩溃/失联 → 租约到期 → 键消失（etcd 服务端自动过期 / SQLite `lease_sweep`）
//! → 该节点名下沙箱成为**孤儿**，由 leader 的对账回收（撤租连带删 meta/state/node）。
//!
//! 沙箱归属：创建时在 `sandbox/<sid>/node` 写 owning node id（与 meta/state **同一租约**，
//! 故回收撤租即三键一并删）。回收只做**store 层**清理（把死节点的沙箱从集群账面移除）；死节点的
//! 本地磁盘产物由该节点重启后自行对账（节点侧清理，非本模块职责）。
//!
//! 全后端无关：SQLite（单机，节点恒存活、无孤儿）与 etcd（多副本，真失联回收）同一套代码。

use crate::{LeaseId, Result, Store};
use std::collections::HashSet;

/// 节点存活键前缀。
pub const NODE_PREFIX: &str = "node/";

/// 节点存活键：`node/<id>`（挂心跳租约）。
pub fn node_key(id: &str) -> String {
    format!("node/{id}")
}

/// 沙箱归属键：`sandbox/<sid>/node`（值=owning node id；与该沙箱 meta/state 同租约）。
pub fn sandbox_node_key(sid: &str) -> String {
    format!("sandbox/{sid}/node")
}

/// 注册本节点：grant 心跳租约 + 写 `node/<id>`（挂该租约）。返回租约 id 供周期心跳。
pub fn register_node(store: &dyn Store, node_id: &str, meta: &[u8], ttl_secs: i64) -> Result<LeaseId> {
    let lease = store.lease_grant(ttl_secs)?;
    store.put(&node_key(node_id), meta, Some(lease))?;
    Ok(lease)
}

/// 心跳续租（节点周期调，约 ttl/3）。返回新到期 unix 秒。
pub fn heartbeat(store: &dyn Store, lease: LeaseId) -> Result<i64> {
    store.lease_keepalive(lease)
}

/// 当前存活节点 id 集（`node/` 前缀，未过期者）。
pub fn live_nodes(store: &dyn Store) -> Result<Vec<String>> {
    Ok(store
        .list(NODE_PREFIX)?
        .into_iter()
        .filter_map(|kv| kv.key.strip_prefix(NODE_PREFIX).map(|s| s.to_string()))
        .collect())
}

/// 回收 owning node 已失联的沙箱：撤其租约（连带删 meta/state/node），返回被回收沙箱 id。
///
/// 仅回收带 `sandbox/<sid>/node` 归属键、且 owner 不在存活集里的沙箱；无归属键的沙箱
/// （单机遗留 / owner 未知）不动，安全。leader 周期调用。
///
/// `protect`：安全护栏——**永不回收**该 owner（本节点自己）名下的沙箱，即便其心跳偶发失效
/// （节点只回收**别的**死节点的沙箱，绝不自戕）。调用方传自身 node id；对账传 None。
pub fn reclaim_orphans(store: &dyn Store, protect: Option<&str>) -> Result<Vec<String>> {
    let live: HashSet<String> = live_nodes(store)?.into_iter().collect();
    let mut reclaimed = Vec::new();
    for kv in store.list("sandbox/")? {
        // 只认归属键 sandbox/<sid>/node
        let sid = match kv
            .key
            .strip_prefix("sandbox/")
            .and_then(|s| s.strip_suffix("/node"))
        {
            Some(s) => s.to_string(),
            None => continue,
        };
        let owner = String::from_utf8_lossy(&kv.value).into_owned();
        if live.contains(&owner) || protect == Some(owner.as_str()) {
            continue; // owner 存活 or 是本节点自己（护栏）→ 不回收
        }
        // 失联 owner：撤租（删 meta/state/node 三键）；无租约则兜底逐删。
        match kv.lease {
            Some(lease) => {
                store.lease_revoke(lease)?;
            }
            None => {
                let _ = store.delete(&kv.key)?;
            }
        }
        reclaimed.push(sid);
    }
    Ok(reclaimed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteStore;

    /// 节点失联 → 其名下沙箱被回收；存活节点的沙箱不受影响。
    #[test]
    fn dead_node_sandboxes_reclaimed_live_untouched() {
        let s = SqliteStore::open_in_memory().unwrap();

        // 两节点存活（ttl 大，不自动过期）。
        let _la = register_node(&s, "node-a", b"a", 3600).unwrap();
        let lb = register_node(&s, "node-b", b"b", 3600).unwrap();
        assert_eq!(live_nodes(&s).unwrap().len(), 2);

        // s1 属 A、s2 属 B：meta/state/node 同租约。
        let l1 = s.lease_grant(3600).unwrap();
        s.put("sandbox/s1/meta", b"{}", Some(l1)).unwrap();
        s.put("sandbox/s1/state", b"running", Some(l1)).unwrap();
        s.put(&sandbox_node_key("s1"), b"node-a", Some(l1)).unwrap();
        let l2 = s.lease_grant(3600).unwrap();
        s.put("sandbox/s2/meta", b"{}", Some(l2)).unwrap();
        s.put("sandbox/s2/state", b"running", Some(l2)).unwrap();
        s.put(&sandbox_node_key("s2"), b"node-b", Some(l2)).unwrap();

        // 都存活 → 无回收。
        assert!(reclaim_orphans(&s, None).unwrap().is_empty());

        // A 失联：撤销其心跳租约 → node/node-a 消失。
        let _ = lb; // B 心跳租约保留
        s.lease_revoke(_la).unwrap();
        assert_eq!(live_nodes(&s).unwrap(), vec!["node-b"]);

        // 回收：s1（属死节点 A）被清，s2（属存活 B）不动。
        let reclaimed = reclaim_orphans(&s, None).unwrap();
        assert_eq!(reclaimed, vec!["s1"]);
        assert!(s.get("sandbox/s1/meta").unwrap().is_none());
        assert!(s.get("sandbox/s1/state").unwrap().is_none());
        assert!(s.get(&sandbox_node_key("s1")).unwrap().is_none());
        assert!(s.get("sandbox/s2/meta").unwrap().is_some());
        assert!(s.get(&sandbox_node_key("s2")).unwrap().is_some());

        // 再回收幂等（s1 已清，s2 仍活）。
        assert!(reclaim_orphans(&s, None).unwrap().is_empty());
    }

    /// 安全护栏：即便本节点心跳失效（node 键没了），也**绝不回收自己**名下的沙箱。
    #[test]
    fn protect_never_reclaims_own_sandboxes() {
        let s = SqliteStore::open_in_memory().unwrap();
        // 本节点 self 的沙箱，但 self 的 node 键**不存在**（模拟自身心跳偶发失效）。
        let l = s.lease_grant(3600).unwrap();
        s.put("sandbox/mine/meta", b"{}", Some(l)).unwrap();
        s.put(&sandbox_node_key("mine"), b"self", Some(l)).unwrap();
        // 无护栏 → 会被当孤儿回收；有护栏 protect=self → 保住。
        assert_eq!(reclaim_orphans(&s, None).unwrap(), vec!["mine"].clone());
        // 复置后带护栏验证
        let l2 = s.lease_grant(3600).unwrap();
        s.put("sandbox/mine2/meta", b"{}", Some(l2)).unwrap();
        s.put(&sandbox_node_key("mine2"), b"self", Some(l2)).unwrap();
        assert!(reclaim_orphans(&s, Some("self")).unwrap().is_empty(), "护栏应保住自身沙箱");
        assert!(s.get("sandbox/mine2/meta").unwrap().is_some());
    }

    /// 无归属键的沙箱（单机遗留）不被回收。
    #[test]
    fn sandbox_without_owner_key_is_never_reclaimed() {
        let s = SqliteStore::open_in_memory().unwrap();
        let l = s.lease_grant(3600).unwrap();
        s.put("sandbox/legacy/meta", b"{}", Some(l)).unwrap();
        s.put("sandbox/legacy/state", b"running", Some(l)).unwrap();
        // 无 sandbox/legacy/node → 不参与回收。
        assert!(reclaim_orphans(&s, None).unwrap().is_empty());
        assert!(s.get("sandbox/legacy/meta").unwrap().is_some());
    }
}
