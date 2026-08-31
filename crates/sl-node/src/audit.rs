//! audit.rs — 审计日志（M3 W7，FR-7.3）。全部 API 变更操作 append-only 记录，可查询。
//!
//! 后端无关（`Store` trait）。条目键 `audit/<ts>-<seq>`（时间近似有序 + 进程内单调 seq 防同秒撞键）；
//! **只 put 新键、绝不改/删**（append-only 不可篡改；保留期/GC 属 ADR-16，后续）。
//! 值 = JSON `{ts, actor, action, target, code}`（actor=项目 或 "-"；code=HTTP 状态）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sl_store::Store;

use crate::json_escape;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 追加一条审计条目（append-only）。失败仅返回 Err 供调用方决定是否忽略（审计不应阻断主流程）。
pub fn record(store: &dyn Store, actor: &str, action: &str, target: &str, code: u16) -> Result<(), String> {
    let ts = now_unix();
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    // 键：ts 十进制定宽 + 单调 seq（同秒不撞）；append-only。
    let key = format!("audit/{ts:012}-{seq:08}");
    let val = format!(
        r#"{{"ts":{ts},"actor":"{}","action":"{}","target":"{}","code":{code}}}"#,
        json_escape(actor),
        json_escape(action),
        json_escape(target)
    );
    store.put(&key, val.as_bytes(), None).map_err(|e| e.to_string())?;
    Ok(())
}

/// 查询审计条目（升序）。`prefix_filter` 为空返回全部（供 GET/审计导出；保留期裁剪属 ADR-16）。
pub fn list(store: &dyn Store) -> Result<Vec<String>, String> {
    let kvs = store.list("audit/").map_err(|e| e.to_string())?;
    Ok(kvs.into_iter().map(|kv| String::from_utf8_lossy(&kv.value).into_owned()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sl_store::SqliteStore;

    #[test]
    fn append_only_ordered_and_queryable() {
        let s = SqliteStore::open_in_memory().unwrap();
        record(&s, "projA", "create_sandbox", "sb1", 201).unwrap();
        record(&s, "projA", "delete_sandbox", "sb1", 204).unwrap();
        record(&s, "projB", "exec", "sb9", 200).unwrap();
        let entries = list(&s).unwrap();
        assert_eq!(entries.len(), 3, "三条审计");
        assert!(entries[0].contains("create_sandbox") && entries[0].contains("projA"));
        assert!(entries[1].contains("delete_sandbox"));
        // append-only：条目数只增（再记一条 → 4，前 3 条不变）。
        record(&s, "projB", "exec", "sb9", 200).unwrap();
        assert_eq!(list(&s).unwrap().len(), 4);
    }
}
