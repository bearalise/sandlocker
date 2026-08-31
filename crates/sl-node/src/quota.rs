//! quota.rs — 按项目配额（M3 W7，FR-7.2）。CPU 总量 / 内存总量 / 并发沙箱数，按项目维度。
//!
//! 后端无关（`Store` trait）。限额存 `quota/<project>` = JSON `{max_sandboxes,max_vcpus,max_mem_mib}`
//! （某字段 0 = 该维度不限）。**用量按当前状态实时计算**（遍历该项目沙箱 meta 累加，crash-safe——
//! 不维护易漂移的增量计数器）。create/fork **前置检查**：投影用量超限即 `QUOTA_EXCEEDED`（ADR-25 语义）。

use serde_json::Value;
use sl_store::Store;

/// 配额超限错误前缀（对齐 UNSUPPORTED_BY_BACKEND 风格，调用方可据此判类）。
pub const QUOTA_EXCEEDED: &str = "QUOTA_EXCEEDED";

/// 项目限额（0 = 该维度不限）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits {
    pub max_sandboxes: u64,
    pub max_vcpus: u64,
    pub max_mem_mib: u64,
}

fn quota_key(project: &str) -> String {
    format!("quota/{project}")
}

/// 设置项目限额。
pub fn set_limits(store: &dyn Store, project: &str, l: Limits) -> Result<(), String> {
    let json = format!(
        r#"{{"max_sandboxes":{},"max_vcpus":{},"max_mem_mib":{}}}"#,
        l.max_sandboxes, l.max_vcpus, l.max_mem_mib
    );
    store.put(&quota_key(project), json.as_bytes(), None).map_err(|e| e.to_string())?;
    Ok(())
}

/// 读项目限额（None = 未设 = 不限）。
pub fn get_limits(store: &dyn Store, project: &str) -> Result<Option<Limits>, String> {
    let kv = store.get(&quota_key(project)).map_err(|e| e.to_string())?;
    Ok(kv.and_then(|kv| {
        let v: Value = serde_json::from_slice(&kv.value).ok()?;
        Some(Limits {
            max_sandboxes: v.get("max_sandboxes").and_then(|x| x.as_u64()).unwrap_or(0),
            max_vcpus: v.get("max_vcpus").and_then(|x| x.as_u64()).unwrap_or(0),
            max_mem_mib: v.get("max_mem_mib").and_then(|x| x.as_u64()).unwrap_or(0),
        })
    }))
}

/// 项目当前用量：`(并发沙箱数, vcpus 合计, mem_mib 合计)`。遍历该项目沙箱 meta 实时累加。
pub fn usage(store: &dyn Store, project: &str) -> Result<(u64, u64, u64), String> {
    let kvs = store.list("sandbox/").map_err(|e| e.to_string())?;
    // id→project 映射。
    let mut proj = std::collections::HashMap::new();
    for kv in &kvs {
        if let Some(id) = kv.key.strip_prefix("sandbox/").and_then(|s| s.strip_suffix("/project")) {
            proj.insert(id.to_string(), String::from_utf8_lossy(&kv.value).into_owned());
        }
    }
    let (mut count, mut vcpus, mut mem) = (0u64, 0u64, 0u64);
    for kv in &kvs {
        let id = match kv.key.strip_prefix("sandbox/").and_then(|s| s.strip_suffix("/meta")) {
            Some(id) => id,
            None => continue,
        };
        if proj.get(id).map(|p| p == project).unwrap_or(false) {
            count += 1;
            if let Ok(v) = serde_json::from_slice::<Value>(&kv.value) {
                vcpus += v.get("vcpus").and_then(|x| x.as_u64()).unwrap_or(0);
                mem += v.get("mem_mib").and_then(|x| x.as_u64()).unwrap_or(0);
            }
        }
    }
    Ok((count, vcpus, mem))
}

/// create/fork 前置配额检查：投影（当前用量 + 本次 add）超任一已设限额即 `QUOTA_EXCEEDED`。
/// 未设限额（None）→ 放行。
pub fn check(store: &dyn Store, project: &str, add_vcpus: u64, add_mem: u64) -> Result<(), String> {
    let lim = match get_limits(store, project)? {
        Some(l) => l,
        None => return Ok(()), // 未设配额 = 不限
    };
    let (count, vcpus, mem) = usage(store, project)?;
    if lim.max_sandboxes > 0 && count + 1 > lim.max_sandboxes {
        return Err(format!("{QUOTA_EXCEEDED}: 项目 {project} 并发沙箱数超限（{}/{}）", count + 1, lim.max_sandboxes));
    }
    if lim.max_vcpus > 0 && vcpus + add_vcpus > lim.max_vcpus {
        return Err(format!("{QUOTA_EXCEEDED}: 项目 {project} vCPU 超限（{}/{}）", vcpus + add_vcpus, lim.max_vcpus));
    }
    if lim.max_mem_mib > 0 && mem + add_mem > lim.max_mem_mib {
        return Err(format!("{QUOTA_EXCEEDED}: 项目 {project} 内存超限（{}/{} MiB）", mem + add_mem, lim.max_mem_mib));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sl_store::SqliteStore;

    // 造一个属某项目的沙箱记录（meta + project 键）。
    fn put_sandbox(s: &dyn Store, id: &str, project: &str, vcpus: u64, mem: u64) {
        let meta = format!(r#"{{"id":"{id}","vcpus":{vcpus},"mem_mib":{mem}}}"#);
        s.put(&format!("sandbox/{id}/meta"), meta.as_bytes(), None).unwrap();
        s.put(&format!("sandbox/{id}/project"), project.as_bytes(), None).unwrap();
    }

    #[test]
    fn no_limit_allows_everything() {
        let s = SqliteStore::open_in_memory().unwrap();
        // 未设配额 → 放行。
        assert!(check(&s, "projA", 100, 100_000).is_ok());
    }

    #[test]
    fn concurrent_and_cpu_and_mem_limits() {
        let s = SqliteStore::open_in_memory().unwrap();
        set_limits(&s, "projA", Limits { max_sandboxes: 2, max_vcpus: 4, max_mem_mib: 1024 }).unwrap();
        // 空项目：可建（1<=2, 2<=4, 512<=1024）。
        assert!(check(&s, "projA", 2, 512).is_ok());
        put_sandbox(&s, "s1", "projA", 2, 512);
        // 再建一个 2vcpu/512 → count 2<=2, vcpu 4<=4, mem 1024<=1024，放行（边界）。
        assert!(check(&s, "projA", 2, 512).is_ok());
        put_sandbox(&s, "s2", "projA", 2, 512);
        // 第三个 → 并发数 3>2 超限。
        let e = check(&s, "projA", 1, 128).unwrap_err();
        assert!(e.starts_with(QUOTA_EXCEEDED) && e.contains("并发"), "应并发超限: {e}");
    }

    #[test]
    fn cpu_limit_independent_of_count() {
        let s = SqliteStore::open_in_memory().unwrap();
        set_limits(&s, "projA", Limits { max_sandboxes: 0, max_vcpus: 4, max_mem_mib: 0 }).unwrap();
        put_sandbox(&s, "s1", "projA", 3, 256);
        // 再加 2 vcpu → 5>4 超限（并发/内存不限）。
        let e = check(&s, "projA", 2, 999_999).unwrap_err();
        assert!(e.contains("vCPU"), "应 vCPU 超限: {e}");
        // 加 1 vcpu → 4<=4 放行。
        assert!(check(&s, "projA", 1, 0).is_ok());
    }

    #[test]
    fn other_project_isolated() {
        let s = SqliteStore::open_in_memory().unwrap();
        set_limits(&s, "projA", Limits { max_sandboxes: 1, ..Default::default() }).unwrap();
        put_sandbox(&s, "s1", "projA", 1, 128);
        // projA 满，但 projB 无配额 → 不受影响。
        assert!(check(&s, "projA", 1, 0).is_err());
        assert!(check(&s, "projB", 1, 0).is_ok());
    }
}
