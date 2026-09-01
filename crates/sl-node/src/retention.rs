//! retention.rs — 快照保留期 + 版本钉住（M3 W10，ADR-16，M3-Q7，【还 M2 债】）。
//!
//! 后端无关（`Store` trait）。两件事：
//!   ① **版本钉住**：paused 快照按（模板版本, 内核版本, VMM 版本）三元组 key（复用 build.rs 的
//!      `adr16_key`）；恢复只能落到**兼容版本**的节点（节点保留 N-1 内核 + FC 二进制）。
//!      旧内核恢复返回「未打补丁 guest 内核」警告。VMM 必须精确匹配（FC 快照绑定 VMM 版本）。
//!   ② **保留期**：paused 快照默认保留 7 天（可配），过期由 leader 统一 GC（撤租连删，并入 ADR-25）。
//!
//! 键：`sandbox/<sid>/pin` = 三元组 JSON；`sandbox/<sid>/retain` = 过期 unix 秒。均挂沙箱租约
//! （回收撤租一并删）。节点 kernel/vmm/N-1 由心跳 meta 登记（见 serve()）。

use serde_json::Value;
use sl_store::{LeaseId, Store};

/// 默认保留期（秒）：7 天。
pub const DEFAULT_RETENTION_SECS: i64 = 7 * 24 * 3600;

/// 快照版本钉（ADR-16 三元组）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub template_version: String,
    pub kernel_version: String,
    pub vmm_version: String,
}

/// 兼容判定结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Compat {
    /// 精确匹配，可直接恢复。
    Ok,
    /// 内核落在节点 N-1 保留范围——可恢复，但 guest 内核未打补丁（返回警告）。
    OldKernelWarn,
    /// 不兼容（VMM 不符 / 内核不在保留范围）——拒绝恢复。
    Incompatible(String),
}

fn pin_key(sid: &str) -> String {
    format!("sandbox/{sid}/pin")
}
fn retain_key(sid: &str) -> String {
    format!("sandbox/{sid}/retain")
}

/// 记快照版本钉（挂沙箱租约）。
pub fn set_pin(store: &dyn Store, sid: &str, pin: &Pin, lease: Option<LeaseId>) -> Result<(), String> {
    let json = format!(
        r#"{{"template_version":"{}","kernel_version":"{}","vmm_version":"{}"}}"#,
        pin.template_version, pin.kernel_version, pin.vmm_version
    );
    store.put(&pin_key(sid), json.as_bytes(), lease).map_err(|e| e.to_string())?;
    Ok(())
}

/// 从模板目录的 `manifest.json`（build.rs 写，含 `adr16_key`）读版本三元组。
/// 非预烘焙模板 / 缺 manifest → None（该沙箱不钉版本，恢复不做兼容门控）。
pub fn pin_from_template(template: &std::path::Path) -> Option<Pin> {
    let bytes = std::fs::read(template.join("manifest.json")).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    let k = v.get("adr16_key")?;
    Some(Pin {
        template_version: k.get("template_version")?.as_str()?.to_string(),
        kernel_version: k.get("kernel_version")?.as_str()?.to_string(),
        vmm_version: k.get("vmm_version")?.as_str()?.to_string(),
    })
}

/// 读快照版本钉（None=未钉）。
pub fn get_pin(store: &dyn Store, sid: &str) -> Result<Option<Pin>, String> {
    let kv = store.get(&pin_key(sid)).map_err(|e| e.to_string())?;
    Ok(kv.and_then(|kv| {
        let v: Value = serde_json::from_slice(&kv.value).ok()?;
        Some(Pin {
            template_version: v.get("template_version")?.as_str()?.to_string(),
            kernel_version: v.get("kernel_version")?.as_str()?.to_string(),
            vmm_version: v.get("vmm_version")?.as_str()?.to_string(),
        })
    }))
}

/// ADR-16 兼容矩阵：快照 pin 能否恢复到某节点。
/// - VMM 版本必须精确匹配（FC 快照绑定 VMM）；
/// - 内核精确匹配 → Ok；内核在节点 N-1 保留列表 → OldKernelWarn；否则 Incompatible。
pub fn check_compat(pin: &Pin, node_kernel: &str, node_vmm: &str, node_n1_kernels: &[String]) -> Compat {
    if pin.vmm_version != node_vmm {
        return Compat::Incompatible(format!(
            "VMM 版本不兼容：快照 {} vs 节点 {node_vmm}",
            pin.vmm_version
        ));
    }
    if pin.kernel_version == node_kernel {
        return Compat::Ok;
    }
    if node_n1_kernels.iter().any(|k| k == &pin.kernel_version) {
        return Compat::OldKernelWarn;
    }
    Compat::Incompatible(format!(
        "内核 {} 不在节点保留范围（当前 {node_kernel} + N-1 {node_n1_kernels:?}）",
        pin.kernel_version
    ))
}

/// 设保留期到期时刻（挂沙箱租约）。通常在 pause 时调：deadline = now + retention_secs。
pub fn set_retention(store: &dyn Store, sid: &str, deadline_unix: i64, lease: Option<LeaseId>) -> Result<(), String> {
    store.put(&retain_key(sid), deadline_unix.to_string().as_bytes(), lease).map_err(|e| e.to_string())?;
    Ok(())
}

/// GC 过期的 paused 快照：`state==paused` 且 `retain <= now` → 撤租（连删 meta/state/pin/retain/...）。
/// 返回被回收的 sid。leader 周期调用（并入 reaper）。仅动 paused——running 的不碰。
pub fn gc_expired(store: &dyn Store, now: i64) -> Result<Vec<String>, String> {
    let kvs = store.list("sandbox/").map_err(|e| e.to_string())?;
    // 建 sid→(retain, state, lease) 视图。
    let mut retain: std::collections::HashMap<String, (i64, Option<LeaseId>)> = std::collections::HashMap::new();
    let mut states: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    for kv in &kvs {
        if let Some(sid) = kv.key.strip_prefix("sandbox/").and_then(|s| s.strip_suffix("/retain")) {
            let d = String::from_utf8_lossy(&kv.value).parse::<i64>().unwrap_or(i64::MAX);
            retain.insert(sid.to_string(), (d, kv.lease));
        } else if let Some(sid) = kv.key.strip_prefix("sandbox/").and_then(|s| s.strip_suffix("/state")) {
            states.insert(sid.to_string(), kv.value.clone());
        }
    }
    let mut gced = Vec::new();
    for (sid, (deadline, lease)) in retain {
        let paused = states.get(&sid).map(|v| v == b"paused").unwrap_or(false);
        if paused && deadline <= now {
            match lease {
                Some(l) => {
                    store.lease_revoke(l).map_err(|e| e.to_string())?;
                }
                None => {
                    // 无租约兜底：逐删该沙箱键。
                    for suffix in ["meta", "state", "pin", "retain", "project", "node", "size"] {
                        let _ = store.delete(&format!("sandbox/{sid}/{suffix}"));
                    }
                }
            }
            gced.push(sid);
        }
    }
    Ok(gced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sl_store::SqliteStore;

    #[test]
    fn compat_matrix() {
        let pin = Pin { template_version: "t1".into(), kernel_version: "6.6.10".into(), vmm_version: "1.7.0".into() };
        // 精确匹配 → Ok
        assert_eq!(check_compat(&pin, "6.6.10", "1.7.0", &[]), Compat::Ok);
        // 内核在 N-1 → 警告
        assert_eq!(
            check_compat(&pin, "6.6.11", "1.7.0", &["6.6.10".into()]),
            Compat::OldKernelWarn
        );
        // VMM 不符 → 不兼容
        assert!(matches!(check_compat(&pin, "6.6.10", "1.8.0", &[]), Compat::Incompatible(_)));
        // 内核不在保留范围 → 不兼容
        assert!(matches!(check_compat(&pin, "6.6.11", "1.7.0", &[]), Compat::Incompatible(_)));
    }

    #[test]
    fn pin_roundtrip() {
        let s = SqliteStore::open_in_memory().unwrap();
        let pin = Pin { template_version: "t1".into(), kernel_version: "6.6.10".into(), vmm_version: "1.7.0".into() };
        set_pin(&s, "sb1", &pin, None).unwrap();
        assert_eq!(get_pin(&s, "sb1").unwrap().unwrap(), pin);
        assert!(get_pin(&s, "nope").unwrap().is_none());
    }

    #[test]
    fn gc_only_expired_paused() {
        let s = SqliteStore::open_in_memory().unwrap();
        let now = 1_000_000i64;
        // sb1: paused + 已过期 → GC
        s.put("sandbox/sb1/meta", b"{}", None).unwrap();
        s.put("sandbox/sb1/state", b"paused", None).unwrap();
        set_retention(&s, "sb1", now - 1, None).unwrap();
        // sb2: paused + 未过期 → 留
        s.put("sandbox/sb2/state", b"paused", None).unwrap();
        set_retention(&s, "sb2", now + 3600, None).unwrap();
        // sb3: running + 过期时刻 → 不碰（只 GC paused）
        s.put("sandbox/sb3/state", b"running", None).unwrap();
        set_retention(&s, "sb3", now - 1, None).unwrap();

        let gced = gc_expired(&s, now).unwrap();
        assert_eq!(gced, vec!["sb1"]);
        assert!(s.get("sandbox/sb1/meta").unwrap().is_none(), "sb1 应被 GC");
        assert!(s.get("sandbox/sb2/state").unwrap().is_some(), "sb2 未过期应留");
        assert!(s.get("sandbox/sb3/state").unwrap().is_some(), "sb3 running 不碰");
    }
}
