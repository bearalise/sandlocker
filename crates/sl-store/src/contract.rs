//! 后端无关的 store 契约套件（M3 W1）。
//!
//! 目标（M3-Q1）：证「单机 SQLite 与集群 etcd **无两套语义**」——两实现跑**同一套**断言。
//! 由 `lib.rs` 单元测试（SqliteStore，进程内）与 sl-node `--store-contract [--etcd]`
//! （两实现逐个跑）共同调用。
//!
//! 设计约束（关键：契约对**非全新** store 健壮，因 etcd 集群可能带历史）：
//!   - 绝不假设起始 revision 为 0；一律取基线后做**相对**断言。
//!   - 键名全部落在 `ct/` 命名空间且各场景子前缀互斥；开跑前清空 `ct/`。
//!   - lease 用**正 TTL + 轮询**，兼容 etcd 服务端自动过期（SQLite 靠 `lease_sweep` 立即回收，
//!     etcd 靠服务端 TTL 到期，二者在「过期后键消失」这一**可观测不变量**上收敛）。
//!   - compact 不假设返回计数（etcd compaction 不回计数）；只断言压实后新事件仍可回放。

use crate::{EventKind, Store};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 契约失败：`场景::原因`。
pub type ContractError = String;

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 删除某前缀下全部键（list→逐个 delete）。用窄接口达成「清空前缀」，两实现皆可。
fn clear_prefix(s: &dyn Store, prefix: &str) -> Result<(), ContractError> {
    let kvs = s.list(prefix).map_err(|e| format!("setup::list({prefix}): {e}"))?;
    for kv in kvs {
        s.delete(&kv.key).map_err(|e| format!("setup::delete({}): {e}", kv.key))?;
    }
    Ok(())
}

/// 跑全部场景。任一失败即返回 `Err("场景::原因")`。跑前后各清空一次 `ct/`。
pub fn run_all(s: &dyn Store) -> Result<(), ContractError> {
    clear_prefix(s, "ct/")?;
    put_get_delete_revision(s)?;
    list_prefix_scoped(s)?;
    cas_guards_transition(s)?;
    changes_since_replays(s)?;
    watch_prefix_only(s)?;
    compact_prunes(s)?;
    lease_expiry_observable(s)?;
    clear_prefix(s, "ct/")?;
    Ok(())
}

/// 场景 1：put/get 往返、覆盖写保 create_revision、delete 幂等、revision 单调前进。
fn put_get_delete_revision(s: &dyn Store) -> Result<(), ContractError> {
    let tag = "put_get_delete_revision";
    let (ka, kb) = ("ct/pgd/a", "ct/pgd/b");
    let r1 = s.put(ka, b"1", None).map_err(|e| format!("{tag}::put(a): {e}"))?;
    let r2 = s.put(kb, b"2", None).map_err(|e| format!("{tag}::put(b): {e}"))?;
    if r2 <= r1 {
        return Err(format!("{tag}::revision 非单调: r1={r1} r2={r2}"));
    }
    let a = s.get(ka).map_err(|e| format!("{tag}::get(a): {e}"))?
        .ok_or_else(|| format!("{tag}::get(a) 应存在"))?;
    if a.value != b"1" {
        return Err(format!("{tag}::get(a).value={:?} 期望 \"1\"", a.value));
    }
    if a.create_revision != r1 || a.mod_revision != r1 {
        return Err(format!("{tag}::新键 create/mod 应=r1: {a:?}"));
    }
    // 覆盖写：create_rev 不变、mod_rev 前进
    let r3 = s.put(ka, b"1b", None).map_err(|e| format!("{tag}::put(a 覆盖): {e}"))?;
    let a = s.get(ka).map_err(|e| format!("{tag}::get(a2): {e}"))?
        .ok_or_else(|| format!("{tag}::get(a2) 应存在"))?;
    if a.create_revision != r1 {
        return Err(format!("{tag}::覆盖写 create_rev 变了: {} 期望 {r1}", a.create_revision));
    }
    if a.mod_revision != r3 {
        return Err(format!("{tag}::覆盖写 mod_rev 应=r3: {} 期望 {r3}", a.mod_revision));
    }
    // delete 幂等
    if !s.delete(ka).map_err(|e| format!("{tag}::delete(a): {e}"))? {
        return Err(format!("{tag}::delete(a) 首次应返回 true"));
    }
    if s.delete(ka).map_err(|e| format!("{tag}::delete(a2): {e}"))? {
        return Err(format!("{tag}::delete(a) 再次应返回 false"));
    }
    if s.get(ka).map_err(|e| format!("{tag}::get(a3): {e}"))?.is_some() {
        return Err(format!("{tag}::delete 后 get(a) 应为空"));
    }
    Ok(())
}

/// 场景 2：list 按前缀严格收敛（不越界到相邻前缀）。
fn list_prefix_scoped(s: &dyn Store) -> Result<(), ContractError> {
    let tag = "list_prefix_scoped";
    s.put("ct/list/sandbox/a", b"1", None).map_err(|e| format!("{tag}::put: {e}"))?;
    s.put("ct/list/sandbox/b", b"2", None).map_err(|e| format!("{tag}::put: {e}"))?;
    s.put("ct/list/template/x", b"9", None).map_err(|e| format!("{tag}::put: {e}"))?;
    let got: Vec<String> = s.list("ct/list/sandbox/")
        .map_err(|e| format!("{tag}::list: {e}"))?
        .into_iter().map(|kv| kv.key).collect();
    if got != vec!["ct/list/sandbox/a", "ct/list/sandbox/b"] {
        return Err(format!("{tag}::前缀 list 越界或乱序: {got:?}"));
    }
    let all = s.list("ct/list/").map_err(|e| format!("{tag}::list all: {e}"))?;
    if all.len() != 3 {
        return Err(format!("{tag}::list(ct/list/) 应 3 个, 得 {}", all.len()));
    }
    Ok(())
}

/// 场景 3：CAS 是并发状态迁移的原子基元（键不存在守卫 + mod_revision 比对）。
fn cas_guards_transition(s: &dyn Store) -> Result<(), ContractError> {
    let tag = "cas_guards_transition";
    let k = "ct/cas/state";
    // 期望键不存在（None）→ 首次创建成功
    let r = s.compare_and_swap(k, None, b"creating", None).map_err(|e| format!("{tag}::cas1: {e}"))?;
    if !r.succeeded {
        return Err(format!("{tag}::首次 CAS(None) 应成功"));
    }
    let mod_rev = s.get(k).map_err(|e| format!("{tag}::get: {e}"))?
        .ok_or_else(|| format!("{tag}::get 应存在"))?.mod_revision;
    // 过期 expect（None，但键已存在）→ 失败并回带当前值
    let r = s.compare_and_swap(k, None, b"running", None).map_err(|e| format!("{tag}::cas2: {e}"))?;
    if r.succeeded {
        return Err(format!("{tag}::过期 CAS(None) 应失败"));
    }
    match r.current {
        Some(kv) if kv.value == b"creating" => {}
        other => return Err(format!("{tag}::失败 CAS 应回带当前值 creating, 得 {other:?}")),
    }
    // 正确 mod_rev → 成功
    let r = s.compare_and_swap(k, Some(mod_rev), b"running", None).map_err(|e| format!("{tag}::cas3: {e}"))?;
    if !r.succeeded {
        return Err(format!("{tag}::正确 mod_rev 的 CAS 应成功"));
    }
    let v = s.get(k).map_err(|e| format!("{tag}::get2: {e}"))?
        .ok_or_else(|| format!("{tag}::get2 应存在"))?.value;
    if v != b"running" {
        return Err(format!("{tag}::CAS 后值应为 running, 得 {v:?}"));
    }
    Ok(())
}

/// 场景 4：changes_since 按前缀回放 put/delete（含删除事件），revision 升序。
fn changes_since_replays(s: &dyn Store) -> Result<(), ContractError> {
    let tag = "changes_since_replays";
    let base = s.current_revision().map_err(|e| format!("{tag}::base rev: {e}"))?;
    s.put("ct/chg/sandbox/a", b"1", None).map_err(|e| format!("{tag}::put a: {e}"))?;
    s.put("ct/chg/template/x", b"9", None).map_err(|e| format!("{tag}::put x: {e}"))?;
    s.delete("ct/chg/sandbox/a").map_err(|e| format!("{tag}::del a: {e}"))?;
    // 仅 ct/chg/sandbox/ 前缀，从 base 起：期望 Put(a) 然后 Delete(a)
    let evs = s.changes_since(base, "ct/chg/sandbox/")
        .map_err(|e| format!("{tag}::changes_since: {e}"))?;
    if evs.len() != 2 {
        return Err(format!("{tag}::前缀事件应 2 个, 得 {}: {evs:?}", evs.len()));
    }
    if evs[0].kind != EventKind::Put || evs[1].kind != EventKind::Delete {
        return Err(format!("{tag}::事件类型序应 Put,Delete: {evs:?}"));
    }
    if evs[0].revision >= evs[1].revision {
        return Err(format!("{tag}::事件应按 revision 升序: {evs:?}"));
    }
    // 全 ct/chg/ 前缀看到 3 个事件（put a / put x / del a）
    let all = s.changes_since(base, "ct/chg/").map_err(|e| format!("{tag}::changes_since all: {e}"))?;
    if all.len() != 3 {
        return Err(format!("{tag}::全前缀事件应 3 个, 得 {}", all.len()));
    }
    Ok(())
}

/// 场景 5：watch 只广播匹配前缀的变更（进程内 mpsc / etcd 流转发到同一 Receiver）。
fn watch_prefix_only(s: &dyn Store) -> Result<(), ContractError> {
    let tag = "watch_prefix_only";
    let rx = s.watch("ct/watch/sandbox/");
    // 给 etcd 的流建立留一点建立时间（SQLite 立即生效，无害）
    std::thread::sleep(Duration::from_millis(50));
    s.put("ct/watch/sandbox/a", b"1", None).map_err(|e| format!("{tag}::put a: {e}"))?;
    s.put("ct/watch/template/x", b"9", None).map_err(|e| format!("{tag}::put x(不应收到): {e}"))?;
    s.delete("ct/watch/sandbox/a").map_err(|e| format!("{tag}::del a: {e}"))?;

    let e1 = rx.recv_timeout(Duration::from_secs(3))
        .map_err(|e| format!("{tag}::收 Put(a) 超时: {e}"))?;
    if e1.kind != EventKind::Put || e1.key != "ct/watch/sandbox/a" {
        return Err(format!("{tag}::首事件应 Put(sandbox/a): {e1:?}"));
    }
    let e2 = rx.recv_timeout(Duration::from_secs(3))
        .map_err(|e| format!("{tag}::收 Delete(a) 超时: {e}"))?;
    if e2.kind != EventKind::Delete || e2.key != "ct/watch/sandbox/a" {
        return Err(format!("{tag}::次事件应 Delete(sandbox/a): {e2:?}"));
    }
    // template/x 不在前缀内：短窗内不应再有事件到达
    if let Ok(extra) = rx.recv_timeout(Duration::from_millis(300)) {
        return Err(format!("{tag}::收到不该广播的事件: {extra:?}"));
    }
    Ok(())
}

/// 场景 6：compact 有界化历史后，压实点之后的事件仍可回放（不断言绝对计数）。
fn compact_prunes(s: &dyn Store) -> Result<(), ContractError> {
    let tag = "compact_prunes";
    s.put("ct/compact/a", b"1", None).map_err(|e| format!("{tag}::put a: {e}"))?;
    let cut = s.current_revision().map_err(|e| format!("{tag}::cut rev: {e}"))?;
    s.put("ct/compact/b", b"2", None).map_err(|e| format!("{tag}::put b: {e}"))?;
    s.compact(cut).map_err(|e| format!("{tag}::compact({cut}): {e}"))?;
    // 压实点之后（since=cut → 回放 rev>cut）应仍见 put(b)；start_revision>compact 点，两实现皆安全
    let evs = s.changes_since(cut, "ct/compact/").map_err(|e| format!("{tag}::changes_since(cut): {e}"))?;
    if !evs.iter().any(|e| e.key == "ct/compact/b" && e.kind == EventKind::Put) {
        return Err(format!("{tag}::压实后 since=cut 应仍见 put(b): {evs:?}"));
    }
    Ok(())
}

/// 场景 7：lease 过期后其挂载键消失、无租约键存活（可观测不变量，跨实现收敛）。
fn lease_expiry_observable(s: &dyn Store) -> Result<(), ContractError> {
    let tag = "lease_expiry_observable";
    let (keph, kper) = ("ct/lease/ephemeral", "ct/lease/persistent");

    // 7a keepalive 续期：大 TTL + keepalive 返回未来到期；sweep(now) 不回收；键在。
    let big = s.lease_grant(3600).map_err(|e| format!("{tag}::grant big: {e}"))?;
    s.put(kper, b"y", Some(big)).map_err(|e| format!("{tag}::put persistent: {e}"))?;
    let exp = s.lease_keepalive(big).map_err(|e| format!("{tag}::keepalive: {e}"))?;
    if exp < now_unix() {
        return Err(format!("{tag}::keepalive 到期 {exp} 不应早于现在"));
    }
    let reaped = s.lease_sweep(now_unix()).map_err(|e| format!("{tag}::sweep(now): {e}"))?;
    if reaped.iter().any(|k| k == kper) {
        return Err(format!("{tag}::未到期 sweep 误回收 persistent"));
    }

    // 7b 短 TTL 到期：ephemeral 消失、persistent 存活。
    //     SQLite 靠 sweep(now+3600) 立即回收；etcd 靠服务端 TTL 到期。轮询到收敛。
    let short = s.lease_grant(1).map_err(|e| format!("{tag}::grant short: {e}"))?;
    s.put(keph, b"x", Some(short)).map_err(|e| format!("{tag}::put ephemeral: {e}"))?;
    if s.get(keph).map_err(|e| format!("{tag}::get eph: {e}"))?.is_none() {
        return Err(format!("{tag}::put 后 ephemeral 应存在"));
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        // sweep horizon 落在 short(1s) 与 big(3600s) 之间：回收 ephemeral、不误伤 persistent。
        // SQLite 立即回收 ttl 已过键；etcd 无害（服务端已按 TTL 自动删）。
        let _ = s.lease_sweep(now_unix() + 5).map_err(|e| format!("{tag}::sweep: {e}"))?;
        if s.get(keph).map_err(|e| format!("{tag}::get eph2: {e}"))?.is_none() {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!("{tag}::ephemeral 到期后仍未消失（8s 超时）"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if s.get(kper).map_err(|e| format!("{tag}::get persistent: {e}"))?.is_none() {
        return Err(format!("{tag}::persistent（大 TTL）不应被回收"));
    }
    Ok(())
}
