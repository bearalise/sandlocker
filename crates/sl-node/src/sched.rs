//! sched.rs — **多节点放置**（M3 W4 余项补完，M3-Q10）。后端无关，建在 `Store` trait 之上。
//!
//! ————————————————————— 在此之前发生了什么 —————————————————————
//!
//! W4 交付「多节点调度」时实际交的是**跨节点可见性**：沙箱→节点映射入 etcd、任一副本都能
//! 看到全集群的沙箱。但**放置**从来没做过——`Orch::register` 直接写本副本的 node_id，
//! 创建路径**从不查存活节点集**。于是沙箱落在哪，只取决于客户端把 `POST /v1/sandboxes`
//! 打给了谁：三副本前面挂个轮询 LB 就"看起来像均衡"，直接打某一台就全堆在那一台。
//!
//! 这个缺口是 2026-09-04 写 `bench-cluster.sh` 时暴露的（`placement` 恒为 `caller-local`），
//! 而 M3-Q10 判据写的是「跨节点创建/**调度**」。本模块补的是「调度」那一半。
//!
//! ————————————————————— 放置口径 —————————————————————
//!
//! **按剩余内存最多者优先。** 依据是 M3-Q9 的裸金属实测：两趟密度的停因都指向内存
//! （`mem-floor` / 内存地板），CPU 从不是先触顶的那一维。所以内存是主键，vCPU 只作**准入**
//! （放不下就排除），不参与排序。
//!
//! **容量按沙箱的「配置内存」记账，不按实测占用。** Firecracker 的 guest 内存惰性缺页，
//! M3-Q9 实测 512MiB 的实例均摊只落 19MB 物理页——照实测记账能塞进去 20 倍的实例，但那份
//! 收益取决于同模板占比与脏页率，PRD §8.1 脚注**明说不作为 SLO 承诺**。调度器按承诺记账，
//! 不按运气记账；确要吃这份收益的部署显式开 `--sched-overcommit`（见 `Policy`）。
//!
//! **用量实时算，不维护计数器。** 与 `quota.rs` 同一手法：遍历 `sandbox/<id>/node` +
//! `sandbox/<id>/meta` 累加。计数器会在崩溃/回收/竞态处漂移，而这里漂移的后果是把实例
//! 塞给一个其实已经满了的节点。

use std::collections::HashMap;

use serde_json::Value;
use sl_store::Store;

/// 节点自报的容量（写在心跳键 `node/<id>` 的值里，随心跳刷新）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capacity {
    pub addr: String,
    /// 可用 vCPU（`nproc`）。
    pub cpus: u64,
    /// 可用内存 MiB（`MemTotal`）。
    pub mem_mib: u64,
}

impl Capacity {
    /// 心跳键的值。**保留 `addr` 字段**——W3 起就是这个形状，老节点的键仍要能读。
    pub fn to_json(&self) -> String {
        format!(r#"{{"addr":"{}","cpus":{},"mem_mib":{}}}"#, self.addr, self.cpus, self.mem_mib)
    }
    /// 解析心跳键的值。**缺 cpus/mem_mib 记 0**——那是 W3/W4 时期的老节点（或未升级的节点），
    /// 容量未知。未知容量在 [`place`] 里被**排除**而不是当成无限大：宁可不往它上面放，
    /// 也不要因为读不到容量就把它当成一台空机器。
    pub fn from_json(b: &[u8]) -> Capacity {
        let v: Value = serde_json::from_slice(b).unwrap_or(Value::Null);
        Capacity {
            addr: v.get("addr").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            cpus: v.get("cpus").and_then(|x| x.as_u64()).unwrap_or(0),
            mem_mib: v.get("mem_mib").and_then(|x| x.as_u64()).unwrap_or(0),
        }
    }
}

/// 一个存活节点的容量与已分配用量。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeLoad {
    pub id: String,
    pub cap: Capacity,
    /// 该节点名下沙箱数。
    pub sandboxes: u64,
    /// 已分配（按配置值累加，非实测占用）。
    pub used_vcpus: u64,
    pub used_mem_mib: u64,
}

impl NodeLoad {
    fn free_mem_mib(&self, overcommit: u32) -> i64 {
        let total = self.cap.mem_mib.saturating_mul(overcommit.max(1) as u64);
        total as i64 - self.used_mem_mib as i64
    }
    fn free_vcpus(&self, overcommit: u32) -> i64 {
        let total = self.cap.cpus.saturating_mul(overcommit.max(1) as u64);
        total as i64 - self.used_vcpus as i64
    }
}

/// 放置策略。
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// 内存/CPU 超售倍数（默认 1 = 不超售）。>1 表示部署方**主动选择**吃 Firecracker 惰性
    /// 缺页那份收益；PRD §8.1 脚注说它不作为 SLO 承诺，所以只能是显式选项，不能是默认。
    pub overcommit: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { overcommit: 1 }
    }
}

/// 盘点存活节点及其已分配用量（一次 `list` 扫完，不发 N 次请求）。
pub fn survey(store: &dyn Store) -> Result<Vec<NodeLoad>, String> {
    let mut loads: HashMap<String, NodeLoad> = HashMap::new();
    for kv in store.list(sl_store::cluster::NODE_PREFIX).map_err(|e| e.to_string())? {
        if let Some(id) = kv.key.strip_prefix(sl_store::cluster::NODE_PREFIX) {
            loads.insert(
                id.to_string(),
                NodeLoad {
                    id: id.to_string(),
                    cap: Capacity::from_json(&kv.value),
                    sandboxes: 0,
                    used_vcpus: 0,
                    used_mem_mib: 0,
                },
            );
        }
    }
    if loads.is_empty() {
        return Ok(Vec::new());
    }

    // sid → owner，再把 owner 已分配的规格累加上去。
    let kvs = store.list("sandbox/").map_err(|e| e.to_string())?;
    let mut owner: HashMap<String, String> = HashMap::new();
    for kv in &kvs {
        if let Some(sid) = kv.key.strip_prefix("sandbox/").and_then(|s| s.strip_suffix("/node")) {
            owner.insert(sid.to_string(), String::from_utf8_lossy(&kv.value).into_owned());
        }
    }
    for kv in &kvs {
        let sid = match kv.key.strip_prefix("sandbox/").and_then(|s| s.strip_suffix("/meta")) {
            Some(s) => s,
            None => continue,
        };
        // 归属未知的沙箱记不到任何节点头上——它们本来也不占某台机器的账面。
        let node = match owner.get(sid).and_then(|o| loads.get_mut(o)) {
            Some(n) => n,
            None => continue,
        };
        node.sandboxes += 1;
        if let Ok(v) = serde_json::from_slice::<Value>(&kv.value) {
            node.used_vcpus += v.get("vcpus").and_then(|x| x.as_u64()).unwrap_or(0);
            node.used_mem_mib += v.get("mem_mib").and_then(|x| x.as_u64()).unwrap_or(0);
        }
    }
    let mut out: Vec<NodeLoad> = loads.into_values().collect();
    out.sort_by(|a, b| a.id.cmp(&b.id)); // 稳定顺序，便于测试与日志比对
    Ok(out)
}

/// 选一个放得下 `(vcpus, mem_mib)` 的节点；`None` = 没有节点放得下。
///
/// 排序键（依次）：**剩余内存多者优先** → 沙箱少者优先 → **本节点优先** → id 升序。
///
/// 「本节点优先」只在前两键打平时起作用（典型是冷启动，所有节点都空）。它省的是一次中继
/// 往返；一旦有了负载差，剩余内存这一键就接管了，不会把实例都黏在收请求的那台上——那正是
/// 本模块要修的老毛病。
///
/// 容量为 0 的节点（老节点没自报容量）被**排除**：读不到容量不等于容量无限。
pub fn place(nodes: &[NodeLoad], vcpus: u64, mem_mib: u64, self_id: &str, p: Policy) -> Option<String> {
    let mut fit: Vec<&NodeLoad> = nodes
        .iter()
        .filter(|n| n.cap.mem_mib > 0 && n.cap.cpus > 0)
        .filter(|n| n.free_mem_mib(p.overcommit) >= mem_mib as i64)
        .filter(|n| n.free_vcpus(p.overcommit) >= vcpus as i64)
        .collect();
    if fit.is_empty() {
        return None;
    }
    fit.sort_by(|a, b| {
        b.free_mem_mib(p.overcommit)
            .cmp(&a.free_mem_mib(p.overcommit))
            .then(a.sandboxes.cmp(&b.sandboxes))
            .then((a.id != self_id).cmp(&(b.id != self_id))) // false<true → self 排前
            .then(a.id.cmp(&b.id))
    });
    Some(fit[0].id.clone())
}

/// 本机容量（`nproc` / `MemTotal`）。读不到就记 0——**宁可让本节点在调度里被排除**，
/// 也不要报一个猜的数字把实例塞过来。
pub fn local_capacity(addr: &str) -> Capacity {
    let cpus = std::thread::available_parallelism().map(|n| n.get() as u64).unwrap_or(0);
    let mem_mib = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0);
    Capacity { addr: addr.to_string(), cpus, mem_mib }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sl_store::SqliteStore;

    fn node(id: &str, cpus: u64, mem: u64, sandboxes: u64, vcpus: u64, used_mem: u64) -> NodeLoad {
        NodeLoad {
            id: id.into(),
            cap: Capacity { addr: id.into(), cpus, mem_mib: mem },
            sandboxes,
            used_vcpus: vcpus,
            used_mem_mib: used_mem,
        }
    }

    #[test]
    fn capacity_json_roundtrip_and_legacy_key() {
        let c = Capacity { addr: "127.0.0.1:7878".into(), cpus: 64, mem_mib: 131072 };
        assert_eq!(Capacity::from_json(c.to_json().as_bytes()), c);
        // W3/W4 时期的老心跳键只有 addr——要能读，且容量记 0（→ 在 place 里被排除）。
        let legacy = Capacity::from_json(br#"{"addr":"10.0.0.1:7878"}"#);
        assert_eq!(legacy.addr, "10.0.0.1:7878");
        assert_eq!((legacy.cpus, legacy.mem_mib), (0, 0));
    }

    #[test]
    fn picks_the_node_with_the_most_free_memory() {
        let ns = [
            node("a", 8, 8192, 4, 8, 6000), // 剩 2192
            node("b", 8, 8192, 1, 2, 1024), // 剩 7168 ← 该选它
            node("c", 8, 8192, 2, 4, 4096), // 剩 4096
        ];
        assert_eq!(place(&ns, 2, 512, "a", Policy::default()).as_deref(), Some("b"));
    }

    /// 这条是本模块存在的理由：收请求的副本**不该**因为是自己就被选中。
    #[test]
    fn does_not_prefer_self_when_self_is_loaded() {
        let ns = [
            node("a", 8, 8192, 10, 16, 7000), // self，快满了
            node("b", 8, 8192, 0, 0, 0),
        ];
        assert_eq!(place(&ns, 2, 512, "a", Policy::default()).as_deref(), Some("b"));
    }

    /// 但全都空着时优先本节点——省一次中继往返，且不引入偏斜（下一次创建后 a 就不再最空）。
    #[test]
    fn prefers_self_only_on_a_tie() {
        let ns = [node("a", 8, 8192, 0, 0, 0), node("b", 8, 8192, 0, 0, 0), node("c", 8, 8192, 0, 0, 0)];
        assert_eq!(place(&ns, 2, 512, "b", Policy::default()).as_deref(), Some("b"));
        // 没有"自己"参与时退到 id 升序，结果确定。
        assert_eq!(place(&ns, 2, 512, "zzz", Policy::default()).as_deref(), Some("a"));
    }

    #[test]
    fn refuses_when_nothing_fits() {
        let ns = [node("a", 8, 1024, 0, 0, 900), node("b", 8, 1024, 0, 0, 1000)];
        assert_eq!(place(&ns, 1, 512, "a", Policy::default()), None);
        // vCPU 也是准入条件（只是不参与排序）。
        let ns2 = [node("a", 2, 65536, 0, 2, 0)];
        assert_eq!(place(&ns2, 4, 512, "a", Policy::default()), None);
    }

    /// 未自报容量的节点被排除，而不是当成空机器——把实例塞给一台容量未知的机器是更坏的默认。
    #[test]
    fn nodes_without_reported_capacity_are_excluded() {
        let ns = [node("legacy", 0, 0, 0, 0, 0), node("b", 4, 4096, 0, 0, 0)];
        assert_eq!(place(&ns, 2, 512, "legacy", Policy::default()).as_deref(), Some("b"));
        assert_eq!(place(&[node("legacy", 0, 0, 0, 0, 0)], 2, 512, "legacy", Policy::default()), None);
    }

    /// 超售是**显式选择**：默认放不下的，开了 overcommit 才放得下。
    #[test]
    fn overcommit_is_opt_in() {
        let ns = [node("a", 8, 1024, 0, 0, 900)];
        assert_eq!(place(&ns, 1, 512, "a", Policy::default()), None);
        assert_eq!(place(&ns, 1, 512, "a", Policy { overcommit: 4 }).as_deref(), Some("a"));
    }

    /// survey：从真 store 读心跳键 + 沙箱 meta，把用量记到正确的节点头上。
    #[test]
    fn survey_accumulates_usage_per_owner() {
        let s = SqliteStore::open_in_memory().unwrap();
        for (id, cpus, mem) in [("n-a", 8u64, 8192u64), ("n-b", 16, 16384)] {
            let cap = Capacity { addr: id.into(), cpus, mem_mib: mem };
            sl_store::cluster::register_node(&s, id, cap.to_json().as_bytes(), 3600).unwrap();
        }
        // 两个沙箱在 a，一个在 b，外加一个归属未知的（不该记到任何人头上）。
        for (sid, owner, vcpus, mem) in
            [("s1", Some("n-a"), 2, 512), ("s2", Some("n-a"), 4, 1024), ("s3", Some("n-b"), 1, 128), ("s4", None, 8, 4096)]
        {
            s.put(&format!("sandbox/{sid}/meta"), format!(r#"{{"vcpus":{vcpus},"mem_mib":{mem}}}"#).as_bytes(), None)
                .unwrap();
            if let Some(o) = owner {
                s.put(&sl_store::cluster::sandbox_node_key(sid), o.as_bytes(), None).unwrap();
            }
        }
        let loads = survey(&s).unwrap();
        assert_eq!(loads.len(), 2);
        let a = loads.iter().find(|n| n.id == "n-a").unwrap();
        assert_eq!((a.sandboxes, a.used_vcpus, a.used_mem_mib), (2, 6, 1536));
        let b = loads.iter().find(|n| n.id == "n-b").unwrap();
        assert_eq!((b.sandboxes, b.used_vcpus, b.used_mem_mib), (1, 1, 128));
        // b 剩得多 → 选 b，即便请求是 a 收到的。
        assert_eq!(place(&loads, 2, 512, "n-a", Policy::default()).as_deref(), Some("n-b"));
    }

    /// 存活集为空（单机 SQLite 未注册 / etcd 里一个节点都没有）→ 无处可放，调用方退回本地。
    #[test]
    fn empty_survey_places_nowhere() {
        let s = SqliteStore::open_in_memory().unwrap();
        assert!(survey(&s).unwrap().is_empty());
        assert_eq!(place(&[], 2, 512, "me", Policy::default()), None);
    }
}
