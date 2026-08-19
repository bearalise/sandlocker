//! nftfw — nftables 网络策略后端（ADR-21，M1 W5）。
//!
//! 模型（ADR-7/ADR-21）：每沙箱一张独立 `inet` table，内含**默认 drop** 的 egress 链
//! + 命名 IP 集合（allow4）+ 端口集合（allowport）。deny-by-default = 链 policy drop
//! 且集合为空；放行 = 往集合里加元素（`nft add element`，原子增量，不重建 table）；
//! 销毁 = `nft delete table`（无残留）。规则批量更新走 `nft -f -` 单事务，杜绝中间态放行窗口。
//! `nft list table` 可审计（P3 刚需）。
//!
//! 抽象方法对应 ADR-21 的防火墙后端接口：ensure / add_allow / remove_allow / teardown。
//! （set_dns_redirect、域名粒度白名单是 M2，FR-3.2b/3.4，本周不做。）
//!
//! 特权模型（同 dmthin，承 D2）：
//!   - euid==0（生产 / CI root）：直呼 nft / ip。
//!   - 非 root（dev）：nft 走 `sudo -n nft`（在 NOPASSWD 白名单内）；但 **ip 不在白名单**，
//!     故带 veth/netns 的 Q7 完整对账只能 root 跑（CI dmthin job 以 root 直呼）。
//!
//! table 归属：per-sandbox netns（`FwCfg.netns=Some`）→ 经 `ip netns exec <ns> nft`，
//! 天然按 netns 隔离、零 host blast radius；`None` → host root netns（jailer-netns 落地后用）。

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

// Q7 对账用的一次性测试通路（host veth ⟷ 沙箱侧 netns 内 veth，点对点 /30）。
const NS: &str = "sl-fwtest";
const VETH_H: &str = "slfw-h";
const VETH_P: &str = "slfw-p";
const HOST_IP: &str = "10.234.0.1"; // host 端（监听侧）
const PEER_IP: &str = "10.234.0.2"; // netns 端（沙箱侧发起）

#[derive(Clone)]
pub struct FwCfg {
    pub table: String,          // per-sandbox table 名，如 "sl_fw_recon"
    pub root: bool,             // euid==0 → 直呼；否则 sudo -n
    pub netns: Option<String>,  // Some(ns) → nft 经 `ip netns exec ns`；None → host root netns
    /// egress 链的 hook（M2 W1）：
    ///   - false（默认，Q7 路径）→ `hook output`：过滤 netns 内**进程自身**出站（如对账探针进程）。
    ///   - true（live 路径）→ `hook forward`：过滤**经 netns 转发**的流量（live microVM 经 tap→veth
    ///     的出口走转发链，唯 forward hook 能咬住；见 netlive.rs / apply_network_policy）。
    pub hook_forward: bool,
}

/// 生成 `ensure` 的 nft 脚本（纯字符串，无副作用 → 可无特权单测）。
/// `add + delete + 重定义` 三句一事务：无论先前状态如何都落到干净初值（幂等）。
/// `hook_forward` 决定 egress 链挂 output（进程自身出站）还是 forward（转发流量）hook。
fn ensure_script(table: &str, hook_forward: bool) -> String {
    let hook = if hook_forward { "forward" } else { "output" };
    // 注：allow4 / allowport 为两个独立集合（ADR-21 口径）。当前放行语义是
    // “目的 IP ∈ allow4 且 目的端口 ∈ allowport”——非严格 (ip,port) 成对；
    // 需成对收紧时改用拼接集合 `type ipv4_addr . inet_service`（M2 视需要）。
    format!(
        "add table inet {table}\n\
         delete table inet {table}\n\
         table inet {table} {{\n\
         \tset allow4 {{ type ipv4_addr; }}\n\
         \tset allowport {{ type inet_service; }}\n\
         \tchain egress {{\n\
         \t\ttype filter hook {hook} priority 0; policy drop;\n\
         \t\tct state established,related accept\n\
         \t\tip daddr @allow4 tcp dport @allowport accept\n\
         \t}}\n\
         }}\n"
    )
}

/// 构造 nft 调用的前缀命令（root/sudo × 是否 netns），调用方续接 nft 自身参数。
fn nft_base(root: bool, netns: Option<&str>) -> Command {
    match (root, netns) {
        (true, None) => Command::new("nft"),
        (true, Some(ns)) => {
            let mut c = Command::new("ip");
            c.args(["netns", "exec", ns, "nft"]);
            c
        }
        (false, None) => {
            let mut c = Command::new("sudo");
            c.args(["-n", "nft"]);
            c
        }
        (false, Some(ns)) => {
            let mut c = Command::new("sudo");
            c.args(["-n", "ip", "netns", "exec", ns, "nft"]);
            c
        }
    }
}

/// 跑 `nft <args>`，返回 stdout（trim）。
fn nft_run(root: bool, netns: Option<&str>, args: &[&str]) -> Result<String, String> {
    let mut c = nft_base(root, netns);
    c.args(args);
    let out = c.output().map_err(|e| format!("执行 nft 失败: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!(
            "nft {:?} 失败（code={:?}）: {}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// 经 stdin 喂脚本给 `nft -f -`（单事务原子提交）。
fn nft_apply(root: bool, netns: Option<&str>, script: &str) -> Result<(), String> {
    let mut c = nft_base(root, netns);
    c.arg("-f").arg("-");
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().map_err(|e| format!("spawn nft 失败: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("拿不到 nft stdin")?
        .write_all(script.as_bytes())
        .map_err(|e| format!("写 nft 脚本失败: {e}"))?; // 写毕即 drop → EOF
    let out = child.wait_with_output().map_err(|e| format!("等 nft 失败: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "nft -f - 失败（code={:?}）: {}\n--- 脚本 ---\n{script}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// 通用特权工具（ip 等）：root 直呼，否则 `sudo -n`（同 dmthin::priv_run）。
fn tool_run(root: bool, tool: &str, args: &[&str]) -> Result<String, String> {
    let mut c = if root {
        Command::new(tool)
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(tool);
        c
    };
    c.args(args);
    let out = c.output().map_err(|e| format!("执行 {tool} 失败: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!(
            "{tool} {:?} 失败（code={:?}）: {}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// 一张已建好的 per-sandbox 策略 table 句柄。
pub struct Sandbox {
    table: String,
    root: bool,
    netns: Option<String>,
}

impl Sandbox {
    /// 原子建 per-sandbox table：默认 drop 的 egress 链 + 空 allow4/allowport 集合。
    /// `add`+`delete`+重定义 三句一事务 → 无论先前状态如何都落到干净初值（幂等）。
    pub fn ensure(cfg: &FwCfg) -> Result<Sandbox, String> {
        let t = &cfg.table;
        let script = ensure_script(t, cfg.hook_forward);
        nft_apply(cfg.root, cfg.netns.as_deref(), &script)?;
        Ok(Sandbox { table: t.clone(), root: cfg.root, netns: cfg.netns.clone() })
    }

    /// 放行一条 (IP, 端口)：往两个集合各加一元素（原子增量，不动链/表）。
    pub fn add_allow(&self, ip: &str, port: u16) -> Result<(), String> {
        let ns = self.netns.as_deref();
        nft_run(self.root, ns, &["add", "element", "inet", &self.table, "allow4", &format!("{{ {ip} }}")])?;
        nft_run(self.root, ns, &["add", "element", "inet", &self.table, "allowport", &format!("{{ {port} }}")])?;
        Ok(())
    }

    /// 撤销一条 (IP, 端口)：从集合删元素。ADR-21 后端抽象的一员，供实例级白名单动态
    /// 收回用（resolver/编排下发）；W5 Q7 对账未走此路，故暂标 allow(dead_code)。
    #[allow(dead_code)]
    pub fn remove_allow(&self, ip: &str, port: u16) -> Result<(), String> {
        let ns = self.netns.as_deref();
        nft_run(self.root, ns, &["delete", "element", "inet", &self.table, "allow4", &format!("{{ {ip} }}")])?;
        nft_run(self.root, ns, &["delete", "element", "inet", &self.table, "allowport", &format!("{{ {port} }}")])?;
        Ok(())
    }

    /// 导出本 table 规则文本（Q7 审计证据）。
    pub fn list_ruleset(&self) -> Result<String, String> {
        nft_run(self.root, self.netns.as_deref(), &["list", "table", "inet", &self.table])
    }

    /// 销毁 = 删 table（幂等，best-effort）。
    pub fn teardown(&self) -> Result<(), String> {
        nft_run(self.root, self.netns.as_deref(), &["delete", "table", "inet", &self.table]).map(|_| ())
    }

    /// table 是否仍在（对账无残留用；list 失败即视为已删）。
    pub fn exists(&self) -> bool {
        self.list_ruleset().is_ok()
    }
}

/// nftfw Q7 对账的 TCP 探针子进程入口（被 `ip netns exec <ns> sl-node --fw-probe HOST:PORT` 拉起，
/// 从沙箱侧 netns 内发起连接）：连上返回 0，连不上（被 drop / 超时）返回 1，参数错返回 2。
pub fn probe(target: &str) -> i32 {
    use std::net::ToSocketAddrs;
    let addr = match target.to_socket_addrs().ok().and_then(|mut it| it.next()) {
        Some(a) => a,
        None => return 2,
    };
    match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// 建 host veth ⟷ netns 测试通路（点对点 /30）。需 root（ip 非白名单）。
fn setup_netns(root: bool) -> Result<(), String> {
    // 清上轮残留（best-effort）
    let _ = tool_run(root, "ip", &["netns", "del", NS]);
    let _ = tool_run(root, "ip", &["link", "del", VETH_H]);

    tool_run(root, "ip", &["netns", "add", NS])?;
    tool_run(root, "ip", &["link", "add", VETH_H, "type", "veth", "peer", "name", VETH_P])?;
    tool_run(root, "ip", &["link", "set", VETH_P, "netns", NS])?;
    tool_run(root, "ip", &["addr", "add", &format!("{HOST_IP}/30"), "dev", VETH_H])?;
    tool_run(root, "ip", &["link", "set", VETH_H, "up"])?;
    tool_run(root, "ip", &["-n", NS, "addr", "add", &format!("{PEER_IP}/30"), "dev", VETH_P])?;
    tool_run(root, "ip", &["-n", NS, "link", "set", VETH_P, "up"])?;
    tool_run(root, "ip", &["-n", NS, "link", "set", "lo", "up"])?;
    Ok(())
}

fn cleanup_netns(root: bool) {
    let _ = tool_run(root, "ip", &["netns", "del", NS]);
    let _ = tool_run(root, "ip", &["link", "del", VETH_H]); // veth 随 peer 消亡通常自动删，兜底
}

/// 从沙箱侧 netns 内探测能否连上 host 监听地址（true=连上）。
fn probe_from_netns(root: bool, exe: &str, port: u16) -> Result<bool, String> {
    let target = format!("{HOST_IP}:{port}");
    let mut c = if root {
        Command::new("ip")
    } else {
        let mut c = Command::new("sudo");
        c.args(["-n", "ip"]);
        c
    };
    c.args(["netns", "exec", NS, exe, "--fw-probe", &target]);
    let st = c.status().map_err(|e| format!("起探针失败: {e}"))?;
    Ok(st.success())
}

/// Q7 对账：同一 per-sandbox table 上验证「无策略拒绝 / 加 allow 放行 / 销毁删表无残留」，
/// 并核对 `nft list table` 可审计（含 policy drop + 放行元素）。真实 TCP 握手为证据。
/// 需 root（veth/netns 依赖 ip，本机 sudoers 未含 ip）。FAIL 返 Err（上层退非 0）。
pub fn reconcile(cfg: FwCfg, json: bool) -> Result<(), String> {
    if !cfg.root {
        return Err(
            "Q7 nft 对账需 root：veth/netns 依赖 ip，而本机 NOPASSWD 白名单未含 ip；\
             CI dmthin job 以 root 直呼跑，本地请用 `sudo -n nft -c -f -` 做语法冒烟"
                .into(),
        );
    }
    if !json {
        eprintln!("[nftfw] Q7 对账：table=inet {} netns={NS} 通路 {PEER_IP}→{HOST_IP}（root 直呼）", cfg.table);
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("取自身路径失败: {e}"))?
        .to_string_lossy()
        .to_string();

    setup_netns(cfg.root)?;

    // host 侧监听（root netns），端口交内核分配后再据此配白名单
    let listener = TcpListener::bind((HOST_IP, 0)).map_err(|e| format!("bind 监听失败: {e}"))?;
    let port = listener.local_addr().map_err(|e| format!("取监听端口失败: {e}"))?.port();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let _ = s; // accept 即完成握手，随即 drop 关闭
        }
    });

    let outcome = (|| -> Result<(bool, bool, bool, bool, String), String> {
        let sb = Sandbox::ensure(&cfg)?;

        // ① 无策略（集合空，policy drop）→ 连接应被拒
        let connected_denied = probe_from_netns(cfg.root, &exe, port)?;
        let deny_ok = !connected_denied;
        if !json {
            eprintln!("[nftfw]   ① 无 allow：连接{} → deny_ok={deny_ok}", if connected_denied { "竟成功" } else { "被拒" });
        }

        // ② 加 allow(HOST_IP, port) → 连接应放行
        sb.add_allow(HOST_IP, port)?;
        let allow_ok = probe_from_netns(cfg.root, &exe, port)?;
        if !json {
            eprintln!("[nftfw]   ② 加 allow {HOST_IP}:{port}：连接{} → allow_ok={allow_ok}", if allow_ok { "成功" } else { "仍被拒" });
        }

        // 审计：规则文本含默认 drop + 放行元素
        let ruleset = sb.list_ruleset()?;
        let audit_ok = ruleset.contains("policy drop")
            && ruleset.contains(HOST_IP)
            && ruleset.contains(&port.to_string());
        if !json {
            eprintln!("[nftfw]   审计 nft list：policy-drop+放行元素齐备 → audit_ok={audit_ok}");
        }

        // ③ 销毁删表 → table 应不复存在（无残留）
        sb.teardown()?;
        let teardown_clean = !sb.exists();
        if !json {
            eprintln!("[nftfw]   ③ 销毁删表：table {} → teardown_clean={teardown_clean}", if teardown_clean { "已消失" } else { "仍残留" });
        }

        Ok((deny_ok, allow_ok, audit_ok, teardown_clean, ruleset))
    })();

    cleanup_netns(cfg.root); // 无论成败都拆通路

    let (deny_ok, allow_ok, audit_ok, teardown_clean, _rs) = outcome?;
    let pass = deny_ok && allow_ok && audit_ok && teardown_clean;

    if json {
        println!(
            r#"{{"metric":"nft_policy","deny_ok":{deny_ok},"allow_ok":{allow_ok},"audit_ok":{audit_ok},"teardown_clean":{teardown_clean},"pass":{pass}}}"#
        );
    } else {
        eprintln!(
            "[nftfw] {} Q7：无策略拒绝={deny_ok} 加allow放行={allow_ok} 可审计={audit_ok} 销毁无残留={teardown_clean}",
            if pass { "✅ PASS" } else { "❌ FAIL" }
        );
    }
    if pass {
        Ok(())
    } else {
        Err(format!(
            "Q7 未过：deny_ok={deny_ok} allow_ok={allow_ok} audit_ok={audit_ok} teardown_clean={teardown_clean}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ensure 脚本是纯字符串生成，可无特权单测：确认关键不变量在位。
    #[test]
    fn ensure_script_shape() {
        // 直接调 ensure() 的脚本生成器（避免模板漂移），校验默认 drop + 两集合 + 放行规则齐备。
        let t = "sl_fw_ut";
        let script = ensure_script(t, false);
        assert!(script.contains("hook output"), "默认 Q7 路径为 output hook（过滤进程自身出站）");
        assert!(!script.contains("hook forward"), "非 live 变体不应挂 forward hook");
        assert!(script.contains("policy drop"), "默认必须 drop（deny-by-default）");
        assert!(script.contains("type ipv4_addr"), "需 IP 集合 allow4");
        assert!(script.contains("type inet_service"), "需端口集合 allowport");
        assert!(script.contains("ip daddr @allow4 tcp dport @allowport accept"), "需放行规则");
        // add+delete+重定义 三句一事务 → 幂等
        assert!(script.starts_with(&format!("add table inet {t}\ndelete table inet {t}\n")));
    }

    // live 变体（M2 W1）：forward hook 咬住经 netns 转发的 microVM 流量，其余不变量与 output 变体一致。
    #[test]
    fn ensure_live_script_shape() {
        let t = "sl_fw_live";
        let script = ensure_script(t, true);
        assert!(script.contains("type filter hook forward priority 0; policy drop;"), "live 变体须挂 forward hook 且默认 drop");
        assert!(!script.contains("hook output"), "live 变体不应再挂 output hook");
        // deny-by-default 语义 + 放行机制与 Q7 路径共用同一套集合/规则
        assert!(script.contains("policy drop"), "live 变体仍 deny-by-default");
        assert!(script.contains("type ipv4_addr") && script.contains("type inet_service"), "live 变体复用 allow4/allowport 集合");
        assert!(script.contains("ct state established,related accept"), "live 变体保留回程放行（否则放行的连接收不到应答）");
        assert!(script.contains("ip daddr @allow4 tcp dport @allowport accept"), "live 变体复用同一放行规则");
        assert!(script.starts_with(&format!("add table inet {t}\ndelete table inet {t}\n")), "live 变体同样三句一事务幂等");
    }

    #[test]
    fn probe_bad_target() {
        assert_eq!(probe("not-a-host:port"), 2, "非法目标应返回 2");
    }
}
