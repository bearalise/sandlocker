//! netlive — 具名 netns + veth + host NAT 出口 + tap 的 live 网络拓扑（M2 W1，root-only）。
//!
//! M1 的 live 路径用匿名 `unshare --net`（无具名句柄、无 NAT、无默认路由 → guest 出口天然为零）。
//! M2 要 gate **真实出口**：须把 microVM 放进**具名** netns（nftfw 才能 `ip netns exec` 进去下规则），
//! 并铺一条能到外网的出口通路（veth ⟷ host + 默认路由 + host NAT masquerade），再由 nftfw 的
//! **forward hook** 门禁（默认 drop + 白名单）坐在 tap→veth 的转发路径上（见 [`gate_up`]）。
//!
//! 拓扑（每沙箱）：
//! ```text
//!   microVM ──tap(sltNN)── [ 具名 netns sl-NN ] ──veth_p(slpNN)⟷veth_h(slhNN)── host root netns
//!                                   │ nft forward hook: 默认 drop + @allow4/@allowport 放行           │
//!                                   └ 默认路由 → veth_h                          NAT masquerade → uplink → 外网
//! ```
//!
//! 特权：全程 `ip`/`nft`/写 `/proc/sys`（需 root）。本机 dev 的 NOPASSWD 白名单**未含 ip**，
//! 且 nft 未装 → live 拓扑只能 root/CI 跑（同 M1 W5 Q7）。`--net-gate-reconcile`（CI dmthin job，
//! root）取证：出口通路打通 + 门禁生效（deny 默认 / 加 allow 放行）+ NAT 铺设 + 销毁无残留。
//!
//! **W1 边界（诚实标注）**：本模块 + reconcile 证明的是「拓扑 + 门禁机制 + NAT 铺设 + 无残留」。
//! reconcile 的探针进程跑在 netns **内**，其自身出站受 `hook output` 治理（故 reconcile 用 output
//! 变体取证）；`hook forward` 唯有**经 netns 转发**的真 microVM 流量（tap→veth）才触发，其端到端
//! 证明随真 VM 入环在 **W2** 落地（forward 变体在此已由 nftfw 单测 `ensure_live_script_shape` 定形）。

use std::net::TcpListener;
use std::process::Command;

use crate::nftfw;

// —— guest 侧子网（netns 内，命名空间隔离 → 各实例可复用同一段，不撞）——
// tap 网关 IP = guest 默认路由下一跳；guest eth0 IP 经内核 cmdline `ip=` 静态配置。
const GW_IP: &str = "172.16.0.1"; // netns 内 tap 网关（guest 默认路由）
const GUEST_IP: &str = "172.16.0.2"; // guest eth0 静态地址
const GUEST_CIDR: &str = "172.16.0.0/30"; // guest 子网（host NAT masquerade 之）

/// per-instance 具名 netns 名（按 id 短哈希）。多实例并发时各自独立 netns。
pub fn ns_for(id: &str) -> String {
    format!("sl-{}", short_hash(id))
}

/// per-instance forward-hook 门禁 table 名（按 id 短哈希）。
pub fn table_for(id: &str) -> String {
    format!("sl_fw_{}", short_hash(id))
}

/// per-instance **host 侧** veth /30（按 id 短哈希派生）：并发 live 实例的 host root netns veth
/// 必须各占不同网段，否则撞地址。返回 (host_ip, peer_ip)，同处一个 /30。
/// netns **内**的 tap/guest 子网可复用固定段（[`GUEST_CIDR`]，各 netns 命名空间隔离）。
fn veth_subnet(h: &str) -> (String, String) {
    let v = u32::from_str_radix(h, 16).unwrap_or(0);
    let o3 = (v >> 6) & 0xff; // 第三八位组
    let base = (v & 0x3f) << 2; // /30 块基址（.0 网络 / .1 host / .2 peer / .3 广播）
    (format!("10.234.{o3}.{}", base + 1), format!("10.234.{o3}.{}", base + 2))
}

/// 通用特权工具（ip/sysctl 等）：root 直呼，否则 `sudo -n`（同 nftfw::tool_run / dmthin::priv_run）。
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

/// 具名 netns 当前是否存在（`ip netns list` 含之）。ip 不可用（无权限/未装）时保守返回 false。
pub fn netns_exists(ns: &str) -> bool {
    let root = unsafe { libc::geteuid() } == 0;
    match tool_run(root, "ip", &["netns", "list"]) {
        Ok(s) => s.lines().any(|l| l.split_whitespace().next() == Some(ns)),
        Err(_) => false,
    }
}

/// 探测默认路由出口网卡（`ip route show default` → `dev <X>`），供 masquerade 绑定。
pub fn detect_uplink(root: bool) -> Option<String> {
    let out = tool_run(root, "ip", &["route", "show", "default"]).ok()?;
    let mut it = out.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            return it.next().map(|s| s.to_string());
        }
    }
    None
}

/// FNV-1a 32-bit：把 sandbox id 压成稳定短哈希（免 Date/random，供接口命名，≤15 字符约束）。
fn short_hash(id: &str) -> String {
    let mut h: u32 = 0x811c9dc5;
    for b in id.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    format!("{:06x}", h & 0xff_ffff)
}

/// 一套已建好的 live 网络拓扑句柄（具名 netns + veth + tap + host NAT + guest 侧接线）。root-only。
pub struct LiveNet {
    pub ns: String,     // 具名 netns（microVM 落此）
    veth_h: String,     // host 端 veth
    /// netns 内给 FC 的 tap（FC net iface 的 host_dev_name）；live_reconcile 冷启动 boot 引用。
    tap: String,
    nat_table: String,  // host root netns 里的 NAT table 名（masquerade）
    host_ip: String,    // host 端 veth /30 地址（per-instance；reconcile 监听侧 + guest 默认下一跳的对端）
    peer_ip: String,    // netns 端 veth /30 地址（per-instance）
    root: bool,
}

impl LiveNet {
    /// 建拓扑：具名 netns + **per-instance** veth /30 双端 + netns 默认路由 + host ip_forward + NAT
    /// masquerade（guest 子网）+ netns 内 tap（配网关 IP、开 netns ip_forward，供真 microVM 冷启动
    /// 挂 eth0 转发出口）+ host→guest 子网回程路由。幂等（先清同名残留）。需 root。
    /// `ns_name` 显式给定（live 用 [`ns_for`]，reconcile 用自定义），接口名/网段由 id 短哈希派生避免撞。
    pub fn up(id: &str, ns_name: &str, uplink: &str, root: bool) -> Result<LiveNet, String> {
        let h = short_hash(id);
        let veth_h = format!("slh{h}"); // ≤15：3+6=9
        let veth_p = format!("slp{h}");
        let tap = format!("slt{h}");
        let nat_table = format!("sl_nat_{h}");
        let (host_ip, peer_ip) = veth_subnet(&h);
        let net = LiveNet {
            ns: ns_name.to_string(),
            veth_h: veth_h.clone(),
            tap: tap.clone(),
            nat_table: nat_table.clone(),
            host_ip: host_ip.clone(),
            peer_ip: peer_ip.clone(),
            root,
        };

        // 先清上轮残留（best-effort，幂等）
        net.down();

        // ① 具名 netns + lo up
        tool_run(root, "ip", &["netns", "add", ns_name])?;
        tool_run(root, "ip", &["-n", ns_name, "link", "set", "lo", "up"])?;

        // ② veth pair：peer 进 netns，双端 per-instance /30
        tool_run(root, "ip", &["link", "add", &veth_h, "type", "veth", "peer", "name", &veth_p])?;
        tool_run(root, "ip", &["link", "set", &veth_p, "netns", ns_name])?;
        tool_run(root, "ip", &["addr", "add", &format!("{host_ip}/30"), "dev", &veth_h])?;
        tool_run(root, "ip", &["link", "set", &veth_h, "up"])?;
        tool_run(root, "ip", &["-n", ns_name, "addr", "add", &format!("{peer_ip}/30"), "dev", &veth_p])?;
        tool_run(root, "ip", &["-n", ns_name, "link", "set", &veth_p, "up"])?;

        // ③ netns 默认路由走 host 端（出口通路）
        tool_run(root, "ip", &["-n", ns_name, "route", "add", "default", "via", &host_ip])?;

        // ④ netns 内 tap：建设备 + 配网关 IP（guest 默认下一跳）+ up；开 netns 内 ip_forward
        //    （guest 经 tap 进来的包要被 netns 转发到 veth_p → 门禁 forward 链正坐此路径）。
        tool_run(root, "ip", &["netns", "exec", ns_name, "ip", "tuntap", "add", "dev", &tap, "mode", "tap"])?;
        tool_run(root, "ip", &["-n", ns_name, "addr", "add", &format!("{GW_IP}/30"), "dev", &tap])?;
        tool_run(root, "ip", &["-n", ns_name, "link", "set", &tap, "up"])?;
        ns_ip_forward_on(root, ns_name)?;

        // ⑤ host 开转发 + host→guest 子网回程路由 + NAT masquerade（guest 子网可达外网）
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| format!("开 host ip_forward 失败（需 root）: {e}"))?;
        // guest 子网（172.16.0.0/30）回程：host 经 veth_h 送到 netns 内 peer_ip
        let _ = tool_run(root, "ip", &["route", "replace", GUEST_CIDR, "via", &peer_ip, "dev", &veth_h]);
        let nat_script = format!(
            "add table ip {nat_table}\n\
             delete table ip {nat_table}\n\
             table ip {nat_table} {{\n\
             \tchain post {{\n\
             \t\ttype nat hook postrouting priority srcnat; policy accept;\n\
             \t\tip saddr {GUEST_CIDR} oifname \"{uplink}\" masquerade\n\
             \t}}\n\
             }}\n"
        );
        nft_apply_host(root, &nat_script)?;

        // ⑥ host FORWARD 放行本实例 veth：docker/firewalld 常把 filter FORWARD 默认 DROP（只加 NAT 不够，
        //    包会被 FORWARD policy drop 丢弃，guest 出不了公网）。per-instance keyed on veth_h（并发安全，
        //    down() 精确删）。best-effort：无 iptables / FORWARD 本就 ACCEPT 时加了也无害；用 iptables 是因为
        //    要插进 docker 所在的 filter FORWARD 链（iptables-nft 兼容），nft 独立表的 accept 压不过其 policy drop。
        let _ = tool_run(root, "iptables", &["-I", "FORWARD", "-i", &veth_h, "-j", "ACCEPT"]);
        let _ = tool_run(root, "iptables", &["-I", "FORWARD", "-o", &veth_h, "-j", "ACCEPT"]);

        Ok(net)
    }

    /// netns 内给 FC 用的 tap 名（FC net iface 的 host_dev_name）。live_reconcile 冷启动 boot 读取。
    pub fn tap(&self) -> &str {
        &self.tap
    }
    /// host 端 veth /30 地址（reconcile 监听侧；guest→此地址的流量经门禁 forward 链）。
    pub fn host_ip(&self) -> &str {
        &self.host_ip
    }
    /// guest eth0 静态地址（冷启动内核 cmdline `ip=` 用）。
    pub fn guest_ip(&self) -> &str {
        GUEST_IP
    }
    /// guest 默认路由下一跳（netns 内 tap 网关 IP）。
    pub fn gateway_ip(&self) -> &str {
        GW_IP
    }
    /// host root netns 里的 NAT masquerade 规则是否已铺（live_reconcile 审计出口通路已就位）。
    pub fn nat_masquerade_present(&self) -> bool {
        match tool_run(self.root, "nft", &["list", "table", "ip", &self.nat_table]) {
            Ok(s) => s.contains("masquerade") && s.contains("postrouting"),
            Err(_) => false,
        }
    }
    /// 拓扑残留自检（live_reconcile 用；同 reconcile 的私有版本）。
    pub fn is_clean(&self) -> bool {
        self.residue_clean()
    }

    /// 拆拓扑（幂等 best-effort）：删 netns（tap/veth_p 随之消亡）+ 删 host veth + 删 host 回程路由
    /// + 删 NAT table。具名 netns **不随进程自动回收**，必须显式删——否则残留（reconcile 校验无残留）。
    pub fn down(&self) {
        let _ = tool_run(self.root, "ip", &["netns", "del", &self.ns]);
        let _ = tool_run(self.root, "ip", &["link", "del", &self.veth_h]); // 通常随 peer 消亡自动删，兜底
        let _ = tool_run(self.root, "ip", &["route", "del", GUEST_CIDR, "via", &self.peer_ip, "dev", &self.veth_h]);
        let _ = nft_delete_host(self.root, &self.nat_table);
        // 删 host FORWARD 放行（best-effort；不存在则 iptables 报错被忽略）。
        let _ = tool_run(self.root, "iptables", &["-D", "FORWARD", "-i", &self.veth_h, "-j", "ACCEPT"]);
        let _ = tool_run(self.root, "iptables", &["-D", "FORWARD", "-o", &self.veth_h, "-j", "ACCEPT"]);
    }

    /// 拓扑残留自检（reconcile 用）：netns / host veth / NAT table 皆不在 → true。
    fn residue_clean(&self) -> bool {
        let ns_gone = !netns_exists(&self.ns);
        let veth_gone = tool_run(self.root, "ip", &["link", "show", &self.veth_h]).is_err();
        let nat_gone = tool_run(self.root, "nft", &["list", "table", "ip", &self.nat_table]).is_err();
        ns_gone && veth_gone && nat_gone
    }
}

/// 在具名 netns 内开启 ip_forward（`ip netns exec <ns> sh -c 'echo 1 > /proc/...'`；sysctl 未必装）。
fn ns_ip_forward_on(root: bool, ns: &str) -> Result<(), String> {
    let mut c = if root {
        Command::new("ip")
    } else {
        let mut c = Command::new("sudo");
        c.args(["-n", "ip"]);
        c
    };
    c.args(["netns", "exec", ns, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"]);
    let st = c.status().map_err(|e| format!("开 netns ip_forward 失败: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("开 netns {ns} ip_forward 失败（code={:?}）", st.code()))
    }
}

/// 在 host root netns 应用 nft 脚本（NAT table 建/删）。root 直呼 / 非 root `sudo -n`。
fn nft_apply_host(root: bool, script: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::process::Stdio;
    let mut c = if root {
        Command::new("nft")
    } else {
        let mut c = Command::new("sudo");
        c.args(["-n", "nft"]);
        c
    };
    c.arg("-f").arg("-");
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().map_err(|e| format!("spawn nft 失败: {e}"))?;
    child.stdin.take().ok_or("拿不到 nft stdin")?.write_all(script.as_bytes())
        .map_err(|e| format!("写 nft 脚本失败: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("等 nft 失败: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("nft -f - 失败: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn nft_delete_host(root: bool, table: &str) -> Result<(), String> {
    tool_run(root, "nft", &["delete", "table", "ip", table]).map(|_| ())
}

/// 在具名 netns 上 ensure per-sandbox 门禁 table（默认 drop + allow4/allowport 空集）。
/// `hook_forward`：live microVM 走 forward hook（true）；netns 内进程自身出站走 output hook（false）。
/// 这是 M2-Q1 的核心接线点——apply_network_policy（resume 前）与 reconcile 都经此。
pub fn gate_up(ns: &str, table: &str, root: bool, hook_forward: bool) -> Result<nftfw::Sandbox, String> {
    nftfw::Sandbox::ensure(&nftfw::FwCfg {
        table: table.to_string(),
        root,
        netns: Some(ns.to_string()),
        hook_forward,
    })
}

/// 从具名 netns 内探测能否连上 host 监听地址（true=连上）。经 `ip netns exec <ns> sl-node --fw-probe`。
fn probe_from_ns(root: bool, ns: &str, exe: &str, host_ip: &str, port: u16) -> Result<bool, String> {
    let target = format!("{host_ip}:{port}");
    let mut c = if root {
        Command::new("ip")
    } else {
        let mut c = Command::new("sudo");
        c.args(["-n", "ip"]);
        c
    };
    c.args(["netns", "exec", ns, exe, "--fw-probe", &target]);
    let st = c.status().map_err(|e| format!("起探针失败: {e}"))?;
    Ok(st.success())
}

/// M2-Q1 起步对账：建 live 出口拓扑（具名 netns + veth + NAT + tap）→ 上门禁 → 验
/// 「无 allow 拒绝 / 加 allow 放行 / 规则可审计 / NAT 已铺设 / 销毁无残留」，随后退出。需 root。
///
/// 门禁用 **output** 变体取证：探针进程跑在 netns 内，其自身出站受 output hook 治理（forward hook
/// 只治转发流量，需真 VM，留 W2）。真实 TCP 握手（netns→host veth，点对点，无需外网）为证据；
/// NAT masquerade 规则的存在性单独审计（证明外网出口通路已铺，其端到端连通同样 W2 随真 VM 验）。
pub fn reconcile(uplink_opt: Option<String>, json: bool) -> Result<(), String> {
    let root = unsafe { libc::geteuid() } == 0;
    if !root {
        return Err(
            "net_gate 对账需 root：具名 netns/veth/NAT 依赖 ip+nft，本机 NOPASSWD 白名单未含 ip 且 nft 未装；\
             CI dmthin job 以 root 直呼跑（sudo apt install nftables）".into(),
        );
    }
    let ns = "sl-gate"; // 对账专用 netns，避开 live 的 sl-live
    let table = "sl_fw_gate";
    let uplink = uplink_opt
        .or_else(|| detect_uplink(root))
        .unwrap_or_else(|| "lo".into()); // 无默认路由（隔离 runner）时退 lo：masquerade 规则仍可建，验铺设
    let net = LiveNet::up("gate", ns, &uplink, root)?;
    let host_ip = net.host_ip().to_string();
    if !json {
        eprintln!("[netlive] net_gate 对账：netns={ns} 通路 {}→{host_ip} NAT→{uplink}（root 直呼）", net.peer_ip);
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("取自身路径失败: {e}"))?
        .to_string_lossy()
        .to_string();

    // host 侧监听（root netns 的 veth_h 地址），端口交内核分配
    let listener = TcpListener::bind((host_ip.as_str(), 0)).map_err(|e| format!("bind 监听失败: {e}"))?;
    let port = listener.local_addr().map_err(|e| format!("取监听端口失败: {e}"))?.port();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let _ = s; // accept 即握手完成，随即 drop 关闭
        }
    });

    let outcome = (|| -> Result<(bool, bool, bool, bool), String> {
        // output 变体（探针进程自身出站）
        let sb = gate_up(ns, table, root, false)?;

        // ① 无 allow（集合空 + policy drop）→ 连接应被拒
        let connected_denied = probe_from_ns(root, ns, &exe, &host_ip, port)?;
        let deny_ok = !connected_denied;
        if !json {
            eprintln!("[netlive]   ① 无 allow：连接{} → deny_ok={deny_ok}", if connected_denied { "竟成功" } else { "被拒" });
        }

        // ② 加 allow(host_ip, port) → 连接应放行
        sb.add_allow(&host_ip, port)?;
        let allow_ok = probe_from_ns(root, ns, &exe, &host_ip, port)?;
        if !json {
            eprintln!("[netlive]   ② 加 allow {host_ip}:{port}：连接{} → allow_ok={allow_ok}", if allow_ok { "成功" } else { "仍被拒" });
        }

        // 审计：门禁规则含默认 drop + 放行元素；NAT masquerade 规则已铺设
        let ruleset = sb.list_ruleset()?;
        let gate_audit = ruleset.contains("policy drop") && ruleset.contains(&host_ip) && ruleset.contains(&port.to_string());
        let nat_list = tool_run(root, "nft", &["list", "table", "ip", &net.nat_table]).unwrap_or_default();
        let nat_audit = nat_list.contains("masquerade") && nat_list.contains("postrouting");
        let audit_ok = gate_audit && nat_audit;
        if !json {
            eprintln!("[netlive]   审计：门禁 policy-drop+放行元素={gate_audit} NAT masquerade 已铺={nat_audit} → audit_ok={audit_ok}");
        }

        // ③ 销毁：删门禁 table + 拆拓扑 → 皆无残留
        sb.teardown()?;
        net.down();
        let teardown_clean = !sb.exists() && net.residue_clean();
        if !json {
            eprintln!("[netlive]   ③ 销毁：门禁+netns+veth+NAT → teardown_clean={teardown_clean}");
        }

        Ok((deny_ok, allow_ok, audit_ok, teardown_clean))
    })();

    net.down(); // 无论成败都拆拓扑（幂等）

    let (deny_ok, allow_ok, audit_ok, teardown_clean) = outcome?;
    let pass = deny_ok && allow_ok && audit_ok && teardown_clean;

    if json {
        println!(
            r#"{{"metric":"net_gate","deny_ok":{deny_ok},"allow_ok":{allow_ok},"audit_ok":{audit_ok},"teardown_clean":{teardown_clean},"pass":{pass}}}"#
        );
    } else {
        eprintln!(
            "[netlive] {} M2-Q1 起步：无策略拒绝={deny_ok} 加allow放行={allow_ok} 可审计(门禁+NAT)={audit_ok} 销毁无残留={teardown_clean}",
            if pass { "✅ PASS" } else { "❌ FAIL" }
        );
    }
    if pass {
        Ok(())
    } else {
        Err(format!(
            "net_gate 未过：deny_ok={deny_ok} allow_ok={allow_ok} audit_ok={audit_ok} teardown_clean={teardown_clean}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 短哈希稳定且落在接口名长度约束内（≤15）——纯计算，可无特权单测。
    #[test]
    fn hash_stable_and_short() {
        assert_eq!(short_hash("sl0"), short_hash("sl0"), "同 id 必得同哈希（稳定）");
        assert_ne!(short_hash("sl0"), short_hash("sl1"), "不同 id 宜得不同哈希");
        let h = short_hash("some-sandbox-id");
        assert_eq!(h.len(), 6, "6 hex 字符");
        assert!(format!("slh{h}").len() <= 15, "veth 名须 ≤15（IFNAMSIZ）");
        assert!(format!("slt{h}").len() <= 15, "tap 名须 ≤15");
    }

    // per-instance netns/table 命名稳定且形态正确（纯计算，可无特权单测）。
    #[test]
    fn per_instance_naming() {
        let id = "deadbeefcafe";
        assert_eq!(ns_for(id), format!("sl-{}", short_hash(id)));
        assert_eq!(table_for(id), format!("sl_fw_{}", short_hash(id)));
        assert_eq!(ns_for(id), ns_for(id), "稳定");
        assert!(ns_for(id) != ns_for("other"), "不同 id 不同 netns");
    }

    // per-instance host 侧 /30：host/peer 同段相邻、落在 10.234/16、不同 id 多半不撞（结构断言）。
    #[test]
    fn veth_subnet_shape() {
        let (h, p) = veth_subnet(&short_hash("sandbox-A"));
        assert!(h.starts_with("10.234."), "host 侧在 10.234/16：{h}");
        assert!(p.starts_with("10.234."), "peer 侧在 10.234/16：{p}");
        // host = base+1, peer = base+2 → 末八位组相差 1
        let last = |s: &str| s.rsplit('.').next().unwrap().parse::<u32>().unwrap();
        assert_eq!(last(&p), last(&h) + 1, "peer 紧邻 host（同 /30）");
        assert_eq!(last(&h) % 4, 1, "host 落在 /30 块的 .1");
        // 稳定
        assert_eq!(veth_subnet(&short_hash("sandbox-A")), veth_subnet(&short_hash("sandbox-A")));
    }
}
