//! api.rs — 长驻守护 + 手写极简 REST server（M1 W8，PRD §9 v1alpha / 7.10）。
//!
//! D3：控制面单进程、全组件进程内。`sl-node --serve` 起长驻守护——HTTP API + orchestrator
//! （[`crate::orch::Orch`]）+ 后台 reaper tick 全在一进程，SQLite 元数据（PRD 7.10 单机一体化）。
//! 用户面 `sandlocker` CLI（`crates/sandlocker`）作为 REST 客户端连本守护。
//!
//! **REST-only + 手写 HTTP/1.1**（延续 D1 `fcapi.rs`「无重依赖 + 全同步 std」风格；不引 tokio/tonic）。
//! gRPC 服务端延后 M2（本周仅出 `contracts/sandlocker.proto` 双描述）。契约先行：路由/字段与
//! `contracts/openapi.yaml` 逐一对齐，W9 Python SDK 据此生成。
//!
//! 边界（如实标注）：仅支持 `Content-Length` + `Connection: close`（不支持 chunked/keep-alive）；
//! 守护级操作（create/destroy/tick）在 `orch.lock()` 内**串行**（单机 MVP，密度/并发吞吐属 M2 池化）；
//! exec/文件/日志的慢 IO 在**取路径后释放锁**再做，不阻塞 reaper/create。

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sl_store::election::Election;
use sl_store::{SqliteStore, Store};

use sl_proto::{parse_exec_output, read_frame, read_msg, write_msg, ExecOutput, Request, Response};

use crate::backend::{Capabilities, ExecTarget, UNSUPPORTED_BY_BACKEND};
use crate::expose::{self, ExposeHandle};
use crate::gateway::{parse_query, proxy_port_http, Action, Gateway, Ticket};
use crate::orch::{NetworkMode, Orch, SandboxSpec};
use crate::{connect_guest, Config};

/// 守护共享态：orchestrator（互斥）+ 模板仓库根（模板名→目录解析）。
type Shared = Arc<Mutex<Orch<'static>>>;
/// 数据面网关（ADR-22）：控制面签发 + 网关验签共用（单机进程内）。
type SharedGw = Arc<Gateway>;

/// 鉴权上下文（M3 W6 多租户，FR-7.1）：`require=false`（默认/单机）→ 不鉴权（M2 行为，零回归）；
/// `require=true`（`--require-auth`）→ 每请求校验 API Key + 作用域 + 跨项目门控。`store` 为独立句柄。
pub struct AuthCtx {
    require: bool,
    store: Box<dyn Store>,
}
type SharedAuth = Arc<AuthCtx>;

/// 鉴权 + 授权判定。成功返回调用者 project（`None`=未开启鉴权）；失败返回 `(状态码, 错误体)`。
/// 跨项目门控：sandbox-id 路由须该沙箱归属 == 调用者 project（无归属键→鉴权模式下不可见）。
fn authorize(
    auth: &SharedAuth,
    shared: &Shared,
    op: crate::auth::Op,
    sid: Option<&str>,
    key: Option<&str>,
) -> Result<Option<String>, (u16, Vec<u8>)> {
    if !auth.require {
        return Ok(None);
    }
    let key = key.ok_or((401, err_json("缺 API Key（Authorization: Bearer <token> 或 X-API-Key）")))?;
    let rec = crate::auth::lookup(auth.store.as_ref(), key)
        .map_err(|e| (500, err_json(&e)))?
        .ok_or((401, err_json("API Key 无效")))?;
    if !rec.scope.allows(op) {
        return Err((403, err_json(&format!("作用域不足：{} 不允许该操作", rec.scope.as_str()))));
    }
    if let Some(id) = sid {
        let proj = shared.lock().unwrap().sandbox_project(id).map_err(|e| (500, err_json(&e)))?;
        match proj {
            Some(p) if p == rec.project => {}
            Some(_) => return Err((403, err_json("跨项目访问被拒"))),
            None => return Err((404, err_json("未知沙箱"))),
        }
    }
    Ok(Some(rec.project))
}

/// 端口暴露（L4 透传）共享态：sid→guest_port→监听器句柄 + 对外 bind 放行开关。
/// 打包进一个 Arc 避免在 handle_conn/dispatch/reaper 到处加参数。
pub(crate) struct ExposeState {
    registry: Mutex<HashMap<String, HashMap<u32, ExposeHandle>>>,
    /// `--expose-allow-public`：未开启时拒绝非回环 bind（对外暴露须显式选择）。
    allow_public: bool,
}
pub(crate) type Exposes = Arc<ExposeState>;

/// 停止并移除某沙箱的全部暴露监听器（destroy/回收路径调用，防悬挂/线程泄漏）。
fn drop_exposes(exposes: &Exposes, id: &str) {
    if let Some(m) = exposes.registry.lock().unwrap().remove(id) {
        for (_gp, h) in m {
            h.stop();
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// 解析守护三路径（默认与 `--build` 产出一致：store=build/templates/sl.db，模板根=build/templates）。
fn resolve_paths(cfg: &Config) -> (PathBuf, PathBuf, PathBuf) {
    let store_path = cfg.store.clone().unwrap_or_else(|| PathBuf::from("build/templates/sl.db"));
    let template_root = cfg.template_root.clone().unwrap_or_else(|| PathBuf::from("build/templates"));
    let run_root = cfg.run_root.clone().unwrap_or_else(|| cfg.workdir.join("instances"));
    (store_path, template_root, run_root)
}

/// 打开一个 store 句柄：`--etcd <ep>` → EtcdStore（集群模式，需 cluster feature）；否则 SQLite（单机）。
/// M3 W4：daemon 迁 etcd 的装配点——Orch/心跳/选举各取一个独立句柄。
fn open_store(cfg: &Config, db_str: &str) -> Result<Box<dyn Store>, String> {
    if let Some(ep) = &cfg.etcd {
        #[cfg(feature = "cluster")]
        {
            return Ok(Box::new(sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?));
        }
        #[cfg(not(feature = "cluster"))]
        {
            return Err(format!("--serve --etcd {ep} 需以 `--features cluster` 构建 sl-node"));
        }
    }
    Ok(Box::new(SqliteStore::open(db_str).map_err(|e| format!("打开 store 失败: {e}"))?))
}

/// 起守护：打开 store → 建 Orch（`Box::leak` cfg 得 `'static`）→ reaper 线程 → TCP accept 循环。
pub fn serve(cfg: &Config) -> Result<(), String> {
    let addr = cfg.serve_addr.clone().unwrap_or_else(|| "127.0.0.1:7878".to_string());
    let (store_path, template_root, run_root) = resolve_paths(cfg);

    if let Some(parent) = store_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("建 store 目录失败: {e}"))?;
    }
    std::fs::create_dir_all(&template_root).map_err(|e| format!("建模板根失败: {e}"))?;
    std::fs::create_dir_all(&run_root).map_err(|e| format!("建 run_root 失败: {e}"))?;
    let db_str = store_path.to_str().ok_or("store 路径非 UTF-8")?;
    // M3 W4：store 后端 = --etcd 时 EtcdStore（集群共享态），否则 SQLite（单机）。
    let store = open_store(cfg, db_str)?;
    let etcd_mode = cfg.etcd.is_some();

    // Orch<'a> 借 &Config；守护存活全程 → leak 得 'static（无需改 Orch 生命周期）。
    let cfg_s: &'static Config = Box::leak(Box::new(cfg.clone()));
    // 默认模板占位：守护恒走 create_in（显式模板），此占位不被 create() 使用；取模板根（存在即合法）。
    let mut orch = Orch::new(cfg_s, &template_root, &run_root, store)?;

    // M2 W4 温池：--pool-size>0 且指定 --pool-template 时，解析该模板→建单模板温池。请求命中同
    // 模板走池命中路径（copy_ms=0），其它模板/未启用均走冷路径（零回归）。模板解析失败仅告警不阻塞。
    // M2 W5 热池：--pool-template 解析成功且 --hot-size>0 时，为该模板预置暂停态 VM（命中优先于温池）。
    if (cfg.pool_size > 0 || cfg.hot_size > 0) && cfg.pool_template.is_some() {
        let name = cfg.pool_template.clone().unwrap();
        match resolve_template(&orch, &template_root, &name) {
            Ok(dir) => {
                if cfg.pool_size > 0 {
                    orch.enable_warm_pool(&dir, cfg.pool_size)?;
                    println!("[sandlocker] 温池已启用：template={name} size={} dir={}", cfg.pool_size, dir.display());
                }
                if cfg.hot_size > 0 {
                    orch.enable_hot_pool(&dir, cfg.hot_size)?;
                    println!("[sandlocker] 热池已启用：template={name} size={}（暂停态 VM 常驻内存）", cfg.hot_size);
                }
            }
            Err(e) => eprintln!("[sandlocker] 池未启用（模板解析失败，走冷路径）: {e}"),
        }
    }
    // M3 W3（M3-Q2）：本节点 id（addr#pid）。设入 Orch → 创建的沙箱写归属键 `sandbox/<id>/node`，
    // 供失联节点的沙箱被 leader 回收。
    let node_id = format!("{addr}#{}", std::process::id());
    orch.set_node_id(&node_id);
    // 同一身份也曝到 /metrics 上（`sandlocker_build_info{node=...}`）：看板按节点拆分要它，
    // 集群基准要靠它问出「哪个副本是这个沙箱的 owner」——否则副本身份只存在于启动日志与
    // etcd 键里，跨机取证时两者都够不着。
    crate::metrics::metrics().set_node_id(&node_id);
    let shared: Shared = Arc::new(Mutex::new(orch));

    // 端口暴露注册表（L4 透传监听器）。allow_public 由 --expose-allow-public 控制。
    let exposes: Exposes = Arc::new(ExposeState {
        registry: Mutex::new(HashMap::new()),
        allow_public: cfg.expose_allow_public,
    });

    // M3 W6 多租户鉴权（FR-7.1）：--require-auth 开启后每请求校验 API Key + 作用域 + 跨项目门控。
    // 默认关闭（M2 行为，零回归）。用独立 store 句柄（与 Orch 解耦，鉴权只读 apikey/*）。
    let auth: SharedAuth = Arc::new(AuthCtx {
        require: cfg.require_auth,
        store: open_store(cfg, db_str)?,
    });
    if cfg.require_auth {
        println!("[sandlocker] 多租户鉴权已开启（--require-auth）：所有 /v1 请求需 API Key + 作用域");
    }

    // M3 W8 可观测：结构化日志转发 sink（--log-sink）。
    crate::logsink::init(cfg.log_sink.clone());
    if let Some(sink) = &cfg.log_sink {
        println!("[sandlocker] 结构化日志转发已开启：sink={sink}");
    }

    // M3 W2/W4（M3-Q2）：leader 选举门控。
    //   - 单机 SQLite（无 --etcd）：ADR-17「单机无选主」→ 恒 leader（零回归）。
    //   - 集群 etcd（--etcd）：**激活** `sl_store::election`——多副本竞争，仅 leader 跑 reaper/回收，
    //     standby 热备（不 tick，防双写）；leader 崩溃 → 租约过期 → standby 夺主。
    let is_leader = Arc::new(AtomicBool::new(!etcd_mode));
    if etcd_mode {
        let elect_store = open_store(cfg, db_str)?;
        let node_id_el = node_id.clone();
        let ttl = std::cmp::max(cfg.tick_secs as i64 * 3, 15);
        let period = std::cmp::max((ttl / 3) as u64, 1);
        let mut election = Election::new(elect_store, &node_id_el, ttl);
        let leader_flag = Arc::clone(&is_leader);
        thread::spawn(move || {
            let mut last = false;
            loop {
                let now_leader = election.try_campaign().unwrap_or(false);
                if now_leader != last {
                    if now_leader {
                        println!("[sandlocker] 本副本当选 leader（{node_id_el}）→ 启用 reaper/回收");
                    } else {
                        println!("[sandlocker] 本副本转 standby（暂停 reaper/回收）");
                    }
                    last = now_leader;
                }
                leader_flag.store(now_leader, Ordering::SeqCst);
                thread::sleep(Duration::from_secs(period));
            }
        });
    }

    // M3 W3（M3-Q2）：节点心跳（易失态走 lease TTL，ADR-17）。本节点在 `node/<id>` 写存活键并周期
    // 续租；崩溃/失联 → 租约到期 → 键消失 → leader 回收其名下沙箱。用独立 store 句柄（同文件另一连接）。
    // 单机：仅本节点、恒存活、无孤儿（回收含护栏，绝不回收自己名下沙箱）。
    {
        let hb_store = open_store(cfg, db_str)?;
        let node_id_hb = node_id.clone();
        // 心跳键的值现在带**容量**（cpus/mem_mib）——调度器据此决定往哪台放（sched.rs）。
        // 随心跳刷新而非只写一次：机器规格可能因重启/内核参数（如 `mem=128G maxcpus=64`）变化。
        let meta = crate::sched::local_capacity(&addr).to_json();
        // 心跳租约窗 max(tick*3, 15s)；续租周期 ~ttl/3。
        let ttl = std::cmp::max(cfg.tick_secs as i64 * 3, 15);
        let period = std::cmp::max((ttl / 3) as u64, 1);
        thread::spawn(move || {
            let mut lease = sl_store::cluster::register_node(hb_store.as_ref(), &node_id_hb, meta.as_bytes(), ttl).ok();
            loop {
                thread::sleep(Duration::from_secs(period));
                let alive = match lease {
                    Some(l) => sl_store::cluster::heartbeat(hb_store.as_ref(), l).is_ok(),
                    None => false,
                };
                // 续租只延长租约，不更新值——容量若变了（重启改内核参数）得重写一次。
                if alive {
                    let _ = hb_store.put(&sl_store::cluster::node_key(&node_id_hb), meta.as_bytes(), lease);
                }
                if !alive {
                    // 租约丢失（被 sweep/首次注册失败）→ 重新注册，恢复存活。
                    lease = sl_store::cluster::register_node(hb_store.as_ref(), &node_id_hb, meta.as_bytes(), ttl).ok();
                }
            }
        });
    }

    // 后台 reaper：周期 tick(now)（TTL 硬顶 + idle sweep）+ 回收失联节点的孤儿沙箱。回收的沙箱须
    // 同步拆掉其暴露监听器。仅 leader 执行——standby 不 tick/回收（active-standby 无双写；单机恒 leader）。
    let tick_secs = if cfg.tick_secs > 0 { cfg.tick_secs } else { 5 };
    let reaper = Arc::clone(&shared);
    let reaper_ex = Arc::clone(&exposes);
    let reaper_leader = Arc::clone(&is_leader);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(tick_secs));
        if !reaper_leader.load(Ordering::SeqCst) {
            continue; // standby：不回收，避免与 leader 双写
        }
        let now = now_unix();
        if let Ok(mut o) = reaper.lock() {
            if let Ok(reaped) = o.tick(now) {
                for id in reaped {
                    drop_exposes(&reaper_ex, &id);
                    crate::metrics::metrics().record_destroy(); // M3 W8：idle/TTL 回收计入
                }
            }
            // M3 W3：回收失联节点（心跳 lease 过期→node 键消失）名下的孤儿沙箱（护栏不碰自己的）。
            if let Ok(orphans) = o.reclaim_orphans() {
                if !orphans.is_empty() {
                    for id in &orphans {
                        drop_exposes(&reaper_ex, id);
                        crate::metrics::metrics().record_destroy();
                    }
                    println!("[sandlocker] 回收失联节点的孤儿沙箱: {orphans:?}");
                }
            }
            // M3 W10（ADR-16）：GC 过期的 paused 快照（保留期到期，默认 7 天）。
            if let Ok(expired) = o.gc_retention(now) {
                if !expired.is_empty() {
                    for id in &expired {
                        drop_exposes(&reaper_ex, id);
                        crate::metrics::metrics().record_destroy();
                    }
                    println!("[sandlocker] 保留期过期回收 paused 快照: {expired:?}");
                }
            }
        }
    });

    // 模板根提前泄漏成 'static：网关监听线程与数据面外拨代理都要它（`/gw/create` 要按模板名
    // 解析模板目录），两者都是 'static 线程。
    let troot: &'static Path = Box::leak(template_root.clone().into_boxed_path());

    // M2 W10 数据面网关（ADR-22）：独立监听（默认 127.0.0.1:7879），与控制面同进程共享 orch + secret。
    let gw_addr = cfg.gw_addr.clone().unwrap_or_else(|| "127.0.0.1:7879".to_string());
    // M3 W5：集群模式网关走**共享 secret + store 一次性 nonce**（任一副本验任一副本签发的 ticket、
    // 一次性跨副本；ADR-22）；单机沿用进程内随机 secret（零回归）。
    // ticket 的外部基址：给了 `--gw-url`（独立 `sandlocker-gw`，M3 W5 余项）就签向它——
    // 客户端据此直连网关，网关再中继到 owning 节点；否则签向本进程内网关（M2 行为）。
    let gw_base = cfg.gw_url.clone().unwrap_or_else(|| format!("http://{gw_addr}"));
    let gw: SharedGw = if etcd_mode {
        Arc::new(Gateway::new_shared(gw_base, open_store(cfg, db_str)?)?)
    } else {
        Arc::new(Gateway::new_random(gw_base))
    };
    {
        let gw_l = Arc::clone(&gw);
        let sh_l = Arc::clone(&shared);
        let ex_l = Arc::clone(&exposes);
        let bind = gw_addr.clone();
        match TcpListener::bind(&bind) {
            Ok(gwl) => {
                println!("[sandlocker] 数据面网关就绪 http://{bind}（一次性 HMAC 签名 URL；/gw/*）");
                thread::spawn(move || {
                    for conn in gwl.incoming().flatten() {
                        let (g, s, x) = (Arc::clone(&gw_l), Arc::clone(&sh_l), Arc::clone(&ex_l));
                        thread::spawn(move || {
                            if let Err(e) = handle_gw_conn(conn, &s, &g, &x, troot) {
                                eprintln!("[sandlocker] 网关连接错误: {e}");
                            }
                        });
                    }
                });
            }
            Err(e) => eprintln!("[sandlocker] 网关 bind {bind} 失败（数据面不可用）: {e}"),
        }
    }

    let listener = TcpListener::bind(&addr).map_err(|e| format!("bind {addr} 失败: {e}"))?;
    let store_desc = match &cfg.etcd {
        Some(ep) => format!("etcd={ep}（集群模式·多副本 active-standby）"),
        None => format!("store={}（单机 SQLite）", store_path.display()),
    };
    println!(
        "[sandlocker] API 守护就绪 http://{addr}（node={node_id} {store_desc} templates={} run={} tick={tick_secs}s）",
        template_root.display(),
        run_root.display()
    );

    // M3 W5 余项（ADR-22）：集群身份 + 网关基址。`--gw-url` 未给 = 单机，跨节点转发整条关掉（零回归）。
    let rt: SharedRemote = Arc::new(Remote {
        node_id: node_id.clone(),
        gw_url: cfg.gw_url.clone(),
        sched: crate::sched::Policy { overcommit: cfg.sched_overcommit },
    });

    // M3 W5 余项：节点侧**主动外拨**代理——预拨若干持久连接停在独立网关上，供网关反向借用
    // 服务本节点沙箱的数据面请求。**节点不因此监听任何入站端口**。
    if let Some(gw_node) = &cfg.gw_node_endpoint {
        let tls = cfg.gw_tls_opts()?;
        if tls.is_none() {
            eprintln!("[sandlocker][WARN] 数据面外拨未启用 mTLS（--gw-insecure）：仅限本机对账/开发");
        }
        let sh = Arc::clone(&shared);
        let ex = Arc::clone(&exposes);
        crate::dataplane::start_node_agent(
            crate::dataplane::AgentCfg {
                gw_addr: gw_node.clone(),
                node_id: node_id.clone(),
                pool: cfg.gw_pool,
                max_streams: cfg.gw_max_streams,
                tls,
            },
            Arc::new(move |ticket, ch| {
                let mut ch = ch;
                // 网关已验签并下发 ticket；这里读它复刻的 HTTP 请求，走**与进程内网关同一段**分发。
                match read_request(&mut ch) {
                    Ok((method, path, _k, body)) => {
                        if let Err(e) = serve_gw_ticket(&mut ch, &ticket, &method, &path, &body, &sh, &ex, troot) {
                            eprintln!("[sandlocker][gw-agent] 服务 {} 失败: {e}", ticket.sid);
                        }
                    }
                    Err(e) => eprintln!("[sandlocker][gw-agent] 读中继请求失败: {e}"),
                }
                ch.0.shutdown_write();
            }),
        )?;
        println!("[sandlocker] 数据面外拨就绪 → {gw_node}（node={node_id} pool={}，节点零入站）", cfg.gw_pool);
    }

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let sh = Arc::clone(&shared);
                let g = Arc::clone(&gw);
                let e = Arc::clone(&exposes);
                let a = Arc::clone(&auth);
                let r = Arc::clone(&rt);
                thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, &sh, troot, &g, &e, &a, &r) {
                        eprintln!("[sandlocker] 连接处理错误: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[sandlocker] accept 失败: {e}"),
        }
    }
    Ok(())
}

// ————————————————————— HTTP 请求解析 / 响应封装（手写，照 fcapi.rs）—————————————————————

/// 读一个请求：解析请求行 `(method, path)` + 按 `Content-Length` 精确读 body。
/// 从 header 段取 API Key：优先 `Authorization: Bearer <t>`，其次 `X-API-Key: <t>`。
fn extract_api_key(head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            if k.eq_ignore_ascii_case("authorization") {
                if let Some(t) = v.trim().strip_prefix("Bearer ").or_else(|| v.trim().strip_prefix("bearer ")) {
                    return Some(t.trim().to_string());
                }
            }
            if k.eq_ignore_ascii_case("x-api-key") {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

pub(crate) fn read_request<S: Read>(
    stream: &mut S,
) -> Result<(String, String, Option<String>, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(p) = find_crlfcrlf(&buf) {
            break p;
        }
        let n = stream.read(&mut chunk).map_err(|e| format!("读请求头失败: {e}"))?;
        if n == 0 {
            return Err("请求未含完整 header（连接过早关闭）".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err("请求头过大".into());
        }
    };
    let head = &buf[..head_end];
    let (method, path) = parse_request_line(head)?;
    let api_key = extract_api_key(head);
    let want = head_end + 4 + content_length(head);
    while buf.len() < want {
        let n = stream.read(&mut chunk).map_err(|e| format!("读请求体失败: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = buf[head_end + 4..].to_vec();
    Ok((method, path, api_key, body))
}

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 解析请求行首行："METHOD /path HTTP/1.1" → (METHOD, /path)。
fn parse_request_line(head: &[u8]) -> Result<(String, String), String> {
    let first = head.split(|&b| b == b'\n').next().unwrap_or(head);
    let line = String::from_utf8_lossy(first);
    let mut it = line.split_whitespace();
    let method = it.next().ok_or("请求行无方法")?.to_string();
    let path = it.next().ok_or("请求行无路径")?.to_string();
    Ok((method, path))
}

fn content_length(head: &[u8]) -> usize {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "OK",
    }
}

pub(crate) fn write_response<S: Write>(stream: &mut S, code: u16, ctype: &str, body: &[u8]) -> Result<(), String> {
    let head = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(code),
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(|e| format!("写响应头失败: {e}"))?;
    stream.write_all(body).map_err(|e| format!("写响应体失败: {e}"))?;
    stream.flush().map_err(|e| format!("flush 失败: {e}"))
}

/// JSON 错误体（application/json）。
pub(crate) fn err_json(msg: &str) -> Vec<u8> {
    format!(r#"{{"error":"{}"}}"#, msg.replace('\\', "\\\\").replace('"', "\\\"")).into_bytes()
}

// ————————————————————— 路由（纯逻辑，单测）—————————————————————

#[derive(Debug, PartialEq, Eq)]
enum Route {
    CreateSandbox,
    ListSandboxes,
    GetSandbox(String),
    DeleteSandbox(String),
    Keepalive(String),
    Pause(String),
    Resume(String),
    Fork(String),
    Ticket(String),
    Expose(String),
    Unexpose(String, u32),
    ListExposes(String),
    Exec(String),
    PutFile(String, String),
    GetFile(String, String),
    Logs(String),
    ListTemplates,
    BuildTemplate,
    ListBackends,
    AuditLog,
    Metrics,
    NotFound,
}

impl Route {
    /// 本路由所需的操作类别（M3 W6 鉴权）；NotFound 无需鉴权（走 404）。
    fn required_op(&self) -> Option<crate::auth::Op> {
        use crate::auth::Op;
        Some(match self {
            Route::ListSandboxes | Route::GetSandbox(_) | Route::Logs(_) | Route::ListExposes(_)
            | Route::GetFile(_, _) | Route::ListTemplates | Route::ListBackends | Route::AuditLog => Op::Read,
            Route::BuildTemplate => Op::Build,
            Route::CreateSandbox | Route::DeleteSandbox(_) | Route::Keepalive(_) | Route::Pause(_)
            | Route::Resume(_) | Route::Fork(_) | Route::Ticket(_) | Route::Expose(_)
            | Route::Unexpose(_, _) | Route::Exec(_) | Route::PutFile(_, _) => Op::Write,
            // /metrics 免鉴权（Prometheus 抓取，仅聚合数，无租户数据）；NotFound 走 404。
            Route::Metrics | Route::NotFound => return None,
        })
    }

    /// 审计动作名（M3 W7，FR-7.3）。
    fn audit_action(&self) -> &'static str {
        match self {
            Route::CreateSandbox => "create_sandbox",
            Route::DeleteSandbox(_) => "delete_sandbox",
            Route::Keepalive(_) => "keepalive",
            Route::Pause(_) => "pause",
            Route::Resume(_) => "resume",
            Route::Fork(_) => "fork",
            Route::Ticket(_) => "mint_ticket",
            Route::Expose(_) => "expose",
            Route::Unexpose(_, _) => "unexpose",
            Route::Exec(_) => "exec",
            Route::PutFile(_, _) => "put_file",
            Route::BuildTemplate => "build_template",
            _ => "other",
        }
    }

    /// 携带沙箱 id 的路由 → Some(id)（供跨项目访问门控）；无 id 路由 → None。
    fn sandbox_id(&self) -> Option<&str> {
        match self {
            Route::GetSandbox(id) | Route::DeleteSandbox(id) | Route::Keepalive(id) | Route::Pause(id)
            | Route::Resume(id) | Route::Fork(id) | Route::Ticket(id) | Route::Expose(id)
            | Route::Unexpose(id, _) | Route::ListExposes(id) | Route::Exec(id) | Route::Logs(id)
            | Route::PutFile(id, _) | Route::GetFile(id, _) => Some(id),
            _ => None,
        }
    }
}

/// 纯路由：`(method, path)` → `Route`。path 去 query；`/files/` 后整段（含 `/`）作文件路径。
fn parse_route(method: &str, path: &str) -> Route {
    let path = path.split('?').next().unwrap_or(path);
    let trimmed = path.trim_matches('/');
    let segs: Vec<&str> = if trimmed.is_empty() { vec![] } else { trimmed.split('/').collect() };
    match (method, segs.as_slice()) {
        ("POST", ["v1", "sandboxes"]) => Route::CreateSandbox,
        ("GET", ["v1", "sandboxes"]) => Route::ListSandboxes,
        ("GET", ["v1", "templates"]) => Route::ListTemplates,
        ("GET", ["v1", "backends"]) => Route::ListBackends,
        ("GET", ["v1", "audit"]) => Route::AuditLog,
        ("GET", ["metrics"]) => Route::Metrics,
        ("POST", ["v1", "templates:build"]) => Route::BuildTemplate,
        ("GET", ["v1", "sandboxes", id]) => Route::GetSandbox((*id).to_string()),
        ("DELETE", ["v1", "sandboxes", id]) => Route::DeleteSandbox((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "keepalive"]) => Route::Keepalive((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "pause"]) => Route::Pause((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "resume"]) => Route::Resume((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "fork"]) => Route::Fork((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "ticket"]) => Route::Ticket((*id).to_string()),
        ("POST", ["v1", "sandboxes", id, "expose"]) => Route::Expose((*id).to_string()),
        ("GET", ["v1", "sandboxes", id, "exposes"]) => Route::ListExposes((*id).to_string()),
        ("DELETE", ["v1", "sandboxes", id, "expose", gp]) => match gp.parse() {
            Ok(p) => Route::Unexpose((*id).to_string(), p),
            Err(_) => Route::NotFound,
        },
        ("POST", ["v1", "sandboxes", id, "exec"]) => Route::Exec((*id).to_string()),
        ("GET", ["v1", "sandboxes", id, "logs"]) => Route::Logs((*id).to_string()),
        (m, [.., ]) if segs.len() >= 5 && segs[0] == "v1" && segs[1] == "sandboxes" && segs[3] == "files" => {
            let id = segs[2].to_string();
            let fpath = segs[4..].join("/");
            match m {
                "PUT" => Route::PutFile(id, fpath),
                "GET" => Route::GetFile(id, fpath),
                _ => Route::NotFound,
            }
        }
        _ => Route::NotFound,
    }
}

// ——————————— 跨节点转发（数据面 M3 W5 余项 / 控制面 M3 W4 余项，ADR-22 / M3-Q3）———————————

/// 该路由是否**必须在 owning 节点受理**（故可经网关中继过去）；是则给出
/// (ticket 动作, HTTP 方法, 签进票里的 port, 附加 query)。
///
/// 判据是「这件事的状态在哪」：
/// - **数据面**（exec/logs/files/stream，M2 起）：落到 guest 的 vsock 通道，通道只在 owning 节点。
/// - **控制面**（pause/resume/fork/destroy/keepalive/expose，M3 W4 余项）：落到 owning 节点的
///   `Orch::live` 表（内存态：lease 句柄、ttl 硬顶、后端归属）与后端进程（FC 的 API socket、
///   jailer 目录）上。**这些都不在 etcd 里**，所以别的副本读同一份 etcd 也办不了——
///   此前它们直接落到本副本的 `live` 表上查无此人，一律 404。
///
/// 其余（GetSandbox/ListSandboxes/审计/模板/配额）纯读 store，任一副本自足，不转。
///
/// `port` 走**签名**字段而非查询串：`Unexpose` 要指明拆哪个 guest 端口，签进票里才不可篡改。
fn forwardable_route(route: &Route) -> Option<(Action, &'static str, u32, String)> {
    match route {
        // —— 数据面（M3 W5 余项）——
        Route::Exec(_) => Some((Action::Exec, "POST", 0, String::new())),
        Route::Logs(_) => Some((Action::Logs, "GET", 0, String::new())),
        Route::GetFile(_, p) => Some((Action::File, "GET", 0, format!("&p={p}"))),
        Route::PutFile(_, p) => Some((Action::File, "PUT", 0, format!("&p={p}"))),
        // —— 控制面（M3 W4 余项）——
        Route::Pause(_) => Some((Action::Pause, "POST", 0, String::new())),
        Route::Resume(_) => Some((Action::Resume, "POST", 0, String::new())),
        Route::Fork(_) => Some((Action::Fork, "POST", 0, String::new())),
        Route::DeleteSandbox(_) => Some((Action::Destroy, "DELETE", 0, String::new())),
        Route::Keepalive(_) => Some((Action::Keepalive, "POST", 0, String::new())),
        Route::Expose(_) => Some((Action::Expose, "POST", 0, String::new())),
        Route::Unexpose(_, gp) => Some((Action::Unexpose, "DELETE", *gp, String::new())),
        Route::ListExposes(_) => Some((Action::Exposes, "GET", 0, String::new())),
        _ => None,
    }
}

/// 本副本的集群身份 + 网关基址。`gw_url=None`（单机）时一切按 M2 行为走，零回归。
pub(crate) struct Remote {
    /// 本节点 id（与 `node/<id>` 心跳键、`sandbox/<sid>/node` 归属键同值）。
    pub node_id: String,
    /// 独立网关面向客户端的基址（`http://host:port`，`--gw-url`）。
    pub gw_url: Option<String>,
    /// 放置策略（`--sched-overcommit`）。
    pub sched: crate::sched::Policy,
}

type SharedRemote = Arc<Remote>;

/// 沙箱是否**不在本节点**：在本节点或归属未知 → None；在别的节点 → Some(owner)。
///
/// 判据取 `sandbox/<sid>/node`（M3 W3 写入的归属键）。归属键不存在（单机遗留/尚未写入）时
/// 一律按本地处理——宁可回 404 也不把请求转给不确定的节点。
fn remote_owner(shared: &Shared, rt: &Remote, id: &str) -> Option<String> {
    if rt.gw_url.is_none() {
        return None; // 单机：无网关可转，走本地路径（M2 行为）
    }
    let o = shared.lock().unwrap();
    if o.exec_target(id).is_some() {
        return None; // 就在本节点
    }
    let owner = o
        .store_get(&sl_store::cluster::sandbox_node_key(id))
        .ok()
        .flatten()
        .map(|v| String::from_utf8_lossy(&v).into_owned())?;
    if owner == rt.node_id {
        None
    } else {
        Some(owner)
    }
}

/// 把一次数据面请求经**独立网关**转到 owning 节点，并把网关的响应**原样**回灌客户端。
///
/// 本副本与网关共享 ticket secret（`cluster/gw_secret`），故这里自签的一次性票网关可无状态验签
/// ——控制面副本不需要知道目标节点在哪、也不持任何数据连接态（无粘滞）。
///
/// 响应逐块转发、不缓冲整体，故流式 exec 的 NDJSON 增量能实时到达客户端。
/// 返回网关实际回的状态码，供本副本如实记指标（不能假定 200——网关可能 404/502/503）。
fn forward_via_gw<S: Read + Write>(
    client: &mut S,
    rt: &Remote,
    gw: &Gateway,
    sid: &str,
    action: Action,
    port: u32,
    method: &str,
    extra_query: &str,
    body: &[u8],
) -> Result<u16, String> {
    let (code, _) = relay_via_gw(Some(client), rt, gw, sid, action, port, method, extra_query, body)?;
    Ok(code)
}

/// 同上，但**缓冲**响应并交回调用方，不直接回灌客户端。
///
/// 创建走这条：副本拿到新沙箱 id 之后还要给它打项目归属键（`sandbox/<id>/project`），
/// 所以响应必须先读到手。响应是一小段 JSON，缓冲无妨——真正不能缓冲的是 exec 流那种
/// 未定长的增量响应，那条仍走上面的流式路径。
fn forward_via_gw_buffered(
    rt: &Remote,
    gw: &Gateway,
    sid: &str,
    action: Action,
    method: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    relay_via_gw(None::<&mut TcpStream>, rt, gw, sid, action, 0, method, "", body)
}

/// 中继实现。`client=Some` → 逐块回灌（流不被缓冲住）；`None` → 缓冲整条响应回传。
#[allow(clippy::too_many_arguments)]
fn relay_via_gw<S: Read + Write>(
    mut client: Option<&mut S>,
    rt: &Remote,
    gw: &Gateway,
    sid: &str,
    action: Action,
    port: u32,
    method: &str,
    extra_query: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let base = rt.gw_url.as_deref().ok_or("未配置 --gw-url，无法跨节点转发")?;
    let host_port = base.trim_start_matches("http://").trim_end_matches('/');
    // mint 出的是 `{base}/gw/{path}?...`；这里只要路径+query 部分。
    let url = gw.mint(sid, action, port, 60, now_unix());
    let rel = url.split_once("/gw/").map(|(_, r)| format!("/gw/{r}")).ok_or("ticket URL 异常")?;
    let target = format!("{rel}{extra_query}");

    let mut up = TcpStream::connect(host_port).map_err(|e| format!("连网关 {host_port} 失败: {e}"))?;
    up.set_nodelay(true).ok();
    let head = format!(
        "{method} {target} HTTP/1.1\r\nHost: sandlocker-gw\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    up.write_all(head.as_bytes()).map_err(|e| format!("写网关请求失败: {e}"))?;
    up.write_all(body).map_err(|e| format!("写网关请求体失败: {e}"))?;
    up.flush().ok();

    let mut buf = vec![0u8; 32 * 1024];
    let mut code = 0u16;
    let mut head = Vec::new();
    let mut collected = Vec::new();
    loop {
        match up.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // 只从**第一块**里嗅状态码（`HTTP/1.1 <code> ...`），流式时不缓冲整体响应。
                if code == 0 {
                    head.extend_from_slice(&buf[..n.min(64)]);
                    if let Some(c) = String::from_utf8_lossy(&head)
                        .split_whitespace()
                        .nth(1)
                        .and_then(|c| c.parse::<u16>().ok())
                    {
                        code = c;
                    }
                }
                match client.as_deref_mut() {
                    Some(c) => {
                        c.write_all(&buf[..n]).map_err(|e| format!("回灌客户端失败: {e}"))?;
                        c.flush().ok();
                    }
                    None => collected.extend_from_slice(&buf[..n]),
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("读网关响应失败: {e}")),
        }
    }
    // 网关一字未回（连接被掐）→ 记 502，别谎报 200。
    Ok((if code == 0 { 502 } else { code }, collected))
}

/// 从一小段 JSON 里取某个字符串字段（免去为一次取值反序列化整个响应）。
fn json_str_field(body: &[u8], key: &str) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let needle = format!("\"{key}\":\"");
    let rest = text.split_once(&needle)?.1;
    Some(rest.split('"').next()?.to_string())
}

/// 从缓冲的 HTTP 响应里取 body（头与体以空行分隔）。
fn split_http_body(raw: &[u8]) -> &[u8] {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &raw[i + 4..])
        .unwrap_or(&[])
}

// ————————————————————— 分派 / handler —————————————————————

/// 创建请求的放置决策（M3 调度器）。
///
/// 返回 `Some(结果)` = 已经把创建转给别的节点并把响应回给了客户端，调用方就此结束；
/// 返回 `None` = 该在**本节点**建（选中自己 / 未启用集群 / 盘点不出可用节点），调用方照旧走
/// 本地 `dispatch`。
///
/// **未启用集群（无 `--gw-url`）时永远返回 None**——单机行为一字未变。
///
/// 盘点失败、没有节点放得下、或选中自己，都退回本地：调度是**优化**，不该成为创建的新故障源。
/// 唯一的例外是配额——那是**拒绝**语义，必须在建 VM 之前判，且判在本副本（它才知道调用者的项目）。
fn schedule_create<S: Read + Write>(
    stream: &mut S,
    shared: &Shared,
    rt: &Remote,
    gw: &Gateway,
    auth: &SharedAuth,
    body: &[u8],
    project: Option<&str>,
) -> Option<Result<(), String>> {
    let json = "application/json";
    if rt.gw_url.is_none() {
        return None; // 单机：无网关可转，零回归
    }
    // 规格取值须与 create_sandbox 的默认值一致，否则按 2c/512M 选节点、实际建出别的规格。
    let v: serde_json::Value = serde_json::from_slice(if body.is_empty() { b"{}" } else { body }).ok()?;
    let vcpus = v.get("cpu").and_then(|x| x.as_u64()).unwrap_or(2);
    let mem = v.get("mem").and_then(|x| x.as_u64()).unwrap_or(512);

    let (nodes, self_id) = {
        let o = shared.lock().unwrap();
        (o.survey_nodes().ok()?, rt.node_id.clone())
    };
    let target = crate::sched::place(&nodes, vcpus, mem, &self_id, rt.sched)?;
    if target == self_id {
        return None; // 就该在本节点建
    }

    // 配额前置检查（FR-7.2）留在本副本：目标节点收到的是一张不带项目信息的创建票
    // （见下），它无从判「这个项目还剩多少额度」。ADR-25 要求 create 在建 VM 之前判。
    if let Some(p) = project {
        if let Err(e) = crate::quota::check(auth.store.as_ref(), p, vcpus, mem, 0) {
            let code = quota_status(&e);
            return Some(write_response(stream, code, json, &err_json(&e)).map(|_| {
                crate::metrics::metrics().record_api(code);
            }));
        }
    }

    // 转给目标节点。票的 sid 装 `node:<id>`——目标在签名内，改不了（见 gateway::NODE_TARGET_PREFIX）。
    let sid = format!("{}{target}", crate::gateway::NODE_TARGET_PREFIX);
    let (code, raw) = match forward_via_gw_buffered(rt, gw, &sid, Action::Create, "POST", body) {
        Ok(v) => v,
        Err(e) => {
            // 转发失败不静默退回本地：本地建会绕过刚做出的放置决策，把实例又堆回这台。
            eprintln!("[sandlocker] 调度到 {target} 失败: {e}");
            return Some(write_response(stream, 502, json, &err_json(&format!("调度到节点 {target} 失败: {e}"))));
        }
    };
    crate::metrics::metrics().record_api(code);
    let resp = split_http_body(&raw).to_vec();

    // 项目归属键由**本副本**补写——目标节点不知道调用者的项目，而把项目塞进转发体属于
    // 「采信未签名字段」。租约从新沙箱的 meta 键上读（目标节点写的那个），于是回收撤租时
    // 这个键一并被删，不会留成孤儿。
    if code == 201 {
        if let (Some(p), Some(id)) = (project, json_str_field(&resp, "id")) {
            let _ = shared.lock().unwrap().tag_project(&id, p);
        }
    }
    Some(write_response(stream, code, json, &resp))
}

/// M3 W7 审计（FR-7.3）：鉴权模式下记录变更操作（append-only）。审计失败不阻断响应。
///
/// 抽成函数是因为它有**两个**调用点：本地 dispatch 之后，与跨节点转发之后。审计写的是共享
/// store，故记在**收到客户端请求的这个副本**上即可（而不是执行操作的 owning 节点）——
/// 一次请求一条，不重不漏。
fn record_audit(auth: &SharedAuth, route: &Route, project: Option<&str>, code: u16) {
    if !auth.require {
        return;
    }
    match route.required_op() {
        Some(op) if op != crate::auth::Op::Read => {
            let actor = project.unwrap_or("-");
            let target = route.sandbox_id().unwrap_or("-");
            let _ = crate::audit::record(auth.store.as_ref(), actor, route.audit_action(), target, code);
        }
        _ => {}
    }
}

fn handle_conn(
    mut stream: TcpStream,
    shared: &Shared,
    template_root: &Path,
    gw: &SharedGw,
    exposes: &Exposes,
    auth: &SharedAuth,
    rt: &SharedRemote,
) -> Result<(), String> {
    let json = "application/json";
    let (method, path, api_key, body) = read_request(&mut stream)?;
    // 流式 exec：需劫持本连接（NDJSON 边收边发、无 Content-Length），不进 dispatch/write_response 一次性路径。
    if let Some(id) = parse_exec_stream(&method, &path) {
        // exec stream = 对沙箱的 Write 操作，同样过鉴权 + 跨项目门控。
        match authorize(auth, shared, crate::auth::Op::Write, Some(&id), api_key.as_deref()) {
            Ok(_) => {
                // 沙箱在别的节点 → 经网关转（全双工中继，NDJSON 增量不被缓冲）。
                return match remote_owner(shared, rt, &id) {
                    Some(_) => {
                        let code =
                            forward_via_gw(&mut stream, rt, gw, &id, Action::Stream, 0, "POST", "", &body)?;
                        crate::metrics::metrics().record_api(code);
                        Ok(())
                    }
                    None => exec_stream_hijack(&mut stream, &id, &body, shared),
                };
            }
            Err((code, b)) => return write_response(&mut stream, code, json, &b),
        }
    }
    // 鉴权 + 授权（NotFound 无需鉴权，走 404）。
    let route = parse_route(&method, &path);
    let project = match route.required_op() {
        None => None,
        Some(op) => match authorize(auth, shared, op, route.sandbox_id(), api_key.as_deref()) {
            Ok(p) => p,
            Err((code, b)) => return write_response(&mut stream, code, json, &b),
        },
    };
    // 创建请求：先**选一个节点**（M3 调度器）。选中别人就把创建整个转过去。
    // 这一步之前，沙箱恒落在收到请求的副本上——三副本前挂个轮询 LB 看着像均衡，
    // 直接打某一台就全堆在那一台。见 sched.rs 模块头。
    if matches!(route, Route::CreateSandbox) {
        match schedule_create(&mut stream, shared, rt, gw, auth, &body, project.as_deref()) {
            Some(r) => return r,
            None => {} // 选中本节点 / 未启用调度 / 盘点失败 → 走本地路径（下面的 dispatch）
        }
    }
    // 沙箱不在本节点 → 经独立网关中继到 owning 节点（数据面 M3 W5 余项，控制面 M3 W4 余项）。
    if let (Some((action, m, port, extra)), Some(id)) = (forwardable_route(&route), route.sandbox_id()) {
        if remote_owner(shared, rt, id).is_some() {
            let code = forward_via_gw(&mut stream, rt, gw, id, action, port, m, &extra, &body)?;
            crate::metrics::metrics().record_api(code);
            // 响应已由 forward_via_gw 逐块回灌，这里只补审计。**此前转发路径直接 return，
            // 于是跨节点的 exec/put_file 一条审计都不落**——FR-7.3 要求变更操作条条在册，
            // 而"在不在本节点"不该改变这一点。
            record_audit(auth, &route, project.as_deref(), code);
            return Ok(());
        }
    }
    let (code, ctype, resp) = dispatch(&method, &path, &body, shared, template_root, gw, exposes, project.as_deref());
    // M3 W8 可观测：记 API 请求量/错误（/metrics 抓取本身不计入，避免自噪声）。
    if !matches!(route, Route::Metrics) {
        crate::metrics::metrics().record_api(code);
    }
    record_audit(auth, &route, project.as_deref(), code);
    write_response(&mut stream, code, ctype, &resp)
}

/// 错误 → HTTP 状态：QUOTA_EXCEEDED→429、UNSUPPORTED_BY_BACKEND→409、其余→400。
fn quota_status(e: &str) -> u16 {
    if e.starts_with(crate::quota::QUOTA_EXCEEDED) {
        429
    } else if e.starts_with(UNSUPPORTED_BY_BACKEND) {
        409
    } else {
        400
    }
}

fn dispatch(
    method: &str,
    path: &str,
    body: &[u8],
    shared: &Shared,
    template_root: &Path,
    gw: &SharedGw,
    exposes: &Exposes,
    project: Option<&str>,
) -> (u16, &'static str, Vec<u8>) {
    let route = parse_route(method, path);
    let json = "application/json";
    match route {
        Route::Ticket(id) => match mint_ticket(&id, body, gw) {
            Ok(v) => (200, json, v),
            Err(e) => (400, json, err_json(&e)),
        },
        Route::CreateSandbox => match create_sandbox(body, shared, template_root, project) {
            Ok(v) => (201, json, v),
            Err(e) => (quota_status(&e), json, err_json(&e)),
        },
        Route::ListSandboxes => match shared.lock().unwrap().list_meta_for(project) {
            Ok(metas) => (200, json, format!("[{}]", metas.join(",")).into_bytes()),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::GetSandbox(id) => match shared.lock().unwrap().get_meta(&id) {
            Ok(Some(m)) => (200, json, m.into_bytes()),
            Ok(None) => (404, json, err_json("未知沙箱")),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::DeleteSandbox(id) => {
            let r = shared.lock().unwrap().destroy(&id);
            match r {
                Ok(_) => {
                    drop_exposes(exposes, &id); // 拆掉该沙箱的暴露监听器，防悬挂
                    crate::metrics::metrics().record_destroy(); // M3 W8 可观测
                    crate::logsink::emit(format!(
                        r#"{{"event":"sandbox_destroy","id":"{}","project":"{}"}}"#,
                        id,
                        project.unwrap_or("-")
                    ));
                    (204, json, Vec::new())
                }
                Err(_) => (404, json, err_json("未知沙箱")),
            }
        }
        Route::Keepalive(id) => {
            // 续期只滑 idle lease 窗；**不**动 TTL 绝对硬顶（过硬顶 keepalive 救不了，M2-Q9）。
            let mut orch = shared.lock().unwrap();
            match orch.keepalive(&id) {
                Ok(lease_deadline) => {
                    let ttl = orch.ttl_deadline(&id).map(|v| v.to_string()).unwrap_or_else(|| "null".into());
                    let body = format!(
                        r#"{{"id":"{id}","lease_deadline":{lease_deadline},"ttl_deadline":{ttl}}}"#
                    );
                    (200, json, body.into_bytes())
                }
                Err(_) => (404, json, err_json("未知沙箱")),
            }
        }
        Route::Pause(id) => {
            let r = shared.lock().unwrap().pause(&id);
            match r {
                Ok(()) => (200, json, format!(r#"{{"id":"{id}","state":"paused"}}"#).into_bytes()),
                Err(e) if e.starts_with(UNSUPPORTED_BY_BACKEND) => (409, json, err_json(&e)),
                Err(e) => (404, json, err_json(&e)),
            }
        }
        Route::Resume(id) => {
            let r = shared.lock().unwrap().resume(&id);
            match r {
                Ok(mid) => {
                    (200, json, format!(r#"{{"id":"{id}","state":"running","machine_id":"{mid}"}}"#).into_bytes())
                }
                Err(e) if e.starts_with(UNSUPPORTED_BY_BACKEND) => (409, json, err_json(&e)),
                Err(e) => (404, json, err_json(&e)),
            }
        }
        Route::Fork(id) => match fork_sandbox(&id, body, shared, project) {
            Ok(v) => (201, json, v),
            Err(e) => (quota_status(&e), json, err_json(&e)),
        },
        Route::Expose(id) => match expose_port(&id, body, shared, exposes) {
            Ok(v) => (201, json, v),
            Err(e) => (400, json, err_json(&e)),
        },
        Route::Unexpose(id, gp) => {
            let removed = exposes.registry.lock().unwrap().get_mut(&id).and_then(|m| m.remove(&gp));
            match removed {
                Some(h) => {
                    h.stop();
                    (204, json, Vec::new())
                }
                None => (404, json, err_json("未暴露该端口")),
            }
        }
        Route::ListExposes(id) => (200, json, list_exposes(&id, exposes)),
        Route::Exec(id) => match exec_in(&id, body, shared) {
            Ok(v) => (200, json, v),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::PutFile(id, fpath) => match put_file(&id, &fpath, body, shared) {
            Ok(()) => (204, json, Vec::new()),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::GetFile(id, fpath) => match get_file(&id, &fpath, shared) {
            Ok(bytes) => (200, "application/octet-stream", bytes),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::Logs(id) => match read_logs(&id, shared) {
            Ok(bytes) => (200, "text/plain; charset=utf-8", bytes),
            Err(e) => (404, json, err_json(&e)),
        },
        Route::ListTemplates => match list_templates(shared) {
            Ok(v) => (200, json, v),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::ListBackends => (200, json, list_backends(shared)),
        Route::AuditLog => match shared.lock().unwrap().list_audit(project) {
            Ok(entries) => (200, json, format!("[{}]", entries.join(",")).into_bytes()),
            Err(e) => (500, json, err_json(&e)),
        },
        Route::Metrics => (
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            crate::metrics::metrics().render().into_bytes(),
        ),
        Route::BuildTemplate => (
            501,
            json,
            err_json("M1 单机版 templates:build 未实现，请用 `sandlocker build <file.toml>`"),
        ),
        Route::NotFound => (404, json, err_json("no such route")),
    }
}

/// 模板名 → 目录：`template/<name>/latest` → 版本 → `<template_root>/<name>/<version>`。
fn resolve_template(orch: &Orch, template_root: &Path, name: &str) -> Result<PathBuf, String> {
    let latest = orch
        .store_get(&format!("template/{name}/latest"))?
        .ok_or_else(|| format!("模板未注册: {name}（先 `sandlocker build`）"))?;
    let version = String::from_utf8_lossy(&latest).trim().to_string();
    let dir = template_root.join(name).join(&version);
    if !dir.is_dir() {
        return Err(format!("模板目录缺失: {}", dir.display()));
    }
    Ok(dir)
}

fn create_sandbox(body: &[u8], shared: &Shared, template_root: &Path, project: Option<&str>) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("请求体非 JSON: {e}"))?;
    let name = v.get("template").and_then(|x| x.as_str()).ok_or("缺 template 字段")?;
    let ttl = v.get("ttl").and_then(|x| x.as_i64()).unwrap_or(300);
    let idle = v.get("idle").and_then(|x| x.as_i64()).unwrap_or(ttl);
    let cpu = v.get("cpu").and_then(|x| x.as_i64()).unwrap_or(2) as u32;
    let mem = v.get("mem").and_then(|x| x.as_i64()).unwrap_or(512) as u32;
    let mut metadata = BTreeMap::new();
    if let Some(env) = v.get("env").and_then(|x| x.as_object()) {
        for (k, val) in env {
            if let Some(s) = val.as_str() {
                metadata.insert(k.clone(), s.to_string());
            }
        }
    }
    // M2 W6（ADR-14）：可选 required_capabilities:[..] snake_case 名列表 → 创建期校验（后端不满足即
    // UNSUPPORTED_BY_BACKEND）。未知能力名恒不被满足，from_names 直接返错。
    let required_capabilities = match v.get("required_capabilities").and_then(|x| x.as_array()) {
        Some(arr) => {
            let names: Vec<String> = arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
            Capabilities::from_names(&names)?
        }
        None => Capabilities::empty(),
    };
    // M2 W7：可选 backend 字段（"fc"/"gvisor"）显式选后端；缺省 fc。
    let backend = v.get("backend").and_then(|x| x.as_str()).map(|s| s.to_string());
    // 运行时网络（FR-3.3）：可选 network 字段 "none"（默认）| "egress"。egress → 冷启动带 NIC 可出站
    // （npm/pip install），仅 FC+root（能力门控，非法值/非支持后端 create 期报错）。
    let network = match v.get("network").and_then(|x| x.as_str()) {
        None | Some("none") => NetworkMode::None,
        Some("egress") => NetworkMode::Egress,
        Some(other) => return Err(format!("network 取值 none|egress，得到 {other:?}")),
    };
    let spec = SandboxSpec {
        vcpus: cpu,
        mem_mib: mem,
        ttl_secs: ttl,
        idle_secs: idle,
        metadata,
        required_capabilities,
        backend,
        network,
    };

    // 建走恢复（~130ms），全程持锁——单机 MVP 串行（如实标注）。
    let mut o = shared.lock().unwrap();
    // M3 W7 配额（FR-7.2）：create 前置检查——投影用量超项目限额即 QUOTA_EXCEEDED（先于建 VM）。
    o.check_quota(project, spec.vcpus, spec.mem_mib)?;
    let dir = resolve_template(&o, template_root, name)?;
    let out = o.create_in(&dir, &spec)?;
    // M3 W8 可观测：创建延迟 + 池命中入指标；结构化事件转发 sink（带分段时序=创建链路 span 分解）。
    crate::metrics::metrics().record_create(out.total_ms, out.pool_hit || out.hot_hit);
    crate::logsink::emit(format!(
        r#"{{"event":"sandbox_create","id":"{}","project":"{}","total_ms":{},"copy_ms":{},"load_ms":{},"resume_ms":{},"pool_hit":{}}}"#,
        out.id, project.unwrap_or("-"), out.total_ms, out.copy_ms, out.load_ms, out.resume_ms, out.pool_hit || out.hot_hit
    ));
    // M3 W6 多租户：鉴权模式下给沙箱打项目归属（跨项目访问被拒 + list 过滤 + 配额累计）。
    if let Some(p) = project {
        o.tag_project(&out.id, p)?;
    }
    Ok(format!(
        r#"{{"id":"{}","state":"running","machine_id":"{}","template":"{}","total_ms":{},"copy_ms":{},"api_ready_ms":{},"load_ms":{},"resume_ms":{},"pool_hit":{},"hot_hit":{}}}"#,
        out.id, out.machine_id, name, out.total_ms, out.copy_ms, out.api_ready_ms, out.load_ms, out.resume_ms, out.pool_hit, out.hot_hit
    )
    .into_bytes())
}

/// 控制面签发一次性 HMAC 签名 URL（M2-Q6）：body{action, port?, ttl?}→gateway::mint→{url}。
fn mint_ticket(id: &str, body: &[u8], gw: &SharedGw) -> Result<Vec<u8>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(if body.is_empty() { b"{}" } else { body }).map_err(|e| format!("请求体非 JSON: {e}"))?;
    let action = v
        .get("action")
        .and_then(|x| x.as_str())
        .and_then(Action::from_str)
        .ok_or("缺/非法 action（exec|file|logs|port）")?;
    // 控制面票**只由副本在跨节点转发时自签**，不签发给客户端：客户端拿到就能直连网关做
    // pause/destroy，绕开配额前置检查（FR-7.2）与审计落账（FR-7.3）。用 /v1 的对应端点。
    if action.is_control() {
        return Err(format!("action={} 是控制面动作，不签发 ticket（请用对应 /v1 端点）", action.as_str()));
    }
    let port = v.get("port").and_then(|x| x.as_i64()).unwrap_or(0) as u32;
    let ttl = v.get("ttl").and_then(|x| x.as_i64()).unwrap_or(300);
    let url = gw.mint(id, action, port, ttl, now_unix());
    Ok(format!(r#"{{"url":"{url}"}}"#).into_bytes())
}

/// 暴露结果 JSON（稳定地址 `http://<bind>:<host_port>/` + 端口映射）。
fn expose_json(bind: &str, host_port: u16, guest_port: u32) -> Vec<u8> {
    format!(r#"{{"url":"http://{bind}:{host_port}/","bind":"{bind}","host_port":{host_port},"guest_port":{guest_port}}}"#)
        .into_bytes()
}

/// 端口暴露（L4 透传）：`body{port, host_port?, bind?}` → 起持久监听器把外部连接裸字节透传到 guest
/// `127.0.0.1:port`。返回稳定地址（`http://bind:host_port/`），支持任意方法/流式/WS/keep-alive。
/// 仅 FC（vsock）后端；同 guest_port 幂等；非回环 bind 需 `--expose-allow-public`。
fn expose_port(id: &str, body: &[u8], shared: &Shared, exposes: &Exposes) -> Result<Vec<u8>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(if body.is_empty() { b"{}" } else { body }).map_err(|e| format!("请求体非 JSON: {e}"))?;
    let guest_port = v.get("port").and_then(|x| x.as_u64()).ok_or("缺/非法 port")? as u32;
    let host_port = v.get("host_port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
    let bind = v.get("bind").and_then(|x| x.as_str()).unwrap_or("127.0.0.1").to_string();

    // 幂等：同沙箱同 guest_port 已暴露则直接回既有地址（不重复起监听）。
    {
        let reg = exposes.registry.lock().unwrap();
        if let Some(h) = reg.get(id).and_then(|m| m.get(&guest_port)) {
            return Ok(expose_json(&h.bind, h.host_port, guest_port));
        }
    }

    // 对外 bind（非回环）门禁：纯 L4 透传无鉴权，须 --expose-allow-public 显式放行。
    let loopback = bind == "127.0.0.1" || bind == "localhost" || bind == "::1";
    if !loopback {
        if !exposes.allow_public {
            return Err(format!(
                "bind={bind} 为非回环地址，纯 L4 透传无鉴权；如确需对外暴露，守护须带 --expose-allow-public"
            ));
        }
        eprintln!("[sandlocker][WARN] expose bind={bind}:{host_port} → guest {id}:{guest_port}：无鉴权 L4 透传，仅限可信网络");
    }

    // 端口暴露仅 FC（vsock）；锁内取 vsock 路径，锁外起监听（不阻塞 create/reaper）。
    let tgt = shared.lock().unwrap().exec_target(id).ok_or("未知沙箱或已回收")?;
    let vsock = match tgt {
        ExecTarget::Vsock(p) => p,
        _ => return Err("端口暴露仅 FC 后端（vsock）支持".into()),
    };

    let h = expose::start_listener(&bind, host_port, vsock, guest_port)?;
    let out = expose_json(&h.bind, h.host_port, guest_port);
    exposes.registry.lock().unwrap().entry(id.to_string()).or_default().insert(guest_port, h);
    Ok(out)
}

/// 列出某沙箱已暴露端口 → JSON 数组 `[{bind,host_port,guest_port,url}, ..]`。
fn list_exposes(id: &str, exposes: &Exposes) -> Vec<u8> {
    let reg = exposes.registry.lock().unwrap();
    let items: Vec<String> = reg
        .get(id)
        .map(|m| {
            m.values()
                .map(|h| String::from_utf8(expose_json(&h.bind, h.host_port, h.guest_port)).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    format!("[{}]", items.join(",")).into_bytes()
}

/// 数据面网关连接（M2-Q6）：验签一次性 ticket → 交 [`serve_gw_ticket`] 分发。验签失败 403。
///
/// **进程内网关**（单机 `--serve` 自带的 `/gw/*` 监听）走这条；独立 `sandlocker-gw` 进程验签后
/// 经数据面把已验签 ticket 下发到 owning 节点，节点侧**跳过验签**直接调 `serve_gw_ticket`
/// （nonce 已被网关一次性消费，节点再验必失败；采信根据是 mTLS，见 dataplane.rs 模块头）。
fn handle_gw_conn(
    mut stream: TcpStream,
    shared: &Shared,
    gw: &SharedGw,
    exposes: &Exposes,
    template_root: &Path,
) -> Result<(), String> {
    // 网关连接靠 ticket 验签授权（非 API Key），忽略 header 里的 api_key。
    let (method, path, _api_key, body) = read_request(&mut stream)?;
    let q = parse_query(&path);
    let ticket = match gw.verify(&q, now_unix()) {
        Ok(t) => t,
        Err(e) => {
            return write_response(&mut stream, 403, "application/json", &err_json(&format!("ticket 无效: {e}")))
        }
    };
    serve_gw_ticket(&mut stream, &ticket, &method, &path, &body, shared, exposes, template_root)
}

/// 按**已验签**的 ticket 就地服务一次数据面 / 控制面请求（沙箱须在本节点）。
///
/// 泛型 over `Read + Write`：既服务进程内网关的 `TcpStream`，也服务 `sandlocker-gw` 借用的那条
/// 外拨连接（`dataplane::Chan`）——**同一套语义、同一段代码**，这正是 ADR-22「拆分零语义变更」。
pub(crate) fn serve_gw_ticket<S: Read + Write>(
    stream: &mut S,
    ticket: &Ticket,
    method: &str,
    path: &str,
    body: &[u8],
    shared: &Shared,
    exposes: &Exposes,
    template_root: &Path,
) -> Result<(), String> {
    let json = "application/json";
    let q = parse_query(path);
    let base = path.split('?').next().unwrap_or("");
    match (base, ticket.action) {
        ("/gw/exec", Action::Exec) => match exec_in(&ticket.sid, body, shared) {
            Ok(v) => write_response(stream, 200, json, &v),
            Err(e) => write_response(stream, 500, json, &err_json(&e)),
        },
        ("/gw/file", Action::File) => {
            let p = q.get("p").cloned().unwrap_or_default();
            if method == "PUT" {
                match put_file(&ticket.sid, &p, body, shared) {
                    Ok(()) => write_response(stream, 204, json, &[]),
                    Err(e) => write_response(stream, 500, json, &err_json(&e)),
                }
            } else {
                match get_file(&ticket.sid, &p, shared) {
                    Ok(b) => write_response(stream, 200, "application/octet-stream", &b),
                    Err(e) => write_response(stream, 500, json, &err_json(&e)),
                }
            }
        }
        ("/gw/logs", Action::Logs) => match read_logs(&ticket.sid, shared) {
            Ok(b) => write_response(stream, 200, "text/plain; charset=utf-8", &b),
            Err(e) => write_response(stream, 404, json, &err_json(&e)),
        },
        // 流式 exec（M3 W5 余项）：NDJSON 增量响应，无 Content-Length。经网关中继时依赖
        // dataplane 的**全双工**搬运，故 guest 的每一块 stdout 都即时到客户端、不被缓冲住。
        ("/gw/stream", Action::Stream) => exec_stream_hijack(stream, &ticket.sid, body, shared),
        ("/gw/p", Action::Port) => {
            let gpath = q.get("p").cloned().unwrap_or_default();
            // 端口反代仅 FC 后端（vsock）；取裸 vsock 路径（锁内），锁外做代理。
            let tgt = shared.lock().unwrap().exec_target(&ticket.sid);
            match tgt {
                Some(ExecTarget::Vsock(vsock)) => match proxy_port_http(&vsock, ticket.port, &gpath) {
                    Ok(raw) => {
                        stream.write_all(&raw).map_err(|e| format!("写客户端失败: {e}"))?;
                        stream.flush().ok();
                        Ok(())
                    }
                    Err(e) => write_response(stream, 502, json, &err_json(&e)),
                },
                Some(_) => write_response(stream, 400, json, &err_json("端口暴露仅 FC 后端（vsock）支持")),
                None => write_response(stream, 404, json, &err_json("未知沙箱或已回收")),
            }
        }
        // ————————————————————— 控制面（M3 W4 余项）—————————————————————
        //
        // 这几条走的是与本地 `dispatch` **完全相同**的 orch 调用与状态码——中继只换了到达
        // 路径，不换语义（ADR-22「拆分零语义变更」对控制面同样成立）。
        //
        // **项目归属从 store 现取**（`sandbox/<id>/project`），不从线上参数取：转发请求里的
        // 任何未签名字段都不该被采信，而发起副本在签票前已经用 API Key 做过跨项目门控，
        // 归属键与那次门控读的是同一个值。
        ("/gw/pause", Action::Pause) => {
            let r = shared.lock().unwrap().pause(&ticket.sid);
            match r {
                Ok(()) => {
                    let sid = &ticket.sid;
                    write_response(stream, 200, json, format!(r#"{{"id":"{sid}","state":"paused"}}"#).as_bytes())
                }
                Err(e) if e.starts_with(UNSUPPORTED_BY_BACKEND) => write_response(stream, 409, json, &err_json(&e)),
                Err(e) => write_response(stream, 404, json, &err_json(&e)),
            }
        }
        ("/gw/resume", Action::Resume) => {
            let r = shared.lock().unwrap().resume(&ticket.sid);
            match r {
                Ok(mid) => {
                    let sid = &ticket.sid;
                    let b = format!(r#"{{"id":"{sid}","state":"running","machine_id":"{mid}"}}"#);
                    write_response(stream, 200, json, b.as_bytes())
                }
                Err(e) if e.starts_with(UNSUPPORTED_BY_BACKEND) => write_response(stream, 409, json, &err_json(&e)),
                Err(e) => write_response(stream, 404, json, &err_json(&e)),
            }
        }
        ("/gw/fork", Action::Fork) => {
            let project = shared.lock().unwrap().sandbox_project(&ticket.sid).unwrap_or(None);
            match fork_sandbox(&ticket.sid, body, shared, project.as_deref()) {
                Ok(v) => write_response(stream, 201, json, &v),
                Err(e) => write_response(stream, quota_status(&e), json, &err_json(&e)),
            }
        }
        ("/gw/destroy", Action::Destroy) => {
            // 项目归属**先读后销毁**：destroy 撤租，挂在该租约上的 `sandbox/<id>/project` 随之
            // 消失，事后再读就只剩 "-"，日志里那条 destroy 事件会丢掉租户维度。
            let r = {
                let mut o = shared.lock().unwrap();
                let project = o.sandbox_project(&ticket.sid).ok().flatten();
                o.destroy(&ticket.sid).map(|_| project)
            };
            match r {
                Ok(project) => {
                    drop_exposes(exposes, &ticket.sid); // 拆掉该沙箱的暴露监听器，防悬挂
                    crate::metrics::metrics().record_destroy();
                    crate::logsink::emit(format!(
                        r#"{{"event":"sandbox_destroy","id":"{}","project":"{}"}}"#,
                        ticket.sid,
                        project.as_deref().unwrap_or("-")
                    ));
                    write_response(stream, 204, json, &[])
                }
                Err(_) => write_response(stream, 404, json, &err_json("未知沙箱")),
            }
        }
        ("/gw/keepalive", Action::Keepalive) => {
            let mut orch = shared.lock().unwrap();
            match orch.keepalive(&ticket.sid) {
                Ok(lease_deadline) => {
                    let sid = &ticket.sid;
                    let ttl = orch.ttl_deadline(sid).map(|v| v.to_string()).unwrap_or_else(|| "null".into());
                    let b = format!(r#"{{"id":"{sid}","lease_deadline":{lease_deadline},"ttl_deadline":{ttl}}}"#);
                    drop(orch);
                    write_response(stream, 200, json, b.as_bytes())
                }
                Err(_) => {
                    drop(orch);
                    write_response(stream, 404, json, &err_json("未知沙箱"))
                }
            }
        }
        // 暴露：监听器起在 **owning 节点**上，返回的地址因此是那台机器的地址（默认回环则
        // 只有该节点自己可达）。跨节点暴露给外部访问须 `--expose-allow-public` + 节点可路由
        // 地址，见 docs/design/端口暴露.md。
        ("/gw/expose", Action::Expose) => match expose_port(&ticket.sid, body, shared, exposes) {
            Ok(v) => write_response(stream, 201, json, &v),
            Err(e) => write_response(stream, 400, json, &err_json(&e)),
        },
        ("/gw/unexpose", Action::Unexpose) => {
            // 拆哪个 guest 端口取**票里签过的 port**，不取查询串（未签名字段不可信）。
            let removed =
                exposes.registry.lock().unwrap().get_mut(&ticket.sid).and_then(|m| m.remove(&ticket.port));
            match removed {
                Some(h) => {
                    h.stop();
                    write_response(stream, 204, json, &[])
                }
                None => write_response(stream, 404, json, &err_json("未暴露该端口")),
            }
        }
        ("/gw/exposes", Action::Exposes) => {
            write_response(stream, 200, json, &list_exposes(&ticket.sid, exposes))
        }
        // 调度器把创建转到了本节点（`ticket.sid` = `node:<本节点 id>`，目标在签名内）。
        //
        // **project 传 None，不是漏了**：调用者的项目只有收到 API 请求的那个副本知道，
        // 而把它塞进转发体就等于采信一个未签名字段。所以配额前置检查与项目归属键
        // 都留在发起副本那边（见 `schedule_create`），这里只管把 VM 建出来。
        ("/gw/create", Action::Create) => match create_sandbox(body, shared, template_root, None) {
            Ok(v) => write_response(stream, 201, json, &v),
            Err(e) => write_response(stream, quota_status(&e), json, &err_json(&e)),
        },
        _ => write_response(stream, 403, json, &err_json("ticket 动作与路径不符")),
    }
}

/// fork（M2-Q5）：从（已 pause 的）父沙箱派生新实例，reinit 得独立身份。ttl/idle 可选（缺省 300）；
/// 后端继承父（经 orch 内部路由），无需 template。返回新 sandbox JSON（含 forked_from）。
fn fork_sandbox(id: &str, body: &[u8], shared: &Shared, project: Option<&str>) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(if body.is_empty() { b"{}" } else { body })
        .map_err(|e| format!("请求体非 JSON: {e}"))?;
    let ttl = v.get("ttl").and_then(|x| x.as_i64()).unwrap_or(300);
    let idle = v.get("idle").and_then(|x| x.as_i64()).unwrap_or(ttl);
    let spec = SandboxSpec { ttl_secs: ttl, idle_secs: idle, ..Default::default() };
    let mut o = shared.lock().unwrap();
    // M3 W7 配额（FR-7.2）：fork 前置检查（fork 也占并发/资源额度，ADR-25）。
    o.check_quota(project, spec.vcpus, spec.mem_mib)?;
    let out = o.fork(id, &spec)?;
    crate::metrics::metrics().record_create(out.total_ms, out.pool_hit || out.hot_hit);
    // 子沙箱继承父项目归属（配额累计 + 跨项目隔离）。
    if let Some(p) = project {
        o.tag_project(&out.id, p)?;
    }
    let forked = out.forked_from.as_deref().unwrap_or("");
    Ok(format!(
        r#"{{"id":"{}","state":"running","machine_id":"{}","forked_from":"{forked}","total_ms":{},"copy_ms":{}}}"#,
        out.id, out.machine_id, out.total_ms, out.copy_ms
    )
    .into_bytes())
}

/// 若为流式 exec 路由（`POST /v1/sandboxes/{id}/exec/stream`）返回 sandbox id，否则 None。
fn parse_exec_stream(method: &str, path: &str) -> Option<String> {
    if method != "POST" {
        return None;
    }
    let path = path.split('?').next().unwrap_or(path);
    let trimmed = path.trim_matches('/');
    let segs: Vec<&str> = if trimmed.is_empty() { vec![] } else { trimmed.split('/').collect() };
    match segs.as_slice() {
        ["v1", "sandboxes", id, "exec", "stream"] => Some((*id).to_string()),
        _ => None,
    }
}

/// 流式 exec（NDJSON）：劫持本连接，把 guest 的 exec 输出帧边收边转成 NDJSON 事件推给客户端。
/// 事件逐行：`{"stream":"stdout"|"stderr","data":"<base64>"}` 逐块，末尾 `{"exit_code":N}`。仅 FC/vsock。
/// 传输：`HTTP/1.1 200` + `Connection: close` + **无 Content-Length**（客户端读到连接关闭为止，可增量收）。
/// 错误在写响应头之前用一次性 `write_response` 报（400/404/500/502）；头写出后只能中断连接。
fn exec_stream_hijack<S: Read + Write>(
    stream: &mut S,
    id: &str,
    body: &[u8],
    shared: &Shared,
) -> Result<(), String> {
    let json = "application/json";
    let v: serde_json::Value = match serde_json::from_slice(if body.is_empty() { b"{}" } else { body }) {
        Ok(v) => v,
        Err(e) => return write_response(stream, 400, json, &err_json(&format!("请求体非 JSON: {e}"))),
    };
    let cmd = match v.get("cmd").and_then(|x| x.as_str()) {
        Some(c) => c.to_string(),
        None => return write_response(stream, 400, json, &err_json("缺 cmd 字段")),
    };
    // 取 target（锁内）后立即释放锁；仅 FC/vsock 支持流式 exec。
    let tgt = shared.lock().unwrap().exec_target(id);
    let vsock = match tgt {
        Some(ExecTarget::Vsock(p)) => p,
        Some(_) => return write_response(stream, 400, json, &err_json("流式 exec 仅 FC 后端（vsock）支持")),
        None => return write_response(stream, 404, json, &err_json("未知沙箱或已回收")),
    };
    // 连 guest、发 ExecStream、等 Ok ack（此前的错误都还能回规范 HTTP 响应）。
    let mut g = match connect_guest(&vsock) {
        Ok(s) => s,
        Err(e) => return write_response(stream, 502, json, &err_json(&format!("连 guest 失败: {e}"))),
    };
    if let Err(e) = write_msg(&mut g, &Request::ExecStream { cmd }) {
        return write_response(stream, 502, json, &err_json(&format!("发 ExecStream 失败: {e}")));
    }
    match read_msg::<_, Response>(&mut g) {
        Ok(Response::Ok) => {}
        Ok(Response::Error { message }) => {
            return write_response(stream, 500, json, &err_json(&format!("guest 执行错误: {message}")))
        }
        Ok(other) => return write_response(stream, 502, json, &err_json(&format!("非预期 ack: {other:?}"))),
        Err(e) => return write_response(stream, 502, json, &err_json(&format!("读 ack 失败: {e}"))),
    }
    // ack 成功 → 写 NDJSON 响应头（无 Content-Length），随后边收帧边发事件。
    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).map_err(|e| format!("写响应头失败: {e}"))?;
    stream.flush().ok();
    loop {
        let payload = match read_frame(&mut g) {
            Ok(p) => p,
            Err(_) => break, // guest EOF/错误：命令结束或连接断
        };
        // base64 字符集 [A-Za-z0-9+/=] 无需 JSON 转义，手拼行避免每块 serde 开销。
        let line = match parse_exec_output(&payload) {
            Some(ExecOutput::Stdout(b)) => format!("{{\"stream\":\"stdout\",\"data\":\"{}\"}}\n", b64_encode(&b)),
            Some(ExecOutput::Stderr(b)) => format!("{{\"stream\":\"stderr\",\"data\":\"{}\"}}\n", b64_encode(&b)),
            Some(ExecOutput::Exit(code)) => {
                let _ = stream.write_all(format!("{{\"exit_code\":{code}}}\n").as_bytes());
                stream.flush().ok();
                break;
            }
            None => continue, // 非法帧忽略
        };
        if stream.write_all(line.as_bytes()).is_err() {
            break; // 客户端断开
        }
        stream.flush().ok();
    }
    Ok(())
}

/// 取 exec 目标（持锁）→ 释放锁 → 后端各自执行（慢 IO 不阻塞 create/reaper）。FC=vsock/gVisor=runsc。
fn exec_in(id: &str, body: &[u8], shared: &Shared) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("请求体非 JSON: {e}"))?;
    let cmd = v.get("cmd").and_then(|x| x.as_str()).ok_or("缺 cmd 字段")?;
    let target = shared.lock().unwrap().exec_target(id).ok_or("未知沙箱或已回收")?;
    let t0 = std::time::Instant::now();
    let (code, out, err) = target.exec(cmd)?;
    crate::metrics::metrics().record_exec(t0.elapsed().as_millis()); // M3 W8 可观测
    Ok(serde_json::json!({"exit_code": code, "stdout": out, "stderr": err}).to_string().into_bytes())
}

/// 文件写：body → base64 → guest `base64 -d` 落盘（后端无关，走 exec 目标）。
fn put_file(id: &str, fpath: &str, body: &[u8], shared: &Shared) -> Result<(), String> {
    let target = shared.lock().unwrap().exec_target(id).ok_or("未知沙箱或已回收")?;
    let b64 = b64_encode(body);
    let path = single_quote(&format!("/{}", fpath.trim_start_matches('/')));
    let cmd = format!("printf %s '{b64}' | base64 -d > {path}");
    let (code, _out, err) = target.exec(&cmd)?;
    if code != 0 {
        return Err(format!("写文件失败（exit={code}）: {}", err.trim()));
    }
    Ok(())
}

/// 文件读：guest `base64 <path>` → 解码回原始字节（后端无关）。
fn get_file(id: &str, fpath: &str, shared: &Shared) -> Result<Vec<u8>, String> {
    let target = shared.lock().unwrap().exec_target(id).ok_or("未知沙箱或已回收")?;
    let path = single_quote(&format!("/{}", fpath.trim_start_matches('/')));
    let (code, out, err) = target.exec(&format!("base64 {path}"))?;
    if code != 0 {
        return Err(format!("读文件失败（exit={code}）: {}", err.trim()));
    }
    b64_decode(&out)
}

fn read_logs(id: &str, shared: &Shared) -> Result<Vec<u8>, String> {
    let p = shared.lock().unwrap().log_path(id).ok_or("未知沙箱或已回收")?;
    std::fs::read(&p).map_err(|e| format!("读日志失败: {e}"))
}

fn list_templates(shared: &Shared) -> Result<Vec<u8>, String> {
    let o = shared.lock().unwrap();
    let kvs = o.store_list("template/")?;
    let mut items = Vec::new();
    for (k, v) in kvs {
        // 仅取 `template/<name>/latest` → {name, version}
        if let Some(rest) = k.strip_prefix("template/") {
            if let Some(name) = rest.strip_suffix("/latest") {
                let version = String::from_utf8_lossy(&v).trim().to_string();
                items.push(format!(r#"{{"name":"{name}","version":"{version}"}}"#));
            }
        }
    }
    Ok(format!("[{}]", items.join(",")).into_bytes())
}

/// `GET /v1/backends`（ADR-14）：后端列表与能力集。W6 单后端（fc）；W7 gVisor 落地时增。
fn list_backends(shared: &Shared) -> Vec<u8> {
    let o = shared.lock().unwrap();
    let items: Vec<String> = o
        .backends_info()
        .into_iter()
        .map(|b| {
            let caps = b.capabilities.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(",");
            format!(r#"{{"id":"{}","capabilities":[{caps}]}}"#, b.id)
        })
        .collect();
    format!("[{}]", items.join(",")).into_bytes()
}

/// 单引号包裹（仓库内路径不含单引号，够用；与 main.rs `sq` 同策略）。
fn single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ————————————————————— base64（无依赖，标准字母表）—————————————————————

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut val = [255u8; 256];
    for (i, &c) in B64.iter().enumerate() {
        val[c as usize] = i as u8;
    }
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        if chunk.len() == 1 {
            return Err("base64 长度非法".into());
        }
        let mut acc = 0u32;
        for i in 0..4 {
            let d = if i < chunk.len() {
                let d = val[chunk[i] as usize];
                if d == 255 {
                    return Err(format!("非法 base64 字符: {}", chunk[i] as char));
                }
                d
            } else {
                0
            };
            acc = (acc << 6) | d as u32;
        }
        let nbytes = chunk.len() - 1; // 4→3, 3→2, 2→1
        let bytes = [(acc >> 16) as u8, (acc >> 8) as u8, acc as u8];
        out.extend_from_slice(&bytes[..nbytes]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_sandbox_crud() {
        assert_eq!(parse_route("POST", "/v1/sandboxes"), Route::CreateSandbox);
        assert_eq!(parse_route("GET", "/v1/sandboxes"), Route::ListSandboxes);
        assert_eq!(parse_route("GET", "/v1/sandboxes?limit=10"), Route::ListSandboxes);
        assert_eq!(parse_route("GET", "/v1/sandboxes/abc"), Route::GetSandbox("abc".into()));
        assert_eq!(parse_route("DELETE", "/v1/sandboxes/abc"), Route::DeleteSandbox("abc".into()));
        assert_eq!(parse_route("POST", "/v1/sandboxes/abc/keepalive"), Route::Keepalive("abc".into()));
        assert_eq!(parse_route("POST", "/v1/sandboxes/abc/exec"), Route::Exec("abc".into()));
        assert_eq!(parse_route("GET", "/v1/sandboxes/abc/logs"), Route::Logs("abc".into()));
    }

    /// 控制面票**不签发给客户端**：客户端若能拿到 destroy 票直连网关，就绕开了配额前置检查
    /// （FR-7.2）与审计落账（FR-7.3）——那两件事只发生在 `/v1` 端点这一侧。
    #[test]
    fn mint_ticket_refuses_control_actions() {
        let gw: SharedGw = Arc::new(Gateway::new_random("http://x".into()));
        for a in ["pause", "resume", "fork", "destroy", "keepalive", "expose", "unexpose", "exposes"] {
            let body = format!(r#"{{"action":"{a}"}}"#);
            assert!(mint_ticket("s", body.as_bytes(), &gw).is_err(), "{a} 不该签发给客户端");
        }
        // 数据面照签（零回归）。
        assert!(mint_ticket("s", br#"{"action":"exec"}"#, &gw).is_ok());
        assert!(mint_ticket("s", br#"{"action":"port","port":8080}"#, &gw).is_ok());
    }

    /// 跨节点转发覆盖面（M3 W4 余项）：**凡是依赖 owning 节点进程内状态的路由，都必须可转**。
    ///
    /// 判据不是"看着像控制面"，而是：这条路由的实现有没有摸 `Orch::live`（内存里的 lease 句柄、
    /// ttl 硬顶、后端归属）或节点进程内的暴露注册表。摸了就只有 owning 节点办得了。
    #[test]
    fn forwardable_covers_every_owner_bound_route() {
        let must = [
            // 数据面：落 guest vsock 通道
            Route::Exec("s".into()),
            Route::Logs("s".into()),
            Route::PutFile("s".into(), "a".into()),
            Route::GetFile("s".into(), "a".into()),
            // 控制面：落 Orch::live + 后端进程
            Route::Pause("s".into()),
            Route::Resume("s".into()),
            Route::Fork("s".into()),
            Route::DeleteSandbox("s".into()),
            Route::Keepalive("s".into()),
            // 暴露注册表是节点进程内状态
            Route::Expose("s".into()),
            Route::Unexpose("s".into(), 8080),
            Route::ListExposes("s".into()),
        ];
        for r in &must {
            assert!(forwardable_route(r).is_some(), "{r:?} 依赖 owning 节点，却不可转发");
        }
        // 纯读 store 的路由不转：任一副本自足，转发只是白白多一跳。
        for r in [
            Route::GetSandbox("s".into()),
            Route::ListSandboxes,
            Route::AuditLog,
            Route::ListTemplates,
            Route::CreateSandbox,
            Route::Ticket("s".into()),
        ] {
            assert!(forwardable_route(&r).is_none(), "{r:?} 不该被转发");
        }
    }

    /// 每条可转路由的 ticket 动作互不相同——共用动作就等于让票在操作之间可替换。
    #[test]
    fn forwardable_actions_are_distinct_per_op() {
        let routes = [
            Route::Pause("s".into()),
            Route::Resume("s".into()),
            Route::Fork("s".into()),
            Route::DeleteSandbox("s".into()),
            Route::Keepalive("s".into()),
            Route::Expose("s".into()),
            Route::Unexpose("s".into(), 1),
            Route::ListExposes("s".into()),
        ];
        let mut seen = std::collections::HashSet::new();
        for r in &routes {
            let (a, _, _, _) = forwardable_route(r).unwrap();
            assert!(a.is_control(), "{r:?} 的动作应归控制面（否则会被签发给客户端）");
            assert!(seen.insert(a.as_str()), "{r:?} 与他人共用动作 {}", a.as_str());
        }
    }

    /// unexpose 的 guest 端口必须走**签名**字段（ticket.port），不能落到未签名查询串上。
    #[test]
    fn unexpose_port_travels_signed() {
        let (action, method, port, extra) = forwardable_route(&Route::Unexpose("s".into(), 8080)).unwrap();
        assert_eq!(action, Action::Unexpose);
        assert_eq!(method, "DELETE");
        assert_eq!(port, 8080);
        assert!(extra.is_empty(), "端口不该出现在未签名的查询串里: {extra}");
    }

    #[test]
    fn route_files_captures_nested_path() {
        assert_eq!(
            parse_route("PUT", "/v1/sandboxes/abc/files/tmp/out.csv"),
            Route::PutFile("abc".into(), "tmp/out.csv".into())
        );
        assert_eq!(
            parse_route("GET", "/v1/sandboxes/abc/files/etc/hostname"),
            Route::GetFile("abc".into(), "etc/hostname".into())
        );
    }

    #[test]
    fn route_expose() {
        assert_eq!(parse_route("POST", "/v1/sandboxes/abc/expose"), Route::Expose("abc".into()));
        assert_eq!(parse_route("GET", "/v1/sandboxes/abc/exposes"), Route::ListExposes("abc".into()));
        assert_eq!(parse_route("DELETE", "/v1/sandboxes/abc/expose/8080"), Route::Unexpose("abc".into(), 8080));
        // 非数字端口 → NotFound（不 panic）。
        assert_eq!(parse_route("DELETE", "/v1/sandboxes/abc/expose/xx"), Route::NotFound);
    }

    #[test]
    fn route_templates_and_unknown() {
        assert_eq!(parse_route("GET", "/v1/templates"), Route::ListTemplates);
        assert_eq!(parse_route("POST", "/v1/templates:build"), Route::BuildTemplate);
        assert_eq!(parse_route("GET", "/"), Route::NotFound);
        assert_eq!(parse_route("PATCH", "/v1/sandboxes/abc"), Route::NotFound);
    }

    #[test]
    fn request_line_and_content_length() {
        let head = b"POST /v1/sandboxes HTTP/1.1\r\nContent-Length: 12\r\nHost: x\r\n";
        let (m, p) = parse_request_line(head).unwrap();
        assert_eq!(m, "POST");
        assert_eq!(p, "/v1/sandboxes");
        assert_eq!(content_length(head), 12);
        assert_eq!(content_length(b"GET / HTTP/1.1\r\nHost: x\r\n"), 0);
    }

    #[test]
    fn base64_roundtrip() {
        for case in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", &[0u8, 255, 16, 128, 3]] {
            let enc = b64_encode(case);
            let dec = b64_decode(&enc).unwrap();
            assert_eq!(dec, case, "roundtrip failed for {case:?} → {enc}");
        }
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_encode(b"Man"), "TWFu");
        assert_eq!(b64_decode("Zm9vYmFy").unwrap(), b"foobar");
        // 容忍换行（guest `base64` 可能换行）
        assert_eq!(b64_decode("Zm9v\nYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn base64_rejects_bad_char() {
        assert!(b64_decode("****").is_err());
    }
}
