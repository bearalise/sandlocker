//! sandlocker-gw — **独立数据面网关进程**（M3 W5 余项，ADR-22 / M3-Q3）。
//!
//! M2 把 ticket 做成**无状态 HMAC 验签** + 节点**主动外拨**，就是为了让这一步是纯部署变更、
//! 零协议变更；M3 W5 又把 secret 与一次性 nonce 挪进 store（跨副本共享）。到这里，网关终于
//! 可以从 `sl-node --serve` 的进程内模块变成**一个自己的进程、自己的副本数**：
//!
//! - **无粘滞**：网关不持任何沙箱状态，按 etcd 的 `sandbox/<sid>/node` 现查现转，
//!   任一副本可服务任一沙箱；
//! - **节点零入站**：连接方向恒为 节点 → 网关（节点预拨一池持久连接停在这里，网关反向借用）；
//! - **mTLS**：节点接入端口强制客户端证书（FR-7.1 集群内 mTLS）。
//!
//! 典型部署（网关副本可水平扩，前面挂 L4 LB）：
//!
//! ```text
//! sandlocker-gw --bind 0.0.0.0:7879 --node-bind 0.0.0.0:7880 --etcd http://etcd:2379 \
//!     --tls-cert gw.pem --tls-key gw.key --tls-ca ca.pem
//!
//! sl-node --serve --etcd http://etcd:2379 --gw gw-lb:7880 --gw-url http://gw-lb:7879 \
//!     --gw-tls-cert node.pem --gw-tls-key node.key --gw-tls-ca ca.pem --gw-tls-name sandlocker-gw
//! ```

use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "sandlocker-gw — 数据面网关（ADR-22）

  --bind <host:port>        面向客户端的 HTTP 监听（签名 URL 打到这里，默认 0.0.0.0:7879）
  --node-bind <host:port>   面向节点的接入监听（节点主动外拨到这里，默认 0.0.0.0:7880）
  --etcd <endpoint>         etcd v3 gateway（如 http://127.0.0.1:2379）——查沙箱→节点映射 + ticket secret/nonce
  --tls-cert/--tls-key/--tls-ca   集群内 mTLS（强制校验节点客户端证书）
  --insecure                明文接入（仅限本机对账/开发；不给 TLS 时须显式指定）
  --take-wait-ms <n>        借空闲连接的最长等待（默认 2000）
  --max-idle-secs <n>       空闲连接最长停留（默认 300）"
    );
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut bind = "0.0.0.0:7879".to_string();
    let mut node_bind = "0.0.0.0:7880".to_string();
    let mut etcd: Option<String> = None;
    let (mut cert, mut key, mut ca) = (None, None, None);
    let mut insecure = false;
    let mut take_wait = Duration::from_millis(2000);
    let mut max_idle = Duration::from_secs(300);

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].clone();
        // 取下一个参数值（缺失即用法错）。
        macro_rules! next {
            () => {{
                i += 1;
                args.get(i).cloned().unwrap_or_else(|| usage())
            }};
        }
        match arg.as_str() {
            "--bind" => bind = next!(),
            "--node-bind" => node_bind = next!(),
            "--etcd" => etcd = Some(next!()),
            "--tls-cert" => cert = Some(std::path::PathBuf::from(next!())),
            "--tls-key" => key = Some(std::path::PathBuf::from(next!())),
            "--tls-ca" => ca = Some(std::path::PathBuf::from(next!())),
            "--insecure" => insecure = true,
            "--take-wait-ms" => take_wait = Duration::from_millis(next!().parse().unwrap_or(2000)),
            "--max-idle-secs" => max_idle = Duration::from_secs(next!().parse().unwrap_or(300)),
            "-h" | "--help" => usage(),
            other => {
                eprintln!("未知参数: {other}");
                usage()
            }
        }
        i += 1;
    }

    // mTLS 材料：默认**不放行明文**——漏配证书应得到明确错误，而非静默降级为无鉴权传输。
    let tls = match (&cert, &key, &ca) {
        (Some(c), Some(k), Some(a)) => Some(sl_node::dataplane::TlsOpts {
            cert: c.clone(),
            key: k.clone(),
            ca: a.clone(),
            server_name: String::new(), // 服务端不需要（只有客户端用它校验对端名）
        }),
        (None, None, None) if insecure => None,
        _ => {
            eprintln!("[sandlocker-gw] 须给全 --tls-cert/--tls-key/--tls-ca（集群内 mTLS），或显式 --insecure");
            std::process::exit(2)
        }
    };

    let ep = match etcd {
        Some(e) => e,
        None => {
            eprintln!("[sandlocker-gw] 须给 --etcd <endpoint>：网关按 etcd 的 sandbox/<sid>/node 映射转发");
            std::process::exit(2)
        }
    };
    // store 工厂：网关要两个句柄——一个给 ticket 验签（共享 secret + 一次性 nonce），一个查归属。
    let open_store = {
        let ep = ep.clone();
        Box::new(move || open_etcd(&ep))
    };

    if let Err(e) = sl_node::dataplane::gw_serve(sl_node::dataplane::GwCfg {
        bind,
        node_bind,
        open_store,
        tls,
        take_wait,
        max_idle,
        on_ready: None,
    }) {
        eprintln!("[sandlocker-gw] 启动失败: {e}");
        std::process::exit(1);
    }
}

#[cfg(feature = "cluster")]
fn open_etcd(ep: &str) -> Result<Box<dyn sl_store::Store>, String> {
    Ok(Box::new(sl_store::etcd::EtcdStore::connect(ep).map_err(|e| e.to_string())?))
}

#[cfg(not(feature = "cluster"))]
fn open_etcd(_ep: &str) -> Result<Box<dyn sl_store::Store>, String> {
    Err("sandlocker-gw 须以 `--features cluster` 构建（需要 etcd 后端）".into())
}
