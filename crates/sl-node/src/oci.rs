//! oci.rs — OCI 镜像当 rootfs 来源（M2 W3，M2-Q12 / ADR-18 / D5）。
//!
//! `from = "python:3.12-slim"`（或 `docker://…` / `docker-archive:./img.tar`）→ 拉取/加载 OCI 镜像
//! → digest 校验 → 层展平（OverlayFS whiteout/opaque 语义）→ 照搬 build-rootfs.sh 配方 bake 成
//! ext4（叠 sl-envd/etc、删 machine-id 保 ADR-12 克隆熵）→ 交回 build.rs 当 `base_rootfs`。其后
//! 两阶段 build-as-sandbox / 内容寻址 / 签名 / 入库**逐字节复用**。OCI config 的
//! `Env/WorkingDir/User` 物化为模板默认，`Cmd/Entrypoint` 记入 manifest（ADR-18：不自动跑）。
//!
//! D5（已定）：拉取机制 = `ureq`+rustls 手写薄 registry v2 协议（同步、无 tokio）；层解压/展平 =
//! `flate2`+`tar` 纯 Rust。**只在 host 侧 sl-node builder 路径**，guest musl `sl-envd` 零影响。
//!
//! 两类来源：
//!   1. 远程 registry（HTTPS registry v2）：docker.io 官方库 + 公有匿名 registry。
//!   2. 本地 tarball（`docker save` / OCI layout）：`docker-archive:`/`oci-archive:` 前缀，
//!      **无网络、无 docker daemon 依赖**（不碰 docker socket / /var/lib/docker）。
//!
//! MVP 边界：匿名拉公有镜像 + 单架构 x86_64（linux/amd64）；私有认证 / multi-arch 选择为 stretch。

use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::hex;

// ── 类型 ────────────────────────────────────────────────────────────────

/// `from` 分类结果。
#[derive(Debug, Clone, PartialEq)]
pub enum Source {
    /// 本地 ext4 基座（向后兼容，不进 OCI 路径）。
    Local(PathBuf),
    /// 远程 registry 镜像引用。
    Remote(OciRef),
    /// 本地 tarball（docker save / OCI layout）。
    Archive(PathBuf),
}

/// 归一化的镜像引用。
#[derive(Debug, Clone, PartialEq)]
pub struct OciRef {
    pub registry: String,
    pub repo: String,
    /// tag 或 `sha256:…` digest。
    pub reference: String,
}

impl OciRef {
    /// 规范串（用于日志 / manifest.oci_source）。
    pub fn canonical(&self) -> String {
        let sep = if self.reference.starts_with("sha256:") { "@" } else { ":" };
        format!("{}/{}{}{}", self.registry, self.repo, sep, self.reference)
    }
}

/// 镜像 config 物化结果（交回 build.rs 作模板默认）。
#[derive(Debug, Clone, Default)]
pub struct OciConfig {
    /// 镜像 Env（有序 KEY=VALUE 拆分）。
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub user: Option<String>,
    pub cmd: Vec<String>,
    pub entrypoint: Vec<String>,
}

/// `source_to_rootfs` 产物。
#[derive(Debug, Clone)]
pub struct OciResult {
    /// 规范来源串（引用或 archive 路径）。
    pub source: String,
    /// 稳定摘要：远程 = 单架构 manifest digest；archive = image config digest（image ID）。
    pub source_digest: String,
    /// 展平的层数。
    pub layers: usize,
    /// 产出 ext4 字节数。
    pub rootfs_bytes: u64,
    /// 缓存内的 ext4 路径（build.rs 拿来当 base_rootfs）。
    pub rootfs_path: PathBuf,
    pub config: OciConfig,
}

// ── A1：来源分类 + 引用解析 ────────────────────────────────────────────────

/// 把 `from` 归到 Local / Remote / Archive（纯函数、无网络、可单测）。
pub fn classify(from: &str) -> Result<Source, String> {
    let s = from.trim();
    if s.is_empty() {
        return Err("from 为空".into());
    }
    // 显式 tarball 前缀
    for pfx in ["docker-archive:", "oci-archive:"] {
        if let Some(rest) = s.strip_prefix(pfx) {
            if rest.is_empty() {
                return Err(format!("{pfx} 后缺少 tarball 路径"));
            }
            return Ok(Source::Archive(PathBuf::from(rest)));
        }
    }
    // 显式远程 scheme
    for pfx in ["docker://", "oci://"] {
        if let Some(rest) = s.strip_prefix(pfx) {
            return Ok(Source::Remote(parse_ref(rest)?));
        }
    }
    // 无 scheme：先看是否本地已存在的文件（向后兼容 ext4 基座）
    let p = Path::new(s);
    if p.exists() {
        return Ok(Source::Local(PathBuf::from(s)));
    }
    // 明显是本地路径形（扩展名/前导路径）却不存在 → 报「文件不存在」而非误当远程引用
    let looks_local = s.ends_with(".ext4")
        || s.ends_with(".img")
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('/');
    if looks_local {
        return Err(format!("base rootfs(from) 不存在: {s}"));
    }
    // 其余按远程镜像引用解析
    Ok(Source::Remote(parse_ref(s)?))
}

/// 解析镜像引用 → OciRef（docker.io 归一化）。
pub fn parse_ref(s: &str) -> Result<OciRef, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("镜像引用为空".into());
    }
    // 拆 digest（@sha256:…）
    let (name_tag, digest) = match s.split_once('@') {
        Some((n, d)) => {
            if !d.starts_with("sha256:") {
                return Err(format!("不支持的 digest 形式: {d}"));
            }
            (n, Some(d.to_string()))
        }
        None => (s, None),
    };
    // 拆 registry：首段含 '.' / ':' 或为 localhost 才当 registry host
    let (registry, remainder) = match name_tag.split_once('/') {
        Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            (first.to_string(), rest.to_string())
        }
        _ => ("registry-1.docker.io".to_string(), name_tag.to_string()),
    };
    // 拆 tag（remainder 里最后一个 ':' 且后半不含 '/'）
    let (repo, tag) = if digest.is_some() {
        (remainder.clone(), None)
    } else {
        match remainder.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') && !t.is_empty() => (r.to_string(), Some(t.to_string())),
            _ => (remainder.clone(), None),
        }
    };
    if repo.is_empty() {
        return Err(format!("镜像引用缺少 repo: {s}"));
    }
    // docker.io 官方库补 library/
    let repo = if registry == "registry-1.docker.io" && !repo.contains('/') {
        format!("library/{repo}")
    } else {
        repo
    };
    let reference = digest.or(tag).unwrap_or_else(|| "latest".to_string());
    Ok(OciRef { registry, repo, reference })
}

// ── A2：薄 registry v2 客户端（ureq，同步）──────────────────────────────────

const ACCEPT_MANIFEST: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json";

struct Client {
    agent: ureq::Agent,
    reg: OciRef,
    token: Option<String>,
}

impl Client {
    fn connect(reg: OciRef) -> Result<Self, String> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(15))
            .timeout_read(std::time::Duration::from_secs(120))
            // 跨主机重定向（blob → CDN 预签名 URL）不带 Authorization，避免签名冲突。
            .redirect_auth_headers(ureq::RedirectAuthHeaders::SameHost);
        // 环境代理（HTTPS_PROXY/ALL_PROXY）：需 proxy 才能出网的宿主上，令 docker:// 远程拉取可用。
        if let Some(purl) = proxy_from_env() {
            let proxy = ureq::Proxy::new(&purl).map_err(|e| format!("解析代理 {purl} 失败: {e}"))?;
            builder = builder.proxy(proxy);
            eprintln!("[oci] 经代理拉取: {purl}");
        }
        let agent = builder.build();
        let token = fetch_token(&agent, &reg.registry, &reg.repo)?;
        Ok(Self { agent, reg, token })
    }

    fn authed_get(&self, url: &str, accept: Option<&str>) -> Result<ureq::Response, String> {
        let mut req = self.agent.get(url);
        if let Some(a) = accept {
            req = req.set("Accept", a);
        }
        if let Some(t) = &self.token {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }
        call_lenient(req, url)
    }

    /// 取 manifest；若为 index/list（multi-arch）→ 选 linux/amd64 再取。返回 (json_bytes, digest)。
    fn get_manifest(&self, reference: &str) -> Result<(Vec<u8>, String), String> {
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            self.reg.registry, self.reg.repo, reference
        );
        let resp = self.authed_get(&url, Some(ACCEPT_MANIFEST))?;
        if resp.status() != 200 {
            return Err(format!("取 manifest 失败 status={} ({url})", resp.status()));
        }
        let hdr_digest = resp.header("Docker-Content-Digest").map(|s| s.to_string());
        let bytes = read_body(resp)?;
        let v: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("解析 manifest JSON 失败: {e}"))?;
        // index / list → 选 amd64
        if v.get("manifests").and_then(|m| m.as_array()).is_some() {
            let sub = select_amd64(&v)?;
            return self.get_manifest(&sub);
        }
        let digest = hdr_digest.unwrap_or_else(|| format!("sha256:{}", hex(&Sha256::digest(&bytes))));
        Ok((bytes, digest))
    }

    /// 取小 blob（config）到内存并校验 digest。
    fn get_blob_bytes(&self, digest: &str) -> Result<Vec<u8>, String> {
        let url = format!("https://{}/v2/{}/blobs/{}", self.reg.registry, self.reg.repo, digest);
        let resp = self.authed_get(&url, None)?;
        if resp.status() != 200 {
            return Err(format!("取 blob 失败 status={} ({digest})", resp.status()));
        }
        let bytes = read_body(resp)?;
        verify_digest(&bytes, digest)?;
        Ok(bytes)
    }

    /// 流式取大 blob（layer）落文件，边写边校验 digest（不符即删文件报错）。
    fn get_blob_to_file(&self, digest: &str, out: &Path) -> Result<(), String> {
        let url = format!("https://{}/v2/{}/blobs/{}", self.reg.registry, self.reg.repo, digest);
        let resp = self.authed_get(&url, None)?;
        if resp.status() != 200 {
            return Err(format!("取 layer blob 失败 status={} ({digest})", resp.status()));
        }
        let mut reader = resp.into_reader();
        let mut file = File::create(out).map_err(|e| format!("建 layer 临时文件失败: {e}"))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = reader.read(&mut buf).map_err(|e| format!("读 layer 流失败: {e}"))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).map_err(|e| format!("写 layer 临时文件失败: {e}"))?;
        }
        let got = format!("sha256:{}", hex(&hasher.finalize()));
        if got != digest {
            let _ = std::fs::remove_file(out);
            return Err(format!("layer digest 不符：期望 {digest} 实得 {got}（拒绝）"));
        }
        Ok(())
    }
}

/// 读环境代理（HTTPS_PROXY/https_proxy/ALL_PROXY/all_proxy，前者优先）。OCI 拉取走 HTTPS，
/// 认 HTTPS_PROXY，ALL_PROXY 兜底。仅宿主 builder 用；不认 NO_PROXY（MVP，需要时自行 unset）。
/// ureq 内置支持 http:// CONNECT 代理；socks5 需 socks-proxy feature（未启用）。
fn proxy_from_env() -> Option<String> {
    ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// ureq 非 2xx 默认抛 Error::Status；这里把它转回 Response 供上层看状态/头。
fn call_lenient(req: ureq::Request, url: &str) -> Result<ureq::Response, String> {
    match req.call() {
        Ok(r) => Ok(r),
        Err(ureq::Error::Status(_, r)) => Ok(r),
        Err(ureq::Error::Transport(t)) => Err(format!("HTTP 传输错误 {url}: {t}")),
    }
}

fn read_body(resp: ureq::Response) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| format!("读响应体失败: {e}"))?;
    Ok(buf)
}

/// 匿名 token 换取：探 `/v2/` 若 401 则按 WWW-Authenticate Bearer 质询取 token；200 则免 token。
fn fetch_token(agent: &ureq::Agent, registry: &str, repo: &str) -> Result<Option<String>, String> {
    let probe = call_lenient(agent.get(&format!("https://{registry}/v2/")), "/v2/")?;
    match probe.status() {
        200 => Ok(None),
        401 => {
            let wa = probe
                .header("www-authenticate")
                .ok_or("401 响应无 WWW-Authenticate 头")?
                .to_string();
            let realm = wa_field(&wa, "realm").ok_or("challenge 缺 realm")?;
            let service = wa_field(&wa, "service");
            let mut url = format!("{realm}?scope=repository:{repo}:pull");
            if let Some(s) = service {
                url.push_str(&format!("&service={s}"));
            }
            let tr = call_lenient(agent.get(&url), &url)?;
            if tr.status() != 200 {
                return Err(format!("token 换取失败 status={}", tr.status()));
            }
            let body = tr.into_string().map_err(|e| format!("读 token 响应失败: {e}"))?;
            let v: Value = serde_json::from_str(&body).map_err(|e| format!("解析 token JSON 失败: {e}"))?;
            let tok = v
                .get("token")
                .or_else(|| v.get("access_token"))
                .and_then(|x| x.as_str())
                .ok_or("token 响应无 token/access_token 字段")?;
            Ok(Some(tok.to_string()))
        }
        other => Err(format!("/v2/ 探测返回意外 status={other}")),
    }
}

/// 从 `Bearer realm="…",service="…",…` 里取某字段的引号值。
fn wa_field(header: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=\"");
    let start = header.find(&pat)? + pat.len();
    let rest = &header[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// 从 index/list 里挑 linux/amd64 的子 manifest digest。
fn select_amd64(index: &Value) -> Result<String, String> {
    let arr = index.get("manifests").and_then(|m| m.as_array()).ok_or("index 无 manifests")?;
    for m in arr {
        let plat = m.get("platform");
        let os = plat.and_then(|p| p.get("os")).and_then(|x| x.as_str()).unwrap_or("");
        let arch = plat.and_then(|p| p.get("architecture")).and_then(|x| x.as_str()).unwrap_or("");
        if os == "linux" && arch == "amd64" {
            if let Some(d) = m.get("digest").and_then(|x| x.as_str()) {
                return Ok(d.to_string());
            }
        }
    }
    Err("multi-arch index 未找到 linux/amd64（MVP 仅支持 amd64，multi-arch 为 stretch）".into())
}

fn verify_digest(bytes: &[u8], digest: &str) -> Result<(), String> {
    let got = format!("sha256:{}", hex(&Sha256::digest(bytes)));
    if got != digest {
        return Err(format!("blob digest 不符：期望 {digest} 实得 {got}（拒绝）"));
    }
    Ok(())
}

// ── A3：层展平（flate2 + tar，OverlayFS whiteout 语义）──────────────────────

/// 按顺序把各层 tar 展平到 `stage`，逐 entry 应用 whiteout/opaque（gzip 自适应）。
pub fn flatten_layers(layer_paths: &[PathBuf], stage: &Path) -> Result<(), String> {
    std::fs::create_dir_all(stage).map_err(|e| format!("建 staging 目录失败: {e}"))?;
    for lp in layer_paths {
        flatten_one(lp, stage)?;
    }
    Ok(())
}

fn flatten_one(layer: &Path, stage: &Path) -> Result<(), String> {
    let mut f = File::open(layer).map_err(|e| format!("打开 layer {} 失败: {e}", layer.display()))?;
    // 探 gzip 魔数（0x1f 0x8b）；docker save classic 层是未压缩 tar，远程/OCI 层多为 gzip。
    let mut magic = [0u8; 2];
    let mut got = 0;
    while got < 2 {
        let n = f.read(&mut magic[got..]).map_err(|e| format!("读 layer 魔数失败: {e}"))?;
        if n == 0 {
            break;
        }
        got += n;
    }
    if got == 0 {
        return Ok(()); // 空层
    }
    let is_gzip = got == 2 && magic == [0x1f, 0x8b];
    let head = Cursor::new(magic[..got].to_vec());
    let raw: Box<dyn Read> = Box::new(head.chain(f));
    let reader: Box<dyn Read> = if is_gzip { Box::new(GzDecoder::new(raw)) } else { raw };
    let mut ar = tar::Archive::new(reader);
    ar.set_preserve_permissions(true);
    ar.set_overwrite(true);

    let entries = ar.entries().map_err(|e| format!("读 tar entries 失败: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("读 tar entry 失败: {e}"))?;
        let path = entry.path().map_err(|e| format!("读 entry 路径失败: {e}"))?.into_owned();
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        if fname == ".wh..wh..opq" {
            // opaque：清空该目录在下层的既有内容。
            let dir = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => match safe_join(stage, p) {
                    Some(d) => d,
                    None => continue,
                },
                _ => stage.to_path_buf(),
            };
            clear_dir_contents(&dir);
            continue;
        }
        if let Some(name) = fname.strip_prefix(".wh.") {
            // whiteout：删除下层同名文件/目录。
            let parent = path.parent().unwrap_or(Path::new(""));
            let rel = parent.join(name);
            if let Some(target) = safe_join(stage, &rel) {
                remove_path(&target);
            }
            continue;
        }
        // 普通 entry：tar crate 处理符号链/硬链/权限/目录，unpack_in 内建路径逃逸防护。
        entry
            .unpack_in(stage)
            .map_err(|e| format!("展平 entry {} 失败: {e}", path.display()))?;
    }
    Ok(())
}

/// 把相对路径安全拼到 stage 下：拒绝绝对路径与 `..` 组件（防逃逸）。
fn safe_join(stage: &Path, rel: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = stage.to_path_buf();
    for c in rel.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => return None, // RootDir / ParentDir / Prefix 一律拒绝
        }
    }
    Some(out)
}

fn clear_dir_contents(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            remove_path(&e.path());
        }
    }
}

fn remove_path(p: &Path) {
    // symlink_metadata：不跟随符号链，避免删到链目标。
    if let Ok(md) = std::fs::symlink_metadata(p) {
        if md.is_dir() {
            let _ = std::fs::remove_dir_all(p);
        } else {
            let _ = std::fs::remove_file(p);
        }
    }
}

// ── A4：bake 到 ext4（照搬 build-rootfs.sh 配方）──────────────────────────────

/// 内容自动定尺的余量/下限（MiB）：留给模板 RUN 步骤写入，且保证再小的镜像也有基本空间。
const ROOTFS_MIN_MIB: u64 = 256;
const ENVD_REL: &str = "target/x86_64-unknown-linux-musl/release/sl-envd";

fn sl_envd_path() -> Result<PathBuf, String> {
    let p = std::env::var("SL_ENVD_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(ENVD_REL));
    if !p.exists() {
        return Err(format!(
            "未找到 sl-envd 静态二进制: {}\n先构建: cargo build -p sl-envd --release --target x86_64-unknown-linux-musl",
            p.display()
        ));
    }
    Ok(p)
}

/// 叠 sl-envd/etc、删 machine-id（ADR-12），mke2fs -d 免 sudo 造 ext4。
fn bake_rootfs(stage: &Path, out: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let envd = sl_envd_path()?;
    // sl-envd → /sbin/sl-envd（最后叠加，保 init 不被基座覆盖）
    let sbin = stage.join("sbin");
    std::fs::create_dir_all(&sbin).map_err(|e| format!("建 sbin 失败: {e}"))?;
    let envd_dst = sbin.join("sl-envd");
    std::fs::copy(&envd, &envd_dst).map_err(|e| format!("装 sl-envd 失败: {e}"))?;
    std::fs::set_permissions(&envd_dst, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod sl-envd 失败: {e}"))?;
    // /etc：hostname 占位；删 machine-id（ADR-12：预置身份会使克隆共享）
    let etc = stage.join("etc");
    std::fs::create_dir_all(&etc).map_err(|e| format!("建 etc 失败: {e}"))?;
    std::fs::write(etc.join("hostname"), "sandlocker-oci\n")
        .map_err(|e| format!("写 hostname 失败: {e}"))?;
    let machine_id = etc.join("machine-id");
    if machine_id.exists() {
        let _ = std::fs::remove_file(&machine_id);
    }
    // FC 启动需要的挂载点（Alpine minirootfs 自带；OCI 镜像可能缺）
    for d in ["proc", "sys", "dev", "tmp"] {
        let _ = std::fs::create_dir_all(stage.join(d));
    }

    // ext4 大小：SL_OCI_ROOTFS_SIZE 显式覆盖；否则按 stage 实际内容自动定尺。
    // **不能死给 1024M**：过大的 ext4 被 build.rs 拷成可写副本后近整盘脏页，预烘焙 snapshot/create
    // 前后 flush 会撑爆 FC API 30s 读超时（慢/嵌套存储尤甚）——guest 明明 boot 成功却在快照阶段假失败
    // （实测 alpine：1024M 复现「读响应头失败」，256M / 自动定尺则 pass）。
    let size = match std::env::var("SL_OCI_ROOTFS_SIZE") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => auto_rootfs_size(stage),
    };
    let _ = std::fs::remove_file(out);
    let stage_s = stage.to_str().ok_or("staging 路径非 UTF-8")?;
    let out_s = out.to_str().ok_or("输出路径非 UTF-8")?;
    let status = std::process::Command::new("mke2fs")
        .args(["-q", "-F", "-L", "rootfs", "-t", "ext4", "-d", stage_s, out_s, &size])
        .status()
        .map_err(|e| format!("执行 mke2fs 失败（装 e2fsprogs？）: {e}"))?;
    if !status.success() {
        return Err(format!("mke2fs 失败（size={size}，可 SL_OCI_ROOTFS_SIZE 调大）"));
    }
    Ok(())
}

/// stage 目录内容的表观字节数（递归求和常规文件大小；符号链/目录节点忽略，不跟随链接）。
fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return 0,
    };
    for ent in rd.flatten() {
        let path = ent.path();
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_dir() => total += dir_bytes(&path),
            Ok(m) if m.file_type().is_file() => total += m.len(),
            _ => {}
        }
    }
    total
}

/// 按内容自动定尺（同 scripts/oci2rootfs.sh）：内容字节 ×1.4（ext4 元数据/目录开销）+ 256M 余量，
/// 下限 256M。返回 mke2fs 认的 "<N>M" 串。alpine → ~256M，python:slim(~150MB) → ~460M。
fn auto_rootfs_size(stage: &Path) -> String {
    let mib = dir_bytes(stage) / (1024 * 1024);
    let sized = mib * 14 / 10 + ROOTFS_MIN_MIB;
    format!("{sized}M")
}

// ── A5：OCI config 物化 ────────────────────────────────────────────────────

/// 解析 image config blob 的 `.config.{Env,WorkingDir,User,Cmd,Entrypoint}`。
pub fn parse_config(blob: &[u8]) -> Result<OciConfig, String> {
    let v: Value = serde_json::from_slice(blob).map_err(|e| format!("解析 image config 失败: {e}"))?;
    let cfg = v.get("config");
    let mut out = OciConfig::default();
    if let Some(env) = cfg.and_then(|c| c.get("Env")).and_then(|e| e.as_array()) {
        for item in env {
            if let Some(kv) = item.as_str() {
                if let Some((k, val)) = kv.split_once('=') {
                    out.env.push((k.to_string(), val.to_string()));
                }
            }
        }
    }
    out.workdir = cfg
        .and_then(|c| c.get("WorkingDir"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    out.user = cfg
        .and_then(|c| c.get("User"))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    out.cmd = str_array(cfg, "Cmd");
    out.entrypoint = str_array(cfg, "Entrypoint");
    Ok(out)
}

fn str_array(cfg: Option<&Value>, key: &str) -> Vec<String> {
    cfg.and_then(|c| c.get(key))
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

// ── A7：本地 tarball 加载（docker-archive / OCI layout）─────────────────────

/// 加载结果：层文件路径（有序）、config blob、image id（config 内容 digest）。
struct ArchiveImage {
    layer_files: Vec<PathBuf>,
    config: Vec<u8>,
    image_id: String,
}

/// 解 tarball 到 `work` 临时目录，解析 manifest，定位有序层文件 + config。
fn load_archive(path: &Path, work: &Path) -> Result<ArchiveImage, String> {
    let extract = work.join("extract");
    std::fs::create_dir_all(&extract).map_err(|e| format!("建解包目录失败: {e}"))?;
    // 外层 tar（docker save 未压缩；容错 gzip）→ 全量解包到 extract
    flatten_extract_plain(path, &extract)?;

    // docker-archive：manifest.json（数组）
    let dm = extract.join("manifest.json");
    if dm.exists() {
        let bytes = std::fs::read(&dm).map_err(|e| format!("读 manifest.json 失败: {e}"))?;
        let arr: Value = serde_json::from_slice(&bytes).map_err(|e| format!("解析 manifest.json 失败: {e}"))?;
        let first = arr.get(0).ok_or("manifest.json 数组为空")?;
        let config_rel = first.get("Config").and_then(|x| x.as_str()).ok_or("manifest.json 缺 Config")?;
        let layers = first
            .get("Layers")
            .and_then(|x| x.as_array())
            .ok_or("manifest.json 缺 Layers")?;
        let config = std::fs::read(extract.join(config_rel))
            .map_err(|e| format!("读 config {config_rel} 失败: {e}"))?;
        let mut layer_files = Vec::new();
        for l in layers {
            let rel = l.as_str().ok_or("Layers 项非字符串")?;
            layer_files.push(extract.join(rel));
        }
        let image_id = format!("sha256:{}", hex(&Sha256::digest(&config)));
        return Ok(ArchiveImage { layer_files, config, image_id });
    }

    // oci-archive：OCI layout（index.json → manifest → config/layers）
    let idx = extract.join("index.json");
    if idx.exists() {
        return load_oci_layout(&extract);
    }

    Err("无法识别 tarball：既无 manifest.json（docker-archive）也无 index.json（oci-archive）".into())
}

fn load_oci_layout(extract: &Path) -> Result<ArchiveImage, String> {
    let blob_path = |digest: &str| -> PathBuf {
        let h = digest.strip_prefix("sha256:").unwrap_or(digest);
        extract.join("blobs").join("sha256").join(h)
    };
    let idx: Value = serde_json::from_slice(&std::fs::read(extract.join("index.json")).map_err(|e| format!("读 index.json 失败: {e}"))?)
        .map_err(|e| format!("解析 index.json 失败: {e}"))?;
    let manifests = idx.get("manifests").and_then(|m| m.as_array()).ok_or("index.json 无 manifests")?;
    // 若 index 直接列多架构 image，选 amd64；否则取第一个（可能指向 index 再选）
    let mut manifest_digest = manifests
        .iter()
        .find(|m| {
            let p = m.get("platform");
            p.and_then(|p| p.get("architecture")).and_then(|x| x.as_str()) == Some("amd64")
        })
        .or_else(|| manifests.first())
        .and_then(|m| m.get("digest"))
        .and_then(|x| x.as_str())
        .ok_or("index.json 未定位 manifest digest")?
        .to_string();

    // 跟随一层 index 嵌套
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(blob_path(&manifest_digest)).map_err(|e| format!("读 manifest blob 失败: {e}"))?)
            .map_err(|e| format!("解析 manifest blob 失败: {e}"))?;
    if manifest.get("manifests").and_then(|m| m.as_array()).is_some() {
        manifest_digest = select_amd64(&manifest)?;
        manifest = serde_json::from_slice(&std::fs::read(blob_path(&manifest_digest)).map_err(|e| format!("读子 manifest 失败: {e}"))?)
            .map_err(|e| format!("解析子 manifest 失败: {e}"))?;
    }

    let config_digest = manifest.get("config").and_then(|c| c.get("digest")).and_then(|x| x.as_str()).ok_or("manifest 缺 config.digest")?;
    let config = std::fs::read(blob_path(config_digest)).map_err(|e| format!("读 config blob 失败: {e}"))?;
    let layers = manifest.get("layers").and_then(|x| x.as_array()).ok_or("manifest 缺 layers")?;
    let mut layer_files = Vec::new();
    for l in layers {
        let d = l.get("digest").and_then(|x| x.as_str()).ok_or("layer 缺 digest")?;
        layer_files.push(blob_path(d));
    }
    let image_id = config_digest.to_string();
    Ok(ArchiveImage { layer_files, config, image_id })
}

/// 把一个 tar（自适应 gzip）原样解包到 dst（用于外层 archive 解包，不做 whiteout）。
fn flatten_extract_plain(tar_path: &Path, dst: &Path) -> Result<(), String> {
    let mut f = File::open(tar_path).map_err(|e| format!("打开 tarball {} 失败: {e}", tar_path.display()))?;
    let mut magic = [0u8; 2];
    let mut got = 0;
    while got < 2 {
        let n = f.read(&mut magic[got..]).map_err(|e| format!("读 tarball 魔数失败: {e}"))?;
        if n == 0 {
            break;
        }
        got += n;
    }
    let is_gzip = got == 2 && magic == [0x1f, 0x8b];
    let head = Cursor::new(magic[..got].to_vec());
    let raw: Box<dyn Read> = Box::new(head.chain(f));
    let reader: Box<dyn Read> = if is_gzip { Box::new(GzDecoder::new(raw)) } else { raw };
    let mut ar = tar::Archive::new(reader);
    ar.unpack(dst).map_err(|e| format!("解包 tarball 失败: {e}"))?;
    Ok(())
}

// ── A6：顶层入口 ────────────────────────────────────────────────────────────

const CACHE_ROOT: &str = "build/oci-cache";

/// 拉取/加载 → 展平 → bake → config 物化。缓存键 = source_digest（内容寻址，可再生）。
pub fn source_to_rootfs(source: &Source, quiet: bool) -> Result<OciResult, String> {
    match source {
        Source::Local(_) => Err("Local 源不走 OCI 路径".into()),
        Source::Remote(r) => remote_to_rootfs(r, quiet),
        Source::Archive(p) => archive_to_rootfs(p, quiet),
    }
}

/// bake 配方版本：改了 bake_rootfs 的配方就 bump（令旧缓存失效）。
const BAKE_RECIPE_VER: &str = "r1";

/// bake 配方标签 = 配方版本 + sl-envd 内容 hash 前 8 hex。
/// 纳入缓存目录名，使**换了 sl-envd（或配方）自动令缓存失效**——否则命中旧 rootfs（烘的是旧 sl-envd），
/// 改了 guest 却看不到效果（实测踩过：改 sl-envd 后必须手动清 build/oci-cache 才生效）。
fn bake_recipe_tag() -> String {
    let envd_h = sl_envd_path()
        .ok()
        .and_then(|p| std::fs::read(&p).ok())
        .map(|b| hex(&Sha256::digest(&b))[..8].to_string())
        .unwrap_or_else(|| "noenvd".into());
    format!("{BAKE_RECIPE_VER}-{envd_h}")
}

fn cache_dir_for(digest: &str) -> PathBuf {
    let short = digest.strip_prefix("sha256:").unwrap_or(digest);
    let short = &short[..short.len().min(16)];
    PathBuf::from(CACHE_ROOT).join(format!("{short}-{}", bake_recipe_tag()))
}

/// 命中缓存：返回已 bake 的 ext4 + config。
fn try_cache(source: String, digest: &str, layers: usize) -> Option<OciResult> {
    let dir = cache_dir_for(digest);
    let rootfs = dir.join("rootfs.ext4");
    let cfg_json = dir.join("config.json");
    if !rootfs.exists() || !cfg_json.exists() {
        return None;
    }
    let blob = std::fs::read(&cfg_json).ok()?;
    let config = parse_config(&blob).ok()?;
    let rootfs_bytes = std::fs::metadata(&rootfs).ok()?.len();
    Some(OciResult { source, source_digest: digest.to_string(), layers, rootfs_bytes, rootfs_path: rootfs, config })
}

fn remote_to_rootfs(r: &OciRef, quiet: bool) -> Result<OciResult, String> {
    let source = r.canonical();
    if !quiet {
        eprintln!("[oci] 拉取远程镜像 {source} ...");
    }
    let client = Client::connect(r.clone())?;
    let (manifest_bytes, digest) = client.get_manifest(&r.reference)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|e| format!("解析 manifest 失败: {e}"))?;
    let layer_digests: Vec<String> = manifest
        .get("layers")
        .and_then(|x| x.as_array())
        .ok_or("manifest 缺 layers")?
        .iter()
        .filter_map(|l| l.get("digest").and_then(|x| x.as_str()).map(str::to_string))
        .collect();

    if let Some(hit) = try_cache(source.clone(), &digest, layer_digests.len()) {
        if !quiet {
            eprintln!("[oci] 命中缓存 {}", hit.rootfs_path.display());
        }
        return Ok(hit);
    }

    let config_digest = manifest.get("config").and_then(|c| c.get("digest")).and_then(|x| x.as_str()).ok_or("manifest 缺 config.digest")?;
    let config_blob = client.get_blob_bytes(config_digest)?;

    let dir = cache_dir_for(&digest);
    std::fs::create_dir_all(&dir).map_err(|e| format!("建缓存目录失败: {e}"))?;
    let tmp = dir.join("layers");
    std::fs::create_dir_all(&tmp).map_err(|e| format!("建 layer 临时目录失败: {e}"))?;
    let mut layer_files = Vec::new();
    for (i, ld) in layer_digests.iter().enumerate() {
        let lf = tmp.join(format!("layer{i}.tar"));
        if !quiet {
            eprintln!("[oci] 下载层 {}/{} {ld}", i + 1, layer_digests.len());
        }
        client.get_blob_to_file(ld, &lf)?;
        layer_files.push(lf);
    }

    finish_bake(source, digest, config_blob, &layer_files, &dir, quiet)
}

fn archive_to_rootfs(path: &Path, quiet: bool) -> Result<OciResult, String> {
    let source = format!("docker-archive:{}", path.display());
    if !path.exists() {
        return Err(format!("tarball 不存在: {}", path.display()));
    }
    if !quiet {
        eprintln!("[oci] 加载本地 tarball {} ...", path.display());
    }
    // 先解到临时目录取 image_id（archive 无 registry digest）
    let staging = PathBuf::from(CACHE_ROOT).join(".archive-staging");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("建 archive 暂存失败: {e}"))?;
    let img = load_archive(path, &staging)?;
    let digest = img.image_id.clone();
    let layers = img.layer_files.len();

    if let Some(hit) = try_cache(source.clone(), &digest, layers) {
        let _ = std::fs::remove_dir_all(&staging);
        if !quiet {
            eprintln!("[oci] 命中缓存 {}", hit.rootfs_path.display());
        }
        return Ok(hit);
    }

    let dir = cache_dir_for(&digest);
    std::fs::create_dir_all(&dir).map_err(|e| format!("建缓存目录失败: {e}"))?;
    let res = finish_bake(source, digest, img.config, &img.layer_files, &dir, quiet);
    let _ = std::fs::remove_dir_all(&staging);
    res
}

/// 展平层 → bake ext4 → 落 config.json → 组装 OciResult。
fn finish_bake(
    source: String,
    digest: String,
    config_blob: Vec<u8>,
    layer_files: &[PathBuf],
    dir: &Path,
    quiet: bool,
) -> Result<OciResult, String> {
    let stage = dir.join("stage");
    let _ = std::fs::remove_dir_all(&stage);
    if !quiet {
        eprintln!("[oci] 展平 {} 层 ...", layer_files.len());
    }
    flatten_layers(layer_files, &stage)?;
    let config = parse_config(&config_blob)?;

    let rootfs = dir.join("rootfs.ext4");
    if !quiet {
        eprintln!("[oci] bake ext4 {} ...", rootfs.display());
    }
    bake_rootfs(&stage, &rootfs)?;
    std::fs::write(dir.join("config.json"), &config_blob).map_err(|e| format!("写 config.json 失败: {e}"))?;
    // 展平中间物清理（保留 rootfs.ext4 + config.json 作缓存）
    let _ = std::fs::remove_dir_all(&stage);
    let _ = std::fs::remove_dir_all(dir.join("layers"));

    let rootfs_bytes = std::fs::metadata(&rootfs).map_err(|e| format!("读 ext4 大小失败: {e}"))?.len();
    Ok(OciResult { source, source_digest: digest, layers: layer_files.len(), rootfs_bytes, rootfs_path: rootfs, config })
}

// ── 测试 ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmpdir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("sl-oci-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn tar_append<W: Write>(b: &mut tar::Builder<W>, path: &str, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append_data(&mut h, path, data).unwrap();
    }

    fn write_tar_gz(path: &Path, files: &[(&str, &[u8])]) {
        let f = File::create(path).unwrap();
        let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
        let mut b = tar::Builder::new(enc);
        for (p, d) in files {
            tar_append(&mut b, p, d);
        }
        b.into_inner().unwrap().finish().unwrap();
    }

    fn write_tar_plain(path: &Path, files: &[(&str, &[u8])]) {
        let f = File::create(path).unwrap();
        let mut b = tar::Builder::new(f);
        for (p, d) in files {
            tar_append(&mut b, p, d);
        }
        b.into_inner().unwrap();
    }

    #[test]
    fn parse_ref_docker_io_defaults() {
        let r = parse_ref("python:3.12-slim").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repo, "library/python");
        assert_eq!(r.reference, "3.12-slim");
    }

    #[test]
    fn parse_ref_default_tag_latest() {
        let r = parse_ref("alpine").unwrap();
        assert_eq!(r.repo, "library/alpine");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn parse_ref_with_registry_host() {
        let r = parse_ref("ghcr.io/org/img:v1").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repo, "org/img");
        assert_eq!(r.reference, "v1");
    }

    #[test]
    fn parse_ref_registry_with_port() {
        let r = parse_ref("localhost:5000/my/app:dev").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repo, "my/app");
        assert_eq!(r.reference, "dev");
    }

    #[test]
    fn parse_ref_digest() {
        let d = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let r = parse_ref(&format!("python@{d}")).unwrap();
        assert_eq!(r.repo, "library/python");
        assert_eq!(r.reference, d);
    }

    #[test]
    fn classify_three_way() {
        // Local：造一个真实文件
        let dir = tmpdir();
        let f = dir.join("base.ext4");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(classify(f.to_str().unwrap()).unwrap(), Source::Local(f.clone()));

        // Remote：docker:// 前缀 + bare ref
        match classify("docker://python:3.12-slim").unwrap() {
            Source::Remote(r) => assert_eq!(r.repo, "library/python"),
            o => panic!("期望 Remote，得 {o:?}"),
        }
        match classify("python:3.12-slim").unwrap() {
            Source::Remote(_) => {}
            o => panic!("期望 Remote，得 {o:?}"),
        }

        // Archive
        match classify("docker-archive:./img.tar").unwrap() {
            Source::Archive(p) => assert_eq!(p, PathBuf::from("./img.tar")),
            o => panic!("期望 Archive，得 {o:?}"),
        }

        // 明显本地路径但不存在 → Err
        assert!(classify("./missing.ext4").is_err());
        assert!(classify("/nope/x.ext4").is_err());
    }

    #[test]
    fn flatten_whiteout_and_opaque() {
        let dir = tmpdir();
        let l1 = dir.join("l1.tar.gz");
        let l2 = dir.join("l2.tar");
        // 层1（gzip）：app/keep.txt, app/gone.txt, data/old.txt
        write_tar_gz(
            &l1,
            &[
                ("app/keep.txt", b"keep"),
                ("app/gone.txt", b"gone"),
                ("data/old.txt", b"old"),
            ],
        );
        // 层2（未压缩，验 gzip 自适应）：删 app/gone.txt、opaque data/、加 app/new.txt
        write_tar_plain(
            &l2,
            &[
                ("app/.wh.gone.txt", b""),
                ("data/.wh..wh..opq", b""),
                ("data/fresh.txt", b"fresh"),
                ("app/new.txt", b"new"),
            ],
        );
        let stage = dir.join("stage");
        flatten_layers(&[l1, l2], &stage).unwrap();

        assert!(stage.join("app/keep.txt").exists(), "keep 应保留");
        assert!(!stage.join("app/gone.txt").exists(), "gone 应被 whiteout 删除");
        assert!(stage.join("app/new.txt").exists(), "new 应加入");
        assert!(!stage.join("data/old.txt").exists(), "opaque 应清 data 旧内容");
        assert!(stage.join("data/fresh.txt").exists(), "opaque 后同层新增应保留");
    }

    #[test]
    fn flatten_higher_layer_overrides() {
        let dir = tmpdir();
        let l1 = dir.join("a.tar.gz");
        let l2 = dir.join("b.tar.gz");
        write_tar_gz(&l1, &[("etc/conf", b"v1")]);
        write_tar_gz(&l2, &[("etc/conf", b"v2")]);
        let stage = dir.join("stage");
        flatten_layers(&[l1, l2], &stage).unwrap();
        let got = std::fs::read_to_string(stage.join("etc/conf")).unwrap();
        assert_eq!(got, "v2", "高层应覆盖低层同名文件");
    }

    #[test]
    fn verify_digest_rejects_tampered() {
        let data = b"hello oci";
        let good = format!("sha256:{}", hex(&Sha256::digest(data)));
        assert!(verify_digest(data, &good).is_ok());
        let bad = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(verify_digest(data, bad).is_err(), "错误 digest 应拒绝");
    }

    #[test]
    fn parse_config_env_workdir_cmd() {
        let blob = br#"{
            "architecture":"amd64","os":"linux",
            "config":{
                "Env":["PATH=/usr/bin","LANG=C.UTF-8"],
                "WorkingDir":"/app","User":"appuser",
                "Cmd":["python3"],"Entrypoint":["/entry.sh"]
            }
        }"#;
        let c = parse_config(blob).unwrap();
        assert_eq!(c.env, vec![("PATH".into(), "/usr/bin".into()), ("LANG".into(), "C.UTF-8".into())]);
        assert_eq!(c.workdir.as_deref(), Some("/app"));
        assert_eq!(c.user.as_deref(), Some("appuser"));
        assert_eq!(c.cmd, vec!["python3".to_string()]);
        assert_eq!(c.entrypoint, vec!["/entry.sh".to_string()]);
    }

    #[test]
    fn auto_rootfs_size_floors_to_min_and_grows() {
        let d = tmpdir();
        // 空/极小内容 → 落到下限 256M（关键：绝不再回到 1024M —— 大 ext4 会撑爆快照超时）
        std::fs::write(d.join("tiny"), b"x").unwrap();
        assert_eq!(auto_rootfs_size(&d), "256M");
        // 内容变大 → 尺寸随之增长（100MiB 文件 → 100×1.4+256 = 396M）
        let big = d.join("big.bin");
        std::fs::write(&big, vec![0u8; 100 * 1024 * 1024]).unwrap();
        assert_eq!(auto_rootfs_size(&d), "396M");
    }

    #[test]
    fn parse_config_empty_workdir_is_none() {
        let blob = br#"{"config":{"WorkingDir":"","User":""}}"#;
        let c = parse_config(blob).unwrap();
        assert!(c.workdir.is_none());
        assert!(c.user.is_none());
    }

    #[test]
    fn load_docker_archive_roundtrip() {
        let dir = tmpdir();
        // 造最小 docker-archive：manifest.json + config json + 一层 tar（未压缩）
        let layer = dir.join("layer0.tar");
        write_tar_plain(&layer, &[("bin/hello", b"#!/bin/sh\necho hi\n")]);
        let layer_bytes = std::fs::read(&layer).unwrap();
        let config = br#"{"architecture":"amd64","os":"linux","config":{"Cmd":["/bin/hello"]}}"#;
        let manifest = br#"[{"Config":"config.json","RepoTags":["x:latest"],"Layers":["layer0.tar"]}]"#;

        let archive = dir.join("img.tar");
        write_tar_plain(
            &archive,
            &[
                ("manifest.json", manifest.as_slice()),
                ("config.json", config.as_slice()),
                ("layer0.tar", &layer_bytes),
            ],
        );

        let work = dir.join("work");
        let img = load_archive(&archive, &work).unwrap();
        assert_eq!(img.layer_files.len(), 1);
        assert!(img.layer_files[0].exists());
        assert_eq!(img.config, config);
        let expect_id = format!("sha256:{}", hex(&Sha256::digest(config)));
        assert_eq!(img.image_id, expect_id);
    }

    #[test]
    fn load_archive_bad_manifest_errors() {
        let dir = tmpdir();
        let archive = dir.join("bad.tar");
        write_tar_plain(&archive, &[("manifest.json", b"{ not json ]")]);
        let work = dir.join("work");
        assert!(load_archive(&archive, &work).is_err(), "坏 manifest.json 应报错");
    }

    #[test]
    fn safe_join_rejects_escape() {
        let stage = Path::new("/tmp/stage");
        assert!(safe_join(stage, Path::new("../etc/passwd")).is_none());
        assert!(safe_join(stage, Path::new("/etc/passwd")).is_none());
        assert_eq!(safe_join(stage, Path::new("a/b")).unwrap(), PathBuf::from("/tmp/stage/a/b"));
    }
}
