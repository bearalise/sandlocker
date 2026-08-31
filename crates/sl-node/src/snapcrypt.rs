//! snapcrypt.rs — 快照信封加密（M3 W9，ADR-15 / M3-Q6 / PRD §8.2）。
//!
//! # 为什么加密只能包在 Firecracker 外面
//!
//! FC 的快照是它自己读写的：`PUT /snapshot/create` 由 FC 把 `vmstate` + `mem` 落盘，
//! `PUT /snapshot/load` 又由 FC 直接 `mmap` 那个 `mem` 文件（**惰性缺页**，ADR-23/D4）。
//! FC 不认识密文，也没有插自定义存储层的口子。所以本模块做的是**落盘后加密 / 恢复前解密**：
//!
//! ```text
//! pause : FC 写 vmstate|mem（明文）→ 本模块加密成 vmstate.enc|mem.enc → 抹掉明文
//! resume: 本模块解密出 vmstate|mem → FC 恢复（mem 全程 mmap）→ 下次 pause 再加密
//! ```
//!
//! **由此界定的边界（务必如实理解）**：受保护的是**暂停态快照**——即节点关机后仍留在盘上的
//! 那份状态。**运行中**实例的 `mem` 必须是明文，因为 FC 全程 mmap 它；这不构成额外暴露
//! （运行中的内存本来就在宿主 RAM 里）。若把解密目标放到 tmpfs 以求"明文永不落盘"，代价是
//! 每个实例额外吃一份等量 RAM（512MiB 量级），直接冲垮密度硬出口（M3-Q9 ≥200/节点），故不取。
//!
//! # 威胁模型（PRD §8.2，必须明示）
//!
//! - **防**：快照仓库/磁盘被整体拷走（静态数据失窃）。密文无 KEK 不可解。
//! - **不防**：**持钥节点被攻破**——V1 的根密钥就在节点上（文件 KMS，开发级），拿到 root
//!   即可逐级解到 DEK。Vault KMS 插件列 P1/GA。
//! - **pause 会捕获 guest 内存里当时存在的一切 secret**。本模块只能保证它落盘时是密文；
//!   用户侧密钥轮换需在文档中指引。sl-envd 在 pause 前擦掉**自己**的会话密钥
//!   （`Request::WipeKeys`），但它管不了用户进程持有的凭据。
//!
//! # 密钥层级（信封加密）
//!
//! ```text
//! 根密钥（KMS：V1 文件实现，开发级 / Vault 插件 P1）
//!   └─ 租户 KEK（每项目一把，随机 32B）——**以密文存控制面** `kek/<project>`
//!        └─ 快照 DEK（每快照一把，随机 32B）——**以密文存快照头**
//! ```
//!
//! 节点**不持久化明文 DEK / 明文 KEK**：两者落盘时都已被上一级包裹，明文只在内存里活到
//! 一次加解密结束。
//!
//! # 容器格式 `SLSNAP1`
//!
//! ```text
//! 头部（明文，但整体绑进每块的 AAD，改一个字节即全块解密失败）：
//!   magic      8B   "SLSNAP1\0"
//!   version    u16  = 1
//!   algo       u16  = 1（AES-256-GCM）
//!   chunk_size u32  = 4 MiB（ADR-15）
//!   plain_len  u64  明文总长（末块可短）
//!   kek_id     u16 长度 + 字节（租户 KEK 标识，指向 `kek/<id>`）
//!   wrapped_dek u16 长度 + 字节（KEK 包裹的 DEK，含 12B nonce + 密文 + 16B tag）
//! 其后 N 块，每块定长 chunk_size + 16B tag（末块 = 余数 + 16B）：
//!   chunk[i] = AES-256-GCM(DEK, nonce=00000000||be64(i), aad=头部字段||be64(i))
//! ```
//!
//! **分块的意义**（ADR-15 明确要求）：块 `i` 的密文起点是 `header_len + i*(chunk_size+16)`，
//! 可直接 seek——**支持随机读**，将来接 userfaultfd 懒加载（P2）时不必改格式。整文件加密做不到
//! 这一点，这正是 ADR-15 选分块 AEAD 而非整文件 AEAD 的原因。[`decrypt_chunk`] 就是这个能力
//! 的实证入口（并被对账用到）。
//!
//! **nonce 唯一性**：DEK 每快照随机，块序号在同一 DEK 下唯一 → (DEK, nonce) 不重复。
//!
//! # 依赖
//!
//! AEAD 用 **ring**——它早已在依赖树里（ureq → rustls → ring），故本特性**零新增 crate**，
//! 守 M2 D5「精简依赖」。

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};

use crate::host_random;

/// 容器魔数。
const MAGIC: &[u8; 8] = b"SLSNAP1\0";
/// 格式版本。
const VERSION: u16 = 1;
/// 算法号：1 = AES-256-GCM。
const ALGO_AES256GCM: u16 = 1;
/// AEAD tag 长度（AES-GCM 固定 16B）。
const TAG_LEN: usize = 16;
/// 分块大小（ADR-15：4MiB，兼顾随机读与完整性）。
pub const CHUNK_SIZE: u32 = 4 * 1024 * 1024;
/// 密钥长度（AES-256）。
pub const KEY_LEN: usize = 32;

/// 32 字节密钥。`Drop` 时清零——明文密钥不在内存里多留一刻。
///
/// 注意：这挡的是「同进程后续代码/堆复用读到残留」，挡不住被换页到 swap 或核心转储。
/// 后者属于「持钥节点被攻破」，本就在威胁模型之外（见模块头）。
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Key(b)
    }
    /// 现取随机密钥（DEK/KEK 生成）。
    pub fn random() -> Self {
        let mut b = [0u8; KEY_LEN];
        host_random(&mut b);
        Key(b)
    }
    /// 裸露密钥字节。**仅供对账/单测**断言「这段字节不该出现在盘上」——
    /// 生产路径没有任何理由取明文密钥，故名字刻意难用。
    pub(crate) fn expose_for_test(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    fn aead(&self) -> Result<LessSafeKey, String> {
        let ub = UnboundKey::new(&AES_256_GCM, &self.0).map_err(|_| "构造 AEAD 密钥失败".to_string())?;
        Ok(LessSafeKey::new(ub))
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // write_volatile：防编译器把「马上就要释放的写」优化掉。
        for b in self.0.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// 一次快照操作用得上的密钥材料：租户 KEK + 它的标识。
///
/// 由 orchestrator 从控制面解出后交给后端（后端不认识 store，也不该认识项目/租户概念）。
/// `None` 表示未启用加密——快照明文落盘，即 M2 行为（零回归）。
pub struct SnapKey {
    pub kek: Key,
    pub kek_id: String,
}

// ————————————————————— KMS（根密钥）—————————————————————

/// 根密钥来源。V1 只有文件实现（开发级）；Vault 插件列 P1/GA（ADR-15 D5）。
///
/// 接口只做两件事：包裹 / 解裹**租户 KEK**。DEK 不经 KMS（由 KEK 直接包裹），
/// 这样每次 pause/resume 不必打 KMS，加解密全在本地内存完成。
pub trait Kms: Send + Sync {
    fn wrap_kek(&self, kek: &Key) -> Result<Vec<u8>, String>;
    fn unwrap_kek(&self, wrapped: &[u8]) -> Result<Key, String>;
    /// 供日志/头部标注用的 KMS 标识。
    fn id(&self) -> &str;
}

/// 文件 KMS（**开发级**，ADR-15 D5）：根密钥是一个 32 字节文件。
///
/// 明确的局限：根密钥与密文同机 → 只防「盘被拷走」，不防「节点被攻破」。生产应换 Vault 插件。
/// 文件权限必须是 0600 且属主可读——否则直接拒绝启动（宁可起不来也不要静默地用一把人人可读的根密钥）。
pub struct FileKms {
    root: Key,
}

impl FileKms {
    /// 从文件加载根密钥。文件须恰好 32 字节且权限 0600。
    pub fn open(path: &Path) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(path).map_err(|e| format!("读 KMS 根密钥 {} 失败: {e}", path.display()))?;
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "KMS 根密钥 {} 权限为 {mode:o}，须为 0600（组/其他用户不可读）",
                path.display()
            ));
        }
        let raw = std::fs::read(path).map_err(|e| format!("读 KMS 根密钥失败: {e}"))?;
        if raw.len() != KEY_LEN {
            return Err(format!("KMS 根密钥须恰好 {KEY_LEN} 字节，实为 {}", raw.len()));
        }
        let mut b = [0u8; KEY_LEN];
        b.copy_from_slice(&raw);
        Ok(FileKms { root: Key::from_bytes(b) })
    }

    /// 生成一把新的根密钥文件（0600）。`--snap-kms-init` 用。
    pub fn init(path: &Path) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        if path.exists() {
            return Err(format!("{} 已存在——拒绝覆盖根密钥（覆盖 = 所有既有快照永久不可解）", path.display()));
        }
        let mut b = [0u8; KEY_LEN];
        host_random(&mut b);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("建 {} 失败: {e}", path.display()))?;
        f.write_all(&b).map_err(|e| format!("写根密钥失败: {e}"))?;
        for x in b.iter_mut() {
            unsafe { std::ptr::write_volatile(x, 0) };
        }
        Ok(())
    }
}

impl Kms for FileKms {
    fn wrap_kek(&self, kek: &Key) -> Result<Vec<u8>, String> {
        seal_blob(&self.root, &kek.0, b"sandlocker/kek/v1")
    }
    fn unwrap_kek(&self, wrapped: &[u8]) -> Result<Key, String> {
        let raw = open_blob(&self.root, wrapped, b"sandlocker/kek/v1")?;
        if raw.len() != KEY_LEN {
            return Err("解裹后的 KEK 长度异常".into());
        }
        let mut b = [0u8; KEY_LEN];
        b.copy_from_slice(&raw);
        Ok(Key::from_bytes(b))
    }
    fn id(&self) -> &str {
        "file"
    }
}

/// 用 `key` 包裹一小段密钥material：`nonce(12B) || 密文 || tag(16B)`。
fn seal_blob(key: &Key, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    host_random(&mut nonce);
    let mut buf = plain.to_vec();
    key.aead()?
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf)
        .map_err(|_| "包裹密钥失败".to_string())?;
    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

fn open_blob(key: &Key, wrapped: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if wrapped.len() < NONCE_LEN + TAG_LEN {
        return Err("被包裹的密钥过短".into());
    }
    let (n, body) = wrapped.split_at(NONCE_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(n);
    let mut buf = body.to_vec();
    let out = key
        .aead()?
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buf)
        .map_err(|_| "解裹密钥失败（根密钥不对，或密文被篡改）".to_string())?;
    Ok(out.to_vec())
}

// ————————————————————— 容器头 —————————————————————

/// 已解析的快照头。
#[derive(Debug, Clone)]
pub struct Header {
    pub chunk_size: u32,
    pub plain_len: u64,
    pub kek_id: String,
    wrapped_dek: Vec<u8>,
    /// 头部字节长度 = 第 0 块密文的起点。
    pub header_len: u64,
}

impl Header {
    /// 每块 AAD：绑定全部头部语义字段 + 块序号。改 `plain_len`/`chunk_size`/`kek_id`
    /// 或把块换位置，AEAD 校验都会失败——头部虽是明文但不可篡改。
    fn aad(&self, idx: u64) -> Vec<u8> {
        let mut a = Vec::with_capacity(64);
        a.extend_from_slice(MAGIC);
        a.extend_from_slice(&VERSION.to_be_bytes());
        a.extend_from_slice(&ALGO_AES256GCM.to_be_bytes());
        a.extend_from_slice(&self.chunk_size.to_be_bytes());
        a.extend_from_slice(&self.plain_len.to_be_bytes());
        a.extend_from_slice(self.kek_id.as_bytes());
        a.extend_from_slice(&idx.to_be_bytes());
        a
    }

    /// 块数（末块可短；空明文 = 0 块）。
    pub fn chunks(&self) -> u64 {
        self.plain_len.div_ceil(self.chunk_size as u64)
    }

    /// 第 `idx` 块密文在文件中的起点——**随机读的关键**：定长块使这是纯算术，无需索引表。
    pub fn chunk_offset(&self, idx: u64) -> u64 {
        self.header_len + idx * (self.chunk_size as u64 + TAG_LEN as u64)
    }

    /// 第 `idx` 块的密文长度（含 tag）。
    pub fn chunk_len(&self, idx: u64) -> usize {
        let start = idx * self.chunk_size as u64;
        let plain = (self.plain_len - start).min(self.chunk_size as u64);
        plain as usize + TAG_LEN
    }

    fn encode(&self) -> Vec<u8> {
        let mut h = Vec::with_capacity(128);
        h.extend_from_slice(MAGIC);
        h.extend_from_slice(&VERSION.to_be_bytes());
        h.extend_from_slice(&ALGO_AES256GCM.to_be_bytes());
        h.extend_from_slice(&self.chunk_size.to_be_bytes());
        h.extend_from_slice(&self.plain_len.to_be_bytes());
        h.extend_from_slice(&(self.kek_id.len() as u16).to_be_bytes());
        h.extend_from_slice(self.kek_id.as_bytes());
        h.extend_from_slice(&(self.wrapped_dek.len() as u16).to_be_bytes());
        h.extend_from_slice(&self.wrapped_dek);
        h
    }

    /// 从文件头解析。只读必要的前缀，不吃整个文件。
    pub fn read_from(f: &mut File) -> Result<Header, String> {
        f.seek(SeekFrom::Start(0)).map_err(|e| format!("seek 头部失败: {e}"))?;
        let mut fixed = [0u8; 8 + 2 + 2 + 4 + 8];
        f.read_exact(&mut fixed).map_err(|e| format!("读头部失败: {e}"))?;
        if &fixed[..8] != MAGIC {
            return Err("不是 SLSNAP1 加密快照（魔数不符）".into());
        }
        let version = u16::from_be_bytes([fixed[8], fixed[9]]);
        if version != VERSION {
            return Err(format!("快照格式版本 {version} 不受支持（本版支持 {VERSION}）"));
        }
        let algo = u16::from_be_bytes([fixed[10], fixed[11]]);
        if algo != ALGO_AES256GCM {
            return Err(format!("快照算法号 {algo} 不受支持"));
        }
        let chunk_size = u32::from_be_bytes([fixed[12], fixed[13], fixed[14], fixed[15]]);
        if chunk_size == 0 {
            return Err("头部 chunk_size 为 0".into());
        }
        let mut pl = [0u8; 8];
        pl.copy_from_slice(&fixed[16..24]);
        let plain_len = u64::from_be_bytes(pl);
        let kek_id = read_len_prefixed(f, "kek_id")?;
        let kek_id = String::from_utf8(kek_id).map_err(|_| "kek_id 非 UTF-8".to_string())?;
        let wrapped_dek = read_len_prefixed(f, "wrapped_dek")?;
        let header_len = f.stream_position().map_err(|e| format!("取头部长度失败: {e}"))?;
        Ok(Header { chunk_size, plain_len, kek_id, wrapped_dek, header_len })
    }

    /// 用租户 KEK 解裹本快照的 DEK。**明文 DEK 只在返回值里活到用完即 Drop 清零。**
    pub fn unwrap_dek(&self, kek: &Key) -> Result<Key, String> {
        let raw = open_blob(kek, &self.wrapped_dek, b"sandlocker/dek/v1")?;
        if raw.len() != KEY_LEN {
            return Err("解裹后的 DEK 长度异常".into());
        }
        let mut b = [0u8; KEY_LEN];
        b.copy_from_slice(&raw);
        Ok(Key::from_bytes(b))
    }
}

fn read_len_prefixed(f: &mut File, what: &str) -> Result<Vec<u8>, String> {
    let mut l = [0u8; 2];
    f.read_exact(&mut l).map_err(|e| format!("读 {what} 长度失败: {e}"))?;
    let n = u16::from_be_bytes(l) as usize;
    let mut b = vec![0u8; n];
    f.read_exact(&mut b).map_err(|e| format!("读 {what} 失败: {e}"))?;
    Ok(b)
}

// ————————————————————— 加 / 解 —————————————————————

/// 加密 `src` → `dst`（`SLSNAP1` 容器）。DEK 现场随机生成、被 `kek` 包裹后写进头部，
/// **明文 DEK 不落盘**、函数返回即清零。
pub fn encrypt_file(src: &Path, dst: &Path, kek: &Key, kek_id: &str) -> Result<u64, String> {
    let dek = Key::random();
    let wrapped_dek = seal_blob(kek, &dek.0, b"sandlocker/dek/v1")?;
    let mut inf = File::open(src).map_err(|e| format!("打开明文 {} 失败: {e}", src.display()))?;
    let plain_len = inf.metadata().map_err(|e| format!("取 {} 大小失败: {e}", src.display()))?.len();

    let hdr = Header {
        chunk_size: CHUNK_SIZE,
        plain_len,
        kek_id: kek_id.to_string(),
        wrapped_dek,
        header_len: 0, // encode 用不到
    };
    let head = hdr.encode();
    let mut outf = create_private(dst)?;
    outf.write_all(&head).map_err(|e| format!("写头部失败: {e}"))?;

    let key = dek.aead()?;
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    let mut idx: u64 = 0;
    let mut done: u64 = 0;
    while done < plain_len {
        let want = ((plain_len - done) as usize).min(CHUNK_SIZE as usize);
        inf.read_exact(&mut buf[..want]).map_err(|e| format!("读明文块 {idx} 失败: {e}"))?;
        let mut chunk = buf[..want].to_vec();
        key.seal_in_place_append_tag(nonce_for(idx), Aad::from(hdr.aad(idx)), &mut chunk)
            .map_err(|_| format!("加密块 {idx} 失败"))?;
        outf.write_all(&chunk).map_err(|e| format!("写密文块 {idx} 失败: {e}"))?;
        done += want as u64;
        idx += 1;
    }
    outf.flush().map_err(|e| format!("flush 失败: {e}"))?;
    // fsync：加密完成必须真正落盘，之后才敢抹掉明文（顺序反了会在掉电时两头皆空）。
    outf.sync_all().map_err(|e| format!("fsync {} 失败: {e}", dst.display()))?;
    Ok(plain_len)
}

/// 解密 `src`（`SLSNAP1`）→ `dst`。任一块 AEAD 校验失败即**中止并删除半成品**——
/// 篡改的快照绝不能被 FC 恢复（M3-Q6「篡改即拒」）。
pub fn decrypt_file(src: &Path, dst: &Path, kek: &Key) -> Result<u64, String> {
    let mut inf = File::open(src).map_err(|e| format!("打开密文 {} 失败: {e}", src.display()))?;
    let hdr = Header::read_from(&mut inf)?;
    let dek = hdr.unwrap_dek(kek)?;
    let key = dek.aead()?;

    let mut outf = create_private(dst)?;
    let run = (|| -> Result<(), String> {
        let mut buf = vec![0u8; CHUNK_SIZE as usize + TAG_LEN];
        for idx in 0..hdr.chunks() {
            let n = hdr.chunk_len(idx);
            inf.read_exact(&mut buf[..n]).map_err(|e| format!("读密文块 {idx} 失败: {e}"))?;
            let plain = key
                .open_in_place(nonce_for(idx), Aad::from(hdr.aad(idx)), &mut buf[..n])
                .map_err(|_| format!("块 {idx} AEAD 校验失败——快照已被篡改或密钥不符，拒绝恢复"))?;
            outf.write_all(plain).map_err(|e| format!("写明文块 {idx} 失败: {e}"))?;
        }
        outf.flush().map_err(|e| format!("flush 失败: {e}"))
    })();
    if let Err(e) = run {
        drop(outf);
        // 半解密的文件绝不能留下——FC 若拿它去 load 会得到无声损坏的内存。
        let _ = shred(dst);
        return Err(e);
    }
    Ok(hdr.plain_len)
}

/// **随机读**：只解一块，不碰其余部分（ADR-15 分块 AEAD 的意义所在，将来接 userfaultfd 懒加载）。
pub fn decrypt_chunk(src: &Path, kek: &Key, idx: u64) -> Result<Vec<u8>, String> {
    let mut f = File::open(src).map_err(|e| format!("打开密文 {} 失败: {e}", src.display()))?;
    let hdr = Header::read_from(&mut f)?;
    if idx >= hdr.chunks() {
        return Err(format!("块序号 {idx} 越界（共 {} 块）", hdr.chunks()));
    }
    let dek = hdr.unwrap_dek(kek)?;
    let n = hdr.chunk_len(idx);
    f.seek(SeekFrom::Start(hdr.chunk_offset(idx))).map_err(|e| format!("seek 块 {idx} 失败: {e}"))?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf).map_err(|e| format!("读块 {idx} 失败: {e}"))?;
    let plain = dek
        .aead()?
        .open_in_place(nonce_for(idx), Aad::from(hdr.aad(idx)), &mut buf)
        .map_err(|_| format!("块 {idx} AEAD 校验失败——快照已被篡改或密钥不符"))?;
    Ok(plain.to_vec())
}

/// 块 nonce：`0u32 || be64(idx)`。DEK 每快照随机 → (DEK, nonce) 全局唯一。
fn nonce_for(idx: u64) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&idx.to_be_bytes());
    Nonce::assume_unique_for_key(n)
}

/// 建 0600 新文件（快照密文/解出的明文都不该让同机其他用户读到）。
fn create_private(p: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(p)
        .map_err(|e| format!("建 {} 失败: {e}", p.display()))
}

/// 抹掉明文快照：先用零覆写再 unlink。
///
/// 诚实说明：在 CoW / 日志式文件系统（btrfs、ext4 data=journal）与 SSD FTL 之下，覆写**不保证**
/// 原物理块被真正擦除。这一步是纵深防御，真正的保证来自「明文从一开始就只在加密前后短暂存在」。
pub fn shred(p: &Path) -> Result<(), String> {
    if let Ok(md) = std::fs::metadata(p) {
        if md.is_file() {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(p) {
                let zero = vec![0u8; 1024 * 1024];
                let mut left = md.len();
                while left > 0 {
                    let n = (left as usize).min(zero.len());
                    if f.write_all(&zero[..n]).is_err() {
                        break;
                    }
                    left -= n as u64;
                }
                let _ = f.sync_all();
            }
        }
    }
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("删除 {} 失败: {e}", p.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("slsnapcrypt-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_file(&d);
        d
    }

    fn write(p: &Path, bytes: &[u8]) {
        let mut f = File::create(p).unwrap();
        f.write_all(bytes).unwrap();
    }

    /// 往返：加密→解密与原文逐字节相同。跨块（> 1 块）与空文件都要成立。
    #[test]
    fn roundtrip_across_chunk_boundaries() {
        let kek = Key::random();
        for len in [0usize, 1, 4095, CHUNK_SIZE as usize, CHUNK_SIZE as usize + 1, CHUNK_SIZE as usize * 2 + 7] {
            let src = tmp(&format!("src{len}"));
            let enc = tmp(&format!("enc{len}"));
            let dec = tmp(&format!("dec{len}"));
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            write(&src, &data);
            let n = encrypt_file(&src, &enc, &kek, "proj-a").unwrap();
            assert_eq!(n, len as u64);
            let m = decrypt_file(&enc, &dec, &kek).unwrap();
            assert_eq!(m, len as u64);
            assert_eq!(std::fs::read(&dec).unwrap(), data, "len={len} 往返不一致");
            for p in [&src, &enc, &dec] {
                let _ = std::fs::remove_file(p);
            }
        }
    }

    /// 密文里不得出现明文片段（最起码的「确实加密了」）。
    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let kek = Key::random();
        let (src, enc) = (tmp("leak-src"), tmp("leak-enc"));
        let needle = b"TOP-SECRET-GUEST-MEMORY-abcdef";
        let mut data = vec![0u8; 100_000];
        data[50_000..50_000 + needle.len()].copy_from_slice(needle);
        write(&src, &data);
        encrypt_file(&src, &enc, &kek, "p").unwrap();
        let ct = std::fs::read(&enc).unwrap();
        assert!(
            !ct.windows(needle.len()).any(|w| w == needle),
            "密文中出现了明文片段"
        );
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&enc);
    }

    /// 篡改任意一个密文字节 → 拒绝恢复，且**不留下半成品明文**。
    #[test]
    fn tampered_ciphertext_is_refused_and_leaves_no_partial_plaintext() {
        let kek = Key::random();
        let (src, enc, dec) = (tmp("t-src"), tmp("t-enc"), tmp("t-dec"));
        write(&src, &vec![7u8; CHUNK_SIZE as usize + 1234]); // 两块
        encrypt_file(&src, &enc, &kek, "p").unwrap();
        let mut ct = std::fs::read(&enc).unwrap();
        let last = ct.len() - 5;
        ct[last] ^= 0xff;
        std::fs::write(&enc, &ct).unwrap();
        let err = decrypt_file(&enc, &dec, &kek).unwrap_err();
        assert!(err.contains("AEAD 校验失败"), "错误信息应指明 AEAD 失败: {err}");
        assert!(!dec.exists(), "篡改用例不得留下半解密的明文文件");
        for p in [&src, &enc] {
            let _ = std::fs::remove_file(p);
        }
    }

    /// 篡改**头部**（明文字段）同样被拒——头部字段全绑进每块 AAD。
    #[test]
    fn tampered_header_is_refused() {
        let kek = Key::random();
        let (src, enc, dec) = (tmp("h-src"), tmp("h-enc"), tmp("h-dec"));
        write(&src, &vec![3u8; 10_000]);
        encrypt_file(&src, &enc, &kek, "proj-a").unwrap();
        let mut ct = std::fs::read(&enc).unwrap();
        ct[23] ^= 0x01; // plain_len 末字节
        std::fs::write(&enc, &ct).unwrap();
        assert!(decrypt_file(&enc, &dec, &kek).is_err(), "改头部 plain_len 应被拒");
        for p in [&src, &enc, &dec] {
            let _ = std::fs::remove_file(p);
        }
    }

    /// 换一把 KEK 解不开（DEK 是被 KEK 包裹的）。
    #[test]
    fn wrong_kek_cannot_open() {
        let (k1, k2) = (Key::random(), Key::random());
        let (src, enc, dec) = (tmp("k-src"), tmp("k-enc"), tmp("k-dec"));
        write(&src, b"hello");
        encrypt_file(&src, &enc, &k1, "p").unwrap();
        assert!(decrypt_file(&enc, &dec, &k2).is_err(), "错误的 KEK 不应能解开");
        for p in [&src, &enc, &dec] {
            let _ = std::fs::remove_file(p);
        }
    }

    /// **随机读**：只解第 i 块，结果与整解后的对应切片一致（懒加载能力的实证）。
    #[test]
    fn random_access_chunk_matches_full_decrypt() {
        let kek = Key::random();
        let (src, enc) = (tmp("r-src"), tmp("r-enc"));
        let len = CHUNK_SIZE as usize * 2 + 999;
        let data: Vec<u8> = (0..len).map(|i| (i % 97) as u8).collect();
        write(&src, &data);
        encrypt_file(&src, &enc, &kek, "p").unwrap();
        for idx in [0u64, 1, 2] {
            let got = decrypt_chunk(&enc, &kek, idx).unwrap();
            let start = idx as usize * CHUNK_SIZE as usize;
            let end = (start + CHUNK_SIZE as usize).min(len);
            assert_eq!(got, &data[start..end], "块 {idx} 随机读不一致");
        }
        assert!(decrypt_chunk(&enc, &kek, 3).is_err(), "越界块应报错");
        for p in [&src, &enc] {
            let _ = std::fs::remove_file(p);
        }
    }

    /// 两次加密同一明文 → 密文不同（DEK 每快照随机，不是确定性加密）。
    #[test]
    fn each_snapshot_gets_a_fresh_dek() {
        let kek = Key::random();
        let (src, e1, e2) = (tmp("d-src"), tmp("d-e1"), tmp("d-e2"));
        write(&src, &vec![1u8; 8192]);
        encrypt_file(&src, &e1, &kek, "p").unwrap();
        encrypt_file(&src, &e2, &kek, "p").unwrap();
        assert_ne!(std::fs::read(&e1).unwrap(), std::fs::read(&e2).unwrap());
        for p in [&src, &e1, &e2] {
            let _ = std::fs::remove_file(p);
        }
    }

    /// KEK 经根密钥包裹/解裹往返；换根密钥解不开。
    #[test]
    fn kek_wrap_roundtrip_and_wrong_root_fails() {
        let root_a = Key::random();
        let root_b = Key::random();
        let kek = Key::random();
        let want = kek.0;
        let wrapped = seal_blob(&root_a, &kek.0, b"sandlocker/kek/v1").unwrap();
        assert!(!wrapped.windows(KEY_LEN).any(|w| w == want), "包裹结果中出现了明文 KEK");
        let got = open_blob(&root_a, &wrapped, b"sandlocker/kek/v1").unwrap();
        assert_eq!(got, want.to_vec());
        assert!(open_blob(&root_b, &wrapped, b"sandlocker/kek/v1").is_err());
    }

    /// 头部里存的是**被包裹的** DEK，明文 DEK 不得出现在文件里（M3-Q6：节点不持久化明文 DEK）。
    #[test]
    fn plaintext_dek_never_hits_disk() {
        let kek = Key::random();
        let (src, enc) = (tmp("p-src"), tmp("p-enc"));
        write(&src, b"x");
        encrypt_file(&src, &enc, &kek, "p").unwrap();
        let mut f = File::open(&enc).unwrap();
        let hdr = Header::read_from(&mut f).unwrap();
        let dek = hdr.unwrap_dek(&kek).unwrap();
        let bytes = std::fs::read(&enc).unwrap();
        assert!(
            !bytes.windows(KEY_LEN).any(|w| w == dek.0),
            "快照文件里出现了明文 DEK"
        );
        for p in [&src, &enc] {
            let _ = std::fs::remove_file(p);
        }
    }
}
