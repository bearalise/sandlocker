//! auth.rs — 多租户 API Key 鉴权（M3 W6，FR-7.1）。
//!
//! 模型：组织(org) → 项目(project) → Key，**作用域**三档：只读 / 读写 / 构建（build ⊇ readwrite ⊇ readonly）。
//! 后端无关（`Store` trait）：单机 SQLite / 集群 etcd 同一套。
//!
//! 安全：token 明文**仅创建时返回一次**；store 只存 `apikey/<sha256hex(token)>` → 记录
//! （org/project/scope），泄露 store 不泄露可用 token。鉴权时对呈递 token 取 sha256 查记录。
//!
//! 项目隔离：创建的沙箱打归属键 `sandbox/<id>/project`；跨项目访问被拒（见 api.rs dispatch 门）。

use sha2::{Digest, Sha256};
use sl_store::Store;

use crate::{hex, host_random};

/// 请求所需的操作类别（路由 → Op，见 api.rs `Route::required_op`）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Read,
    Write,
    Build,
}

/// API Key 作用域（读写/只读/构建）。层级：Build ⊇ ReadWrite ⊇ ReadOnly。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    ReadOnly,
    ReadWrite,
    Build,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::ReadOnly => "readonly",
            Scope::ReadWrite => "readwrite",
            Scope::Build => "build",
        }
    }
    pub fn from_str(s: &str) -> Option<Scope> {
        match s {
            "readonly" => Some(Scope::ReadOnly),
            "readwrite" => Some(Scope::ReadWrite),
            "build" => Some(Scope::Build),
            _ => None,
        }
    }
    fn rank(self) -> u8 {
        match self {
            Scope::ReadOnly => 0,
            Scope::ReadWrite => 1,
            Scope::Build => 2,
        }
    }
    /// 本作用域是否允许某操作类别。
    pub fn allows(self, op: Op) -> bool {
        match op {
            Op::Read => true,                    // 任何有效 key 可读
            Op::Write => self.rank() >= 1,       // readwrite / build
            Op::Build => self == Scope::Build,   // 仅 build
        }
    }
}

/// 一个 API Key 记录（不含 token 本身）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyRecord {
    pub org: String,
    pub project: String,
    pub scope: Scope,
}

/// token → store 键（存 sha256，不存明文）。
fn key_store_key(token: &str) -> String {
    format!("apikey/{}", hex(&Sha256::digest(token.as_bytes())))
}

/// 记录编码（`\x1f` 分隔，避免引 JSON；org/project 不含该控制字符）。
fn encode(rec: &ApiKeyRecord) -> String {
    format!("{}\x1f{}\x1f{}", rec.org, rec.project, rec.scope.as_str())
}
fn decode(v: &[u8]) -> Option<ApiKeyRecord> {
    let s = String::from_utf8_lossy(v);
    let p: Vec<&str> = s.split('\x1f').collect();
    if p.len() != 3 {
        return None;
    }
    Scope::from_str(p[2]).map(|scope| ApiKeyRecord { org: p[0].to_string(), project: p[1].to_string(), scope })
}

/// 创建一个 API Key：生成随机 token，store 存 sha256→记录，返回 token（明文仅此一次）。
pub fn create_key(store: &dyn Store, org: &str, project: &str, scope: Scope) -> Result<String, String> {
    let mut tb = [0u8; 32];
    host_random(&mut tb);
    let token = hex(&tb);
    let rec = ApiKeyRecord { org: org.to_string(), project: project.to_string(), scope };
    store
        .put(&key_store_key(&token), encode(&rec).as_bytes(), None)
        .map_err(|e| e.to_string())?;
    Ok(token)
}

/// 按 token 查记录（None = 无此 key）。
pub fn lookup(store: &dyn Store, token: &str) -> Result<Option<ApiKeyRecord>, String> {
    let kv = store.get(&key_store_key(token)).map_err(|e| e.to_string())?;
    Ok(kv.and_then(|kv| decode(&kv.value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sl_store::SqliteStore;

    #[test]
    fn scope_hierarchy() {
        assert!(Scope::ReadOnly.allows(Op::Read) && !Scope::ReadOnly.allows(Op::Write));
        assert!(Scope::ReadWrite.allows(Op::Write) && !Scope::ReadWrite.allows(Op::Build));
        assert!(Scope::Build.allows(Op::Build) && Scope::Build.allows(Op::Write) && Scope::Build.allows(Op::Read));
    }

    #[test]
    fn create_lookup_roundtrip_and_unknown() {
        let s = SqliteStore::open_in_memory().unwrap();
        let tok = create_key(&s, "acme", "proj1", Scope::ReadWrite).unwrap();
        let rec = lookup(&s, &tok).unwrap().expect("应查到");
        assert_eq!(rec, ApiKeyRecord { org: "acme".into(), project: "proj1".into(), scope: Scope::ReadWrite });
        assert!(lookup(&s, "deadbeef-unknown").unwrap().is_none(), "未知 token 应无记录");
        // store 只存 hash：不含明文 token
        let kvs = s.list("apikey/").unwrap();
        assert_eq!(kvs.len(), 1);
        assert!(!kvs[0].key.contains(&tok), "store 键不应含明文 token");
    }
}
