//! Access keys (let a tool such as Claude Code pass secrets to commands without the identity check)
//! and the audit log of every access that skipped it.
//!
//! A tool presents its key in KEYLO_ACCESS_KEY; Keylo stores only its SHA-256 hash. Keys are
//! run-only: they let a tool pass secrets to commands, never read values.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use base64::Engine;
use chrono::{DateTime, Duration, FixedOffset, Local};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::KeyloConfig;
use crate::secrets::SecretInfo;
use crate::{eq_ic, paths, platform, Result};

pub const ENVIRONMENT_VARIABLE: &str = "KEYLO_ACCESS_KEY";
const TOKEN_PREFIX: &str = "kyl_";

/// What a caller is doing with secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretOperation {
    /// Listing or searching names and details (never values).
    Browse,
    /// Handing values to a child process as environment variables.
    Run,
    /// Printing, copying or exporting a value.
    Get,
}

impl SecretOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretOperation::Browse => "browse",
            SecretOperation::Run => "run",
            SecretOperation::Get => "get",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum KeyScope {
    /// Its categories and secrets (none of either: nothing).
    #[default]
    Selected,
    /// Every secret.
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessKey {
    /// Short public id (not secret).
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// Lowercase hex SHA-256 of the full key.
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub scope: KeyScope,
    #[serde(default)]
    pub categories: Vec<String>,
    /// Individual secrets, mostly added by "Always allow" in an approval.
    #[serde(default)]
    pub secrets: Vec<String>,
    pub created: DateTime<FixedOffset>,
    #[serde(default)]
    pub expires: Option<DateTime<FixedOffset>>,
}

impl AccessKey {
    pub fn is_expired(&self, now: DateTime<FixedOffset>) -> bool {
        self.expires.is_some_and(|e| e <= now)
    }

    pub fn covers(&self, secret: &SecretInfo) -> bool {
        self.scope == KeyScope::All
            || self.secrets.iter().any(|s| eq_ic(s, &secret.name))
            || secret.category.as_ref().is_some_and(|c| self.categories.iter().any(|k| eq_ic(k, c)))
    }

    /// Whether this key alone allows `op` on every one of `secrets`. Browsing is always allowed;
    /// reading values never is (that always needs the user).
    pub fn allows(&self, op: SecretOperation, secrets: &[SecretInfo]) -> bool {
        match op {
            SecretOperation::Browse => true,
            SecretOperation::Get => false,
            SecretOperation::Run => !secrets.is_empty() && secrets.iter().all(|s| self.covers(s)),
        }
    }
}

fn now() -> DateTime<FixedOffset> {
    Local::now().fixed_offset()
}

/// Creates a key; the returned token is shown once and never stored.
pub fn create(name: &str, expires_days: Option<i64>) -> (AccessKey, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = format!("{TOKEN_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes));
    let mut id = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut id);
    let created = now();
    let key = AccessKey {
        id: hex::encode(id),
        name: name.trim().to_string(),
        hash: hash_of(&token),
        scope: KeyScope::Selected,
        categories: vec![],
        secrets: vec![],
        created,
        expires: expires_days.map(|d| created + Duration::days(d)),
    };
    (key, token)
}

/// The unexpired key matching `token`.
pub fn find<'a>(config: &'a KeyloConfig, token: Option<&str>) -> Option<&'a AccessKey> {
    let token = token?.trim();
    if !token.starts_with(TOKEN_PREFIX) {
        return None;
    }
    let hash = hash_of(token);
    let now = now();
    config
        .access_keys
        .iter()
        .find(|k| !k.is_expired(now) && constant_time_eq(k.hash.as_bytes(), hash.as_bytes()))
}

/// The key this process was given through KEYLO_ACCESS_KEY, if valid.
pub fn from_environment(config: &KeyloConfig) -> Option<&AccessKey> {
    find(config, std::env::var(ENVIRONMENT_VARIABLE).ok().as_deref())
}

/// Whether this process was given a key at all (valid or not), for clearer errors.
pub fn is_present_in_environment() -> bool {
    std::env::var(ENVIRONMENT_VARIABLE).is_ok_and(|v| !v.trim().is_empty())
}

/// Adds secrets to a key's scope, e.g. after "Always allow" in an approval.
pub fn grant(config: &mut KeyloConfig, key_id: &str, secrets: &[String]) -> bool {
    let Some(key) = config.access_keys.iter_mut().find(|k| k.id == key_id) else { return false };
    for s in secrets {
        if !key.secrets.iter().any(|k| eq_ic(k, s)) {
            key.secrets.push(s.clone());
        }
    }
    true
}

pub fn hash_of(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------- audit log

pub fn audit_path_in(dir: &Path) -> PathBuf {
    dir.join("audit.log")
}

#[derive(Serialize)]
struct AuditEntry<'a> {
    time: String,
    operation: &'a str,
    secrets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
    #[serde(rename = "keyId", skip_serializing_if = "Option::is_none")]
    key_id: Option<&'a str>,
    via: &'a str,
    chain: Vec<String>,
}

/// Appends one line to audit.log (one JSON object per line) and prunes old entries.
/// `via`: the access key's name, or "approved" for a one-off approval.
pub fn audit(operation: &str, secrets: &[String], key: Option<&AccessKey>, via: &str) -> Result<()> {
    let dir = paths::data_dir();
    fs::create_dir_all(&dir)?;
    let chain = if platform::is_installed() {
        platform::current()
            .processes()
            .current(12)
            .into_iter()
            .take(6)
            .map(|p| format!("{}({})", p.executable_name, p.process_id))
            .collect()
    } else {
        vec![]
    };
    let entry = AuditEntry {
        time: now().to_rfc3339(),
        operation,
        secrets: secrets.to_vec(),
        key: key.map(|k| k.name.as_str()),
        key_id: key.map(|k| k.id.as_str()),
        via,
        chain,
    };
    let path = audit_path_in(&dir);

    // The CLI, the app and MCP servers can all write at once; a prune must not drop an append.
    let lock = OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("audit.lock"))?;
    lock.lock()?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{}", serde_json::to_string(&entry).unwrap())?;
    drop(file);
    let days = KeyloConfig::load_from(&dir).map(|c| c.audit_retention_days).unwrap_or(90);
    let result = prune(&path, days, now());
    let _ = lock.unlock();
    result.map(|_| ())
}

/// Drops entries older than `days` (0: keep all). Only rewrites the file when its first entry has
/// expired. Unreadable lines are kept.
pub fn prune(path: &Path, days: i64, now: DateTime<FixedOffset>) -> Result<usize> {
    if days <= 0 || !path.exists() {
        return Ok(0);
    }
    let cutoff = now - Duration::days(days);
    let first = BufReader::new(fs::File::open(path)?).lines().next().transpose()?;
    match first.as_deref().and_then(time_of) {
        Some(t) if t < cutoff => {}
        _ => return Ok(0),
    }
    let text = fs::read_to_string(path)?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    let kept: Vec<&str> = lines.iter().copied().filter(|l| time_of(l).is_none_or(|t| t >= cutoff)).collect();
    let temp = path.with_extension("log.tmp");
    let mut body = kept.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    fs::write(&temp, body)?;
    fs::rename(&temp, path)?;
    Ok(lines.len() - kept.len())
}

pub fn time_of(line: &str) -> Option<DateTime<FixedOffset>> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    DateTime::parse_from_rfc3339(v.get("time")?.as_str()?).ok()
}
