//! Keylo's vault: one SQLite database (keylo.db in Keylo's data folder).
//!
//! - **Values** are sealed one by one with AES-256-GCM, bound to their row's id, and decrypted only
//!   when one is read (`read`); listing, searching and changing details never decrypt them.
//! - **Details** (name, category, type, username, website and other non-secret fields, notes) are
//!   stored readable, as Credential Manager and the Keychain stored them, so they can be listed and
//!   searched without a key. Each row carries an HMAC over its details and its sealed value, so a
//!   change made outside Keylo is detected when the row is read.
//! - **An integrity record** (meta `state`): an HMAC over a monotonic counter, the schema, the
//!   key's protection and every row's id and HMAC. It's checked before every read, list and change
//!   and re-signed after each change, so rows deleted, added, altered or put back from an older copy
//!   are refused — and the record itself can't be removed or reset without the key.
//! - **The vault key** is random (32 bytes) and kept by the OS through an [`OsKey`] (DPAPI on
//!   Windows). The value and HMAC keys are derived from it with HKDF-SHA256.
//!
//! Every change is one SQLite transaction (WAL, synchronous=FULL): durable when it returns, and
//! serialized between the app, the CLI and the MCP server by SQLite's own locking.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use keylo_core::platform::{CredentialDetails, CredentialStore, RawCredential};
use keylo_core::{bail, Error, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{open, random_key, seal};

/// The schema this build writes. Schema 1 (Keylo 2.0, a weaker manifest) is read and upgraded; a
/// newer schema is refused rather than rewritten.
const SCHEMA: i64 = 2;
const VALUE_AAD: &str = "keylo:vault:value:v1:";

/// Keeps the vault key safe with the operating system, so the vault opens for this user only.
pub trait OsKey: Send + Sync {
    /// How the key is protected, recorded in the vault: "dpapi", "keychain"…
    fn kind(&self) -> &'static str;
    /// Protects a new vault key; the result is stored in the vault.
    fn protect(&self, key: &[u8]) -> Result<Vec<u8>>;
    /// The vault key from what [`OsKey::protect`] returned.
    fn unprotect(&self, stored: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

struct Opened {
    conn: Connection,
    value_key: Zeroizing<Vec<u8>>,
    mac_key: Zeroizing<Vec<u8>>,
}

pub struct SqliteVault {
    path: PathBuf,
    os_key: Box<dyn OsKey>,
    /// Opened on first use; a failure isn't remembered, so the next call tries again.
    opened: Mutex<Option<Opened>>,
}

fn db_err(e: rusqlite::Error) -> Error {
    Error::msg(format!("Keylo's vault: {e}"))
}

/// One row, as stored.
struct Row {
    id: String,
    target: String,
    user_name: Option<String>,
    comment: Option<String>,
    last_written: String,
    attributes: String,
    summary: Vec<u8>,
    value: Vec<u8>,
    mac: Vec<u8>,
}

const COLUMNS: &str = "id, target, user_name, comment, last_written, attributes, summary, value, mac";

fn row(r: &rusqlite::Row) -> rusqlite::Result<Row> {
    Ok(Row {
        id: r.get(0)?,
        target: r.get(1)?,
        user_name: r.get(2)?,
        comment: r.get(3)?,
        last_written: r.get(4)?,
        attributes: r.get(5)?,
        summary: r.get(6)?,
        value: r.get(7)?,
        mac: r.get(8)?,
    })
}

impl SqliteVault {
    pub fn new(path: PathBuf, os_key: Box<dyn OsKey>) -> Self {
        SqliteVault { path, os_key, opened: Mutex::new(None) }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Opened) -> Result<T>) -> Result<T> {
        let mut guard = self.opened.lock().unwrap();
        if guard.is_none() {
            *guard = Some(self.open()?);
        }
        f(guard.as_mut().unwrap())
    }

    fn open(&self) -> Result<Opened> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // CREATE only makes a missing file; an existing one that can't be opened is an error, never
        // replaced.
        let mut conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| Error::msg(format!("Couldn't open Keylo's vault ({}): {e}", self.path.display())))?;
        conn.busy_timeout(Duration::from_secs(30)).map_err(db_err)?;
        conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true).map_err(db_err)?;
        conn.pragma_update(None, "trusted_schema", "OFF").map_err(db_err)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(db_err)?;
        conn.pragma_update(None, "synchronous", "FULL").map_err(db_err)?;

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_err)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS items (
                 id TEXT PRIMARY KEY,
                 target TEXT NOT NULL UNIQUE COLLATE NOCASE,
                 user_name TEXT,
                 comment TEXT,
                 last_written TEXT NOT NULL,
                 attributes TEXT NOT NULL,
                 summary BLOB NOT NULL,
                 value BLOB NOT NULL,
                 mac BLOB NOT NULL
             );",
        )
        .map_err(db_err)?;
        let meta = |key: &str| -> Result<Option<Vec<u8>>> {
            tx.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional().map_err(db_err)
        };

        let schema = meta("schema")?.map(|v| String::from_utf8_lossy(&v).parse::<i64>().unwrap_or(i64::MAX));
        if let Some(s) = schema {
            if s > SCHEMA {
                bail!("Keylo's vault ({}) was written by a newer Keylo. Update Keylo to open it.", self.path.display());
            }
        }

        let vault_key = match (meta("protection")?, meta("key")?) {
            (Some(protection), Some(stored)) => {
                let protection = String::from_utf8_lossy(&protection).to_string();
                if protection != self.os_key.kind() {
                    bail!("Keylo's vault ({}) is protected by {protection}, not {}; it can't be opened here.", self.path.display(), self.os_key.kind());
                }
                let key = self.os_key.unprotect(&stored).map_err(|e| Error::msg(format!("Couldn't open Keylo's vault: {e}")))?;
                if key.len() != 32 {
                    bail!("Keylo's vault ({}) is damaged: its key isn't valid.", self.path.display());
                }
                key
            }
            (None, None) => {
                // A new vault: nothing in it yet, so nothing can be lost by making its key.
                let count: i64 = tx.query_row("SELECT count(*) FROM items", [], |r| r.get(0)).map_err(db_err)?;
                if count > 0 {
                    bail!("Keylo's vault ({}) is damaged: it has secrets but no key.", self.path.display());
                }
                let key = random_key();
                tx.execute("INSERT INTO meta (key, value) VALUES ('schema', ?1)", [SCHEMA.to_string().into_bytes()]).map_err(db_err)?;
                tx.execute("INSERT INTO meta (key, value) VALUES ('protection', ?1)", [self.os_key.kind().as_bytes().to_vec()]).map_err(db_err)?;
                tx.execute("INSERT INTO meta (key, value) VALUES ('key', ?1)", [self.os_key.protect(&key)?]).map_err(db_err)?;
                key
            }
            _ => bail!("Keylo's vault ({}) is damaged: its key is incomplete.", self.path.display()),
        };
        let derive = |info: &[u8]| -> Result<Zeroizing<Vec<u8>>> {
            let mut k = Zeroizing::new(vec![0u8; 32]);
            Hkdf::<Sha256>::new(None, &vault_key).expand(info, &mut k).map_err(|_| Error::msg("HKDF failed."))?;
            Ok(k)
        };
        let opened_keys = (derive(b"keylo:vault:value-key:v1")?, derive(b"keylo:vault:mac-key:v1")?);
        let mac_key = &opened_keys.1;
        let rows: i64 = tx.query_row("SELECT count(*) FROM items", [], |r| r.get(0)).map_err(db_err)?;
        match meta("state")? {
            // Already on the authenticated-state scheme: it must verify.
            Some(stored) => {
                if !constant_eq(&stored, &state_mac(&tx, mac_key)?) {
                    bail!("Keylo's vault ({}) was changed outside Keylo, so it isn't trusted.", self.path.display());
                }
            }
            None => match meta("manifest")? {
                // A Keylo 2.0 vault (the weaker manifest): verify it, then upgrade to the state record.
                Some(m) => {
                    if !constant_eq(&m, &legacy_manifest(&tx, mac_key)?) {
                        bail!("Keylo's vault ({}) was changed outside Keylo, so it isn't trusted.", self.path.display());
                    }
                    tx.execute("DELETE FROM meta WHERE key = 'manifest'", []).map_err(db_err)?;
                    tx.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema', ?1)", [SCHEMA.to_string().into_bytes()]).map_err(db_err)?;
                    sign_state(&tx, mac_key)?;
                }
                // No integrity record at all. Only a brand-new, empty vault is allowed to make one;
                // rows without a record mean it was removed outside Keylo to hide other changes.
                None => {
                    if rows > 0 {
                        bail!("Keylo's vault ({}) has no integrity record; it may have been changed outside Keylo.", self.path.display());
                    }
                    sign_state(&tx, mac_key)?;
                }
            },
        }
        tx.commit().map_err(db_err)?;
        Ok(Opened { conn, value_key: opened_keys.0, mac_key: opened_keys.1 })
    }

    /// Adds `credentials` with their original times, keeping a vault item that's newer. Returns how
    /// many it wrote. One transaction: all or nothing. For moving another store's items in.
    pub fn import(&self, credentials: &[RawCredential]) -> Result<usize> {
        self.with(|o| {
            let tx = o.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_err)?;
            check_state(&tx, &o.mac_key)?;
            let mut written = 0;
            for c in credentials {
                let existing: Option<String> = tx
                    .query_row("SELECT last_written FROM items WHERE target = ?1", [&c.target], |r| r.get(0))
                    .optional()
                    .map_err(db_err)?;
                let newer = existing.is_none_or(|t| parse_time(&t).is_none_or(|t| t < c.last_written));
                if newer {
                    put(&tx, &o.value_key, &o.mac_key, &c.target, &c.blob, c.user_name.as_deref(), c.comment.as_deref(), &c.attributes, c.last_written)?;
                    written += 1;
                }
            }
            sign_state(&tx, &o.mac_key)?;
            tx.commit().map_err(db_err)?;
            Ok(written)
        })
    }
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|t| t.with_timezone(&Utc))
}

fn clean(attributes: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    attributes.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// The HMAC over a row's details and its sealed value (length-prefixed, so fields can't run together).
fn mac_of(mac_key: &[u8], id: &str, target: &str, user: Option<&str>, comment: Option<&str>, when: &str, attributes: &str, summary: &[u8], value: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC takes any key length");
    let mut field = |b: &[u8]| {
        m.update(&(b.len() as u64).to_le_bytes());
        m.update(b);
    };
    field(b"keylo:vault:row:v1");
    field(id.as_bytes());
    field(target.as_bytes());
    field(user.map(str::as_bytes).unwrap_or(b"\0none"));
    field(comment.map(str::as_bytes).unwrap_or(b"\0none"));
    field(when.as_bytes());
    field(attributes.as_bytes());
    field(summary);
    field(&Sha256::digest(value));
    m.finalize().into_bytes().to_vec()
}

fn verify(mac_key: &[u8], r: &Row) -> Result<()> {
    let expected = mac_of(mac_key, &r.id, &r.target, r.user_name.as_deref(), r.comment.as_deref(), &r.last_written, &r.attributes, &r.summary, &r.value);
    if !constant_eq(&expected, &r.mac) {
        bail!("Keylo's vault: '{}' was changed outside Keylo, so it isn't trusted.", r.target);
    }
    Ok(())
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn meta_value(conn: &Connection, key: &str) -> Result<Vec<u8>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get::<_, Vec<u8>>(0))
        .optional()
        .map_err(db_err)?
        .unwrap_or_default())
}

/// The integrity record: an HMAC over a monotonic counter, the schema, the key's protection and
/// every row's id and HMAC (in id order). The counter lets a spliced-in older row be told from the
/// current one; binding schema and protection stops them being downgraded unnoticed.
fn state_mac(conn: &Connection, mac_key: &[u8]) -> Result<Vec<u8>> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC takes any key length");
    let mut field = |b: &[u8]| {
        m.update(&(b.len() as u64).to_le_bytes());
        m.update(b);
    };
    field(b"keylo:vault:state:v2");
    field(&meta_value(conn, "seq")?);
    field(&meta_value(conn, "schema")?);
    field(&meta_value(conn, "protection")?);
    let mut stmt = conn.prepare("SELECT id, mac FROM items ORDER BY id").map_err(db_err)?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))).map_err(db_err)?;
    for r in rows {
        let (id, mac) = r.map_err(db_err)?;
        field(id.as_bytes());
        field(&mac);
    }
    Ok(m.finalize().into_bytes().to_vec())
}

/// Bumps the counter and writes a fresh integrity record. Run at the end of every change.
fn sign_state(conn: &Connection, mac_key: &[u8]) -> Result<()> {
    let seq: i64 = String::from_utf8_lossy(&meta_value(conn, "seq")?).parse().unwrap_or(0) + 1;
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('seq', ?1)", [seq.to_string().into_bytes()]).map_err(db_err)?;
    let state = state_mac(conn, mac_key)?;
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('state', ?1)", [state]).map_err(db_err)?;
    Ok(())
}

/// Refuses the vault unless its integrity record matches the current contents. Run before every
/// read and at the start of every change, so tampering is caught everywhere, not only when listing,
/// and a later change can't bless it.
fn check_state(conn: &Connection, mac_key: &[u8]) -> Result<()> {
    let stored: Option<Vec<u8>> = conn.query_row("SELECT value FROM meta WHERE key = 'state'", [], |r| r.get(0)).optional().map_err(db_err)?;
    let expected = state_mac(conn, mac_key)?;
    if !stored.is_some_and(|s| constant_eq(&s, &expected)) {
        bail!("Keylo's vault: it was changed outside Keylo (secrets added, removed, altered or restored), so it isn't trusted.");
    }
    Ok(())
}

/// Keylo 2.0's record, kept only to verify a 2.0 vault before upgrading it.
fn legacy_manifest(conn: &Connection, mac_key: &[u8]) -> Result<Vec<u8>> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC takes any key length");
    m.update(b"keylo:vault:manifest:v1");
    let mut stmt = conn.prepare("SELECT id, mac FROM items ORDER BY id").map_err(db_err)?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))).map_err(db_err)?;
    for r in rows {
        let (id, mac) = r.map_err(db_err)?;
        m.update(&(id.len() as u64).to_le_bytes());
        m.update(id.as_bytes());
        m.update(&mac);
    }
    Ok(m.finalize().into_bytes().to_vec())
}

/// Replaces (or adds) the item named `target` (case-insensitively) with a new row.
#[allow(clippy::too_many_arguments)]
fn put(
    conn: &Connection,
    value_key: &[u8],
    mac_key: &[u8],
    target: &str,
    blob: &[u8],
    user: Option<&str>,
    comment: Option<&str>,
    attributes: &BTreeMap<String, String>,
    when: DateTime<Utc>,
) -> Result<()> {
    let id = uuid_v4();
    let when = when.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let attributes = serde_json::to_string(&clean(attributes)).map_err(|e| Error::msg(e.to_string()))?;
    let summary = keylo_core::store::summarize(blob);
    let value = seal(value_key, blob, format!("{VALUE_AAD}{id}").as_bytes())?;
    let mac = mac_of(mac_key, &id, target, user, comment, &when, &attributes, &summary, &value);
    conn.execute("DELETE FROM items WHERE target = ?1", [target]).map_err(db_err)?;
    conn.execute(
        &format!("INSERT INTO items ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"),
        params![id, target, user, comment, when, attributes, summary, value, mac],
    )
    .map_err(db_err)?;
    Ok(())
}

fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn details_of(r: &Row) -> Result<CredentialDetails> {
    Ok(CredentialDetails {
        target: r.target.clone(),
        user_name: r.user_name.clone(),
        comment: r.comment.clone(),
        last_written: parse_time(&r.last_written).unwrap_or_default(),
        attributes: serde_json::from_str(&r.attributes).map_err(|_| Error::msg(format!("Keylo's vault: '{}' has unreadable details.", r.target)))?,
        summary: r.summary.clone(),
    })
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

impl CredentialStore for SqliteVault {
    fn max_blob_bytes(&self) -> usize {
        64 * 1024
    }
    fn max_attribute_bytes(&self) -> usize {
        1024
    }
    fn max_attributes(&self) -> usize {
        64
    }

    fn read(&self, target: &str) -> Result<Option<RawCredential>> {
        self.with(|o| {
            let r = o
                .conn
                .query_row(&format!("SELECT {COLUMNS} FROM items WHERE target = ?1"), [target], row)
                .optional()
                .map_err(db_err)?;
            check_state(&o.conn, &o.mac_key)?;
            let Some(r) = r else { return Ok(None) };
            verify(&o.mac_key, &r)?;
            let d = details_of(&r)?;
            let blob = open(&o.value_key, &r.value, format!("{VALUE_AAD}{}", r.id).as_bytes())
                .ok_or_else(|| Error::msg(format!("Keylo's vault: '{}' couldn't be decrypted.", r.target)))?;
            Ok(Some(RawCredential { target: d.target, user_name: d.user_name, comment: d.comment, last_written: d.last_written, blob, attributes: d.attributes }))
        })
    }

    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
        self.with(|o| {
            check_state(&o.conn, &o.mac_key)?;
            let mut stmt = o
                .conn
                .prepare(&format!("SELECT {COLUMNS} FROM items WHERE target LIKE ?1 ESCAPE '\\' ORDER BY target"))
                .map_err(db_err)?;
            let rows = stmt.query_map([format!("{}%", escape_like(prefix))], row).map_err(db_err)?;
            let mut out = Vec::new();
            for r in rows {
                let r = r.map_err(db_err)?;
                verify(&o.mac_key, &r)?;
                let blob = open(&o.value_key, &r.value, format!("{VALUE_AAD}{}", r.id).as_bytes())
                    .ok_or_else(|| Error::msg(format!("Keylo's vault: '{}' couldn't be decrypted.", r.target)))?;
                let d = details_of(&r)?;
                out.push(RawCredential { target: d.target, user_name: d.user_name, comment: d.comment, last_written: d.last_written, blob, attributes: d.attributes });
            }
            Ok(out)
        })
    }

    fn write(&self, target: &str, blob: &[u8], user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<()> {
        self.with(|o| {
            let tx = o.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_err)?;
            check_state(&tx, &o.mac_key)?;
            put(&tx, &o.value_key, &o.mac_key, target, blob, user_name, comment, attributes, Utc::now())?;
            sign_state(&tx, &o.mac_key)?;
            tx.commit().map_err(db_err)
        })
    }

    fn delete(&self, target: &str) -> Result<bool> {
        self.with(|o| {
            let tx = o.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_err)?;
            check_state(&tx, &o.mac_key)?;
            let n = tx.execute("DELETE FROM items WHERE target = ?1", [target]).map_err(db_err)?;
            sign_state(&tx, &o.mac_key)?;
            tx.commit().map_err(db_err)?;
            Ok(n > 0)
        })
    }

    fn enumerate_details(&self, prefix: &str) -> Result<Vec<CredentialDetails>> {
        self.with(|o| {
            check_state(&o.conn, &o.mac_key)?;
            let mut stmt = o
                .conn
                .prepare(&format!("SELECT {COLUMNS} FROM items WHERE target LIKE ?1 ESCAPE '\\' ORDER BY target"))
                .map_err(db_err)?;
            let rows = stmt.query_map([format!("{}%", escape_like(prefix))], row).map_err(db_err)?;
            let mut out = Vec::new();
            for r in rows {
                let r = r.map_err(db_err)?;
                verify(&o.mac_key, &r)?;
                out.push(details_of(&r)?);
            }
            Ok(out)
        })
    }

    fn read_details(&self, target: &str) -> Result<Option<CredentialDetails>> {
        self.with(|o| {
            let r = o
                .conn
                .query_row(&format!("SELECT {COLUMNS} FROM items WHERE target = ?1"), [target], row)
                .optional()
                .map_err(db_err)?;
            check_state(&o.conn, &o.mac_key)?;
            let Some(r) = r else { return Ok(None) };
            verify(&o.mac_key, &r)?;
            details_of(&r).map(Some)
        })
    }

    fn update_details(&self, target: &str, user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<bool> {
        self.with(|o| {
            let tx = o.conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_err)?;
            check_state(&tx, &o.mac_key)?;
            let r = tx
                .query_row(&format!("SELECT {COLUMNS} FROM items WHERE target = ?1"), [target], row)
                .optional()
                .map_err(db_err)?;
            let Some(r) = r else { return Ok(false) };
            verify(&o.mac_key, &r)?;
            // The sealed value stays as it is (it's bound to the row's id, which doesn't change).
            let when = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let attributes = serde_json::to_string(&clean(attributes)).map_err(|e| Error::msg(e.to_string()))?;
            let mac = mac_of(&o.mac_key, &r.id, &r.target, user_name, comment, &when, &attributes, &r.summary, &r.value);
            tx.execute(
                "UPDATE items SET user_name = ?2, comment = ?3, last_written = ?4, attributes = ?5, mac = ?6 WHERE id = ?1",
                params![r.id, user_name, comment, when, attributes, mac],
            )
            .map_err(db_err)?;
            sign_state(&tx, &o.mac_key)?;
            tx.commit().map_err(db_err)?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for DPAPI: XORs with a fixed pad (tests only).
    struct TestKey;
    impl OsKey for TestKey {
        fn kind(&self) -> &'static str {
            "test"
        }
        fn protect(&self, key: &[u8]) -> Result<Vec<u8>> {
            Ok(key.iter().map(|b| b ^ 0x5a).collect())
        }
        fn unprotect(&self, stored: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(stored.iter().map(|b| b ^ 0x5a).collect()))
        }
    }

    fn temp(name: &str) -> (PathBuf, SqliteVault) {
        let dir = std::env::temp_dir().join(format!("keylo-sqlvault-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("keylo.db");
        (dir, SqliteVault::new(path, Box::new(TestKey)))
    }

    fn attrs(category: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("KeyloCategory".to_string(), category.to_string()), ("Empty".to_string(), String::new())])
    }

    fn inline(value: &[u8]) -> Vec<u8> {
        let mut b = vec![0x01];
        b.extend_from_slice(value);
        b
    }

    #[test]
    fn values_are_sealed_and_details_are_readable() {
        let (dir, v) = temp("basic");
        v.write("Keylo:github", &inline(b"ghp_secretvalue"), Some("octocat"), Some("a note"), &attrs("dev")).unwrap();
        let d = v.read_details("keylo:GITHUB").unwrap().unwrap();
        assert_eq!(d.user_name.as_deref(), Some("octocat"));
        assert_eq!(d.attribute("KeyloCategory"), Some("dev"));
        assert_eq!(d.attribute("Empty"), None);
        assert_eq!(d.summary, keylo_core::store::summarize(&inline(b"ghp_secretvalue")));
        assert_eq!(v.read("Keylo:github").unwrap().unwrap().blob.as_slice(), inline(b"ghp_secretvalue").as_slice());
        drop(v);
        // The value never appears in the files; the name does (details are readable by design).
        let mut all = Vec::new();
        for f in std::fs::read_dir(&dir).unwrap() {
            all.extend(std::fs::read(f.unwrap().path()).unwrap());
        }
        let text = String::from_utf8_lossy(&all);
        assert!(!text.contains("ghp_secretvalue"));
        assert!(text.contains("Keylo:github"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopened_by_another_process_and_details_change_without_the_value() {
        let (dir, v) = temp("reopen");
        v.write("Keylo:a", &inline(b"one"), None, None, &attrs("x")).unwrap();
        assert!(v.update_details("Keylo:a", Some("me"), Some("n"), &attrs("y")).unwrap());
        let again = SqliteVault::new(dir.join("keylo.db"), Box::new(TestKey));
        let a = again.read("Keylo:a").unwrap().unwrap();
        assert_eq!(a.blob.as_slice(), inline(b"one").as_slice());
        assert_eq!(a.attribute("KeyloCategory"), Some("y"));
        assert_eq!(a.user_name.as_deref(), Some("me"));
        assert!(!again.update_details("Keylo:missing", None, None, &BTreeMap::new()).unwrap());
        assert_eq!(again.enumerate_details("Keylo:").unwrap().len(), 1);
        assert!(again.delete("keylo:A").unwrap());
        assert!(again.enumerate_details("Keylo:").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prefixes_are_literal() {
        let (dir, v) = temp("prefix");
        v.write("Test_1:a", &inline(b"x"), None, None, &BTreeMap::new()).unwrap();
        v.write("TestX1:b", &inline(b"y"), None, None, &BTreeMap::new()).unwrap();
        let found: Vec<String> = v.enumerate_details("Test_1:").unwrap().into_iter().map(|d| d.target).collect();
        assert_eq!(found, vec!["Test_1:a".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampering_outside_keylo_is_detected() {
        let (dir, v) = temp("tamper");
        v.write("Keylo:a", &inline(b"one"), None, None, &attrs("x")).unwrap();
        v.write("Keylo:b", &inline(b"two"), None, None, &attrs("x")).unwrap();
        drop(v);
        let raw = Connection::open(dir.join("keylo.db")).unwrap();
        // A changed detail.
        raw.execute("UPDATE items SET attributes = '{\"KeyloCategory\":\"evil\"}' WHERE target = 'Keylo:a'", []).unwrap();
        let v = SqliteVault::new(dir.join("keylo.db"), Box::new(TestKey));
        assert!(v.read_details("Keylo:a").is_err());
        assert!(v.read("Keylo:a").is_err());
        // Swapping one row's sealed value onto another.
        raw.execute("UPDATE items SET attributes = '{\"KeyloCategory\":\"x\"}' WHERE target = 'Keylo:a'", []).unwrap();
        let b_value: Vec<u8> = raw.query_row("SELECT value FROM items WHERE target = 'Keylo:b'", [], |r| r.get(0)).unwrap();
        raw.execute("UPDATE items SET value = ?1 WHERE target = 'Keylo:a'", [b_value]).unwrap();
        assert!(v.read("Keylo:a").is_err());
        // A deleted row.
        raw.execute("DELETE FROM items WHERE target = 'Keylo:a'", []).unwrap();
        assert!(v.enumerate_details("Keylo:").is_err());
        drop(raw);
        drop(v);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- the three attacks from the security review: each must now be refused ---

    fn mac_key_of(path: &std::path::Path) -> Vec<u8> {
        let c = Connection::open(path).unwrap();
        let blob: Vec<u8> = c.query_row("SELECT value FROM meta WHERE key = 'key'", [], |r| r.get(0)).unwrap();
        let vk = TestKey.unprotect(&blob).unwrap();
        let mut mk = vec![0u8; 32];
        Hkdf::<Sha256>::new(None, &vk).expand(b"keylo:vault:mac-key:v1", &mut mk).unwrap();
        mk
    }

    #[test]
    fn removing_the_integrity_record_to_hide_a_deletion_is_refused() {
        // Attack: delete the `state` meta row so Keylo would regenerate it over the tampered rows.
        let (dir, v) = temp("reset");
        let db = dir.join("keylo.db");
        v.write("Keylo:a", &inline(b"one"), None, None, &attrs("x")).unwrap();
        v.write("Keylo:b", &inline(b"two"), None, None, &attrs("x")).unwrap();
        drop(v);
        {
            let c = Connection::open(&db).unwrap();
            c.execute("DELETE FROM meta WHERE key = 'state'", []).unwrap();
            c.execute("DELETE FROM items WHERE target = 'Keylo:a'", []).unwrap();
        }
        let v = SqliteVault::new(db, Box::new(TestKey));
        assert!(v.read("Keylo:b").is_err());
        assert!(v.enumerate_details("Keylo:").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rolling_one_secret_back_is_detected_on_read_and_cannot_be_healed() {
        // Attack: while Keylo has the vault open, splice an older, validly-signed copy of a rotated
        // secret back in. The read path (not only listing) must catch it, and a later write must not
        // bless it.
        let (dir, v) = temp("rollback");
        let db = dir.join("keylo.db");
        v.write("Keylo:a", &inline(b"v1"), None, None, &attrs("x")).unwrap();
        let old: (String, Vec<u8>, Vec<u8>, String) = {
            let c = Connection::open(&db).unwrap();
            c.query_row("SELECT id, value, mac, last_written FROM items WHERE target = 'Keylo:a'", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap()
        };
        v.write("Keylo:a", &inline(b"v2"), None, None, &attrs("x")).unwrap(); // rotate
        assert_eq!(v.read("Keylo:a").unwrap().unwrap().blob.as_slice(), inline(b"v2").as_slice());
        {
            let c = Connection::open(&db).unwrap();
            c.busy_timeout(Duration::from_secs(5)).unwrap();
            c.execute("DELETE FROM items WHERE target = 'Keylo:a'", []).unwrap();
            let summary = keylo_core::store::summarize(&inline(b"v1"));
            c.execute(
                "INSERT INTO items (id, target, user_name, comment, last_written, attributes, summary, value, mac) \
                 VALUES (?1, 'Keylo:a', NULL, NULL, ?4, '{\"KeyloCategory\":\"x\"}', ?5, ?2, ?3)",
                params![old.0, old.1, old.2, old.3, summary],
            )
            .unwrap();
        }
        // The same open vault now reads the tampered file: the old value is refused, not returned.
        assert!(v.read("Keylo:a").is_err());
        // And a later, unrelated write can't re-sign (heal) the tampered state.
        assert!(v.write("Keylo:c", &inline(b"x"), None, None, &BTreeMap::new()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_2_0_vault_is_upgraded_and_a_tampered_one_refused() {
        let (dir, v) = temp("upgrade");
        let db = dir.join("keylo.db");
        v.write("Keylo:a", &inline(b"one"), None, None, &attrs("x")).unwrap();
        drop(v);
        let mk = mac_key_of(&db);
        // Rewrite the file on disk as a 2.0 vault: a valid legacy manifest, no state record.
        let to_2_0 = |mk: &[u8]| {
            let c = Connection::open(&db).unwrap();
            let manifest = legacy_manifest(&c, mk).unwrap();
            c.execute("DELETE FROM meta WHERE key IN ('state', 'seq')", []).unwrap();
            c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('manifest', ?1)", [manifest]).unwrap();
            c.execute("UPDATE meta SET value = CAST('1' AS BLOB) WHERE key = 'schema'", []).unwrap();
        };
        to_2_0(&mk);
        // Keylo opens it, verifies the manifest, and upgrades to the state record.
        let v = SqliteVault::new(db.clone(), Box::new(TestKey));
        assert_eq!(v.read("Keylo:a").unwrap().unwrap().blob.as_slice(), inline(b"one").as_slice());
        drop(v);
        {
            let c = Connection::open(&db).unwrap();
            let state: i64 = c.query_row("SELECT count(*) FROM meta WHERE key = 'state'", [], |r| r.get(0)).unwrap();
            let manifest: i64 = c.query_row("SELECT count(*) FROM meta WHERE key = 'manifest'", [], |r| r.get(0)).unwrap();
            assert_eq!((state, manifest), (1, 0));
        }
        // A tampered 2.0 vault (its manifest no longer matches the rows) is refused, not upgraded.
        to_2_0(&mk);
        {
            let c = Connection::open(&db).unwrap();
            c.execute("UPDATE items SET mac = x'00' WHERE target = 'Keylo:a'", []).unwrap();
        }
        assert!(SqliteVault::new(db, Box::new(TestKey)).read("Keylo:a").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_keeps_times_and_prefers_newer() {
        let (dir, v) = temp("import");
        let now = Utc::now();
        let at = |days: i64| now - chrono::Duration::days(days);
        let c = |t: &str, val: &[u8], days| RawCredential {
            target: t.into(),
            user_name: Some("u".into()),
            comment: None,
            last_written: at(days),
            blob: Zeroizing::new(inline(val)),
            attributes: attrs("c"),
        };
        assert_eq!(v.import(&[c("Keylo:a", b"old", 5), c("Keylo:b", b"b", 4)]).unwrap(), 2);
        assert_eq!(v.read_details("Keylo:a").unwrap().unwrap().last_written.timestamp(), at(5).timestamp());
        assert_eq!(v.import(&[c("Keylo:a", b"older", 9)]).unwrap(), 0);
        assert_eq!(v.import(&[c("Keylo:a", b"newer", 1)]).unwrap(), 1);
        assert_eq!(v.read("Keylo:a").unwrap().unwrap().blob.as_slice(), inline(b"newer").as_slice());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_newer_schema_or_another_protection_is_refused() {
        let (dir, v) = temp("refuse");
        v.write("Keylo:a", &inline(b"one"), None, None, &BTreeMap::new()).unwrap();
        drop(v);
        let raw = Connection::open(dir.join("keylo.db")).unwrap();
        raw.execute("UPDATE meta SET value = CAST('3' AS BLOB) WHERE key = 'schema'", []).unwrap();
        assert!(SqliteVault::new(dir.join("keylo.db"), Box::new(TestKey)).read("Keylo:a").is_err());
        raw.execute("UPDATE meta SET value = CAST('2' AS BLOB) WHERE key = 'schema'", []).unwrap();
        raw.execute("UPDATE meta SET value = CAST('other' AS BLOB) WHERE key = 'protection'", []).unwrap();
        assert!(SqliteVault::new(dir.join("keylo.db"), Box::new(TestKey)).read("Keylo:a").is_err());
        drop(raw);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
