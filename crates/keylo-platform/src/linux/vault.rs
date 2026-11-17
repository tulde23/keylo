//! Keylo's own encrypted store, for Linux machines without a desktop keyring (servers, containers,
//! WSL). One file holds every item, sealed with AES-256-GCM under a random vault key; the vault key
//! is wrapped with a key derived from the user's passphrase (PBKDF2-SHA256, 600,000 iterations).
//! The format is the C# build's (vault.json), so either build opens the other's vault.
//!
//! The passphrase comes from KEYLO_PASSPHRASE or KEYLO_PASSPHRASE_FILE, or is asked for on the
//! terminal; the unlocked vault key is then cached in the kernel keyring for
//! KEYLO_VAULT_CACHE_MINUTES (15 by default), so later commands don't ask again.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, FixedOffset, Local, Utc};
use keylo_core::platform::{CredentialStore, RawCredential};
use keylo_core::{bail, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::keycache;
use crate::unix::{self, open, seal};

const ITERATIONS: u32 = 600_000;
const KEY_AAD: &[u8] = b"keylo-vault:key:v1";
const DATA_AAD: &[u8] = b"keylo-vault:data:v1";

/// Whether terminal prompts are allowed (the CLI; not the MCP server or the app).
pub static CAN_PROMPT_ON_TERMINAL: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    target: String,
    user_name: Option<String>,
    comment: Option<String>,
    last_written: DateTime<FixedOffset>,
    blob: String,
    #[serde(default)]
    attributes: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Kdf {
    alg: String,
    iterations: u32,
    salt: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    format: String,
    version: i32,
    kdf: Kdf,
    key: String,
    data: String,
}

pub struct FileVault {
    path: PathBuf,
    cache_name: String,
    key: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl FileVault {
    pub fn new(path: PathBuf) -> Self {
        let full = std::path::absolute(&path).unwrap_or_else(|_| path.clone());
        let digest = hex::encode(Sha256::digest(full.to_string_lossy().as_bytes()));
        FileVault { cache_name: format!("keylo:vault:{}", &digest[..16]), path, key: Mutex::new(None) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    /// The vault key (for sealing protected files), unlocking first if needed.
    pub fn vault_key(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.ensure_unlocked()?;
        Ok(self.key.lock().unwrap().clone().unwrap())
    }

    /// Unlocks without asking: a cached key, KEYLO_PASSPHRASE, or KEYLO_PASSPHRASE_FILE.
    pub fn try_unlock_quietly(&self) -> Result<bool> {
        if self.key.lock().unwrap().is_some() {
            return Ok(true);
        }
        if !self.exists() {
            return Ok(false);
        }
        if let Some(cached) = keycache::get(&self.cache_name).filter(|k| k.len() == 32) {
            if self.decrypts(&cached) {
                *self.key.lock().unwrap() = Some(cached);
                return Ok(true);
            }
        }
        if let Some(p) = environment_passphrase()? {
            self.unlock(&p)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Unlocks with `passphrase`; fails when it's wrong.
    pub fn unlock(&self, passphrase: &str) -> Result<()> {
        let envelope = self.load()?.ok_or_else(|| Error::msg(format!("There's no Keylo vault at {}.", self.path.display())))?;
        let kek = derive(passphrase, &B64.decode(&envelope.kdf.salt).unwrap_or_default(), envelope.kdf.iterations);
        let wrapped = B64.decode(&envelope.key).unwrap_or_default();
        let key = open(&kek, &wrapped, KEY_AAD).ok_or_else(|| Error::msg("That passphrase doesn't unlock Keylo's vault."))?;
        *self.key.lock().unwrap() = Some(key);
        self.cache();
        Ok(())
    }

    /// Creates an empty vault protected by `passphrase`.
    pub fn create(&self, passphrase: &str) -> Result<()> {
        if self.exists() {
            bail!("A Keylo vault already exists at {}.", self.path.display());
        }
        let key = unix::random_key();
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        let kek = derive(passphrase, &salt, ITERATIONS);
        let envelope = Envelope {
            format: "keylo-vault".into(),
            version: 1,
            kdf: Kdf { alg: "pbkdf2-sha256".into(), iterations: ITERATIONS, salt: B64.encode(salt) },
            key: B64.encode(seal(&kek, &key, KEY_AAD)?),
            data: String::new(),
        };
        *self.key.lock().unwrap() = Some(key);
        self.with_lock(|| self.save(&envelope, &[]))?;
        self.cache();
        Ok(())
    }

    /// Forgets the vault key here and in the kernel keyring.
    pub fn lock(&self) {
        *self.key.lock().unwrap() = None;
        keycache::remove(&self.cache_name);
    }

    fn ensure_unlocked(&self) -> Result<()> {
        if self.try_unlock_quietly()? {
            return Ok(());
        }
        let can_prompt = CAN_PROMPT_ON_TERMINAL.load(Ordering::Relaxed) && unix::terminal_available();
        if !self.exists() {
            if let Some(p) = environment_passphrase()? {
                if let Some(weak) = keylo_core::backup::check_password(&p) {
                    bail!("KEYLO_PASSPHRASE can't protect a new vault: {weak}");
                }
                return self.create(&p);
            }
            if !can_prompt {
                bail!(
                    "Keylo has no vault yet and there's no desktop keyring. Run any keylo command in a terminal to create one \
                     (it asks for a passphrase), or set KEYLO_PASSPHRASE."
                );
            }
            eprintln!("No desktop keyring here, so Keylo keeps secrets in an encrypted vault ({}).", self.path.display());
            loop {
                let first = unix::read_hidden("New vault passphrase: ").ok_or_else(|| Error::msg("Canceled."))?;
                if let Some(problem) = keylo_core::backup::check_password(&first) {
                    eprintln!("{problem}");
                    continue;
                }
                if unix::read_hidden("Repeat it: ").map(|r| r.as_str() == first.as_str()) != Some(true) {
                    eprintln!("They don't match.");
                    continue;
                }
                self.create(&first)?;
                eprintln!("Vault created. Don't lose the passphrase: without it the vault can't be opened.");
                return Ok(());
            }
        }
        if !can_prompt {
            bail!(
                "Keylo's vault is locked. Run 'keylo unlock' in a terminal (it stays unlocked for a while), \
                 or set KEYLO_PASSPHRASE / KEYLO_PASSPHRASE_FILE."
            );
        }
        for attempt in 1.. {
            let p = unix::read_hidden("Keylo vault passphrase: ").ok_or_else(|| Error::msg("Canceled."))?;
            match self.unlock(&p) {
                Ok(()) => return Ok(()),
                Err(_) if attempt < 3 => eprintln!("That's not it. Try again."),
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    fn cache(&self) {
        let minutes: u64 = std::env::var("KEYLO_VAULT_CACHE_MINUTES").ok().and_then(|m| m.parse().ok()).unwrap_or(15);
        if let Some(key) = self.key.lock().unwrap().as_ref() {
            keycache::put(&self.cache_name, key, Duration::from_secs(minutes * 60));
        }
    }

    fn decrypts(&self, key: &[u8]) -> bool {
        match self.load() {
            Ok(Some(e)) => e.data.is_empty() || open(key, &B64.decode(&e.data).unwrap_or_default(), DATA_AAD).is_some(),
            _ => false,
        }
    }

    fn items(&self) -> Result<Vec<Item>> {
        self.ensure_unlocked()?;
        self.decrypt(self.load()?.as_ref())
    }

    fn decrypt(&self, envelope: Option<&Envelope>) -> Result<Vec<Item>> {
        let Some(e) = envelope.filter(|e| !e.data.is_empty()) else { return Ok(vec![]) };
        let key = self.key.lock().unwrap().clone().ok_or_else(|| Error::msg("Keylo's vault is locked."))?;
        let plain = open(&key, &B64.decode(&e.data).unwrap_or_default(), DATA_AAD)
            .ok_or_else(|| Error::msg(format!("Keylo's vault ({}) is damaged or was changed outside Keylo.", self.path.display())))?;
        serde_json::from_slice(&plain).map_err(|_| Error::msg(format!("Keylo's vault ({}) isn't readable.", self.path.display())))
    }

    /// Read, change and write the items under a lock, so the CLI, app and MCP server can't
    /// overwrite each other.
    fn change(&self, f: impl FnOnce(&mut Vec<Item>) -> bool) -> Result<bool> {
        self.ensure_unlocked()?;
        self.with_lock(|| {
            let envelope = self.load()?.ok_or_else(|| Error::msg(format!("Keylo's vault ({}) is missing.", self.path.display())))?;
            let mut items = self.decrypt(Some(&envelope))?;
            if !f(&mut items) {
                return Ok(false);
            }
            self.save(&envelope, &items)?;
            Ok(true)
        })
    }

    fn save(&self, envelope: &Envelope, items: &[Item]) -> Result<()> {
        let key = self.key.lock().unwrap().clone().ok_or_else(|| Error::msg("Keylo's vault is locked."))?;
        let plain = Zeroizing::new(serde_json::to_vec(items).unwrap());
        let mut envelope = envelope.clone();
        envelope.data = B64.encode(seal(&key, &plain, DATA_AAD)?);
        let json = serde_json::to_vec(&envelope).unwrap();

        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let temp = self.path.with_extension("json.tmp");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        fs::rename(&temp, &self.path)?;
        Ok(())
    }

    fn load(&self) -> Result<Option<Envelope>> {
        if !self.path.is_file() {
            return Ok(None);
        }
        let bytes = fs::read(&self.path)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Error::msg(format!("Keylo's vault ({}) isn't readable.", self.path.display())))
    }

    /// An exclusive lock on vault.json.lock (flock), shared with other Keylo processes.
    fn with_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        use std::os::fd::AsRawFd;
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let lock_path = PathBuf::from(format!("{}.lock", self.path.display()));
        let file = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&lock_path)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            if Instant::now() > deadline {
                bail!("Keylo's vault is busy (another Keylo is writing it).");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let result = f();
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        result
    }
}

fn derive(passphrase: &str, salt: &[u8], iterations: u32) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iterations, &mut key);
    key
}

fn environment_passphrase() -> Result<Option<Zeroizing<String>>> {
    if let Ok(p) = std::env::var("KEYLO_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(Some(Zeroizing::new(p)));
        }
    }
    if let Ok(file) = std::env::var("KEYLO_PASSPHRASE_FILE") {
        if !file.is_empty() {
            let text = fs::read_to_string(&file).map_err(|e| Error::msg(format!("Couldn't read KEYLO_PASSPHRASE_FILE ({file}): {e}")))?;
            return Ok(Some(Zeroizing::new(text.trim_end_matches(['\r', '\n']).to_string())));
        }
    }
    Ok(None)
}

fn to_credential(i: &Item) -> RawCredential {
    RawCredential {
        target: i.target.clone(),
        user_name: i.user_name.clone(),
        comment: i.comment.clone(),
        last_written: i.last_written.with_timezone(&Utc),
        blob: Zeroizing::new(B64.decode(&i.blob).unwrap_or_default()),
        attributes: i.attributes.clone(),
    }
}

impl CredentialStore for FileVault {
    fn max_blob_bytes(&self) -> usize {
        16 * 1024
    }
    fn max_attribute_bytes(&self) -> usize {
        1024
    }
    fn max_attributes(&self) -> usize {
        64
    }

    fn read(&self, target: &str) -> Result<Option<RawCredential>> {
        Ok(self.items()?.iter().find(|i| i.target.eq_ignore_ascii_case(target)).map(to_credential))
    }

    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
        let p = prefix.to_lowercase();
        Ok(self.items()?.iter().filter(|i| i.target.to_lowercase().starts_with(&p)).map(to_credential).collect())
    }

    fn write(&self, target: &str, blob: &[u8], user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<()> {
        self.change(|items| {
            items.retain(|i| !i.target.eq_ignore_ascii_case(target));
            items.push(Item {
                target: target.into(),
                user_name: user_name.map(str::to_string),
                comment: comment.map(str::to_string),
                last_written: Local::now().fixed_offset(),
                blob: B64.encode(blob),
                attributes: attributes.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| (k.clone(), v.clone())).collect(),
            });
            true
        })?;
        Ok(())
    }

    fn delete(&self, target: &str) -> Result<bool> {
        self.change(|items| {
            let before = items.len();
            items.retain(|i| !i.target.eq_ignore_ascii_case(target));
            items.len() != before
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_write_reopen() {
        let dir = std::env::temp_dir().join(format!("keylo-vault-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("vault.json");
        let v = FileVault::new(path.clone());
        v.create("correct horse battery").unwrap();
        let mut attrs = BTreeMap::new();
        attrs.insert("category".to_string(), "dev".to_string());
        v.write("Keylo:a", b"value-1", Some("me"), None, &attrs).unwrap();

        let again = FileVault::new(path.clone());
        assert!(again.unlock("wrong passphrase!").is_err());
        again.unlock("correct horse battery").unwrap();
        let c = again.read("keylo:A").unwrap().unwrap();
        assert_eq!(c.blob.as_slice(), b"value-1");
        assert_eq!(c.attribute("category"), Some("dev"));
        assert!(again.delete("Keylo:a").unwrap());
        assert!(again.enumerate("Keylo:").unwrap().is_empty());
        v.lock();
        let _ = fs::remove_dir_all(&dir);
    }
}
