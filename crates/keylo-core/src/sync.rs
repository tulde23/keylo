//! Syncing secrets between your own devices through a shared folder (OneDrive, iCloud Drive,
//! Dropbox, Syncthing…). Keylo never talks to a server: the folder's sync tool moves the files,
//! and the files are encrypted with a vault key only your devices have.
//!
//! Folder layout:
//!   keylo-sync.json                  the vault's id and a check value for its key (no secrets)
//!   devices/{device id}.keylo-sync   one file per device, written only by that device
//!
//! Each device file holds the device's view of the whole vault: every secret (value and details),
//! custom types, category styles and uploaded icons, as records with a version, plus tombstones
//! for deletions. It is gzipped JSON encrypted with AES-256-GCM under the vault key, with the
//! device id as associated data. One file per device means two devices never write the same file,
//! so sync tools don't make "conflicted copies".
//!
//! A sync reads this device's secrets, compares them with the state of the last sync to find local
//! changes, merges every other device's file record by record (the newest version wins; versions
//! are hybrid logical clocks, so they follow causality even when clocks disagree), applies what
//! changed, and writes this device's file. When two devices changed the same secret since they last
//! synced, the losing version is kept as a new secret named "{name} (conflict {device} {time})".
//!
//! Local files (data folder): sync.json (folder, device, last result), sync.key (the vault key,
//! protected by the platform's data protector), sync-state.bin (the last sync's record versions
//! and keyed digests, protected too).
//!
//! What doesn't sync: access keys and agents' grants, the audit log, settings, pins and recent
//! uses, the session. They belong to each device.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::secrets::SecretDraft;
use crate::store::{normalize_name, SecretStore, MAX_NAME_LENGTH};
use crate::{bail, paths, platform, Error, Result};

const FORMAT: u32 = 1;
const VAULT_FILE: &str = "keylo-sync.json";
const DEVICES_DIR: &str = "devices";
const DEVICE_EXT: &str = "keylo-sync";
const MAGIC: &[u8; 4] = b"KLSY";
const KEY_ENTROPY: &[u8] = b"keylo:sync:key:v1";
const STATE_ENTROPY: &[u8] = b"keylo:sync:state:v1";
/// Files in the data folder that sync whole (newest wins).
const SYNCED_FILES: &[&str] = &["types.json", "categories.json"];

// ---------------------------------------------------------------------------- the device

/// One Keylo installation: its data folder and secret store. Tests use several against one folder.
pub struct Device {
    pub data_dir: PathBuf,
    pub store: SecretStore,
}

impl Device {
    /// This installation (KEYLO_HOME and KEYLO_PREFIX apply).
    pub fn local() -> Self {
        Device { data_dir: paths::data_dir(), store: SecretStore::default() }
    }

    fn config_path(&self) -> PathBuf {
        self.data_dir.join("sync.json")
    }
    fn key_path(&self) -> PathBuf {
        self.data_dir.join("sync.key")
    }
    fn state_path(&self) -> PathBuf {
        self.data_dir.join("sync-state.bin")
    }
    fn icon_dir(&self) -> PathBuf {
        self.data_dir.join("icons")
    }
}

/// sync.json: where and as whom this device syncs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncConfig {
    pub folder: PathBuf,
    pub vault: String,
    pub device_id: String,
    pub device_name: String,
    #[serde(default)]
    pub last: Option<LastSync>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastSync {
    pub at: DateTime<Utc>,
    pub ok: bool,
    pub summary: String,
}

/// What a sync did.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Secrets and files changed here from other devices (added, updated or deleted).
    pub received: usize,
    /// Changes made here since the last sync, now in this device's file.
    pub sent: usize,
    /// Conflict copies made, by name.
    pub conflicts: Vec<String>,
    /// Records that couldn't be applied here (they're retried next time).
    pub errors: Vec<String>,
    /// Other devices whose files were read.
    pub devices: usize,
}

impl Report {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        parts.push(match self.received {
            0 => "nothing new from other devices".to_string(),
            1 => "1 change received".to_string(),
            n => format!("{n} changes received"),
        });
        match self.sent {
            0 => {}
            1 => parts.push("1 change sent".into()),
            n => parts.push(format!("{n} changes sent")),
        }
        if !self.conflicts.is_empty() {
            parts.push(format!("{} conflict copies kept", self.conflicts.len()));
        }
        if !self.errors.is_empty() {
            parts.push(format!("{} couldn't be applied", self.errors.len()));
        }
        let mut s = parts.join(", ");
        if let Some(first) = s.get(..1) {
            s = first.to_uppercase() + &s[1..];
        }
        s + "."
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSummary {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub synced_at: DateTime<Utc>,
    pub this_device: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub folder: PathBuf,
    pub device_id: String,
    pub device_name: String,
    pub last: Option<LastSync>,
    pub devices: Vec<DeviceSummary>,
    /// Why the folder couldn't be read, if it couldn't (e.g. a drive that isn't connected).
    pub problem: Option<String>,
}

// ---------------------------------------------------------------------------- set up, join, leave

/// Whether this device syncs, and with whom.
pub fn status(dev: &Device) -> Result<Option<Status>> {
    let Some(config) = load_config(dev)? else { return Ok(None) };
    let mut devices = Vec::new();
    let mut problem = None;
    match load_key(dev).and_then(|key| read_device_files(&config, &key, true)) {
        Ok(files) => {
            for (_, f) in files {
                devices.push(DeviceSummary {
                    this_device: f.device.id == config.device_id,
                    id: f.device.id,
                    name: f.device.name,
                    platform: f.device.platform,
                    synced_at: f.device.synced_at,
                });
            }
        }
        Err(e) => problem = Some(e.to_string()),
    }
    devices.sort_by(|a, b| b.this_device.cmp(&a.this_device).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(Some(Status {
        folder: config.folder,
        device_id: config.device_id,
        device_name: config.device_name,
        last: config.last,
        devices,
        problem,
    }))
}

/// Starts a new sync vault in `folder` (an empty folder, or one without a vault) and syncs this
/// device into it. Other devices join with [`join_code`].
pub fn create(dev: &Device, folder: &Path, device_name: &str) -> Result<Report> {
    ensure_not_set_up(dev)?;
    let folder = check_folder(folder)?;
    if folder.join(VAULT_FILE).exists() {
        bail!("{} already holds a Keylo sync vault. Join it with the code from one of its devices.", folder.display());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut key[..]);
    let vault = uuid::Uuid::new_v4().simple().to_string();
    let header = VaultFile { format: FORMAT, vault: vault.clone(), check: key_check(&key[..], &vault) };
    fs::create_dir_all(folder.join(DEVICES_DIR))?;
    write_atomic(&folder.join(VAULT_FILE), serde_json::to_string_pretty(&header).unwrap().as_bytes())?;
    set_up(dev, &folder, &vault, &key[..], device_name)?;
    sync(dev)
}

/// Joins the vault in `folder` with a code shown on one of its devices, then syncs. Secrets this
/// device already has are kept; where another device has a different secret with the same name,
/// that one wins and this device's is kept as a conflict copy.
pub fn join(dev: &Device, folder: &Path, device_name: &str, code: &str) -> Result<Report> {
    ensure_not_set_up(dev)?;
    let folder = check_folder(folder)?;
    let header = read_vault_file(&folder)?;
    let key = decode_code(code)?;
    if !constant_time_eq(key_check(&key[..], &header.vault).as_bytes(), header.check.as_bytes()) {
        bail!("That code doesn't match the vault in {}. Check it, or show it again on a device that syncs.", folder.display());
    }
    set_up(dev, &folder, &header.vault, &key[..], device_name)?;
    sync(dev)
}

/// The code another device needs to join (the vault key). Show it only after an identity check.
pub fn join_code(dev: &Device) -> Result<String> {
    load_config(dev)?.ok_or_else(not_set_up)?;
    Ok(encode_code(&load_key(dev)?[..]))
}

/// Stops syncing on this device: forgets the folder and key and removes this device's file. The
/// secrets stay, here and on the other devices.
pub fn leave(dev: &Device) -> Result<()> {
    if let Some(config) = load_config(dev)? {
        let _ = fs::remove_file(device_path(&config.folder, &config.device_id));
    }
    for p in [dev.config_path(), dev.key_path(), dev.state_path()] {
        let _ = fs::remove_file(p);
    }
    Ok(())
}

/// Removes another device's file from the folder. It doesn't revoke the device: if it still syncs
/// it writes its file again, and it already knows the vault key and every secret.
pub fn forget(dev: &Device, device_id: &str) -> Result<()> {
    let config = load_config(dev)?.ok_or_else(not_set_up)?;
    if device_id == config.device_id {
        bail!("That's this device; use leave to stop syncing here.");
    }
    if device_id.is_empty() || !device_id.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("'{device_id}' isn't a device id.");
    }
    let path = device_path(&config.folder, device_id);
    if !path.exists() {
        bail!("No device '{device_id}' in the sync folder.");
    }
    fs::remove_file(path)?;
    Ok(())
}

/// This device's sync settings, without reading the folder (None: it doesn't sync).
pub fn config(dev: &Device) -> Result<Option<SyncConfig>> {
    load_config(dev)
}

/// The other devices' files by name, time and size: it changes when another device syncs. None when
/// the folder can't be read.
pub fn folder_stamp(config: &SyncConfig) -> Option<Vec<(String, std::time::SystemTime, u64)>> {
    let own = format!("{}.{DEVICE_EXT}", config.device_id);
    let mut stamp: Vec<_> = fs::read_dir(config.folder.join(DEVICES_DIR))
        .ok()?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if name == own || !name.ends_with(DEVICE_EXT) {
                return None;
            }
            let m = e.metadata().ok()?;
            Some((name, m.modified().ok()?, m.len()))
        })
        .collect();
    stamp.sort();
    Some(stamp)
}

pub fn rename_device(dev: &Device, name: &str) -> Result<()> {
    let mut config = load_config(dev)?.ok_or_else(not_set_up)?;
    config.device_name = clean_device_name(name)?;
    save_config(dev, &config)
}

/// A name for this computer: its host name.
pub fn default_device_name() -> String {
    let from_env = ["COMPUTERNAME", "HOSTNAME"].iter().find_map(|v| std::env::var(v).ok().filter(|s| !s.trim().is_empty()));
    let from_file = || fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let from_mac = || {
        std::process::Command::new("scutil")
            .args(["--get", "ComputerName"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let name = if cfg!(target_os = "macos") { from_mac().or(from_env) } else { from_env.or_else(from_file) };
    name.unwrap_or_else(|| "This device".into())
}

fn set_up(dev: &Device, folder: &Path, vault: &str, key: &[u8], device_name: &str) -> Result<()> {
    let config = SyncConfig {
        folder: folder.to_path_buf(),
        vault: vault.to_string(),
        device_id: uuid::Uuid::new_v4().simple().to_string(),
        device_name: clean_device_name(device_name)?,
        last: None,
    };
    fs::create_dir_all(&dev.data_dir)?;
    let protected = platform::current().data_protector().protect(key, KEY_ENTROPY)?;
    write_atomic(&dev.key_path(), &protected)?;
    let _ = fs::remove_file(dev.state_path());
    save_config(dev, &config)
}

fn ensure_not_set_up(dev: &Device) -> Result<()> {
    if let Some(c) = load_config(dev)? {
        bail!("This device already syncs with {}. Stop syncing first to use another folder.", c.folder.display());
    }
    Ok(())
}

fn not_set_up() -> Error {
    Error::msg("This device doesn't sync yet. Set it up in Settings → Sync, or with 'keylo sync create' or 'keylo sync join'.")
}

fn check_folder(folder: &Path) -> Result<PathBuf> {
    if !folder.is_dir() {
        bail!("{} isn't a folder.", folder.display());
    }
    Ok(std::path::absolute(folder).unwrap_or_else(|_| folder.to_path_buf()))
}

fn clean_device_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("Give this device a name.");
    }
    if name.chars().count() > 40 || name.chars().any(char::is_control) || name.contains('*') {
        bail!("Device names are up to 40 characters, without control characters or '*'.");
    }
    Ok(name.to_string())
}

fn load_config(dev: &Device) -> Result<Option<SyncConfig>> {
    match fs::read_to_string(dev.config_path()) {
        Ok(text) => serde_json::from_str(&text).map(Some).map_err(|e| Error::msg(format!("sync.json is invalid: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn save_config(dev: &Device, config: &SyncConfig) -> Result<()> {
    write_atomic(&dev.config_path(), serde_json::to_string_pretty(config).unwrap().as_bytes())
}

fn load_key(dev: &Device) -> Result<Zeroizing<Vec<u8>>> {
    let data = fs::read(dev.key_path()).map_err(|_| Error::msg("This device's sync key is missing. Stop syncing and join again."))?;
    let key = platform::current().data_protector().unprotect(&data, KEY_ENTROPY)?;
    if key.len() != 32 {
        bail!("This device's sync key is damaged. Stop syncing and join again.");
    }
    Ok(key)
}

// ---------------------------------------------------------------------------- files in the folder

#[derive(Serialize, Deserialize)]
struct VaultFile {
    format: u32,
    vault: String,
    check: String,
}

fn read_vault_file(folder: &Path) -> Result<VaultFile> {
    let text = fs::read_to_string(folder.join(VAULT_FILE))
        .map_err(|_| Error::msg(format!("{} has no Keylo sync vault ({VAULT_FILE}). Pick the folder another device syncs with.", folder.display())))?;
    let header: VaultFile = serde_json::from_str(&text).map_err(|e| Error::msg(format!("{VAULT_FILE} is invalid: {e}")))?;
    if header.format > FORMAT {
        bail!("The sync vault was made by a newer Keylo. Update Keylo on this device.");
    }
    Ok(header)
}

#[derive(Serialize, Deserialize)]
struct DeviceFile {
    format: u32,
    vault: String,
    device: DeviceInfo,
    records: Vec<Record>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceInfo {
    id: String,
    name: String,
    platform: String,
    synced_at: DateTime<Utc>,
    keylo: String,
}

/// One secret, file or icon at a version. `secret`/`file` are absent for a deletion.
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    key: String,
    version: u64,
    /// The device that made this version.
    by: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    deleted: bool,
    /// HMAC of the content under the vault key: equal digests, equal content.
    digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<SecretPayload>,
    /// A file's or icon's bytes, base64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
}

impl Record {
    fn newer_than(&self, other: &Record) -> bool {
        (self.version, &self.by) > (other.version, &other.by)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct SecretPayload {
    name: String,
    /// The value, base64.
    value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    color: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    type_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    fields: BTreeMap<String, String>,
}

impl Drop for SecretPayload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
    }
}

fn device_path(folder: &Path, id: &str) -> PathBuf {
    folder.join(DEVICES_DIR).join(format!("{id}.{DEVICE_EXT}"))
}

fn seal(key: &[u8], device_id: &str, plain: &[u8]) -> Result<Vec<u8>> {
    let mut packed = Vec::new();
    {
        let mut gz = flate2::write::GzEncoder::new(&mut packed, flate2::Compression::default());
        gz.write_all(plain)?;
        gz.finish()?;
    }
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let aad = device_aad(device_id);
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), AeadPayload { msg: &packed, aad: &aad })
        .map_err(|_| Error::msg("Couldn't encrypt the sync file."))?;
    let mut out = Vec::with_capacity(MAGIC.len() + 1 + 12 + sealed.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open(key: &[u8], device_id: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 17 + 16 || &data[..4] != MAGIC {
        bail!("not a Keylo sync file");
    }
    if data[4] as u32 > FORMAT {
        bail!("written by a newer Keylo; update Keylo on this device");
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let aad = device_aad(device_id);
    let packed = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&data[5..17]), AeadPayload { msg: &data[17..], aad: &aad })
            .map_err(|_| Error::msg("it doesn't decrypt with this vault's key (damaged, or from another vault)"))?,
    );
    let mut plain = Zeroizing::new(Vec::new());
    flate2::read::GzDecoder::new(&packed[..]).read_to_end(&mut plain)?;
    Ok(plain)
}

fn device_aad(device_id: &str) -> Vec<u8> {
    format!("keylo-sync:device:{device_id}").into_bytes()
}

/// Every device file in the folder that decrypts, by device id. Unreadable ones are skipped: a sync
/// tool may be halfway through writing one, or it belongs to another vault.
fn read_device_files(config: &SyncConfig, key: &[u8], include_own: bool) -> Result<Vec<(String, DeviceFile)>> {
    let dir = config.folder.join(DEVICES_DIR);
    let entries = fs::read_dir(&dir).map_err(|e| Error::msg(format!("Couldn't read the sync folder {}: {e}", dir.display())))?;
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(id) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(&format!(".{DEVICE_EXT}")))
            .map(str::to_string)
        else {
            continue;
        };
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) || (!include_own && id == config.device_id) {
            continue;
        }
        let Ok(data) = fs::read(&path) else { continue };
        let Ok(plain) = open(key, &id, &data) else { continue };
        let Ok(file) = serde_json::from_slice::<DeviceFile>(&plain) else { continue };
        if file.vault != config.vault || file.device.id != id {
            continue;
        }
        out.push((id, file));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------- local state

/// The last sync's records (no content): which version of each key this device has.
#[derive(Default, Serialize, Deserialize)]
struct State {
    /// The hybrid logical clock: the highest version seen or made.
    clock: u64,
    base: HashMap<String, Meta>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Meta {
    version: u64,
    by: String,
    #[serde(default)]
    deleted: bool,
    digest: String,
}

impl State {
    fn load(dev: &Device) -> Result<State> {
        let Ok(data) = fs::read(dev.state_path()) else { return Ok(State::default()) };
        let plain = platform::current().data_protector().unprotect(&data, STATE_ENTROPY)?;
        Ok(serde_json::from_slice(&plain).unwrap_or_default())
    }

    fn save(&self, dev: &Device) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(self).unwrap());
        write_atomic(&dev.state_path(), &platform::current().data_protector().protect(&plain, STATE_ENTROPY)?)
    }

    /// A new version, later than now and than anything seen.
    fn tick(&mut self) -> u64 {
        let now = Utc::now().timestamp_millis().max(0) as u64;
        self.clock = now.max(self.clock + 1);
        self.clock
    }

    fn observe(&mut self, version: u64) {
        self.clock = self.clock.max(version);
    }
}

// ---------------------------------------------------------------------------- sync

/// What this device holds for one key right now.
struct LocalItem {
    /// The secret's name as stored here (for secrets).
    name: Option<String>,
    digest: String,
    secret: Option<SecretPayload>,
    file: Option<String>,
}

/// Syncs once: reads the other devices' files, applies their changes here, and writes this device's
/// file. Only one sync runs at a time per data folder.
pub fn sync(dev: &Device) -> Result<Report> {
    let mut config = load_config(dev)?.ok_or_else(not_set_up)?;
    let _lock = SyncLock::take(&dev.data_dir)?;
    let result = sync_locked(dev, &config);
    config.last = Some(LastSync {
        at: Utc::now(),
        ok: result.is_ok(),
        summary: match &result {
            Ok(r) => r.summary(),
            Err(e) => e.to_string(),
        },
    });
    let _ = save_config(dev, &config);
    result
}

fn sync_locked(dev: &Device, config: &SyncConfig) -> Result<Report> {
    let key = load_key(dev)?;
    let header = read_vault_file(&config.folder)?;
    if header.vault != config.vault {
        bail!("The folder {} now holds a different sync vault. Stop syncing and join it again.", config.folder.display());
    }
    let mut state = State::load(dev)?;
    let mut report = Report::default();

    // 1. This device, now.
    let local = read_local(dev, &key)?;

    // 2. This device's records: unchanged since the last sync keep their version; changes get a new one.
    let mut mine: BTreeMap<String, (Record, bool)> = BTreeMap::new(); // key → (record, changed here since last sync)
    let keys: Vec<String> = local.keys().chain(state.base.keys()).cloned().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    for k in &keys {
        let base = state.base.get(k).cloned();
        let record = match (local.get(k), &base) {
            (Some(item), Some(b)) if !b.deleted && b.digest == item.digest => {
                (record_of(k, b.version, &b.by, false, item), false)
            }
            (Some(item), _) => {
                let v = state.tick();
                (record_of(k, v, &config.device_id, false, item), true)
            }
            (None, Some(b)) if b.deleted => (tombstone(k, b.version, &b.by, &b.digest), false),
            (None, Some(_)) => {
                let v = state.tick();
                (tombstone(k, v, &config.device_id, &deletion_digest(&key, k)), true)
            }
            (None, None) => continue,
        };
        mine.insert(k.clone(), record);
    }
    report.sent = mine.values().filter(|(_, changed)| *changed).count();

    // A store that was emptied (a reinstalled OS, a reset keychain) with this device's sync state
    // still in place would look like you deleted everything. Refuse rather than delete it everywhere.
    let synced = state.base.iter().filter(|(k, m)| k.starts_with("secret:") && !m.deleted).count();
    let gone_here = mine.iter().filter(|(k, (r, changed))| *changed && r.deleted && k.starts_with("secret:")).count();
    if too_many(gone_here, synced) {
        bail!(
            "{gone_here} of the {synced} synced secrets are missing on this device, so nothing was synced (that would delete them on every device).              If this device's store was reset, stop syncing here and join again: joining deletes nothing, and brings them back.              If you meant to delete them, delete a few at a time."
        );
    }

    // 3. Every other device's newest record per key.
    let others = read_device_files(config, &key, false)?;
    report.devices = others.len();
    let names: HashMap<String, String> = others.iter().map(|(id, f)| (id.clone(), f.device.name.clone())).collect();
    let mut theirs: BTreeMap<String, Record> = BTreeMap::new();
    for (_, file) in others {
        for r in file.records {
            state.observe(r.version);
            if !valid_key(&r.key) {
                continue;
            }
            match theirs.get(&r.key) {
                Some(have) if !r.newer_than(have) => {}
                _ => {
                    theirs.insert(r.key.clone(), r);
                }
            }
        }
    }

    // The same check for deletions arriving from another device.
    let incoming = theirs
        .iter()
        .filter(|(k, r)| r.deleted && k.starts_with("secret:") && local.contains_key(*k) && mine.get(*k).is_none_or(|(l, _)| r.newer_than(l)))
        .count();
    let here = local.keys().filter(|k| k.starts_with("secret:")).count();
    if too_many(incoming, here) {
        bail!(
            "Another device would delete {incoming} of this device's {here} secrets, so nothing was synced.              If that device's store was reset, stop syncing there and join again. To accept the deletions,              stop syncing here, delete them here, and join again."
        );
    }

    // 4. Merge.
    let device_name = |id: &str| -> String {
        if id == config.device_id {
            config.device_name.clone()
        } else {
            names.get(id).cloned().unwrap_or_else(|| "another device".into())
        }
    };
    let all_keys: std::collections::BTreeSet<String> = mine.keys().chain(theirs.keys()).cloned().collect();
    let mut merged: BTreeMap<String, Record> = BTreeMap::new();
    let mut new_base: HashMap<String, Meta> = HashMap::new();
    for k in all_keys {
        let base = state.base.get(&k);
        let ours = mine.get(&k);
        let remote = theirs.get(&k);
        let (winner, loser) = match (ours, remote) {
            (Some((l, _)), None) => (l.clone(), None),
            (None, Some(r)) => (r.clone(), None),
            (Some((l, changed)), Some(r)) => {
                if l.digest == r.digest && l.deleted == r.deleted {
                    // Same content: keep the newer version so every device agrees on it.
                    (if r.newer_than(l) { r.clone() } else { l.clone() }, None)
                } else if base.is_none() && !l.deleted && !r.deleted {
                    // Never synced here, and another device has something different under this
                    // name (a device joining with secrets of its own): theirs wins, ours is kept.
                    (r.clone(), Some(l.clone()))
                } else {
                    // The newest version wins. If both sides changed since the last sync here, the
                    // other side is a concurrent edit: it's kept as a copy (unless it's a deletion).
                    let remote_changed = base.is_none_or(|b| r.version != b.version || r.by != b.by);
                    let (w, other) = if r.newer_than(l) { (r, l) } else { (l, r) };
                    let lost = (*changed && remote_changed && !other.deleted).then(|| other.clone());
                    (w.clone(), lost)
                }
            }
            (None, None) => continue,
        };

        // Keep the losing side of a conflict as a copy (secrets only: files and icons just take the newest).
        if let Some(lost) = loser.filter(|_| k.starts_with("secret:")) {
            match keep_conflict_copy(dev, &lost, &device_name(&lost.by)) {
                Ok(Some(name)) => report.conflicts.push(name),
                Ok(None) => {}
                Err(e) => report.errors.push(format!("a conflict copy of {}: {e}", display_key(&k))),
            }
        }

        // Apply the winner here if it isn't what this device holds.
        let here = local.get(&k);
        let differs = match (here, winner.deleted) {
            (Some(item), false) => item.digest != winner.digest,
            (Some(_), true) => true,
            (None, false) => true,
            (None, true) => false,
        };
        let mut applied = true;
        if differs {
            match apply(dev, &k, &winner, here) {
                Ok(()) => report.received += 1,
                Err(e) => {
                    applied = false;
                    report.errors.push(format!("{}: {e}", display_key(&k)));
                }
            }
        }
        if applied {
            new_base.insert(k.clone(), Meta { version: winner.version, by: winner.by.clone(), deleted: winner.deleted, digest: winner.digest.clone() });
        } else if let Some(b) = base {
            new_base.insert(k.clone(), b.clone());
        }
        merged.insert(k, winner);
    }

    // Conflict copies are new secrets made here: publish them now, not at the next sync.
    for name in &report.conflicts {
        if let Some(info) = dev.store.find(name)? {
            let (k, item) = local_secret(dev, &key, info)?;
            let v = state.tick();
            let record = record_of(&k, v, &config.device_id, false, &item);
            new_base.insert(k.clone(), Meta { version: v, by: config.device_id.clone(), deleted: false, digest: item.digest.clone() });
            merged.insert(k, record);
        }
    }

    // 5. Write this device's file: the merged state, so others get everything even when the device
    //    that made a change is offline.
    let file = DeviceFile {
        format: FORMAT,
        vault: config.vault.clone(),
        device: DeviceInfo {
            id: config.device_id.clone(),
            name: config.device_name.clone(),
            platform: platform::current().name().to_string(),
            synced_at: Utc::now(),
            keylo: crate::version::VERSION.to_string(),
        },
        records: merged.into_values().collect(),
    };
    let plain = Zeroizing::new(serde_json::to_vec(&file).unwrap());
    fs::create_dir_all(config.folder.join(DEVICES_DIR))?;
    write_atomic(&device_path(&config.folder, &config.device_id), &seal(&key, &config.device_id, &plain)?)?;

    state.base = new_base;
    state.save(dev)?;
    Ok(report)
}

/// More deletions at once than a person makes: more than 5, and more than half.
fn too_many(deleted: usize, total: usize) -> bool {
    deleted > 5 && deleted * 2 > total
}

fn record_of(key: &str, version: u64, by: &str, deleted: bool, item: &LocalItem) -> Record {
    Record { key: key.to_string(), version, by: by.to_string(), deleted, digest: item.digest.clone(), secret: item.secret.clone(), file: item.file.clone() }
}

fn tombstone(key: &str, version: u64, by: &str, digest: &str) -> Record {
    Record { key: key.to_string(), version, by: by.to_string(), deleted: true, digest: digest.to_string(), secret: None, file: None }
}

fn valid_key(key: &str) -> bool {
    if let Some(name) = key.strip_prefix("file:") {
        return SYNCED_FILES.contains(&name);
    }
    if let Some(name) = key.strip_prefix("icon:") {
        return valid_icon_file(name);
    }
    key.strip_prefix("secret:").is_some_and(|n| !n.is_empty())
}

fn valid_icon_file(name: &str) -> bool {
    name.len() <= 80 && name.ends_with(".png") && name[..name.len() - 4].chars().all(|c| c.is_ascii_alphanumeric())
}

fn display_key(key: &str) -> String {
    match key.split_once(':') {
        Some(("secret", n)) => format!("'{n}'"),
        Some((_, n)) => n.to_string(),
        None => key.to_string(),
    }
}

/// This device's secrets, synced files and icons, with keyed digests.
fn read_local(dev: &Device, key: &[u8]) -> Result<BTreeMap<String, LocalItem>> {
    let mut out = BTreeMap::new();
    for info in dev.store.list()? {
        let (k, item) = local_secret(dev, key, info)?;
        out.insert(k, item);
    }
    for name in SYNCED_FILES {
        if let Ok(bytes) = fs::read(dev.data_dir.join(name)) {
            let k = format!("file:{name}");
            out.insert(k.clone(), LocalItem { name: None, digest: digest(key, &k, &bytes), secret: None, file: Some(base64::engine::general_purpose::STANDARD.encode(&bytes)) });
        }
    }
    if let Ok(entries) = fs::read_dir(dev.icon_dir()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !valid_icon_file(&name) {
                continue;
            }
            if let Ok(bytes) = fs::read(entry.path()) {
                let k = format!("icon:{name}");
                out.insert(k.clone(), LocalItem { name: None, digest: digest(key, &k, &bytes), secret: None, file: Some(base64::engine::general_purpose::STANDARD.encode(&bytes)) });
            }
        }
    }
    Ok(out)
}

/// One secret as a record's content and digest.
fn local_secret(dev: &Device, key: &[u8], info: crate::secrets::SecretInfo) -> Result<(String, LocalItem)> {
    let secret = dev.store.get(&info.name)?;
    let payload = SecretPayload {
        name: info.name.clone(),
        value: base64::engine::general_purpose::STANDARD.encode(&secret.value[..]),
        category: info.category.clone(),
        username: info.username.clone(),
        notes: info.notes.clone(),
        icon: info.icon.clone(),
        color: info.color.clone(),
        type_id: info.type_id.clone(),
        fields: info.fields.clone(),
    };
    let k = secret_key(&info.name);
    let canonical = Zeroizing::new(serde_json::to_vec(&payload).unwrap());
    let digest = digest(key, &k, &canonical);
    Ok((k, LocalItem { name: Some(info.name), digest, secret: Some(payload), file: None }))
}

fn secret_key(name: &str) -> String {
    format!("secret:{}", name.trim().to_lowercase())
}

fn digest(key: &[u8], record_key: &str, content: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(b"keylo-sync:content:");
    mac.update(record_key.as_bytes());
    mac.update(&[0]);
    mac.update(content);
    hex::encode(mac.finalize().into_bytes())
}

fn deletion_digest(key: &[u8], record_key: &str) -> String {
    digest(key, record_key, b"\0deleted")
}

/// Makes this device hold `winner` for `key`.
fn apply(dev: &Device, key: &str, winner: &Record, here: Option<&LocalItem>) -> Result<()> {
    if key.starts_with("secret:") {
        let local_name = here.and_then(|h| h.name.clone());
        if winner.deleted {
            if let Some(name) = local_name {
                dev.store.delete(&name)?;
            }
            return Ok(());
        }
        let p = winner.secret.as_ref().ok_or_else(|| Error::msg("the record has no content"))?;
        let draft = draft_of(p)?;
        if secret_key(&draft.name) != key {
            bail!("the record's name doesn't match it");
        }
        dev.store.save(&draft, local_name.as_deref())?;
        return Ok(());
    }
    let path = if let Some(name) = key.strip_prefix("file:") {
        dev.data_dir.join(name)
    } else if let Some(name) = key.strip_prefix("icon:") {
        dev.icon_dir().join(name)
    } else {
        bail!("unknown record");
    };
    if winner.deleted {
        let _ = fs::remove_file(path);
        return Ok(());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(winner.file.as_deref().unwrap_or(""))
        .map_err(|_| Error::msg("the record's content isn't valid"))?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    write_atomic(&path, &bytes)
}

fn draft_of(p: &SecretPayload) -> Result<SecretDraft> {
    let value = Zeroizing::new(
        base64::engine::general_purpose::STANDARD.decode(&p.value).map_err(|_| Error::msg("the record's value isn't valid"))?,
    );
    Ok(SecretDraft {
        name: normalize_name(&p.name)?,
        value,
        category: p.category.clone(),
        username: p.username.clone(),
        notes: p.notes.clone(),
        icon: p.icon.clone(),
        color: p.color.clone(),
        type_id: p.type_id.clone(),
        fields: p.fields.clone(),
    })
}

/// Saves the losing side of a conflict as "{name} (conflict {device} {time})". The name comes from
/// the losing version itself, so devices that see the same conflict make the same copy.
fn keep_conflict_copy(dev: &Device, lost: &Record, device: &str) -> Result<Option<String>> {
    let Some(p) = &lost.secret else { return Ok(None) };
    let mut draft = draft_of(p)?;
    let when = Utc.timestamp_millis_opt(lost.version as i64).single().unwrap_or_else(Utc::now).format("%Y-%m-%d %H%M");
    let device: String = device.chars().filter(|c| *c != '*').take(24).collect();
    let suffix = format!(" (conflict {device} {when})");
    let room = MAX_NAME_LENGTH.saturating_sub(suffix.encode_utf16().count());
    let base: String = draft.name.chars().take(room).collect();
    let name = format!("{}{suffix}", base.trim_end());
    if dev.store.exists(&name)? {
        return Ok(None);
    }
    draft.name = name.clone();
    dev.store.save(&draft, None)?;
    Ok(Some(name))
}

// ---------------------------------------------------------------------------- the join code

fn key_check(key: &[u8], vault: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(b"keylo-sync:check:");
    mac.update(vault.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The vault key as 52 base32 characters in groups of four: ABCD-EFGH-…
fn encode_code(key: &[u8]) -> String {
    let mut bits = 0u32;
    let mut count = 0;
    let mut chars = String::new();
    for &b in key {
        bits = (bits << 8) | b as u32;
        count += 8;
        while count >= 5 {
            count -= 5;
            chars.push(BASE32[((bits >> count) & 31) as usize] as char);
        }
    }
    if count > 0 {
        chars.push(BASE32[((bits << (5 - count)) & 31) as usize] as char);
    }
    chars.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

fn decode_code(code: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Zeroizing::new(Vec::new());
    let mut chars = 0;
    for c in code.chars().filter(|c| !c.is_whitespace() && *c != '-') {
        let c = c.to_ascii_uppercase();
        let v = BASE32.iter().position(|&x| x as char == c).ok_or_else(|| Error::msg("That isn't a join code (letters A–Z and digits 2–7)."))?;
        chars += 1;
        bits = (bits << 5) | v as u32;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    if chars != 52 || out.len() != 32 {
        bail!("A join code has 52 characters (13 groups of 4).");
    }
    Ok(out)
}

// ---------------------------------------------------------------------------- helpers

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let temp = path.with_file_name(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    fs::write(&temp, data)?;
    if let Err(e) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(e.into());
    }
    Ok(())
}

/// One sync at a time per data folder (the app and `keylo sync` may both try). A lock older than
/// five minutes is from a sync that died, and is taken over.
struct SyncLock(PathBuf);

impl SyncLock {
    fn take(dir: &Path) -> Result<SyncLock> {
        fs::create_dir_all(dir)?;
        let path = dir.join("sync.lock");
        for _ in 0..2 {
            match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(SyncLock(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .map(|t| t.elapsed().map(|d| d.as_secs() > 300).unwrap_or(false))
                        .unwrap_or(true);
                    if !stale {
                        bail!("Keylo is already syncing; try again in a moment.");
                    }
                    let _ = fs::remove_file(&path);
                }
                Err(e) => return Err(e.into()),
            }
        }
        bail!("Keylo is already syncing; try again in a moment.")
    }
}

impl Drop for SyncLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    fn device() -> Device {
        let dir = testing::setup();
        let prefix = testing::prefix();
        Device { store: SecretStore::new(Some(&dir), Some(&prefix)), data_dir: dir }
    }

    fn folder() -> PathBuf {
        let d = std::env::temp_dir().join(format!("keylo-sync-test-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn put(dev: &Device, name: &str, value: &str) {
        let original = dev.store.find(name).unwrap().map(|s| s.name);
        let draft = SecretDraft { name: name.into(), value: Zeroizing::new(value.as_bytes().to_vec()), category: Some("dev".into()), ..Default::default() };
        dev.store.save(&draft, original.as_deref()).unwrap();
    }

    fn value(dev: &Device, name: &str) -> Option<String> {
        dev.store.find(name).unwrap()?;
        Some(String::from_utf8(dev.store.get(name).unwrap().value.to_vec()).unwrap())
    }

    fn names(dev: &Device) -> Vec<String> {
        dev.store.list().unwrap().into_iter().map(|s| s.name).collect()
    }

    fn pair() -> (Device, Device, PathBuf) {
        let (a, b, f) = (device(), device(), folder());
        create(&a, &f, "Desktop").unwrap();
        join(&b, &f, "Laptop", &join_code(&a).unwrap()).unwrap();
        (a, b, f)
    }

    #[test]
    fn a_joining_device_gets_everything_and_changes_flow_both_ways() {
        let (a, f) = (device(), folder());
        put(&a, "github-token", "gh1");
        put(&a, "prod-db", "pg1");
        create(&a, &f, "Desktop").unwrap();

        let b = device();
        let r = join(&b, &f, "Laptop", &join_code(&a).unwrap()).unwrap();
        assert_eq!(r.received, 2);
        assert_eq!(value(&b, "prod-db").as_deref(), Some("pg1"));
        assert_eq!(b.store.find("prod-db").unwrap().unwrap().category.as_deref(), Some("dev"));

        // Laptop edits one, adds one; the desktop picks both up.
        put(&b, "prod-db", "pg2");
        put(&b, "stripe", "sk1");
        assert_eq!(sync(&b).unwrap().sent, 2);
        let r = sync(&a).unwrap();
        assert_eq!(r.received, 2);
        assert_eq!(value(&a, "prod-db").as_deref(), Some("pg2"));
        assert_eq!(value(&a, "stripe").as_deref(), Some("sk1"));

        // The desktop deletes one; the laptop deletes it too.
        a.store.delete("github-token").unwrap();
        sync(&a).unwrap();
        sync(&b).unwrap();
        assert_eq!(value(&b, "github-token"), None);

        // Nothing changed: nothing moves, and the deletion doesn't come back.
        let r = sync(&a).unwrap();
        assert_eq!((r.received, r.sent), (0, 0));
        assert_eq!(names(&a), ["prod-db", "stripe"]);
        assert_eq!(status(&a).unwrap().unwrap().devices.len(), 2);
    }

    #[test]
    fn concurrent_edits_keep_the_losing_version_as_a_copy() {
        let (a, b, _) = pair();
        put(&a, "api", "v0");
        sync(&a).unwrap();
        sync(&b).unwrap();

        put(&a, "api", "from-desktop");
        sync(&a).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        put(&b, "api", "from-laptop"); // made later, without having seen the desktop's edit
        let r = sync(&b).unwrap();
        assert_eq!(r.conflicts.len(), 1, "{:?}", r.conflicts);
        assert_eq!(value(&b, "api").as_deref(), Some("from-laptop"));
        let copy = &r.conflicts[0];
        assert!(copy.starts_with("api (conflict Desktop "), "{copy}");
        assert_eq!(value(&b, copy).as_deref(), Some("from-desktop"));

        // The desktop converges on the same two secrets, without making a second copy.
        let r = sync(&a).unwrap();
        assert!(r.conflicts.is_empty());
        assert_eq!(value(&a, "api").as_deref(), Some("from-laptop"));
        assert_eq!(value(&a, copy).as_deref(), Some("from-desktop"));
        sync(&b).unwrap();
        assert_eq!(names(&a), names(&b));
    }

    #[test]
    fn a_joining_device_keeps_its_own_version_of_a_name_as_a_copy() {
        let (a, f) = (device(), folder());
        put(&a, "db", "shared");
        create(&a, &f, "Desktop").unwrap();

        let b = device();
        put(&b, "db", "laptop-only");
        put(&b, "notes", "n");
        let r = join(&b, &f, "Laptop", &join_code(&a).unwrap()).unwrap();
        assert_eq!(value(&b, "db").as_deref(), Some("shared"));
        assert_eq!(r.conflicts.len(), 1);
        assert_eq!(value(&b, &r.conflicts[0]).as_deref(), Some("laptop-only"));

        sync(&a).unwrap();
        assert_eq!(value(&a, "notes").as_deref(), Some("n"));
        assert_eq!(value(&a, "db").as_deref(), Some("shared"));
    }

    #[test]
    fn changes_reach_a_third_device_while_their_author_is_away() {
        let (a, b, f) = pair();
        let c = device();
        join(&c, &f, "Server", &join_code(&b).unwrap()).unwrap();
        put(&a, "only-on-desktop", "x");
        sync(&a).unwrap();
        sync(&b).unwrap();
        forget(&b, &status(&a).unwrap().unwrap().device_id).unwrap(); // the desktop's file is gone
        sync(&c).unwrap();
        assert_eq!(value(&c, "only-on-desktop").as_deref(), Some("x"));
    }

    #[test]
    fn a_wiped_store_doesnt_delete_secrets_everywhere() {
        let (a, b, _) = pair();
        for i in 0..8 {
            put(&a, &format!("s{i}"), "v");
        }
        sync(&a).unwrap();
        sync(&b).unwrap();
        for i in 0..8 {
            a.store.delete(&format!("s{i}")).unwrap(); // as if the OS store was reset
        }
        let e = sync(&a).unwrap_err().to_string();
        assert!(e.contains("missing on this device"), "{e}");
        sync(&b).unwrap();
        assert_eq!(names(&b).len(), 8, "nothing was deleted on the other device");
        assert!(!status(&a).unwrap().unwrap().last.unwrap().ok);

        // Leaving and joining again brings them back.
        leave(&a).unwrap();
        join(&a, &status(&b).unwrap().unwrap().folder, "Desktop", &join_code(&b).unwrap()).unwrap();
        assert_eq!(names(&a).len(), 8);

        // Deleting a few is fine.
        a.store.delete("s0").unwrap();
        sync(&a).unwrap();
        sync(&b).unwrap();
        assert_eq!(names(&b).len(), 7);
    }

    #[test]
    fn custom_types_and_category_styles_sync_too() {
        let (a, b, _) = pair();
        fs::write(a.data_dir.join("categories.json"), br#"{"dev":{"icon":"Code24"}}"#).unwrap();
        sync(&a).unwrap();
        sync(&b).unwrap();
        assert_eq!(fs::read_to_string(b.data_dir.join("categories.json")).unwrap(), r#"{"dev":{"icon":"Code24"}}"#);
    }

    #[test]
    fn codes_round_trip_and_a_wrong_one_is_refused() {
        let key: Vec<u8> = (0u8..32).collect();
        let code = encode_code(&key);
        assert_eq!(code.len(), 52 + 12);
        assert_eq!(&decode_code(&code.to_lowercase().replace('-', " ")).unwrap()[..], &key[..]);
        assert!(decode_code("ABCD").is_err());

        let (a, f) = (device(), folder());
        create(&a, &f, "Desktop").unwrap();
        let b = device();
        assert!(join(&b, &f, "Laptop", &encode_code(&[7u8; 32])).is_err());
        assert!(status(&b).unwrap().is_none());
        assert!(create(&b, &f, "Laptop").is_err(), "a folder can't hold two vaults");
    }

    #[test]
    fn the_folder_holds_no_readable_secrets() {
        let (a, f) = (device(), folder());
        put(&a, "prod-db", "super-secret-value");
        create(&a, &f, "Desktop").unwrap();
        for entry in fs::read_dir(f.join(DEVICES_DIR)).unwrap().flatten() {
            let bytes = fs::read(entry.path()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("super-secret") && !text.contains("prod-db"));
        }
        // And a file renamed to another device's id doesn't decrypt.
        let id = status(&a).unwrap().unwrap().device_id;
        let data = fs::read(device_path(&f, &id)).unwrap();
        assert!(open(&load_key(&a).unwrap(), "0123abcd", &data).is_err());
    }
}
