//! Keylo on Linux: the desktop keyring (Secret Service) where there is one, else Keylo's own
//! passphrase-protected vault file; polkit for the presence check; wl-clipboard / xclip / xsel;
//! /proc for process ancestry; logind for the screen lock; zenity / kdialog for approvals.
//!
//! The store is chosen once and remembered (store.txt in Keylo's data folder), so a machine never
//! ends up with secrets split between the two. KEYLO_STORE=keyring|file overrides the choice.

mod keycache;
mod keyring;
pub mod vault;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use hkdf::Hkdf;
use keylo_core::platform::{
    AncestorProcess, CredentialDetails, CredentialStore, DataProtector, Platform, ProcessAncestry, RawCredential,
    SecureClipboard, UserVerifier, VerificationResult,
};
use keylo_core::{bail, paths, Error, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::sqlite_vault::{OsKey, SqliteVault};
use crate::unix::{self, AesKeyProtector};
use keyring::SecretServiceStore;
use vault::FileVault;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    Keyring,
    File,
}

struct Shared {
    data_dir: PathBuf,
    vault: FileVault,
    kind: OnceLock<std::result::Result<StoreKind, String>>,
    /// The keyring store, the SQLite vault with its key kept in the desktop keyring.
    keyring_vault: KeyringVaultStore,
}

impl Shared {
    fn kind(&self) -> Result<StoreKind> {
        self.kind.get_or_init(|| choose_store(&self.data_dir, &self.vault)).clone().map_err(Error::msg)
    }

    fn store(&self) -> Result<&dyn CredentialStore> {
        Ok(match self.kind()? {
            StoreKind::Keyring => &self.keyring_vault,
            StoreKind::File => &self.vault,
        })
    }

    /// Records the store on the first write, so later runs use the same one.
    fn remember(&self) {
        let file = self.data_dir.join("store.txt");
        if std::env::var("KEYLO_STORE").is_ok_and(|s| !s.is_empty()) || file.exists() {
            return;
        }
        if let Ok(kind) = self.kind() {
            let _ = std::fs::create_dir_all(&self.data_dir);
            let _ = std::fs::write(file, if kind == StoreKind::Keyring { "keyring\n" } else { "file\n" });
        }
    }
}

fn choose_store(data_dir: &Path, vault: &FileVault) -> std::result::Result<StoreKind, String> {
    let setting = std::env::var("KEYLO_STORE").ok().filter(|s| !s.is_empty()).or_else(|| std::fs::read_to_string(data_dir.join("store.txt")).ok());
    match setting.as_deref().map(|s| s.trim().to_lowercase()).as_deref() {
        Some("keyring") => {
            return match SecretServiceStore::probe() {
                Ok(()) => Ok(StoreKind::Keyring),
                Err(problem) => Err(format!(
                    "Keylo keeps its secrets in the desktop keyring here, but the keyring isn't available ({problem}). \
                     Use Keylo from your desktop session, or unlock the keyring first."
                )),
            }
        }
        Some("file") => return Ok(StoreKind::File),
        _ => {}
    }
    if vault.exists() {
        return Ok(StoreKind::File);
    }
    Ok(if SecretServiceStore::probe().is_ok() { StoreKind::Keyring } else { StoreKind::File })
}

/// Picks the store on first use rather than at startup, so 'keylo version' never touches it.
struct LazyStore(&'static Shared);

impl CredentialStore for LazyStore {
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
        self.0.store()?.read(target)
    }
    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
        self.0.store()?.enumerate(prefix)
    }
    fn write(&self, target: &str, blob: &[u8], user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<()> {
        self.0.store()?.write(target, blob, user_name, comment, attributes)?;
        self.0.remember();
        Ok(())
    }
    fn delete(&self, target: &str) -> Result<bool> {
        self.0.store()?.delete(target)
    }
}

pub struct LinuxPlatform {
    shared: &'static Shared,
    credentials: LazyStore,
    protector: AesKeyProtector,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        let data_dir = paths::data_dir();
        let vault_path = data_dir.join("vault.json");
        let db_path = data_dir.join("keylo.db");
        let shared: &'static Shared = Box::leak(Box::new(Shared {
            vault: FileVault::new(vault_path),
            keyring_vault: KeyringVaultStore { sqlite: SqliteVault::new(db_path, Box::new(KeyringKey)), moved: Mutex::new(false) },
            data_dir,
            kind: OnceLock::new(),
        }));
        let protector = AesKeyProtector::new(move || match shared.kind()? {
            StoreKind::Keyring => keyring_master_key(),
            StoreKind::File => {
                // The files key is derived from the vault key.
                let vault_key = shared.vault.vault_key()?;
                let mut key = Zeroizing::new(vec![0u8; 32]);
                Hkdf::<Sha256>::new(None, &vault_key).expand(b"keylo-vault:files:v1", &mut key).map_err(|_| Error::msg("HKDF failed."))?;
                Ok(key)
            }
        });
        LinuxPlatform { shared, credentials: LazyStore(shared), protector }
    }
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

/// The key for protected files with the keyring store: a random key in the keyring, under its own service.
fn keyring_master_key() -> Result<Zeroizing<Vec<u8>>> {
    const ITEM: &str = "keylo-master-key";
    let store = SecretServiceStore::new(&format!("{}.Internal", keyring::DEFAULT_SERVICE));
    if let Some(existing) = store.read(ITEM)?.filter(|c| c.blob.len() == 32) {
        return Ok(existing.blob);
    }
    let key = unix::random_key();
    store.write(ITEM, &key, None, Some("Keylo's key for its encrypted local files. Deleting it makes those files unreadable."), &BTreeMap::new())?;
    Ok(key)
}

const VAULT_KEY_ENTROPY: &[u8] = b"keylo-vault-key:v1";

/// The vault key, sealed under Keylo's keyring-stored master key — so the vault opens whenever the
/// desktop keyring is unlocked, as DPAPI/Keychain do for Windows/macOS.
struct KeyringKey;

impl OsKey for KeyringKey {
    fn kind(&self) -> &'static str {
        "keyring"
    }
    fn protect(&self, key: &[u8]) -> Result<Vec<u8>> {
        crate::crypto::seal(&keyring_master_key()?, key, VAULT_KEY_ENTROPY)
    }
    fn unprotect(&self, stored: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crate::crypto::open(&keyring_master_key()?, stored, VAULT_KEY_ENTROPY)
            .ok_or_else(|| Error::msg("Couldn't open Keylo's vault: its key didn't unseal (the keyring master key changed?)."))
    }
}

/// The keyring store: the SQLite vault, after moving in any secrets an earlier Keylo kept as keyring
/// items. Headless machines use the file vault instead (see [`FileVault`]).
struct KeyringVaultStore {
    sqlite: SqliteVault,
    /// Whether the move from keyring items has been done (or wasn't needed).
    moved: Mutex<bool>,
}

/// Move keyring items into the vault only for the real setup, or a test that names its own prefix —
/// never drag the real keyring into a throwaway KEYLO_HOME vault.
fn keyring_migrates() -> bool {
    let set = |v: &str| std::env::var(v).is_ok_and(|s| !s.is_empty());
    !set("KEYLO_HOME") || set("KEYLO_PREFIX")
}

impl KeyringVaultStore {
    fn ready(&self) -> Result<&SqliteVault> {
        let mut moved = self.moved.lock().unwrap();
        if !*moved {
            if keyring_migrates() {
                let legacy = SecretServiceStore::new(keyring::DEFAULT_SERVICE);
                crate::sqlite_vault::absorb(&self.sqlite, &legacy, &paths::credential_prefix()).map_err(Error::msg)?;
            }
            *moved = true;
        }
        Ok(&self.sqlite)
    }
}

impl CredentialStore for KeyringVaultStore {
    fn max_blob_bytes(&self) -> usize {
        self.sqlite.max_blob_bytes()
    }
    fn max_attribute_bytes(&self) -> usize {
        self.sqlite.max_attribute_bytes()
    }
    fn max_attributes(&self) -> usize {
        self.sqlite.max_attributes()
    }
    fn read(&self, target: &str) -> Result<Option<RawCredential>> {
        self.ready()?.read(target)
    }
    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
        self.ready()?.enumerate(prefix)
    }
    fn write(&self, target: &str, blob: &[u8], user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<()> {
        self.ready()?.write(target, blob, user_name, comment, attributes)
    }
    fn delete(&self, target: &str) -> Result<bool> {
        self.ready()?.delete(target)
    }
    fn enumerate_details(&self, prefix: &str) -> Result<Vec<CredentialDetails>> {
        self.ready()?.enumerate_details(prefix)
    }
    fn read_details(&self, target: &str) -> Result<Option<CredentialDetails>> {
        self.ready()?.read_details(target)
    }
    fn update_details(&self, target: &str, user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<bool> {
        self.ready()?.update_details(target, user_name, comment, attributes)
    }
}

impl Platform for LinuxPlatform {
    fn name(&self) -> &str {
        "Linux"
    }
    fn credentials(&self) -> &dyn CredentialStore {
        &self.credentials
    }
    fn data_protector(&self) -> &dyn DataProtector {
        &self.protector
    }
    fn verifier(&self) -> &dyn UserVerifier {
        &PolkitVerifier
    }
    fn verifier_name(&self) -> String {
        "system authentication".into()
    }
    fn store_name(&self) -> String {
        match self.shared.kind() {
            Ok(StoreKind::File) => "Keylo's encrypted vault".into(),
            _ => "Keylo's vault (key in the desktop keyring)".into(),
        }
    }
    fn file_protection_name(&self) -> String {
        match self.shared.kind() {
            Ok(StoreKind::File) => "vault key".into(),
            _ => "keyring key".into(),
        }
    }
    fn clipboard(&self) -> &dyn SecureClipboard {
        &LinuxClipboard
    }
    fn processes(&self) -> &dyn ProcessAncestry {
        &ProcAncestry
    }
}

static INSTALLED: OnceLock<&'static Shared> = OnceLock::new();

pub(crate) fn install() {
    let platform = LinuxPlatform::new();
    let _ = INSTALLED.set(platform.shared);
    keylo_core::platform::install(Box::new(platform));
}

/// The vault, when it's the store in use.
fn vault() -> Option<&'static FileVault> {
    let shared = INSTALLED.get()?;
    (shared.kind().ok()? == StoreKind::File).then_some(&shared.vault)
}

/// `keylo unlock`: unlocks the vault (asking for the passphrase); None with the keyring.
pub(crate) fn unlock_store() -> Result<Option<String>> {
    match vault() {
        Some(v) => {
            v.vault_key()?;
            Ok(Some("Vault unlocked.".into()))
        }
        None => Ok(None),
    }
}

pub(crate) fn lock_store() {
    if let Some(v) = vault() {
        v.lock();
    }
}

/// "Store: ..." for `keylo status`.
pub(crate) fn store_status() -> Option<String> {
    let shared = INSTALLED.get()?;
    Some(match shared.kind() {
        Ok(StoreKind::Keyring) => "Keylo's vault (key in the desktop keyring)".into(),
        Ok(StoreKind::File) => {
            let state = if shared.vault.try_unlock_quietly().unwrap_or(false) { "unlocked" } else { "locked" };
            format!("Keylo's encrypted vault ({}, {state})", shared.vault.path().display())
        }
        Err(e) => format!("unavailable: {e}"),
    })
}

// ---------------------------------------------------------------------------- polkit

pub const POLKIT_ACTION: &str = "io.github.tulde23.keylo.verify";
pub const POLKIT_POLICY: &str = "/usr/share/polkit-1/actions/io.github.tulde23.keylo.policy";

/// The presence check through polkit: the user authenticates as themselves (password, or
/// fingerprint with fprintd) in the desktop's polkit prompt, or on the terminal (pkttyagent).
struct PolkitVerifier;

impl UserVerifier for PolkitVerifier {
    fn verify(&self, _owner: isize, message: &str) -> (VerificationResult, Option<String>) {
        let Some(pkcheck) = unix::find("pkcheck") else {
            return (VerificationResult::Unavailable, Some("polkit isn't installed".into()));
        };
        if !Path::new(POLKIT_POLICY).exists() {
            return (
                VerificationResult::Unavailable,
                Some(format!("Keylo's polkit policy isn't installed ({POLKIT_POLICY}); run Keylo's install.sh")),
            );
        }
        let pid = std::process::id();
        let Some(start) = start_time(pid) else { return (VerificationResult::Failed, Some("couldn't read /proc".into())) };
        let subject = format!("{pid},{start}");

        // No desktop (SSH, a plain terminal): a text agent so polkit can ask here.
        let terminal = vault::CAN_PROMPT_ON_TERMINAL.load(std::sync::atomic::Ordering::Relaxed);
        let mut agent = None;
        if !unix::has_display() && terminal {
            if let Some(tty_agent) = unix::find("pkttyagent") {
                agent = std::process::Command::new(tty_agent).args(["--process", &subject, "--fallback"]).spawn().ok();
                std::thread::sleep(std::time::Duration::from_millis(300)); // let it register
                eprintln!("{message}");
            }
        }
        let out = unix::run(&pkcheck, &["--action-id", POLKIT_ACTION, "--process", &subject, "--allow-user-interaction"], None, true);
        if let Some(mut a) = agent {
            let _ = a.kill();
            let _ = a.wait();
        }
        let no_agent = "there's no polkit agent to ask for your password (no desktop session)";
        match out {
            Err(e) => (VerificationResult::Failed, Some(e.to_string())),
            Ok(o) => match o.code {
                0 => (VerificationResult::Verified, None),
                3 => (VerificationResult::Canceled, None),
                2 => (VerificationResult::Unavailable, Some(no_agent.into())),
                1 if o.stderr.to_lowercase().contains("no authentication agent") => (VerificationResult::Unavailable, Some(no_agent.into())),
                _ => (VerificationResult::Failed, (!o.stderr.is_empty()).then_some(o.stderr)),
            },
        }
    }
}

/// /proc/PID/stat: (parent pid, command name, start time in clock ticks).
fn stat(pid: u32) -> Option<(u32, String, String)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let name = text[open + 1..close].to_string();
    let fields: Vec<&str> = text.get(close + 2..)?.split(' ').collect();
    Some((fields.get(1)?.parse().ok()?, name, fields.get(19)?.to_string()))
}

fn start_time(pid: u32) -> Option<String> {
    stat(pid).map(|s| s.2)
}

struct ProcAncestry;

impl ProcessAncestry for ProcAncestry {
    fn current(&self, max_depth: usize) -> Vec<AncestorProcess> {
        let mut chain = Vec::new();
        let mut next = stat(std::process::id()).map(|s| s.0);
        while let Some(pid) = next.filter(|p| *p > 1) {
            if chain.len() >= max_depth {
                break;
            }
            let Some((parent, name, _)) = stat(pid) else { break };
            chain.push(AncestorProcess { process_id: pid, executable_name: name });
            next = Some(parent);
        }
        chain
    }
}

// ---------------------------------------------------------------------------- clipboard

/// wl-clipboard (Wayland) or xclip / xsel (X11). There's no change counter, so the token is a hash
/// of what was copied: clearing checks the clipboard still holds it.
struct LinuxClipboard;

fn clipboard_token(text: &str) -> u32 {
    let d = Sha256::digest(text.as_bytes());
    u32::from_le_bytes([d[0], d[1], d[2], d[3]])
}

fn backend(operation: &str) -> Result<(PathBuf, Vec<&'static str>)> {
    if std::env::var("WAYLAND_DISPLAY").is_ok_and(|v| !v.is_empty()) {
        if operation == "get" {
            if let Some(p) = unix::find("wl-paste") {
                return Ok((p, vec!["--no-newline"]));
            }
        } else if let Some(c) = unix::find("wl-copy") {
            return Ok((c, if operation == "clear" { vec!["--clear"] } else { vec![] }));
        }
    }
    if std::env::var("DISPLAY").is_ok_and(|v| !v.is_empty()) {
        if let Some(x) = unix::find("xclip") {
            return Ok((x, if operation == "get" { vec!["-selection", "clipboard", "-out"] } else { vec!["-selection", "clipboard", "-in"] }));
        }
        if let Some(x) = unix::find("xsel") {
            let args = match operation {
                "get" => vec!["--clipboard", "--output"],
                "clear" => vec!["--clipboard", "--clear"],
                _ => vec!["--clipboard", "--input"],
            };
            return Ok((x, args));
        }
    }
    if unix::has_display() {
        bail!("Copying needs wl-clipboard (Wayland) or xclip (X11). Install one, e.g. 'sudo apt install wl-clipboard xclip'.")
    }
    bail!("There's no desktop session here, so there's no clipboard. Use 'keylo get NAME' instead.")
}

impl SecureClipboard for LinuxClipboard {
    fn set_text(&self, text: &str) -> Result<u32> {
        let (program, args) = backend("set")?;
        let out = unix::run(&program, &args, Some(text), false)?;
        if out.code != 0 {
            bail!("Couldn't copy to the clipboard ({} failed).", program.file_name().unwrap_or_default().to_string_lossy());
        }
        Ok(clipboard_token(text))
    }

    fn clear_if_unchanged(&self, token: u32) -> bool {
        let Ok((get, get_args)) = backend("get") else { return false };
        let Ok(current) = unix::run(&get, &get_args, None, true) else { return false };
        if current.code != 0 || clipboard_token(&current.stdout) != token {
            return false;
        }
        let Ok((clear, clear_args)) = backend("clear") else { return false };
        let stdin = clear.ends_with("xclip").then_some("");
        unix::run(&clear, &clear_args, stdin, false).is_ok_and(|o| o.code == 0)
    }
}

// ---------------------------------------------------------------------------- session and dialogs

/// True while the screen is locked (logind's LockedHint, set by GNOME, KDE and others).
pub(crate) fn is_screen_locked() -> bool {
    let Some(loginctl) = unix::find("loginctl") else { return false };
    let session = std::env::var("XDG_SESSION_ID").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "self".into());
    unix::run(&loginctl, &["show-session", &session, "-p", "LockedHint", "--value"], None, true)
        .is_ok_and(|o| o.code == 0 && o.stdout.trim() == "yes")
}

/// The MCP server's approval without the app: zenity or kdialog. 10 deny, 11 once, 12 always.
pub(crate) fn approval_dialog(title: &str, message: &str, allow_always: bool) -> Result<i32> {
    if !unix::has_display() {
        bail!("There's no desktop session to ask for approval in. Add the secrets to the access key instead ('keylo keys').");
    }
    let text = format!("{title}\n\n{message}");
    if let Some(zenity) = unix::find("zenity") {
        let text_arg = format!("--text={text}");
        let mut args = vec![
            "--question", "--no-markup", "--width=460", "--icon-name=dialog-warning", "--title=Keylo", &text_arg,
            "--ok-label=Allow once", "--cancel-label=Deny",
        ];
        if allow_always {
            args.push("--extra-button=Always allow");
        }
        let out = unix::run(&zenity, &args, None, true)?;
        return Ok(if out.code == 0 { 11 } else if out.stdout.trim() == "Always allow" { 12 } else { 10 });
    }
    if let Some(kdialog) = unix::find("kdialog") {
        let out = if allow_always {
            unix::run(&kdialog, &["--title", "Keylo", "--warningyesnocancel", &text, "--yes-label", "Allow once", "--no-label", "Always allow", "--cancel-label", "Deny"], None, true)?
        } else {
            unix::run(&kdialog, &["--title", "Keylo", "--warningyesno", &text, "--yes-label", "Allow once", "--no-label", "Deny"], None, true)?
        };
        return Ok(match out.code {
            0 => 11,
            1 if allow_always => 12,
            _ => 10,
        });
    }
    bail!("Approving access needs zenity or kdialog. Install one, e.g. 'sudo apt install zenity'.")
}
