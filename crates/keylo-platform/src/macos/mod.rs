//! Keylo on macOS: the login keychain, Touch ID, a concealed pasteboard and ps for process info.
//! Touch ID, the pasteboard and approval alerts need Apple's Objective-C frameworks, so they go
//! through keylo-mac, the small Swift helper installed next to keylo
//! (packaging/macos/keylo-mac.swift).

mod keychain;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use hkdf::Hkdf;
use keylo_core::platform::{
    AncestorProcess, CredentialDetails, CredentialStore, DataProtector, Platform, ProcessAncestry, RawCredential,
    SecureClipboard, UserVerifier, VerificationResult,
};
use keylo_core::{bail, paths, Error, Result};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::file_vault::FileVault;
use crate::sqlite_vault::{OsKey, SqliteVault};
use crate::unix::{self, AesKeyProtector};
use keychain::KeychainStore;

/// The Keychain scope: KEYLO_KEYCHAIN (a throwaway keychain for tests, or an SSH session where the
/// login keychain is locked), else the login keychain.
fn keychain_path() -> Option<String> {
    std::env::var("KEYLO_KEYCHAIN").ok().filter(|p| !p.is_empty())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// The SQLite vault, its key sealed under a login-Keychain master key (a desktop session).
    Keychain,
    /// Keylo's passphrase-protected vault file, for a headless/SSH session where the Keychain can't
    /// be reached without a prompt (the same store Linux uses without a desktop keyring).
    File,
}

struct Shared {
    data_dir: PathBuf,
    file: FileVault,
    keychain: MacVaultStore,
    kind: OnceLock<std::result::Result<StoreKind, String>>,
}

impl Shared {
    fn kind(&self) -> Result<StoreKind> {
        self.kind.get_or_init(|| choose_store(&self.data_dir, &self.file)).clone().map_err(Error::msg)
    }

    fn store(&self) -> Result<&dyn CredentialStore> {
        Ok(match self.kind()? {
            StoreKind::Keychain => &self.keychain,
            StoreKind::File => &self.file,
        })
    }

    /// Records the store on the first write, so later runs use the same one and secrets never split.
    fn remember(&self) {
        let file = self.data_dir.join("store.txt");
        if std::env::var("KEYLO_STORE").is_ok_and(|s| !s.is_empty()) || file.exists() {
            return;
        }
        if let Ok(kind) = self.kind() {
            let _ = std::fs::create_dir_all(&self.data_dir);
            let _ = std::fs::write(file, if kind == StoreKind::Keychain { "keychain\n" } else { "file\n" });
        }
    }
}

/// Keychain-sealed vault in a desktop session, else the passphrase vault file. KEYLO_STORE
/// (keychain|file) or store.txt override; an existing vault.json or keylo.db stays the store it is.
fn choose_store(data_dir: &Path, file: &FileVault) -> std::result::Result<StoreKind, String> {
    let setting = std::env::var("KEYLO_STORE").ok().filter(|s| !s.is_empty()).or_else(|| std::fs::read_to_string(data_dir.join("store.txt")).ok());
    match setting.as_deref().map(|s| s.trim().to_lowercase()).as_deref() {
        Some("file") => return Ok(StoreKind::File),
        Some("keychain") => {
            return if keychain_reachable() {
                Ok(StoreKind::Keychain)
            } else {
                Err("Keylo's vault is sealed in this Mac's login Keychain, but this session can't reach it \
                     (no desktop session, e.g. over SSH). Use Keylo on the Mac itself, or set KEYLO_STORE=file \
                     to keep secrets in a passphrase-protected vault here instead."
                    .into())
            };
        }
        _ => {}
    }
    // Stick with whichever store already holds secrets.
    if file.exists() {
        return Ok(StoreKind::File);
    }
    if data_dir.join("keylo.db").exists() {
        return Ok(StoreKind::Keychain);
    }
    // Fresh: the Keychain in a desktop session, else the passphrase vault.
    Ok(if has_graphic_access() { StoreKind::Keychain } else { StoreKind::File })
}

/// Whether this process is in a session with a window server (a desktop login) — false over SSH.
fn has_graphic_access() -> bool {
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SessionGetInfo(session: i32, id: *mut i32, attributes: *mut u32) -> i32;
    }
    const CALLER_SECURITY_SESSION: i32 = -1;
    const SESSION_HAS_GRAPHIC_ACCESS: u32 = 0x0010;
    let (mut id, mut attributes) = (0i32, 0u32);
    let ok = unsafe { SessionGetInfo(CALLER_SECURITY_SESSION, &mut id, &mut attributes) } == 0;
    ok && attributes & SESSION_HAS_GRAPHIC_ACCESS != 0
}

/// Whether the login Keychain can be read here without a prompt (false only when macOS would need to
/// ask and can't — errSecInteractionNotAllowed, e.g. over SSH).
fn keychain_reachable() -> bool {
    let internal = KeychainStore::new(&format!("{}.Internal", keychain::DEFAULT_SERVICE), keychain_path().as_deref());
    internal.reachable("keylo-master-key")
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
    fn enumerate_details(&self, prefix: &str) -> Result<Vec<CredentialDetails>> {
        self.0.store()?.enumerate_details(prefix)
    }
    fn read_details(&self, target: &str) -> Result<Option<CredentialDetails>> {
        self.0.store()?.read_details(target)
    }
    fn update_details(&self, target: &str, user_name: Option<&str>, comment: Option<&str>, attributes: &BTreeMap<String, String>) -> Result<bool> {
        self.0.store()?.update_details(target, user_name, comment, attributes)
    }
}

pub struct MacPlatform {
    shared: &'static Shared,
    credentials: LazyStore,
    protector: AesKeyProtector,
}

impl MacPlatform {
    pub fn new() -> Self {
        let data_dir = paths::data_dir();
        let shared: &'static Shared = Box::leak(Box::new(Shared {
            file: FileVault::new(data_dir.join("vault.json")),
            keychain: MacVaultStore { vault: vault(), moved: Mutex::new(false) },
            data_dir,
            kind: OnceLock::new(),
        }));
        // The files key: with the Keychain store, Keylo's master key from the login Keychain (which
        // also seals large values and the session); with the file vault, a key derived from the vault
        // key, as on Linux.
        let protector = AesKeyProtector::new(move || match shared.kind()? {
            StoreKind::Keychain => {
                let internal = KeychainStore::new(&format!("{}.Internal", keychain::DEFAULT_SERVICE), keychain_path().as_deref());
                master_key(&internal)
            }
            StoreKind::File => {
                let vault_key = shared.file.vault_key()?;
                let mut key = Zeroizing::new(vec![0u8; 32]);
                Hkdf::<Sha256>::new(None, &vault_key).expand(b"keylo-vault:files:v1", &mut key).map_err(|_| Error::msg("HKDF failed."))?;
                Ok(key)
            }
        });
        MacPlatform { shared, credentials: LazyStore(shared), protector }
    }
}

impl Default for MacPlatform {
    fn default() -> Self {
        Self::new()
    }
}

/// The key that seals local files (large values, the session), created on first use.
fn master_key(store: &KeychainStore) -> Result<Zeroizing<Vec<u8>>> {
    const ITEM: &str = "keylo-master-key";
    if let Some(existing) = store.read(ITEM)?.filter(|c| c.blob.len() == 32) {
        return Ok(existing.blob);
    }
    let key = unix::random_key();
    store.write(ITEM, &key, None, Some("Keylo's key for its encrypted local files. Deleting it makes those files unreadable."), &BTreeMap::new())?;
    Ok(key)
}

impl Platform for MacPlatform {
    fn name(&self) -> &str {
        "macOS"
    }
    fn credentials(&self) -> &dyn CredentialStore {
        &self.credentials
    }
    fn data_protector(&self) -> &dyn DataProtector {
        &self.protector
    }
    fn verifier(&self) -> &dyn UserVerifier {
        &TouchId
    }
    fn verifier_name(&self) -> String {
        "Touch ID".into()
    }
    fn store_name(&self) -> String {
        match self.shared.kind() {
            Ok(StoreKind::File) => "Keylo's encrypted vault".into(),
            _ => "Keylo's vault".into(),
        }
    }
    fn file_protection_name(&self) -> String {
        match self.shared.kind() {
            Ok(StoreKind::File) => "vault key".into(),
            _ => "Keychain key".into(),
        }
    }
    fn clipboard(&self) -> &dyn SecureClipboard {
        &Pasteboard
    }
    fn processes(&self) -> &dyn ProcessAncestry {
        &PsAncestry
    }
}

static INSTALLED: OnceLock<&'static Shared> = OnceLock::new();

pub(crate) fn install() {
    let platform = MacPlatform::new();
    let _ = INSTALLED.set(platform.shared);
    keylo_core::platform::install(Box::new(platform));
}

/// The chosen store kind, once the platform is installed.
fn kind() -> Option<StoreKind> {
    INSTALLED.get()?.kind().ok()
}

/// The passphrase vault file, when it's the store in use (a headless/SSH session).
fn file_vault() -> Option<&'static FileVault> {
    let shared = INSTALLED.get()?;
    (shared.kind().ok()? == StoreKind::File).then_some(&shared.file)
}

// ---------------------------------------------------------------------------- the SQLite vault

const VAULT_KEY_ENTROPY: &[u8] = b"keylo-vault-key:v1";

/// Protects the vault key with Keylo's Keychain-stored master key — the same key that seals local
/// files — so the vault is bound to this user's login keychain, as DPAPI binds it to the Windows
/// account on Windows.
struct KeychainKey;

impl KeychainKey {
    fn master() -> Result<Zeroizing<Vec<u8>>> {
        let store = KeychainStore::new(&format!("{}.Internal", keychain::DEFAULT_SERVICE), keychain_path().as_deref());
        master_key(&store)
    }
}

impl OsKey for KeychainKey {
    fn kind(&self) -> &'static str {
        "keychain"
    }
    fn protect(&self, key: &[u8]) -> Result<Vec<u8>> {
        crate::crypto::seal(&Self::master()?, key, VAULT_KEY_ENTROPY)
    }
    fn unprotect(&self, stored: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crate::crypto::open(&Self::master()?, stored, VAULT_KEY_ENTROPY)
            .ok_or_else(|| Error::msg("Couldn't open Keylo's vault: its key didn't unseal (wrong Keychain?)."))
    }
}

/// The one vault for this process, so the platform store and the passphrase/lock commands share it.
fn vault() -> &'static SqliteVault {
    static VAULT: OnceLock<&'static SqliteVault> = OnceLock::new();
    VAULT.get_or_init(|| Box::leak(Box::new(SqliteVault::new(paths::data_dir().join("keylo.db"), Box::new(KeychainKey)))))
}

/// Keylo's vault, after moving in any secrets an earlier Keylo kept in the login Keychain.
struct MacVaultStore {
    vault: &'static SqliteVault,
    /// Whether the move has been done (or wasn't needed). A failed move is tried again next time.
    moved: Mutex<bool>,
}

/// Move the Keychain's secrets into the vault only when it's the real setup, or a test that scopes its
/// own keychain or prefix — never drag the real login keychain into a throwaway KEYLO_HOME vault.
fn migrates() -> bool {
    let set = |v: &str| std::env::var(v).is_ok_and(|s| !s.is_empty());
    !set("KEYLO_HOME") || set("KEYLO_KEYCHAIN") || set("KEYLO_PREFIX")
}

impl MacVaultStore {
    fn ready(&self) -> Result<&SqliteVault> {
        let mut moved = self.moved.lock().unwrap();
        if !*moved {
            if migrates() {
                let legacy = KeychainStore::new(keychain::DEFAULT_SERVICE, keychain_path().as_deref());
                crate::sqlite_vault::absorb(self.vault, &legacy, &paths::credential_prefix()).map_err(Error::msg)?;
            }
            *moved = true;
        }
        Ok(self.vault)
    }
}

impl CredentialStore for MacVaultStore {
    fn max_blob_bytes(&self) -> usize {
        self.vault.max_blob_bytes()
    }
    fn max_attribute_bytes(&self) -> usize {
        self.vault.max_attribute_bytes()
    }
    fn max_attributes(&self) -> usize {
        self.vault.max_attributes()
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

/// `keylo unlock` for the passphrase vault file (the headless store); None with the Keychain store,
/// which the master-passphrase path below handles.
pub(crate) fn unlock_store() -> Result<Option<String>> {
    match file_vault() {
        Some(v) => {
            v.vault_key()?;
            Ok(Some("Vault unlocked.".into()))
        }
        None => Ok(None),
    }
}

/// `keylo lock`: ends the session and locks the vault (the passphrase file vault, or a master-passphrase
/// Keychain vault).
pub(crate) fn lock() {
    match file_vault() {
        Some(v) => v.lock(),
        None => vault().lock(),
    }
}

/// Whether a master passphrase is set on the Keychain vault. The headless file vault unlocks through
/// its own passphrase (`unlock_store`), not this optional layer, so it reports false here.
pub(crate) fn has_passphrase() -> Result<bool> {
    match kind() {
        Some(StoreKind::File) => Ok(false),
        _ => vault().has_passphrase(),
    }
}

/// Unlocks the vault: `Some` with the passphrase, `None` to try quietly (session or KEYLO_PASSPHRASE).
pub(crate) fn unlock(passphrase: Option<&str>) -> Result<bool> {
    if let Some(v) = file_vault() {
        return match passphrase {
            Some(p) => v.unlock(p).map(|()| true),
            None => v.try_unlock_quietly(),
        };
    }
    match passphrase {
        Some(p) => vault().unlock(p).map(|()| true),
        None => vault().try_unlock_quietly(),
    }
}

/// Sets, changes or removes the Keychain vault's master passphrase.
pub(crate) fn set_passphrase(current: Option<&str>, new: Option<&str>) -> Result<()> {
    if file_vault().is_some() {
        bail!(
            "This is Keylo's passphrase-protected vault file (a headless session). It's created from \
             KEYLO_PASSPHRASE or a prompt on first use; a separate master passphrase doesn't apply here."
        );
    }
    vault().set_passphrase(current, new)
}

/// Where secrets are kept, with its state, for `keylo status`.
pub(crate) fn status() -> Option<String> {
    if let Some(v) = file_vault() {
        let state = if v.try_unlock_quietly().unwrap_or(false) { "unlocked" } else { "locked" };
        return Some(format!("Keylo's encrypted vault ({}, {state})", v.path().display()));
    }
    let v = vault();
    let has = v.has_passphrase().unwrap_or(false);
    let locked = has && !v.try_unlock_quietly().unwrap_or(true);
    Some(match (has, locked) {
        (false, _) => "Keylo's vault".into(),
        (true, false) => "Keylo's vault (master passphrase, unlocked)".into(),
        (true, true) => "Keylo's vault (master passphrase, locked)".into(),
    })
}

// ---------------------------------------------------------------------------- Touch ID vault unlock

// Touch ID unlock: keylo-mac keeps a random 32-byte key behind biometrics in the data-protection
// keychain; the vault key is wrapped under it, beside the master passphrase. A Touch ID gesture
// releases the key to open the vault without typing the passphrase. (Needs the signed keylo-mac with
// its keychain-access-group entitlement; an unsigned build can't use that keychain.)

/// Whether Touch ID can be a vault key source here (biometrics enrolled, helper present). Not with the
/// headless file vault — Touch ID needs a desktop session.
pub(crate) fn hello_available() -> bool {
    if matches!(kind(), Some(StoreKind::File)) {
        return false;
    }
    matches!(run_helper(&["bio-available"], None), Ok((0, _)))
}

/// Whether "unlock with Touch ID" is set up for the vault (the wrap and the Secure Enclave blob).
pub(crate) fn has_hello() -> Result<bool> {
    if matches!(kind(), Some(StoreKind::File)) {
        return Ok(false);
    }
    Ok(vault().has_hello()? && touchid_blob_path().is_file())
}

/// Where Keylo keeps the Secure Enclave blob (opaque key material + peer public key) for Touch ID
/// unlock. Not secret: it's useless without this Mac's Secure Enclave and a Touch ID gesture.
fn touchid_blob_path() -> PathBuf {
    paths::data_dir().join("touchid.bin")
}

/// Turns Touch ID unlock on (creates a Secure Enclave key and wraps the vault key under what it
/// yields) or off. Enabling prompts Touch ID, and needs a live session or `passphrase` to reach the
/// vault key.
pub(crate) fn set_hello(enable: bool, passphrase: Option<&str>) -> Result<()> {
    if file_vault().is_some() {
        bail!("Touch ID unlock needs a desktop session; it isn't available for the headless vault file.");
    }
    if enable {
        let (code, out) = run_helper(&["bio-enroll"], None)?;
        match code {
            0 => {}
            1 => bail!("Touch ID was cancelled."),
            2 => bail!("Touch ID or the Secure Enclave isn't available on this Mac."),
            _ => bail!("Couldn't set up Touch ID unlock{}.", if out.is_empty() { String::new() } else { format!(": {out}") }),
        }
        let mut lines = out.lines();
        let blob = lines.next().unwrap_or("").trim().to_string();
        let kek = decode_kek(lines.next().unwrap_or(""))?;
        let arr: &[u8; 32] = kek.as_slice().try_into().map_err(|_| Error::msg("Touch ID returned an unexpected key."))?;
        if blob.is_empty() {
            bail!("Touch ID setup returned no key material.");
        }
        // Store the blob, then wrap the vault key; undo both if either fails, so they stay in step.
        std::fs::write(touchid_blob_path(), blob.as_bytes())?;
        if let Err(e) = vault().set_hello(true, passphrase, Some(arr)) {
            let _ = std::fs::remove_file(touchid_blob_path());
            return Err(e);
        }
        Ok(())
    } else {
        vault().set_hello(false, None, None)?;
        let _ = std::fs::remove_file(touchid_blob_path());
        Ok(())
    }
}

/// Unlocks the vault with Touch ID (prompts the gesture): re-derives the key from the stored blob.
pub(crate) fn unlock_hello() -> Result<()> {
    if file_vault().is_some() {
        bail!("Touch ID unlock needs a desktop session; it isn't available for the headless vault file.");
    }
    let blob = std::fs::read_to_string(touchid_blob_path()).map_err(|_| Error::msg("Touch ID unlock isn't set up for this vault."))?;
    let blob = blob.trim();
    if blob.is_empty() {
        bail!("Touch ID unlock isn't set up for this vault.");
    }
    let (code, out) = run_helper(&["bio-derive", blob], None)?;
    match code {
        0 => {
            let kek = decode_kek(out.trim())?;
            let arr: &[u8; 32] = kek.as_slice().try_into().map_err(|_| Error::msg("Touch ID returned an unexpected key."))?;
            vault().unlock_hello(arr)
        }
        1 => bail!("Touch ID was cancelled."),
        2 => bail!("Touch ID or the Secure Enclave isn't available."),
        _ => bail!("Touch ID unlock failed{}.", if out.is_empty() { String::new() } else { format!(": {out}") }),
    }
}

fn decode_kek(b64: &str) -> Result<Zeroizing<Vec<u8>>> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| Error::msg("Touch ID returned an unreadable key."))?;
    if bytes.len() != 32 {
        bail!("Touch ID returned an unexpected key length.");
    }
    Ok(Zeroizing::new(bytes))
}

/// End-to-end Touch ID check for `keylo __hello-selftest`: on a throwaway vault (KEYLO_HOME), set a
/// passphrase, turn Touch ID on (gesture), lock, unlock with Touch ID (gesture), and read a secret
/// back. Leaves the throwaway vault empty again.
pub(crate) fn touchid_selftest() -> Result<String> {
    if std::env::var("KEYLO_HOME").map(|h| h.is_empty()).unwrap_or(true) {
        bail!("Set KEYLO_HOME to a throwaway folder first — this self-test sets a passphrase and Touch ID on that vault.");
    }
    if !hello_available() {
        bail!("Touch ID or the Secure Enclave isn't available here (run it in a desktop session, not over SSH).");
    }
    let v = vault();
    let target = "KeyloTouchIDSelftest:probe";
    let value: &[u8] = b"\x01touch-id-selftest-value";
    let pass = "touch id selftest passphrase";

    v.write(target, value, None, None, &BTreeMap::new())?;
    v.set_passphrase(None, Some(pass))?;
    set_hello(true, Some(pass))?; // Touch ID gesture (enrol)
    v.lock();
    unlock_hello()?; // Touch ID gesture (derive)
    let got = v.read(target)?.ok_or_else(|| Error::msg("the secret was missing after the Touch ID unlock"))?;
    let ok = got.blob.as_slice() == value;

    // Put the throwaway vault back the way it was.
    let _ = set_hello(false, None);
    let _ = v.set_passphrase(Some(pass), None);
    let _ = v.delete(target);

    if ok {
        Ok("Touch ID unlock WORKS: set a passphrase, enabled Touch ID, locked, unlocked with Touch ID, and read the secret back.".into())
    } else {
        bail!("Unlocked with Touch ID, but the secret's value didn't match.")
    }
}

// ---------------------------------------------------------------------------- keylo-mac

/// keylo-mac, next to this program (or, in the app bundle, next to keylow in Contents/MacOS).
/// The real program, not a symlink to it (Homebrew's `keylo` is one): current_exe can return the
/// path it was started by.
fn helper() -> Result<PathBuf> {
    let exe = std::env::current_exe().ok().map(|e| std::fs::canonicalize(&e).unwrap_or(e));
    let path = exe.and_then(|e| e.parent().map(|d| d.join("keylo-mac"))).unwrap_or_else(|| "keylo-mac".into());
    if !path.is_file() {
        bail!("keylo-mac (Keylo's macOS helper) isn't installed next to keylo ({}). Re-run the build.", path.display());
    }
    Ok(path)
}

fn run_helper(args: &[&str], stdin: Option<&str>) -> Result<(i32, String)> {
    let out = unix::run(&helper()?, args, stdin, true)?;
    Ok((out.code, out.stdout.trim().to_string()))
}

/// Touch ID (or Apple Watch / password) through LocalAuthentication.
struct TouchId;

impl UserVerifier for TouchId {
    fn verify(&self, _owner: isize, message: &str) -> (VerificationResult, Option<String>) {
        // The system prompt reads "<app> is trying to <reason>", so drop Keylo's "Keylo: " prefix.
        let reason = message.strip_prefix("Keylo: ").unwrap_or(message);
        match run_helper(&["auth", reason], None) {
            Err(e) => (VerificationResult::Unavailable, Some(e.to_string())),
            Ok((0, _)) => (VerificationResult::Verified, None),
            Ok((1, _)) => (VerificationResult::Canceled, None),
            Ok((2, out)) => (
                VerificationResult::Unavailable,
                Some(if out.is_empty() { "no Touch ID, Apple Watch or password available".into() } else { out }),
            ),
            Ok((_, out)) => (VerificationResult::Failed, (!out.is_empty()).then_some(out)),
        }
    }
}

/// The general pasteboard, marked concealed and transient so clipboard managers and Universal
/// Clipboard history skip it. The token is the pasteboard's change count.
struct Pasteboard;

impl SecureClipboard for Pasteboard {
    fn set_text(&self, text: &str) -> Result<u32> {
        match run_helper(&["copy"], Some(text))? {
            (0, out) => out.parse().map_err(|_| keylo_core::Error::msg("Couldn't copy to the clipboard.")),
            _ => bail!("Couldn't copy to the clipboard."),
        }
    }

    fn clear_if_unchanged(&self, token: u32) -> bool {
        run_helper(&["clear", &token.to_string()], None).is_ok_and(|(code, _)| code == 0)
    }
}

/// The parent chain from `ps -o ppid=,ucomm= -p PID`.
struct PsAncestry;

fn ps_row(pid: u32) -> Option<(u32, String)> {
    let out = unix::run(std::path::Path::new("/bin/ps"), &["-o", "ppid=,ucomm=", "-p", &pid.to_string()], None, true).ok()?;
    let line = out.stdout.trim();
    let (ppid, name) = line.split_once(char::is_whitespace)?;
    Some((ppid.trim().parse().ok()?, name.trim().to_string()))
}

impl ProcessAncestry for PsAncestry {
    fn current(&self, max_depth: usize) -> Vec<AncestorProcess> {
        let mut chain = Vec::new();
        let mut next = ps_row(std::process::id()).map(|r| r.0);
        while let Some(pid) = next.filter(|p| *p > 1) {
            if chain.len() >= max_depth {
                break;
            }
            let Some((parent, name)) = ps_row(pid) else { break };
            chain.push(AncestorProcess { process_id: pid, executable_name: name });
            next = Some(parent);
        }
        chain
    }
}

/// The MCP server's approval without the app: an alert from keylo-mac. 10 deny, 11 once, 12 always.
pub(crate) fn approval_dialog(title: &str, message: &str, allow_always: bool) -> Result<i32> {
    let (code, _) = run_helper(&["approve", title, message, if allow_always { "1" } else { "0" }], None)?;
    Ok(code)
}

// ---------------------------------------------------------------------------- screen lock

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGSessionCopyCurrentDictionary() -> core_foundation_sys::dictionary::CFDictionaryRef;
}

/// True while the screen is locked (or the user switched away); false when it can't tell.
pub(crate) fn is_screen_locked() -> bool {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    let session = unsafe { CGSessionCopyCurrentDictionary() };
    if session.is_null() {
        return false; // no GUI session, e.g. over SSH
    }
    let dict: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(session) };
    dict.find(CFString::from_static_string("CGSSessionScreenIsLocked"))
        .and_then(|v| v.downcast::<CFBoolean>())
        .is_some_and(bool::from)
}
