//! Keylo on macOS: the login keychain, Touch ID, a concealed pasteboard and ps for process info.
//! Touch ID, the pasteboard and approval alerts need Apple's Objective-C frameworks, so they go
//! through keylo-mac, the small Swift helper installed next to keylo
//! (packaging/macos/keylo-mac.swift).

mod keychain;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use keylo_core::platform::{
    AncestorProcess, CredentialDetails, CredentialStore, DataProtector, Platform, ProcessAncestry, RawCredential,
    SecureClipboard, UserVerifier, VerificationResult,
};
use keylo_core::{bail, paths, Error, Result};
use zeroize::Zeroizing;

use crate::sqlite_vault::{OsKey, SqliteVault};
use crate::unix::{self, AesKeyProtector};
use keychain::KeychainStore;

/// The Keychain scope: KEYLO_KEYCHAIN (a throwaway keychain for tests, or an SSH session where the
/// login keychain is locked), else the login keychain.
fn keychain_path() -> Option<String> {
    std::env::var("KEYLO_KEYCHAIN").ok().filter(|p| !p.is_empty())
}

pub struct MacPlatform {
    credentials: MacVaultStore,
    protector: AesKeyProtector,
}

impl MacPlatform {
    pub fn new() -> Self {
        // The master key sits under its own service so it never shows up among secrets. It seals local
        // files (large values, the session) and wraps the vault key.
        let internal = KeychainStore::new(&format!("{}.Internal", keychain::DEFAULT_SERVICE), keychain_path().as_deref());
        let protector = AesKeyProtector::new(move || master_key(&internal));
        MacPlatform { credentials: MacVaultStore { vault: vault(), moved: Mutex::new(false) }, protector }
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
        "Keylo's vault".into()
    }
    fn file_protection_name(&self) -> String {
        "Keychain key".into()
    }
    fn clipboard(&self) -> &dyn SecureClipboard {
        &Pasteboard
    }
    fn processes(&self) -> &dyn ProcessAncestry {
        &PsAncestry
    }
}

pub(crate) fn install() {
    keylo_core::platform::install(Box::new(MacPlatform::new()));
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

/// `keylo lock`: ends the session and locks a master-passphrase vault.
pub(crate) fn lock() {
    vault().lock();
}

/// Whether a master passphrase is set on the vault.
pub(crate) fn has_passphrase() -> Result<bool> {
    vault().has_passphrase()
}

/// Unlocks the vault: `Some` with the passphrase, `None` to try quietly (session or KEYLO_PASSPHRASE).
pub(crate) fn unlock(passphrase: Option<&str>) -> Result<bool> {
    match passphrase {
        Some(p) => vault().unlock(p).map(|()| true),
        None => vault().try_unlock_quietly(),
    }
}

/// Sets, changes or removes the vault's master passphrase.
pub(crate) fn set_passphrase(current: Option<&str>, new: Option<&str>) -> Result<()> {
    vault().set_passphrase(current, new)
}

/// Where secrets are kept, with its state, for `keylo status`.
pub(crate) fn status() -> Option<String> {
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

/// Whether Touch ID can be a vault key source here (biometrics enrolled, helper present).
pub(crate) fn hello_available() -> bool {
    matches!(run_helper(&["bio-available"], None), Ok((0, _)))
}

/// Whether "unlock with Touch ID" is set up for the vault.
pub(crate) fn has_hello() -> Result<bool> {
    vault().has_hello()
}

/// Turns Touch ID unlock on (stores a random key behind biometrics and wraps the vault key under it)
/// or off. Enabling needs a live session or `passphrase` to reach the vault key.
pub(crate) fn set_hello(enable: bool, passphrase: Option<&str>) -> Result<()> {
    use base64::Engine;
    if enable {
        let kek = unix::random_key();
        let arr: &[u8; 32] = kek.as_slice().try_into().map_err(|_| Error::msg("Couldn't generate a Touch ID key."))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(kek.as_slice());
        match run_helper(&["bio-store"], Some(&b64))? {
            (0, _) => {}
            (_, out) => bail!("Couldn't store the Touch ID key{}.", if out.is_empty() { String::new() } else { format!(": {out}") }),
        }
        // Wrap the vault key under it; undo the stored key if that fails, so the two stay in step.
        if let Err(e) = vault().set_hello(true, passphrase, Some(arr)) {
            let _ = run_helper(&["bio-remove"], None);
            return Err(e);
        }
        Ok(())
    } else {
        vault().set_hello(false, None, None)?;
        let _ = run_helper(&["bio-remove"], None);
        Ok(())
    }
}

/// Unlocks the vault with Touch ID (prompts the gesture).
pub(crate) fn unlock_hello() -> Result<()> {
    use base64::Engine;
    let (code, out) = run_helper(&["bio-get", "unlock your Keylo vault"], None)?;
    match code {
        0 => {
            let bytes = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(out.trim())
                    .map_err(|_| Error::msg("Touch ID returned an unreadable key."))?,
            );
            let arr: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::msg("Touch ID returned an unexpected key."))?;
            vault().unlock_hello(arr)
        }
        1 => bail!("Touch ID was cancelled."),
        2 => bail!("Touch ID unlock isn't set up on this Mac (no stored key or biometrics)."),
        _ => bail!("Touch ID unlock failed{}.", if out.is_empty() { String::new() } else { format!(": {out}") }),
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
