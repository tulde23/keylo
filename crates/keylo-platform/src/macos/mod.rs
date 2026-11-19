//! Keylo on macOS: the login keychain, Touch ID, a concealed pasteboard and ps for process info.
//! Touch ID, the pasteboard and approval alerts need Apple's Objective-C frameworks, so they go
//! through keylo-mac, the small Swift helper installed next to keylo
//! (rust_csharp/src/Keylo.Platform.MacOS/helper/keylo-mac.swift, shared with the C# build).

mod keychain;

use std::collections::BTreeMap;
use std::path::PathBuf;

use keylo_core::platform::{
    AncestorProcess, CredentialStore, DataProtector, Platform, ProcessAncestry, SecureClipboard, UserVerifier, VerificationResult,
};
use keylo_core::{bail, Result};
use zeroize::Zeroizing;

use crate::unix::{self, AesKeyProtector};
use keychain::KeychainStore;

pub struct MacPlatform {
    credentials: KeychainStore,
    protector: AesKeyProtector,
}

impl MacPlatform {
    pub fn new() -> Self {
        let path = std::env::var("KEYLO_KEYCHAIN").ok();
        // The master key sits under its own service so it never shows up among secrets.
        let internal = KeychainStore::new(&format!("{}.Internal", keychain::DEFAULT_SERVICE), path.as_deref());
        let protector = AesKeyProtector::new(move || master_key(&internal));
        MacPlatform { credentials: KeychainStore::new(keychain::DEFAULT_SERVICE, path.as_deref()), protector }
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
        "macOS Keychain".into()
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
