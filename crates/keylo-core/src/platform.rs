//! What Keylo needs from the operating system. Each host (CLI, app, tests) installs one platform at
//! startup with [`install`]; the core itself is OS-neutral.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::Result;

/// A secure item in the OS store, the unit [`crate::store::SecretStore`] builds secrets from.
#[derive(Clone)]
pub struct RawCredential {
    pub target: String,
    pub user_name: Option<String>,
    pub comment: Option<String>,
    pub last_written: DateTime<Utc>,
    /// Keylo's value, or a reference to an encrypted file. Wiped when dropped.
    pub blob: Zeroizing<Vec<u8>>,
    /// Small named strings stored with the item (category, type, fields…).
    pub attributes: BTreeMap<String, String>,
}

impl RawCredential {
    /// An attribute by name, ignoring case (Windows treats attribute names case-insensitively).
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The OS's secure item store: Credential Manager, the Keychain, the Secret Service…
pub trait CredentialStore: Send + Sync {
    /// Largest blob the store accepts; larger values go to protected files.
    fn max_blob_bytes(&self) -> usize;
    /// Largest UTF-8 size of one attribute value.
    fn max_attribute_bytes(&self) -> usize;
    /// Most attributes per item.
    fn max_attributes(&self) -> usize;

    fn read(&self, target: &str) -> Result<Option<RawCredential>>;
    /// Items whose target starts with `prefix`.
    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>>;
    /// Creates or replaces an item.
    fn write(
        &self,
        target: &str,
        blob: &[u8],
        user_name: Option<&str>,
        comment: Option<&str>,
        attributes: &BTreeMap<String, String>,
    ) -> Result<()>;
    fn delete(&self, target: &str) -> Result<bool>;
}

/// Encrypts local files so only this user can read them: DPAPI, a Keychain-held key…
pub trait DataProtector: Send + Sync {
    fn protect(&self, data: &[u8], entropy: &[u8]) -> Result<Vec<u8>>;
    /// Fails when the data can't be decrypted.
    fn unprotect(&self, data: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    Verified,
    Canceled,
    Unavailable,
    Failed,
}

/// Windows Hello, Touch ID, polkit: someone at the keyboard approves.
pub trait UserVerifier: Send + Sync {
    /// `owner` is a native window handle to parent the prompt to (0: none).
    fn verify(&self, owner: isize, message: &str) -> (VerificationResult, Option<String>);
}

/// A clipboard that keeps copied secrets out of history and sync, and can clear them later.
pub trait SecureClipboard: Send + Sync {
    /// Copies `text`; returns a token for [`SecureClipboard::clear_if_unchanged`].
    fn set_text(&self, text: &str) -> Result<u32>;
    /// Empties the clipboard if it still holds what `set_text` put there.
    fn clear_if_unchanged(&self, token: u32) -> bool;
}

#[derive(Debug, Clone)]
pub struct AncestorProcess {
    pub process_id: u32,
    pub executable_name: String,
}

/// The chain of processes that started this one (parent first), for the audit log.
pub trait ProcessAncestry: Send + Sync {
    fn current(&self, max_depth: usize) -> Vec<AncestorProcess>;
}

/// Everything Keylo needs from the operating system.
pub trait Platform: Send + Sync {
    /// "Windows", "macOS", "Linux".
    fn name(&self) -> &str;
    fn credentials(&self) -> &dyn CredentialStore;
    fn data_protector(&self) -> &dyn DataProtector;
    fn verifier(&self) -> &dyn UserVerifier;
    /// The verifier as people know it: "Windows Hello", "Touch ID".
    fn verifier_name(&self) -> String {
        "device sign-in".into()
    }
    /// Where secrets live: "Windows Credential Manager", "the macOS Keychain".
    fn store_name(&self) -> String {
        "the system credential store".into()
    }
    /// What protects large values kept as files: "DPAPI".
    fn file_protection_name(&self) -> String {
        "encrypted".into()
    }
    fn clipboard(&self) -> &dyn SecureClipboard;
    fn processes(&self) -> &dyn ProcessAncestry;
}

static CURRENT: OnceLock<Box<dyn Platform>> = OnceLock::new();

/// Installs the platform (once; later calls are ignored).
pub fn install(platform: Box<dyn Platform>) {
    let _ = CURRENT.set(platform);
}

pub fn is_installed() -> bool {
    CURRENT.get().is_some()
}

/// The installed platform. Panics if none is installed: a host bug, not a user error.
pub fn current() -> &'static dyn Platform {
    CURRENT
        .get()
        .expect("No Keylo platform is installed; call keylo_platform::install() at startup")
        .as_ref()
}
