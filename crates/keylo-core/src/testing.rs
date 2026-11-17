//! An in-memory platform for core's tests: a credential store in a map, a reversible "protector",
//! and a verifier that always says yes. Each test uses its own prefix and data folder.

use std::collections::BTreeMap;
use std::sync::Mutex;

use chrono::Utc;
use zeroize::Zeroizing;

use crate::platform::*;
use crate::Result;

#[derive(Default)]
struct MemoryStore(Mutex<BTreeMap<String, RawCredential>>);

impl CredentialStore for MemoryStore {
    fn max_blob_bytes(&self) -> usize {
        2560
    }
    fn max_attribute_bytes(&self) -> usize {
        256
    }
    fn max_attributes(&self) -> usize {
        64
    }
    fn read(&self, target: &str) -> Result<Option<RawCredential>> {
        Ok(self.0.lock().unwrap().iter().find(|(k, _)| k.eq_ignore_ascii_case(target)).map(|(_, v)| v.clone()))
    }
    fn enumerate(&self, prefix: &str) -> Result<Vec<RawCredential>> {
        let p = prefix.to_lowercase();
        Ok(self.0.lock().unwrap().values().filter(|c| c.target.to_lowercase().starts_with(&p)).cloned().collect())
    }
    fn write(&self, target: &str, blob: &[u8], user: Option<&str>, comment: Option<&str>, attrs: &BTreeMap<String, String>) -> Result<()> {
        let mut map = self.0.lock().unwrap();
        // Like Credential Manager: names are case-insensitive, and a write keeps the stored spelling.
        let key = map.keys().find(|k| k.eq_ignore_ascii_case(target)).cloned().unwrap_or_else(|| target.to_string());
        map.insert(
            key.clone(),
            RawCredential {
                target: key,
                user_name: user.map(str::to_string),
                comment: comment.map(str::to_string),
                last_written: Utc::now(),
                blob: Zeroizing::new(blob.to_vec()),
                attributes: attrs.clone(),
            },
        );
        Ok(())
    }
    fn delete(&self, target: &str) -> Result<bool> {
        let mut map = self.0.lock().unwrap();
        let key = map.keys().find(|k| k.eq_ignore_ascii_case(target)).cloned();
        Ok(key.is_some_and(|k| map.remove(&k).is_some()))
    }
}

struct Xor;
impl DataProtector for Xor {
    fn protect(&self, data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        Ok(data.iter().enumerate().map(|(i, b)| b ^ entropy[i % entropy.len()]).collect())
    }
    fn unprotect(&self, data: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.protect(data, entropy)?))
    }
}

struct Yes;
impl UserVerifier for Yes {
    fn verify(&self, _: isize, _: &str) -> (VerificationResult, Option<String>) {
        (VerificationResult::Verified, None)
    }
}
impl SecureClipboard for Yes {
    fn set_text(&self, _: &str) -> Result<u32> {
        Ok(1)
    }
    fn clear_if_unchanged(&self, _: u32) -> bool {
        true
    }
}
impl ProcessAncestry for Yes {
    fn current(&self, _: usize) -> Vec<AncestorProcess> {
        vec![]
    }
}

struct MemoryPlatform {
    store: MemoryStore,
}

impl Platform for MemoryPlatform {
    fn name(&self) -> &str {
        "Test"
    }
    fn credentials(&self) -> &dyn CredentialStore {
        &self.store
    }
    fn data_protector(&self) -> &dyn DataProtector {
        &Xor
    }
    fn verifier(&self) -> &dyn UserVerifier {
        &Yes
    }
    fn clipboard(&self) -> &dyn SecureClipboard {
        &Yes
    }
    fn processes(&self) -> &dyn ProcessAncestry {
        &Yes
    }
}

/// Installs the in-memory platform (once per test binary) and returns a fresh, empty data folder.
pub fn setup() -> std::path::PathBuf {
    install(Box::new(MemoryPlatform { store: MemoryStore::default() }));
    let dir = std::env::temp_dir().join(format!("keylo-test-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A prefix of its own for each test, so tests sharing the store don't see each other's secrets.
pub fn prefix() -> String {
    format!("T{}:", uuid::Uuid::new_v4().simple())
}
