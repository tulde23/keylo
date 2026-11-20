//! Windows Hello as a key source via the NGC / Windows-Hello-for-Business container
//! ([`KeyCredentialManager`]), not WebAuthn. `RequestCreateAsync` makes a TPM-backed key that only a
//! Hello gesture can use; signing a fixed challenge with it is deterministic (RSA PKCS#1), so the
//! signature is a stable secret that wraps the vault key. The private key never leaves the TPM and
//! can't be used without the gesture, so the wrap can't be undone at rest.
//!
//! This is the path that works for an unpackaged desktop app: the WebAuthn passkey UI never offers
//! "This Windows device" to our process, but KeyCredentialManager talks to the local Hello container
//! directly (PIN or biometric, no passkey chooser, no phone).

use hkdf::Hkdf;
use keylo_core::{bail, Error, Result};
use sha2::Sha256;
use windows::core::HSTRING;
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Storage::Streams::{DataReader, DataWriter, IBuffer};

/// The name of Keylo's Hello-protected key in the user's NGC container. Stable forever: recreating it
/// changes the signature and would orphan anything it wrapped.
const KEY_NAME: &str = "keylo-vault-hello-key";
/// A fixed challenge. The signature over it is the secret; it's constant so the secret is stable.
const CHALLENGE: &[u8] = b"keylo-vault-unlock:v1";
/// HKDF context separating this secret from any other use of the signature.
const HKDF_INFO: &[u8] = b"keylo-hello-key:v1";

/// Turns a Windows error into Keylo's, keeping the message.
fn w<T>(r: windows::core::Result<T>) -> Result<T> {
    r.map_err(|e| Error::msg(e.message().to_string()))
}

/// Whether this machine has Windows Hello set up so a Hello-protected key can be made.
pub fn available() -> bool {
    (|| -> windows::core::Result<bool> { KeyCredentialManager::IsSupportedAsync()?.join() })().unwrap_or(false)
}

fn ibuffer(bytes: &[u8]) -> windows::core::Result<IBuffer> {
    let writer = DataWriter::new()?;
    writer.WriteBytes(bytes)?;
    writer.DetachBuffer()
}

fn buffer_bytes(buf: &IBuffer) -> windows::core::Result<Vec<u8>> {
    let len = buf.Length()? as usize;
    let reader = DataReader::FromBuffer(buf)?;
    let mut out = vec![0u8; len];
    reader.ReadBytes(&mut out)?;
    Ok(out)
}

/// Opens Keylo's Hello key, creating it (one Hello gesture) the first time.
fn open_or_create() -> Result<KeyCredential> {
    let name = HSTRING::from(KEY_NAME);
    let opened = w(w(KeyCredentialManager::OpenAsync(&name))?.join())?;
    match w(opened.Status())? {
        KeyCredentialStatus::Success => w(opened.Credential()),
        KeyCredentialStatus::NotFound => {
            let created = w(w(KeyCredentialManager::RequestCreateAsync(
                &name,
                KeyCredentialCreationOption::FailIfExists,
            ))?
            .join())?;
            match w(created.Status())? {
                KeyCredentialStatus::Success => w(created.Credential()),
                KeyCredentialStatus::UserCanceled => bail!("Windows Hello was cancelled."),
                KeyCredentialStatus::UserPrefersPassword => {
                    bail!("Windows Hello isn't set up for this account (choose a PIN in Sign-in options).")
                }
                s => bail!("Couldn't create the Windows Hello key (status {:?}).", s),
            }
        }
        KeyCredentialStatus::UserCanceled => bail!("Windows Hello was cancelled."),
        s => bail!("Couldn't open the Windows Hello key (status {:?}).", s),
    }
}

/// Signs the fixed challenge with the Hello key (one gesture) and returns the raw signature bytes.
fn sign(cred: &KeyCredential) -> Result<Vec<u8>> {
    let buf = w(ibuffer(CHALLENGE))?;
    let res = w(w(cred.RequestSignAsync(&buf))?.join())?;
    match w(res.Status())? {
        KeyCredentialStatus::Success => w(buffer_bytes(&w(res.Result())?)),
        KeyCredentialStatus::UserCanceled => bail!("Windows Hello was cancelled."),
        s => bail!("Windows Hello signing failed (status {:?}).", s),
    }
}

/// Derives Keylo's 32-byte Hello secret: a Hello gesture, a deterministic signature, HKDF to a key.
/// Creates the Hello key on first use. The secret is stable for the life of that key.
pub fn derive() -> Result<[u8; 32]> {
    if !available() {
        bail!("Windows Hello isn't available on this machine.");
    }
    let sig = sign(&open_or_create()?)?;
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &sig)
        .expand(HKDF_INFO, &mut key)
        .map_err(|_| Error::msg("HKDF failed."))?;
    Ok(key)
}

/// Creates/opens the Hello key, signs twice and checks the signature is deterministic (so it can wrap
/// the vault key). For `keylo __hello-selftest`. Leaves a Hello key named `keylo-vault-hello-key`.
pub fn selftest() -> Result<String> {
    if !available() {
        return Ok("Windows Hello (KeyCredentialManager) isn't supported here — no PIN/biometric is set up.".into());
    }
    let cred = match open_or_create() {
        Ok(c) => c,
        Err(e) => return Ok(format!("Couldn't get a Windows Hello key: {e}")),
    };
    let a = match sign(&cred) {
        Ok(s) => s,
        Err(e) => return Ok(format!("Hello key created, but signing failed: {e}")),
    };
    let b = sign(&cred)?;
    if a != b {
        return Ok(format!(
            "Windows Hello signing is NOT deterministic ({}-byte signatures differed), so it can't be a stable key \
             source as-is (the key is likely ECDSA, not RSA).",
            a.len()
        ));
    }
    Ok(format!(
        "Windows Hello key WORKS: TPM-backed key '{KEY_NAME}', a gesture signs a {}-byte challenge and two signatures \
         match — a stable secret to wrap the vault key, no passphrase needed.",
        a.len()
    ))
}
