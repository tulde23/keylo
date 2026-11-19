//! AES-256-GCM sealing shared by every platform: Keylo's vault, and (on macOS and Linux) the local
//! files sealed under a key from the store.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use keylo_core::{Error, Result};
use rand::RngCore;
use zeroize::Zeroizing;

const NONCE: usize = 12;
const TAG: usize = 16;

/// AES-256-GCM with a 12-byte nonce in front and the tag behind (nonce | ciphertext | tag).
pub fn seal(key: &[u8], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::msg("Bad key length."))?;
    let mut nonce = [0u8; NONCE];
    rand::thread_rng().fill_bytes(&mut nonce);
    let body = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad })
        .map_err(|_| Error::msg("Couldn't encrypt."))?;
    let mut out = Vec::with_capacity(NONCE + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens [`seal`]ed data; None when the key or associated data is wrong, or it was changed.
pub fn open(key: &[u8], sealed: &[u8], aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE + TAG {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(&sealed[..NONCE]), Payload { msg: &sealed[NONCE..], aad })
        .ok()
        .map(Zeroizing::new)
}

pub fn random_key() -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; 32]);
    rand::thread_rng().fill_bytes(&mut key);
    key
}
