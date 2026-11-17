#![cfg_attr(target_os = "macos", allow(dead_code))]
//! Pieces macOS and Linux share: sealing local files under a key from the store, running helper
//! programs, and asking for a passphrase on the terminal.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use keylo_core::platform::DataProtector;
use keylo_core::{Error, Result};
use rand::RngCore;
use zeroize::Zeroizing;

const NONCE: usize = 12;
const TAG: usize = 16;

/// AES-256-GCM with a 12-byte nonce in front and the tag behind (nonce | ciphertext | tag), as the
/// C# build writes.
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

/// Seals local files (large values, the session) under a 32-byte key from the store, fetched once.
/// The entropy is bound in as associated data, as DPAPI's optional entropy is.
pub struct AesKeyProtector {
    key: Box<dyn Fn() -> Result<Zeroizing<Vec<u8>>> + Send + Sync>,
    cached: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl AesKeyProtector {
    pub fn new(key: impl Fn() -> Result<Zeroizing<Vec<u8>>> + Send + Sync + 'static) -> Self {
        AesKeyProtector { key: Box::new(key), cached: Mutex::new(None) }
    }

    fn key(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut cached = self.cached.lock().unwrap();
        if cached.is_none() {
            *cached = Some((self.key)()?);
        }
        Ok(cached.clone().unwrap())
    }
}

impl DataProtector for AesKeyProtector {
    fn protect(&self, data: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        seal(&self.key()?, data, entropy)
    }

    fn unprotect(&self, data: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        open(&self.key()?, data, entropy).ok_or_else(|| Error::msg("The protected data couldn't be decrypted."))
    }
}

/// A program on PATH (or in /usr/bin, /bin).
pub fn find(name: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    let found = path
        .split(':')
        .filter(|d| !d.is_empty())
        .chain(["/usr/bin", "/bin", "/usr/local/bin"])
        .map(|d| PathBuf::from(d).join(name))
        .find(|p| p.is_file());
    found
}

pub struct ToolOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs a program. `capture: false` leaves stdout/stderr unread (programs that fork a server, such
/// as wl-copy and xclip, keep inherited pipes open).
pub fn run(program: &std::path::Path, args: &[&str], stdin: Option<&str>, capture: bool) -> Result<ToolOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(if capture { Stdio::piped() } else { Stdio::null() })
        .stderr(if capture { Stdio::piped() } else { Stdio::null() });
    let mut child = command
        .spawn()
        .map_err(|e| Error::msg(format!("Couldn't start {}: {e}", program.display())))?;
    if let (Some(text), Some(mut input)) = (stdin, child.stdin.take()) {
        let _ = input.write_all(text.as_bytes());
    }
    let (mut stdout, mut stderr) = (String::new(), String::new());
    if capture {
        if let Some(mut o) = child.stdout.take() {
            let _ = o.read_to_string(&mut stdout);
        }
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut stderr);
        }
    }
    let status = child.wait()?;
    Ok(ToolOutput { code: status.code().unwrap_or(-1), stdout, stderr: stderr.trim().to_string() })
}

pub fn has_display() -> bool {
    ["WAYLAND_DISPLAY", "DISPLAY"].iter().any(|v| std::env::var(v).is_ok_and(|x| !x.is_empty()))
}

/// Asks on the controlling terminal (/dev/tty, not stdin, so it works while a value is piped in)
/// with echo off. None when there's no terminal.
pub fn read_hidden(prompt: &str) -> Option<Zeroizing<String>> {
    use std::os::fd::AsRawFd;
    let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").ok()?;
    let fd = tty.as_raw_fd();
    let _ = tty.write_all(prompt.as_bytes());
    let _ = tty.flush();

    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let have_term = unsafe { libc::tcgetattr(fd, &mut saved) } == 0;
    if have_term {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ECHONL;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    let ok = loop {
        match tty.read(&mut byte) {
            Ok(0) => break !line.is_empty(),
            Ok(_) if byte[0] == b'\n' => break true,
            Ok(_) => line.push(byte[0]),
            Err(_) => break false,
        }
    };
    if have_term {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    }
    if !ok {
        return None;
    }
    while line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line.to_vec()).ok().map(Zeroizing::new)
}

pub fn terminal_available() -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trips_and_binds_the_aad() {
        let key = random_key();
        let sealed = seal(&key, b"hello", b"aad").unwrap();
        assert_eq!(sealed.len(), 12 + 5 + 16);
        assert_eq!(open(&key, &sealed, b"aad").unwrap().as_slice(), b"hello");
        assert!(open(&key, &sealed, b"other").is_none());
    }
}
