//! Keeps the unlocked vault key in the kernel's user keyring for a while (like ssh-agent, without a
//! daemon), so each keylo command and the MCP server don't ask for the passphrase again. Readable by
//! this user's processes only, and it expires by itself. Where the keyring syscalls are blocked
//! (Docker's default seccomp profile), caching is simply off.

use std::ffi::CString;
use std::time::Duration;

use zeroize::Zeroizing;

const KEY_SPEC_USER_KEYRING: libc::c_long = -4;
const KEYCTL_SETPERM: libc::c_long = 5;
const KEYCTL_SEARCH: libc::c_long = 10;
const KEYCTL_READ: libc::c_long = 11;
const KEYCTL_SET_TIMEOUT: libc::c_long = 15;
const KEYCTL_INVALIDATE: libc::c_long = 21;
/// Possessor: all; user: all; group and others: none.
const PERMISSIONS: libc::c_long = 0x3f3f_0000;

fn search(description: &str) -> Option<libc::c_long> {
    let kind = CString::new("user").ok()?;
    let desc = CString::new(description).ok()?;
    let id = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SEARCH, KEY_SPEC_USER_KEYRING, kind.as_ptr(), desc.as_ptr(), 0 as libc::c_long) };
    (id > 0).then_some(id)
}

pub fn get(description: &str) -> Option<Zeroizing<Vec<u8>>> {
    let id = search(description)?;
    let mut buffer = Zeroizing::new(vec![0u8; 64]);
    let n = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_READ, id, buffer.as_mut_ptr(), 64 as libc::c_long, 0 as libc::c_long) };
    if n <= 0 || n > 64 {
        return None;
    }
    buffer.truncate(n as usize);
    Some(buffer)
}

pub fn put(description: &str, key: &[u8], lifetime: Duration) {
    if lifetime.is_zero() {
        return;
    }
    let (Ok(kind), Ok(desc)) = (CString::new("user"), CString::new(description)) else { return };
    let id = unsafe { libc::syscall(libc::SYS_add_key, kind.as_ptr(), desc.as_ptr(), key.as_ptr(), key.len(), KEY_SPEC_USER_KEYRING) };
    if id <= 0 {
        return;
    }
    unsafe {
        libc::syscall(libc::SYS_keyctl, KEYCTL_SETPERM, id, PERMISSIONS, 0 as libc::c_long, 0 as libc::c_long);
        libc::syscall(libc::SYS_keyctl, KEYCTL_SET_TIMEOUT, id, lifetime.as_secs() as libc::c_long, 0 as libc::c_long, 0 as libc::c_long);
    }
}

pub fn remove(description: &str) {
    if let Some(id) = search(description) {
        unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_INVALIDATE, id, 0 as libc::c_long, 0 as libc::c_long, 0 as libc::c_long) };
    }
}
