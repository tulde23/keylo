//! Keylo's operating-system layer: Windows (Credential Manager, DPAPI, Windows Hello), macOS
//! (Keychain, Touch ID) and Linux (desktop keyring or Keylo's vault file, polkit). Call [`install`]
//! once at startup.

mod crypto;
#[cfg(windows)]
mod sqlite_vault;
#[cfg(windows)]
mod hello_prf;

#[cfg(windows)]
mod windows_platform;
#[cfg(windows)]
pub use windows_platform::WindowsPlatform;

#[cfg(unix)]
mod unix;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxPlatform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacPlatform;

/// Installs this OS's platform as Keylo's.
pub fn install() {
    #[cfg(windows)]
    keylo_core::platform::install(Box::new(WindowsPlatform::new()));
    #[cfg(target_os = "linux")]
    linux::install();
    #[cfg(target_os = "macos")]
    macos::install();
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    panic!("Keylo doesn't support this OS.");
}

/// Whether the store may ask for a passphrase on the terminal (Linux's vault file). The CLI allows
/// it; the MCP server and the app don't (they have no terminal to ask on).
pub fn set_terminal_prompts(allowed: bool) {
    #[cfg(target_os = "linux")]
    linux::vault::CAN_PROMPT_ON_TERMINAL.store(allowed, std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(target_os = "linux"))]
    let _ = allowed;
}

/// `keylo unlock` for stores that lock on their own (Linux's vault file: asks for the passphrase).
/// Some(message) when there was one to unlock.
pub fn unlock_store() -> keylo_core::Result<Option<String>> {
    #[cfg(target_os = "linux")]
    return linux::unlock_store();
    #[cfg(not(target_os = "linux"))]
    Ok(None)
}

/// `keylo lock`: forgets a store's unlocked key (Linux's vault file, or a Windows master passphrase).
pub fn lock_store() {
    #[cfg(target_os = "linux")]
    linux::lock_store();
    #[cfg(windows)]
    windows_platform::lock();
}

/// Where secrets are kept, with its state, for `keylo status` (None: nothing to add).
pub fn store_status() -> Option<String> {
    #[cfg(target_os = "linux")]
    return linux::store_status();
    #[cfg(windows)]
    return windows_platform::status();
    #[cfg(not(any(target_os = "linux", windows)))]
    None
}

/// Whether the vault is unlocked with a master passphrase (Windows). False where there's none.
pub fn vault_has_passphrase() -> keylo_core::Result<bool> {
    #[cfg(windows)]
    return windows_platform::has_passphrase();
    #[cfg(not(windows))]
    Ok(false)
}

/// Unlocks the vault: `Some(passphrase)` to open a passphrase vault, `None` to try quietly (the
/// session cache or KEYLO_PASSPHRASE). Returns whether it's unlocked afterwards.
pub fn unlock_vault(passphrase: Option<&str>) -> keylo_core::Result<bool> {
    #[cfg(windows)]
    return windows_platform::unlock(passphrase);
    #[cfg(not(windows))]
    {
        let _ = passphrase;
        Ok(true)
    }
}

/// Sets, changes or removes the vault's master passphrase (Windows). `current` must match when one
/// is set; `new` of None removes it.
pub fn set_vault_passphrase(current: Option<&str>, new: Option<&str>) -> keylo_core::Result<()> {
    #[cfg(windows)]
    return windows_platform::set_passphrase(current, new);
    #[cfg(not(windows))]
    {
        let _ = (current, new);
        keylo_core::bail!("A master passphrase isn't available on this platform yet.")
    }
}

/// Whether Windows Hello can be used as a key source (WebAuthn hmac-secret/PRF).
pub fn hello_prf_available() -> bool {
    #[cfg(windows)]
    return hello_prf::available();
    #[cfg(not(windows))]
    false
}

/// Enrols, derives twice and checks stability, to confirm Hello PRF works on this machine.
pub fn hello_selftest() -> keylo_core::Result<String> {
    #[cfg(windows)]
    return hello_prf::selftest();
    #[cfg(not(windows))]
    keylo_core::bail!("Windows Hello PRF is only on Windows.")
}

/// An approval dialog for the MCP server when the app isn't installed (macOS and Linux; Windows
/// uses a message box in keylo itself). 10 denied, 11 once, 12 always.
pub fn approval_dialog(title: &str, message: &str, allow_always: bool) -> keylo_core::Result<i32> {
    #[cfg(target_os = "linux")]
    return linux::approval_dialog(title, message, allow_always);
    #[cfg(target_os = "macos")]
    return macos::approval_dialog(title, message, allow_always);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (title, message, allow_always);
        Ok(10)
    }
}

/// True while the screen is locked (or the session is disconnected); false when it can't tell.
pub fn is_screen_locked() -> bool {
    #[cfg(windows)]
    return windows_platform::is_screen_locked();
    #[cfg(target_os = "linux")]
    return linux::is_screen_locked();
    #[cfg(target_os = "macos")]
    return macos::is_screen_locked();
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    false
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn an_unlocked_desktop_reads_as_unlocked() {
        // Run from an interactive, unlocked session (as these tests are).
        assert!(!super::is_screen_locked());
    }
}
