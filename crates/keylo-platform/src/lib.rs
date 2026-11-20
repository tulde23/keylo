//! Keylo's operating-system layer: Windows (Credential Manager, DPAPI, Windows Hello), macOS
//! (Keychain, Touch ID) and Linux (desktop keyring or Keylo's vault file, polkit). Call [`install`]
//! once at startup.

mod crypto;
// The SQLite vault is shared by Windows and macOS (Linux still uses the keyring / vault file).
#[cfg(any(windows, target_os = "macos"))]
mod sqlite_vault;
#[cfg(windows)]
mod hello_key;

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

/// `keylo lock`: forgets a store's unlocked key (Linux's vault file, or a Windows/macOS master passphrase).
pub fn lock_store() {
    #[cfg(target_os = "linux")]
    linux::lock_store();
    #[cfg(windows)]
    windows_platform::lock();
    #[cfg(target_os = "macos")]
    macos::lock();
}

/// Where secrets are kept, with its state, for `keylo status` (None: nothing to add).
pub fn store_status() -> Option<String> {
    #[cfg(target_os = "linux")]
    return linux::store_status();
    #[cfg(windows)]
    return windows_platform::status();
    #[cfg(target_os = "macos")]
    return macos::status();
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    None
}

/// Whether the vault is unlocked with a master passphrase (Windows/macOS). False where there's none.
pub fn vault_has_passphrase() -> keylo_core::Result<bool> {
    #[cfg(windows)]
    return windows_platform::has_passphrase();
    #[cfg(target_os = "macos")]
    return macos::has_passphrase();
    #[cfg(not(any(windows, target_os = "macos")))]
    Ok(false)
}

/// Unlocks the vault: `Some(passphrase)` to open a passphrase vault, `None` to try quietly (the
/// session cache or KEYLO_PASSPHRASE). Returns whether it's unlocked afterwards.
pub fn unlock_vault(passphrase: Option<&str>) -> keylo_core::Result<bool> {
    #[cfg(windows)]
    return windows_platform::unlock(passphrase);
    #[cfg(target_os = "macos")]
    return macos::unlock(passphrase);
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = passphrase;
        Ok(true)
    }
}

/// Sets, changes or removes the vault's master passphrase (Windows/macOS). `current` must match when
/// one is set; `new` of None removes it.
pub fn set_vault_passphrase(current: Option<&str>, new: Option<&str>) -> keylo_core::Result<()> {
    #[cfg(windows)]
    return windows_platform::set_passphrase(current, new);
    #[cfg(target_os = "macos")]
    return macos::set_passphrase(current, new);
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (current, new);
        keylo_core::bail!("A master passphrase isn't available on this platform yet.")
    }
}

/// Whether a biometric unlock is available as a key source: Windows Hello (TPM via
/// KeyCredentialManager) or macOS Touch ID (a key behind biometrics in the Keychain).
pub fn hello_available() -> bool {
    #[cfg(windows)]
    return hello_key::available();
    #[cfg(target_os = "macos")]
    return macos::hello_available();
    #[cfg(not(any(windows, target_os = "macos")))]
    false
}

/// Whether a biometric unlock (Windows Hello / Touch ID) is set up for the vault.
pub fn vault_has_hello() -> keylo_core::Result<bool> {
    #[cfg(windows)]
    return windows_platform::has_hello();
    #[cfg(target_os = "macos")]
    return macos::has_hello();
    #[cfg(not(any(windows, target_os = "macos")))]
    Ok(false)
}

/// Turns the biometric unlock (Windows Hello / Touch ID) on (needs the gesture and, if no session is
/// live, the current passphrase to bind the key) or off.
pub fn set_vault_hello(enable: bool, passphrase: Option<&str>) -> keylo_core::Result<()> {
    #[cfg(windows)]
    return windows_platform::set_hello(enable, passphrase);
    #[cfg(target_os = "macos")]
    return macos::set_hello(enable, passphrase);
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (enable, passphrase);
        keylo_core::bail!("A biometric unlock isn't available on this platform.")
    }
}

/// Unlocks the vault with the biometric unlock (Windows Hello / Touch ID; asks for the gesture).
/// Returns whether it's unlocked after.
pub fn unlock_vault_hello() -> keylo_core::Result<bool> {
    #[cfg(windows)]
    {
        windows_platform::unlock_hello()?;
        return Ok(true);
    }
    #[cfg(target_os = "macos")]
    {
        macos::unlock_hello()?;
        return Ok(true);
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    keylo_core::bail!("A biometric unlock isn't available on this platform.")
}

/// Confirms the biometric unlock works on this machine: Windows Hello signs a stable key; macOS Touch
/// ID runs an end-to-end vault round-trip on a throwaway KEYLO_HOME.
pub fn hello_selftest() -> keylo_core::Result<String> {
    #[cfg(windows)]
    return hello_key::selftest();
    #[cfg(target_os = "macos")]
    return macos::touchid_selftest();
    #[cfg(not(any(windows, target_os = "macos")))]
    keylo_core::bail!("A biometric unlock isn't available on this platform.")
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
