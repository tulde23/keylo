//! Keylo's operating-system layer: Windows (Credential Manager, DPAPI, Windows Hello), with macOS
//! and Linux to follow. Call [`install`] once at startup.

#[cfg(windows)]
mod windows_platform;

#[cfg(windows)]
pub use windows_platform::WindowsPlatform;

/// Installs this OS's platform as Keylo's.
pub fn install() {
    #[cfg(windows)]
    keylo_core::platform::install(Box::new(WindowsPlatform::new()));

    #[cfg(not(windows))]
    panic!("The Rust port of Keylo doesn't support this OS yet.");
}

/// True while the screen is locked (or the session is disconnected); false when it can't tell.
pub fn is_screen_locked() -> bool {
    #[cfg(windows)]
    {
        windows_platform::is_screen_locked()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn an_unlocked_desktop_reads_as_unlocked() {
        // Run from an interactive, unlocked session (as these tests are).
        assert!(!super::is_screen_locked());
    }
}
