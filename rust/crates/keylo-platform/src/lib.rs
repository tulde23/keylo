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
