use std::path::PathBuf;

pub const DEFAULT_PREFIX: &str = "Keylo:";

/// The data folder: KEYLO_HOME, else the per-user local data folder + "Keylo"
/// (%LOCALAPPDATA%\Keylo, ~/Library/Application Support/Keylo, ~/.local/share/Keylo).
pub fn data_dir() -> PathBuf {
    match std::env::var("KEYLO_HOME") {
        Ok(home) if !home.is_empty() => PathBuf::from(home),
        _ => dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")).join("Keylo"),
    }
}

/// Uploaded icon images (icons/{hash}.png).
pub fn icon_dir() -> PathBuf {
    data_dir().join("icons")
}

/// The OS store's item-name prefix: "Keylo:", or KEYLO_PREFIX (tests use their own).
pub fn credential_prefix() -> String {
    match std::env::var("KEYLO_PREFIX") {
        Ok(p) if !p.is_empty() => p,
        _ => DEFAULT_PREFIX.to_string(),
    }
}
