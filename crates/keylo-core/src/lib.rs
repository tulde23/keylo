//! Keylo's OS-neutral core: the secret store format, secret types, settings, access keys, the
//! identity gate and the audit log. Compatible with the C# Keylo's data: secrets, config.json,
//! types.json, session.bin and audit.log written by either can be read by the other.

pub mod access;
pub mod activity;
pub mod approval;
pub mod backup;
pub mod browser;
pub mod categories;
pub mod claude_code;
pub mod config;
pub mod error;
pub mod gate;
pub mod icons;
pub mod import;
pub mod inference;
pub mod links;
pub mod password;
pub mod paths;
pub mod platform;
pub mod pm_import;
pub mod redactor;
pub mod refs;
pub mod search;
pub mod secrets;
pub mod store;
pub mod sync;
pub mod totp;
pub mod types;
pub mod updates;
pub mod version;

pub use error::{Error, Result};

/// Case-insensitive equality, as .NET's OrdinalIgnoreCase (close enough for names and categories).
pub fn eq_ic(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b) || a.to_lowercase() == b.to_lowercase()
}

/// Case-insensitive substring test.
pub fn contains_ic(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[cfg(test)]
pub(crate) mod testing;
