//! config.json: the identity-check mode, timeouts, access keys and provider settings. Fields this
//! version doesn't know are kept as they are, so older and newer versions can share one file.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::access::AccessKey;
use crate::{paths, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum HelloMode {
    /// Verify once, then trust this user for `session_minutes` (CLI and app share it).
    #[default]
    Session,
    /// Verify on every value access.
    Always,
    /// No prompt; rely on the OS login alone.
    Never,
}

fn d_session() -> i64 {
    15
}
fn d_clipboard() -> i64 {
    30
}
fn d_audit() -> i64 {
    90
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyloConfig {
    #[serde(default)]
    pub hello: HelloMode,
    #[serde(default = "d_session")]
    pub session_minutes: i64,
    #[serde(default = "d_clipboard")]
    pub clipboard_seconds: i64,
    /// Days of audit log to keep; 0 keeps everything.
    #[serde(default = "d_audit")]
    pub audit_retention_days: i64,
    #[serde(default)]
    pub access_keys: Vec<AccessKey>,
    /// Per-provider settings, e.g. { "1password": { "vault": "Private" } }.
    #[serde(default)]
    pub providers: BTreeMap<String, BTreeMap<String, String>>,
    /// Anything else in the file, written back unchanged.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

impl Default for KeyloConfig {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap()
    }
}

impl KeyloConfig {
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join("config.json")
    }

    pub fn load() -> Result<Self> {
        Self::load_from(&paths::data_dir())
    }

    pub fn load_from(dir: &Path) -> Result<Self> {
        let path = Self::path_in(dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path)?;
        let mut config: KeyloConfig = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|e| Error::msg(format!("config.json is invalid: {e}")))?;
        config.clamp();
        Ok(config)
    }

    pub fn save(&mut self) -> Result<()> {
        self.save_to(&paths::data_dir())
    }

    pub fn save_to(&mut self, dir: &Path) -> Result<()> {
        self.clamp();
        fs::create_dir_all(dir)?;
        fs::write(Self::path_in(dir), serde_json::to_string_pretty(self).unwrap())?;
        Ok(())
    }

    fn clamp(&mut self) {
        self.session_minutes = self.session_minutes.clamp(1, 24 * 60);
        self.clipboard_seconds = self.clipboard_seconds.clamp(5, 600);
        self.audit_retention_days = if self.audit_retention_days <= 0 { 0 } else { self.audit_retention_days.clamp(7, 3650) };
    }
}
