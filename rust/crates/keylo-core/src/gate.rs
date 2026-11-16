//! Decides when the identity check (Windows Hello, Touch ID, polkit) must run before a secret is used.
//!
//! This is a presence check, not encryption: values are protected by the OS store and readable by
//! any process running as this user. session.bin holds the session's expiry (UTC .NET ticks,
//! little-endian), protected by the platform's data protector: the same file as the C# build.

use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Duration, TimeZone, Utc};

use crate::config::{HelloMode, KeyloConfig};
use crate::platform::{self, VerificationResult};
use crate::{paths, Error, Result};

const SESSION_ENTROPY: &[u8] = b"keylo:session:v1";
/// .NET ticks (100 ns since 0001-01-01) at the Unix epoch.
const UNIX_EPOCH_TICKS: i64 = 621_355_968_000_000_000;

pub struct AccessGate {
    mode: HelloMode,
    session_minutes: i64,
    session_path: PathBuf,
    // In Always mode, browsing is allowed after one verification in this process.
    browse_unlocked: bool,
}

impl AccessGate {
    pub fn new(config: &KeyloConfig) -> Self {
        AccessGate {
            mode: config.hello,
            session_minutes: config.session_minutes,
            session_path: paths::data_dir().join("session.bin"),
            browse_unlocked: false,
        }
    }

    pub fn mode(&self) -> HelloMode {
        self.mode
    }

    pub fn session_expires_at(&self) -> Option<DateTime<Utc>> {
        if self.mode == HelloMode::Session { self.read_session() } else { None }
    }

    /// Whether the secret list can be shown without prompting.
    pub fn is_unlocked(&self) -> bool {
        match self.mode {
            HelloMode::Never => true,
            HelloMode::Session => self.read_session().is_some(),
            HelloMode::Always => self.browse_unlocked,
        }
    }

    pub fn unlock(&mut self, owner: isize, message: &str) -> Result<()> {
        self.ensure(owner, message, false)
    }

    /// Fails with AccessDenied unless access is (or just became) allowed.
    pub fn ensure(&mut self, owner: isize, message: &str, value_access: bool) -> Result<()> {
        match self.mode {
            HelloMode::Never => return Ok(()),
            HelloMode::Session if self.read_session().is_some() => return Ok(()),
            HelloMode::Always if !value_access && self.browse_unlocked => return Ok(()),
            _ => {}
        }
        let (result, detail) = platform::current().verifier().verify(owner, message);
        let name = verifier_name();
        match result {
            VerificationResult::Verified => {
                self.browse_unlocked = true;
                if self.mode == HelloMode::Session {
                    self.write_session(Utc::now() + Duration::minutes(self.session_minutes))?;
                }
                Ok(())
            }
            VerificationResult::Unavailable => {
                let how = if cfg!(windows) { "Set it up in Settings → Accounts → Sign-in options, or run " } else { "Set it up, or run " };
                Err(Error::AccessDenied(format!(
                    "{name} isn't available ({}). {how}'keylo config hello never'.",
                    detail.unwrap_or_default()
                )))
            }
            VerificationResult::Canceled => Err(Error::AccessDenied(format!("{name} was canceled."))),
            VerificationResult::Failed => Err(Error::AccessDenied(format!(
                "{name} verification failed{}.",
                detail.map(|d| format!(" ({d})")).unwrap_or_default()
            ))),
        }
    }

    /// Always verifies (ignoring any session) unless the check is off. For changes to the settings
    /// that decide what skips verification.
    pub fn confirm(&self, owner: isize, message: &str) -> Result<()> {
        if self.mode == HelloMode::Never {
            return Ok(());
        }
        let (result, detail) = platform::current().verifier().verify(owner, message);
        let name = verifier_name();
        match result {
            VerificationResult::Verified => Ok(()),
            VerificationResult::Canceled => Err(Error::AccessDenied(format!("{name} was canceled."))),
            _ => Err(Error::AccessDenied(format!(
                "{name} verification failed{}.",
                detail.map(|d| format!(" ({d})")).unwrap_or_default()
            ))),
        }
    }

    /// Slides an active session's expiry to a full session length from now (app activity only).
    pub fn extend_session(&self) -> Result<()> {
        if self.mode != HelloMode::Session {
            return Ok(());
        }
        let Some(expires) = self.read_session() else { return Ok(()) };
        let extended = Utc::now() + Duration::minutes(self.session_minutes);
        if extended - expires > Duration::seconds(30) {
            self.write_session(extended)?;
        }
        Ok(())
    }

    pub fn lock(&mut self) {
        self.browse_unlocked = false;
        let _ = fs::remove_file(&self.session_path);
    }

    fn read_session(&self) -> Option<DateTime<Utc>> {
        let data = fs::read(&self.session_path).ok()?;
        let raw = platform::current().data_protector().unprotect(&data, SESSION_ENTROPY).ok()?;
        let ticks = i64::from_le_bytes(raw.as_slice().try_into().ok()?);
        let expires = Utc.timestamp_nanos((ticks - UNIX_EPOCH_TICKS).checked_mul(100)?);
        let now = Utc::now();
        // Reject a session that outlives the configured length (e.g. after it was shortened).
        (expires > now && expires <= now + Duration::minutes(self.session_minutes)).then_some(expires)
    }

    fn write_session(&self, expires: DateTime<Utc>) -> Result<()> {
        let ticks = expires.timestamp_nanos_opt().unwrap_or(0) / 100 + UNIX_EPOCH_TICKS;
        if let Some(dir) = self.session_path.parent() {
            fs::create_dir_all(dir)?;
        }
        let data = platform::current().data_protector().protect(&ticks.to_le_bytes(), SESSION_ENTROPY)?;
        fs::write(&self.session_path, data)?;
        Ok(())
    }
}

/// "Windows Hello", "Touch ID"… capitalized, to start a message with.
pub fn verifier_name() -> String {
    let name = if platform::is_installed() { platform::current().verifier_name() } else { "Windows Hello".into() };
    let mut c = name.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => name,
    }
}
