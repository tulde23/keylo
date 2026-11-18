//! Updates from the project's GitHub releases, shared by the app, `keylo update` and the MCP
//! server's check_for_updates.
//!
//! Each release publishes latest.json: the version, notes, and per platform a download and its
//! minisign signature (made with the TAURI_SIGNING_PRIVATE_KEY secret in the release workflow). A
//! download is only used if its signature matches [`PUBLIC_KEY`], the same key as
//! `plugins.updater.pubkey` in the app's tauri.conf.json.
//!
//! On Windows an update is the release zip: keylow.exe and keylo.exe are swapped in place
//! ([`swap_in_place`]). A running .exe can be renamed but not overwritten, so the old files are set
//! aside as *.old and deleted later ([`remove_old_programs`]); running `keylo mcp` servers keep
//! working on the old version until they exit.

use std::path::Path;

use base64::Engine;
use serde::Deserialize;

use crate::{Error, Result};

pub const LATEST_JSON: &str = "https://github.com/tulde23/keylo/releases/latest/download/latest.json";
pub const RELEASES_PAGE: &str = "https://github.com/tulde23/keylo/releases/latest";

/// The update key's public half (base64 of the minisign public key file).
pub const PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDAzQzVCRDZFRUVGMkJCNDEKUldSQnUvTHVicjNGQTYxTmNlRk4wOVd5NHMyaW03ZWNFV25kbVZNdWZoT2I4UEF3RVJqYnVXTWsK";

/// This build's version.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub version: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub platforms: std::collections::HashMap<String, Download>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Download {
    pub url: String,
    pub signature: String,
}

impl Manifest {
    /// The version without a leading "v".
    pub fn latest(&self) -> &str {
        self.version.trim().trim_start_matches('v')
    }

    /// Whether this is newer than the running build.
    pub fn is_newer(&self) -> bool {
        is_newer(self.latest(), CURRENT)
    }

    /// The download for this computer, if the release has one.
    pub fn download(&self) -> Option<&Download> {
        self.platforms.get(platform_key()?)
    }
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    let parse = |v: &str| semver::Version::parse(v.trim().trim_start_matches('v')).ok();
    matches!((parse(latest), parse(current)), (Some(l), Some(c)) if l > c)
}

/// latest.json's name for this platform.
pub fn platform_key() -> Option<&'static str> {
    if cfg!(all(windows, target_arch = "x86_64")) {
        Some("windows-x86_64")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("darwin-aarch64")
    } else {
        None
    }
}

fn agent(seconds: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(seconds)))
        .user_agent("Keylo")
        .build()
        .into()
}

/// Reads latest.json from the newest release.
pub fn check() -> Result<Manifest> {
    let mut response = agent(20).get(LATEST_JSON).call().map_err(|e| match e {
        ureq::Error::StatusCode(404) => Error::msg(format!("The latest release has no update information; see {RELEASES_PAGE}")),
        e => Error::msg(format!("Couldn't check for updates: {e}")),
    })?;
    let text = response.body_mut().read_to_string().map_err(|e| Error::msg(format!("Couldn't check for updates: {e}")))?;
    serde_json::from_str(&text).map_err(|e| Error::msg(format!("The update information isn't readable: {e}")))
}

/// Downloads an update and returns it only if its signature matches [`PUBLIC_KEY`].
pub fn download_verified(download: &Download) -> Result<Vec<u8>> {
    let mut response = agent(600).get(&download.url).call().map_err(|e| Error::msg(format!("Couldn't download the update: {e}")))?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(500 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| Error::msg(format!("Couldn't download the update: {e}")))?;
    verify(&bytes, &download.signature, PUBLIC_KEY)?;
    Ok(bytes)
}

/// Checks a minisign signature the way Tauri's updater does: the key and the signature are each
/// base64 of the minisign file text.
pub fn verify(data: &[u8], signature: &str, public_key: &str) -> Result<()> {
    let text = |b64: &str, what: &str| -> Result<String> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| Error::msg(format!("The update's {what} isn't valid.")))?;
        String::from_utf8(raw).map_err(|_| Error::msg(format!("The update's {what} isn't valid.")))
    };
    let key = minisign_verify::PublicKey::decode(&text(public_key, "key")?).map_err(|_| Error::msg("Keylo's update key isn't valid."))?;
    let sig = minisign_verify::Signature::decode(&text(signature, "signature")?).map_err(|_| Error::msg("The update's signature isn't valid."))?;
    key.verify(data, &sig, true)
        .map_err(|_| Error::msg("The update's signature doesn't match Keylo's update key; it was not installed."))
}

/// Why the copy of Keylo in `dir` can't update itself in place, if it can't.
pub fn install_blocker(dir: &Path) -> Option<String> {
    if cfg!(debug_assertions) {
        return Some("This is a development build.".into());
    }
    if platform_key().is_none() {
        return Some("Updates here are installed from the release page (the .deb or tarball on Linux).".into());
    }
    if cfg!(target_os = "macos") && dir.to_string_lossy().contains("/AppTranslocation/") {
        return Some("Move Keylo to Applications first; macOS is running it from a temporary copy.".into());
    }
    let probe = dir.join(".keylo-update-probe");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            None
        }
        Err(_) => Some(format!("Keylo's folder ({}) isn't writable.", dir.display())),
    }
}

/// The folder the running program is in.
pub fn program_dir() -> Result<std::path::PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.to_path_buf()))
        .ok_or_else(|| Error::msg("Keylo's folder wasn't found."))
}

/// The files a Windows update replaces.
pub const WINDOWS_PROGRAMS: &[&str] = &["keylow.exe", "keylo.exe"];

/// Writes the zip's keylow.exe and keylo.exe into `dir`. Each new file is written beside the old one
/// first; then the old one is renamed aside and the new one moved into place. If anything fails,
/// nothing is left changed.
pub fn swap_in_place(zip: &[u8], dir: &Path) -> Result<()> {
    use std::io::Read;

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip)).map_err(|e| Error::msg(format!("The update isn't a valid zip: {e}")))?;
    let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();

    let mut staged = Vec::new();
    for name in WINDOWS_PROGRAMS {
        let new = dir.join(format!("{name}.new"));
        let written = (|| -> Result<()> {
            let mut entry = archive.by_name(name).map_err(|_| Error::msg(format!("The update has no {name}.")))?;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            std::fs::write(&new, &bytes).map_err(|e| Error::msg(format!("Couldn't write {}: {e}", new.display())))
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(&new);
            for (_, new, _) in &staged {
                let _ = std::fs::remove_file(new);
            }
            return Err(e);
        }
        staged.push((dir.join(name), new, dir.join(format!("{name}.{stamp}.old"))));
    }

    let mut done: Vec<&(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> = Vec::new();
    for s in &staged {
        let (target, new, old) = s;
        let result = (|| -> std::io::Result<()> {
            if target.exists() {
                std::fs::rename(target, old)?;
            }
            if let Err(e) = std::fs::rename(new, target) {
                let _ = std::fs::rename(old, target);
                return Err(e);
            }
            Ok(())
        })();
        if let Err(e) = result {
            for (target, _, old) in done {
                let _ = std::fs::remove_file(target);
                let _ = std::fs::rename(old, target);
            }
            for (_, new, _) in &staged {
                let _ = std::fs::remove_file(new);
            }
            return Err(Error::msg(format!("Couldn't replace {}: {e}", target.display())));
        }
        done.push(s);
    }
    Ok(())
}

/// Deletes programs set aside by an earlier update. One still running (a `keylo mcp` started before
/// the update) can't be deleted yet; a later start tries again.
pub fn remove_old_programs(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        let leftover = WINDOWS_PROGRAMS
            .iter()
            .any(|p| name.starts_with(&format!("{p}.")) && (name.ends_with(".old") || name.ends_with(".new")));
        if leftover {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn versions_compare_as_semver() {
        assert!(is_newer("1.2.10", "1.2.9"));
        assert!(is_newer("v1.3.0", "1.2.99"));
        assert!(!is_newer("1.2.9", "1.2.9"));
        assert!(!is_newer("1.2.8", "1.2.9"));
        assert!(!is_newer("not a version", "1.2.0"));
    }

    // Made with `tauri signer generate` and `tauri signer sign` and a throwaway key (not Keylo's).
    const TEST_KEY: &str = include_str!("../testdata/update-test.key.pub");
    const TEST_SIG: &str = include_str!("../testdata/update-test.txt.sig");
    const TEST_DATA: &[u8] = include_bytes!("../testdata/update-test.txt");

    #[test]
    fn a_tauri_signature_verifies_and_a_changed_file_doesnt() {
        verify(TEST_DATA, TEST_SIG, TEST_KEY).unwrap();
        let mut changed = TEST_DATA.to_vec();
        changed[0] ^= 1;
        assert!(verify(&changed, TEST_SIG, TEST_KEY).is_err());
        // Keylo's real key didn't sign it.
        assert!(verify(TEST_DATA, TEST_SIG, PUBLIC_KEY).is_err());
    }

    #[test]
    fn the_public_key_is_valid() {
        let raw = base64::engine::general_purpose::STANDARD.decode(PUBLIC_KEY).unwrap();
        minisign_verify::PublicKey::decode(std::str::from_utf8(&raw).unwrap()).unwrap();
    }

    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in files {
            out.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            out.write_all(bytes).unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("keylo-update-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn swaps_both_programs_and_keeps_the_old_ones_aside() {
        let dir = temp_dir("swap");
        std::fs::write(dir.join("keylow.exe"), b"old app").unwrap();
        std::fs::write(dir.join("keylo.exe"), b"old cli").unwrap();
        // On Windows a running program can be renamed but not overwritten: hold keylo.exe open like `keylo mcp`.
        let running = std::fs::File::open(dir.join("keylo.exe")).unwrap();

        swap_in_place(&zip_of(&[("keylow.exe", b"new app"), ("keylo.exe", b"new cli"), ("install.ps1", b"")]), &dir).unwrap();

        assert_eq!(std::fs::read(dir.join("keylow.exe")).unwrap(), b"new app");
        assert_eq!(std::fs::read(dir.join("keylo.exe")).unwrap(), b"new cli");
        let names = || -> Vec<String> { std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect() };
        assert_eq!(names().iter().filter(|n| n.ends_with(".old")).count(), 2, "{:?}", names());
        assert!(!dir.join("install.ps1").exists());

        drop(running);
        remove_old_programs(&dir);
        let mut left = names();
        left.sort();
        assert_eq!(left, ["keylo.exe", "keylow.exe"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_incomplete_update_changes_nothing() {
        let dir = temp_dir("incomplete");
        std::fs::write(dir.join("keylow.exe"), b"old app").unwrap();
        std::fs::write(dir.join("keylo.exe"), b"old cli").unwrap();

        assert!(swap_in_place(&zip_of(&[("keylow.exe", b"new app")]), &dir).is_err());

        assert_eq!(std::fs::read(dir.join("keylow.exe")).unwrap(), b"old app");
        assert_eq!(std::fs::read(dir.join("keylo.exe")).unwrap(), b"old cli");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
