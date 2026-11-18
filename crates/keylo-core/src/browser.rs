//! The browser extension's link to Keylo: native messaging. A browser starts `keylo` (the "native
//! messaging host") when the Keylo extension asks, and only for the extension ids listed in the
//! host's manifest. This module writes and removes those manifests for each browser, and decides
//! which logins belong to a page.
//!
//! Where browsers look for the manifest:
//! - Windows: a registry key per browser (HKCU\Software\…\NativeMessagingHosts\{name}) pointing at
//!   the manifest file, which Keylo keeps in its data folder.
//! - macOS and Linux: the manifest file itself, in a folder per browser.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{bail, paths, Error, Result};

/// The native messaging host's name, as the extension calls it.
pub const HOST_NAME: &str = "io.github.tulde23.keylo";
/// The extension's id in Chrome, Edge and Brave (fixed by the public key in its manifest).
pub const CHROME_EXTENSION_ID: &str = "agnnnnmhcgeabnaakpoidnblaaeaicfi";
/// The extension's id in Firefox.
pub const FIREFOX_EXTENSION_ID: &str = "keylo@tulde23.github.io";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Edge,
    Brave,
    Chromium,
    Firefox,
}

impl Browser {
    pub const ALL: [Browser; 5] = [Browser::Chrome, Browser::Edge, Browser::Brave, Browser::Chromium, Browser::Firefox];

    pub fn id(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Edge => "edge",
            Browser::Brave => "brave",
            Browser::Chromium => "chromium",
            Browser::Firefox => "firefox",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Browser::Chrome => "Google Chrome",
            Browser::Edge => "Microsoft Edge",
            Browser::Brave => "Brave",
            Browser::Chromium => "Chromium",
            Browser::Firefox => "Firefox",
        }
    }

    pub fn parse(id: &str) -> Option<Browser> {
        Browser::ALL.into_iter().find(|b| b.id().eq_ignore_ascii_case(id.trim()))
    }

    fn is_firefox(self) -> bool {
        self == Browser::Firefox
    }

    /// HKCU\{this}\{HOST_NAME} on Windows.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn registry_key(self) -> &'static str {
        match self {
            Browser::Chrome => r"Software\Google\Chrome\NativeMessagingHosts",
            Browser::Edge => r"Software\Microsoft\Edge\NativeMessagingHosts",
            Browser::Brave => r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
            Browser::Chromium => r"Software\Chromium\NativeMessagingHosts",
            Browser::Firefox => r"Software\Mozilla\NativeMessagingHosts",
        }
    }

    /// Where the manifest file goes: on macOS and Linux the folder the browser reads; on Windows,
    /// Keylo's data folder (the registry points there).
    fn manifest_path(self) -> Option<PathBuf> {
        let file = format!("{HOST_NAME}.json");
        if cfg!(windows) {
            let kind = if self.is_firefox() { "firefox" } else { "chromium" };
            return Some(paths::data_dir().join("browser").join(kind).join(file));
        }
        let home = dirs::home_dir()?;
        let dir = if cfg!(target_os = "macos") {
            let support = home.join("Library/Application Support");
            match self {
                Browser::Chrome => support.join("Google/Chrome/NativeMessagingHosts"),
                Browser::Edge => support.join("Microsoft Edge/NativeMessagingHosts"),
                Browser::Brave => support.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
                Browser::Chromium => support.join("Chromium/NativeMessagingHosts"),
                Browser::Firefox => support.join("Mozilla/NativeMessagingHosts"),
            }
        } else {
            let config = home.join(".config");
            match self {
                Browser::Chrome => config.join("google-chrome/NativeMessagingHosts"),
                Browser::Edge => config.join("microsoft-edge/NativeMessagingHosts"),
                Browser::Brave => config.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
                Browser::Chromium => config.join("chromium/NativeMessagingHosts"),
                Browser::Firefox => home.join(".mozilla/native-messaging-hosts"),
            }
        };
        Some(dir.join(file))
    }

    /// Whether the browser seems to be installed (its program or profile folder exists).
    fn detected(self) -> bool {
        let candidates: Vec<PathBuf> = if cfg!(windows) {
            let env = |v: &str| std::env::var(v).ok().map(PathBuf::from);
            let roots: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"].iter().filter_map(|v| env(v)).collect();
            let rel = match self {
                Browser::Chrome => r"Google\Chrome\Application\chrome.exe",
                Browser::Edge => r"Microsoft\Edge\Application\msedge.exe",
                Browser::Brave => r"BraveSoftware\Brave-Browser\Application\brave.exe",
                Browser::Chromium => r"Chromium\Application\chrome.exe",
                Browser::Firefox => r"Mozilla Firefox\firefox.exe",
            };
            roots.into_iter().map(|r| r.join(rel)).collect()
        } else if cfg!(target_os = "macos") {
            let app = match self {
                Browser::Chrome => "Google Chrome.app",
                Browser::Edge => "Microsoft Edge.app",
                Browser::Brave => "Brave Browser.app",
                Browser::Chromium => "Chromium.app",
                Browser::Firefox => "Firefox.app",
            };
            let mut c = vec![PathBuf::from("/Applications").join(app)];
            if let Some(h) = dirs::home_dir() {
                c.push(h.join("Applications").join(app));
            }
            c
        } else {
            // The profile folder's parent exists once the browser has run.
            self.manifest_path().and_then(|p| p.parent().and_then(|d| d.parent()).map(Path::to_path_buf)).into_iter().collect()
        };
        candidates.iter().any(|p| p.exists())
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStatus {
    pub id: String,
    pub name: String,
    /// The browser seems to be installed.
    pub detected: bool,
    /// Keylo is registered as its native messaging host, pointing at this `keylo`.
    pub connected: bool,
    /// Registered, but for a `keylo` somewhere else (an older install).
    pub elsewhere: Option<String>,
}

/// Every browser Keylo knows, and whether it can talk to the extension.
pub fn status(keylo: &Path) -> Vec<BrowserStatus> {
    Browser::ALL
        .into_iter()
        .map(|b| {
            let registered = registered_path(b);
            let connected = registered.as_deref().is_some_and(|p| same_path(p, keylo));
            BrowserStatus {
                id: b.id().into(),
                name: b.name().into(),
                detected: b.detected(),
                connected,
                elsewhere: registered.filter(|_| !connected).map(|p| p.display().to_string()),
            }
        })
        .collect()
}

/// Lets `browser` start `keylo` (this program's path) for the Keylo extension.
pub fn connect(browser: Browser, keylo: &Path) -> Result<()> {
    if !keylo.is_file() {
        bail!("{} wasn't found; the browser needs the keylo command installed next to Keylo.", keylo.display());
    }
    let manifest = browser.manifest_path().ok_or_else(|| Error::msg("Your home folder wasn't found."))?;
    let allowed = if browser.is_firefox() {
        serde_json::json!({ "allowed_extensions": [FIREFOX_EXTENSION_ID] })
    } else {
        serde_json::json!({ "allowed_origins": [format!("chrome-extension://{CHROME_EXTENSION_ID}/")] })
    };
    let mut doc = serde_json::json!({
        "name": HOST_NAME,
        "description": "Keylo: fills your saved logins",
        "path": keylo.display().to_string(),
        "type": "stdio",
    });
    doc.as_object_mut().unwrap().extend(allowed.as_object().unwrap().clone());
    if let Some(dir) = manifest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&manifest, serde_json::to_string_pretty(&doc).unwrap())?;
    #[cfg(windows)]
    reg(&["add", &format!(r"HKCU\{}\{HOST_NAME}", browser.registry_key()), "/ve", "/t", "REG_SZ", "/d", &manifest.display().to_string(), "/f"])?;
    Ok(())
}

/// Stops `browser` from starting Keylo.
pub fn disconnect(browser: Browser) -> Result<()> {
    #[cfg(windows)]
    {
        let key = format!(r"HKCU\{}\{HOST_NAME}", browser.registry_key());
        if reg(&["query", &key, "/ve"]).is_ok() {
            reg(&["delete", &key, "/f"])?;
        }
        // The manifest file is shared by the Chromium browsers: keep it while another uses it.
        let still_used = Browser::ALL.into_iter().any(|b| b != browser && b.is_firefox() == browser.is_firefox() && registered_path(b).is_some());
        if !still_used {
            if let Some(m) = browser.manifest_path() {
                let _ = std::fs::remove_file(m);
            }
        }
    }
    #[cfg(not(windows))]
    if let Some(m) = browser.manifest_path() {
        let _ = std::fs::remove_file(m);
    }
    Ok(())
}

/// The `keylo` a browser would start, if Keylo is registered with it.
fn registered_path(browser: Browser) -> Option<PathBuf> {
    #[cfg(windows)]
    let manifest = {
        let out = reg(&["query", &format!(r"HKCU\{}\{HOST_NAME}", browser.registry_key()), "/ve"]).ok()?;
        // "    (Default)    REG_SZ    C:\...\io.github.tulde23.keylo.json"
        let line = out.lines().find(|l| l.contains("REG_SZ"))?;
        PathBuf::from(line.split("REG_SZ").nth(1)?.trim())
    };
    #[cfg(not(windows))]
    let manifest = browser.manifest_path()?;
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(manifest).ok()?).ok()?;
    doc.get("path").and_then(|p| p.as_str()).map(PathBuf::from)
}

fn same_path(a: &Path, b: &Path) -> bool {
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let (a, b) = (canon(a), canon(b));
    if cfg!(windows) {
        a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
    } else {
        a == b
    }
}

#[cfg(windows)]
fn reg(args: &[&str]) -> Result<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("reg").args(args).creation_flags(CREATE_NO_WINDOW).output()?;
    if !out.status.success() {
        bail!("reg {} failed: {}", args[0], String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------------------- which logins fit a page

/// A page's site: lower-case host without "www.", and the port if one is given.
fn site(url: &str) -> Option<(String, String, Option<u16>)> {
    let url = url.trim();
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("https".to_string(), url),
    };
    let authority = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || h.ends_with(']') => (h, p.parse().ok()),
        _ => (authority, None),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    (!host.is_empty()).then_some((scheme, host, port))
}

/// Whether a login saved for `login_url` may be filled on `page_url`: the page is https (or a local
/// address), and its host is the login's host or a subdomain of it ("github.com" fills on
/// "gist.github.com", never the other way, and never on "github.com.evil.io").
pub fn site_matches(login_url: &str, page_url: &str) -> bool {
    let (Some((_, lh, lp)), Some((ps, ph, pp))) = (site(login_url), site(page_url)) else { return false };
    let local = ph == "localhost" || ph == "127.0.0.1" || ph == "[::1]";
    if ps != "https" && !(ps == "http" && local) {
        return false;
    }
    if lp.is_some() && lp != pp {
        return false;
    }
    ph == lh || ph.ends_with(&format!(".{lh}"))
}

/// Whether a page can be filled at all (https, or a local address over http).
pub fn fillable_page(page_url: &str) -> bool {
    site(page_url).is_some_and(|(s, h, _)| s == "https" || (s == "http" && (h == "localhost" || h == "127.0.0.1" || h == "[::1]")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logins_match_their_site_and_its_subdomains_only() {
        assert!(site_matches("https://github.com/login", "https://github.com/session"));
        assert!(site_matches("github.com", "https://www.github.com/"));
        assert!(site_matches("https://github.com", "https://gist.github.com/x"));
        assert!(!site_matches("https://gist.github.com", "https://github.com/"), "not upwards");
        assert!(!site_matches("https://github.com", "https://github.com.evil.io/"));
        assert!(!site_matches("https://github.com", "https://evilgithub.com/"));
        assert!(!site_matches("https://github.com", "http://github.com/"), "never over plain http");
        assert!(site_matches("http://localhost:3000", "http://localhost:3000/login"));
        assert!(!site_matches("http://localhost:3000", "http://localhost:4000/login"), "the port counts when given");
        assert!(!site_matches("https://user@github.com", "https://github.com:443@evil.io/"));
        assert!(!site_matches("", "https://github.com/"));
        assert!(fillable_page("https://x.io") && !fillable_page("http://x.io") && !fillable_page("file:///c:/x.html"));
    }

    #[test]
    fn browsers_parse_and_have_manifest_places() {
        for b in Browser::ALL {
            assert_eq!(Browser::parse(b.id()), Some(b));
            assert!(b.manifest_path().unwrap().ends_with(format!("{HOST_NAME}.json")));
        }
        assert_eq!(Browser::parse("nope"), None);
    }
}
