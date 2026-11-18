//! The app's side of updates (see keylo_core::updates): check latest.json, and on Install download
//! and verify the update, install it and restart.
//! - Windows: the release zip; keylow.exe and keylo.exe are swapped in place (as `keylo update` does).
//! - macOS: Tauri's updater replaces Keylo.app (it checks the same signature).
//! - Linux: no in-place updates; the notice links to the release.

use keylo_core::updates;
use serde::Serialize;
use tauri::AppHandle;

use crate::commands::{err, Res};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    current: String,
    latest: String,
    notes: Option<String>,
    available: bool,
    /// Whether Install can update this copy in place; otherwise `reason` says why not and the
    /// release page is offered instead.
    can_install: bool,
    reason: Option<String>,
}

fn blocker() -> Option<String> {
    match updates::program_dir() {
        Ok(dir) => updates::install_blocker(&dir),
        Err(e) => Some(e.to_string()),
    }
}

#[tauri::command]
pub async fn check_update() -> Res<UpdateInfo> {
    let manifest = tauri::async_runtime::spawn_blocking(updates::check).await.map_err(|e| e.to_string())?.map_err(err)?;
    let reason = blocker();
    Ok(UpdateInfo {
        current: updates::CURRENT.to_string(),
        latest: manifest.latest().to_string(),
        notes: manifest.notes.clone().filter(|n| !n.trim().is_empty()),
        available: manifest.is_newer(),
        can_install: reason.is_none(),
        reason,
    })
}

/// Downloads and verifies the update, installs it, and restarts Keylo.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Res<()> {
    if let Some(reason) = blocker() {
        return Err(reason);
    }

    #[cfg(windows)]
    tauri::async_runtime::spawn_blocking(|| -> keylo_core::Result<()> {
        let manifest = updates::check()?;
        if !manifest.is_newer() {
            return Err(keylo_core::Error::msg("Keylo is up to date."));
        }
        let download = manifest.download().ok_or_else(|| keylo_core::Error::msg("The release has no Windows update."))?;
        let zip = updates::download_verified(download)?;
        updates::swap_in_place(&zip, &updates::program_dir()?)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(err)?;

    #[cfg(not(windows))]
    {
        use tauri_plugin_updater::UpdaterExt;
        let fail = |e: tauri_plugin_updater::Error| format!("Couldn't update: {e}");
        let update = app.updater().map_err(fail)?.check().await.map_err(fail)?.ok_or("Keylo is up to date.")?;
        update.download_and_install(|_, _| {}, || {}).await.map_err(fail)?;
    }

    app.restart();
}

#[tauri::command]
pub async fn open_releases() -> Res<()> {
    let url = updates::RELEASES_PAGE;
    #[cfg(windows)]
    let mut command = {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    command.spawn().map(|_| ()).map_err(|e| format!("Couldn't open {url}: {e}"))
}

/// Deletes programs an earlier Windows update set aside (in the background; ones still running stay).
pub fn remove_old_programs() {
    if cfg!(windows) {
        std::thread::spawn(|| {
            if let Ok(dir) = updates::program_dir() {
                updates::remove_old_programs(&dir);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    /// The updater plugin (macOS) and keylo_core (Windows, `keylo update`) must trust the same key.
    #[test]
    fn tauri_conf_has_keylos_update_key() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["plugins"]["updater"]["pubkey"].as_str(), Some(keylo_core::updates::PUBLIC_KEY));
        assert_eq!(conf["plugins"]["updater"]["endpoints"][0].as_str(), Some(keylo_core::updates::LATEST_JSON));
    }
}
