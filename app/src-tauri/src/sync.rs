//! The app's side of syncing (see keylo_core::sync): Settings → Sync, and syncing in the background
//! while Keylo is unlocked: every 30 seconds, and within a few seconds of another device's file
//! changing in the folder.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use keylo_core::sync::{self, Device, Report, Status};
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

use crate::commands::{confirm, ensure, err, require_unlocked, Res};
use crate::AppState;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> keylo_core::Result<T> + Send + 'static) -> Res<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())?.map_err(err)
}

/// After a sync: the window reloads what changed, and Settings → Sync shows the result.
fn announce(app: &AppHandle, report: &Report) {
    if report.received > 0 || !report.conflicts.is_empty() {
        let _ = app.emit("keylo://data-changed", ());
    }
    let _ = app.emit("keylo://synced", ());
}

#[tauri::command]
pub async fn sync_status() -> Res<Option<Status>> {
    blocking(|| sync::status(&Device::local())).await
}

#[tauri::command]
pub async fn sync_device_name() -> Res<String> {
    Ok(sync::default_device_name())
}

#[tauri::command]
pub async fn pick_sync_folder(window: WebviewWindow) -> Res<Option<String>> {
    Ok(window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Choose the folder to sync through")
        .blocking_pick_folder()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string()))
}

#[tauri::command]
pub async fn sync_create(window: WebviewWindow, app: AppHandle, state: State<'_, AppState>, folder: String, name: String) -> Res<Report> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    let report = blocking(move || sync::create(&Device::local(), &PathBuf::from(folder), &name)).await?;
    announce(&app, &report);
    Ok(report)
}

#[tauri::command]
pub async fn sync_join(window: WebviewWindow, app: AppHandle, state: State<'_, AppState>, folder: String, name: String, code: String) -> Res<Report> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    let report = blocking(move || sync::join(&Device::local(), &PathBuf::from(folder), &name, &code)).await?;
    announce(&app, &report);
    Ok(report)
}

/// The join code is the vault key: an identity check every time, even during a session.
#[tauri::command]
pub async fn sync_code(window: WebviewWindow) -> Res<String> {
    confirm(&window, "Keylo: show the sync join code").await?;
    blocking(|| sync::join_code(&Device::local())).await
}

#[tauri::command]
pub async fn sync_now(app: AppHandle, state: State<'_, AppState>) -> Res<Report> {
    require_unlocked(&state)?;
    let report = blocking(|| sync::sync(&Device::local())).await?;
    announce(&app, &report);
    Ok(report)
}

#[tauri::command]
pub async fn sync_rename(name: String) -> Res<()> {
    blocking(move || sync::rename_device(&Device::local(), &name)).await
}

#[tauri::command]
pub async fn sync_forget(id: String) -> Res<()> {
    blocking(move || sync::forget(&Device::local(), &id)).await
}

#[tauri::command]
pub async fn sync_leave() -> Res<()> {
    blocking(|| sync::leave(&Device::local())).await
}

/// Syncs in the background while Keylo is unlocked (a sync reads every value, so never while it's
/// locked): every 30 seconds, and soon after another device's file changes in the folder.
pub fn watch(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last_sync: Option<Instant> = None;
        let mut last_stamp = None;
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let dev = Device::local();
            let Ok(Some(config)) = sync::config(&dev) else {
                last_sync = None;
                continue;
            };
            let unlocked = app.state::<AppState>().gate.lock().map(|g| g.is_unlocked()).unwrap_or(false);
            if !unlocked {
                continue;
            }
            let stamp = sync::folder_stamp(&config);
            let due = last_sync.is_none_or(|t| t.elapsed() >= Duration::from_secs(30));
            if !due && stamp == last_stamp {
                continue;
            }
            last_stamp = stamp;
            last_sync = Some(Instant::now());
            match sync::sync(&dev) {
                Ok(report) => announce(&app, &report),
                // Recorded as the last result; Settings → Sync shows it.
                Err(_) => {
                    let _ = app.emit("keylo://synced", ());
                }
            }
        }
    });
}
