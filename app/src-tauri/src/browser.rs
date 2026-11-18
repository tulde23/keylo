//! Settings → Browser: lets each browser start `keylo` for the Keylo extension (native messaging),
//! using the keylo command installed next to the app.

use keylo_core::browser::{self, Browser, BrowserStatus};
use std::path::PathBuf;

use crate::commands::{err, Res};

fn keylo() -> PathBuf {
    PathBuf::from(crate::commands::keylo_path())
}

#[tauri::command]
pub async fn browser_status() -> Res<Vec<BrowserStatus>> {
    tauri::async_runtime::spawn_blocking(|| browser::status(&keylo())).await.map_err(|e| e.to_string())
}

fn which(id: &str) -> Res<Browser> {
    Browser::parse(id).ok_or_else(|| format!("No browser '{id}'."))
}

#[tauri::command]
pub async fn browser_connect(id: String) -> Res<Vec<BrowserStatus>> {
    let b = which(&id)?;
    tauri::async_runtime::spawn_blocking(move || {
        browser::connect(b, &keylo()).map_err(err)?;
        Ok(browser::status(&keylo()))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn browser_disconnect(id: String) -> Res<Vec<BrowserStatus>> {
    let b = which(&id)?;
    tauri::async_runtime::spawn_blocking(move || {
        browser::disconnect(b).map_err(err)?;
        Ok(browser::status(&keylo()))
    })
    .await
    .map_err(|e| e.to_string())?
}
