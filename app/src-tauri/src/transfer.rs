//! Import, backup and restore for the app. File dialogs open from here (the web view has no file
//! system access); a decrypted backup waits in AppState between previewing and restoring.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use keylo_core::backup::{self, BackupSummary, RestoreResult};
use keylo_core::categories::CategoryCatalog;
use keylo_core::import::{self, ImportOptions, ImportResult};
use keylo_core::store::SecretStore;
use keylo_core::types::SecretTypeCatalog;
use keylo_core::paths;
use serde::{Deserialize, Serialize};
use tauri::{State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroizing;

use crate::commands::{confirm, ensure, err, require_unlocked, Res};
use crate::AppState;

fn to_paths(files: Option<Vec<tauri_plugin_dialog::FilePath>>) -> Vec<String> {
    files.unwrap_or_default().into_iter().filter_map(|f| f.into_path().ok()).map(|p| p.display().to_string()).collect()
}

// ---------------------------------------------------------------------------- import

/// Files (or, with `folder`, folders) to import; empty when the dialog is canceled.
#[tauri::command]
pub async fn pick_import(window: WebviewWindow, folder: bool) -> Vec<String> {
    let dialog = window.dialog().file().set_parent(&window);
    if folder {
        to_paths(dialog.set_title("Import folders").blocking_pick_folders())
    } else {
        to_paths(dialog.set_title("Import files").blocking_pick_files())
    }
}

/// Paths Keylo was started with (`--import`), once.
#[tauri::command]
pub async fn take_startup_import(state: State<'_, AppState>) -> Res<Vec<String>> {
    Ok(std::mem::take(&mut *state.startup_import.lock().unwrap())
        .into_iter()
        .map(|p| std::path::absolute(&p).map(|a| a.display().to_string()).unwrap_or(p))
        .collect())
}

#[tauri::command]
pub async fn import_plan(state: State<'_, AppState>, paths: Vec<String>, category: Option<String>, subfolder_categories: bool) -> Res<ImportResult> {
    require_unlocked(&state)?;
    import::plan(&paths, category.as_deref(), subfolder_categories, Some(&SecretStore::default())).map_err(err)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportInput {
    paths: Vec<String>,
    category: Option<String>,
    subfolder_categories: bool,
    overwrite: bool,
    /// Per file (full path): the secret's name, and its type ("" for plain).
    names: HashMap<String, String>,
    types: HashMap<String, String>,
    delete_originals: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOutcome {
    #[serde(flatten)]
    result: ImportResult,
    deleted: usize,
}

#[tauri::command]
pub async fn import_files(window: WebviewWindow, state: State<'_, AppState>, input: ImportInput) -> Res<ImportOutcome> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    let options = ImportOptions {
        category: input.category.filter(|c| !c.trim().is_empty()),
        overwrite: input.overwrite,
        subfolder_categories: input.subfolder_categories,
        names: input.names,
        types: input.types,
        infer_types: true,
    };
    let result = import::import(&SecretStore::default(), &SecretTypeCatalog::default(), &input.paths, &options).map_err(err)?;
    let mut deleted = 0;
    let mut result = result;
    if input.delete_originals && !result.imported.is_empty() {
        let failed = import::delete_originals(&result.imported);
        deleted = result.imported.len() - failed.len();
        result.skipped.extend(failed.into_iter().map(|mut f| {
            f.reason = format!("Imported, but the file couldn't be deleted: {}", f.reason);
            f
        }));
    }
    Ok(ImportOutcome { result, deleted })
}

// ---------------------------------------------------------------------------- backup and restore

/// Where to save a backup (`save`) or which one to open; None when canceled.
#[tauri::command]
pub async fn pick_backup(window: WebviewWindow, save: bool) -> Option<String> {
    let dialog = window.dialog().file().set_parent(&window).add_filter("Keylo backup", &[backup::FILE_EXTENSION]);
    let picked = if save {
        let name = format!("keylo-{}.{}", chrono::Local::now().format("%Y-%m-%d"), backup::FILE_EXTENSION);
        dialog.set_title("Back up Keylo").set_file_name(name).blocking_save_file()
    } else {
        dialog.set_title("Restore a Keylo backup").blocking_pick_file()
    };
    picked.and_then(|p| p.into_path().ok()).map(|p| p.display().to_string())
}

#[tauri::command]
pub async fn check_backup_password(password: String) -> Option<String> {
    let password = Zeroizing::new(password);
    backup::check_password(&password)
}

/// Writes a backup of everything. It exports every value, so it always asks for the identity check.
#[tauri::command]
pub async fn create_backup(window: WebviewWindow, state: State<'_, AppState>, path: String, password: String) -> Res<BackupSummary> {
    require_unlocked(&state)?;
    let password = Zeroizing::new(password);
    if let Some(problem) = backup::check_password(&password) {
        return Err(problem);
    }
    confirm(&window, "Keylo: back up all secrets").await?;
    let path = backup::with_extension(Path::new(&path));
    let dir = paths::data_dir();
    let contents = backup::collect(&SecretStore::default(), &CategoryCatalog::in_dir(&dir), &SecretTypeCatalog::default(), &dir).map_err(err)?;
    backup::write(&contents, &path, &password, backup::DEFAULT_ITERATIONS).map_err(err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupPreview {
    path: String,
    created_at: String,
    secrets: usize,
    existing: usize,
    categories: usize,
    icons: usize,
    types: usize,
}

/// Decrypts a backup and says what restoring it would do; it waits for restore_backup.
#[tauri::command]
pub async fn open_backup(window: WebviewWindow, state: State<'_, AppState>, path: String, password: String) -> Res<BackupPreview> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    let password = Zeroizing::new(password);
    let contents = backup::read(&PathBuf::from(&path), &password).map_err(err)?;
    let store = SecretStore::default();
    let mut existing = 0;
    for s in &contents.secrets {
        if store.exists(&s.name).map_err(err)? {
            existing += 1;
        }
    }
    let preview = BackupPreview {
        path,
        created_at: contents.created_at.to_rfc3339(),
        secrets: contents.secrets.len(),
        existing,
        categories: contents.categories.len(),
        icons: contents.icons.len(),
        types: contents.types.len(),
    };
    *state.pending_restore.lock().unwrap() = Some(contents);
    Ok(preview)
}

#[tauri::command]
pub async fn restore_backup(window: WebviewWindow, state: State<'_, AppState>, overwrite: bool) -> Res<RestoreResult> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    let contents = state.pending_restore.lock().unwrap().take().ok_or("Open the backup again.")?;
    let dir = paths::data_dir();
    let mut catalog = CategoryCatalog::in_dir(&dir);
    backup::restore(&SecretStore::default(), &mut catalog, &SecretTypeCatalog::default(), &dir, &contents, overwrite).map_err(err)
}

/// Forgets a decrypted backup that wasn't restored.
#[tauri::command]
pub async fn cancel_restore(state: State<'_, AppState>) -> Res<()> {
    state.pending_restore.lock().unwrap().take();
    Ok(())
}

// ---------------------------------------------------------------------------- other password managers

/// A CSV export from another password manager; None when canceled.
#[tauri::command]
pub async fn pick_password_export(window: WebviewWindow) -> Option<String> {
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Choose the export from your other password manager")
        .add_filter("CSV export", &["csv"])
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
}

/// The app a CSV was exported from, if it's a password export (for the Import panel to offer it).
#[tauri::command]
pub async fn password_export_format(path: String) -> Option<String> {
    let path = PathBuf::from(path);
    let is_csv = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("csv"));
    if !is_csv {
        return None;
    }
    tauri::async_runtime::spawn_blocking(move || keylo_core::pm_import::detect(&path)).await.ok().flatten()
}

/// What importing an export would do (names, sites, usernames, categories; never passwords).
#[tauri::command]
pub async fn password_import_plan(state: State<'_, AppState>, path: String, category: Option<String>) -> Res<keylo_core::pm_import::PasswordImport> {
    require_unlocked(&state)?;
    tauri::async_runtime::spawn_blocking(move || keylo_core::pm_import::plan(Path::new(&path), category.as_deref(), &SecretStore::default()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(err)
}

/// Imports an export; with `delete_file`, removes it afterwards (it holds every password in plain text).
#[tauri::command]
pub async fn password_import(
    window: WebviewWindow,
    state: State<'_, AppState>,
    path: String,
    category: Option<String>,
    overwrite: bool,
    delete_file: bool,
) -> Res<keylo_core::pm_import::PasswordImport> {
    ensure(&window, &state, "Unlock Keylo", false).await?;
    tauri::async_runtime::spawn_blocking(move || {
        let path = PathBuf::from(path);
        let result = keylo_core::pm_import::import(&path, category.as_deref(), overwrite, &SecretStore::default()).map_err(err)?;
        if delete_file && result.imported > 0 {
            std::fs::remove_file(&path).map_err(|e| format!("Imported, but couldn't delete {}: {e}", path.display()))?;
        }
        Ok(result)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Where to save a password export; None when canceled.
#[tauri::command]
pub async fn pick_password_export_save(window: WebviewWindow, format: String) -> Option<String> {
    let name = format!("keylo-{}-{}.csv", format.to_lowercase(), chrono::Local::now().format("%Y-%m-%d"));
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Export passwords")
        .add_filter("CSV", &["csv"])
        .set_file_name(name)
        .blocking_save_file()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
}

/// Writes secrets as a CSV another password manager imports. Plain text, so it always asks for
/// the identity check.
#[tauri::command]
pub async fn export_passwords(
    window: WebviewWindow,
    state: State<'_, AppState>,
    path: String,
    format: String,
    category: Option<String>,
) -> Res<keylo_core::pm_export::PasswordExport> {
    use keylo_core::pm_export::{self, ExportFormat};
    require_unlocked(&state)?;
    let format = ExportFormat::parse(&format).ok_or_else(|| format!("Unknown export format '{format}'."))?;
    confirm(&window, "Keylo: export passwords in plain text").await?;
    tauri::async_runtime::spawn_blocking(move || {
        pm_export::export(Path::new(&path), format, category.as_deref(), &SecretStore::default(), &SecretTypeCatalog::default()).map_err(err)
    })
    .await
    .map_err(|e| e.to_string())?
}
