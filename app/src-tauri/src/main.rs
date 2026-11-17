//! Keylo's desktop app (Tauri + React). Started with `--approve <request>` by `keylo mcp`, it
//! shows only an approval window and exits with the answer (10 denied, 11 once, 12 always).
//! `keylow --import PATH...` opens the Import panel with those files and folders.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod transfer;
mod vaults;

use std::sync::Mutex;

use keylo_core::approval::{self, ApprovalRequest};
use keylo_core::config::KeyloConfig;
use keylo_core::gate::AccessGate;
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};

pub struct AppState {
    pub gate: Mutex<AccessGate>,
    pub approval: Option<ApprovalRequest>,
    /// Paths from `--import` waiting for the UI to pick them up.
    pub startup_import: Mutex<Vec<String>>,
    /// A decrypted backup between previewing and restoring it.
    pub pending_restore: Mutex<Option<keylo_core::backup::BackupContents>>,
}

fn main() {
    keylo_platform::install();

    let args: Vec<String> = std::env::args().collect();
    let approval = args
        .iter()
        .position(|a| a == approval::ARGUMENT)
        .and_then(|i| args.get(i + 1))
        .and_then(|encoded| ApprovalRequest::decode(encoded));
    if args.iter().any(|a| a == approval::ARGUMENT) && approval.is_none() {
        std::process::exit(approval::DENIED);
    }

    let config = KeyloConfig::load().unwrap_or_default();
    let approving = approval.is_some();
    let state = AppState { gate: Mutex::new(AccessGate::new(&config)), approval, startup_import: Mutex::new(import_args(&args)), pending_restore: Mutex::new(None) };

    let mut builder = tauri::Builder::default();
    if !approving {
        // Opening Keylo again shows the window that's already open. (Approval windows are separate:
        // several agents can ask at once.)
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, cwd| {
            // `keylow --import ...` while Keylo is open: hand the paths (relative to that shell) over.
            let paths: Vec<String> = import_args(&args)
                .into_iter()
                .map(|p| std::path::Path::new(&cwd).join(p).display().to_string())
                .collect();
            if !paths.is_empty() {
                let _ = app.emit("keylo://import", paths);
            }
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
        }));
    }

    builder
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::status,
            commands::unlock,
            commands::lock,
            commands::touch,
            commands::secrets,
            commands::secret_types,
            commands::save_type,
            commands::delete_type,
            commands::categories,
            commands::fetch_image,
            commands::save_icon_image,
            commands::icon_image,
            commands::create_category,
            commands::set_category_style,
            commands::rename_category,
            commands::delete_category,
            commands::reveal,
            commands::copy_field,
            commands::save_secret,
            commands::delete_secret,
            commands::set_pinned,
            commands::recent,
            commands::settings,
            commands::save_settings,
            commands::access_keys,
            commands::create_key,
            commands::update_key,
            commands::revoke_key,
            commands::audit_log,
            commands::generate_password,
            commands::approval_request,
            commands::answer_approval,
            transfer::pick_import,
            commands::claude_status,
            commands::ui_theme,
            commands::set_ui_theme,
            commands::add_to_claude,
            vaults::vault_providers,
            vaults::save_vault_provider,
            vaults::vault_status,
            vaults::aws_choices,
            vaults::link_search,
            vaults::link_describe,
            vaults::create_links,
            vaults::push_preview,
            vaults::push_secret,
            transfer::take_startup_import,
            transfer::import_plan,
            transfer::import_files,
            transfer::pick_backup,
            transfer::check_backup_password,
            transfer::create_backup,
            transfer::open_backup,
            transfer::restore_backup,
            transfer::cancel_restore,
        ])
        .setup(move |app| {
            if approving {
                WebviewWindowBuilder::new(app, "approve", WebviewUrl::App("index.html#approve".into()))
                    .title("Keylo: approve access")
                    .inner_size(480.0, 440.0)
                    .resizable(false)
                    .minimizable(false)
                    .maximizable(false)
                    .always_on_top(true)
                    .center()
                    .focused(true)
                    .build()?;
                // The agent waits on this window; deny by itself after 5 minutes.
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(300));
                    handle.exit(approval::DENIED);
                });
            } else {
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("Keylo")
                    .inner_size(1120.0, 720.0)
                    .min_inner_size(760.0, 480.0)
                    .center()
                    .build()?;
                watch_screen_lock(app.handle().clone());
                watch_data_files(app.handle().clone());
            }
            Ok(())
        })
        .on_window_event(move |window, event| {
            // Closing the approval window is a denial.
            if approving && matches!(event, tauri::WindowEvent::CloseRequested { .. }) {
                window.app_handle().exit(approval::DENIED);
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Keylo");
}

/// The paths after `--import` (up to the next option).
fn import_args(args: &[String]) -> Vec<String> {
    match args.iter().position(|a| a == "--import") {
        Some(i) => args[i + 1..].iter().take_while(|a| !a.starts_with("--")).cloned().collect(),
        None => vec![],
    }
}

/// Tells the window when Keylo's files change outside it (the keylo command, another Keylo, an
/// agent's use), so it can reload: keys and settings, types, categories, pins and recent uses, the
/// audit log, the session. Checked every 2 seconds by modification time and size; cheap, no I/O
/// beyond file metadata.
fn watch_data_files(app: tauri::AppHandle) {
    const FILES: &[&str] = &[
        "config.json", "types.json", "categories.json", "pins.json", "recent.json", "audit.log", "session.bin", "vault.json",
    ];
    std::thread::spawn(move || {
        let stamp = || -> Vec<Option<(std::time::SystemTime, u64)>> {
            let dir = keylo_core::paths::data_dir();
            FILES
                .iter()
                .map(|f| std::fs::metadata(dir.join(f)).ok().and_then(|m| Some((m.modified().ok()?, m.len()))))
                .collect()
        };
        let mut last = stamp();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let now = stamp();
            if now != last {
                last = now;
                let _ = app.emit("keylo://data-changed", ());
            }
        }
    });
}

/// Locks Keylo when the screen locks: the session ends (for the keylo command too) and the app shows
/// its lock screen.
fn watch_screen_lock(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        let mut was_locked = false;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let locked = keylo_platform::is_screen_locked();
            if locked && !was_locked {
                app.state::<AppState>().gate.lock().unwrap().lock();
                let _ = app.emit("keylo://locked", ());
            }
            was_locked = locked;
        }
    });
}
