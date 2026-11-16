//! Keylo's desktop app (Tauri + React). Started with `--approve <request>` by `keylo mcp`, it
//! shows only an approval window and exits with the answer (10 denied, 11 once, 12 always).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use std::sync::Mutex;

use keylo_core::approval::{self, ApprovalRequest};
use keylo_core::config::KeyloConfig;
use keylo_core::gate::AccessGate;
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

pub struct AppState {
    pub gate: Mutex<AccessGate>,
    pub approval: Option<ApprovalRequest>,
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
    let state = AppState { gate: Mutex::new(AccessGate::new(&config)), approval };

    tauri::Builder::default()
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
        ])
        .setup(move |app| {
            if approving {
                WebviewWindowBuilder::new(app, "approve", WebviewUrl::App("index.html#approve".into()))
                    .title("Keylo: approve access")
                    .inner_size(480.0, 440.0)
                    .resizable(false)
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
