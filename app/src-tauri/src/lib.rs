//! the Iris desktop shell. this crate is the thin Tauri host: it opens the
//! window, exposes the command surface the UI needs, runs a tray icon, and
//! bridges the UI to the privileged engine service over the named-pipe IPC.

mod icon;
mod ipc;
mod net;
mod report;
mod rulectl;
mod startup;
mod svcctl;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

/// build and run the Tauri application
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iris=info,iris_ipc=info".into()),
        )
        .init();

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(32);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(ipc::StatusState::default())
        .manage(ipc::Commander(cmd_tx))
        .invoke_handler(tauri::generate_handler![
            ipc::engine_status,
            ipc::list_rules,
            ipc::list_alerts,
            ipc::ack_alert,
            ipc::get_usage,
            ipc::get_adapter_usage,
            ipc::kill_connection,
            ipc::get_enrichment,
            ipc::list_plugins,
            ipc::grant_plugin,
            ipc::set_plugin_enabled,
            ipc::list_proposals,
            ipc::reject_proposal,
            ipc::get_plugin_panel,
            net::reverse_dns,
            svcctl::install_service,
            svcctl::uninstall_service,
            rulectl::rule_add,
            rulectl::rule_remove,
            rulectl::rule_set_enabled,
            rulectl::rule_import,
            rulectl::proposal_accept,
            startup::get_launch_at_login,
            startup::set_launch_at_login,
            report::save_download,
            icon::app_icon
        ])
        .setup(move |app| {
            ipc::spawn(app.handle().clone(), cmd_rx);
            build_tray(app.handle())?;
            // a login launch passes --tray so it comes up quietly in the tray
            if std::env::args().any(|a| a == "--tray") {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // close to tray: hide the window and keep the app (and its tray
            // icon and pipe client) alive. real exit is the tray "Quit" item.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Iris");
}

/// a tray icon that restores the window on click and offers show / quit
fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show Iris", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    TrayIconBuilder::with_id("iris-tray")
        .icon(app.default_window_icon().unwrap().clone())
        .tooltip("Iris")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => reveal(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, .. } = event {
                reveal(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

fn reveal(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}
