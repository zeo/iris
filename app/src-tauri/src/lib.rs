//! the Iris desktop shell. this crate is the thin Tauri host: it opens the
//! window, exposes the command surface the UI needs, runs a tray icon, and
//! bridges the UI to the privileged engine service over the named-pipe IPC.

mod elevate;
mod icon;
mod ipc;
mod net;
mod prompt;
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
        .manage(ipc::TickDetailState::default())
        .manage(ipc::Commander(cmd_tx))
        .invoke_handler(tauri::generate_handler![
            ipc::engine_status,
            ipc::set_tick_details,
            ipc::list_rules,
            ipc::list_apps,
            ipc::forget_app,
            ipc::list_alerts,
            ipc::restore_connection_prompts,
            prompt::resize_connection_prompts,
            ipc::ack_alert,
            ipc::decide_alert,
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
            fit_main_window(app.handle());
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
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Iris");
}

fn fit_main_window(app: &tauri::AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let (Ok(Some(monitor)), Ok(scale)) = (window.current_monitor(), window.scale_factor()) else {
        return;
    };
    let work = monitor.work_area().size;
    let available_width = (f64::from(work.width) / scale - 32.0).max(640.0);
    let available_height = (f64::from(work.height) / scale - 32.0).max(480.0);
    let webview_scale = prompt::webview_scale();
    // the widest tab (Protect's 7-column table) needs ~1080 logical px before its
  // fixed columns overflow and clip, so hold the window minimum there
  let (width, min_width) = main_dimension(1180.0, 1080.0, available_width, webview_scale);
    let (height, min_height) = main_dimension(820.0, 600.0, available_height, webview_scale);
    // under the fractional-scaling workaround (GDK_SCALE=1) the computed sizes are
    // already physical pixels; set_size(LogicalSize) would divide the 1.5x back out
    // and leave the content at its base width while webkit renders it 1.5x larger,
    // which clips. size in physical pixels in that mode, logical otherwise.
    if (webview_scale - 1.0).abs() < f64::EPSILON {
        let _ = window.set_min_size(Some(tauri::LogicalSize::new(min_width, min_height)));
        let _ = window.set_size(tauri::LogicalSize::new(width, height));
    } else {
        let _ = window.set_min_size(Some(tauri::PhysicalSize::new(min_width, min_height)));
        let _ = window.set_size(tauri::PhysicalSize::new(width, height));
    }
    let _ = window.set_resizable(true);
    let _ = window.set_maximizable(true);
}

fn main_dimension(preferred: f64, minimum: f64, available: f64, webview_scale: f64) -> (f64, f64) {
    let size = (preferred * webview_scale).min(available);
    (size, (minimum * webview_scale).min(size))
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
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                ..
            } = event
            {
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

#[cfg(test)]
mod tests {
    use super::main_dimension;

    #[test]
    fn expands_main_host_for_fractional_webview_scale() {
        assert_eq!(main_dimension(1180.0, 820.0, 2000.0, 1.5), (1770.0, 1230.0));
        assert_eq!(main_dimension(820.0, 600.0, 1400.0, 1.5), (1230.0, 900.0));
    }

    #[test]
    fn caps_main_host_to_the_monitor_work_area() {
        assert_eq!(main_dimension(1180.0, 820.0, 1500.0, 1.5), (1500.0, 1230.0));
        assert_eq!(main_dimension(820.0, 600.0, 1000.0, 1.5), (1000.0, 900.0));
    }
}
