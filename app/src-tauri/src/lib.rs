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

use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

/// the webview's measured device-pixel-ratio (physical px per CSS px). the
/// frontend reports it after load so window sizing can multiply CSS sizes by it
/// and the layout always gets its intended logical width, whatever GTK, XWayland,
/// or the compositor does to the surface. seeded with a startup guess.
pub struct DisplayScale(pub Mutex<f64>);

fn valid_scale(scale: f64) -> Option<f64> {
    (scale.is_finite() && (0.5..=4.0).contains(&scale)).then_some(scale)
}

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
        .manage(DisplayScale(Mutex::new(1.0)))
        .manage(prompt::PromptCount::default())
        .invoke_handler(tauri::generate_handler![
            ipc::engine_status,
            ipc::set_tick_details,
            ipc::list_rules,
            ipc::list_apps,
            ipc::forget_app,
            ipc::list_alerts,
            ipc::restore_connection_prompts,
            prompt::resize_connection_prompts,
            report_display_scale,
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
            // best startup guess before the webview reports its real ratio: the
            // fractional-scaling env hint if we set one, else the window's own
            // gtk scale factor. keeps the first paint from flashing under-sized.
            let initial_scale = {
                let hint = prompt::webview_scale();
                if (hint - 1.0).abs() > f64::EPSILON {
                    hint
                } else {
                    app.get_webview_window("main")
                        .and_then(|w| w.scale_factor().ok())
                        .filter(|s| s.is_finite() && *s > 0.0)
                        .unwrap_or(1.0)
                }
            };
            *app.state::<DisplayScale>().0.lock().unwrap() = initial_scale;
            fit_main_window(app.handle(), initial_scale);
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

/// the webview reports its real device-pixel-ratio once the page loads; re-fit
/// the reporting window to that truth. sizing in physical pixels (css * ratio)
/// lands the CSS viewport at the intended logical width whether the surface is
/// scaled by GTK, XWayland, native wayland, or not at all.
#[tauri::command]
fn report_display_scale(
    app: tauri::AppHandle,
    window: tauri::Window,
    scale: f64,
) -> Result<(), String> {
    let Some(scale) = valid_scale(scale) else {
        return Ok(());
    };
    {
        let state = app.state::<DisplayScale>();
        let mut current = state.0.lock().unwrap();
        // only react to a genuine change: re-fitting on every duplicate report
        // would fight a window the user has since resized
        if (*current - scale).abs() < 0.005 {
            return Ok(());
        }
        *current = scale;
    }
    match window.label() {
        "main" => fit_main_window(&app, scale),
        prompt::LABEL => prompt::apply_scale(&app, scale),
        _ => {}
    }
    Ok(())
}

fn fit_main_window(app: &tauri::AppHandle, scale: f64) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let Ok(Some(monitor)) = window.current_monitor() else {
        return;
    };
    // work_area is physical pixels; so are the sizes we set below (css * scale)
    let work = monitor.work_area().size;
    let margin = 32.0 * scale;
    let available_width = (f64::from(work.width) - margin).max(640.0 * scale);
    let available_height = (f64::from(work.height) - margin).max(480.0 * scale);
    // the widest tab (Protect's console + rule matrix) needs ~1080 logical px
    // before its fixed columns overflow and clip, so hold the window minimum there
    let (width, min_width) = main_dimension(1180.0, 1080.0, available_width, scale);
    let (height, min_height) = main_dimension(820.0, 600.0, available_height, scale);
    let _ = window.set_min_size(Some(tauri::PhysicalSize::new(min_width, min_height)));
    let _ = window.set_size(tauri::PhysicalSize::new(width, height));
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
