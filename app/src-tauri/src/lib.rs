//! the Iris desktop shell. this crate is the thin Tauri host: it opens the
//! window, exposes the command surface the UI needs, runs a tray icon, and
//! bridges the UI to the privileged engine service over the named-pipe IPC.

mod elevate;
mod icon;
mod ipc;
mod net;
mod notify;
mod prefs;
mod prompt;
mod report;
mod rulectl;
mod startup;
mod svcctl;
mod traygraph;
mod updater;

use std::sync::Mutex;
use iris_core::FirewallMode;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

/// the webview's measured device-pixel-ratio (physical px per CSS px). the
/// frontend reports it after load so window sizing can multiply CSS sizes by it
/// and the layout always gets its intended logical width, whatever GTK, XWayland,
/// or the compositor does to the surface. seeded with a startup guess.
pub struct DisplayScale(pub Mutex<f64>);

pub(crate) const TRAY_ID: &str = "iris-tray";

/// the tray's firewall mode entries, kept so a change made anywhere ticks the
/// right one
struct ModeMenu(Vec<(FirewallMode, CheckMenuItem<tauri::Wry>)>);

const MODES: [(FirewallMode, &str, &str); 3] = [
    (FirewallMode::Ask, "mode-ask", "Ask before new apps connect"),
    (FirewallMode::Notify, "mode-notify", "Allow new apps and notify"),
    (FirewallMode::Lockdown, "mode-lockdown", "Lockdown: block everything"),
];

/// tick the tray entry for `mode` and untick the others
pub(crate) fn refresh_mode_menu(app: &tauri::AppHandle, mode: FirewallMode) {
    if let Some(menu) = app.try_state::<ModeMenu>() {
        for (item_mode, item) in &menu.0 {
            let _ = item.set_checked(*item_mode == mode);
        }
    }
}

fn valid_scale(scale: f64) -> Option<f64> {
    (scale.is_finite() && (0.5..=4.0).contains(&scale)).then_some(scale)
}

/// build and run the Tauri application
pub fn run() {
    #[cfg(windows)]
    {
        use windows::core::w;
        use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
        unsafe {
            let _ = SetCurrentProcessExplicitAppUserModelID(w!("lt.rot.iris"));
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iris=info,iris_ipc=info".into()),
        )
        .init();

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(32);

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _| {
            if !args.iter().any(|arg| arg == "--tray") {
                reveal(app);
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(ipc::StatusState::default())
        .manage(ipc::TickDetailState::default())
        .manage(ipc::Commander(cmd_tx))
        .manage(DisplayScale(Mutex::new(1.0)))
        .manage(prompt::PromptState::default())
        .manage(traygraph::TrayGraphState::default())
        .manage(notify::NotifyState::default())
        .manage(prefs::PrefsState::default())
        .invoke_handler(tauri::generate_handler![
            ipc::engine_status,
            ipc::set_tick_details,
            ipc::list_rules,
            ipc::list_apps,
            ipc::forget_app,
            ipc::forget_apps,
            ipc::rule_grant,
            rulectl::set_rule_grant,
            ipc::list_alerts,
            prompt::resize_connection_prompts,
            prompt::set_prompt_hit_region,
            prompt::prompt_cards,
            prompt::set_prompt_aside,
            prompt::dismiss_info_card,
            rulectl::firewall_mode,
            ipc::get_host_usage,
            ipc::get_profiles,
            ipc::list_caps,
            ipc::list_quotas,
            ipc::engine_health,
            rulectl::set_cap,
            rulectl::set_quota,
            rulectl::set_profiles,
            traygraph::set_tray_graph,
            rulectl::set_firewall_mode,
            notify::set_notifications_enabled,
            notify::set_info_cards,
            prefs::host_prefs,
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
            icon::app_icon,
            updater::check_installer_update,
            updater::install_installer_update
        ])
        .setup(move |app| {
            ipc::spawn(app.handle().clone(), cmd_rx);
            build_tray(app.handle())?;
            let prefs = prefs::load(app.handle());
            notify::apply_enabled(app.handle(), prefs.notifications);
            traygraph::apply_enabled(app.handle(), prefs.tray_graph);
            if let Err(error) = startup::repair_launch_at_login() {
                tracing::warn!("could not refresh launch at login: {error}");
            }
            // a login launch passes --tray so it comes up quietly in the tray,
            // with no webview until the window is first opened
            if !std::env::args().any(|a| a == "--tray") {
                open_main(app.handle());
            }
            updater::schedule(app.handle());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Iris")
        // closing the main window destroys its webview; the tray, the card host
        // and the pipe client keep running until the tray's "Quit"
        .run(|_app, event| {
            if let tauri::RunEvent::ExitRequested { code: None, api, .. } = event {
                api.prevent_exit();
            }
        });
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
        let mut current = state.0.lock().unwrap_or_else(|error| error.into_inner());
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
    let pause = CheckMenuItem::with_id(
        app,
        "pause-prompts",
        "Pause connection prompts",
        true,
        prompt::snoozed(app),
        None::<&str>,
    )?;
    let mode_items = MODES
        .iter()
        .map(|(mode, id, label)| {
            CheckMenuItem::with_id(app, *id, *label, true, *mode == FirewallMode::Ask, None::<&str>)
                .map(|item| (*mode, item))
        })
        .collect::<tauri::Result<Vec<_>>>()?;
    let mode_refs: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> =
        mode_items.iter().map(|(_, item)| item as _).collect();
    let modes = Submenu::with_items(app, "Firewall mode", true, &mode_refs)?;
    app.manage(ModeMenu(mode_items));
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&show, &modes, &pause, &separator, &quit])?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(app.default_window_icon().unwrap().clone())
        .tooltip("Iris")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "show" => reveal(app),
            "pause-prompts" => prompt::set_snoozed(app, pause.is_checked().unwrap_or(false)),
            "quit" => app.exit(0),
            id => {
                if let Some((mode, _, _)) = MODES.iter().find(|(_, mode_id, _)| *mode_id == id) {
                    choose_mode(app, *mode);
                }
            }
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

/// a check item flips itself on click; put the ticks back to the engine's truth
/// until the change lands, so a refused elevation never leaves a false tick
fn choose_mode(app: &tauri::AppHandle, mode: FirewallMode) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let current = ipc::firewall_mode(&app).await.unwrap_or_default();
        refresh_mode_menu(&app, current);
        if current == mode {
            return;
        }
        if let Err(error) = rulectl::set_firewall_mode(app.clone(), mode.as_str().into()).await {
            tracing::warn!(mode = mode.as_str(), "could not switch firewall mode: {error}");
        }
    });
}

fn reveal(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
        return;
    }
    // webview2 creation deadlocks inside the tray and single-instance handlers
    // that call this, so build from a worker, which routes through the event loop
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Some(win) = open_main(&app) {
            let _ = win.set_focus();
        }
    });
}

/// build the main window from its config entry and fit it to its monitor
fn open_main(app: &tauri::AppHandle) -> Option<tauri::WebviewWindow> {
    let config = app.config().app.windows.iter().find(|window| window.label == "main")?;
    let window = match tauri::WebviewWindowBuilder::from_config(app, config).and_then(|builder| builder.build()) {
        Ok(window) => window,
        Err(error) => {
            tracing::warn!("could not open the main window: {error}");
            return None;
        }
    };
    // best guess before the webview reports its real ratio: the
    // fractional-scaling env hint if we set one, else the window's own scale
    // factor. keeps the first paint from flashing under-sized
    let hint = prompt::webview_scale();
    let scale = if (hint - 1.0).abs() > f64::EPSILON {
        hint
    } else {
        window
            .scale_factor()
            .ok()
            .filter(|s| s.is_finite() && *s > 0.0)
            .unwrap_or(1.0)
    };
    *app.state::<DisplayScale>()
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = scale;
    fit_main_window(app, scale);
    let _ = window.center();
    Some(window)
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
