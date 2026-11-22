//! the Iris desktop shell. this crate is the thin ceri host: it opens the
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

use ceri::{MenuItem, Monitor, TrayConfig, TrayEvent, WindowAction, WindowConfig};
use iris_core::FirewallMode;
use std::sync::{LazyLock, Mutex, OnceLock};

/// the page's measured device-pixel-ratio (physical px per CSS px). the
/// frontend reports it after load so window sizing can multiply CSS sizes by it
/// and the layout always gets its intended logical width, whatever the
/// compositor does to the surface. seeded with a startup guess.
pub struct DisplayScale(pub Mutex<f64>);

static DISPLAY_SCALE: DisplayScale = DisplayScale(Mutex::new(1.0));

const IDENTIFIER: &str = "lt.rot.iris";
const ICON: &[u8] = include_bytes!("../icons/icon.png");

static APP: OnceLock<ceri::AppHandle> = OnceLock::new();

/// the running app, for the commands a page calls
fn handle() -> ceri::AppHandle {
    APP.get().expect("commands run after the app is built").clone()
}

static RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().expect("could not start the async runtime"));

/// where the pipe client and every async command run
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    &RUNTIME
}

const MODES: [(FirewallMode, &str, &str); 3] = [
    (FirewallMode::Ask, "mode-ask", "Ask before new apps connect"),
    (FirewallMode::Notify, "mode-notify", "Allow new apps and notify"),
    (FirewallMode::Lockdown, "mode-lockdown", "Lockdown: block everything"),
];

/// tick the tray entry for `mode` and untick the others
pub(crate) fn refresh_mode_menu(app: &ceri::AppHandle, mode: FirewallMode) {
    if let Some(tray) = app.tray() {
        for (item_mode, id, _) in &MODES {
            tray.set_checked(id, *item_mode == mode);
        }
    }
}

fn valid_scale(scale: f64) -> Option<f64> {
    (scale.is_finite() && (0.5..=4.0).contains(&scale)).then_some(scale)
}

/// what the Iris window is allowed to call, and through the opener to open
const MAIN_COMMANDS: &[&str] = &[
    "opener:open-url",
    "opener:reveal",
    "engine_status",
    "engine_health",
    "set_tick_details",
    "list_rules",
    "list_apps",
    "forget_app",
    "list_alerts",
    "list_blocked",
    "firewall_mode",
    "get_host_usage",
    "host_addresses",
    "get_profiles",
    "list_caps",
    "set_cap",
    "list_quotas",
    "set_quota",
    "set_profiles",
    "set_tray_graph",
    "forget_apps",
    "rule_grant",
    "set_rule_grant",
    "set_notifications_enabled",
    "set_info_cards",
    "host_prefs",
    "set_firewall_mode",
    "resize_connection_prompts",
    "report_display_scale",
    "ack_alert",
    "decide_alert",
    "get_usage",
    "get_adapter_usage",
    "kill_connection",
    "get_enrichment",
    "list_plugins",
    "grant_plugin",
    "set_plugin_enabled",
    "list_proposals",
    "reject_proposal",
    "get_plugin_panel",
    "reverse_dns",
    "install_service",
    "uninstall_service",
    "reset_outbound",
    "rule_add",
    "rule_remove",
    "rule_set_enabled",
    "rule_import",
    "proposal_accept",
    "get_launch_at_login",
    "set_launch_at_login",
    "save_download",
    "app_icon",
    "check_installer_update",
    "install_installer_update",
];

/// network decision prompt access
const PROMPT_COMMANDS: &[&str] = &[
    "prompt_cards",
    "set_prompt_aside",
    "dismiss_info_card",
    "resize_connection_prompts",
    "set_prompt_hit_region",
    "report_display_scale",
    "decide_alert",
    "app_icon",
];

fn capabilities() -> ceri::Capabilities {
    let grant = |window: &str, commands: &[&str]| ceri::Grant {
        windows: vec![window.into()],
        origins: vec![ceri::APP_ORIGIN.into()],
        commands: commands.iter().map(|command| command.to_string()).collect(),
    };
    ceri::Capabilities::new(vec![grant("main", MAIN_COMMANDS), grant(prompt::LABEL, PROMPT_COMMANDS)])
}

/// build and run the ceri application
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
    let _ = ipc::COMMANDER.set(ipc::Commander(cmd_tx));

    let app = ceri::App::new()
        .identifier(IDENTIFIER)
        .name("Iris")
        .version(env!("CARGO_PKG_VERSION"))
        .icon(ICON)
        .assets(ceri::embedded_assets!())
        .content_security_policy(
            "default-src 'self'; base-uri 'none'; object-src 'none'; img-src 'self' data: blob:; \
             style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'",
        )
        .capabilities(capabilities())
        // closing the main window drops its page; the tray, the card host
        // and the pipe client keep running until the tray's "Quit"
        .keep_running()
        // --remote-debugging-port inspects the pages, as webview2's browser arguments did
        .devtools(true)
        .single_instance(|app, args, _| {
            if !args.iter().any(|arg| arg == "--tray") {
                reveal(app);
            }
        })
        .tray(TrayConfig { tooltip: "Iris".into(), menu: tray_menu(), ..TrayConfig::default() }, tray_event)
        .on_window_opened(|app, label| {
            if label == prompt::LABEL {
                prompt::host_opened(app);
            }
        })
        .on_start(move |app| {
            ipc::spawn(app.clone(), cmd_rx);
            let prefs = prefs::load();
            notify::apply_enabled(prefs.notifications);
            traygraph::apply_enabled(app, prefs.tray_graph);
            if let Err(error) = startup::repair_launch_at_login() {
                tracing::warn!("could not refresh launch at login: {error}");
            }
            // a login launch passes --tray so it comes up quietly in the tray,
            // with no page until the window is first opened
            if !std::env::args().any(|a| a == "--tray") {
                reveal(app);
            }
            updater::schedule(app);
        });
    // a debug build loads the pages from `pnpm dev` so edits show up live
    #[cfg(debug_assertions)]
    let app = app.dev_url("http://localhost:1423");
    // the tauri build kept the page's settings in webview2's storage, under the same identifier
    #[cfg(windows)]
    let app = match ceri::dirs::local_data() {
        Some(data) => app.import_local_storage(
            data.join(IDENTIFIER).join("EBWebView/Default/Local Storage/leveldb"),
            "http://tauri.localhost",
        ),
        None => app,
    };
    let _ = APP.set(app.handle());
    commands(app).run().expect("error while running Iris");
}

/// the command surface the pages call. every command answers from a thread of
/// its own, where an async one waits on the runtime
fn commands(app: ceri::App) -> ceri::App {
    fn wait<T>(command: impl std::future::Future<Output = T>) -> T {
        runtime().block_on(command)
    }
    app.blocking_json_command("engine_status", ceri::command!(|| ipc::engine_status()))
        .blocking_json_command(
            "set_tick_details",
            ceri::command!(|enabled: bool, cadence_ms: u64| ipc::set_tick_details(enabled, cadence_ms)),
        )
        .blocking_json_command("list_rules", ceri::command!(|| wait(ipc::list_rules())))
        .blocking_json_command("list_apps", ceri::command!(|| wait(ipc::list_apps())))
        .blocking_json_command("forget_app", ceri::command!(|path: String| wait(ipc::forget_app(path))))
        .blocking_json_command(
            "forget_apps",
            ceri::command!(|paths: Vec<String>| wait(ipc::forget_apps(paths))),
        )
        .blocking_json_command("rule_grant", ceri::command!(|| wait(ipc::rule_grant())))
        .blocking_json_command(
            "set_rule_grant",
            ceri::command!(|granted: bool| wait(rulectl::set_rule_grant(granted))),
        )
        .blocking_json_command(
            "list_alerts",
            ceri::command!(|unacked_only: bool| wait(ipc::list_alerts(unacked_only))),
        )
        .blocking_json_command("list_blocked", ceri::command!(|limit: u32| wait(ipc::list_blocked(limit))))
        .blocking_json_command(
            "resize_connection_prompts",
            ceri::command!(|count: usize| prompt::resize_connection_prompts(handle(), count)),
        )
        .blocking_json_command(
            "set_prompt_hit_region",
            ceri::command!(|rects: Vec<prompt::HitRect>| prompt::set_prompt_hit_region(handle(), rects)),
        )
        .blocking_json_command("prompt_cards", ceri::command!(|| wait(prompt::prompt_cards())))
        .blocking_json_command("set_prompt_aside", ceri::command!(|id: i64| prompt::set_prompt_aside(id)))
        .blocking_json_command("dismiss_info_card", ceri::command!(|id: u64| prompt::dismiss_info_card(id)))
        .blocking_json_command("firewall_mode", ceri::command!(|| wait(rulectl::firewall_mode())))
        .blocking_json_command(
            "get_host_usage",
            ceri::command!(|path: Option<String>, from_ms: u64, to_ms: u64| wait(ipc::get_host_usage(path,
                from_ms,
                to_ms
            ))),
        )
        .blocking_json_command(
            "host_addresses",
            ceri::command!(|host: String| wait(ipc::host_addresses(host))),
        )
        .blocking_json_command("get_profiles", ceri::command!(|| wait(ipc::get_profiles())))
        .blocking_json_command("list_caps", ceri::command!(|| wait(ipc::list_caps())))
        .blocking_json_command("list_quotas", ceri::command!(|| wait(ipc::list_quotas())))
        .blocking_json_command("engine_health", ceri::command!(|| wait(ipc::engine_health())))
        .blocking_json_command(
            "set_cap",
            ceri::command!(
                |path: String, up_bytes_per_sec: Option<u64>, down_bytes_per_sec: Option<u64>| wait(
                    rulectl::set_cap(path, up_bytes_per_sec, down_bytes_per_sec)
                )
            ),
        )
        .blocking_json_command(
            "set_quota",
            ceri::command!(|path: Option<String>, limit: Option<iris_core::QuotaLimit>| wait(rulectl::set_quota(path,
                limit
            ))),
        )
        .blocking_json_command(
            "set_profiles",
            ceri::command!(|profiles: Vec<iris_core::Profile>, manual: Option<String>| wait(
                rulectl::set_profiles(handle(), profiles, manual)
            )),
        )
        .blocking_json_command(
            "set_tray_graph",
            ceri::command!(|enabled: bool| traygraph::set_tray_graph(handle(), enabled)),
        )
        .blocking_json_command(
            "set_firewall_mode",
            ceri::command!(|mode: String| wait(rulectl::set_firewall_mode(handle(), mode))),
        )
        .blocking_json_command(
            "set_notifications_enabled",
            ceri::command!(|enabled: bool| notify::set_notifications_enabled(enabled)),
        )
        .blocking_json_command(
            "set_info_cards",
            ceri::command!(|cards: prefs::InfoCards| notify::set_info_cards(cards)),
        )
        .blocking_json_command("host_prefs", ceri::command!(|| prefs::host_prefs()))
        .blocking_json_command(
            "report_display_scale",
            ceri::command!(|call, scale: f64| report_display_scale(handle(), &call.window, scale)),
        )
        .blocking_json_command("ack_alert", ceri::command!(|id: i64| wait(ipc::ack_alert(handle(), id))))
        .blocking_json_command(
            "decide_alert",
            ceri::command!(|id: i64, action: String, options: Option<rulectl::RuleOptions>| wait(
                ipc::decide_alert(handle(), id, action, options)
            )),
        )
        .blocking_json_command(
            "get_usage",
            ceri::command!(|from_ms: f64, to_ms: f64, granularity: String| wait(ipc::get_usage(from_ms,
                to_ms,
                granularity
            ))),
        )
        .blocking_json_command(
            "get_adapter_usage",
            ceri::command!(|from_ms: f64, to_ms: f64| wait(ipc::get_adapter_usage(from_ms, to_ms))),
        )
        .blocking_json_command(
            "kill_connection",
            ceri::command!(|local_port: u16, remote_addr: String, remote_port: u16| wait(ipc::kill_connection(local_port,
                remote_addr,
                remote_port
            ))),
        )
        .blocking_json_command(
            "get_enrichment",
            ceri::command!(|ips: Vec<String>| wait(ipc::get_enrichment(ips))),
        )
        .blocking_json_command("list_plugins", ceri::command!(|| wait(ipc::list_plugins())))
        .blocking_json_command(
            "grant_plugin",
            ceri::command!(|id: String, caps: Vec<String>, egress: Vec<String>| wait(ipc::grant_plugin(id,
                caps,
                egress
            ))),
        )
        .blocking_json_command(
            "set_plugin_enabled",
            ceri::command!(|id: String, enabled: bool| wait(ipc::set_plugin_enabled(id, enabled))),
        )
        .blocking_json_command("list_proposals", ceri::command!(|| wait(ipc::list_proposals())))
        .blocking_json_command("reject_proposal", ceri::command!(|id: i64| wait(ipc::reject_proposal(id))))
        .blocking_json_command(
            "get_plugin_panel",
            ceri::command!(|id: String| wait(ipc::get_plugin_panel(id))),
        )
        .blocking_json_command("reverse_dns", ceri::command!(|ip: String| wait(net::reverse_dns(ip))))
        .blocking_json_command("install_service", ceri::command!(|| wait(svcctl::install_service())))
        .blocking_json_command("uninstall_service", ceri::command!(|| wait(svcctl::uninstall_service())))
        .blocking_json_command("reset_outbound", ceri::command!(|| wait(svcctl::reset_outbound())))
        .blocking_json_command(
            "rule_add",
            ceri::command!(
                |path: String, direction: String, action: String, options: Option<rulectl::RuleOptions>| wait(
                    rulectl::rule_add(path, direction, action, options)
                )
            ),
        )
        .blocking_json_command("rule_remove", ceri::command!(|id: i64| wait(rulectl::rule_remove(id))))
        .blocking_json_command(
            "rule_set_enabled",
            ceri::command!(|id: i64, enabled: bool| wait(rulectl::rule_set_enabled(id, enabled))),
        )
        .blocking_json_command("rule_import", ceri::command!(|| wait(rulectl::rule_import())))
        .blocking_json_command(
            "proposal_accept",
            ceri::command!(|id: i64| wait(rulectl::proposal_accept(id))),
        )
        .blocking_json_command("get_launch_at_login", ceri::command!(|| startup::get_launch_at_login()))
        .blocking_json_command(
            "set_launch_at_login",
            ceri::command!(|enabled: bool| startup::set_launch_at_login(enabled)),
        )
        .blocking_json_command(
            "save_download",
            ceri::command!(|name: String, contents: String| report::save_download(name, contents)),
        )
        .blocking_json_command("app_icon", ceri::command!(|path: String| icon::app_icon(path)))
        .blocking_json_command(
            "check_installer_update",
            ceri::command!(|| wait(updater::check_installer_update())),
        )
        .blocking_json_command(
            "install_installer_update",
            ceri::command!(|| updater::install_installer_update(handle())),
        )
}

/// the page reports its real device-pixel-ratio once it loads; re-fit the
/// reporting window to that truth. sizing in physical pixels (css * ratio)
/// lands the CSS viewport at the intended logical width whatever scales the
/// surface.
fn report_display_scale(app: ceri::AppHandle, window: &str, scale: f64) -> Result<(), String> {
    let Some(scale) = valid_scale(scale) else {
        return Ok(());
    };
    {
        let mut current = DISPLAY_SCALE.0.lock().unwrap_or_else(|error| error.into_inner());
        // only react to a genuine change: re-fitting on every duplicate report
        // would fight a window the user has since resized
        if (*current - scale).abs() < 0.005 {
            return Ok(());
        }
        *current = scale;
    }
    match window {
        "main" => fit_main_window(&app, scale),
        prompt::LABEL => prompt::apply_scale(&app, scale),
        _ => {}
    }
    Ok(())
}

/// the monitor's own scale, which turns its physical pixels into the logical
/// ones ceri sizes and places windows in
pub(crate) fn monitor_scale(monitor: &Monitor) -> f64 {
    if monitor.scale.is_finite() && monitor.scale > 0.0 {
        monitor.scale
    } else {
        1.0
    }
}

pub(crate) fn primary_monitor(app: &ceri::AppHandle) -> Option<Monitor> {
    let monitors = app.windows()?.monitors();
    monitors.iter().find(|monitor| monitor.primary).or(monitors.first()).cloned()
}

fn fit_main_window(app: &ceri::AppHandle, scale: f64) {
    let Some(windows) = app.windows() else {
        return;
    };
    let Some(state) = windows.state("main") else {
        return;
    };
    let centre = (state.position.0 + state.size.0 as i32 / 2, state.position.1 + state.size.1 as i32 / 2);
    let holds_centre = |monitor: &&Monitor| {
        let ((left, top), (width, height)) = (monitor.position, monitor.size);
        (left..left + width as i32).contains(&centre.0) && (top..top + height as i32).contains(&centre.1)
    };
    let Some(monitor) = windows.monitors().iter().find(holds_centre).cloned().or_else(|| primary_monitor(app)) else {
        return;
    };
    // the minimum stays as the window opened with it: ceri changes a size
    // after that, not a minimum. the size goes in physical pixels, as measured
    let ((width, height), _) = main_physical(&monitor, scale);
    windows.act("main", WindowAction::PhysicalSize(width.round() as u32, height.round() as u32));
}

/// the main window's size and minimum size on `monitor`, in logical pixels
fn main_fit(monitor: &Monitor, scale: f64) -> ((u32, u32), (u32, u32)) {
    let ((width, height), (min_width, min_height)) = main_physical(monitor, scale);
    let logical = |physical: f64| (physical / monitor_scale(monitor)).round() as u32;
    ((logical(width), logical(height)), (logical(min_width), logical(min_height)))
}

/// the main window's size and minimum size on `monitor`, in physical pixels
fn main_physical(monitor: &Monitor, scale: f64) -> ((f64, f64), (f64, f64)) {
    // work_area is physical pixels; so are the sizes worked out below (css * scale)
    let (_, work) = monitor.work_area;
    let margin = 32.0 * scale;
    let available_width = (f64::from(work.0) - margin).max(640.0 * scale);
    let available_height = (f64::from(work.1) - margin).max(480.0 * scale);
    // the widest tab (Protect's console + rule matrix) needs ~1080 logical px
    // before its fixed columns overflow and clip, so hold the window minimum there
    let (width, min_width) = main_dimension(1180.0, 1080.0, available_width, scale);
    let (height, min_height) = main_dimension(820.0, 600.0, available_height, scale);
    ((width, height), (min_width, min_height))
}

fn main_dimension(preferred: f64, minimum: f64, available: f64, webview_scale: f64) -> (f64, f64) {
    let size = (preferred * webview_scale).min(available);
    (size, (minimum * webview_scale).min(size))
}

fn tray_menu() -> Vec<MenuItem> {
    let modes = MODES
        .iter()
        .map(|(mode, id, label)| MenuItem::check(*id, *label, *mode == FirewallMode::Ask))
        .collect();
    vec![
        MenuItem::new("show", "Show Iris"),
        MenuItem::submenu("Firewall mode", modes),
        MenuItem::check("pause-prompts", "Pause connection prompts", prompt::snoozed()),
        MenuItem::Separator,
        MenuItem::new("quit", "Quit"),
    ]
}

/// a tray icon that restores the window on click and offers show / quit
fn tray_event(app: &ceri::AppHandle, event: TrayEvent) {
    let TrayEvent::Menu(id) = event else {
        return reveal(app);
    };
    match id.as_str() {
        "show" => reveal(app),
        // the check item has flipped itself by now, as the pause it stands for does here
        "pause-prompts" => prompt::set_snoozed(app, !prompt::snoozed()),
        "quit" => app.exit(),
        id => {
            if let Some((mode, _, _)) = MODES.iter().find(|(_, mode_id, _)| *mode_id == id) {
                choose_mode(app, *mode);
            }
        }
    }
}

/// a check item flips itself on click; put the ticks back to the engine's truth
/// until the change lands, so a refused elevation never leaves a false tick
fn choose_mode(app: &ceri::AppHandle, mode: FirewallMode) {
    let app = app.clone();
    runtime().spawn(async move {
        let current = ipc::firewall_mode().await.unwrap_or_default();
        refresh_mode_menu(&app, current);
        if current == mode {
            return;
        }
        if let Err(error) = rulectl::set_firewall_mode(app.clone(), mode.as_str().into()).await {
            tracing::warn!(mode = mode.as_str(), "could not switch firewall mode: {error}");
        }
    });
}

/// whether the main window is open to draw what the engine sends
pub(crate) fn main_open(app: &ceri::AppHandle) -> bool {
    app.windows().is_some_and(|windows| windows.state("main").is_some())
}

/// open the main window fitted to the primary monitor, where ceri centres it,
/// or bring the open one to the front
fn reveal(app: &ceri::AppHandle) {
    let Some(windows) = app.windows() else {
        return;
    };
    let mut config = WindowConfig {
        label: "main".into(),
        title: "Iris".into(),
        width: 1180,
        height: 820,
        minimum_width: 820,
        minimum_height: 600,
        decorations: false,
        background: [0x0b, 0x0c, 0x0e],
        ..WindowConfig::default()
    };
    if let Some(monitor) = primary_monitor(app) {
        // best guess before the page reports its real ratio: the monitor's own
        // scale. keeps the first paint from flashing under-sized
        let scale = monitor_scale(&monitor);
        if !main_open(app) {
            *DISPLAY_SCALE.0.lock().unwrap_or_else(|error| error.into_inner()) = scale;
        }
        ((config.width, config.height), (config.minimum_width, config.minimum_height)) = main_fit(&monitor, scale);
    }
    windows.open(config);
}

#[cfg(test)]
mod tests {
    use super::{main_dimension, main_fit};

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

    #[test]
    fn fits_the_main_window_in_logical_pixels() {
        let monitor = |width, height, scale| ceri::Monitor {
            size: (width, height),
            scale,
            work_area: ((0, 0), (width, height - 60)),
            ..ceri::Monitor::default()
        };
        assert_eq!(main_fit(&monitor(3840, 2160, 1.5), 1.5), ((1180, 820), (1080, 600)));
        // a small display caps the window at its work area less the margin
        assert_eq!(main_fit(&monitor(1280, 720, 1.0), 1.0), ((1180, 628), (1080, 600)));
    }
}
