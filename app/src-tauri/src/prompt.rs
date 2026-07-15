use iris_core::{Alert, AlertKind};
use tauri::{Manager, PhysicalPosition, WebviewUrl, WebviewWindowBuilder, WindowEvent};

const EDGE_MARGIN: i32 = 18;
const STACK_STEP: i32 = 246;

pub fn show(app: &tauri::AppHandle, alert: &Alert) {
    if !matches!(alert.kind, AlertKind::NewApp { .. }) {
        return;
    }

    let handle = app.clone();
    let alert = alert.clone();
    let _ = app.run_on_main_thread(move || show_window(&handle, &alert));
}

fn show_window(app: &tauri::AppHandle, alert: &Alert) {
    let label = format!("connection-prompt-{}", alert.id);
    if let Some(window) = app.get_webview_window(&label) {
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }

    let Ok(window) = WebviewWindowBuilder::new(
        app,
        label,
        WebviewUrl::App(format!("index.html?connection-prompt={}", alert.id).into()),
    )
    .title("New network connection")
    .inner_size(420.0, 228.0)
    .min_inner_size(420.0, 228.0)
    .max_inner_size(420.0, 228.0)
    .resizable(false)
    .decorations(false)
    .transparent(true)
    .shadow(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .focused(true)
    .visible(false)
    .build() else {
        return;
    };

    let app_for_close = app.clone();
    let closed_label = window.label().to_string();
    window.on_window_event(move |event| {
        if matches!(event, WindowEvent::Destroyed) {
            relayout(&app_for_close, Some(&closed_label));
        }
    });
    relayout(app, None);
    let _ = window.show();
    let _ = window.set_focus();
}

fn relayout(app: &tauri::AppHandle, closing: Option<&str>) {
    let mut prompts: Vec<_> = app
        .webview_windows()
        .into_iter()
        .filter(|(label, _)| {
            label.starts_with("connection-prompt-") && closing.is_none_or(|closed| label != closed)
        })
        .collect();
    prompts.sort_by_key(|(label, _)| {
        label
            .strip_prefix("connection-prompt-")
            .and_then(|id| id.parse::<i64>().ok())
            .unwrap_or(i64::MAX)
    });

    for (index, (_, window)) in prompts.into_iter().enumerate() {
        let bottom_margin = EDGE_MARGIN + index as i32 * STACK_STEP;
        #[cfg(target_os = "linux")]
        if anchor_wayland(app, &window, bottom_margin) {
            continue;
        }
        position_window(&window, bottom_margin);
    }
}

fn position_window(window: &tauri::WebviewWindow, bottom_margin: i32) {
    let (Ok(Some(monitor)), Ok(size)) = (window.current_monitor(), window.outer_size()) else {
        return;
    };
    let area = monitor.work_area();
    let x = area.position.x + area.size.width as i32 - size.width as i32 - EDGE_MARGIN;
    let y = area.position.y + area.size.height as i32 - size.height as i32 - bottom_margin;
    let _ = window.set_position(PhysicalPosition::new(x, y));
}

#[cfg(target_os = "linux")]
fn anchor_wayland(
    app: &tauri::AppHandle,
    window: &tauri::WebviewWindow,
    bottom_margin: i32,
) -> bool {
    use gtk::prelude::*;
    use gtk_layer_shell::{Edge, KeyboardMode, Layer, LayerShell};

    if !gtk_layer_shell::is_supported() {
        return false;
    }
    let Ok(gtk_window) = window.gtk_window() else {
        return false;
    };
    if !gtk_window.is_layer_window() {
        gtk_window.init_layer_shell();
    }
    gtk_window.set_layer(Layer::Overlay);
    gtk_window.set_namespace("iris-connection-prompt");
    let display = gtk_window.display();
    let monitor = app
        .get_webview_window("main")
        .and_then(|main| main.gtk_window().ok())
        .and_then(|main| main.window())
        .and_then(|main| display.monitor_at_window(&main))
        .or_else(|| display.primary_monitor());
    if let Some(monitor) = monitor {
        gtk_window.set_monitor(&monitor);
    }
    gtk_window.set_anchor(Edge::Right, true);
    gtk_window.set_anchor(Edge::Bottom, true);
    gtk_window.set_layer_shell_margin(Edge::Right, 18);
    gtk_window.set_layer_shell_margin(Edge::Bottom, bottom_margin);
    gtk_window.set_keyboard_mode(KeyboardMode::OnDemand);
    true
}
