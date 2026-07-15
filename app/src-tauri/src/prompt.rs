use iris_core::{Alert, AlertKind};
use tauri::{Emitter, LogicalSize, Manager, PhysicalPosition, WebviewUrl, WebviewWindowBuilder};

const LABEL: &str = "connection-prompts";
const CARD_WIDTH: f64 = 420.0;
const CARD_HEIGHT: f64 = 228.0;
const CARD_GAP: f64 = 10.0;
const HOST_PADDING: f64 = 8.0;
const EDGE_MARGIN: i32 = 18;
const MAX_VISIBLE: usize = 2;

fn stack_height(count: usize) -> f64 {
    let count = count.clamp(1, MAX_VISIBLE) as f64;
    count * CARD_HEIGHT + (count - 1.0) * CARD_GAP + HOST_PADDING * 2.0
}

pub fn show(app: &tauri::AppHandle, alert: &Alert) {
    if !matches!(alert.kind, AlertKind::NewApp { .. }) {
        return;
    }

    let handle = app.clone();
    let _ = app.run_on_main_thread(move || show_window(&handle));
}

fn show_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.emit("connection-prompts-refresh", ());
        return;
    }

    let Ok(window) = WebviewWindowBuilder::new(
        app,
        LABEL,
        WebviewUrl::App("index.html?connection-prompts=1".into()),
    )
    .title("New network connection")
    .inner_size(CARD_WIDTH + HOST_PADDING * 2.0, stack_height(1))
    .min_inner_size(CARD_WIDTH + HOST_PADDING * 2.0, stack_height(1))
    .max_inner_size(CARD_WIDTH + HOST_PADDING * 2.0, stack_height(MAX_VISIBLE))
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

    position_window(app, &window);
}

#[tauri::command]
pub fn resize_connection_prompts(app: tauri::AppHandle, count: usize) -> Result<(), String> {
    let Some(window) = app.get_webview_window(LABEL) else {
        return Ok(());
    };
    if count == 0 {
        window.hide().map_err(|error| error.to_string())?;
        return Ok(());
    }
    let height = stack_height(count);
    window
        .set_size(LogicalSize::new(CARD_WIDTH + HOST_PADDING * 2.0, height))
        .map_err(|error| error.to_string())?;
    position_window(&app, &window);
    window.show().map_err(|error| error.to_string())?;
    window.set_focus().map_err(|error| error.to_string())?;
    Ok(())
}

fn position_window(app: &tauri::AppHandle, window: &tauri::WebviewWindow) {
    #[cfg(target_os = "linux")]
    if anchor_wayland(app, window) {
        return;
    }

    let (Ok(Some(monitor)), Ok(size)) = (window.current_monitor(), window.outer_size()) else {
        return;
    };
    let area = monitor.work_area();
    let x = area.position.x + area.size.width as i32 - size.width as i32 - EDGE_MARGIN;
    let y = area.position.y + area.size.height as i32 - size.height as i32 - EDGE_MARGIN;
    let _ = window.set_position(PhysicalPosition::new(x, y));
}

#[cfg(target_os = "linux")]
fn anchor_wayland(app: &tauri::AppHandle, window: &tauri::WebviewWindow) -> bool {
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
    gtk_window.set_namespace("iris-connection-prompts");
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
    gtk_window.set_layer_shell_margin(Edge::Right, EDGE_MARGIN);
    gtk_window.set_layer_shell_margin(Edge::Bottom, EDGE_MARGIN);
    gtk_window.set_keyboard_mode(KeyboardMode::OnDemand);
    true
}

#[cfg(test)]
mod tests {
    use super::stack_height;

    #[test]
    fn sizes_the_visible_prompt_stack_without_exceeding_two_cards() {
        assert_eq!(stack_height(1), 244.0);
        assert_eq!(stack_height(2), 482.0);
        assert_eq!(stack_height(3), 482.0);
    }
}
