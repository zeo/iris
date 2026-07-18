use iris_core::{Alert, AlertKind};
use std::sync::atomic::{AtomicUsize, Ordering};
use tauri::{Emitter, Manager, PhysicalPosition, PhysicalSize, WebviewUrl, WebviewWindowBuilder};

pub(crate) const LABEL: &str = "connection-prompts";
const CARD_WIDTH: f64 = 420.0;
const CARD_HEIGHT: f64 = 228.0;
const CARD_GAP: f64 = 10.0;
const EDGE_MARGIN: i32 = 18;
const MAX_VISIBLE: usize = 2;

/// how many prompt cards the host window currently shows; the frontend drives it
/// through `resize_connection_prompts`, and a later scale change re-reads it
#[derive(Default)]
pub struct PromptCount(pub AtomicUsize);

fn stack_height(count: usize) -> f64 {
    let count = count.clamp(1, MAX_VISIBLE) as f64;
    count * CARD_HEIGHT + (count - 1.0) * CARD_GAP
}

/// startup hint for the webview's device-pixel-ratio, from the fractional-scaling
/// workaround in `main.rs`. the frontend later reports the real ratio, which is
/// what `DisplayScale` holds; this only seeds the very first prompt.
pub(crate) fn webview_scale() -> f64 {
    std::env::var("IRIS_X11_WEBVIEW_SCALE")
        .ok()
        .and_then(|scale| scale.parse().ok())
        .filter(|scale: &f64| scale.is_finite() && (1.0..=4.0).contains(scale))
        .unwrap_or(1.0)
}

/// the webview's measured device-pixel-ratio, best known so far
fn current_scale(app: &tauri::AppHandle) -> f64 {
    app.try_state::<crate::DisplayScale>()
        .map(|state| *state.0.lock().unwrap())
        .filter(|scale| scale.is_finite() && *scale > 0.0)
        .unwrap_or(1.0)
}

/// the host window's physical size for `count` cards at `scale`. sizing in
/// physical pixels (css * ratio) lands the CSS viewport at the card's authored
/// 420px width whatever the surface scale, so the card never clips.
fn host_size(count: usize, scale: f64) -> PhysicalSize<f64> {
    PhysicalSize::new(CARD_WIDTH * scale, stack_height(count) * scale)
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

    let scale = current_scale(app);
    let size = host_size(1, scale);
    let Ok(window) = WebviewWindowBuilder::new(
        app,
        LABEL,
        WebviewUrl::App("index.html?connection-prompts=1".into()),
    )
    .title("New network connection")
    .inner_size(CARD_WIDTH, CARD_HEIGHT)
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

    app.state::<PromptCount>().0.store(1, Ordering::Relaxed);
    let _ = window.set_size(size);
    position_window(app, &window, size);
}

#[tauri::command]
pub fn resize_connection_prompts(app: tauri::AppHandle, count: usize) -> Result<(), String> {
    let Some(window) = app.get_webview_window(LABEL) else {
        return Ok(());
    };
    if count == 0 {
        app.state::<PromptCount>().0.store(0, Ordering::Relaxed);
        window.hide().map_err(|error| error.to_string())?;
        return Ok(());
    }
    app.state::<PromptCount>().0.store(count, Ordering::Relaxed);
    let size = host_size(count, current_scale(&app));
    window
        .set_size(size)
        .map_err(|error| error.to_string())?;
    position_window(&app, &window, size);
    window.show().map_err(|error| error.to_string())?;
    // re-anchor once the window is mapped: the pre-show placement can be dropped
    // by the compositor before the surface exists (the position reads back as
    // 0,0 until it settles), which strands the host away from the corner
    position_window(&app, &window, size);
    window.set_focus().map_err(|error| error.to_string())?;
    Ok(())
}

/// re-size the open prompt window to a freshly reported device-pixel-ratio
pub fn apply_scale(app: &tauri::AppHandle, scale: f64) {
    let Some(window) = app.get_webview_window(LABEL) else {
        return;
    };
    let count = app.state::<PromptCount>().0.load(Ordering::Relaxed);
    if count == 0 {
        return;
    }
    let size = host_size(count, scale);
    let _ = window.set_size(size);
    position_window(app, &window, size);
}

fn position_window(app: &tauri::AppHandle, window: &tauri::WebviewWindow, size: PhysicalSize<f64>) {
    #[cfg(target_os = "linux")]
    if anchor_wayland(app, window) {
        return;
    }

    // anchor to the monitor the main window sits on; an unmapped prompt window
    // can report the wrong monitor (or none) on a multi-monitor setup
    let monitor = app
        .get_webview_window("main")
        .and_then(|main| main.current_monitor().ok().flatten())
        .or_else(|| window.current_monitor().ok().flatten())
        .or_else(|| window.primary_monitor().ok().flatten());
    let Some(monitor) = monitor else {
        return;
    };
    let area = monitor.work_area();
    let scale = monitor.scale_factor();
    let margin = (EDGE_MARGIN as f64 * scale).round() as i32;
    let x = trailing_edge(area.position.x, area.size.width, size.width, margin);
    let y = trailing_edge(area.position.y, area.size.height, size.height, margin);
    let _ = window.set_position(PhysicalPosition::new(x, y));
}

/// bottom/right corner of the work area, inset by `margin`, for a window of the
/// given physical `extent` (already scaled) along that axis
fn trailing_edge(origin: i32, available: u32, extent: f64, margin: i32) -> i32 {
    origin + available as i32 - extent.round() as i32 - margin
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
    use super::{host_size, stack_height, trailing_edge};

    #[test]
    fn sizes_the_visible_prompt_stack_without_exceeding_two_cards() {
        assert_eq!(stack_height(1), 228.0);
        assert_eq!(stack_height(2), 466.0);
        assert_eq!(stack_height(3), 466.0);
    }

    #[test]
    fn anchors_a_physical_size_to_the_work_area_corner() {
        // origin + available - extent - margin
        assert_eq!(trailing_edge(0, 720, 466.0, 18), 236);
        assert_eq!(trailing_edge(40, 1080, 699.0, 27), 394);
    }

    #[test]
    fn scales_the_host_in_physical_pixels() {
        let one = host_size(1, 1.5);
        assert_eq!((one.width, one.height), (630.0, 342.0));
        let two = host_size(2, 1.5);
        assert_eq!((two.width, two.height), (630.0, 699.0));
    }
}
