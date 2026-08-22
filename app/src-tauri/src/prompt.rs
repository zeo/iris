use iris_core::Alert;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use tauri::{Emitter, Manager, PhysicalPosition, PhysicalSize, WebviewUrl, WebviewWindowBuilder};

pub(crate) const LABEL: &str = "connection-prompts";
const CARD_WIDTH: f64 = 420.0;
const CARD_HEIGHT: f64 = 228.0;
const CARD_GAP: f64 = 10.0;
const EDGE_MARGIN: i32 = 18;
const MAX_VISIBLE: usize = 2;

#[derive(Default)]
pub struct PromptState {
    count: AtomicUsize,
    visibility_lock: Mutex<()>,
}

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

pub fn prewarm(app: &tauri::AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let state = handle.state::<PromptState>();
        let _visibility_guard = state
            .visibility_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());

        if handle.get_webview_window(LABEL).is_some() {
            return;
        }

        let monitor = target_monitor_app(&handle);
        let scale = monitor
            .as_ref()
            .map(|m| m.scale_factor())
            .unwrap_or_else(|| current_scale(&handle));
        let size = host_size(1, scale);
        let Ok(window) = WebviewWindowBuilder::new(
            &handle,
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
        .focused(false)
        .visible(false)
        .build() else {
            return;
        };

        let _ = window.set_ignore_cursor_events(true);
        let _ = window.set_size(size);
        position_window_on_monitor(&handle, &window, monitor.as_ref(), size);
        #[cfg(windows)]
        if let Err(error) = configure_prompt_window(&window) {
            tracing::debug!("could not configure connection prompt host: {error}");
        }
    });
}

pub fn show(app: &tauri::AppHandle, alert: &Alert) {
    if !crate::notify::needs_decision(alert) {
        return;
    }

    let handle = app.clone();
    let alert_clone = alert.clone();
    let _ = app.run_on_main_thread(move || show_window(&handle, Some(&alert_clone)));
}

fn show_window(app: &tauri::AppHandle, alert: Option<&Alert>) {
    let state = app.state::<PromptState>();
    let _visibility_guard = state
        .visibility_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());

    let count = state.count.load(Ordering::Acquire).clamp(1, MAX_VISIBLE);

    if let Some(window) = app.get_webview_window(LABEL) {
        let monitor = target_monitor(app, &window);
        let scale = monitor
            .as_ref()
            .map(|m| m.scale_factor())
            .unwrap_or_else(|| current_scale(app));
        let size = host_size(count, scale);
        #[cfg(windows)]
        let _ = configure_prompt_window(&window);
        let _ = window.set_size(size);
        position_window_on_monitor(app, &window, monitor.as_ref(), size);
        let _ = show_without_focus(&window);
        let _ = window.set_ignore_cursor_events(false);
        let _ = window.emit("connection-prompts-refresh", ());
        if let Some(alert) = alert {
            let _ = window.emit("engine-alert", alert);
        }
        return;
    }

    let monitor = target_monitor_app(app);
    let scale = monitor
        .as_ref()
        .map(|m| m.scale_factor())
        .unwrap_or_else(|| current_scale(app));
    let size = host_size(count, scale);

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
    .focused(false)
    .visible(false)
    .build() else {
        return;
    };

    let _ = window.set_size(size);
    position_window_on_monitor(app, &window, monitor.as_ref(), size);
    #[cfg(windows)]
    if let Err(error) = configure_prompt_window(&window) {
        tracing::debug!("could not configure connection prompt host: {error}");
    }
    let _ = show_without_focus(&window);
    let _ = window.set_ignore_cursor_events(false);
    if let Some(alert) = alert {
        let _ = window.emit("engine-alert", alert);
    }
}

#[tauri::command]
pub fn resize_connection_prompts(app: tauri::AppHandle, count: usize) -> Result<(), String> {
    let state = app.state::<PromptState>();
    let _visibility_guard = state
        .visibility_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(window) = app.get_webview_window(LABEL) else {
        return Ok(());
    };
    if count == 0 {
        state.count.store(0, Ordering::Release);
        hide_without_input(&window)?;
        return Ok(());
    }
    state.count.store(count.min(MAX_VISIBLE), Ordering::Release);
    sync_window_visibility(&app, &window)
}

fn hide_without_input(window: &tauri::WebviewWindow) -> Result<(), String> {
    let cursor = window.set_ignore_cursor_events(true);
    let hidden = window.hide();
    #[cfg(windows)]
    if let Err(error) = configure_prompt_window(window) {
        tracing::debug!("could not configure connection prompt host: {error}");
    }
    cursor.and(hidden).map_err(|error| error.to_string())
}

fn sync_window_visibility(
    app: &tauri::AppHandle,
    window: &tauri::WebviewWindow,
) -> Result<(), String> {
    let count = app.state::<PromptState>().count.load(Ordering::Acquire);
    if count == 0 {
        return hide_without_input(window);
    }

    let monitor = target_monitor(app, window);
    let scale = monitor
        .as_ref()
        .map(|m| m.scale_factor())
        .unwrap_or_else(|| current_scale(app));
    let size = host_size(count, scale);
    window.set_size(size).map_err(|error| error.to_string())?;
    position_window_on_monitor(app, window, monitor.as_ref(), size);
    show_without_focus(window)?;
    position_window_on_monitor(app, window, monitor.as_ref(), size);
    window
        .set_ignore_cursor_events(false)
        .map_err(|error| error.to_string())?;
    #[cfg(windows)]
    configure_prompt_window(window)?;
    Ok(())
}

#[cfg(windows)]
fn configure_prompt_window(window: &tauri::WebviewWindow) -> Result<(), String> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowLongPtrW, SetWindowLongPtrW, SetWindowPos, GWL_EXSTYLE, SWP_FRAMECHANGED,
        SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER,
    };

    let hwnd = HWND(window.hwnd().map_err(|error| error.to_string())?.0);
    unsafe {
        let current = GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32;
        let desired = prompt_extended_style(current);
        if desired != current {
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, desired as isize);
            SetWindowPos(
                hwnd,
                None,
                0,
                0,
                0,
                0,
                SWP_FRAMECHANGED | SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
            )
            .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn prompt_extended_style(style: u32) -> u32 {
    use windows::Win32::UI::WindowsAndMessaging::{
        WS_EX_APPWINDOW, WS_EX_TOOLWINDOW,
    };

    (style & !WS_EX_APPWINDOW.0) | WS_EX_TOOLWINDOW.0
}

#[cfg(windows)]
fn show_without_focus(window: &tauri::WebviewWindow) -> Result<(), String> {
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowPos, HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW,
    };

    configure_prompt_window(window)?;
    let _ = window.show();
    let _ = window.set_always_on_top(true);
    let hwnd =
        windows::Win32::Foundation::HWND(window.hwnd().map_err(|error| error.to_string())?.0);
    unsafe {
        SetWindowPos(
            hwnd,
            Some(HWND_TOPMOST),
            0,
            0,
            0,
            0,
            SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW,
        )
        .map_err(|error| error.to_string())
    }
}

#[cfg(not(windows))]
fn show_without_focus(window: &tauri::WebviewWindow) -> Result<(), String> {
    window.show().map_err(|error| error.to_string())
}

/// re-size the open prompt window to a freshly reported device-pixel-ratio
pub fn apply_scale(app: &tauri::AppHandle, scale: f64) {
    let state = app.state::<PromptState>();
    let _visibility_guard = state
        .visibility_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(window) = app.get_webview_window(LABEL) else {
        return;
    };
    let count = state.count.load(Ordering::Acquire);
    if count == 0 {
        return;
    }
    let size = host_size(count, scale);
    let _ = window.set_size(size);
    position_window(app, &window, size);
}

fn target_monitor_app(app: &tauri::AppHandle) -> Option<tauri::Monitor> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::POINT;
        use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;
        let mut pt = POINT::default();
        if unsafe { GetCursorPos(&mut pt) }.is_ok() {
            if let Ok(monitors) = app.available_monitors() {
                for m in monitors {
                    let pos = m.position();
                    let size = m.size();
                    if pt.x >= pos.x
                        && pt.x < pos.x + size.width as i32
                        && pt.y >= pos.y
                        && pt.y < pos.y + size.height as i32
                    {
                        return Some(m);
                    }
                }
            }
        }
    }

    app.get_webview_window("main")
        .and_then(|main| main.current_monitor().ok().flatten())
        .or_else(|| app.primary_monitor().ok().flatten())
}

fn target_monitor(app: &tauri::AppHandle, window: &tauri::WebviewWindow) -> Option<tauri::Monitor> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::POINT;
        use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;
        let mut pt = POINT::default();
        if unsafe { GetCursorPos(&mut pt) }.is_ok() {
            if let Ok(monitors) = app.available_monitors() {
                for m in monitors {
                    let pos = m.position();
                    let size = m.size();
                    if pt.x >= pos.x
                        && pt.x < pos.x + size.width as i32
                        && pt.y >= pos.y
                        && pt.y < pos.y + size.height as i32
                    {
                        return Some(m);
                    }
                }
            }
        }
    }

    app.get_webview_window("main")
        .and_then(|main| main.current_monitor().ok().flatten())
        .or_else(|| window.current_monitor().ok().flatten())
        .or_else(|| window.primary_monitor().ok().flatten())
        .or_else(|| app.primary_monitor().ok().flatten())
}

fn position_window(app: &tauri::AppHandle, window: &tauri::WebviewWindow, size: PhysicalSize<f64>) {
    position_window_on_monitor(app, window, None, size);
}

fn position_window_on_monitor(
    app: &tauri::AppHandle,
    window: &tauri::WebviewWindow,
    monitor: Option<&tauri::Monitor>,
    size: PhysicalSize<f64>,
) {
    #[cfg(target_os = "linux")]
    if anchor_wayland(app, window) {
        return;
    }

    let fallback;
    let target = match monitor {
        Some(m) => Some(m),
        None => {
            fallback = target_monitor(app, window);
            fallback.as_ref()
        }
    };
    let Some(monitor) = target else {
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
    gtk_window.set_exclusive_zone(0);
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

    #[cfg(windows)]
    #[test]
    fn prompt_host_cannot_enter_alt_tab() {
        use super::prompt_extended_style;
        use windows::Win32::UI::WindowsAndMessaging::{
            WS_EX_APPWINDOW, WS_EX_TOOLWINDOW,
        };

        let style = prompt_extended_style(WS_EX_APPWINDOW.0);
        assert_eq!(style & WS_EX_APPWINDOW.0, 0);
        assert_ne!(style & WS_EX_TOOLWINDOW.0, 0);
    }
}
