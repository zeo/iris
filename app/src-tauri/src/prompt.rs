use iris_core::{Alert, AlertKind};
#[cfg(windows)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
#[cfg(windows)]
use std::time::Duration;
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
    #[cfg(windows)]
    watcher_active: AtomicBool,
    #[cfg(windows)]
    suppression_in_flight: AtomicBool,
    #[cfg(windows)]
    suppression_generation: std::sync::atomic::AtomicU64,
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

pub fn show(app: &tauri::AppHandle, alert: &Alert) {
    if !matches!(alert.kind, AlertKind::NewApp { .. }) {
        return;
    }

    #[cfg(windows)]
    if notifications_suppressed() {
        let handle = app.clone();
        let _ = app.run_on_main_thread(move || {
            let state = handle.state::<PromptState>();
            let _visibility_guard = state
                .visibility_lock
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(window) = handle.get_webview_window(LABEL) {
                let _ = hide_without_input(&window);
            }
        });
        suppress_pending_prompts(app);
        return;
    }

    let handle = app.clone();
    let _ = app.run_on_main_thread(move || show_window(&handle));
}

#[cfg(windows)]
fn suppress_pending_prompts(app: &tauri::AppHandle) {
    let state = app.state::<PromptState>();
    state.suppression_generation.fetch_add(1, Ordering::AcqRel);
    if state
        .suppression_in_flight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let state = handle.state::<PromptState>();
            let generation = state.suppression_generation.load(Ordering::Acquire);
            if crate::ipc::suppress_alert_prompts(handle.clone())
                .await
                .is_ok()
            {
                let _ = handle.emit("connection-prompts-refresh", ());
            }
            if state.suppression_generation.load(Ordering::Acquire) != generation {
                continue;
            }
            state.suppression_in_flight.store(false, Ordering::Release);
            if state.suppression_generation.load(Ordering::Acquire) == generation {
                break;
            }
            if state
                .suppression_in_flight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                break;
            }
        }
    });
}

fn show_window(app: &tauri::AppHandle) {
    let state = app.state::<PromptState>();
    let _visibility_guard = state
        .visibility_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());

    #[cfg(windows)]
    if notifications_suppressed() {
        if let Some(window) = app.get_webview_window(LABEL) {
            let _ = hide_without_input(&window);
        }
        suppress_pending_prompts(app);
        return;
    }

    if let Some(window) = app.get_webview_window(LABEL) {
        #[cfg(windows)]
        let _ = configure_prompt_window(&window);
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
    .focused(false)
    .visible(false)
    .build() else {
        return;
    };

    let _ = window.set_ignore_cursor_events(true);
    let _ = window.set_size(size);
    position_window(app, &window, size);
    #[cfg(windows)]
    if let Err(error) = configure_prompt_window(&window) {
        tracing::debug!("could not configure connection prompt host: {error}");
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
    #[cfg(windows)]
    {
        ensure_visibility_watcher(&app);
        if notifications_suppressed() {
            suppress_pending_prompts(&app);
            return hide_without_input(&window);
        }
        // a hidden host waits for the watcher to observe a stable foreground
        // this removes the alt-tab frame where an old prompt can flash before
        // the fullscreen check catches up
        if !window.is_visible().unwrap_or(false) {
            return hide_without_input(&window);
        }
    }
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
    #[cfg(windows)]
    let suppressed = notifications_suppressed();
    #[cfg(windows)]
    if count == 0 || suppressed {
        if suppressed {
            suppress_pending_prompts(app);
        }
        return hide_without_input(window);
    }
    #[cfg(not(windows))]
    if count == 0 {
        return hide_without_input(window);
    }

    let size = host_size(count, current_scale(app));
    window.set_size(size).map_err(|error| error.to_string())?;
    position_window(app, window, size);
    if !window.is_visible().unwrap_or(false) {
        show_without_focus(window)?;
        // re-anchor once the window is mapped: the pre-show placement can be dropped
        // by the compositor before the surface exists (the position reads back as
        // 0,0 until it settles), which strands the host away from the corner
        position_window(app, window, size);
    }
    window
        .set_ignore_cursor_events(false)
        .map_err(|error| error.to_string())?;
    #[cfg(windows)]
    configure_prompt_window(window)?;
    Ok(())
}

#[cfg(windows)]
fn ensure_visibility_watcher(app: &tauri::AppHandle) {
    let state = app.state::<PromptState>();
    if state
        .watcher_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut watch = VisibilityWatch::default();
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if handle.state::<PromptState>().count.load(Ordering::Acquire) == 0 {
                break;
            }

            let suppressed = notifications_suppressed();
            if suppressed {
                suppress_pending_prompts(&handle);
            }
            if watch.sample(suppressed) {
                sync_on_main_thread(&handle);
            }
        }

        handle
            .state::<PromptState>()
            .watcher_active
            .store(false, Ordering::Release);
        if handle.state::<PromptState>().count.load(Ordering::Acquire) > 0 {
            ensure_visibility_watcher(&handle);
        }
    });
}

#[cfg(windows)]
#[derive(Default)]
struct VisibilityWatch {
    last_suppressed: Option<bool>,
    clear_samples: u8,
}

#[cfg(windows)]
impl VisibilityWatch {
    fn sample(&mut self, suppressed: bool) -> bool {
        if suppressed {
            self.clear_samples = 0;
            return self.last_suppressed.replace(true) != Some(true);
        }
        self.clear_samples = self.clear_samples.saturating_add(1);
        if self.clear_samples < 4 {
            return false;
        }
        self.last_suppressed.replace(false) != Some(false)
    }
}

#[cfg(windows)]
fn sync_on_main_thread(app: &tauri::AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let state = handle.state::<PromptState>();
        let _visibility_guard = state
            .visibility_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(window) = handle.get_webview_window(LABEL) else {
            return;
        };
        if let Err(error) = sync_window_visibility(&handle, &window) {
            tracing::debug!("could not update connection prompt visibility: {error}");
        }
    });
}

#[cfg(windows)]
fn notifications_suppressed() -> bool {
    use windows::Win32::UI::Shell::SHQueryUserNotificationState;

    let shell_blocks = unsafe { SHQueryUserNotificationState() }
        .is_ok_and(|state| notification_state_suppresses(state.0));
    shell_blocks || foreground_is_borderless_fullscreen()
}

#[cfg(windows)]
fn notification_state_suppresses(state: i32) -> bool {
    use windows::Win32::UI::Shell::{
        QUNS_BUSY, QUNS_NOT_PRESENT, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN,
    };

    matches!(
        state,
        value if value == QUNS_NOT_PRESENT.0
            || value == QUNS_BUSY.0
            || value == QUNS_RUNNING_D3D_FULL_SCREEN.0
            || value == QUNS_PRESENTATION_MODE.0
    )
}

#[cfg(windows)]
fn foreground_is_borderless_fullscreen() -> bool {
    use std::mem::size_of;
    use windows::Win32::Foundation::RECT;
    use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_EXTENDED_FRAME_BOUNDS};
    use windows::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowLongPtrW, GetWindowRect, GetWindowThreadProcessId, IsIconic,
        IsWindowVisible, GWL_STYLE,
    };

    unsafe {
        let foreground = GetForegroundWindow();
        if foreground.0.is_null()
            || !IsWindowVisible(foreground).as_bool()
            || IsIconic(foreground).as_bool()
        {
            return false;
        }

        let mut process_id = 0;
        GetWindowThreadProcessId(foreground, Some(&mut process_id));
        if process_id == GetCurrentProcessId() {
            return false;
        }

        let monitor = MonitorFromWindow(foreground, MONITOR_DEFAULTTONEAREST);
        if monitor.0.is_null() {
            return false;
        }
        let mut monitor_info = MONITORINFO {
            cbSize: size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if !GetMonitorInfoW(monitor, &mut monitor_info).as_bool() {
            return false;
        }

        let mut bounds = RECT::default();
        if DwmGetWindowAttribute(
            foreground,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            &mut bounds as *mut RECT as *mut std::ffi::c_void,
            size_of::<RECT>() as u32,
        )
        .is_err()
            && GetWindowRect(foreground, &mut bounds).is_err()
        {
            return false;
        }

        borderless_fullscreen_bounds(
            bounds,
            monitor_info.rcMonitor,
            GetWindowLongPtrW(foreground, GWL_STYLE) as u32,
        )
    }
}

#[cfg(windows)]
fn borderless_fullscreen_bounds(
    bounds: windows::Win32::Foundation::RECT,
    monitor: windows::Win32::Foundation::RECT,
    style: u32,
) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{WS_CAPTION, WS_THICKFRAME};

    const EDGE_TOLERANCE: u32 = 2;
    let framed = style & (WS_CAPTION.0 | WS_THICKFRAME.0) != 0;
    !framed
        && bounds.left.abs_diff(monitor.left) <= EDGE_TOLERANCE
        && bounds.top.abs_diff(monitor.top) <= EDGE_TOLERANCE
        && bounds.right.abs_diff(monitor.right) <= EDGE_TOLERANCE
        && bounds.bottom.abs_diff(monitor.bottom) <= EDGE_TOLERANCE
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
        WS_EX_APPWINDOW, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
    };

    (style & !WS_EX_APPWINDOW.0) | WS_EX_NOACTIVATE.0 | WS_EX_TOOLWINDOW.0
}

#[cfg(windows)]
fn show_without_focus(window: &tauri::WebviewWindow) -> Result<(), String> {
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowPos, HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW,
    };

    configure_prompt_window(window)?;
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
    fn suppresses_interruptive_windows_notification_states() {
        use super::notification_state_suppresses;

        for state in 1..=4 {
            assert!(notification_state_suppresses(state));
        }
        for state in 5..=7 {
            assert!(!notification_state_suppresses(state));
        }
    }

    #[cfg(windows)]
    #[test]
    fn detects_borderless_monitor_coverage() {
        use super::borderless_fullscreen_bounds;
        use windows::Win32::Foundation::RECT;
        use windows::Win32::UI::WindowsAndMessaging::WS_CAPTION;

        let monitor = RECT {
            left: -2560,
            top: 0,
            right: 0,
            bottom: 1440,
        };
        assert!(borderless_fullscreen_bounds(monitor, monitor, 0));
        assert!(borderless_fullscreen_bounds(
            RECT {
                left: -2558,
                top: 1,
                right: -1,
                bottom: 1438,
            },
            monitor,
            0,
        ));
        assert!(!borderless_fullscreen_bounds(
            RECT {
                bottom: 1400,
                ..monitor
            },
            monitor,
            0,
        ));
        assert!(!borderless_fullscreen_bounds(
            monitor,
            monitor,
            WS_CAPTION.0,
        ));
    }

    #[cfg(windows)]
    #[test]
    fn restores_only_after_fullscreen_is_stably_clear() {
        use super::VisibilityWatch;

        let mut watch = VisibilityWatch::default();
        assert!(!watch.sample(false));
        assert!(!watch.sample(false));
        assert!(!watch.sample(false));
        assert!(watch.sample(false));
        assert!(watch.sample(true));
        assert!(!watch.sample(true));
        assert!(!watch.sample(false));
        assert!(!watch.sample(false));
        assert!(!watch.sample(false));
        assert!(watch.sample(false));
        assert!(!watch.sample(false));
    }

    #[cfg(windows)]
    #[test]
    fn prompt_host_cannot_enter_alt_tab_or_activate() {
        use super::prompt_extended_style;
        use windows::Win32::UI::WindowsAndMessaging::{
            WS_EX_APPWINDOW, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
        };

        let style = prompt_extended_style(WS_EX_APPWINDOW.0);
        assert_eq!(style & WS_EX_APPWINDOW.0, 0);
        assert_ne!(style & WS_EX_TOOLWINDOW.0, 0);
        assert_ne!(style & WS_EX_NOACTIVATE.0, 0);
    }
}
