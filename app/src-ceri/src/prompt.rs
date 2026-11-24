//! the card host: a topmost window in the primary monitor's corner that takes
//! input only on its cards. it exists only while a card does: it is built
//! when a decision or info card arrives, shown once the page reports where its
//! cards are, and destroyed when the last card leaves, so nothing is left over
//! a game to catch the mouse between cards.

use ceri::{Monitor, WindowAction, WindowConfig, WindowControl};
use iris_core::Alert;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

pub(crate) const LABEL: &str = "connection-prompts";
const CARD_WIDTH: f64 = 420.0;
// keep in sync with the .connection-prompt max-height in styles.css
const CARD_HEIGHT: f64 = 256.0;
const CARD_GAP: f64 = 10.0;
const EDGE_MARGIN: i32 = 18;
/// cards in the stack at once; keep in sync with the page
const MAX_CARDS: usize = 3;
/// info cards held for the host; older ones give way to newer
const MAX_INFO: usize = 3;
/// a host whose page has not reported its cards by now failed to load
const LOAD_TIMEOUT: Duration = Duration::from_secs(5);
const WATCH_POLL: Duration = Duration::from_secs(1);

#[derive(Default)]
pub struct PromptState {
    count: AtomicUsize,
    visibility_lock: Mutex<()>,
    /// card rectangles in css pixels; everything outside them passes input through
    hit_region: Mutex<Vec<HitRect>>,
    snoozed: AtomicBool,
    /// a watcher is waiting for exclusive fullscreen or presentation mode to end
    deferred: AtomicBool,
    /// bumped each time a host is built or torn down, so a watcher can tell
    /// whether the host it watches is still the live one
    generation: AtomicU64,
    /// a host is open or on its way; the window list trails the requests that
    /// open and close one
    open: AtomicBool,
    shown: AtomicBool,
    /// decisions the user set aside with X or Escape; they wait in Alerts
    /// until the app asks again
    set_aside: Mutex<HashSet<i64>>,
    info: Mutex<VecDeque<InfoCard>>,
    next_info: AtomicU64,
}

static STATE: LazyLock<PromptState> = LazyLock::new(PromptState::default);

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct InfoCard {
    id: u64,
    title: String,
    body: String,
}

/// everything the host page shows, in one read
#[derive(serde::Serialize)]
pub struct PromptCards {
    decisions: Vec<Alert>,
    info: Vec<InfoCard>,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Deserialize)]
pub struct HitRect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[cfg(windows)]
const CARD_RADIUS: f64 = 12.0;
const DEFER_POLL: Duration = Duration::from_secs(1);

fn stack_height(count: usize) -> f64 {
    let count = count.clamp(1, MAX_CARDS) as f64;
    count * CARD_HEIGHT + (count - 1.0) * CARD_GAP
}

/// the page's measured device-pixel-ratio, best known so far
fn current_scale() -> f64 {
    let scale = *crate::DISPLAY_SCALE.0.lock().unwrap_or_else(|error| error.into_inner());
    if scale.is_finite() && scale > 0.0 {
        scale
    } else {
        1.0
    }
}

/// the host window's physical size for `count` cards at `scale`. sizing in
/// physical pixels (css * ratio) lands the CSS viewport at the card's authored
/// 420px width whatever the surface scale, so the card never clips.
fn host_size(count: usize, scale: f64) -> (f64, f64) {
    (CARD_WIDTH * scale, stack_height(count) * scale)
}

/// a decision arrived; surface it unless cards are snoozed
pub fn show(app: &ceri::AppHandle, alert: &Alert) {
    if !crate::notify::needs_decision(alert) {
        return;
    }
    // the app asking again brings a set-aside card back
    STATE
        .set_aside
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&alert.id);
    request_host(app);
}

/// pending decisions came back with a reconnect; cards the user set aside
/// stay aside until the app asks again
pub fn restore(app: &ceri::AppHandle, prompts: &[Alert]) {
    let set_aside = STATE.set_aside.lock().unwrap_or_else(|error| error.into_inner());
    let waiting = any_waiting(prompts.to_vec(), &set_aside);
    drop(set_aside);
    if waiting {
        request_host(app);
    }
}

fn any_waiting(prompts: Vec<Alert>, set_aside: &HashSet<i64>) -> bool {
    newest_per_app(prompts).iter().any(|alert| !set_aside.contains(&alert.id))
}

/// queue a short-lived card that needs no answer
pub fn push_info(app: &ceri::AppHandle, title: String, body: String) {
    let state = &*STATE;
    if state.snoozed.load(Ordering::Acquire) {
        return;
    }
    let id = state.next_info.fetch_add(1, Ordering::Relaxed);
    {
        let mut info = state.info.lock().unwrap_or_else(|error| error.into_inner());
        info.push_back(InfoCard { id, title, body });
        while info.len() > MAX_INFO {
            info.pop_front();
        }
    }
    request_host(app);
}

fn request_host(app: &ceri::AppHandle) {
    if snoozed() {
        return;
    }
    if presentation_blocked() {
        defer_until_clear(app);
        return;
    }
    ensure_host(app);
}

/// build the host if it is down, or tell the live one to re-read its cards
fn ensure_host(app: &ceri::AppHandle) {
    let state = &*STATE;
    if state.snoozed.load(Ordering::Acquire) {
        return;
    }
    let _visibility_guard = state
        .visibility_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(windows) = app.windows() else {
        return;
    };
    if state.open.swap(true, Ordering::AcqRel) {
        app.emit("connection-prompts-refresh", ());
        return;
    }

    let monitor = crate::primary_monitor(app);
    let scale = monitor.as_ref().map(crate::monitor_scale).unwrap_or_else(current_scale);
    let size = host_size(1, scale);
    let (width, height) = logical_size(size, monitor.as_ref());
    state
        .hit_region
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    state.count.store(0, Ordering::Release);
    state.shown.store(false, Ordering::Release);
    let generation = state.generation.fetch_add(1, Ordering::AcqRel) + 1;
    windows.open(WindowConfig {
        label: LABEL.into(),
        title: "New network connection".into(),
        width,
        height,
        minimum_width: width,
        minimum_height: height,
        position: monitor.as_ref().map(|monitor| corner_position(monitor, size)),
        start_url: "/index.html?connection-prompts=1".into(),
        resizable: false,
        decorations: false,
        transparent: true,
        shadow: false,
        always_on_top: true,
        skip_taskbar: true,
        // a never-shown window shows without activating only when built
        // unfocused, which is why each card stack gets a fresh window
        focused: false,
        visible: false,
        click_through: true,
        ..WindowConfig::default()
    });
    watch_host(app, generation);
}

/// the host window exists: clip it to nothing until its cards report in
pub fn host_opened(app: &ceri::AppHandle) {
    if let Some(windows) = app.windows() {
        apply_hit_region(windows);
    }
}

/// tear the host down, but never a newer host than the one the caller saw
fn close_host(app: &ceri::AppHandle, generation: Option<u64>) {
    let state = &*STATE;
    let _visibility_guard = state
        .visibility_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if generation.is_some_and(|generation| generation != state.generation.load(Ordering::Acquire)) {
        return;
    }
    if !state.open.swap(false, Ordering::AcqRel) {
        return;
    }
    state
        .hit_region
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
    state.count.store(0, Ordering::Release);
    state.shown.store(false, Ordering::Release);
    state.generation.fetch_add(1, Ordering::AcqRel);
    if let Some(windows) = app.windows() {
        windows.close(LABEL);
    }
}

/// destroy the host from a command its own page called, once that command has
/// let go of the host, then rebuild it if a card arrived while the page
/// counted down to zero
fn close_host_later(app: &ceri::AppHandle, generation: u64) {
    let handle = app.clone();
    crate::runtime().spawn(async move {
        close_host(&handle, Some(generation));
        reconcile(&handle);
    });
}

/// while a host lives: drop it if its page never reports cards, and step it
/// aside when exclusive fullscreen or presentation mode takes the display
fn watch_host(app: &ceri::AppHandle, generation: u64) {
    let handle = app.clone();
    std::thread::spawn(move || {
        let built = Instant::now();
        loop {
            std::thread::sleep(WATCH_POLL);
            let state = &*STATE;
            if state.generation.load(Ordering::Acquire) != generation {
                return;
            }
            let blocked = presentation_blocked();
            let stalled = !state.shown.load(Ordering::Acquire) && built.elapsed() > LOAD_TIMEOUT;
            if !blocked && !stalled {
                continue;
            }
            if stalled {
                // the next alert builds a fresh host
                tracing::warn!("the card host did not report its cards in time; closing it");
            }
            close_host(&handle, Some(generation));
            if blocked {
                defer_until_clear(&handle);
            }
            return;
        }
    });
}

/// rebuild the host if anything still waits for it
fn reconcile(app: &ceri::AppHandle) {
    let handle = app.clone();
    crate::runtime().spawn(async move {
        let cards = prompt_cards().await;
        if !cards.decisions.is_empty() || !cards.info.is_empty() {
            request_host(&handle);
        }
    });
}

/// the pending decisions minus those set aside, and the queued info cards
pub async fn prompt_cards() -> PromptCards {
    let (decisions, error) = match crate::ipc::list_prompt_alerts().await {
        Ok(alerts) => (alerts, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let state = &*STATE;
    let set_aside = state.set_aside.lock().unwrap_or_else(|error| error.into_inner());
    let decisions = newest_per_app(decisions)
        .into_iter()
        .filter(|alert| !set_aside.contains(&alert.id))
        .collect();
    drop(set_aside);
    let info = state
        .info
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .cloned()
        .collect();
    PromptCards {
        decisions,
        info,
        error,
    }
}

/// one card per app and direction, the newest: answering it decides what that
/// app is waiting on, and an answer limited to one host lets the rest ask again
fn newest_per_app(mut alerts: Vec<Alert>) -> Vec<Alert> {
    alerts.retain(crate::notify::needs_decision);
    alerts.sort_by_key(|alert| std::cmp::Reverse(alert.id));
    let mut seen = HashSet::new();
    alerts.retain(|alert| match &alert.kind {
        iris_core::AlertKind::NewApp { app, direction, .. } => seen.insert((app.clone(), *direction)),
        _ => true,
    });
    alerts
}

/// X or Escape on a decision card leaves it to the Alerts view
pub fn set_prompt_aside(id: i64) {
    let mut set_aside = STATE.set_aside.lock().unwrap_or_else(|error| error.into_inner());
    // ids only grow, so a clear can only bring back old cards the engine has
    // usually settled long since
    if set_aside.len() > 4096 {
        set_aside.clear();
    }
    set_aside.insert(id);
}

pub fn dismiss_info_card(id: u64) {
    STATE
        .info
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .retain(|card| card.id != id);
}

/// hold cards back while an exclusive fullscreen app or presentation owns the
/// display, then surface whatever is still pending once it lets go
fn defer_until_clear(app: &ceri::AppHandle) {
    if STATE.deferred.swap(true, Ordering::AcqRel) {
        return;
    }
    let handle = app.clone();
    std::thread::spawn(move || {
        while presentation_blocked() {
            std::thread::sleep(DEFER_POLL);
        }
        STATE.deferred.store(false, Ordering::Release);
        reconcile(&handle);
    });
}

/// true while windows reports a state where a topmost card is unseen or would
/// interrupt: exclusive d3d fullscreen or presentation mode. borderless
/// fullscreen (busy) still gets the card, clipped to its own pixels
#[cfg(windows)]
fn presentation_blocked() -> bool {
    use windows::Win32::UI::Shell::{
        SHQueryUserNotificationState, QUNS_PRESENTATION_MODE, QUNS_RUNNING_D3D_FULL_SCREEN,
    };
    matches!(
        unsafe { SHQueryUserNotificationState() },
        Ok(state) if state == QUNS_RUNNING_D3D_FULL_SCREEN || state == QUNS_PRESENTATION_MODE
    )
}

#[cfg(not(windows))]
fn presentation_blocked() -> bool {
    false
}

pub fn snoozed() -> bool {
    STATE.snoozed.load(Ordering::Acquire)
}

/// snoozing drops the host and any info cards; resuming surfaces the
/// decisions that queued meanwhile
pub fn set_snoozed(app: &ceri::AppHandle, snoozed: bool) {
    let state = &*STATE;
    state.snoozed.store(snoozed, Ordering::Release);
    if snoozed {
        state
            .info
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clear();
        close_host(app, None);
    } else {
        reconcile(app);
    }
}

/// the frontend's measured card rectangles; only these pixels take input. the
/// first non-empty report is what shows a freshly built host, so it never
/// appears before its cards have painted
pub fn set_prompt_hit_region(app: ceri::AppHandle, rects: Vec<HitRect>) {
    let state = &*STATE;
    let _visibility_guard = state
        .visibility_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let has_cards = !physical_rects(&rects, 1.0).is_empty();
    *state
        .hit_region
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = rects;
    let Some(windows) = app.windows().filter(|_| state.open.load(Ordering::Acquire)) else {
        return;
    };
    apply_hit_region(windows);
    if has_cards
        && !state.shown.load(Ordering::Acquire)
        && !state.snoozed.load(Ordering::Acquire)
        && !presentation_blocked()
    {
        show_without_focus(windows);
        state.shown.store(true, Ordering::Release);
    }
}

/// the host's native window and its monitor's scale, read on the loop's
/// thread, which owns the window
#[cfg(windows)]
fn host_hwnd(windows: &WindowControl) -> Option<(windows::Win32::Foundation::HWND, f64)> {
    let state = windows.state(LABEL)?;
    let Some(ceri::NativeHandle::Win32 { hwnd }) = state.handle else {
        return None;
    };
    let scale = Some(state.scale)
        .filter(|scale| scale.is_finite() && *scale > 0.0)
        .unwrap_or_else(current_scale);
    Some((windows::Win32::Foundation::HWND(hwnd as *mut core::ffi::c_void), scale))
}

/// clip the host to the last reported card rectangles, the way a per-pixel
/// alpha layered window passes clicks through its clear pixels. an empty set
/// clips it to nothing, so a host before its cards render never swallows a
/// click meant for the window beneath
#[cfg(windows)]
fn apply_hit_region(windows: &WindowControl) {
    use windows::Win32::Graphics::Gdi::{
        CombineRgn, CreateRectRgn, CreateRoundRectRgn, DeleteObject, SetWindowRgn, RGN_OR,
    };

    let control = windows.clone();
    // after the size and position asked of the loop before it
    windows.run_on_loop(move || {
        // the host's own monitor, which may differ from the one the main window reports
        let Some((hwnd, scale)) = host_hwnd(&control) else {
            return;
        };
        let rects = physical_rects(
            &STATE
                .hit_region
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            scale,
        );
        let radius = (CARD_RADIUS * scale).round() as i32;
        unsafe {
            let region = CreateRectRgn(0, 0, 0, 0);
            for (left, top, right, bottom) in rects {
                let card = CreateRoundRectRgn(left, top, right + 1, bottom + 1, radius, radius);
                CombineRgn(Some(region), Some(region), Some(card), RGN_OR);
                let _ = DeleteObject(card.into());
            }
            // the system owns the region once it is set
            if SetWindowRgn(hwnd, Some(region), true) == 0 {
                let _ = DeleteObject(region.into());
                tracing::warn!("could not clip connection prompt host");
            }
        }
    });
}

#[cfg(not(windows))]
fn apply_hit_region(_windows: &WindowControl) {}

/// css rectangles to physical (left, top, right, bottom), dropping empty ones
fn physical_rects(rects: &[HitRect], scale: f64) -> Vec<(i32, i32, i32, i32)> {
    rects
        .iter()
        .filter(|rect| rect.width > 0.0 && rect.height > 0.0)
        .map(|rect| {
            (
                (rect.x * scale).floor() as i32,
                (rect.y * scale).floor() as i32,
                ((rect.x + rect.width) * scale).ceil() as i32,
                ((rect.y + rect.height) * scale).ceil() as i32,
            )
        })
        .collect()
}

/// the page's card count; zero tears the host down
pub fn resize_connection_prompts(app: ceri::AppHandle, count: usize) {
    let state = &*STATE;
    let _visibility_guard = state
        .visibility_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(windows) = app.windows().filter(|_| state.open.load(Ordering::Acquire)) else {
        return;
    };
    if count == 0 {
        close_host_later(&app, state.generation.load(Ordering::Acquire));
        return;
    }
    let count = count.min(MAX_CARDS);
    state.count.store(count, Ordering::Release);
    fit_host(&app, windows, count, None);
    apply_hit_region(windows);
}

#[cfg(windows)]
fn configure_prompt_window(hwnd: windows::Win32::Foundation::HWND) -> Result<(), String> {
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowLongPtrW, SetWindowLongPtrW, SetWindowPos, GWL_EXSTYLE, SWP_FRAMECHANGED,
        SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER,
    };

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

/// show the host without taking the keyboard, and let its cards take the pointer
fn show_without_focus(windows: &WindowControl) {
    windows.act(LABEL, WindowAction::Show);
    windows.act(LABEL, WindowAction::AlwaysOnTop(true));
    windows.act(LABEL, WindowAction::ClickThrough(false));
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{
            SetWindowPos, HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW,
        };

        let control = windows.clone();
        // each change above has the loop write the window's styles afresh, so
        // the one that keeps the host out of alt-tab goes on after them
        windows.run_on_loop(move || {
            let Some((hwnd, _)) = host_hwnd(&control) else {
                return;
            };
            let raised = configure_prompt_window(hwnd).and_then(|()| unsafe {
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
            });
            if let Err(error) = raised {
                tracing::warn!("could not configure connection prompt host: {error}");
            }
        });
    }
}

/// re-size the open prompt window to a freshly reported device-pixel-ratio
pub fn apply_scale(app: &ceri::AppHandle, scale: f64) {
    let state = &*STATE;
    let _visibility_guard = state
        .visibility_lock
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(windows) = app.windows().filter(|_| state.open.load(Ordering::Acquire)) else {
        return;
    };
    let count = state.count.load(Ordering::Acquire);
    if count == 0 {
        return;
    }
    fit_host(app, windows, count, Some(scale));
    apply_hit_region(windows);
}

/// size the host for `count` cards and anchor it in the primary monitor's
/// corner; without a `scale` the monitor's own stands in
fn fit_host(app: &ceri::AppHandle, windows: &WindowControl, count: usize, scale: Option<f64>) {
    let monitor = crate::primary_monitor(app);
    let scale = scale
        .or_else(|| monitor.as_ref().map(crate::monitor_scale))
        .unwrap_or_else(current_scale);
    let size = host_size(count, scale);
    windows.act(LABEL, WindowAction::PhysicalSize(size.0.round() as u32, size.1.round() as u32));
    if let Some(monitor) = &monitor {
        let (x, y) = corner_position(monitor, size);
        windows.act(LABEL, WindowAction::Position(x, y));
    }
}

/// a physical size in the logical pixels ceri sizes windows in
fn logical_size(size: (f64, f64), monitor: Option<&Monitor>) -> (u32, u32) {
    let scale = monitor.map_or(1.0, crate::monitor_scale);
    ((size.0 / scale).round() as u32, (size.1 / scale).round() as u32)
}

/// where a host of the given physical `size` sits in the bottom right corner
/// of the monitor's work area, in the logical pixels ceri places windows in
fn corner_position(monitor: &Monitor, size: (f64, f64)) -> (i32, i32) {
    let ((left, top), (width, height)) = monitor.work_area;
    let scale = crate::monitor_scale(monitor);
    let margin = (EDGE_MARGIN as f64 * scale).round() as i32;
    let x = trailing_edge(left, width, size.0, margin);
    let y = trailing_edge(top, height, size.1, margin);
    ((f64::from(x) / scale).round() as i32, (f64::from(y) / scale).round() as i32)
}

/// bottom/right corner of the work area, inset by `margin`, for a window of the
/// given physical `extent` (already scaled) along that axis
fn trailing_edge(origin: i32, available: u32, extent: f64, margin: i32) -> i32 {
    origin + available as i32 - extent.round() as i32 - margin
}

#[cfg(test)]
mod tests {
    use super::{
        any_waiting, corner_position, host_size, newest_per_app, physical_rects, stack_height, trailing_edge, HitRect,
    };
    use iris_core::{Alert, AlertKind, AppId, Direction, Endpoint, Protocol};
    use std::collections::HashSet;

    fn prompt(id: i64, app: &str, direction: Direction) -> Alert {
        Alert {
            id,
            at_ms: 0,
            kind: AlertKind::NewApp {
                app: AppId(app.into()),
                remote: Some(Endpoint { addr: "104.18.37.228".parse().unwrap(), port: 443, protocol: Protocol::Tcp }),
                direction: Some(direction),
            },
            acknowledged: false,
        }
    }

    #[test]
    fn keeps_one_card_per_app_and_direction() {
        let alerts = vec![
            prompt(1, "chat.exe", Direction::Outbound),
            prompt(3, "chat.exe", Direction::Outbound),
            prompt(2, "game.exe", Direction::Outbound),
            prompt(4, "chat.exe", Direction::Inbound),
        ];
        let ids: Vec<i64> = newest_per_app(alerts).iter().map(|alert| alert.id).collect();
        assert_eq!(ids, vec![4, 3, 2]);
    }

    #[test]
    fn a_reconnect_leaves_set_aside_cards_aside() {
        let prompts = vec![
            prompt(1, "chat.exe", Direction::Outbound),
            prompt(3, "chat.exe", Direction::Outbound),
            prompt(2, "game.exe", Direction::Outbound),
        ];
        let everything: HashSet<i64> = [3, 2].into_iter().collect();
        assert!(!any_waiting(prompts.clone(), &everything));
        let one: HashSet<i64> = [3].into_iter().collect();
        assert!(any_waiting(prompts.clone(), &one));
        assert!(!any_waiting(Vec::new(), &HashSet::new()));
    }

    #[test]
    fn hit_region_covers_only_cards_in_physical_pixels() {
        let rects = [
            HitRect { x: 0.0, y: 0.0, width: 420.0, height: 228.0 },
            HitRect { x: 0.0, y: 238.0, width: 0.0, height: 228.0 },
        ];
        assert_eq!(physical_rects(&rects, 1.5), vec![(0, 0, 630, 342)]);
        assert!(physical_rects(&[], 1.0).is_empty());
    }

    #[test]
    fn sizes_the_card_stack_without_exceeding_three_cards() {
        assert_eq!(stack_height(1), 256.0);
        assert_eq!(stack_height(2), 522.0);
        assert_eq!(stack_height(3), 788.0);
        assert_eq!(stack_height(4), 788.0);
    }

    #[test]
    fn anchors_a_physical_size_to_the_work_area_corner() {
        // origin + available - extent - margin
        assert_eq!(trailing_edge(0, 720, 466.0, 18), 236);
        assert_eq!(trailing_edge(40, 1080, 699.0, 27), 394);
    }

    #[test]
    fn places_the_host_in_logical_pixels() {
        let monitor = ceri::Monitor {
            size: (2560, 1440),
            scale: 1.5,
            work_area: ((0, 0), (2560, 1380)),
            ..ceri::Monitor::default()
        };
        // physical (1903, 969) over the monitor's scale
        assert_eq!(corner_position(&monitor, host_size(1, 1.5)), (1269, 646));
    }

    #[test]
    fn scales_the_host_in_physical_pixels() {
        assert_eq!(host_size(1, 1.5), (630.0, 384.0));
        assert_eq!(host_size(2, 1.5), (630.0, 783.0));
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
