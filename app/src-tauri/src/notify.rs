//! native desktop toasts, raised from the host process. alerts used to be
//! toasted by the main window's webview, which meant no notification when the
//! window sat hidden in the tray (a hidden webview can be throttled or
//! suspended) and none at all while the UI process was closed. the host is
//! always alive as long as Iris runs, so it toasts the moment an alert arrives
//! over the pipe, and announces the backlog that accumulated while it was not
//! running.

use iris_core::{Alert, AlertKind};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::Manager;
use tauri_plugin_notification::NotificationExt;

/// host-side notification preferences and per-session dedupe
pub struct NotifyState {
    /// mirrors the "Desktop notifications" settings toggle; the frontend syncs
    /// it at startup and on change. defaults on, matching the UI default.
    enabled: AtomicBool,
    /// alert ids already toasted this session, so a replayed or restored alert
    /// never toasts twice
    toasted: Mutex<HashSet<i64>>,
}

impl Default for NotifyState {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            toasted: Mutex::new(HashSet::new()),
        }
    }
}

#[tauri::command]
pub fn set_notifications_enabled(state: tauri::State<'_, NotifyState>, enabled: bool) {
    state.enabled.store(enabled, Ordering::Release);
}

/// whether this alert is handled by the actionable connection-prompt window
/// instead of a generic toast. mirrors `needsDecision` in the frontend.
pub fn needs_decision(alert: &Alert) -> bool {
    !alert.acknowledged
        && matches!(
            alert.kind,
            AlertKind::NewApp {
                remote: Some(_),
                direction: Some(_),
                ..
            }
        )
}

fn enabled(app: &tauri::AppHandle) -> bool {
    app.try_state::<NotifyState>()
        .map(|s| s.enabled.load(Ordering::Acquire))
        .unwrap_or(true)
}

/// record the id; returns false when this alert was already toasted
fn first_sighting(app: &tauri::AppHandle, id: i64) -> bool {
    let Some(state) = app.try_state::<NotifyState>() else {
        return true;
    };
    let mut toasted = state.toasted.lock().unwrap_or_else(|e| e.into_inner());
    // bound the set over a very long session; ids are monotonic so a clear can
    // only re-admit old ids, and a duplicate toast is harmless next to the leak
    if toasted.len() > 4096 {
        toasted.clear();
    }
    toasted.insert(id)
}

/// toast a live alert as it arrives from the engine.
pub fn alert_toast(app: &tauri::AppHandle, alert: &Alert) {
    if !enabled(app) || needs_decision(alert) || !first_sighting(app, alert.id) {
        return;
    }
    let (title, body) = match &alert.kind {
        AlertKind::Plugin { source, message } => (source.clone(), message.clone()),
        AlertKind::NewApp {
            app,
            remote,
            direction,
        } => {
            let file = app.file_name();
            if let Some(remote) = remote {
                let dir_str = match direction {
                    Some(iris_core::Direction::Inbound) => "incoming connection from",
                    _ => "connecting to",
                };
                (
                    "New network connection".to_string(),
                    format!("{file} is {dir_str} {}:{}", remote.addr, remote.port),
                )
            } else {
                (
                    "New app on the network".to_string(),
                    format!("{file} connected for the first time"),
                )
            }
        }
        AlertKind::Blocked { app, .. } => (
            "Connection blocked".to_string(),
            format!("Blocked {}", app.file_name()),
        ),
    };
    show(app, &title, &body);
}

/// summarize unacknowledged alerts missed during startup or an
/// engine reconnect. ids already surfaced live stay suppressed.
pub fn announce_backlog(app: &tauri::AppHandle, alerts: &[Alert]) {
    let Some(state) = app.try_state::<NotifyState>() else {
        return;
    };
    if !enabled(app) {
        return;
    }
    let mut toasted = state
        .toasted
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let count = alerts
        .iter()
        .filter(|alert| !alert.acknowledged)
        .filter(|alert| toasted.insert(alert.id))
        .count();
    drop(toasted);
    if count == 0 {
        return;
    }
    let body = if count == 1 {
        "1 network alert needs attention".to_string()
    } else {
        format!("{count} network alerts need attention")
    };
    show(app, "Iris", &body);
}

fn show(app: &tauri::AppHandle, title: &str, body: &str) {
    if let Err(error) = app.notification().builder().title(title).body(body).show() {
        tracing::warn!("could not raise notification: {error}");
    }
}
