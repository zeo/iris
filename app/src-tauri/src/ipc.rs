//! the UI's client to the engine. a background task keeps a connection to the
//! service's named pipe, negotiates the protocol, subscribes to the live stream,
//! and forwards everything to the webview as Tauri events. it reconnects on its
//! own, so the UI can launch before the engine and simply light up when it
//! appears.
//!
//! the latest status is also kept in managed state and served by the
//! `engine_status` command, so a webview that registers its listener after the
//! first status event still learns the truth on mount (Tauri does not buffer
//! events for windows that are not yet listening).

use iris_ipc::message::{ClientMessage, ServerMessage, PROTOCOL_VERSION};
use iris_ipc::transport;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Status {
    pub online: bool,
    pub version: Option<String>,
}

/// managed holder for the latest engine status
#[derive(Default)]
pub struct StatusState(pub Mutex<Status>);

/// seed value for a webview that just mounted
#[tauri::command]
pub fn engine_status(state: tauri::State<'_, StatusState>) -> Status {
    state.inner().0.lock().map(|s| s.clone()).unwrap_or_default()
}

/// start the reconnecting client loop for the given app handle.
pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            if let Err(e) = session(&app).await {
                tracing::debug!("engine session ended: {e}");
            }
            set_status(&app, false, None);
            tokio::time::sleep(Duration::from_millis(1200)).await;
        }
    });
}

async fn session(app: &AppHandle) -> anyhow::Result<()> {
    let stream = transport::connect().await?;
    let (mut recv, mut send) = transport::split(stream);

    transport::write_frame(
        &mut send,
        &ClientMessage::Hello {
            protocol: PROTOCOL_VERSION,
        },
    )
    .await?;

    match transport::read_frame::<_, ServerMessage>(&mut recv).await? {
        Some(ServerMessage::Welcome {
            protocol,
            engine_version,
        }) => {
            if protocol != PROTOCOL_VERSION {
                anyhow::bail!("protocol mismatch: engine {protocol}, ui {PROTOCOL_VERSION}");
            }
            set_status(app, true, Some(engine_version));
        }
        other => anyhow::bail!("expected Welcome, got {other:?}"),
    }

    transport::write_frame(&mut send, &ClientMessage::Subscribe).await?;

    while let Some(msg) = transport::read_frame::<_, ServerMessage>(&mut recv).await? {
        match msg {
            ServerMessage::Tick(tick) => {
                let _ = app.emit("engine-tick", tick);
            }
            ServerMessage::Alert(alert) => {
                let _ = app.emit("engine-alert", alert);
            }
            ServerMessage::Welcome { .. } | ServerMessage::Reply { .. } => {}
        }
    }
    Ok(())
}

fn set_status(app: &AppHandle, online: bool, version: Option<String>) {
    let status = Status { online, version };
    if let Some(state) = app.try_state::<StatusState>() {
        if let Ok(mut s) = state.0.lock() {
            *s = status.clone();
        }
    }
    let _ = app.emit("engine-status", status);
}
