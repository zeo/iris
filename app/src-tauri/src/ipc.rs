//! the UI's client to the engine. a background task keeps a connection to the
//! service's named pipe, negotiates the protocol, subscribes to the live stream,
//! and forwards pushes to the webview as Tauri events. it also carries
//! request/response commands (rules today) correlated by id, so the UI can drive
//! the privileged engine. it reconnects on its own.

use iris_core::{AppId, Direction, Rule, RuleAction, StoredRule};
use iris_ipc::message::{ClientMessage, Reply, ServerMessage, PROTOCOL_VERSION};
use iris_ipc::transport;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::{mpsc, oneshot};

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Status {
    pub online: bool,
    pub version: Option<String>,
}

#[derive(Default)]
pub struct StatusState(pub Mutex<Status>);

/// what the UI asks the engine to do; the session task assigns the wire id
pub enum RuleCmd {
    List,
    Add(Rule),
    Remove(i64),
    SetEnabled(i64, bool),
}
pub struct Command {
    cmd: RuleCmd,
    resp: oneshot::Sender<Reply>,
}

/// managed handle the commands use to reach the session task
pub struct Commander(pub mpsc::Sender<Command>);

#[tauri::command]
pub fn engine_status(state: tauri::State<'_, StatusState>) -> Status {
    state.inner().0.lock().map(|s| s.clone()).unwrap_or_default()
}

async fn dispatch(app: &AppHandle, cmd: RuleCmd) -> Result<Reply, String> {
    let tx = {
        let state = app.try_state::<Commander>().ok_or("ipc not ready")?;
        state.0.clone()
    };
    let (resp, rx) = oneshot::channel();
    tx.send(Command { cmd, resp })
        .await
        .map_err(|_| "engine offline".to_string())?;
    rx.await.map_err(|_| "engine offline".to_string())
}

#[tauri::command]
pub async fn list_rules(app: AppHandle) -> Result<Vec<StoredRule>, String> {
    match dispatch(&app, RuleCmd::List).await? {
        Reply::Rules(r) => Ok(r),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn add_rule(
    app: AppHandle,
    path: String,
    direction: String,
    action: String,
) -> Result<StoredRule, String> {
    let rule = Rule {
        app: AppId::from_path(&path),
        direction: parse_direction(&direction),
        action: parse_action(&action),
        label: None,
    };
    match dispatch(&app, RuleCmd::Add(rule)).await? {
        Reply::RuleAdded(r) => Ok(r),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn remove_rule(app: AppHandle, id: i64) -> Result<(), String> {
    match dispatch(&app, RuleCmd::Remove(id)).await? {
        Reply::Ok => Ok(()),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn set_rule_enabled(app: AppHandle, id: i64, enabled: bool) -> Result<(), String> {
    match dispatch(&app, RuleCmd::SetEnabled(id, enabled)).await? {
        Reply::Ok => Ok(()),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

fn parse_direction(s: &str) -> Direction {
    match s {
        "inbound" => Direction::Inbound,
        _ => Direction::Outbound,
    }
}
fn parse_action(s: &str) -> RuleAction {
    match s {
        "allow" => RuleAction::Allow,
        _ => RuleAction::Block,
    }
}

/// start the reconnecting client loop. `rx` carries UI commands across the loop's
/// lifetime; each connection drains it.
pub fn spawn(app: AppHandle, mut rx: mpsc::Receiver<Command>) {
    tauri::async_runtime::spawn(async move {
        loop {
            if let Err(e) = session(&app, &mut rx).await {
                tracing::debug!("engine session ended: {e}");
            }
            set_status(&app, false, None);
            tokio::time::sleep(Duration::from_millis(1200)).await;
        }
    });
}

async fn session(app: &AppHandle, rx: &mut mpsc::Receiver<Command>) -> anyhow::Result<()> {
    let stream = transport::connect().await?;
    let (mut recv, mut send) = transport::split(stream);

    transport::write_frame(&mut send, &ClientMessage::Hello { protocol: PROTOCOL_VERSION }).await?;
    match transport::read_frame::<_, ServerMessage>(&mut recv).await? {
        Some(ServerMessage::Welcome { protocol, engine_version }) => {
            if protocol != PROTOCOL_VERSION {
                anyhow::bail!("protocol mismatch: engine {protocol}, ui {PROTOCOL_VERSION}");
            }
            set_status(app, true, Some(engine_version));
        }
        other => anyhow::bail!("expected Welcome, got {other:?}"),
    }
    transport::write_frame(&mut send, &ClientMessage::Subscribe).await?;

    let mut next_id: u64 = 1;
    let mut pending: HashMap<u64, oneshot::Sender<Reply>> = HashMap::new();

    loop {
        tokio::select! {
            frame = transport::read_frame::<_, ServerMessage>(&mut recv) => {
                let Some(msg) = frame? else { break };
                match msg {
                    ServerMessage::Tick(tick) => { let _ = app.emit("engine-tick", tick); }
                    ServerMessage::Alert(alert) => { let _ = app.emit("engine-alert", alert); }
                    ServerMessage::Reply { req, result } => {
                        if let Some(resp) = pending.remove(&req) {
                            let _ = resp.send(result);
                        }
                    }
                    ServerMessage::Welcome { .. } => {}
                }
            }
            command = rx.recv() => {
                let Some(command) = command else { break };
                let req = next_id;
                next_id += 1;
                let msg = match command.cmd {
                    RuleCmd::List => ClientMessage::ListRules { req },
                    RuleCmd::Add(rule) => ClientMessage::AddRule { req, rule },
                    RuleCmd::Remove(id) => ClientMessage::RemoveRule { req, id },
                    RuleCmd::SetEnabled(id, enabled) => ClientMessage::SetRuleEnabled { req, id, enabled },
                };
                pending.insert(req, command.resp);
                if let Err(e) = transport::write_frame(&mut send, &msg).await {
                    // drop the connection; the pending oneshot resolves as offline
                    return Err(e.into());
                }
            }
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
