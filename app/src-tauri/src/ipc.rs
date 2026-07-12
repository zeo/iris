//! the UI's client to the engine's telemetry pipe. a background task keeps a
//! connection open, negotiates the protocol, subscribes to the live stream, and
//! forwards pushes to the webview as Tauri events. it also carries the
//! unprivileged request/response commands (reads, kills, enrichment) correlated
//! by id. privileged rule mutations do not go here; they run elevated over the
//! admin pipe (see `rulectl`). it reconnects on its own.

use iris_core::{
    AdapterKind, Alert, Annotation, ByteCounts, EnrichTarget, Granularity, RuleProposal,
    StoredRule, UsageBucket, UsageQuery,
};
use iris_ipc::message::{ClientMessage, PluginInfo, Reply, ServerMessage, PROTOCOL_VERSION};
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

/// forwarded to the webview when the engine resolves annotations for a target
#[derive(Serialize, Clone)]
pub struct EnrichmentEvent {
    pub target: EnrichTarget,
    pub annotations: Vec<Annotation>,
}

#[derive(Default)]
pub struct StatusState(pub Mutex<Status>);

/// what the UI asks the engine to do; the session task assigns the wire id
pub enum EngineCmd {
    ListRules,
    GetUsage(UsageQuery),
    GetAdapterUsage(u64, u64),
    ListAlerts(bool),
    AckAlert(i64),
    KillConnection(u16, String, u16),
    GetEnrichment(Vec<EnrichTarget>),
    ListPlugins,
    GrantPlugin(String, Vec<String>, Vec<String>),
    SetPluginEnabled(String, bool),
    ListProposals,
    // rejecting is unprivileged; accepting enforces a rule and goes over the
    // admin pipe (see rulectl), never through here
    RejectProposal(i64),
}
pub struct Command {
    cmd: EngineCmd,
    resp: oneshot::Sender<Reply>,
}

/// managed handle the commands use to reach the session task
pub struct Commander(pub mpsc::Sender<Command>);

#[tauri::command]
pub fn engine_status(state: tauri::State<'_, StatusState>) -> Status {
    state.inner().0.lock().map(|s| s.clone()).unwrap_or_default()
}

async fn dispatch(app: &AppHandle, cmd: EngineCmd) -> Result<Reply, String> {
    // fail fast when the engine is known to be offline, so a UI action during an
    // outage returns at once instead of buffering on a queue nobody is draining
    if let Some(state) = app.try_state::<StatusState>() {
        let online = state.0.lock().map(|s| s.online).unwrap_or(false);
        if !online {
            return Err("engine offline".into());
        }
    }
    let tx = {
        let state = app.try_state::<Commander>().ok_or("ipc not ready")?;
        state.0.clone()
    };
    let (resp, rx) = oneshot::channel();
    tx.send(Command { cmd, resp })
        .await
        .map_err(|_| "engine offline".to_string())?;
    // backstop the wait: if the engine drops mid-request the reconnect can take a
    // moment, but the UI promise must never hang forever
    match tokio::time::timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(_)) => Err("engine offline".into()),
        Err(_) => Err("engine timed out".into()),
    }
}

#[tauri::command]
pub async fn list_rules(app: AppHandle) -> Result<Vec<StoredRule>, String> {
    match dispatch(&app, EngineCmd::ListRules).await? {
        Reply::Rules(r) => Ok(r),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn list_alerts(app: AppHandle, unacked_only: bool) -> Result<Vec<Alert>, String> {
    match dispatch(&app, EngineCmd::ListAlerts(unacked_only)).await? {
        Reply::Alerts(a) => Ok(a),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn ack_alert(app: AppHandle, id: i64) -> Result<(), String> {
    match dispatch(&app, EngineCmd::AckAlert(id)).await? {
        Reply::Ok => Ok(()),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn kill_connection(
    app: AppHandle,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
) -> Result<(), String> {
    match dispatch(&app, EngineCmd::KillConnection(local_port, remote_addr, remote_port)).await? {
        Reply::Ok => Ok(()),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn get_usage(
    app: AppHandle,
    from_ms: f64,
    to_ms: f64,
    granularity: String,
) -> Result<Vec<UsageBucket>, String> {
    let query = UsageQuery {
        app: None,
        from_ms: from_ms as u64,
        to_ms: to_ms as u64,
        granularity: match granularity.as_str() {
            "hour" => Granularity::Hour,
            "day" => Granularity::Day,
            _ => Granularity::Minute,
        },
    };
    match dispatch(&app, EngineCmd::GetUsage(query)).await? {
        Reply::Usage(u) => Ok(u),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

/// one row of the per-adapter breakdown handed to the webview
#[derive(Serialize, Clone)]
pub struct AdapterUsageRow {
    pub kind: AdapterKind,
    pub bytes: ByteCounts,
}

#[tauri::command]
pub async fn get_adapter_usage(
    app: AppHandle,
    from_ms: f64,
    to_ms: f64,
) -> Result<Vec<AdapterUsageRow>, String> {
    match dispatch(&app, EngineCmd::GetAdapterUsage(from_ms as u64, to_ms as u64)).await? {
        Reply::AdapterUsage(rows) => Ok(rows
            .into_iter()
            .map(|(kind, bytes)| AdapterUsageRow { kind, bytes })
            .collect()),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn list_plugins(app: AppHandle) -> Result<Vec<PluginInfo>, String> {
    match dispatch(&app, EngineCmd::ListPlugins).await? {
        Reply::Plugins(p) => Ok(p),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn grant_plugin(
    app: AppHandle,
    id: String,
    caps: Vec<String>,
    egress: Vec<String>,
) -> Result<(), String> {
    match dispatch(&app, EngineCmd::GrantPlugin(id, caps, egress)).await? {
        Reply::Ok => Ok(()),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn set_plugin_enabled(app: AppHandle, id: String, enabled: bool) -> Result<(), String> {
    match dispatch(&app, EngineCmd::SetPluginEnabled(id, enabled)).await? {
        Reply::Ok => Ok(()),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn list_proposals(app: AppHandle) -> Result<Vec<RuleProposal>, String> {
    match dispatch(&app, EngineCmd::ListProposals).await? {
        Reply::Proposals(p) => Ok(p),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn reject_proposal(app: AppHandle, id: i64) -> Result<(), String> {
    match dispatch(&app, EngineCmd::RejectProposal(id)).await? {
        Reply::Ok => Ok(()),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn get_enrichment(app: AppHandle, ips: Vec<String>) -> Result<Vec<EnrichmentEvent>, String> {
    let targets: Vec<EnrichTarget> = ips
        .iter()
        .filter_map(|s| s.parse::<std::net::IpAddr>().ok().map(EnrichTarget::Endpoint))
        .collect();
    match dispatch(&app, EngineCmd::GetEnrichment(targets)).await? {
        Reply::Enrichment(list) => Ok(list
            .into_iter()
            .map(|(target, annotations)| EnrichmentEvent { target, annotations })
            .collect()),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
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
                    ServerMessage::Enrichment { target, annotations } => {
                        let _ = app.emit("engine-enrichment", EnrichmentEvent { target, annotations });
                    }
                    ServerMessage::Proposal(proposal) => {
                        let _ = app.emit("engine-proposal", proposal);
                    }
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
                    EngineCmd::ListRules => ClientMessage::ListRules { req },
                    EngineCmd::GetUsage(query) => ClientMessage::GetUsage { req, query },
                    EngineCmd::GetAdapterUsage(from_ms, to_ms) =>
                        ClientMessage::GetAdapterUsage { req, from_ms, to_ms },
                    EngineCmd::ListAlerts(unacked_only) => ClientMessage::ListAlerts { req, unacked_only },
                    EngineCmd::AckAlert(id) => ClientMessage::AckAlert { req, id },
                    EngineCmd::KillConnection(local_port, remote_addr, remote_port) =>
                        ClientMessage::KillConnection { req, local_port, remote_addr, remote_port },
                    EngineCmd::GetEnrichment(targets) => ClientMessage::GetEnrichment { req, targets },
                    EngineCmd::ListPlugins => ClientMessage::ListPlugins { req },
                    EngineCmd::GrantPlugin(id, caps, egress) =>
                        ClientMessage::GrantPlugin { req, id, caps, egress },
                    EngineCmd::SetPluginEnabled(id, enabled) =>
                        ClientMessage::SetPluginEnabled { req, id, enabled },
                    EngineCmd::ListProposals => ClientMessage::ListProposals { req },
                    EngineCmd::RejectProposal(id) =>
                        ClientMessage::ResolveProposal { req, id, accept: false },
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
