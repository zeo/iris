//! the UI's client to the engine's telemetry pipe. a background task keeps a
//! connection open, negotiates the protocol, subscribes to the live stream, and
//! forwards pushes to the webview as Tauri events. it also carries the
//! unprivileged request/response commands (reads, kills, enrichment) correlated
//! by id. privileged rule mutations do not go here; they run elevated over the
//! admin pipe (see `rulectl`). it reconnects on its own.

use iris_core::{
    AdapterKind, Alert, Annotation, ByteCounts, EnrichTarget, Granularity, KnownApp, Panel,
    RuleAction, RuleProposal, StoredRule, UsageBucket, UsageQuery,
};
use iris_ipc::message::{ClientMessage, PluginInfo, Reply, ServerMessage, PROTOCOL_VERSION};
use iris_ipc::transport;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

pub struct TickDetailState {
    detailed: AtomicBool,
    cadence_ms: AtomicU64,
}

impl Default for TickDetailState {
    fn default() -> Self {
        Self {
            detailed: AtomicBool::new(false),
            cadence_ms: AtomicU64::new(4_000),
        }
    }
}

/// what the UI asks the engine to do; the session task assigns the wire id
pub enum EngineCmd {
    ListRules,
    ListApps,
    ForgetApp(String),
    ForgetApps(Vec<String>),
    AddRule(iris_core::Rule),
    RemoveRule(i64),
    SetRuleEnabled(i64, bool),
    GetRuleGrant,
    GetUsage(UsageQuery),
    GetAdapterUsage(u64, u64),
    ListAlerts(bool),
    ListPromptAlerts,
    SuppressAlertPrompts,
    AckAlert(i64),
    DecideAlert(i64, RuleAction),
    KillConnection(u16, String, u16),
    GetEnrichment(Vec<EnrichTarget>),
    ListPlugins,
    GrantPlugin(String, Vec<String>, Vec<String>),
    SetPluginEnabled(String, bool),
    ListProposals,
    // rejecting is unprivileged; accepting enforces a rule, so it needs the
    // delegated grant or an elevated run (see rulectl)
    RejectProposal(i64),
    ResolveProposal(i64, bool),
    GetPluginPanel(String),
}
pub struct Command {
    cmd: EngineCmd,
    resp: oneshot::Sender<Reply>,
}

/// managed handle the commands use to reach the session task
pub struct Commander(pub mpsc::Sender<Command>);

#[tauri::command]
pub fn engine_status(state: tauri::State<'_, StatusState>) -> Status {
    state
        .inner()
        .0
        .lock()
        .map(|s| s.clone())
        .unwrap_or_default()
}

#[tauri::command]
pub fn set_tick_details(state: tauri::State<'_, TickDetailState>, enabled: bool, cadence_ms: u64) {
    state.detailed.store(enabled, Ordering::Release);
    state
        .cadence_ms
        .store(cadence_ms.max(1_000), Ordering::Release);
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
pub async fn list_apps(app: AppHandle) -> Result<Vec<KnownApp>, String> {
    match dispatch(&app, EngineCmd::ListApps).await? {
        Reply::Apps(apps) => Ok(apps),
        Reply::Error(error) => Err(error),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn forget_app(app: AppHandle, path: String) -> Result<(), String> {
    match dispatch(&app, EngineCmd::ForgetApp(path)).await? {
        Reply::Ok => Ok(()),
        Reply::Error(error) => Err(error),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn forget_apps(app: AppHandle, paths: Vec<String>) -> Result<usize, String> {
    match dispatch(&app, EngineCmd::ForgetApps(paths)).await? {
        Reply::Forgotten(count) => Ok(count),
        Reply::Error(error) => Err(error),
        _ => Err("unexpected reply".into()),
    }
}

/// whether this account may change rules without an elevation prompt
#[tauri::command]
pub async fn rule_grant(app: AppHandle) -> Result<bool, String> {
    match dispatch(&app, EngineCmd::GetRuleGrant).await? {
        Reply::RuleGrant(granted) => Ok(granted),
        Reply::Error(error) => Err(error),
        _ => Err("unexpected reply".into()),
    }
}

/// try a rule mutation over the telemetry channel, which the engine accepts only
/// when the one-time grant is in force. `Ok(false)` means the engine wants
/// elevation, so the caller falls back to the elevated one-shot.
pub(crate) async fn try_unelevated(app: &AppHandle, cmd: EngineCmd) -> Result<bool, String> {
    match dispatch(app, cmd).await {
        Ok(Reply::Ok) | Ok(Reply::RuleAdded(_)) => Ok(true),
        Ok(Reply::Error(error)) if error == NEEDS_ELEVATION => Ok(false),
        Ok(Reply::Error(error)) => Err(error),
        Ok(_) => Err("unexpected reply".into()),
        // the engine being unreachable is not a reason to raise a UAC prompt
        Err(error) => Err(error),
    }
}

/// mirrors the engine's own wording for a rule change that needs elevation
const NEEDS_ELEVATION: &str = "rule changes require elevation";

#[tauri::command]
pub async fn list_alerts(app: AppHandle, unacked_only: bool) -> Result<Vec<Alert>, String> {
    match dispatch(&app, EngineCmd::ListAlerts(unacked_only)).await? {
        Reply::Alerts(a) => Ok(a),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn list_prompt_alerts(app: AppHandle) -> Result<Vec<Alert>, String> {
    match dispatch(&app, EngineCmd::ListPromptAlerts).await? {
        Reply::Alerts(alerts) => Ok(alerts),
        Reply::Error(error) => Err(error),
        _ => Err("unexpected reply".into()),
    }
}

pub(crate) async fn suppress_alert_prompts(app: AppHandle) -> Result<(), String> {
    match dispatch(&app, EngineCmd::SuppressAlertPrompts).await? {
        Reply::Ok => Ok(()),
        Reply::Error(error) => Err(error),
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
pub async fn decide_alert(app: AppHandle, id: i64, action: String) -> Result<(), String> {
    let action = if action == "allow" {
        RuleAction::Allow
    } else {
        RuleAction::Block
    };
    match dispatch(&app, EngineCmd::DecideAlert(id, action)).await? {
        Reply::Ok => Ok(()),
        Reply::Error(error) => Err(error),
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
    match dispatch(
        &app,
        EngineCmd::KillConnection(local_port, remote_addr, remote_port),
    )
    .await?
    {
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
    match dispatch(
        &app,
        EngineCmd::GetAdapterUsage(from_ms as u64, to_ms as u64),
    )
    .await?
    {
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
pub async fn get_plugin_panel(app: AppHandle, id: String) -> Result<Panel, String> {
    match dispatch(&app, EngineCmd::GetPluginPanel(id)).await? {
        Reply::Panel(p) => Ok(p),
        Reply::Error(e) => Err(e),
        _ => Err("unexpected reply".into()),
    }
}

#[tauri::command]
pub async fn get_enrichment(
    app: AppHandle,
    ips: Vec<String>,
) -> Result<Vec<EnrichmentEvent>, String> {
    let targets: Vec<EnrichTarget> = ips
        .iter()
        .filter_map(|s| {
            s.parse::<std::net::IpAddr>()
                .ok()
                .map(EnrichTarget::Endpoint)
        })
        .collect();
    match dispatch(&app, EngineCmd::GetEnrichment(targets)).await? {
        Reply::Enrichment(list) => Ok(list
            .into_iter()
            .map(|(target, annotations)| EnrichmentEvent {
                target,
                annotations,
            })
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
            reconcile_alerts(app, &mut recv, &mut send).await?;
            set_status(app, true, Some(engine_version));
        }
        other => anyhow::bail!("expected Welcome, got {other:?}"),
    }

    let mut next_id: u64 = 1;
    let mut last_tick_emit = 0;
    let mut pending: HashMap<u64, oneshot::Sender<Reply>> = HashMap::new();
    let (incoming_tx, mut incoming_rx) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let frame = transport::read_frame::<_, ServerMessage>(&mut recv).await;
            let done = !matches!(frame, Ok(Some(_)));
            if incoming_tx
                .send(frame.and_then(|msg| {
                    msg.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
                }))
                .await
                .is_err()
                || done
            {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            incoming = incoming_rx.recv() => {
                let Some(incoming) = incoming else { break };
                let msg = incoming?;
                match msg {
                    ServerMessage::Tick(mut tick) => {
                        let Some(state) = app.try_state::<TickDetailState>() else {
                            continue;
                        };
                        let cadence_ms = state.cadence_ms.load(Ordering::Acquire);
                        if tick.at_ms.saturating_sub(last_tick_emit) < cadence_ms {
                            continue;
                        }
                        last_tick_emit = tick.at_ms;
                        let detailed = state.detailed.load(Ordering::Acquire);
                        if !detailed {
                            for sample in &mut tick.apps {
                                sample.processes.clear();
                            }
                        }
                        let _ = app.emit("engine-tick", tick);
                    }
                    ServerMessage::Alert(alert) => {
                        crate::prompt::show(app, &alert);
                        crate::notify::alert_toast(app, &alert);
                        let _ = app.emit("engine-alert", alert);
                    }
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
                    EngineCmd::ListApps => ClientMessage::ListApps { req },
                    EngineCmd::ForgetApp(path) => ClientMessage::ForgetApp { req, path },
                    EngineCmd::ForgetApps(paths) => ClientMessage::ForgetApps { req, paths },
                    EngineCmd::AddRule(rule) => ClientMessage::AddRule { req, rule },
                    EngineCmd::RemoveRule(id) => ClientMessage::RemoveRule { req, id },
                    EngineCmd::SetRuleEnabled(id, enabled) =>
                        ClientMessage::SetRuleEnabled { req, id, enabled },
                    EngineCmd::GetRuleGrant => ClientMessage::GetRuleGrant { req },
                    EngineCmd::GetUsage(query) => ClientMessage::GetUsage { req, query },
                    EngineCmd::GetAdapterUsage(from_ms, to_ms) =>
                        ClientMessage::GetAdapterUsage { req, from_ms, to_ms },
                    EngineCmd::ListAlerts(unacked_only) => ClientMessage::ListAlerts { req, unacked_only },
                    EngineCmd::ListPromptAlerts => ClientMessage::ListPromptAlerts { req },
                    EngineCmd::SuppressAlertPrompts => ClientMessage::SuppressAlertPrompts { req },
                    EngineCmd::AckAlert(id) => ClientMessage::AckAlert { req, id },
                    EngineCmd::DecideAlert(id, action) =>
                        ClientMessage::DecideAlert { req, id, action },
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
                    EngineCmd::ResolveProposal(id, accept) =>
                        ClientMessage::ResolveProposal { req, id, accept },
                    EngineCmd::GetPluginPanel(id) => ClientMessage::GetPluginPanel { req, id },
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

async fn reconcile_alerts(
    app: &AppHandle,
    recv: &mut transport::RecvHalf,
    send: &mut transport::SendHalf,
) -> anyhow::Result<()> {
    const BACKLOG_REQ: u64 = 0;
    const PROMPT_REQ: u64 = 1;
    transport::write_frame(send, &ClientMessage::Subscribe).await?;
    transport::write_frame(
        send,
        &ClientMessage::ListAlerts {
            req: BACKLOG_REQ,
            unacked_only: true,
        },
    )
    .await?;
    transport::write_frame(send, &ClientMessage::ListPromptAlerts { req: PROMPT_REQ }).await?;

    let mut backlog: Option<Vec<Alert>> = None;
    let mut prompts: Option<Vec<Alert>> = None;

    loop {
        let frame = tokio::time::timeout(
            Duration::from_secs(10),
            transport::read_frame::<_, ServerMessage>(recv),
        )
        .await
        .map_err(|_| anyhow::anyhow!("engine timed out during alert restore"))??;
        match frame {
            Some(ServerMessage::Reply {
                req: BACKLOG_REQ,
                result: Reply::Alerts(alerts),
            }) => {
                backlog = Some(alerts);
                if let (Some(backlog), Some(prompts)) = (&backlog, &prompts) {
                    finish_alert_reconcile(app, backlog, prompts);
                    return Ok(());
                }
            }
            Some(ServerMessage::Reply {
                req: PROMPT_REQ,
                result: Reply::Alerts(alerts),
            }) => {
                prompts = Some(alerts);
                if let (Some(backlog), Some(prompts)) = (&backlog, &prompts) {
                    finish_alert_reconcile(app, backlog, prompts);
                    return Ok(());
                }
            }
            Some(ServerMessage::Alert(alert)) => {
                crate::prompt::show(app, &alert);
                crate::notify::alert_toast(app, &alert);
                let _ = app.emit("engine-alert", alert);
            }
            Some(ServerMessage::Enrichment {
                target,
                annotations,
            }) => {
                let _ = app.emit(
                    "engine-enrichment",
                    EnrichmentEvent {
                        target,
                        annotations,
                    },
                );
            }
            Some(ServerMessage::Proposal(proposal)) => {
                let _ = app.emit("engine-proposal", proposal);
            }
            Some(ServerMessage::Tick(_) | ServerMessage::Welcome { .. }) => {}
            Some(ServerMessage::Reply { .. }) => {
                anyhow::bail!("unexpected reply during alert restore")
            }
            None => anyhow::bail!("engine disconnected during alert restore"),
        }
    }
}

fn finish_alert_reconcile(app: &AppHandle, backlog: &[Alert], prompts: &[Alert]) {
    crate::notify::announce_backlog(app, backlog);
    if let Some(alert) = prompts
        .iter()
        .find(|alert| crate::notify::needs_decision(alert))
    {
        crate::prompt::show(app, alert);
    }
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
