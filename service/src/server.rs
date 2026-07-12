use crate::engine::Engine;
use crate::plugins::registry::EnrichmentRegistry;
use crate::plugins::PanelHub;
use crate::rules::RuleStore;
use iris_ipc::message::{ClientMessage, Reply, ServerMessage, PROTOCOL_VERSION};
use iris_ipc::transport;
use iris_store::Store;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::select;
use tokio::sync::broadcast::error::RecvError;

/// accept clients on the iris pipe until the runtime is cancelled. each
/// connection is served on its own task.
pub async fn serve(
    engine: Engine,
    rules: Arc<Mutex<RuleStore>>,
    store: Arc<Mutex<Store>>,
    enrich: Arc<EnrichmentRegistry>,
    panels: Arc<PanelHub>,
) -> anyhow::Result<()> {
    let listener = transport::listen()?;
    tracing::info!(pipe = iris_ipc::PIPE_NAME, "engine listening");
    // cap concurrent clients so a local process cannot exhaust the engine by
    // opening connections in a loop; a real deployment has one UI plus headroom
    const MAX_CONNECTIONS: usize = 32;
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        // a transient accept error (a client aborting the pipe handshake, a
        // momentary resource shortage) must never take the listener down, or one
        // bad connection attempt kills IPC for every UI. log and keep serving.
        let conn = match transport::accept(&listener).await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                // a brief pause so a hypothetical persistent accept error backs
                // off instead of spinning the CPU; imperceptible for the normal
                // rare transient case
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let permit = match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!("connection limit reached, refusing client");
                drop(conn);
                continue;
            }
        };
        let engine = engine.clone();
        let rules = rules.clone();
        let store = store.clone();
        let enrich = enrich.clone();
        let panels = panels.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for the session, released on disconnect
            if let Err(e) = handle(conn, engine, rules, store, enrich, panels).await {
                tracing::debug!("client disconnected: {e}");
            }
        });
    }
}

/// one client session: negotiate, then multiplex inbound commands against the
/// outbound tick/alert stream on a single duplex connection.
async fn handle(
    stream: transport::Stream,
    engine: Engine,
    rules: Arc<Mutex<RuleStore>>,
    store: Arc<Mutex<Store>>,
    enrich: Arc<EnrichmentRegistry>,
    panels: Arc<PanelHub>,
) -> io::Result<()> {
    let (mut recv, mut send) = transport::split(stream);

    if !negotiate(&mut recv, &mut send).await? {
        return Ok(());
    }

    let mut subscribed = false;
    let mut events = engine.subscribe();

    loop {
        select! {
            inbound = transport::read_frame::<_, ClientMessage>(&mut recv) => {
                let Some(msg) = inbound? else { break };
                match msg {
                    ClientMessage::Hello { .. } => {}
                    ClientMessage::Subscribe => subscribed = true,
                    ClientMessage::Unsubscribe => subscribed = false,
                    ClientMessage::Ping { req } => {
                        reply(&mut send, req, Reply::Pong).await?;
                    }
                    ClientMessage::ListRules { req } => {
                        let list = rules.lock().map(|r| r.list()).unwrap_or_default();
                        reply(&mut send, req, Reply::Rules(list)).await?;
                    }
                    // rule mutations are privileged: they run WFP changes as
                    // LocalSystem, so they are only accepted on the admin pipe
                    // (which the OS lets only an elevated caller open). reject
                    // them here rather than let an unprivileged client change the
                    // firewall.
                    ClientMessage::AddRule { req, .. }
                    | ClientMessage::RemoveRule { req, .. }
                    | ClientMessage::SetRuleEnabled { req, .. } => {
                        reply(&mut send, req, Reply::Error("rule changes require elevation".into()))
                            .await?;
                    }
                    ClientMessage::GetUsage { req, mut query } => {
                        // bound the window so a caller cannot force a scan of the
                        // entire history (a from=0,to=MAX dump / DoS)
                        const MAX_WINDOW_MS: u64 = 400 * 86_400_000;
                        if query.to_ms.saturating_sub(query.from_ms) > MAX_WINDOW_MS {
                            query.from_ms = query.to_ms.saturating_sub(MAX_WINDOW_MS);
                        }
                        // a wide history query can touch many rows; run it on the
                        // blocking pool so it never stalls the reactor or the tick
                        let store = store.clone();
                        let rows = tokio::task::spawn_blocking(move || {
                            store.lock().unwrap_or_else(|e| e.into_inner()).query_usage(&query)
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::Usage(rows)).await?;
                    }
                    ClientMessage::ListAlerts { req, unacked_only } => {
                        let store = store.clone();
                        let list = tokio::task::spawn_blocking(move || {
                            store
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .list_alerts(unacked_only)
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::Alerts(list)).await?;
                    }
                    ClientMessage::AckAlert { req, id } => {
                        if let Ok(s) = store.lock() {
                            s.ack_alert(id);
                        }
                        reply(&mut send, req, Reply::Ok).await?;
                    }
                    ClientMessage::KillConnection { req, local_port, remote_addr, remote_port } => {
                        let killed = kill_conn(local_port, &remote_addr, remote_port);
                        let result = if killed {
                            Reply::Ok
                        } else {
                            Reply::Error("connection not found or not killable".into())
                        };
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::GetEnrichment { req, targets } => {
                        // cache-only read; a miss is filled by the monitor's
                        // resolve-and-push path, so this never blocks on an enricher
                        let anns = enrich.cached_for(&targets);
                        reply(&mut send, req, Reply::Enrichment(anns)).await?;
                    }
                    ClientMessage::ListPlugins { req } => {
                        let store = store.clone();
                        let list = tokio::task::spawn_blocking(move || {
                            crate::plugins::supervisor::catalog(&store)
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::Plugins(list)).await?;
                    }
                    ClientMessage::GrantPlugin { req, id, caps, egress } => {
                        let store = store.clone();
                        let ok = tokio::task::spawn_blocking(move || {
                            crate::plugins::supervisor::grant(&store, &id, &caps, &egress, now_ms())
                        })
                        .await
                        .unwrap_or(false);
                        let result = if ok {
                            Reply::Ok
                        } else {
                            Reply::Error("no such plugin installed".into())
                        };
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::SetPluginEnabled { req, id, enabled } => {
                        let store = store.clone();
                        let ok = tokio::task::spawn_blocking(move || {
                            crate::plugins::supervisor::set_enabled(&store, &id, enabled)
                        })
                        .await
                        .unwrap_or(false);
                        let result = if ok {
                            Reply::Ok
                        } else {
                            Reply::Error("plugin has no consent grant yet".into())
                        };
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::GetPluginPanel { req, id } => {
                        // a plugin round-trip; keep it off the reactor
                        let panels = panels.clone();
                        let result = tokio::task::spawn_blocking(move || panels.panel(&id))
                            .await
                            .unwrap_or_else(|_| Err("panel fetch failed".into()));
                        let result = match result {
                            Ok(panel) => Reply::Panel(panel),
                            Err(e) => Reply::Error(e),
                        };
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::ListProposals { req } => {
                        let store = store.clone();
                        let list = tokio::task::spawn_blocking(move || {
                            store.lock().unwrap_or_else(|e| e.into_inner()).list_proposals()
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::Proposals(list)).await?;
                    }
                    // rejecting a proposal enforces nothing, so any client may;
                    // accepting turns it into a firewall rule and belongs to the
                    // admin pipe, the same boundary as AddRule
                    ClientMessage::ResolveProposal { req, id, accept } => {
                        let result = if accept {
                            Reply::Error("accepting a proposal requires elevation".into())
                        } else if store
                            .lock()
                            .map(|s| s.resolve_proposal(id, false).is_some())
                            .unwrap_or(false)
                        {
                            Reply::Ok
                        } else {
                            Reply::Error("no pending proposal with that id".into())
                        };
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::GetAdapterUsage { req, from_ms, to_ms } => {
                        // same window bound as GetUsage, for the same reason
                        const MAX_WINDOW_MS: u64 = 400 * 86_400_000;
                        let from = from_ms.max(to_ms.saturating_sub(MAX_WINDOW_MS));
                        let store = store.clone();
                        let rows = tokio::task::spawn_blocking(move || {
                            store
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .adapter_usage_totals(from, to_ms)
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::AdapterUsage(rows)).await?;
                    }
                    // commands whose engine support arrives in later slices: answer
                    // rather than leave the UI awaiting a reply that never comes
                    other => {
                        if let Some(req) = req_of(&other) {
                            reply(&mut send, req, Reply::Error("not yet supported".into())).await?;
                        }
                    }
                }
            }
            outbound = events.recv() => {
                match outbound {
                    // ticks only go to subscribers; alerts always go out
                    Ok(msg) => {
                        let deliver = subscribed || matches!(msg, ServerMessage::Alert(_));
                        if deliver {
                            transport::write_frame(&mut send, &msg).await?;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        tracing::trace!(dropped = n, "client fell behind on ticks");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}

/// accept elevated clients on the admin pipe and run their rule mutations. only
/// an elevated process can open this pipe (its DACL grants SYSTEM + admins only),
/// so a message arriving here is authorized to change the firewall.
pub async fn serve_admin(
    rules: Arc<Mutex<RuleStore>>,
    store: Arc<Mutex<Store>>,
) -> anyhow::Result<()> {
    let listener = transport::listen_admin()?;
    tracing::info!(pipe = iris_ipc::ADMIN_PIPE_NAME, "admin channel listening");
    let slots = Arc::new(tokio::sync::Semaphore::new(8));
    loop {
        let conn = match transport::accept(&listener).await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("admin accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let permit = match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                drop(conn);
                continue;
            }
        };
        let rules = rules.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_admin(conn, rules, store).await {
                tracing::debug!("admin client disconnected: {e}");
            }
        });
    }
}

async fn handle_admin(
    stream: transport::Stream,
    rules: Arc<Mutex<RuleStore>>,
    store: Arc<Mutex<Store>>,
) -> io::Result<()> {
    let (mut recv, mut send) = transport::split(stream);
    if !negotiate(&mut recv, &mut send).await? {
        return Ok(());
    }
    while let Some(msg) = transport::read_frame::<_, ClientMessage>(&mut recv).await? {
        match msg {
            ClientMessage::AddRule { req, rule } => {
                let result = rules
                    .lock()
                    .map(|mut r| r.add(rule))
                    .map(Reply::RuleAdded)
                    .unwrap_or_else(|_| Reply::Error("rule store unavailable".into()));
                reply(&mut send, req, result).await?;
            }
            ClientMessage::RemoveRule { req, id } => {
                let removed = rules.lock().map(|mut r| r.remove(id)).unwrap_or(false);
                let result = if removed {
                    Reply::Ok
                } else {
                    Reply::Error("no rule with that id".into())
                };
                reply(&mut send, req, result).await?;
            }
            ClientMessage::SetRuleEnabled { req, id, enabled } => {
                let updated = rules.lock().ok().and_then(|mut r| r.set_enabled(id, enabled));
                let result = if updated.is_some() {
                    Reply::Ok
                } else {
                    Reply::Error("no rule with that id".into())
                };
                reply(&mut send, req, result).await?;
            }
            // the elevated half of proposal review: settle it, and on accept
            // enforce the proposed rule through the one path that touches WFP
            ClientMessage::ResolveProposal { req, id, accept } => {
                let settled = store
                    .lock()
                    .map(|s| s.resolve_proposal(id, accept))
                    .unwrap_or(None);
                let result = match settled {
                    Some(p) if accept => rules
                        .lock()
                        .map(|mut r| r.add(p.rule))
                        .map(Reply::RuleAdded)
                        .unwrap_or_else(|_| Reply::Error("rule store unavailable".into())),
                    Some(_) => Reply::Ok,
                    None => Reply::Error("no pending proposal with that id".into()),
                };
                reply(&mut send, req, result).await?;
            }
            ClientMessage::Ping { req } => reply(&mut send, req, Reply::Pong).await?,
            other => {
                if let Some(req) = req_of(&other) {
                    reply(
                        &mut send,
                        req,
                        Reply::Error("the admin channel accepts only rule changes".into()),
                    )
                    .await?;
                }
            }
        }
    }
    Ok(())
}

/// the shared Hello/Welcome handshake; returns false when the client should be
/// dropped (a protocol mismatch or a non-Hello first frame).
async fn negotiate(
    recv: &mut transport::RecvHalf,
    send: &mut transport::SendHalf,
) -> io::Result<bool> {
    match transport::read_frame::<_, ClientMessage>(recv).await? {
        Some(ClientMessage::Hello { protocol }) => {
            transport::write_frame(
                send,
                &ServerMessage::Welcome {
                    protocol: PROTOCOL_VERSION,
                    engine_version: env!("CARGO_PKG_VERSION").to_string(),
                },
            )
            .await?;
            if protocol != PROTOCOL_VERSION {
                tracing::warn!(client = protocol, ours = PROTOCOL_VERSION, "protocol mismatch");
            }
            Ok(protocol == PROTOCOL_VERSION)
        }
        _ => Ok(false),
    }
}

async fn reply(
    send: &mut transport::SendHalf,
    req: u64,
    result: Reply,
) -> io::Result<()> {
    transport::write_frame(send, &ServerMessage::Reply { req, result }).await
}

fn req_of(m: &ClientMessage) -> Option<u64> {
    match m {
        ClientMessage::ListConnections { req }
        | ClientMessage::ListRules { req }
        | ClientMessage::AddRule { req, .. }
        | ClientMessage::RemoveRule { req, .. }
        | ClientMessage::SetRuleEnabled { req, .. }
        | ClientMessage::GetUsage { req, .. }
        | ClientMessage::ListAlerts { req, .. }
        | ClientMessage::AckAlert { req, .. }
        | ClientMessage::KillConnection { req, .. }
        | ClientMessage::GetEnrichment { req, .. }
        | ClientMessage::GetAdapterUsage { req, .. }
        | ClientMessage::ListPlugins { req }
        | ClientMessage::GrantPlugin { req, .. }
        | ClientMessage::SetPluginEnabled { req, .. }
        | ClientMessage::ListProposals { req }
        | ClientMessage::ResolveProposal { req, .. }
        | ClientMessage::GetPluginPanel { req, .. }
        | ClientMessage::Ping { req } => Some(*req),
        ClientMessage::Hello { .. } | ClientMessage::Subscribe | ClientMessage::Unsubscribe => None,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn kill_conn(local_port: u16, remote_addr: &str, remote_port: u16) -> bool {
    #[cfg(has_platform)]
    {
        match remote_addr.parse() {
            Ok(ip) => crate::platform::kill_connection(local_port, ip, remote_port),
            Err(_) => false,
        }
    }
    #[cfg(not(has_platform))]
    {
        let _ = (local_port, remote_addr, remote_port);
        false
    }
}
