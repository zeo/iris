use crate::engine::Engine;
use crate::plugins::registry::EnrichmentRegistry;
use crate::plugins::PanelHub;
use crate::rules::RuleStore;
use iris_core::{Alert, AlertKind, Direction, Endpoint, Rule, RuleAction, RuleLifetime, RuleScope};
use iris_ipc::message::{ClientMessage, Health, Reply, ServerMessage, PROTOCOL_VERSION};
use iris_ipc::transport;
use iris_store::Store;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

/// what the UI is told when a rule change arrives without the delegated grant.
/// the app matches on it to decide whether to retry the change elevated.
pub const NEEDS_ELEVATION: &str = "rule changes require elevation";

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
    #[cfg(target_os = "linux")]
    crate::paths::grant_telemetry_socket(iris_ipc::PIPE_NAME)?;
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
        let peer = match authorize_peer(&conn) {
            Ok(peer) => peer,
            Err(e) => {
                tracing::warn!("refusing client, authorization check failed: {e}");
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
            if let Err(e) = handle(conn, peer, engine, rules, store, enrich, panels).await {
                tracing::debug!("client disconnected: {e}");
            }
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_auth_tests {
    use super::authorized_linux_uid;

    #[test]
    fn admits_root_and_the_installed_desktop_account() {
        assert!(authorized_linux_uid(0, 1000));
        assert!(authorized_linux_uid(1000, 1000));
    }

    #[test]
    fn rejects_plugins_and_unrelated_accounts() {
        assert!(!authorized_linux_uid(997, 1000));
        assert!(!authorized_linux_uid(1001, 1000));
    }
}

#[cfg(target_os = "linux")]
fn authorized_linux_uid(peer: u32, desktop: u32) -> bool {
    peer == 0 || peer == desktop
}

/// who is on the other end of a telemetry connection: the desktop scope the
/// session-liveness check uses, plus the account identity the delegated
/// rule-management grant is compared against
#[derive(Clone)]
pub struct Peer {
    scope: u32,
    account: crate::grant::Account,
}

impl Peer {
    /// whether this peer may mutate rules without elevating, which requires both
    /// a recorded grant naming exactly this account and a still-active session
    fn may_manage_rules(&self) -> bool {
        peer_scope_is_active(self.scope) && crate::grant::allows(&self.account)
    }
}

#[cfg(target_os = "linux")]
fn authorize_peer(stream: &transport::Stream) -> io::Result<Peer> {
    let desktop = crate::paths::desktop_uid()?;
    let peer = transport::peer_euid(stream)?;
    if authorized_linux_uid(peer, desktop) {
        Ok(Peer {
            scope: desktop,
            account: peer,
        })
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("uid {peer} is not the desktop account"),
        ))
    }
}

#[cfg(windows)]
fn authorize_peer(stream: &transport::Stream) -> io::Result<Peer> {
    use windows::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTSGetActiveConsoleSessionId,
    };

    let pid = transport::peer_pid(stream)?;
    let mut session = u32::MAX;
    unsafe { ProcessIdToSessionId(pid, &mut session) }.map_err(io::Error::other)?;
    let active = unsafe { WTSGetActiveConsoleSessionId() };
    if active == u32::MAX || session != active {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client is outside the active desktop session",
        ));
    }
    Ok(Peer {
        scope: session,
        account: crate::grant::sid_of_process(pid)?,
    })
}

#[cfg(not(any(windows, target_os = "linux")))]
fn authorize_peer(_stream: &transport::Stream) -> io::Result<Peer> {
    Ok(Peer {
        scope: 0,
        account: 0,
    })
}

#[cfg(windows)]
fn peer_scope_is_active(scope: u32) -> bool {
    use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
    (unsafe { WTSGetActiveConsoleSessionId() }) == scope
}

#[cfg(not(windows))]
fn peer_scope_is_active(_scope: u32) -> bool {
    true
}

/// one client session: negotiate, then multiplex inbound commands against the
/// outbound tick/alert stream on a single duplex connection.
async fn handle(
    stream: transport::Stream,
    peer: Peer,
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

    let mut feed = Feed::Off;
    let mut events = engine.subscribe();
    let (incoming_tx, mut incoming_rx) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let frame = transport::read_frame::<_, ClientMessage>(&mut recv).await;
            let done = !matches!(frame, Ok(Some(_)));
            if incoming_tx
                .send(frame.and_then(|msg| {
                    msg.ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
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
        select! {
            incoming = incoming_rx.recv() => {
                let Some(incoming) = incoming else { break };
                if !peer_scope_is_active(peer.scope) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "desktop session is no longer active",
                    ));
                }
                let msg = incoming?;
                match msg {
                    ClientMessage::Hello { .. } => {}
                    ClientMessage::Subscribe => feed = Feed::Full,
                    ClientMessage::SubscribeTotals => feed = Feed::Totals,
                    ClientMessage::Unsubscribe => feed = Feed::Off,
                    ClientMessage::Ping { req } => {
                        reply(&mut send, req, Reply::Pong).await?;
                    }
                    ClientMessage::ListRules { req } => {
                        let list = read_rules(&rules, RuleStore::list).await.unwrap_or_default();
                        reply(&mut send, req, Reply::Rules(list)).await?;
                    }
                    ClientMessage::ListApps { req } => {
                        let store = store.clone();
                        let list = tokio::task::spawn_blocking(move || {
                            store.lock().unwrap_or_else(|e| e.into_inner()).list_apps()
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::Apps(list)).await?;
                    }
                    ClientMessage::ForgetApp { req, path } => {
                        let store = store.clone();
                        #[cfg(target_os = "linux")]
                        let rules = rules.clone();
                        let removed = tokio::task::spawn_blocking(move || {
                            let removed = store
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .forget_app(&path);
                            #[cfg(target_os = "linux")]
                            if removed {
                                rules
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .forget_trusted_app(&path);
                            }
                            removed
                        })
                        .await
                        .unwrap_or(false);
                        reply(
                            &mut send,
                            req,
                            if removed { Reply::Ok } else { Reply::Error("application not found".into()) },
                        )
                        .await?;
                    }
                    // rule mutations run WFP changes as LocalSystem, so they are
                    // privileged. they are accepted here only when the user has
                    // already elevated once to authorize exactly this account
                    // (see `grant`), and the peer is still in the active console
                    // session. without that grant the admin pipe remains the only
                    // way in, so an unprivileged client cannot touch the firewall.
                    ClientMessage::AddRule { req, rule } => {
                        if !peer.may_manage_rules() {
                            reply(&mut send, req, Reply::Error(NEEDS_ELEVATION.into())).await?;
                        } else {
                            let rules = rules.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                rules
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .add(rule)
                                    .map(Reply::RuleAdded)
                                    .unwrap_or_else(|error| Reply::Error(error.to_string()))
                            })
                            .await
                            .unwrap_or_else(|_| Reply::Error("the rule change failed".into()));
                            reply(&mut send, req, result).await?;
                        }
                    }
                    ClientMessage::RemoveRule { req, id } => {
                        if !peer.may_manage_rules() {
                            reply(&mut send, req, Reply::Error(NEEDS_ELEVATION.into())).await?;
                        } else {
                            let rules = rules.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                match rules
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .remove(id)
                                {
                                    Ok(true) => Reply::Ok,
                                    Ok(false) => Reply::Error("no rule with that id".into()),
                                    Err(error) => Reply::Error(error.to_string()),
                                }
                            })
                            .await
                            .unwrap_or_else(|_| Reply::Error("the rule change failed".into()));
                            reply(&mut send, req, result).await?;
                        }
                    }
                    ClientMessage::SetRuleEnabled { req, id, enabled } => {
                        if !peer.may_manage_rules() {
                            reply(&mut send, req, Reply::Error(NEEDS_ELEVATION.into())).await?;
                        } else {
                            let rules = rules.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                match rules
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .set_enabled(id, enabled)
                                {
                                    Ok(Some(_)) => Reply::Ok,
                                    Ok(None) => Reply::Error("no rule with that id".into()),
                                    Err(error) => Reply::Error(error.to_string()),
                                }
                            })
                            .await
                            .unwrap_or_else(|_| Reply::Error("the rule change failed".into()));
                            reply(&mut send, req, result).await?;
                        }
                    }
                    ClientMessage::GetRuleGrant { req } => {
                        reply(&mut send, req, Reply::RuleGrant(peer.may_manage_rules())).await?;
                    }
                    ClientMessage::GetFirewallMode { req } => {
                        let result = read_rules(&rules, RuleStore::mode)
                            .await
                            .map_or_else(rules_unavailable, Reply::FirewallMode);
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::SetFirewallMode { req, mode } => {
                        let result = if peer.may_manage_rules() {
                            set_mode(&rules, mode).await
                        } else {
                            Reply::Error(NEEDS_ELEVATION.into())
                        };
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::ListCaps { req } => {
                        let result = read_rules(&rules, RuleStore::caps)
                            .await
                            .map_or_else(rules_unavailable, Reply::Caps);
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::SetCap { req, app, up_bytes_per_sec, down_bytes_per_sec } => {
                        let result = if peer.may_manage_rules() {
                            set_cap(&rules, app, up_bytes_per_sec, down_bytes_per_sec).await
                        } else {
                            Reply::Error(NEEDS_ELEVATION.into())
                        };
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::ListQuotas { req } => {
                        let result = read_rules(&rules, |rules| rules.quotas(now_ms()))
                            .await
                            .map_or_else(rules_unavailable, Reply::Quotas);
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::SetQuota { req, app, limit } => {
                        let result = if app.is_none() || peer.may_manage_rules() {
                            set_quota(&rules, app, limit).await
                        } else {
                            Reply::Error(NEEDS_ELEVATION.into())
                        };
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::GetProfiles { req } => {
                        let result = read_rules(&rules, RuleStore::profile_state)
                            .await
                            .map_or_else(rules_unavailable, Reply::Profiles);
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::SetProfiles { req, profiles, manual } => {
                        let result = if peer.may_manage_rules() {
                            set_profiles(&rules, profiles, manual).await
                        } else {
                            Reply::Error(NEEDS_ELEVATION.into())
                        };
                        reply(&mut send, req, result).await?;
                    }
                    // establishing or revoking the grant is itself privileged, so
                    // it only happens on the admin channel
                    ClientMessage::SetRuleGrant { req, .. } => {
                        reply(&mut send, req, Reply::Error(NEEDS_ELEVATION.into())).await?;
                    }
                    ClientMessage::ForgetApps { req, paths } => {
                        let store = store.clone();
                        #[cfg(target_os = "linux")]
                        let rules = rules.clone();
                        let removed = tokio::task::spawn_blocking(move || {
                            let removed = store
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .forget_apps(&paths);
                            #[cfg(target_os = "linux")]
                            {
                                let rules = rules.lock().unwrap_or_else(|e| e.into_inner());
                                for path in &paths {
                                    rules.forget_trusted_app(path);
                                }
                            }
                            removed
                        })
                        .await
                        .unwrap_or(0);
                        reply(&mut send, req, Reply::Forgotten(removed)).await?;
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
                    ClientMessage::GetHostUsage { req, app, from_ms, to_ms } => {
                        let store = store.clone();
                        let rows = tokio::task::spawn_blocking(move || {
                            store
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .host_usage(app.as_ref(), from_ms, to_ms)
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::HostUsage(rows)).await?;
                    }
                    ClientMessage::HostAddresses { req, host } => {
                        #[cfg(has_platform)]
                        let addresses = crate::platform::addresses_of(&engine.dns, &host);
                        #[cfg(not(has_platform))]
                        let addresses = {
                            let _ = host;
                            Vec::new()
                        };
                        reply(&mut send, req, Reply::HostAddresses(addresses)).await?;
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
                    ClientMessage::ListBlocked { req, limit } => {
                        let store = store.clone();
                        let list = tokio::task::spawn_blocking(move || {
                            store
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .list_blocked(limit)
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::Blocked(list)).await?;
                    }
                    ClientMessage::GetHealth { req } => {
                        let store = store.clone();
                        let health = tokio::task::spawn_blocking(move || {
                            #[cfg_attr(not(windows), allow(unused_mut))]
                            let mut health = Health {
                                history_in_memory: store.lock().unwrap_or_else(|e| e.into_inner()).in_memory(),
                                ..Health::default()
                            };
                            #[cfg(windows)]
                            for block in crate::platform::outbound_blocks() {
                                if block.by_policy {
                                    health.outbound_policy.push(block.profile.to_string());
                                }
                                health.outbound_blocked.push(block.profile.to_string());
                            }
                            health
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::Health(health)).await?;
                    }
                    ClientMessage::ListPromptAlerts { req } => {
                        let store = store.clone();
                        let list = tokio::task::spawn_blocking(move || {
                            store
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .list_prompt_alerts()
                        })
                        .await
                        .unwrap_or_default();
                        reply(&mut send, req, Reply::Alerts(list)).await?;
                    }
                    ClientMessage::AckAlert { req, id } => {
                        let store = store.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            store.lock().unwrap_or_else(|e| e.into_inner()).ack_alert(id);
                        })
                        .await;
                        reply(&mut send, req, Reply::Ok).await?;
                    }
                    ClientMessage::DecideAlert { req, id, action, scope, lifetime } => {
                        let store = store.clone();
                        let rules = rules.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            let pending = store
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .list_prompt_alerts();
                            let alert = pending.iter().find(|alert| alert.id == id);
                            if let Some(AlertKind::NewApp { remote, .. }) = alert.map(|alert| &alert.kind) {
                                if let Some(error) =
                                    answer_error(&scope, lifetime, remote.as_ref(), now_ms())
                                {
                                    return Reply::Error(error.into());
                                }
                            }
                            match alert.map(|alert| alert.kind.clone()) {
                                Some(AlertKind::NewApp { app, direction, .. }) => {
                                    let path = app.0.clone();
                                    // this command is bounded to one pending alert and
                                    // the active desktop session. manual rule changes
                                    // still use the admin endpoint.
                                    //
                                    // under ask-before-connect an Allow has to become
                                    // a real permit rule: the catch-all deny is still
                                    // in force, so recording the decision alone would
                                    // leave the app blocked forever.
                                    let asking = {
                                        #[cfg(has_platform)]
                                        {
                                            rules
                                                .lock()
                                                .unwrap_or_else(|error| error.into_inner())
                                                .ask_mode()
                                        }
                                        #[cfg(not(has_platform))]
                                        {
                                            false
                                        }
                                    };
                                    // an app gone since it asked has nothing left to
                                    // allow or block; answering just settles the prompt
                                    let needs_rule = !crate::monitor::app_is_gone(&path)
                                        && (asking || matches!(action, RuleAction::Block));
                                    let rule = Rule {
                                        scope,
                                        lifetime,
                                        ..Rule::new(app, direction.unwrap_or(Direction::Outbound), action)
                                    };
                                    let applied = if needs_rule {
                                        rules
                                            .lock()
                                            .unwrap_or_else(|error| error.into_inner())
                                            .add(rule.clone())
                                            .map(|_| ())
                                    } else {
                                        Ok(())
                                    };
                                    match applied {
                                        Ok(()) => {
                                            let store =
                                                store.lock().unwrap_or_else(|e| e.into_inner());
                                            settle_answer(&store, &pending, id, &rule);
                                            Reply::Ok
                                        }
                                        Err(error) => Reply::Error(format!(
                                            "could not apply decision: {error}"
                                        )),
                                    }
                                }
                                _ => Reply::Error("connection decision is no longer pending".into()),
                            }
                        })
                        .await
                        .unwrap_or_else(|_| {
                            Reply::Error("the engine could not apply the decision".into())
                        });
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::KillConnection { req, local_port, remote_addr, remote_port } => {
                        let killed = kill_conn(local_port, &remote_addr, remote_port, peer.scope);
                        let result = if killed {
                            Reply::Ok
                        } else {
                            Reply::Error("connection not found or not killable".into())
                        };
                        reply(&mut send, req, result).await?;
                    }
                    ClientMessage::GetEnrichment { req, targets } => {
                        // cache-only read; a miss is filled by the monitor's
                        // resolve-and-push path, so this never blocks on an enricher.
                        // still off the reactor, since targets is client-sized
                        let enrich = enrich.clone();
                        let anns = tokio::task::spawn_blocking(move || enrich.cached_for(&targets))
                            .await
                            .unwrap_or_default();
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
                    // a plugin runs as a child of the engine with its own egress, so
                    // consenting to one or switching it on needs the same authority as
                    // AddRule. switching one off only takes power away, so any client may
                    ClientMessage::GrantPlugin { req, id, caps, egress } => {
                        if !peer.may_manage_rules() {
                            reply(&mut send, req, Reply::Error(NEEDS_ELEVATION.into())).await?;
                        } else {
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
                    }
                    ClientMessage::SetPluginEnabled { req, id, enabled } => {
                        if enabled && !peer.may_manage_rules() {
                            reply(&mut send, req, Reply::Error(NEEDS_ELEVATION.into())).await?;
                        } else {
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
                    // accepting turns it into a firewall rule and needs the same
                    // authority as AddRule
                    ClientMessage::ResolveProposal { req, id, accept } => {
                        let result = if accept && !peer.may_manage_rules() {
                            Reply::Error(NEEDS_ELEVATION.into())
                        } else if accept {
                            let store = store.clone();
                            let rules = rules.clone();
                            tokio::task::spawn_blocking(move || {
                                let settled = store
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .resolve_proposal(id, true);
                                match settled {
                                    Some(proposal) => rules
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .add(proposal.rule)
                                        .map(Reply::RuleAdded)
                                        .unwrap_or_else(|e| Reply::Error(e.to_string())),
                                    None => {
                                        Reply::Error("no pending proposal with that id".into())
                                    }
                                }
                            })
                            .await
                            .unwrap_or_else(|_| Reply::Error("the rule change failed".into()))
                        } else {
                            let store = store.clone();
                            let resolved = tokio::task::spawn_blocking(move || {
                                store
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .resolve_proposal(id, false)
                                    .is_some()
                            })
                            .await
                            .unwrap_or(false);
                            if resolved {
                                Reply::Ok
                            } else {
                                Reply::Error("no pending proposal with that id".into())
                            }
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
                }
            }
            outbound = events.recv() => {
                if !peer_scope_is_active(peer.scope) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "desktop session is no longer active",
                    ));
                }
                match outbound {
                    // ticks only go to subscribers; alerts always go out
                    Ok(msg) => {
                        if let Some(frame) = outbound_frame(feed, msg) {
                            transport::write_frame(&mut send, &frame).await?;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        tracing::debug!(dropped = n, "client fell behind; resending pending decisions");
                        // a decision alert lost in the gap would leave ask mode
                        // denying with no card; clients drop repeats by id
                        let store = store.clone();
                        let pending = tokio::task::spawn_blocking(move || {
                            store.lock().unwrap_or_else(|e| e.into_inner()).list_prompt_alerts()
                        })
                        .await
                        .unwrap_or_default();
                        for alert in pending {
                            transport::write_frame(&mut send, &ServerMessage::Alert(alert)).await?;
                        }
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
                let rules = rules.clone();
                let result = tokio::task::spawn_blocking(move || match rules.lock() {
                    Ok(mut rules) => match rules.add(rule) {
                        Ok(stored) => Reply::RuleAdded(stored),
                        Err(e) => Reply::Error(e.to_string()),
                    },
                    Err(_) => Reply::Error("rule store unavailable".into()),
                })
                .await
                .unwrap_or_else(|_| Reply::Error("the rule change failed".into()));
                reply(&mut send, req, result).await?;
            }
            ClientMessage::RemoveRule { req, id } => {
                let rules = rules.clone();
                let result = tokio::task::spawn_blocking(move || match rules.lock() {
                    Ok(mut rules) => match rules.remove(id) {
                        Ok(true) => Reply::Ok,
                        Ok(false) => Reply::Error("no rule with that id".into()),
                        Err(e) => Reply::Error(e.to_string()),
                    },
                    Err(_) => Reply::Error("rule store unavailable".into()),
                })
                .await
                .unwrap_or_else(|_| Reply::Error("the rule change failed".into()));
                reply(&mut send, req, result).await?;
            }
            ClientMessage::SetRuleEnabled { req, id, enabled } => {
                let rules = rules.clone();
                let result = tokio::task::spawn_blocking(move || match rules.lock() {
                    Ok(mut rules) => match rules.set_enabled(id, enabled) {
                        Ok(Some(_)) => Reply::Ok,
                        Ok(None) => Reply::Error("no rule with that id".into()),
                        Err(e) => Reply::Error(e.to_string()),
                    },
                    Err(_) => Reply::Error("rule store unavailable".into()),
                })
                .await
                .unwrap_or_else(|_| Reply::Error("the rule change failed".into()));
                reply(&mut send, req, result).await?;
            }
            // the elevated half of proposal review: settle it, and on accept
            // enforce the proposed rule through the one path that touches WFP
            ClientMessage::ResolveProposal { req, id, accept } => {
                let rules = rules.clone();
                let store = store.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let settled = store
                        .lock()
                        .map(|s| s.resolve_proposal(id, accept))
                        .unwrap_or(None);
                    match settled {
                        Some(p) if accept => match rules.lock() {
                            Ok(mut rules) => match rules.add(p.rule) {
                                Ok(stored) => Reply::RuleAdded(stored),
                                Err(e) => Reply::Error(e.to_string()),
                            },
                            Err(_) => Reply::Error("rule store unavailable".into()),
                        },
                        Some(_) => Reply::Ok,
                        None => Reply::Error("no pending proposal with that id".into()),
                    }
                })
                .await
                .unwrap_or_else(|_| Reply::Error("the rule change failed".into()));
                reply(&mut send, req, result).await?;
            }
            // the one elevated step that buys the user out of every later
            // prompt: authorize this account to manage rules, or take it back
            ClientMessage::SetRuleGrant { req, granted } => {
                let result = match crate::grant::calling_account()
                    .and_then(|account| crate::grant::set(&account, granted))
                {
                    Ok(()) => {
                        tracing::info!(granted, "delegated rule management grant updated");
                        Reply::Ok
                    }
                    Err(error) => Reply::Error(format!("could not record the grant: {error}")),
                };
                reply(&mut send, req, result).await?;
            }
            ClientMessage::GetRuleGrant { req } => {
                reply(&mut send, req, Reply::RuleGrant(crate::grant::is_granted())).await?;
            }
            ClientMessage::SetFirewallMode { req, mode } => {
                let result = set_mode(&rules, mode).await;
                reply(&mut send, req, result).await?;
            }
            ClientMessage::SetCap { req, app, up_bytes_per_sec, down_bytes_per_sec } => {
                let result = set_cap(&rules, app, up_bytes_per_sec, down_bytes_per_sec).await;
                reply(&mut send, req, result).await?;
            }
            ClientMessage::SetProfiles { req, profiles, manual } => {
                let result = set_profiles(&rules, profiles, manual).await;
                reply(&mut send, req, result).await?;
            }
            ClientMessage::SetQuota { req, app, limit } => {
                let result = set_quota(&rules, app, limit).await;
                reply(&mut send, req, result).await?;
            }
            ClientMessage::GrantPlugin { req, id, caps, egress } => {
                let store = store.clone();
                let ok = tokio::task::spawn_blocking(move || {
                    crate::plugins::supervisor::grant(&store, &id, &caps, &egress, now_ms())
                })
                .await
                .unwrap_or(false);
                let result =
                    if ok { Reply::Ok } else { Reply::Error("no such plugin installed".into()) };
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
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        transport::read_frame::<_, ClientMessage>(recv),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client handshake timed out"))??;
    match first {
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
                tracing::warn!(
                    client = protocol,
                    ours = PROTOCOL_VERSION,
                    "protocol mismatch"
                );
            }
            Ok(protocol == PROTOCOL_VERSION)
        }
        _ => Ok(false),
    }
}

async fn set_mode(rules: &Arc<Mutex<RuleStore>>, mode: iris_core::FirewallMode) -> Reply {
    let rules = rules.clone();
    tokio::task::spawn_blocking(move || {
        match rules
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .set_mode(mode)
        {
            Ok(()) => {
                tracing::info!(mode = mode.as_str(), "firewall mode changed");
                Reply::Ok
            }
            Err(error) => Reply::Error(format!("could not switch firewall mode: {error}")),
        }
    })
    .await
    .unwrap_or_else(|_| Reply::Error("the mode change failed".into()))
}

async fn set_cap(
    rules: &Arc<Mutex<RuleStore>>,
    app: iris_core::AppId,
    up_bytes_per_sec: Option<u64>,
    down_bytes_per_sec: Option<u64>,
) -> Reply {
    let rules = rules.clone();
    tokio::task::spawn_blocking(move || {
        match rules
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .set_cap(app, up_bytes_per_sec, down_bytes_per_sec)
        {
            Ok(()) => Reply::Ok,
            Err(error) => Reply::Error(format!("could not set the cap: {error}")),
        }
    })
    .await
    .unwrap_or_else(|_| Reply::Error("the cap change failed".into()))
}

async fn set_quota(
    rules: &Arc<Mutex<RuleStore>>,
    app: Option<iris_core::AppId>,
    limit: Option<iris_core::QuotaLimit>,
) -> Reply {
    let rules = rules.clone();
    tokio::task::spawn_blocking(move || {
        match rules.lock().unwrap_or_else(|error| error.into_inner()).set_quota(app, limit) {
            Ok(()) => Reply::Ok,
            Err(error) => Reply::Error(format!("could not set the quota: {error}")),
        }
    })
    .await
    .unwrap_or_else(|_| Reply::Error("the quota change failed".into()))
}

async fn set_profiles(
    rules: &Arc<Mutex<RuleStore>>,
    profiles: Vec<iris_core::Profile>,
    manual: Option<String>,
) -> Reply {
    let rules = rules.clone();
    tokio::task::spawn_blocking(move || {
        let mut rules = rules.lock().unwrap_or_else(|error| error.into_inner());
        match rules.set_profiles(profiles, manual) {
            Ok(()) => Reply::Profiles(rules.profile_state()),
            Err(error) => Reply::Error(format!("could not save profiles: {error}")),
        }
    })
    .await
    .unwrap_or_else(|_| Reply::Error("the profile change failed".into()))
}

/// read the rule store off the reactor: a cap or mode change can hold its
/// lock for a powershell round-trip, which must not stall an async worker
async fn read_rules<T: Send + 'static>(rules: &Arc<Mutex<RuleStore>>, read: fn(&RuleStore) -> T) -> Option<T> {
    let rules = rules.clone();
    tokio::task::spawn_blocking(move || read(&rules.lock().unwrap_or_else(|error| error.into_inner())))
        .await
        .ok()
}

fn rules_unavailable() -> Reply {
    Reply::Error("rule store unavailable".into())
}

async fn reply(send: &mut transport::SendHalf, req: u64, result: Reply) -> io::Result<()> {
    transport::write_frame(send, &ServerMessage::Reply { req, result }).await
}

fn req_of(m: &ClientMessage) -> Option<u64> {
    match m {
        ClientMessage::ListRules { req }
        | ClientMessage::ListApps { req }
        | ClientMessage::ForgetApp { req, .. }
        | ClientMessage::ForgetApps { req, .. }
        | ClientMessage::GetRuleGrant { req }
        | ClientMessage::SetRuleGrant { req, .. }
        | ClientMessage::AddRule { req, .. }
        | ClientMessage::GetFirewallMode { req }
        | ClientMessage::GetProfiles { req }
        | ClientMessage::ListCaps { req }
        | ClientMessage::GetHealth { req }
        | ClientMessage::SetCap { req, .. }
        | ClientMessage::ListQuotas { req }
        | ClientMessage::SetQuota { req, .. }
        | ClientMessage::SetProfiles { req, .. }
        | ClientMessage::SetFirewallMode { req, .. }
        | ClientMessage::RemoveRule { req, .. }
        | ClientMessage::SetRuleEnabled { req, .. }
        | ClientMessage::GetUsage { req, .. }
        | ClientMessage::ListAlerts { req, .. }
        | ClientMessage::ListBlocked { req, .. }
        | ClientMessage::ListPromptAlerts { req }
        | ClientMessage::AckAlert { req, .. }
        | ClientMessage::DecideAlert { req, .. }
        | ClientMessage::KillConnection { req, .. }
        | ClientMessage::GetEnrichment { req, .. }
        | ClientMessage::GetAdapterUsage { req, .. }
        | ClientMessage::GetHostUsage { req, .. }
        | ClientMessage::HostAddresses { req, .. }
        | ClientMessage::ListPlugins { req }
        | ClientMessage::GrantPlugin { req, .. }
        | ClientMessage::SetPluginEnabled { req, .. }
        | ClientMessage::ListProposals { req }
        | ClientMessage::ResolveProposal { req, .. }
        | ClientMessage::GetPluginPanel { req, .. }
        | ClientMessage::Ping { req } => Some(*req),
        ClientMessage::Hello { .. }
        | ClientMessage::Subscribe
        | ClientMessage::SubscribeTotals
        | ClientMessage::Unsubscribe => None,
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Feed {
    Off,
    Totals,
    Full,
}

/// the frame a client on `feed` gets for a broadcast message, if any.
/// alerts always go out so a decision is never lost
fn outbound_frame(feed: Feed, msg: ServerMessage) -> Option<ServerMessage> {
    match (feed, msg) {
        (_, msg @ ServerMessage::Alert(_)) => Some(msg),
        (Feed::Off, _) => None,
        (Feed::Totals, ServerMessage::Tick(tick)) => Some(ServerMessage::Totals {
            at_ms: tick.at_ms,
            total_rate_sent: tick.total_rate_sent,
            total_rate_recv: tick.total_rate_recv,
            mode: tick.mode,
        }),
        (_, msg) => Some(msg),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// why a prompt answer cannot stand: it may only narrow to the host the
/// prompt is about, and a lifetime already over would add a rule that is
/// dropped before it ever applies
fn answer_error(
    scope: &RuleScope,
    lifetime: RuleLifetime,
    remote: Option<&Endpoint>,
    now_ms: u64,
) -> Option<&'static str> {
    let own_host = |cidr: iris_core::Cidr| {
        remote.is_some_and(|remote| {
            !remote.addr.is_unspecified()
                && cidr.addr == remote.addr
                && cidr.prefix == if remote.addr.is_ipv4() { 32 } else { 128 }
        })
    };
    if scope.ports.is_some() || scope.protocol.is_some() || !scope.remote.is_none_or(own_host) {
        Some("a prompt answer can only be limited to the connection's own host")
    } else if lifetime.expired(now_ms) {
        Some("that answer has already expired")
    } else {
        None
    }
}

/// settle a prompt once its rule is in force. only a permanent answer for the
/// whole app becomes the app's standing decision, and only the prompts the rule
/// covers are acknowledged, so another host or a later connection asks again
fn settle_answer(store: &Store, pending: &[Alert], id: i64, rule: &Rule) {
    if rule.scope.is_whole_app() && rule.lifetime.is_permanent() {
        store.set_app_decision(&rule.app.0, rule.action);
    }
    for alert in pending {
        let covered = alert.id == id
            || matches!(&alert.kind, AlertKind::NewApp { app, remote: Some(remote), direction: Some(d) }
                if *app == rule.app && *d == rule.direction && rule.scope.matches(remote));
        if covered {
            store.ack_alert(alert.id);
        }
    }
}

fn kill_conn(local_port: u16, remote_addr: &str, remote_port: u16, peer_scope: u32) -> bool {
    #[cfg(has_platform)]
    {
        match remote_addr.parse() {
            Ok(ip) => crate::platform::kill_connection(local_port, ip, remote_port, peer_scope),
            Err(_) => false,
        }
    }
    #[cfg(not(has_platform))]
    {
        let _ = (local_port, remote_addr, remote_port, peer_scope);
        false
    }
}

#[cfg(test)]
mod feed_tests {
    use super::{outbound_frame, Feed};
    use iris_core::{Alert, AlertKind, AppId, Direction, Endpoint, FirewallMode, Protocol, StatsTick};
    use iris_ipc::message::ServerMessage;

    fn tick() -> ServerMessage {
        ServerMessage::Tick(StatsTick {
            at_ms: 5,
            total_rate_sent: 10,
            total_rate_recv: 20,
            apps: Vec::new(),
            adapters: Vec::new(),
            mode: FirewallMode::Notify,
        })
    }

    #[test]
    fn feed_off_drops_ticks_but_keeps_alerts() {
        let alert = ServerMessage::Alert(Alert {
            id: 9,
            at_ms: 42,
            kind: AlertKind::NewApp {
                app: AppId::from_path("/usr/bin/browser"),
                remote: Some(Endpoint {
                    addr: "203.0.113.7".parse().unwrap(),
                    port: 443,
                    protocol: Protocol::Tcp,
                }),
                direction: Some(Direction::Outbound),
            },
            acknowledged: false,
        });
        assert_eq!(outbound_frame(Feed::Off, tick()), None);
        assert_eq!(outbound_frame(Feed::Off, alert.clone()), Some(alert));
    }

    #[test]
    fn feed_totals_reduces_a_tick_to_its_rates() {
        assert_eq!(
            outbound_frame(Feed::Totals, tick()),
            Some(ServerMessage::Totals {
                at_ms: 5,
                total_rate_sent: 10,
                total_rate_recv: 20,
                mode: FirewallMode::Notify,
            })
        );
    }

    #[test]
    fn feed_totals_keeps_other_pushes() {
        let degraded = ServerMessage::CaptureDegraded { degraded: true };
        assert_eq!(outbound_frame(Feed::Totals, degraded.clone()), Some(degraded));
    }

    #[test]
    fn feed_full_passes_the_tick_unchanged() {
        assert_eq!(outbound_frame(Feed::Full, tick()), Some(tick()));
    }
}

#[cfg(test)]
mod answer_tests {
    use super::{answer_error, settle_answer};
    use iris_core::{
        AlertKind, AppId, Cidr, Direction, Endpoint, PortRange, Protocol, Rule, RuleAction,
        RuleLifetime, RuleScope,
    };
    use iris_store::Store;

    fn endpoint(addr: &str) -> Endpoint {
        Endpoint {
            addr: addr.parse().unwrap(),
            port: 443,
            protocol: Protocol::Tcp,
        }
    }

    fn host(cidr: &str) -> RuleScope {
        RuleScope {
            remote: Cidr::parse(cidr),
            ..RuleScope::default()
        }
    }

    #[test]
    fn an_answer_may_narrow_to_the_prompts_own_host() {
        let remote = endpoint("203.0.113.7");
        let v6 = endpoint("2001:db8::7");
        let forever = RuleLifetime::Permanent;
        assert_eq!(answer_error(&RuleScope::default(), forever, Some(&remote), 0), None);
        assert_eq!(answer_error(&host("203.0.113.7"), forever, Some(&remote), 0), None);
        assert_eq!(answer_error(&host("2001:db8::7/128"), forever, Some(&v6), 0), None);
    }

    #[test]
    fn an_answer_may_not_reach_past_the_prompts_host() {
        let remote = endpoint("203.0.113.7");
        let forever = RuleLifetime::Permanent;
        let ports = RuleScope {
            ports: PortRange::parse("443"),
            ..RuleScope::default()
        };
        assert!(answer_error(&host("203.0.113.8"), forever, Some(&remote), 0).is_some());
        assert!(answer_error(&host("203.0.113.0/24"), forever, Some(&remote), 0).is_some());
        assert!(answer_error(&host("203.0.113.7"), forever, None, 0).is_some());
        assert!(answer_error(&ports, forever, Some(&remote), 0).is_some());
        let unspecified = endpoint("0.0.0.0");
        assert!(answer_error(&host("0.0.0.0"), forever, Some(&unspecified), 0).is_some());
    }

    #[test]
    fn an_answer_that_already_ran_out_is_refused() {
        let remote = endpoint("203.0.113.7");
        let scope = RuleScope::default();
        assert!(answer_error(&scope, RuleLifetime::Until { at_ms: 1_000 }, Some(&remote), 1_000).is_some());
        assert_eq!(answer_error(&scope, RuleLifetime::Until { at_ms: 2_000 }, Some(&remote), 1_000), None);
        assert_eq!(answer_error(&scope, RuleLifetime::UntilRestart, Some(&remote), 1_000), None);
    }

    fn prompt(store: &Store, app: &AppId, addr: &str) -> i64 {
        store
            .insert_alert(
                &AlertKind::NewApp {
                    app: app.clone(),
                    remote: Some(endpoint(addr)),
                    direction: Some(Direction::Outbound),
                },
                1,
            )
            .id
    }

    #[test]
    fn a_host_answer_leaves_other_hosts_asking_and_the_app_undecided() {
        let store = Store::open_in_memory().unwrap();
        let app = AppId::from_path("/usr/bin/browser");
        store.ensure_app(&app.0, None, 1);
        let other = prompt(&store, &app, "198.51.100.2");
        let answered = prompt(&store, &app, "203.0.113.7");
        let rule = Rule {
            scope: host("203.0.113.7"),
            ..Rule::new(app.clone(), Direction::Outbound, RuleAction::Allow)
        };
        settle_answer(&store, &store.list_prompt_alerts(), answered, &rule);
        let still: Vec<i64> = store.list_prompt_alerts().iter().map(|alert| alert.id).collect();
        assert_eq!(still, vec![other]);
        assert!(store.trusted_apps().is_empty());
    }

    #[test]
    fn a_timed_answer_does_not_become_the_apps_decision() {
        let store = Store::open_in_memory().unwrap();
        let app = AppId::from_path("/usr/bin/browser");
        store.ensure_app(&app.0, None, 1);
        let first = prompt(&store, &app, "203.0.113.7");
        prompt(&store, &app, "198.51.100.2");
        let rule = Rule {
            lifetime: RuleLifetime::UntilRestart,
            ..Rule::new(app.clone(), Direction::Outbound, RuleAction::Allow)
        };
        settle_answer(&store, &store.list_prompt_alerts(), first, &rule);
        assert!(store.list_prompt_alerts().is_empty());
        assert!(store.trusted_apps().is_empty());
    }

    #[test]
    fn a_permanent_whole_app_answer_is_remembered() {
        let store = Store::open_in_memory().unwrap();
        let app = AppId::from_path("/usr/bin/browser");
        store.ensure_app(&app.0, None, 1);
        let id = prompt(&store, &app, "203.0.113.7");
        let rule = Rule::new(app.clone(), Direction::Outbound, RuleAction::Allow);
        settle_answer(&store, &store.list_prompt_alerts(), id, &rule);
        assert!(store.list_prompt_alerts().is_empty());
        assert_eq!(store.trusted_apps(), vec![app.0]);
    }

    /// the alert a denial to `next` raises once `first` was answered with `rule`
    #[cfg(has_platform)]
    fn prompt_after(rule: &Rule, first: &str, next: &str) -> Option<(i64, iris_core::Alert)> {
        use iris_ipc::message::ServerMessage;
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        let engine = crate::engine::Engine::new();
        let mut events = engine.subscribe();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let mut last_notified = HashMap::new();
        let deny = |addr: &str| crate::platform::PendingConnection {
            app: rule.app.clone(),
            remote: endpoint(addr),
            direction: rule.direction,
        };
        crate::monitor::publish_pending(vec![deny(first)], &store, &engine, &mut last_notified);
        let Ok(ServerMessage::Alert(answered)) = events.try_recv() else {
            panic!("expected the first prompt");
        };
        {
            let store = store.lock().unwrap();
            settle_answer(&store, &store.list_prompt_alerts(), answered.id, rule);
        }
        // a person answers well past the one-second per-app throttle
        last_notified.clear();
        crate::monitor::publish_pending(vec![deny(next)], &store, &engine, &mut last_notified);
        match events.try_recv() {
            Ok(ServerMessage::Alert(alert)) => Some((answered.id, alert)),
            _ => None,
        }
    }

    #[cfg(has_platform)]
    #[test]
    fn a_denial_to_another_host_after_a_host_answer_prompts_again() {
        let rule = Rule {
            scope: host("203.0.113.7"),
            ..Rule::new(AppId::from_path("/usr/bin/browser"), Direction::Outbound, RuleAction::Allow)
        };
        let (answered, alert) = prompt_after(&rule, "203.0.113.7", "198.51.100.2").unwrap();
        assert_ne!(alert.id, answered);
        assert!(matches!(
            alert.kind,
            AlertKind::NewApp { remote: Some(remote), .. } if remote == endpoint("198.51.100.2")
        ));
    }

    #[cfg(has_platform)]
    #[test]
    fn a_denial_once_a_timed_answer_ran_out_prompts_again() {
        let rule = Rule {
            lifetime: RuleLifetime::Until { at_ms: 1 },
            ..Rule::new(AppId::from_path("/usr/bin/browser"), Direction::Outbound, RuleAction::Allow)
        };
        let (answered, alert) = prompt_after(&rule, "203.0.113.7", "203.0.113.7").unwrap();
        assert_ne!(alert.id, answered);
    }
}
