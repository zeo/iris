//! the out-of-process plugin host. at startup it discovers installed plugins,
//! keeps only those the user has consented to and enabled, and runs each one as
//! a restricted low-integrity child. the child connects back on the plugin pipe
//! and authenticates with a spawn-time token; from then on the service forwards
//! enrich requests to it and relays the results, alerts, and (if it subscribed)
//! the live stream, all stamped with the plugin's authenticated identity.

use crate::engine::Engine;
use crate::plugins::manifest::{self, Manifest};
use crate::plugins::proxy::{PluginLink, ProxyRequest};
use iris_core::{AlertKind, Annotation, TargetKind};
use iris_ipc::plugin::{
    HostMessage, PluginEvent, PluginMessage, StreamKind, PLUGIN_PROTOCOL_VERSION,
};
use iris_ipc::transport;
use iris_ipc::ServerMessage;
use iris_store::{PluginGrant, Store};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// one consented, enabled plugin: its manifest, the user's grant, the proxy link
/// the registry enriches through, and its spawn-time auth token.
pub struct PluginRuntime {
    pub id: String,
    pub manifest: Manifest,
    pub grant: PluginGrant,
    pub dir: PathBuf,
    pub link: Arc<PluginLink>,
    token: String,
    #[cfg(windows)]
    child: Mutex<Option<iris_platform_win::RestrictedChild>>,
}

impl PluginRuntime {
    fn effective_caps(&self) -> Vec<String> {
        // the grant is the user-approved subset; never exceed the manifest
        self.grant
            .caps
            .iter()
            .filter(|c| self.manifest.declares(c))
            .cloned()
            .collect()
    }

    /// the egress the child is actually pinned to: the user's consent, never
    /// wider than what the manifest declares
    pub fn effective_egress(&self) -> Vec<String> {
        self.grant
            .egress
            .iter()
            .filter(|e| self.manifest.egress.iter().any(|d| d == *e))
            .cloned()
            .collect()
    }

    #[cfg(windows)]
    fn spawn(&self) {
        let exe = self.manifest.entry_path(&self.dir);
        let env = vec![(iris_ipc::plugin::TOKEN_ENV.to_string(), self.token.clone())];
        match iris_platform_win::spawn_restricted(&exe, &env) {
            Ok(child) => {
                tracing::info!(plugin = %self.id, "plugin started");
                *self.child.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
            }
            Err(e) => tracing::error!(plugin = %self.id, "could not start plugin: {e}"),
        }
    }

    #[cfg(windows)]
    fn is_alive(&self) -> bool {
        self.child
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|c| c.is_alive())
            .unwrap_or(false)
    }
}

/// enumerate every installed plugin joined with its consent state, for the
/// management UI. re-reads the manifests from disk, so a newly-installed plugin
/// shows up without a service restart.
pub fn catalog(store: &Arc<Mutex<Store>>) -> Vec<iris_ipc::message::PluginInfo> {
    manifest::discover()
        .into_iter()
        .map(|(_, m)| {
            let grant = store
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .plugin_grant(&m.id);
            iris_ipc::message::PluginInfo {
                id: m.id,
                name: m.name,
                version: m.version,
                description: m.description,
                capabilities: m.capabilities,
                egress: m.egress,
                granted: grant.is_some(),
                enabled: grant.map(|g| g.enabled).unwrap_or(false),
            }
        })
        .collect()
}

/// record the user's consent for a plugin, clamped to what its manifest
/// actually declares so a stale or crafted grant can never exceed the ceiling.
/// returns whether a matching installed plugin was found.
pub fn grant(store: &Arc<Mutex<Store>>, id: &str, caps: &[String], egress: &[String], at_ms: u64) -> bool {
    let Some((_, manifest)) = manifest::discover().into_iter().find(|(_, m)| m.id == id) else {
        return false;
    };
    let caps: Vec<String> = caps.iter().filter(|c| manifest.declares(c)).cloned().collect();
    let egress: Vec<String> = egress
        .iter()
        .filter(|e| manifest.egress.iter().any(|d| d == *e))
        .cloned()
        .collect();
    store
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .set_plugin_grant(id, &caps, &egress, true, at_ms);
    true
}

/// switch a granted plugin on or off; false when it was never granted
pub fn set_enabled(store: &Arc<Mutex<Store>>, id: &str, enabled: bool) -> bool {
    store
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .set_plugin_enabled(id, enabled)
}

/// maps a manifest's enrich capabilities to the target kinds the proxy declares
fn target_kinds(manifest: &Manifest) -> Vec<TargetKind> {
    let mut kinds = Vec::new();
    if manifest.declares("enrich:endpoint") {
        kinds.push(TargetKind::Endpoint);
    }
    if manifest.declares("enrich:app") {
        kinds.push(TargetKind::App);
    }
    kinds
}

/// build a runtime for every installed, consented, enabled plugin and hand back
/// the proxy links to register in the enrichment registry
pub fn plan(store: &Arc<Mutex<Store>>) -> Vec<Arc<PluginRuntime>> {
    let mut runtimes = Vec::new();
    for (dir, manifest) in manifest::discover() {
        let grant = {
            let s = store.lock().unwrap_or_else(|e| e.into_inner());
            s.plugin_grant(&manifest.id)
        };
        let grant = match grant {
            Some(g) if g.enabled => g,
            _ => {
                tracing::info!(plugin = %manifest.id, "installed but not enabled, skipping");
                continue;
            }
        };
        let link = Arc::new(PluginLink::new(manifest.id.clone(), target_kinds(&manifest)));
        #[cfg(windows)]
        let token = iris_platform_win::random_token();
        #[cfg(not(windows))]
        let token = String::new();
        runtimes.push(Arc::new(PluginRuntime {
            id: manifest.id.clone(),
            manifest,
            grant,
            dir,
            link,
            token,
            #[cfg(windows)]
            child: Mutex::new(None),
        }));
    }
    runtimes
}

/// the running host: owns the runtimes and serves the plugin pipe
pub struct Supervisor {
    runtimes: Vec<Arc<PluginRuntime>>,
    store: Arc<Mutex<Store>>,
    engine: Engine,
}

impl Supervisor {
    pub fn new(
        runtimes: Vec<Arc<PluginRuntime>>,
        store: Arc<Mutex<Store>>,
        engine: Engine,
    ) -> Self {
        Supervisor { runtimes, store, engine }
    }

    /// spawn every plugin child and accept their connections until shutdown. a
    /// no-op idle when nothing is installed, so the pipe never exists on a stock
    /// install with no plugins.
    pub async fn serve(self) -> anyhow::Result<()> {
        if self.runtimes.is_empty() {
            std::future::pending::<()>().await;
            return Ok(());
        }

        let this = Arc::new(self);

        // fail closed: a child that cannot be pinned to its granted egress
        // never runs at all
        #[cfg(windows)]
        match crate::plugins::egress::Pinner::open() {
            Ok(pinner) => {
                let pinner = Arc::new(pinner);
                for rt in &this.runtimes {
                    this.clone().launch(pinner.clone(), rt.clone());
                }
            }
            Err(e) => tracing::error!("cannot pin plugin networking, plugins stay stopped: {e}"),
        }

        let listener = transport::listen_plugins()?;
        tracing::info!(pipe = iris_ipc::PLUGIN_PIPE_NAME, "plugin host listening");
        loop {
            let conn = match transport::accept(&listener).await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!("plugin accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let this = this.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle(conn).await {
                    tracing::debug!("plugin connection ended: {e}");
                }
            });
        }
    }

    /// pin the plugin's binary to its granted egress, then start it and keep it
    /// alive. named hosts re-resolve on a slow cadence so a rotated record does
    /// not strand the child, while the pin never widens past the grant.
    #[cfg(windows)]
    fn launch(self: Arc<Self>, pinner: Arc<crate::plugins::egress::Pinner>, rt: Arc<PluginRuntime>) {
        tokio::spawn(async move {
            let pinned = {
                let pinner = pinner.clone();
                let rt = rt.clone();
                tokio::task::spawn_blocking(move || pinner.pin(&rt)).await
            };
            let mut state = match pinned {
                Ok(Ok(state)) => state,
                Ok(Err(e)) => {
                    tracing::error!(plugin = %rt.id, "egress pin failed, plugin not started: {e}");
                    return;
                }
                Err(e) => {
                    tracing::error!(plugin = %rt.id, "egress pin task died: {e}");
                    return;
                }
            };
            rt.spawn();
            self.watch(rt.clone());

            if !state.needs_refresh() {
                return;
            }
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                let pinner = pinner.clone();
                let Ok((returned, outcome)) = tokio::task::spawn_blocking(move || {
                    let mut state = state;
                    let outcome = pinner.refresh(&mut state);
                    (state, outcome)
                })
                .await
                else {
                    return;
                };
                state = returned;
                match outcome {
                    Ok(true) => tracing::info!(plugin = %rt.id, "egress endpoints re-resolved"),
                    Ok(false) => {}
                    Err(e) => tracing::warn!(plugin = %rt.id, "egress refresh failed: {e}"),
                }
            }
        });
    }

    /// restart a plugin that dies, with a backoff, and quarantine it after too
    /// many quick failures so a crash-looping plugin cannot burn the machine
    #[cfg(windows)]
    fn watch(self: Arc<Self>, rt: Arc<PluginRuntime>) {
        tokio::spawn(async move {
            const MAX_QUICK_FAILURES: u32 = 5;
            const HEALTHY_MS: u64 = 60_000;
            let mut failures = 0u32;
            let mut last_start = now_ms();
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if rt.is_alive() {
                    if now_ms().saturating_sub(last_start) > HEALTHY_MS {
                        failures = 0;
                    }
                    continue;
                }
                rt.link.detach();
                failures += 1;
                if failures > MAX_QUICK_FAILURES {
                    tracing::error!(plugin = %rt.id, "quarantined after repeated crashes");
                    return;
                }
                let backoff = Duration::from_secs(2u64.pow(failures.min(5)));
                tracing::warn!(plugin = %rt.id, "plugin exited, restarting after {backoff:?}");
                tokio::time::sleep(backoff).await;
                last_start = now_ms();
                rt.spawn();
            }
        });
    }

    async fn handle(&self, stream: transport::Stream) -> anyhow::Result<()> {
        let (mut recv, mut send) = transport::split(stream);

        // the first frame must authenticate; anything else drops the pipe
        let rt = match transport::read_frame::<_, PluginMessage>(&mut recv).await? {
            Some(PluginMessage::Register { id, protocol, token, caps }) => {
                match self.authenticate(&id, protocol, &token, &caps) {
                    Ok(rt) => rt,
                    Err(reason) => {
                        tracing::warn!(plugin = %id, "plugin registration rejected: {reason}");
                        let _ = transport::write_frame(&mut send, &HostMessage::Rejected { reason }).await;
                        return Ok(());
                    }
                }
            }
            _ => return Ok(()),
        };

        transport::write_frame(
            &mut send,
            &HostMessage::Registered {
                granted: rt.effective_caps(),
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
            },
        )
        .await?;

        let result = self.actor(&rt, recv, send).await;
        rt.link.detach();
        result
    }

    /// validate a registration against the launched manifest and the grant
    fn authenticate(
        &self,
        id: &str,
        protocol: u32,
        token: &str,
        caps: &[String],
    ) -> Result<Arc<PluginRuntime>, String> {
        let rt = self
            .runtimes
            .iter()
            .find(|r| r.id == id)
            .cloned()
            .ok_or_else(|| "unknown plugin".to_string())?;
        if protocol != PLUGIN_PROTOCOL_VERSION {
            return Err(format!(
                "protocol mismatch: plugin {protocol}, host {PLUGIN_PROTOCOL_VERSION}"
            ));
        }
        // reject an empty token outright so a spawn whose RNG failed cannot be
        // impersonated by a guessed empty string
        if rt.token.is_empty() || token != rt.token {
            return Err("bad token".to_string());
        }
        let granted = rt.effective_caps();
        for cap in caps {
            if !granted.contains(cap) {
                return Err(format!("capability not granted: {cap}"));
            }
        }
        Ok(rt)
    }

    /// the per-connection message loop: forward enrich requests to the plugin,
    /// relay its replies, alerts, and enrichment, and push the subscribed streams
    async fn actor(
        &self,
        rt: &Arc<PluginRuntime>,
        mut recv: transport::RecvHalf,
        mut send: transport::SendHalf,
    ) -> anyhow::Result<()> {
        let (req_tx, mut req_rx) = mpsc::channel::<ProxyRequest>(64);
        rt.link.attach(req_tx);

        let mut events = self.engine.subscribe();
        let mut streams: Vec<StreamKind> = Vec::new();
        let mut next_req: u64 = 1;
        let mut pending: HashMap<u64, std::sync::mpsc::Sender<Vec<Annotation>>> = HashMap::new();

        loop {
            select! {
                request = req_rx.recv() => {
                    let Some(request) = request else { break };
                    let req = next_req;
                    next_req += 1;
                    pending.insert(req, request.reply);
                    transport::write_frame(&mut send, &HostMessage::EnrichRequest { req, target: request.target }).await?;
                }
                frame = transport::read_frame::<_, PluginMessage>(&mut recv) => {
                    let Some(msg) = frame? else { break };
                    self.on_plugin_message(rt, msg, &mut streams, &mut pending).await?;
                }
                event = events.recv() => {
                    match event {
                        Ok(msg) => self.forward_event(&mut send, &streams, msg).await?,
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => break,
                    }
                }
            }
        }
        Ok(())
    }

    async fn on_plugin_message(
        &self,
        rt: &Arc<PluginRuntime>,
        msg: PluginMessage,
        streams: &mut Vec<StreamKind>,
        pending: &mut HashMap<u64, std::sync::mpsc::Sender<Vec<Annotation>>>,
    ) -> anyhow::Result<()> {
        match msg {
            PluginMessage::EnrichReply { req, annotations } => {
                if let Some(reply) = pending.remove(&req) {
                    let _ = reply.send(annotations);
                }
            }
            PluginMessage::Enrichment { target, annotations } => {
                // an unsolicited push from a stream-watching plugin; surface it
                // to the UI the same way a resolved lookup would
                if !annotations.is_empty() {
                    self.engine.publish(ServerMessage::Enrichment { target, annotations });
                }
            }
            PluginMessage::RaiseAlert { message } => {
                if rt.effective_caps().iter().any(|c| c == "emit:alerts") {
                    // the source is the authenticated plugin name, never trusted
                    // from the wire
                    let kind = AlertKind::Plugin {
                        source: rt.manifest.name.clone(),
                        message,
                    };
                    let alert = self
                        .store
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert_alert(&kind, now_ms());
                    self.engine.publish(ServerMessage::Alert(alert));
                }
            }
            PluginMessage::ProposeRule { rule, reason } => {
                if rt.effective_caps().iter().any(|c| c == "emit:rule-proposals") {
                    // recorded for review only; enforcement stays behind the
                    // elevated accept on the admin pipe
                    let proposal = self
                        .store
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert_proposal(&rt.manifest.name, &rule, &reason, now_ms());
                    if let Some(proposal) = proposal {
                        self.engine.publish(ServerMessage::Proposal(proposal));
                    }
                }
            }
            PluginMessage::Subscribe { streams: requested } => {
                let granted = rt.effective_caps();
                streams.clear();
                for s in requested {
                    let cap = match s {
                        StreamKind::Ticks => "observe:ticks",
                        StreamKind::Alerts => "observe:alerts",
                    };
                    if granted.iter().any(|c| c == cap) {
                        streams.push(s);
                    }
                }
            }
            PluginMessage::Pong { .. } | PluginMessage::Register { .. } => {}
        }
        Ok(())
    }

    async fn forward_event(
        &self,
        send: &mut transport::SendHalf,
        streams: &[StreamKind],
        msg: ServerMessage,
    ) -> anyhow::Result<()> {
        let event = match msg {
            ServerMessage::Tick(t) if streams.contains(&StreamKind::Ticks) => {
                Some(PluginEvent::Tick(t))
            }
            ServerMessage::Alert(a) if streams.contains(&StreamKind::Alerts) => {
                Some(PluginEvent::Alert(a))
            }
            _ => None,
        };
        if let Some(event) = event {
            transport::write_frame(send, &HostMessage::Event(event)).await?;
        }
        Ok(())
    }
}
