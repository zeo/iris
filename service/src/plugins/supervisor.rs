//! the out-of-process plugin host. at startup it discovers installed plugins,
//! keeps only those the user has consented to and enabled, and runs each one as
//! a restricted low-integrity child. the child connects back on the plugin pipe
//! and authenticates with a spawn-time token; from then on the service forwards
//! enrich requests to it and relays the results, alerts, and (if it subscribed)
//! the live stream, all stamped with the plugin's authenticated identity.

use crate::engine::Engine;
use crate::plugins::manifest::{self, Manifest};
use crate::plugins::proxy::{PluginLink, ProxyRequest};
use iris_core::{AlertKind, Annotation, AnnotationValue, EnrichTarget, Panel, TargetKind};
use iris_ipc::plugin::{
    HostMessage, PluginEvent, PluginMessage, StreamKind, PLUGIN_PROTOCOL_VERSION,
};
use iris_ipc::transport;
use iris_ipc::ServerMessage;
use iris_store::{PluginGrant, Store};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

const PLUGIN_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PENDING_REQUESTS: usize = 64;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn enrich_cap(target: &EnrichTarget) -> &'static str {
    match target {
        EnrichTarget::Endpoint(_) => "enrich:endpoint",
        EnrichTarget::App(_) => "enrich:app",
    }
}

struct OutputRate {
    since: Instant,
    alerts: u32,
    enrichments: u32,
    proposals: u32,
}

impl OutputRate {
    fn new() -> Self {
        Self {
            since: Instant::now(),
            alerts: 0,
            enrichments: 0,
            proposals: 0,
        }
    }

    fn refresh(&mut self) {
        if self.since.elapsed() >= Duration::from_secs(60) {
            self.since = Instant::now();
            self.alerts = 0;
            self.enrichments = 0;
            self.proposals = 0;
        }
    }

    fn allow(counter: &mut u32, limit: u32) -> bool {
        if *counter >= limit {
            return false;
        }
        *counter += 1;
        true
    }

    fn allow_alert(&mut self) -> bool {
        self.refresh();
        Self::allow(&mut self.alerts, 60)
    }

    fn allow_enrichment(&mut self) -> bool {
        self.refresh();
        Self::allow(&mut self.enrichments, 120)
    }

    fn allow_proposal(&mut self) -> bool {
        self.refresh();
        Self::allow(&mut self.proposals, 60)
    }
}

fn bounded_annotations(annotations: Vec<Annotation>) -> Vec<Annotation> {
    let mut kept = Vec::new();
    let mut bytes = 0usize;
    for annotation in annotations {
        let value_bytes = match &annotation.value {
            AnnotationValue::Text(value) | AnnotationValue::Badge(value) => value.len(),
            AnnotationValue::Link { label, url } => label.len() + url.len(),
        };
        let annotation_bytes = annotation.key.len() + annotation.label.len() + value_bytes;
        if annotation.key.len() <= 128
            && annotation.label.len() <= 256
            && value_bytes <= 4096
            && bytes + annotation_bytes <= 32 * 1024
        {
            bytes += annotation_bytes;
            kept.push(annotation);
            if kept.len() == 64 {
                break;
            }
        }
    }
    kept
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
    alerts_emitted: AtomicU32,
    #[cfg(has_platform)]
    child: Mutex<Option<crate::platform::RestrictedChild>>,
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

    /// whether the user consented to this plugin showing a panel tab
    pub fn panel_granted(&self) -> bool {
        self.effective_caps().iter().any(|c| c == "ui:panel")
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

    #[cfg(has_platform)]
    fn spawn(&self) {
        let exe = self.manifest.entry_path(&self.dir);
        let env = vec![(iris_ipc::plugin::TOKEN_ENV.to_string(), self.token.clone())];
        match crate::platform::spawn_restricted(&exe, &env) {
            Ok(child) => {
                tracing::info!(plugin = %self.id, "plugin started");
                *self.child.lock().unwrap_or_else(|e| e.into_inner()) = Some(child);
            }
            Err(e) => tracing::error!(plugin = %self.id, "could not start plugin: {e}"),
        }
    }

    #[cfg(has_platform)]
    fn is_alive(&self) -> bool {
        // as_mut: the Linux child checks liveness via try_wait, which reaps and
        // needs a mutable borrow; the Windows handle is fine through it too
        self.child
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
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
pub fn grant(
    store: &Arc<Mutex<Store>>,
    id: &str,
    caps: &[String],
    egress: &[String],
    at_ms: u64,
) -> bool {
    let Some((_, manifest)) = manifest::discover().into_iter().find(|(_, m)| m.id == id) else {
        return false;
    };
    let caps: Vec<String> = caps
        .iter()
        .filter(|c| manifest.declares(c))
        .cloned()
        .collect();
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
fn target_kinds(manifest: &Manifest, grant: &PluginGrant) -> Vec<TargetKind> {
    let mut kinds = Vec::new();
    if manifest.declares("enrich:endpoint") && grant.caps.iter().any(|cap| cap == "enrich:endpoint")
    {
        kinds.push(TargetKind::Endpoint);
    }
    if manifest.declares("enrich:app") && grant.caps.iter().any(|cap| cap == "enrich:app") {
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
        let link = Arc::new(PluginLink::new(
            manifest.id.clone(),
            target_kinds(&manifest, &grant),
        ));
        #[cfg(has_platform)]
        let token = crate::platform::random_token();
        #[cfg(not(has_platform))]
        let token = String::new();
        runtimes.push(Arc::new(PluginRuntime {
            id: manifest.id.clone(),
            manifest,
            grant,
            dir,
            link,
            token,
            alerts_emitted: AtomicU32::new(0),
            #[cfg(has_platform)]
            child: Mutex::new(None),
        }));
    }
    runtimes
}

/// an outstanding request to a plugin, keyed by wire id in the actor
enum Pending {
    Enrich {
        reply: std::sync::mpsc::Sender<Vec<Annotation>>,
        since: Instant,
    },
    Panel {
        reply: std::sync::mpsc::Sender<Option<Panel>>,
        since: Instant,
    },
}

impl Pending {
    fn expired(&self) -> bool {
        let since = match self {
            Self::Enrich { since, .. } | Self::Panel { since, .. } => since,
        };
        since.elapsed() >= PLUGIN_IO_TIMEOUT
    }
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
        Supervisor {
            runtimes,
            store,
            engine,
        }
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
        // never runs at all. the pinner owns the network filters (a dynamic WFP
        // session on Windows, the plugin nftables table on Linux), so it must
        // outlive the launch tasks: bind it here so it lives for the whole serve
        // loop rather than being dropped after launch, which would tear the pins
        // down (and reopen the plugin's network) the moment spawning finished.
        #[cfg(has_platform)]
        let _pinner = match crate::plugins::egress::Pinner::open() {
            Ok(pinner) => {
                let pinner = Arc::new(pinner);
                for rt in &this.runtimes {
                    this.clone().launch(pinner.clone(), rt.clone());
                }
                Some(pinner)
            }
            Err(e) => {
                tracing::error!("cannot pin plugin networking, plugins stay stopped: {e}");
                None
            }
        };

        let listener = transport::listen_plugins()?;
        // on Linux the sandboxed plugin child connects as the iris-plugin user;
        // group-own the socket so only that account can reach it (the Windows
        // side enforces the same via the pipe SDDL)
        #[cfg(target_os = "linux")]
        crate::paths::grant_plugin_socket(iris_ipc::PLUGIN_PIPE_NAME)?;
        tracing::info!(pipe = iris_ipc::PLUGIN_PIPE_NAME, "plugin host listening");
        let slots = Arc::new(tokio::sync::Semaphore::new(64));
        loop {
            let conn = match transport::accept(&listener).await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!("plugin accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let permit = match Arc::clone(&slots).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::warn!("plugin connection limit reached");
                    continue;
                }
            };
            let this = this.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = this.handle(conn).await {
                    tracing::debug!("plugin connection ended: {e}");
                }
            });
        }
    }

    /// pin the plugin's binary to its granted egress, then start it and keep it
    /// alive. named hosts re-resolve on a slow cadence so a rotated record does
    /// not strand the child, while the pin never widens past the grant.
    #[cfg(has_platform)]
    fn launch(
        self: Arc<Self>,
        pinner: Arc<crate::plugins::egress::Pinner>,
        rt: Arc<PluginRuntime>,
    ) {
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
    #[cfg(has_platform)]
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
                rt.link.detach_current();
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
        const MAX_PLUGIN_FRAME: u32 = 1024 * 1024;
        let first = tokio::time::timeout(
            Duration::from_secs(5),
            transport::read_frame_limited::<_, PluginMessage>(&mut recv, MAX_PLUGIN_FRAME),
        )
        .await
        .map_err(|_| anyhow::anyhow!("plugin registration timed out"))??;
        let (rt, granted) = match first {
            Some(PluginMessage::Register {
                id,
                protocol,
                token,
                caps,
            }) => match self.authenticate(&id, protocol, &token, &caps) {
                Ok(rt) => rt,
                Err(reason) => {
                    tracing::warn!(plugin = %id, "plugin registration rejected: {reason}");
                    let _ = tokio::time::timeout(
                        PLUGIN_IO_TIMEOUT,
                        transport::write_frame(&mut send, &HostMessage::Rejected { reason }),
                    )
                    .await;
                    return Ok(());
                }
            },
            _ => return Ok(()),
        };

        let (req_tx, req_rx) = mpsc::channel::<ProxyRequest>(MAX_PENDING_REQUESTS);
        let Some(session) = rt.link.attach(req_tx) else {
            let reason = "plugin is already connected".to_string();
            let _ = tokio::time::timeout(
                PLUGIN_IO_TIMEOUT,
                transport::write_frame(&mut send, &HostMessage::Rejected { reason }),
            )
            .await;
            return Ok(());
        };
        let registered = tokio::time::timeout(
            PLUGIN_IO_TIMEOUT,
            transport::write_frame(
                &mut send,
                &HostMessage::Registered {
                    granted: granted.clone(),
                    engine_version: env!("CARGO_PKG_VERSION").to_string(),
                },
            ),
        )
        .await;
        match registered {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                rt.link.detach(session);
                return Err(error.into());
            }
            Err(_) => {
                rt.link.detach(session);
                return Err(anyhow::anyhow!("plugin registration write timed out"));
            }
        }

        let result = self.actor(&rt, &granted, req_rx, recv, send).await;
        rt.link.detach(session);
        result
    }

    /// validate a registration against the launched manifest and the grant
    fn authenticate(
        &self,
        id: &str,
        protocol: u32,
        token: &str,
        caps: &[String],
    ) -> Result<(Arc<PluginRuntime>, Vec<String>), String> {
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
        let mut negotiated = Vec::new();
        for cap in caps {
            if !granted.contains(cap) {
                return Err(format!("capability not granted: {cap}"));
            }
            if !negotiated.contains(cap) {
                negotiated.push(cap.clone());
            }
        }
        Ok((rt, negotiated))
    }

    /// the per-connection message loop: forward enrich and panel requests to
    /// the plugin, relay its replies, alerts, and enrichment, and push the
    /// subscribed streams
    async fn actor(
        &self,
        rt: &Arc<PluginRuntime>,
        granted: &[String],
        mut req_rx: mpsc::Receiver<ProxyRequest>,
        mut recv: transport::RecvHalf,
        mut send: transport::SendHalf,
    ) -> anyhow::Result<()> {
        let mut events = self.engine.subscribe();
        let mut streams: Vec<StreamKind> = Vec::new();
        let mut next_req: u64 = 1;
        let mut pending: HashMap<u64, Pending> = HashMap::new();
        let mut output_rate = OutputRate::new();
        let mut reap_pending = tokio::time::interval(Duration::from_secs(1));
        reap_pending.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            select! {
                request = req_rx.recv() => {
                    let Some(request) = request else { break };
                    if pending.len() >= MAX_PENDING_REQUESTS {
                        continue;
                    }
                    let req = next_req;
                    next_req += 1;
                    let frame = match request {
                        ProxyRequest::Enrich { target, reply } => {
                            if !granted.iter().any(|cap| cap == enrich_cap(&target)) {
                                continue;
                            }
                            pending.insert(req, Pending::Enrich {
                                reply,
                                since: Instant::now(),
                            });
                            HostMessage::EnrichRequest { req, target }
                        }
                        ProxyRequest::Panel { reply } => {
                            if !granted.iter().any(|cap| cap == "ui:panel") {
                                continue;
                            }
                            pending.insert(req, Pending::Panel {
                                reply,
                                since: Instant::now(),
                            });
                            HostMessage::PanelRequest { req }
                        }
                    };
                    tokio::time::timeout(
                        PLUGIN_IO_TIMEOUT,
                        transport::write_frame(&mut send, &frame),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("plugin request write timed out"))??;
                }
                frame = transport::read_frame_limited::<_, PluginMessage>(&mut recv, 1024 * 1024) => {
                    let Some(msg) = frame? else { break };
                    self.on_plugin_message(
                        rt,
                        granted,
                        msg,
                        &mut streams,
                        &mut pending,
                        &mut output_rate,
                    ).await?;
                }
                event = events.recv() => {
                    match event {
                        Ok(msg) => self.forward_event(&mut send, &streams, msg).await?,
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => break,
                    }
                }
                _ = reap_pending.tick() => {
                    pending.retain(|_, request| !request.expired());
                }
            }
        }
        Ok(())
    }

    async fn on_plugin_message(
        &self,
        rt: &Arc<PluginRuntime>,
        granted: &[String],
        msg: PluginMessage,
        streams: &mut Vec<StreamKind>,
        pending: &mut HashMap<u64, Pending>,
        output_rate: &mut OutputRate,
    ) -> anyhow::Result<()> {
        match msg {
            PluginMessage::EnrichReply { req, annotations } => {
                if let Some(Pending::Enrich { reply, .. }) = pending.remove(&req) {
                    let _ = reply.send(bounded_annotations(annotations));
                }
            }
            PluginMessage::PanelReply { req, panel } => {
                if let Some(Pending::Panel { reply, .. }) = pending.remove(&req) {
                    let _ = reply.send(panel);
                }
            }
            PluginMessage::Enrichment {
                target,
                annotations,
            } => {
                // an unsolicited push from a stream-watching plugin; surface it
                // to the UI the same way a resolved lookup would
                let annotations = bounded_annotations(annotations);
                if granted.iter().any(|cap| cap == enrich_cap(&target))
                    && !annotations.is_empty()
                    && output_rate.allow_enrichment()
                {
                    self.engine.publish(ServerMessage::Enrichment {
                        target,
                        annotations,
                    });
                }
            }
            PluginMessage::RaiseAlert { message } => {
                if granted.iter().any(|cap| cap == "emit:alerts")
                    && message.len() <= 4096
                    && output_rate.allow_alert()
                    && rt.alerts_emitted.fetch_add(1, Ordering::Relaxed) < 1000
                {
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
                if reason.len() <= 4096
                    && output_rate.allow_proposal()
                    && granted.iter().any(|cap| cap == "emit:rule-proposals")
                {
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
                streams.clear();
                for s in requested {
                    let cap = match s {
                        StreamKind::Ticks => "observe:ticks",
                        StreamKind::Alerts => "observe:alerts",
                    };
                    if granted.iter().any(|granted| granted == cap) {
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
            tokio::time::timeout(
                PLUGIN_IO_TIMEOUT,
                transport::write_frame(send, &HostMessage::Event(event)),
            )
            .await
            .map_err(|_| anyhow::anyhow!("plugin event write timed out"))??;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{bounded_annotations, target_kinds, OutputRate};
    use crate::plugins::manifest::Manifest;
    use iris_core::{Annotation, Severity, TargetKind};
    use iris_store::PluginGrant;

    #[test]
    fn bounds_plugin_annotations() {
        let mut annotations = vec![Annotation::text("x", "label", "ok", Severity::Info)];
        annotations.push(Annotation::text(
            "x".repeat(129).as_str(),
            "label",
            "rejected",
            Severity::Info,
        ));
        annotations.extend((0..130).map(|index| {
            Annotation::text(&format!("key-{index}"), "label", "value", Severity::Info)
        }));

        let bounded = bounded_annotations(annotations);
        assert_eq!(bounded.len(), 64);
        assert_eq!(bounded[0].key, "x");
    }

    #[test]
    fn rate_limits_plugin_alerts() {
        let mut rate = OutputRate::new();
        assert!((0..60).all(|_| rate.allow_alert()));
        assert!(!rate.allow_alert());
    }

    #[test]
    fn proxy_targets_stay_inside_the_user_grant() {
        let manifest = Manifest {
            id: "test".into(),
            name: "Test".into(),
            version: "1".into(),
            description: String::new(),
            entry: "test.exe".into(),
            capabilities: vec!["enrich:endpoint".into(), "enrich:app".into()],
            egress: Vec::new(),
        };
        let grant = PluginGrant {
            id: "test".into(),
            caps: vec!["enrich:endpoint".into()],
            egress: Vec::new(),
            enabled: true,
            granted_at: 0,
        };

        assert_eq!(target_kinds(&manifest, &grant), vec![TargetKind::Endpoint]);
    }
}
