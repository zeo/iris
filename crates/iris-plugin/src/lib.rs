//! the SDK for out-of-process Iris plugins. an author implements [`Plugin`] and
//! calls [`run`] from `main`; the SDK handles the pipe handshake, the message
//! loop, and delivering enrichment and alerts back to the service.
//!
//! a plugin is a normal binary the service spawns under a restricted token. it
//! never holds an Iris handle or a SYSTEM token, and its network reach is pinned
//! by the service to the hosts it declared. everything it emits is stamped with
//! its authenticated id on the service side, so it can only ever speak as
//! itself.
//!
//! [`Plugin`] methods are synchronous on purpose: each plugin owns its process,
//! so a blocking lookup or HTTP call is fine. the SDK runs `enrich` on a
//! blocking task so a slow call never stalls the message loop.

use iris_core::{Alert, Annotation, EnrichTarget, StatsTick};
use iris_ipc::plugin::{
    HostMessage, PluginEvent, PluginMessage, StreamKind, PLUGIN_PROTOCOL_VERSION, TOKEN_ENV,
};
use iris_ipc::transport;
use std::sync::Arc;
use tokio::sync::mpsc;

// so a plugin author depends only on iris-plugin for the whole surface
pub use iris_core::{
    AnnotationValue, AppId, Direction, Panel, Rule, RuleAction, Severity, TargetKind, Widget,
};
pub use iris_ipc::plugin::StreamKind as Stream;

/// what an out-of-process plugin implements. every method has a default, so a
/// plugin overrides only what it needs.
pub trait Plugin: Send + Sync + 'static {
    /// the plugin's stable id, matched against the manifest the service launched
    fn id(&self) -> &str;

    /// annotations for a target the service asked about. runs on a blocking
    /// task, so a synchronous network call here is fine.
    fn enrich(&self, _target: &EnrichTarget) -> Vec<Annotation> {
        Vec::new()
    }

    /// the panel view-model for this plugin's tab, if it declares `ui:panel`.
    /// called on demand when the user opens the tab; runs on a blocking task.
    fn panel(&self) -> Option<Panel> {
        None
    }

    /// a live tick, if the plugin subscribed to `StreamKind::Ticks`
    fn on_tick(&self, _ctx: &PluginCtx, _tick: &StatsTick) {}

    /// a live alert, if the plugin subscribed to `StreamKind::Alerts`
    fn on_alert(&self, _ctx: &PluginCtx, _alert: &Alert) {}
}

/// what a plugin declares it wants at startup. the service intersects this with
/// the user's consent, and rejects the registration if anything requested was
/// never granted.
#[derive(Debug, Clone, Default)]
pub struct Registration {
    pub caps: Vec<String>,
    pub streams: Vec<StreamKind>,
}

/// the handle a plugin uses to push results back to the service, outside the
/// request/response of `enrich`. cloneable and cheap.
#[derive(Clone)]
pub struct PluginCtx {
    tx: mpsc::Sender<PluginMessage>,
}

impl PluginCtx {
    /// push annotations for a target the plugin resolved on its own (e.g. from
    /// watching the tick stream), rather than in response to an EnrichRequest
    pub fn push_enrichment(&self, target: EnrichTarget, annotations: Vec<Annotation>) {
        let _ = self.tx.try_send(PluginMessage::Enrichment { target, annotations });
    }

    /// raise a durable alert. the service stamps the source from this plugin's
    /// authenticated id, so `message` is the only field the plugin controls.
    pub fn raise_alert(&self, message: impl Into<String>) {
        let _ = self.tx.try_send(PluginMessage::RaiseAlert { message: message.into() });
    }

    /// suggest a firewall rule with a human-readable reason. needs the
    /// `emit:rule-proposals` capability. the suggestion only ever reaches the
    /// user's review list; the plugin learns nothing about its fate.
    pub fn propose_rule(&self, rule: iris_core::Rule, reason: impl Into<String>) {
        let _ = self.tx.try_send(PluginMessage::ProposeRule { rule, reason: reason.into() });
    }
}

/// connect to the service, register, and run the message loop until the pipe
/// closes. reads the spawn-time token from the environment.
pub async fn run<P: Plugin>(plugin: P, registration: Registration) -> anyhow::Result<()> {
    let token = std::env::var(TOKEN_ENV)
        .map_err(|_| anyhow::anyhow!("{TOKEN_ENV} not set (plugins are launched by the service)"))?;
    // clear it so it does not linger in the child's environment for anything
    // this process later spawns
    std::env::remove_var(TOKEN_ENV);

    let plugin = Arc::new(plugin);
    let stream = transport::connect_plugins().await?;
    let (mut recv, mut send) = transport::split(stream);

    transport::write_frame(
        &mut send,
        &PluginMessage::Register {
            id: plugin.id().to_string(),
            protocol: PLUGIN_PROTOCOL_VERSION,
            token,
            caps: registration.caps.clone(),
        },
    )
    .await?;

    match transport::read_frame::<_, HostMessage>(&mut recv).await? {
        Some(HostMessage::Registered { engine_version, granted }) => {
            tracing::info!(engine = %engine_version, ?granted, "plugin registered");
        }
        Some(HostMessage::Rejected { reason }) => anyhow::bail!("registration rejected: {reason}"),
        other => anyhow::bail!("expected Registered, got {other:?}"),
    }

    if !registration.streams.is_empty() {
        transport::write_frame(
            &mut send,
            &PluginMessage::Subscribe { streams: registration.streams.clone() },
        )
        .await?;
    }

    // a bounded outbound queue: enrich tasks and stream handlers enqueue here,
    // one writer task drains it, so the pipe has a single writer
    let (tx, mut rx) = mpsc::channel::<PluginMessage>(256);
    let ctx = PluginCtx { tx: tx.clone() };

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if transport::write_frame(&mut send, &msg).await.is_err() {
                break;
            }
        }
    });

    let result = read_loop(&plugin, &ctx, &tx, &mut recv).await;
    drop(tx);
    drop(ctx);
    let _ = writer.await;
    result
}

async fn read_loop<P: Plugin>(
    plugin: &Arc<P>,
    ctx: &PluginCtx,
    tx: &mpsc::Sender<PluginMessage>,
    recv: &mut transport::RecvHalf,
) -> anyhow::Result<()> {
    while let Some(msg) = transport::read_frame::<_, HostMessage>(recv).await? {
        match msg {
            HostMessage::EnrichRequest { req, target } => {
                // run the (possibly blocking) lookup off the loop so pings and
                // further requests are still serviced while it works
                let plugin = plugin.clone();
                let tx = tx.clone();
                tokio::task::spawn_blocking(move || {
                    let annotations = plugin.enrich(&target);
                    let _ = tx.blocking_send(PluginMessage::EnrichReply { req, annotations });
                });
            }
            HostMessage::PanelRequest { req } => {
                let plugin = plugin.clone();
                let tx = tx.clone();
                tokio::task::spawn_blocking(move || {
                    let panel = plugin.panel();
                    let _ = tx.blocking_send(PluginMessage::PanelReply { req, panel });
                });
            }
            HostMessage::Event(PluginEvent::Tick(tick)) => plugin.on_tick(ctx, &tick),
            HostMessage::Event(PluginEvent::Alert(alert)) => plugin.on_alert(ctx, &alert),
            HostMessage::Ping { req } => {
                let _ = tx.send(PluginMessage::Pong { req }).await;
            }
            HostMessage::Registered { .. } | HostMessage::Rejected { .. } => {}
        }
    }
    Ok(())
}
