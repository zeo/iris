use crate::error::EngineResult;
use crate::model::{AppId, Endpoint, LiveConnection, StatsTick};
use crate::rule::Rule;

/// where a running monitor delivers its output. the platform monitor owns the
/// OS event source (ETW on windows) and calls into a sink on every sample tick
/// and every attributed connection. implementations are the service's own
/// aggregator, which forwards ticks to the UI over IPC and connections to the
/// alert path.
pub trait MonitorSink: Send + Sync {
    /// a full per-app throughput sample, emitted about once per second
    fn on_tick(&self, tick: StatsTick);
    /// an application was seen talking to a remote endpoint; drives first-seen
    /// alerting. fired at most once per (app, endpoint) burst by the caller.
    fn on_connection(&self, app: &AppId, remote: &Endpoint);
}

/// per-application network monitoring. the platform layer implements this over
/// the OS's kernel network events; core and the service stay OS-agnostic.
pub trait NetworkMonitor: Send {
    /// begin delivering ticks and connection events to `sink`. returns once the
    /// background source is running; errors if the OS source cannot be opened
    /// (e.g. insufficient privilege).
    fn start(&mut self, sink: std::sync::Arc<dyn MonitorSink>) -> EngineResult<()>;

    /// stop the source and release OS resources. idempotent.
    fn stop(&mut self);

    /// point-in-time list of active connections with their owning app, for the
    /// activity table's connection drill-down
    fn snapshot_connections(&self) -> Vec<LiveConnection>;
}

/// per-application allow/block enforcement. maps a [`Rule`] onto native OS
/// filters and returns an opaque filter id the caller stores for later removal.
pub trait FirewallController: Send {
    /// provision any one-time OS state (provider / sublayer). idempotent.
    fn init(&mut self) -> EngineResult<()>;

    /// enforce `rule`, returning the platform filter id that backs it
    fn apply(&mut self, rule: &Rule) -> EngineResult<u64>;

    /// remove the filter previously returned by [`FirewallController::apply`]
    fn remove(&mut self, filter_id: u64) -> EngineResult<()>;

    /// remove every filter this controller owns (used on uninstall)
    fn clear_all(&mut self) -> EngineResult<()>;
}
