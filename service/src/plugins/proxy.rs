//! the bridge that lets an out-of-process plugin present as a first-party
//! [`Enricher`]. the registry calls [`OutOfProcEnricher::enrich`] synchronously
//! off the hot path; the proxy forwards the request to the plugin's connection
//! actor over a channel and blocks (with a timeout) for the reply. when no
//! plugin is connected the call returns empty at once, so a stopped or crashed
//! plugin never stalls enrichment.

use iris_core::{Annotation, EnrichTarget, Enricher, TargetKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::mpsc;

/// how long the registry waits for a plugin to answer one enrich request
const ENRICH_TIMEOUT: Duration = Duration::from_secs(5);

/// one enrich request handed from the proxy to the active connection actor,
/// carrying a std channel the actor answers on
pub struct ProxyRequest {
    pub target: EnrichTarget,
    pub reply: std::sync::mpsc::Sender<Vec<Annotation>>,
}

/// shared between the proxy (in the registry) and the supervisor's per-plugin
/// connection actor. the actor swaps the sender in on connect and clears it on
/// disconnect, so the proxy always routes to the live connection or nobody.
pub struct PluginLink {
    id: String,
    targets: Vec<TargetKind>,
    connected: AtomicBool,
    sender: Mutex<Option<mpsc::Sender<ProxyRequest>>>,
}

impl PluginLink {
    pub fn new(id: String, targets: Vec<TargetKind>) -> Self {
        PluginLink {
            id,
            targets,
            connected: AtomicBool::new(false),
            sender: Mutex::new(None),
        }
    }

    /// bind the proxy to a freshly-connected plugin's request channel
    pub fn attach(&self, sender: mpsc::Sender<ProxyRequest>) {
        *self.sender.lock().unwrap_or_else(|e| e.into_inner()) = Some(sender);
        self.connected.store(true, Ordering::Release);
    }

    /// detach on disconnect, so further enrich calls return empty immediately
    pub fn detach(&self) {
        self.connected.store(false, Ordering::Release);
        *self.sender.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    fn sender(&self) -> Option<mpsc::Sender<ProxyRequest>> {
        self.sender.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// the registry-facing enricher that forwards to a plugin over [`PluginLink`]
pub struct OutOfProcEnricher {
    link: std::sync::Arc<PluginLink>,
}

impl OutOfProcEnricher {
    pub fn new(link: std::sync::Arc<PluginLink>) -> Self {
        OutOfProcEnricher { link }
    }
}

impl Enricher for OutOfProcEnricher {
    fn id(&self) -> &str {
        &self.link.id
    }

    fn targets(&self) -> &[TargetKind] {
        &self.link.targets
    }

    fn enrich(&self, target: &EnrichTarget) -> Vec<Annotation> {
        if !self.link.is_connected() {
            return Vec::new();
        }
        let Some(sender) = self.link.sender() else {
            return Vec::new();
        };
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let request = ProxyRequest {
            target: target.clone(),
            reply: reply_tx,
        };
        // the actor lives on the async runtime; blocking_send hands the request
        // over from this blocking resolve thread. a full or closed channel means
        // the plugin cannot keep up or is gone, so answer empty.
        if sender.blocking_send(request).is_err() {
            return Vec::new();
        }
        reply_rx.recv_timeout(ENRICH_TIMEOUT).unwrap_or_default()
    }
}
