//! the plugin subsystem. it hosts the compiled-in enrichment registry and the
//! first-party enrichers, and the out-of-process runtime: a restricted-token
//! child speaking a separate pipe presents through the same
//! [`registry::EnrichmentRegistry`] via a proxy, so the registry's callers never
//! learn whether an enricher is built in or a plugin.

pub mod builtin;
#[cfg(has_platform)]
pub mod egress;
pub mod manifest;
pub mod proxy;
pub mod registry;
pub mod supervisor;

use crate::engine::Engine;
use iris_store::Store;
use proxy::{OutOfProcEnricher, PluginLink};
use registry::EnrichmentRegistry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use supervisor::Supervisor;

/// routes panel fetches to the plugins the user let show one. gated at build
/// time: a plugin without the `ui:panel` grant is simply absent here.
pub struct PanelHub {
    links: HashMap<String, Arc<PluginLink>>,
}

impl PanelHub {
    /// blocking (a plugin round-trip); run on a blocking thread
    pub fn panel(&self, id: &str) -> Result<iris_core::Panel, String> {
        let link = self
            .links
            .get(id)
            .ok_or_else(|| "no panel for that plugin".to_string())?;
        link.panel().ok_or_else(|| "the plugin has no panel right now".to_string())
    }
}

/// build the enrichment registry (first-party enrichers plus a proxy for every
/// enabled out-of-process plugin), the panel hub, and the supervisor that runs
/// those plugins.
pub fn build(
    store: Arc<Mutex<Store>>,
    engine: Engine,
) -> (Arc<EnrichmentRegistry>, Arc<PanelHub>, Supervisor) {
    let mut registry = EnrichmentRegistry::new();
    registry.register(Box::new(builtin::NetworkScope));
    registry.register(Box::new(builtin::Geo::new()));
    registry.register(Box::new(builtin::Watchlist::new()));

    let runtimes = supervisor::plan(&store);
    let mut links = HashMap::new();
    for rt in &runtimes {
        registry.register(Box::new(OutOfProcEnricher::new(rt.link.clone())));
        if rt.panel_granted() {
            links.insert(rt.id.clone(), rt.link.clone());
        }
    }

    let supervisor = Supervisor::new(runtimes, store, engine);
    (Arc::new(registry), Arc::new(PanelHub { links }), supervisor)
}
