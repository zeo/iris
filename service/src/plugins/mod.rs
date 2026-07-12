//! the plugin subsystem. it hosts the compiled-in enrichment registry and the
//! first-party enrichers, and the out-of-process runtime: a restricted-token
//! child speaking a separate pipe presents through the same
//! [`registry::EnrichmentRegistry`] via a proxy, so the registry's callers never
//! learn whether an enricher is built in or a plugin.

pub mod builtin;
pub mod manifest;
pub mod proxy;
pub mod registry;
pub mod supervisor;

use crate::engine::Engine;
use iris_store::Store;
use proxy::OutOfProcEnricher;
use registry::EnrichmentRegistry;
use std::sync::{Arc, Mutex};
use supervisor::Supervisor;

/// build the enrichment registry (first-party enrichers plus a proxy for every
/// enabled out-of-process plugin) and the supervisor that runs those plugins.
pub fn build(store: Arc<Mutex<Store>>, engine: Engine) -> (Arc<EnrichmentRegistry>, Supervisor) {
    let mut registry = EnrichmentRegistry::new();
    registry.register(Box::new(builtin::NetworkScope));
    registry.register(Box::new(builtin::Watchlist::new()));

    let runtimes = supervisor::plan(&store);
    for rt in &runtimes {
        registry.register(Box::new(OutOfProcEnricher::new(rt.link.clone())));
    }

    let supervisor = Supervisor::new(runtimes, store, engine);
    (Arc::new(registry), supervisor)
}
