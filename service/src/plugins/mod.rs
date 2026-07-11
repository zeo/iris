//! the plugin subsystem. today it hosts the compiled-in enrichment registry and
//! the first-party enrichers; the out-of-process runtime (a restricted-token
//! child speaking a separate pipe, its egress pinned with WFP) plugs into the
//! same [`registry::EnrichmentRegistry`] later without changing its callers.

pub mod builtin;
pub mod registry;

use registry::EnrichmentRegistry;
use std::sync::Arc;

/// build the registry with every first-party enricher registered
pub fn builtin_registry() -> Arc<EnrichmentRegistry> {
    let mut registry = EnrichmentRegistry::new();
    registry.register(Box::new(builtin::NetworkScope));
    Arc::new(registry)
}
