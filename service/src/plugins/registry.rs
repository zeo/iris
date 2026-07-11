//! the in-service enrichment registry. holds the compiled-in enrichers, runs
//! them off the tick path, and caches results per target so a repeat lookup is
//! free. out-of-process plugins will later register here through a proxy that
//! implements the same [`Enricher`] trait, so this code will not need to know
//! whether an enricher is built in or a plugin.

use iris_core::{Annotation, EnrichTarget, Enricher, TargetKind};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// annotations for an endpoint or app change rarely, so a generous TTL keeps
/// repeat lookups (a drawer reopened, the same host seen again) off the enrichers
const TTL: Duration = Duration::from_secs(3600);

struct Cached {
    annotations: Vec<Annotation>,
    at: Instant,
}

pub struct EnrichmentRegistry {
    enrichers: Vec<Box<dyn Enricher>>,
    cache: Mutex<HashMap<EnrichTarget, Cached>>,
}

impl EnrichmentRegistry {
    pub fn new() -> Self {
        EnrichmentRegistry {
            enrichers: Vec::new(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&mut self, enricher: Box<dyn Enricher>) {
        tracing::info!(enricher = enricher.id(), "enricher registered");
        self.enrichers.push(enricher);
    }

    /// return already-cached annotations for these targets, skipping any that are
    /// missing or stale. used by the UI's GetEnrichment (never blocks on work).
    pub fn cached_for(&self, targets: &[EnrichTarget]) -> Vec<(EnrichTarget, Vec<Annotation>)> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        targets
            .iter()
            .filter_map(|t| {
                cache
                    .get(t)
                    .filter(|c| c.at.elapsed() < TTL)
                    .map(|c| (t.clone(), c.annotations.clone()))
            })
            .collect()
    }

    /// run every enricher that handles this target's kind, cache the result, and
    /// return it. synchronous, so callers run it off the hot path. a fresh cache
    /// entry short-circuits the enrichers.
    pub fn resolve(&self, target: &EnrichTarget) -> Vec<Annotation> {
        if let Some(hit) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(target)
            .filter(|c| c.at.elapsed() < TTL)
        {
            return hit.annotations.clone();
        }

        let kind = match target {
            EnrichTarget::Endpoint(_) => TargetKind::Endpoint,
            EnrichTarget::App(_) => TargetKind::App,
        };
        let mut annotations = Vec::new();
        for enricher in &self.enrichers {
            if enricher.targets().contains(&kind) {
                annotations.extend(enricher.enrich(target));
            }
        }

        self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(
            target.clone(),
            Cached {
                annotations: annotations.clone(),
                at: Instant::now(),
            },
        );
        annotations
    }
}

impl Default for EnrichmentRegistry {
    fn default() -> Self {
        Self::new()
    }
}
