//! ties the platform data sources to the engine: the ETW byte monitor fills a
//! shared aggregator, the [`Tracker`] merges that with live connections and the
//! online/offline lifecycle, and a one-second timer publishes the resulting
//! sample tick to every subscribed UI. it also records usage to the store and
//! raises a first-seen alert the first time an app reaches the network.

use crate::engine::Engine;
use crate::plugins::registry::EnrichmentRegistry;
use crate::tracker::Tracker;
use iris_core::{Aggregator, AlertKind, EnrichTarget};
use iris_ipc::ServerMessage;
use iris_store::Store;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// start monitoring and the flush loop.
pub fn spawn(engine: Engine, store: Arc<Mutex<Store>>, enrich: Arc<EnrichmentRegistry>) {
    let agg = Arc::new(Mutex::new(Aggregator::new(now_ms())));

    #[cfg(windows)]
    let dns = iris_platform_win::new_map();

    #[cfg(windows)]
    let byte_monitor = match iris_platform_win::Monitor::start(agg.clone(), dns.clone()) {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::error!("byte monitor unavailable (connections still shown): {e}");
            None
        }
    };

    #[cfg(windows)]
    let mut tracker = Tracker::new(agg, dns);
    #[cfg(not(windows))]
    let mut tracker = Tracker::new(agg);

    tokio::spawn(async move {
        #[cfg(windows)]
        let byte_monitor = byte_monitor;
        let mut ticks: u64 = 0;
        // register everything already connected silently for the first few
        // seconds so a fresh install does not toast every running app at once
        let baseline_until = now_ms() + 6_000;
        // remote endpoints already handed to the enrichers, so each is resolved
        // and pushed once rather than every tick it stays connected
        let mut enriched_seen: HashSet<IpAddr> = HashSet::new();

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let now = now_ms();
            let tick = tracker.tick(now);

            // record usage + first-seen alerts under one store lock. recover a
            // poisoned guard so one panicking tick never silently ends all
            // history and alerting
            {
                let store = store.lock().unwrap_or_else(|e| e.into_inner());
                let alerting = now > baseline_until;
                for app in &tick.apps {
                    // rate over a ~1s window is close enough to bytes this second
                    store.add_usage(app.app.as_str(), now, app.rate_sent, app.rate_recv);
                    if app.online
                        && store.ensure_app(app.app.as_str(), app.name.as_deref(), now)
                        && alerting
                    {
                        let alert = store.insert_alert(
                            &AlertKind::NewApp {
                                app: app.app.clone(),
                            },
                            now,
                        );
                        engine.publish(ServerMessage::Alert(alert));
                    }
                }
            }

            // gather remote endpoints not enriched yet, before the tick is moved
            let mut new_targets: Vec<EnrichTarget> = Vec::new();
            for app in &tick.apps {
                for proc in &app.processes {
                    for conn in &proc.conns {
                        let ip = conn.remote.addr;
                        if enriched_seen.insert(ip) {
                            new_targets.push(EnrichTarget::Endpoint(ip));
                        }
                    }
                }
            }
            // bound the seen-set over a long session; a re-resolve after a clear
            // is a cache hit in the registry, so clearing is cheap
            if enriched_seen.len() > 8192 {
                enriched_seen.clear();
            }

            engine.publish(ServerMessage::Tick(tick));

            // resolve and push enrichment off the tick path so a slow enricher
            // never delays the next sample
            if !new_targets.is_empty() {
                let engine = engine.clone();
                let enrich = enrich.clone();
                tokio::spawn(async move {
                    for target in new_targets {
                        let annotations = enrich.resolve(&target);
                        if !annotations.is_empty() {
                            engine.publish(ServerMessage::Enrichment { target, annotations });
                        }
                    }
                });
            }

            ticks += 1;
            if ticks.is_multiple_of(30) {
                tracker.clear_cache();
                #[cfg(windows)]
                if let Some(m) = byte_monitor.as_ref() {
                    m.clear_cache();
                    m.refresh_adapters();
                }
            }
            // prune usage older than 45 days, hourly
            if ticks.is_multiple_of(3600) {
                let store = store.lock().unwrap_or_else(|e| e.into_inner());
                store.prune_usage(now.saturating_sub(45 * 86_400_000));
            }
        }
    });
}
