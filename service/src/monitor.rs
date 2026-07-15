//! ties the platform data sources to the engine: the ETW byte monitor fills a
//! shared aggregator, the [`Tracker`] merges that with live connections and the
//! online/offline lifecycle, and a one-second timer publishes the resulting
//! sample tick to every subscribed UI. it also records usage to the store and
//! raises a first-seen alert the first time an app reaches the network.

use crate::engine::Engine;
use crate::plugins::registry::EnrichmentRegistry;
use crate::rules::RuleStore;
use crate::tracker::Tracker;
use iris_core::{Aggregator, AlertKind, EnrichTarget, Severity};
use iris_ipc::ServerMessage;
use iris_store::Store;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
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

fn target_name(target: &EnrichTarget) -> String {
    match target {
        EnrichTarget::Endpoint(ip) => ip.to_string(),
        EnrichTarget::App(app) => app.file_name().to_string(),
    }
}

/// start monitoring and the flush loop.
pub fn spawn(
    engine: Engine,
    rules: Arc<Mutex<RuleStore>>,
    store: Arc<Mutex<Store>>,
    enrich: Arc<EnrichmentRegistry>,
) {
    #[cfg(not(target_os = "linux"))]
    let _ = &rules;
    let agg = Arc::new(Mutex::new(Aggregator::new(now_ms())));

    #[cfg(has_platform)]
    let dns = crate::platform::new_map();

    #[cfg(has_platform)]
    let byte_monitor = match crate::platform::Monitor::start(agg.clone(), dns.clone()) {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::error!("byte monitor unavailable (connections still shown): {e}");
            None
        }
    };

    #[cfg(has_platform)]
    let mut tracker = Tracker::new(agg, dns);
    #[cfg(not(has_platform))]
    let mut tracker = Tracker::new(agg);

    tokio::spawn(async move {
        #[cfg(has_platform)]
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
            #[cfg(target_os = "linux")]
            let pending = rules
                .lock()
                .map(|rules| rules.take_pending_connections())
                .unwrap_or_default();
            #[cfg(target_os = "linux")]
            for connection in pending {
                let alert = {
                    let store = store.lock().unwrap_or_else(|error| error.into_inner());
                    store.ensure_app(connection.app.as_str(), None, now);
                    let already_pending = store.list_alerts(true).into_iter().any(|alert| {
                        matches!(
                            alert.kind,
                            AlertKind::NewApp { ref app, direction, .. }
                                if app == &connection.app && direction == Some(connection.direction)
                        )
                    });
                    (!already_pending).then(|| {
                        store.insert_alert(
                            &AlertKind::NewApp {
                                app: connection.app,
                                remote: Some(connection.remote),
                                direction: Some(connection.direction),
                            },
                            now,
                        )
                    })
                };
                if let Some(alert) = alert {
                    engine.publish(ServerMessage::Alert(alert));
                }
            }
            let tick = tracker.tick(now);
            #[cfg(target_os = "linux")]
            let recent_flows: HashMap<String, crate::platform::RecentFlow> = byte_monitor
                .as_ref()
                .map(|monitor| {
                    monitor
                        .take_recent_flows()
                        .into_iter()
                        .map(|flow| (flow.path.clone(), flow))
                        .collect()
                })
                .unwrap_or_default();

            // record usage + first-seen alerts under one store lock. recover a
            // poisoned guard so one panicking tick never silently ends all
            // history and alerting
            {
                let store = store.lock().unwrap_or_else(|e| e.into_inner());
                let alerting = now > baseline_until;
                for adapter in &tick.adapters {
                    store.add_adapter_usage(
                        adapter.kind,
                        now,
                        adapter.rate_sent,
                        adapter.rate_recv,
                    );
                }
                for app in &tick.apps {
                    // rate over a ~1s window is close enough to bytes this second
                    store.add_usage(app.app.as_str(), now, app.rate_sent, app.rate_recv);
                    if app.online
                        && store.ensure_app(app.app.as_str(), app.name.as_deref(), now)
                        && alerting
                    {
                        let connection = app
                            .processes
                            .iter()
                            .flat_map(|process| &process.conns)
                            .next();
                        #[cfg(target_os = "linux")]
                        let closed = recent_flows.get(app.app.as_str());
                        let alert = store.insert_alert(
                            &AlertKind::NewApp {
                                app: app.app.clone(),
                                remote: connection.map(|conn| conn.remote.clone()).or({
                                    #[cfg(target_os = "linux")]
                                    {
                                        closed.map(|flow| flow.remote.clone())
                                    }
                                    #[cfg(not(target_os = "linux"))]
                                    {
                                        None
                                    }
                                }),
                                direction: connection.map(|conn| conn.direction).or({
                                    #[cfg(target_os = "linux")]
                                    {
                                        closed.map(|flow| flow.direction)
                                    }
                                    #[cfg(not(target_os = "linux"))]
                                    {
                                        None
                                    }
                                }),
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
            // never delays the next sample. this runs on a blocking thread: a
            // built-in enricher may touch disk (the watchlist file) and an
            // out-of-process plugin proxy blocks on a pipe round-trip, neither of
            // which may run on an async worker.
            if !new_targets.is_empty() {
                let engine = engine.clone();
                let enrich = enrich.clone();
                let store = store.clone();
                tokio::task::spawn_blocking(move || {
                    for target in new_targets {
                        let annotations = enrich.resolve(&target);
                        if annotations.is_empty() {
                            continue;
                        }
                        // a danger-severity annotation is alert-worthy: the first
                        // sighting persists and toasts, not just a drawer badge
                        for a in annotations
                            .iter()
                            .filter(|a| a.severity == Severity::Danger)
                        {
                            let kind = AlertKind::Plugin {
                                source: a.label.clone(),
                                message: format!("{} flagged {}", a.label, target_name(&target)),
                            };
                            let alert = store
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert_alert(&kind, now_ms());
                            engine.publish(ServerMessage::Alert(alert));
                        }
                        engine.publish(ServerMessage::Enrichment {
                            target,
                            annotations,
                        });
                    }
                });
            }

            ticks += 1;
            if ticks.is_multiple_of(30) {
                tracker.clear_cache();
                #[cfg(has_platform)]
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
