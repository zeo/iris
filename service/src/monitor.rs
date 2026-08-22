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

#[cfg(has_platform)]
#[allow(unused_imports)]
use std::collections::HashMap;

#[cfg(has_platform)]
fn publish_pending(
    pending: Vec<crate::platform::PendingConnection>,
    store: &Arc<Mutex<Store>>,
    engine: &Engine,
    last_notified: &mut HashMap<(iris_core::AppId, iris_core::Direction), u64>,
) {
    if pending.is_empty() {
        return;
    }

    let now = now_ms();
    let mut unthrottled = Vec::with_capacity(pending.len());
    for conn in pending {
        let key = (conn.app.clone(), conn.direction);
        let last = last_notified.get(&key).copied().unwrap_or(0);
        if now.saturating_sub(last) >= 1000 || last == 0 {
            unthrottled.push(conn);
        }
    }

    if unthrottled.is_empty() {
        return;
    }

    let mut to_publish = Vec::new();
    let store = store.lock().unwrap_or_else(|error| error.into_inner());
    let prompt_alerts = store.list_prompt_alerts();
    let mut seen: HashMap<(iris_core::AppId, iris_core::Direction), iris_core::Alert> =
        prompt_alerts
            .into_iter()
            .filter_map(|alert| match &alert.kind {
                AlertKind::NewApp {
                    app,
                    direction: Some(direction),
                    ..
                } => Some(((app.clone(), *direction), alert)),
                _ => None,
            })
            .collect();

    for connection in unthrottled {
        store.ensure_app(connection.app.as_str(), None, now);
        let key = (connection.app.clone(), connection.direction);
        if let Some(existing) = seen.get(&key) {
            let last = last_notified.get(&key).copied().unwrap_or(0);
            if now.saturating_sub(last) >= 1000 || last == 0 {
                last_notified.insert(key, now);
                to_publish.push(existing.clone());
            }
        } else {
            let alert = store.insert_alert(
                &AlertKind::NewApp {
                    app: connection.app.clone(),
                    remote: Some(connection.remote),
                    direction: Some(connection.direction),
                },
                now,
            );
            seen.insert(key.clone(), alert.clone());
            last_notified.insert(key, now);
            to_publish.push(alert);
        }
    }
    drop(store);

    if last_notified.len() > 1024 {
        last_notified.retain(|_, &mut time| now.saturating_sub(time) <= 60_000);
    }

    for alert in to_publish {
        tracing::info!(alert_id = alert.id, "published pending connection alert");
        engine.publish(ServerMessage::Alert(alert));
    }
}

#[cfg(has_platform)]
fn start_pending_publisher(
    pending: std::sync::mpsc::Receiver<crate::platform::PendingConnection>,
    store: Arc<Mutex<Store>>,
    engine: Engine,
) {
    std::thread::Builder::new()
        .name("iris-pending-publisher".to_string())
        .spawn(move || {
            let mut last_notified = HashMap::new();
            for connection in pending {
                tracing::info!(app = connection.app.as_str(), "received pending connection");
                publish_pending(vec![connection], &store, &engine, &mut last_notified);
            }
        })
        .unwrap_or_else(|error| panic!("cannot start pending publisher: {error}"));
}

#[cfg(all(test, has_platform))]
mod tests {
    use super::*;
    use iris_core::{AppId, Direction, Endpoint, Protocol};
    use std::net::IpAddr;

    #[test]
    fn pending_connection_publishes_without_waiting_for_a_telemetry_tick() {
        let engine = Engine::new();
        let mut events = engine.subscribe();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let app = AppId::from_path("/usr/bin/example");
        let mut last_notified = HashMap::new();

        publish_pending(
            vec![crate::platform::PendingConnection {
                app: app.clone(),
                remote: Endpoint {
                    addr: "203.0.113.7".parse::<IpAddr>().unwrap(),
                    port: 443,
                    protocol: Protocol::Tcp,
                },
                direction: Direction::Outbound,
            }],
            &store,
            &engine,
            &mut last_notified,
        );

        let ServerMessage::Alert(alert) = events.try_recv().unwrap() else {
            panic!("expected alert");
        };
        assert!(matches!(
            alert.kind,
            AlertKind::NewApp {
                app: alerted_app,
                direction: Some(Direction::Outbound),
                ..
            } if alerted_app == app
        ));
    }

    #[test]
    fn pending_receiver_publishes_without_an_async_wakeup() {
        let engine = Engine::new();
        let mut events = engine.subscribe();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let (send, pending) = std::sync::mpsc::channel();
        start_pending_publisher(pending, store, engine);
        send.send(crate::platform::PendingConnection {
            app: AppId::from_path("/usr/bin/receiver-example"),
            remote: Endpoint {
                addr: "203.0.113.7".parse::<IpAddr>().unwrap(),
                port: 443,
                protocol: Protocol::Tcp,
            },
            direction: Direction::Outbound,
        })
        .unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let alert = runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(250), events.recv())
                .await
                .unwrap()
                .unwrap()
        });
        assert!(matches!(alert, ServerMessage::Alert(_)));
    }

    #[test]
    fn pending_alert_stays_visible_until_decided() {
        let engine = Engine::new();
        let _events = engine.subscribe();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let app = AppId::from_path("/usr/bin/rotated-app");
        let mut last_notified = HashMap::new();
        let now = now_ms();
        {
            let store = store.lock().unwrap();
            store.insert_alert(
                &AlertKind::NewApp {
                    app: app.clone(),
                    remote: Some(Endpoint {
                        addr: "203.0.113.7".parse::<IpAddr>().unwrap(),
                        port: 443,
                        protocol: Protocol::Tcp,
                    }),
                    direction: Some(iris_core::Direction::Outbound),
                },
                now,
            );
        }
        assert_eq!(store.lock().unwrap().list_prompt_alerts().len(), 1);

        publish_pending(
            vec![crate::platform::PendingConnection {
                app: app.clone(),
                remote: Endpoint {
                    addr: "203.0.113.8".parse::<IpAddr>().unwrap(),
                    port: 443,
                    protocol: Protocol::Tcp,
                },
                direction: Direction::Outbound,
            }],
            &store,
            &engine,
            &mut last_notified,
        );

        assert_eq!(store.lock().unwrap().list_prompt_alerts().len(), 1);
    }

    #[test]
    fn pending_connection_republishes_on_retry() {
        let engine = Engine::new();
        let mut events = engine.subscribe();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let app = AppId::from_path("/usr/bin/retry-example");
        let mut last_notified = HashMap::new();

        let conn = crate::platform::PendingConnection {
            app: app.clone(),
            remote: Endpoint {
                addr: "203.0.113.7".parse::<IpAddr>().unwrap(),
                port: 443,
                protocol: Protocol::Tcp,
            },
            direction: Direction::Outbound,
        };

        publish_pending(vec![conn.clone()], &store, &engine, &mut last_notified);
        let ServerMessage::Alert(alert1) = events.try_recv().unwrap() else {
            panic!("expected first alert");
        };

        // Simulate 1 second later retry
        last_notified.insert((app.clone(), Direction::Outbound), 0);
        publish_pending(vec![conn], &store, &engine, &mut last_notified);
        let ServerMessage::Alert(alert2) = events.try_recv().unwrap() else {
            panic!("expected second alert on retry");
        };

        assert_eq!(alert1.id, alert2.id);
        assert_eq!(store.lock().unwrap().list_prompt_alerts().len(), 1);
    }
}

/// start monitoring and the flush loop.
pub fn spawn(
    engine: Engine,
    rules: Arc<Mutex<RuleStore>>,
    store: Arc<Mutex<Store>>,
    enrich: Arc<EnrichmentRegistry>,
) {
    #[cfg(not(has_platform))]
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
    let mut tracker = Tracker::new(agg.clone(), dns.clone());
    #[cfg(not(has_platform))]
    let mut tracker = Tracker::new(agg);

    #[cfg(has_platform)]
    if let Some(pending) = rules
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take_pending_receiver()
    {
        start_pending_publisher(pending, store.clone(), engine.clone());
    }

    // the sample loop runs on a dedicated thread, not the async reactor: every
    // tick takes the store lock for its SQLite write, so a stalled reactor or
    // one slow write must never delay samples for every connected UI. the
    // loop's only engine work is a broadcast send that never blocks.
    let sample_loop = std::thread::Builder::new()
        .name("iris-sample-loop".to_string())
        .spawn(move || {
            #[cfg(has_platform)]
            #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
            let mut byte_monitor = byte_monitor;
            #[cfg(all(has_platform, target_os = "windows"))]
            let agg = agg;
            #[cfg(all(has_platform, target_os = "windows"))]
            let dns = dns;
            let mut ticks: u64 = 0;
            // register everything already connected silently on the first tick so a
            // fresh start does not toast every already-running app at once
            let mut baseline_done = false;
            // remote endpoints already handed to the enrichers, so each is resolved
            // and pushed once rather than every tick it stays connected
            let mut enriched_seen: HashSet<IpAddr> = HashSet::new();
            // whether the UI has been told byte capture is down; only transitions
            // publish, so a long outage does not spam every client
            #[cfg(all(has_platform, target_os = "windows"))]
            let mut degraded_published = false;

            loop {
                std::thread::sleep(Duration::from_secs(1));
                let now = now_ms();
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
                #[cfg_attr(not(target_os = "windows"), allow(unused_variables))]
                let any_online = tick.apps.iter().any(|app| app.online);
                {
                    let mut store = store.lock().unwrap_or_else(|e| e.into_inner());
                    let alerting = baseline_done;
                    let fresh_apps = store.record_tick(&tick);
                    baseline_done = true;
                    for app in &tick.apps {
                        if app.online && fresh_apps.contains(&app.app) && alerting {
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
                    std::thread::Builder::new()
                        .name("iris-enrich".to_string())
                        .spawn(move || {
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
                                        message: format!(
                                            "{} flagged {}",
                                            a.label,
                                            target_name(&target)
                                        ),
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
                        })
                        .ok();
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
                // a dead ETW session is invisible from inside: the trace object
                // still exists, events just stop. the one observable symptom is
                // an old last-event stamp while the connection view keeps
                // finding active sockets, so restart the capture when both hold.
                // quiet traffic with an old stamp stays alone.
                #[cfg(all(has_platform, target_os = "windows"))]
                if ticks.is_multiple_of(30) {
                    const ETW_STALE_MS: u64 = 20_000;
                    let capture_dead = byte_monitor
                        .as_ref()
                        .is_some_and(|m| m.ms_since_last_event() > ETW_STALE_MS);
                    if capture_dead && any_online {
                        tracing::warn!("byte capture stalled, restarting the ETW session");
                        if let Some(dead) = byte_monitor.take() {
                            drop(dead);
                        }
                        crate::platform::Monitor::stop_leaked_sessions();
                        let restarted = crate::platform::Monitor::start(agg.clone(), dns.clone());
                        match restarted {
                            Ok(monitor) => {
                                byte_monitor = Some(monitor);
                                if degraded_published {
                                    engine.publish(ServerMessage::CaptureDegraded {
                                        degraded: false,
                                    });
                                    degraded_published = false;
                                }
                            }
                            Err(e) => {
                                tracing::error!("byte monitor restart failed: {e}");
                                if !degraded_published {
                                    engine
                                        .publish(ServerMessage::CaptureDegraded { degraded: true });
                                    degraded_published = true;
                                }
                            }
                        }
                    }
                }
                // prune usage older than 45 days, hourly
                if ticks.is_multiple_of(3600) {
                    let store = store.lock().unwrap_or_else(|e| e.into_inner());
                    store.prune_usage(now.saturating_sub(45 * 86_400_000));
                }
            }
        })
        .and_then(|handle| {
            handle
                .join()
                .map_err(|_| std::io::Error::other("sample loop panicked"))
        });
    if let Err(error) = sample_loop {
        tracing::error!("sample loop could not start or died: {error}");
    }
}
