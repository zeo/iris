//! ties the platform data sources to the engine: the ETW byte monitor fills a
//! shared aggregator, the [`Tracker`] merges that with live connections and the
//! online/offline lifecycle, and a one-second timer publishes the resulting
//! sample tick to every subscribed UI. it also records usage to the store and
//! raises a first-seen alert the first time an app reaches the network.

use crate::engine::Engine;
use crate::plugins::registry::EnrichmentRegistry;
use crate::rules::RuleStore;
use crate::tracker::Tracker;
use iris_core::{Aggregator, AlertKind, AppSample, EnrichTarget, FirewallMode, Severity};
use iris_ipc::ServerMessage;
use iris_store::Store;
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
pub(crate) fn publish_pending(
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
        tracing::debug!(alert_id = alert.id, "published pending connection alert");
        engine.publish(ServerMessage::Alert(alert));
    }
}

/// run the thread `make` builds under `name`, building and starting a fresh one
/// a second after each panic, until a run returns normally. the supervisor has
/// its own thread so the caller never waits on the work
fn respawn<M, F>(name: &str, mut make: M) -> io::Result<()>
where
    M: FnMut() -> F + Send + 'static,
    F: FnOnce() + Send + 'static,
{
    let name = name.to_string();
    std::thread::Builder::new()
        .name(format!("{name}-supervisor"))
        .spawn(move || loop {
            let outcome = std::thread::Builder::new()
                .name(name.clone())
                .spawn(make())
                .and_then(|handle| {
                    handle
                        .join()
                        .map_err(|_| io::Error::other("thread panicked"))
                });
            match outcome {
                Ok(()) => break,
                Err(error) => {
                    tracing::error!("{name} ended ({error}); restarting in 1s");
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        })
        .map(drop)
}

#[cfg(has_platform)]
fn start_pending_publisher(
    pending: std::sync::mpsc::Receiver<crate::platform::PendingConnection>,
    store: Arc<Mutex<Store>>,
    engine: Engine,
) -> io::Result<()> {
    // shared so a respawned publisher keeps draining the same channel
    let pending = Arc::new(Mutex::new(pending));
    respawn("iris-pending-publisher", move || {
        let pending = pending.clone();
        let store = store.clone();
        let engine = engine.clone();
        move || {
            let pending = pending.lock().unwrap_or_else(|error| error.into_inner());
            let mut last_notified = HashMap::new();
            // drain whatever queued behind the first so a retry storm costs one
            // store lock per batch, not one per denied packet
            while let Ok(first) = pending.recv() {
                let batch: Vec<_> = std::iter::once(first).chain(pending.try_iter()).collect();
                tracing::debug!(count = batch.len(), "received pending connections");
                publish_pending(batch, &store, &engine, &mut last_notified);
            }
        }
    })
}

#[cfg(windows)]
type BlockedKey = (iris_core::AppId, iris_core::Endpoint, iris_core::Direction);

/// count one drop into the row for its app, remote, and direction
#[cfg(windows)]
fn fold_blocked(
    rows: &mut HashMap<BlockedKey, iris_core::BlockedConnection>,
    drop: crate::platform::PendingConnection,
    at_ms: u64,
) {
    rows.entry((drop.app.clone(), drop.remote.clone(), drop.direction))
        .and_modify(|row| {
            row.last_ms = at_ms;
            row.count += 1;
        })
        .or_insert(iris_core::BlockedConnection {
            app: drop.app,
            remote: drop.remote,
            direction: drop.direction,
            first_ms: at_ms,
            last_ms: at_ms,
            count: 1,
        });
}

/// how long drops gather in memory before one upsert writes them, so a retry
/// storm costs a transaction a second rather than one per dropped packet
#[cfg(windows)]
const BLOCKED_FLUSH: Duration = Duration::from_secs(1);

#[cfg(windows)]
fn start_blocked_logger(
    blocked: Receiver<crate::platform::PendingConnection>,
    store: Arc<Mutex<Store>>,
) -> io::Result<()> {
    let blocked = Arc::new(Mutex::new(blocked));
    respawn("iris-blocked-logger", move || {
        let blocked = blocked.clone();
        let store = store.clone();
        move || {
            let blocked = blocked.lock().unwrap_or_else(|error| error.into_inner());
            while let Ok(first) = blocked.recv() {
                let mut rows = HashMap::new();
                fold_blocked(&mut rows, first, now_ms());
                let flush_at = Instant::now() + BLOCKED_FLUSH;
                while let Ok(drop) =
                    blocked.recv_timeout(flush_at.saturating_duration_since(Instant::now()))
                {
                    fold_blocked(&mut rows, drop, now_ms());
                }
                let rows: Vec<_> = rows.into_values().collect();
                store
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .record_blocked(&rows);
            }
        }
    })
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
        start_pending_publisher(pending, store, engine).unwrap();
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
            tokio::time::timeout(Duration::from_secs(5), events.recv())
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
    #[test]
    fn a_retry_burst_in_one_batch_raises_one_alert() {
        let engine = Engine::new();
        let mut events = engine.subscribe();
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let denied = |port| crate::platform::PendingConnection {
            app: AppId::from_path("/usr/bin/retrying-app"),
            remote: Endpoint {
                addr: "203.0.113.9".parse::<IpAddr>().unwrap(),
                port,
                protocol: Protocol::Tcp,
            },
            direction: Direction::Outbound,
        };
        let burst = (0..50).map(|n| denied(443 + n)).collect();
        publish_pending(burst, &store, &engine, &mut HashMap::new());

        assert!(matches!(events.try_recv(), Ok(ServerMessage::Alert(_))));
        assert!(events.try_recv().is_err());
        assert_eq!(store.lock().unwrap().list_prompt_alerts().len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn a_drop_storm_lands_as_one_counted_row_per_remote() {
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
        let (send, blocked) = std::sync::mpsc::sync_channel(64);
        start_blocked_logger(blocked, store.clone()).unwrap();
        let drop = |port| crate::platform::PendingConnection {
            app: AppId::from_path(r"C:\Apps\retrying.exe"),
            remote: Endpoint {
                addr: "203.0.113.9".parse::<IpAddr>().unwrap(),
                port,
                protocol: Protocol::Tcp,
            },
            direction: Direction::Outbound,
        };
        for _ in 0..40 {
            send.send(drop(443)).unwrap();
        }
        send.send(drop(80)).unwrap();

        let started = Instant::now();
        let rows = loop {
            let rows = store.lock().unwrap().list_blocked(10);
            if rows.len() == 2 || started.elapsed() > Duration::from_secs(5) {
                break rows;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let count = |port| rows.iter().find(|row| row.remote.port == port).map(|row| row.count);
        assert_eq!(count(443), Some(40));
        assert_eq!(count(80), Some(1));
        assert!(rows.iter().all(|row| row.first_ms <= row.last_ms));
    }

    #[test]
    fn respawn_returns_at_once_and_restarts_after_a_panic() {
        let (runs, ran) = std::sync::mpsc::channel();
        let mut attempt = 0;
        let started = std::time::Instant::now();
        respawn("iris-respawn-test", move || {
            attempt += 1;
            let runs = runs.clone();
            let this = attempt;
            move || {
                runs.send(this).unwrap();
                assert!(this > 1, "first run panics");
            }
        })
        .unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        let wait = Duration::from_secs(5);
        assert_eq!(ran.recv_timeout(wait).unwrap(), 1);
        assert_eq!(ran.recv_timeout(wait).unwrap(), 2);
        assert!(ran.recv_timeout(Duration::from_millis(1500)).is_err());
    }
}

/// start monitoring and the flush loop on their own threads and return.
pub fn spawn(
    engine: Engine,
    rules: Arc<Mutex<RuleStore>>,
    store: Arc<Mutex<Store>>,
    enrich: Arc<EnrichmentRegistry>,
) {
    #[cfg(not(has_platform))]
    let _ = &rules;
    let agg = Arc::new(Mutex::new(Aggregator::new(Instant::now())));

    #[cfg(has_platform)]
    let dns = engine.dns.clone();

    #[cfg(has_platform)]
    let byte_monitor = match crate::platform::Monitor::start(agg.clone(), dns.clone()) {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::error!("byte monitor unavailable (connections still shown): {e}");
            None
        }
    };

    #[cfg(has_platform)]
    // the first monitor handle moves into the first spawned sampler; later
    // respawns start with no capture and their capture restart path brings it
    // back within 30 ticks, the same self-heal a degraded boot gets
    let mut first_monitor = Some(byte_monitor);

    if let Some(pending) = rules
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take_pending_receiver()
    {
        if let Err(error) = start_pending_publisher(pending, store.clone(), engine.clone()) {
            tracing::error!("cannot start the pending publisher: {error}");
        }
    }
    #[cfg(windows)]
    if let Some(blocked) = rules
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take_blocked_receiver()
    {
        if let Err(error) = start_blocked_logger(blocked, store.clone()) {
            tracing::error!("cannot start the blocked logger: {error}");
        }
    }

    let enrich = match start_enrich_worker(enrich, store.clone(), engine.clone()) {
        Ok(queue) => queue,
        Err(error) => {
            tracing::error!("cannot start the enrich worker: {error}");
            std::sync::mpsc::sync_channel(0).0
        }
    };

    // the sample loop runs on a dedicated thread, not the async reactor: every
    // tick takes the store lock for its SQLite write, so a stalled reactor or
    // one slow write must never delay samples for every connected UI. the
    // loop's only engine work is a broadcast send that never blocks.
    // a panic inside a tick must not end monitoring for the life of the process,
    // and the SCM only restarts the engine when the service reports failure, so
    // the sampling thread is respawned instead of dying with the panic
    let started = respawn("iris-sample-loop", move || {
        let engine = engine.clone();
        let rules = rules.clone();
        let store = store.clone();
        let enrich = enrich.clone();
        let agg = agg.clone();
        #[cfg(has_platform)]
        let dns = dns.clone();
        #[cfg(has_platform)]
        let byte_monitor = first_monitor.take().unwrap_or_else(|| {
            tracing::warn!("respawned sample loop will retry byte capture");
            None
        });
        move || sample_forever(engine, rules, store, enrich, agg, dns, byte_monitor)
    });
    if let Err(error) = started {
        tracing::error!("cannot start the sample loop: {error}");
    }
}

/// resolve and push enrichment off the tick path so a slow enricher never
/// delays the next sample. this is a plain thread, not an async worker: a
/// built-in enricher may touch disk (the watchlist file) and an out-of-process
/// plugin proxy blocks on a pipe round-trip. one long-lived worker drains a
/// bounded queue, so a stalled plugin backs the queue up instead of piling up
/// a thread per tick
fn start_enrich_worker(
    enrich: Arc<EnrichmentRegistry>,
    store: Arc<Mutex<Store>>,
    engine: Engine,
) -> io::Result<SyncSender<Vec<EnrichTarget>>> {
    let (queue, targets) = std::sync::mpsc::sync_channel(64);
    let targets: Arc<Mutex<Receiver<Vec<EnrichTarget>>>> = Arc::new(Mutex::new(targets));
    respawn("iris-enrich", move || {
        let targets = targets.clone();
        let enrich = enrich.clone();
        let store = store.clone();
        let engine = engine.clone();
        move || {
            let targets = targets.lock().unwrap_or_else(|error| error.into_inner());
            for target in targets.iter().flatten() {
                enrich_one(&enrich, &store, &engine, target);
            }
        }
    })?;
    Ok(queue)
}

fn enrich_one(
    enrich: &EnrichmentRegistry,
    store: &Mutex<Store>,
    engine: &Engine,
    target: EnrichTarget,
) {
    let annotations = enrich.resolve(&target);
    if annotations.is_empty() {
        return;
    }
    // a danger-severity annotation is alert-worthy: the first sighting persists
    // and toasts, not just a drawer badge
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

/// run the per-second sampler until it unwinds. [`respawn`] restarts this
/// whole function after a panic so one bad tick never ends
/// monitoring.
#[cfg_attr(not(has_platform), allow(unused_variables))]
fn sample_forever(
    engine: Engine,
    rules: Arc<Mutex<RuleStore>>,
    store: Arc<Mutex<Store>>,
    enrich: SyncSender<Vec<EnrichTarget>>,
    #[cfg(has_platform)] agg: Arc<Mutex<Aggregator>>,
    #[cfg(has_platform)] dns: crate::platform::DnsMap,

    #[cfg(has_platform)] byte_monitor: Option<crate::platform::Monitor>,
) {
    #[cfg(has_platform)]
    let mut tracker = Tracker::new(agg.clone(), dns.clone());
    #[cfg(not(has_platform))]
    let mut tracker = Tracker::new(agg);
    let mut watcher = crate::watch::Watcher::default();

    // the capture restart paths reassign this, so mutability lives in a local instead of the signature
    #[cfg(has_platform)]
    let mut byte_monitor = byte_monitor;

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

    let mut mode = rules.lock().unwrap_or_else(|e| e.into_inner()).mode();
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = now_ms();
        let mut tick = tracker.tick(now);
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
        let network = baseline_done.then(|| watcher.probe_network()).flatten();
        {
            let mut store = store.lock().unwrap_or_else(|e| e.into_inner());
            let alerting = baseline_done;
            let fresh_apps = store.record_tick(&tick);
            let host_usage = tracker.take_host_usage();
            if baseline_done {
                for kind in watcher.observe(&tick, &host_usage, network, &store) {
                    let alert = store.insert_alert(&kind, tick.at_ms);
                    engine.publish(ServerMessage::Alert(alert));
                }
            }
            store.record_host_usage(tick.at_ms, &host_usage);
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

        if let Some(current) = follow_caps(&engine, &rules, &store, &tick.apps, now) {
            mode = current;
        }
        tick.mode = mode;
        engine.publish(ServerMessage::Tick(tick));

        // a full queue means the enrichers are behind; forget these so a
        // later tick offers them again instead of losing them for the session
        if !new_targets.is_empty() {
            if let Err(TrySendError::Full(skipped)) = enrich.try_send(new_targets) {
                for target in skipped {
                    if let EnrichTarget::Endpoint(ip) = target {
                        enriched_seen.remove(&ip);
                    }
                }
            }
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
            let capture_missing = byte_monitor.is_none();
            if (capture_dead && any_online) || capture_missing {
                tracing::warn!("byte capture stalled, restarting the ETW session");
                if capture_dead {
                    if let Some(dead) = byte_monitor.take() {
                        drop(dead);
                    }
                }
                crate::platform::Monitor::stop_leaked_sessions();
                let restarted = crate::platform::Monitor::start(agg.clone(), dns.clone());
                match restarted {
                    Ok(monitor) => {
                        byte_monitor = Some(monitor);
                        if degraded_published {
                            engine.publish(ServerMessage::CaptureDegraded { degraded: false });
                            degraded_published = false;
                        }
                    }
                    Err(e) => {
                        tracing::error!("byte monitor restart failed: {e}");
                        if !degraded_published {
                            engine.publish(ServerMessage::CaptureDegraded { degraded: true });
                            degraded_published = true;
                        }
                    }
                }
            }
        }
        // a respawned loop starts without capture; linux has no stale-session
        // signal, so only a missing monitor is restarted
        #[cfg(all(has_platform, target_os = "linux"))]
        if ticks.is_multiple_of(30) && byte_monitor.is_none() {
            match crate::platform::Monitor::start(agg.clone(), dns.clone()) {
                Ok(monitor) => byte_monitor = Some(monitor),
                Err(e) => tracing::error!("byte monitor restart failed: {e}"),
            }
        }
        if ticks.is_multiple_of(10) {
            check_quotas(&engine, &rules, &store, now);
        }
        if ticks == 1 || ticks.is_multiple_of(3600) {
            settle_stale_prompts(&store.lock().unwrap_or_else(|e| e.into_inner()), now);
        }
        // prune usage older than 45 days and blocked rows older than 30, hourly
        if ticks.is_multiple_of(3600) {
            let store = store.lock().unwrap_or_else(|e| e.into_inner());
            store.prune_usage(now.saturating_sub(45 * 86_400_000));
            store.prune_blocked(now.saturating_sub(30 * 86_400_000));
        }
    }
}

/// an app file that no longer exists, as after an update that moved it
pub(crate) fn app_is_gone(path: &str) -> bool {
    let path = std::path::Path::new(path);
    path.is_absolute() && !path.exists()
}

/// settle pending prompts nobody can act on: the app is gone, or the prompt is
/// over a day old. an app still being denied raises a fresh one on its next try
fn settle_stale_prompts(store: &Store, now: u64) {
    for alert in store.list_prompt_alerts() {
        if let AlertKind::NewApp { app, .. } = &alert.kind {
            if now.saturating_sub(alert.at_ms) > 86_400_000 || app_is_gone(app.as_str()) {
                store.ack_alert(alert.id);
            }
        }
    }
}

fn follow_caps(engine: &Engine, rules: &Mutex<RuleStore>, store: &Mutex<Store>, apps: &[AppSample], now: u64) -> Option<FirewallMode> {
    // a held rule store means a change is under way; the next tick catches up
    let mut rules = match rules.try_lock() {
        Ok(rules) => rules,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return None,
    };
    let notice = rules.follow_flows(apps);
    let mode = rules.mode();
    drop(rules);
    if let Some(kind) = notice {
        let alert = store.lock().unwrap_or_else(|e| e.into_inner()).insert_alert(&kind, now);
        engine.publish(ServerMessage::Alert(alert));
    }
    Some(mode)
}

fn check_quotas(engine: &Engine, rules: &Mutex<RuleStore>, store: &Mutex<Store>, now: u64) {
    // a held rule store means a change is under way; the next check catches up
    let mut rules = match rules.try_lock() {
        Ok(rules) => rules,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return,
    };
    let reached = rules.check_quotas(now, |app, from, to| {
        store.lock().unwrap_or_else(|e| e.into_inner()).usage_bytes(app, from, to)
    });
    drop(rules);
    if reached.is_empty() {
        return;
    }
    let store = store.lock().unwrap_or_else(|e| e.into_inner());
    for kind in reached {
        let alert = store.insert_alert(&kind, now);
        engine.publish(ServerMessage::Alert(alert));
    }
}
