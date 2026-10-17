//! iris's own watchers, run on the monitor thread once per tick: an app moving
//! far more data than usual, an established app reaching a new domain, a
//! decided app replaced on disk, and a gateway answering from a new hardware
//! address. each one is rate limited, since an alert nobody reads is noise.

use iris_core::{AlertKind, AppId, Granularity, HostUsage, StatsTick, WatchReason};
use iris_store::Store;
use std::collections::{HashMap, HashSet, VecDeque};

/// a minute has to move at least this much before it can count as a spike
const SPIKE_FLOOR_BYTES: u64 = 250 * 1024 * 1024;
/// and this many times the app's usual busy minute
const SPIKE_FACTOR: u64 = 10;
/// busy minutes remembered per app to judge what usual is
const SPIKE_HISTORY: usize = 30;
const SPIKE_MIN_HISTORY: usize = 10;
const SPIKE_COOLDOWN_MS: u64 = 3_600_000;

/// an app has to be this old before a new domain is worth mentioning; before
/// that it is still showing what it normally talks to
const NEW_HOST_LEARNING_MS: u64 = 7 * 86_400_000;
const NEW_HOST_PER_APP_PER_DAY: u32 = 3;

const FINGERPRINT_EVERY_TICKS: u64 = 60;
const DECISIONS_EVERY_TICKS: u64 = 300;
const GATEWAY_EVERY_TICKS: u64 = 30;

#[derive(Default)]
struct Spike {
    minute: u64,
    bytes: u64,
    history: VecDeque<u64>,
    last_alert_ms: Option<u64>,
}

#[derive(Default)]
pub struct Watcher {
    ticks: u64,
    spikes: HashMap<String, Spike>,
    domains: HashMap<String, HashSet<String>>,
    new_host_budget: HashMap<String, (u64, u32)>,
    decided: HashSet<String>,
}

impl Watcher {
    /// look over one tick and its per-host split, before the split is stored
    pub fn observe(&mut self, tick: &StatsTick, hosts: &[HostUsage], store: &Store) -> Vec<AlertKind> {
        let mut alerts = Vec::new();
        if self.ticks.is_multiple_of(DECISIONS_EVERY_TICKS) {
            self.decided = store.trusted_apps().into_iter().collect();
        }
        self.spikes(tick, &mut alerts);
        self.new_hosts(tick.at_ms, hosts, store, &mut alerts);
        if self.ticks.is_multiple_of(FINGERPRINT_EVERY_TICKS) {
            self.fingerprints(tick, store, &mut alerts);
        }
        if self.ticks.is_multiple_of(GATEWAY_EVERY_TICKS) {
            gateway(store, &mut alerts);
        }
        self.ticks = self.ticks.wrapping_add(1);
        alerts
    }

    fn spikes(&mut self, tick: &StatsTick, alerts: &mut Vec<AlertKind>) {
        let minute = Granularity::Minute.bucket_start(tick.at_ms);
        for app in &tick.apps {
            let bytes = app.rate_sent.saturating_add(app.rate_recv);
            let state = self.spikes.entry(app.app.0.clone()).or_default();
            if state.minute != minute {
                if let Some(message) = judge_minute(state, tick.at_ms, &app.app) {
                    alerts.push(AlertKind::Watch {
                        reason: WatchReason::TrafficSpike,
                        app: Some(app.app.clone()),
                        message,
                    });
                }
                state.minute = minute;
                state.bytes = 0;
            }
            state.bytes = state.bytes.saturating_add(bytes);
        }
    }

    fn new_hosts(&mut self, now: u64, hosts: &[HostUsage], store: &Store, alerts: &mut Vec<AlertKind>) {
        for row in hosts {
            let Some(domain) = registrable(&row.host) else {
                continue;
            };
            let known = self.domains.entry(row.app.0.clone()).or_insert_with(|| {
                store
                    .hosts_for(&row.app)
                    .iter()
                    .filter_map(|host| registrable(host))
                    .collect()
            });
            if !known.insert(domain.clone()) {
                continue;
            }
            let established = store
                .first_seen(row.app.as_str())
                .is_some_and(|first| now.saturating_sub(first) >= NEW_HOST_LEARNING_MS);
            if !established {
                continue;
            }
            let day = now / 86_400_000;
            let budget = self.new_host_budget.entry(row.app.0.clone()).or_insert((day, 0));
            if budget.0 != day {
                *budget = (day, 0);
            }
            if budget.1 >= NEW_HOST_PER_APP_PER_DAY {
                continue;
            }
            budget.1 += 1;
            alerts.push(AlertKind::Watch {
                reason: WatchReason::NewHost,
                app: Some(row.app.clone()),
                message: format!("{} reached {domain} for the first time", row.app.file_name()),
            });
        }
    }

    fn fingerprints(&mut self, tick: &StatsTick, store: &Store, alerts: &mut Vec<AlertKind>) {
        for app in tick.apps.iter().filter(|app| app.online) {
            if !self.decided.contains(app.app.as_str()) {
                continue;
            }
            let Ok(meta) = std::fs::metadata(app.app.as_str()) else {
                continue;
            };
            let modified = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |since| since.as_millis() as u64);
            let previous = store.replace_fingerprint(app.app.as_str(), meta.len(), modified);
            if previous.is_some_and(|previous| previous != (meta.len(), modified)) {
                alerts.push(AlertKind::Watch {
                    reason: WatchReason::BinaryChanged,
                    app: Some(app.app.clone()),
                    message: format!(
                        "{} changed on disk since you decided about it; an update does this, so does tampering",
                        app.app.file_name()
                    ),
                });
            }
        }
    }
}

/// at a minute boundary, decide whether the minute that just ended was a spike
fn judge_minute(state: &mut Spike, now: u64, app: &AppId) -> Option<String> {
    if state.bytes == 0 {
        return None;
    }
    let finished = state.bytes;
    let mut sorted: Vec<u64> = state.history.iter().copied().collect();
    if state.history.len() == SPIKE_HISTORY {
        state.history.pop_front();
    }
    state.history.push_back(finished);
    if sorted.len() < SPIKE_MIN_HISTORY {
        return None;
    }
    sorted.sort_unstable();
    let usual = sorted[sorted.len() / 2].max(1);
    let spiked = finished >= SPIKE_FLOOR_BYTES && finished >= usual.saturating_mul(SPIKE_FACTOR);
    if !spiked || state.last_alert_ms.is_some_and(|last| now.saturating_sub(last) < SPIKE_COOLDOWN_MS) {
        return None;
    }
    state.last_alert_ms = Some(now);
    Some(format!(
        "{} moved {} MB in one minute, about {}x its usual busy minute",
        app.file_name(),
        finished / (1024 * 1024),
        finished / usual
    ))
}

/// the part of a hostname an owner registers, roughly: `cdn.example.com` is
/// `example.com`, `a.b.co.uk` is `b.co.uk`. addresses have none
fn registrable(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let keep = match labels.as_slice() {
        [.., second, last] if last.len() == 2 && second.len() <= 3 && labels.len() >= 3 => 3,
        _ => 2,
    };
    Some(labels[labels.len().saturating_sub(keep)..].join("."))
}

#[cfg(has_platform)]
fn gateway(store: &Store, alerts: &mut Vec<AlertKind>) {
    let Some(network) = crate::platform::current_network() else {
        return;
    };
    let Some(mac) = network.key.strip_prefix("mac:") else {
        return;
    };
    if let Some(previous) = store.replace_gateway_mac(&network.label, mac) {
        alerts.push(AlertKind::Watch {
            reason: WatchReason::GatewayChanged,
            app: None,
            message: format!(
                "{} now answers from {mac} instead of {previous}; a new router explains this, otherwise something on the network may be intercepting traffic",
                network.label
            ),
        });
    }
}

#[cfg(not(has_platform))]
fn gateway(_store: &Store, _alerts: &mut Vec<AlertKind>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use iris_core::{AppSample, ByteCounts};

    fn tick(at_ms: u64, bytes_per_sec: u64) -> StatsTick {
        StatsTick {
            at_ms,
            total_rate_sent: 0,
            total_rate_recv: bytes_per_sec,
            apps: vec![AppSample {
                app: AppId::from_path("c:/apps/sync.exe"),
                name: None,
                rate_sent: 0,
                rate_recv: bytes_per_sec,
                total: ByteCounts::default(),
                connections: 1,
                online: true,
                hosts: Vec::new(),
                processes: Vec::new(),
            }],
            adapters: Vec::new(),
        }
    }

    #[test]
    fn a_minute_far_above_the_usual_raises_one_spike() {
        let store = Store::open_in_memory().unwrap();
        let mut watcher = Watcher::default();
        let minute = 60_000;
        let mut raised = Vec::new();
        for n in 1..=12 {
            raised.extend(watcher.observe(&tick(n * minute, 1024 * 1024), &[], &store));
        }
        assert!(raised.is_empty(), "steady traffic is not a spike");
        raised.extend(watcher.observe(&tick(13 * minute, 600 * 1024 * 1024), &[], &store));
        raised.extend(watcher.observe(&tick(14 * minute, 1024 * 1024), &[], &store));
        let spikes: Vec<_> = raised
            .iter()
            .filter(|kind| matches!(kind, AlertKind::Watch { reason: WatchReason::TrafficSpike, .. }))
            .collect();
        assert_eq!(spikes.len(), 1);
    }

    #[test]
    fn new_domains_alert_only_for_established_apps_and_only_once() {
        let store = Store::open_in_memory().unwrap();
        let app = AppId::from_path("c:/apps/old.exe");
        store.ensure_app(app.as_str(), None, 0);
        let row = |host: &str| HostUsage { app: app.clone(), host: host.into(), bytes: ByteCounts { sent: 1, recv: 1 } };
        let mut watcher = Watcher::default();
        let later = NEW_HOST_LEARNING_MS + 1;
        let first = watcher.observe(&tick(later, 0), &[row("api.example.com"), row("203.0.113.9")], &store);
        assert_eq!(first.len(), 1);
        let again = watcher.observe(&tick(later + 1000, 0), &[row("cdn.example.com")], &store);
        assert!(again.is_empty(), "same registrable domain");

        let young = AppId::from_path("c:/apps/new.exe");
        store.ensure_app(young.as_str(), None, later);
        let quiet = watcher.observe(
            &tick(later + 2000, 0),
            &[HostUsage { app: young, host: "other.example.org".into(), bytes: ByteCounts::default() }],
            &store,
        );
        assert!(quiet.is_empty(), "still learning");
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable("cdn.Example.com.").as_deref(), Some("example.com"));
        assert_eq!(registrable("a.b.co.uk").as_deref(), Some("b.co.uk"));
        assert_eq!(registrable("example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable("192.168.1.1"), None);
        assert_eq!(registrable("localhost"), None);
    }
}
