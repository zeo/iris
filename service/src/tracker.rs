//! merges the two data sources into the per-app rows the UI shows: byte rates
//! from the ETW [`Aggregator`] and live connections from the platform connection
//! enumerator. it also owns each app's online/offline lifecycle: an app with no
//! connections and no traffic enters a grace window (shown offline, name dimmed
//! red in the UI) and is dropped only once the window elapses.

use iris_core::{AppId, Aggregator, Conn, StatsTick};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// how long an app lingers as "offline" after its last connection or byte before
/// it drops off the activity list entirely
const GRACE_MS: u64 = 20_000;

pub struct Tracker {
    agg: Arc<Mutex<Aggregator>>,
    #[cfg(windows)]
    conns: iris_platform_win::ConnCounter,
    /// when each currently-idle app went offline; absent while active
    offline_since: HashMap<AppId, u64>,
}

impl Tracker {
    pub fn new(agg: Arc<Mutex<Aggregator>>) -> Self {
        Tracker {
            agg,
            #[cfg(windows)]
            conns: iris_platform_win::ConnCounter::new(),
            offline_since: HashMap::new(),
        }
    }

    fn connections(&mut self) -> HashMap<AppId, Vec<Conn>> {
        #[cfg(windows)]
        {
            self.conns.by_app()
        }
        #[cfg(not(windows))]
        {
            HashMap::new()
        }
    }

    /// build the sample tick for `now`
    pub fn tick(&mut self, now: u64) -> StatsTick {
        let conns_by_app = self.connections();

        {
            let mut a = self.agg.lock().expect("aggregator poisoned");
            for app in conns_by_app.keys() {
                a.touch(app);
            }
        }
        let base = self.agg.lock().expect("aggregator poisoned").flush(now);

        let mut apps = Vec::with_capacity(base.apps.len());
        let mut total_s = 0u64;
        let mut total_r = 0u64;
        let mut expired: Vec<AppId> = Vec::new();

        for mut s in base.apps {
            let conns = conns_by_app.get(&s.app).cloned().unwrap_or_default();
            let active = !conns.is_empty() || s.rate_sent > 0 || s.rate_recv > 0;

            if active {
                self.offline_since.remove(&s.app);
            } else {
                self.offline_since.entry(s.app.clone()).or_insert(now);
            }

            if let Some(&since) = self.offline_since.get(&s.app) {
                if now.saturating_sub(since) > GRACE_MS {
                    expired.push(s.app.clone());
                    continue;
                }
            }

            s.online = active;
            s.connections = conns.len() as u32;
            s.conns = conns;
            total_s = total_s.saturating_add(s.rate_sent);
            total_r = total_r.saturating_add(s.rate_recv);
            apps.push(s);
        }

        if !expired.is_empty() {
            let mut a = self.agg.lock().expect("aggregator poisoned");
            for app in &expired {
                a.forget(app);
                self.offline_since.remove(app);
            }
        }

        apps.sort_by(|a, b| {
            (b.rate_sent + b.rate_recv)
                .cmp(&(a.rate_sent + a.rate_recv))
                .then_with(|| b.total.total().cmp(&a.total.total()))
        });

        StatsTick {
            at_ms: now,
            total_rate_sent: total_s,
            total_rate_recv: total_r,
            apps,
        }
    }

    /// clear the connection enumerator's PID cache to bound reuse staleness
    pub fn clear_cache(&mut self) {
        #[cfg(windows)]
        self.conns.clear_cache();
    }
}
