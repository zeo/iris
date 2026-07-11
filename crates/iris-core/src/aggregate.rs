use crate::model::{AppId, AppSample, ByteCounts, StatsTick};
use std::collections::HashMap;

/// accumulates per-app byte deltas between sample ticks and turns them into a
/// [`StatsTick`] on flush. the platform monitor calls [`Aggregator::record`] for
/// every attributed network event; the service calls [`Aggregator::flush`] on a
/// fixed cadence to produce the sample pushed to the UI and the history store.
///
/// rates are computed over the real elapsed wall-clock window, not the nominal
/// cadence, so a late flush reports the correct bytes/sec instead of a spike.
pub struct Aggregator {
    apps: HashMap<AppId, AppAccum>,
    window_start_ms: u64,
}

struct AppAccum {
    name: Option<String>,
    /// cumulative for the whole session
    total: ByteCounts,
    /// accumulated since the last flush
    window: ByteCounts,
    connections: u32,
    /// whether any traffic landed since last flush (drops idle apps from ticks)
    active: bool,
}

impl Aggregator {
    pub fn new(now_ms: u64) -> Self {
        Aggregator {
            apps: HashMap::new(),
            window_start_ms: now_ms,
        }
    }

    /// add a network event's byte deltas for one app
    pub fn record(&mut self, app: &AppId, name: Option<&str>, sent: u64, recv: u64) {
        let entry = self.apps.entry(app.clone()).or_insert_with(|| AppAccum {
            name: None,
            total: ByteCounts::default(),
            window: ByteCounts::default(),
            connections: 0,
            active: false,
        });
        if entry.name.is_none() {
            if let Some(n) = name {
                entry.name = Some(n.to_string());
            }
        }
        let delta = ByteCounts { sent, recv };
        entry.total.add(delta);
        entry.window.add(delta);
        entry.active = true;
    }

    /// set the current open-connection count for an app
    pub fn set_connections(&mut self, app: &AppId, count: u32) {
        if let Some(entry) = self.apps.get_mut(app) {
            entry.connections = count;
            if count > 0 {
                entry.active = true;
            }
        }
    }

    /// produce a sample tick over the window since the last flush and reset the
    /// window. `now_ms` must be monotonic with respect to the previous flush.
    pub fn flush(&mut self, now_ms: u64) -> StatsTick {
        let elapsed_ms = now_ms.saturating_sub(self.window_start_ms).max(1);
        let per_sec = |bytes: u64| -> u64 {
            // bytes * 1000 / elapsed_ms, saturating on the multiply
            ((bytes as u128 * 1000) / elapsed_ms as u128) as u64
        };

        let mut samples: Vec<AppSample> = Vec::new();
        let mut total_rate_sent = 0u64;
        let mut total_rate_recv = 0u64;

        for (app, accum) in self.apps.iter_mut() {
            let rate_sent = per_sec(accum.window.sent);
            let rate_recv = per_sec(accum.window.recv);
            if accum.active || accum.connections > 0 {
                total_rate_sent = total_rate_sent.saturating_add(rate_sent);
                total_rate_recv = total_rate_recv.saturating_add(rate_recv);
                samples.push(AppSample {
                    app: app.clone(),
                    name: accum.name.clone(),
                    rate_sent,
                    rate_recv,
                    total: accum.total,
                    connections: accum.connections,
                });
            }
            accum.window = ByteCounts::default();
            accum.active = false;
        }

        // hottest first, so the UI's default sort needs no post-processing
        samples.sort_by(|a, b| {
            (b.rate_sent + b.rate_recv)
                .cmp(&(a.rate_sent + a.rate_recv))
                .then_with(|| b.total.total().cmp(&a.total.total()))
        });

        self.window_start_ms = now_ms;
        StatsTick {
            at_ms: now_ms,
            total_rate_sent,
            total_rate_recv,
            apps: samples,
        }
    }

    /// drop apps that have gone fully idle to bound memory. call periodically.
    pub fn prune_idle(&mut self) {
        self.apps
            .retain(|_, a| a.active || a.connections > 0 || a.total.total() > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(p: &str) -> AppId {
        AppId::from_path(p)
    }

    #[test]
    fn rate_is_bytes_over_elapsed_seconds() {
        let mut agg = Aggregator::new(0);
        agg.record(&app("c:/x.exe"), Some("X"), 1000, 2000);
        // flush one second later -> rate equals the window bytes
        let tick = agg.flush(1000);
        assert_eq!(tick.apps.len(), 1);
        let s = &tick.apps[0];
        assert_eq!(s.rate_sent, 1000);
        assert_eq!(s.rate_recv, 2000);
        assert_eq!(s.total.sent, 1000);
        assert_eq!(s.total.recv, 2000);
        assert_eq!(tick.total_rate_sent, 1000);
        assert_eq!(tick.total_rate_recv, 2000);
    }

    #[test]
    fn half_second_window_doubles_the_rate() {
        let mut agg = Aggregator::new(0);
        agg.record(&app("c:/x.exe"), None, 500, 0);
        let tick = agg.flush(500);
        assert_eq!(tick.apps[0].rate_sent, 1000);
    }

    #[test]
    fn totals_accumulate_across_flushes_but_rate_resets() {
        let mut agg = Aggregator::new(0);
        agg.record(&app("c:/x.exe"), None, 100, 0);
        let _ = agg.flush(1000);
        // no traffic in the next window: app is idle, absent from the tick, but
        // its cumulative total is retained
        let tick = agg.flush(2000);
        assert!(tick.apps.is_empty());
        agg.record(&app("c:/x.exe"), None, 50, 0);
        let tick = agg.flush(3000);
        assert_eq!(tick.apps[0].total.sent, 150);
        assert_eq!(tick.apps[0].rate_sent, 50);
    }

    #[test]
    fn samples_sorted_hottest_first() {
        let mut agg = Aggregator::new(0);
        agg.record(&app("c:/slow.exe"), None, 10, 0);
        agg.record(&app("c:/fast.exe"), None, 9000, 0);
        let tick = agg.flush(1000);
        assert_eq!(tick.apps[0].app, app("c:/fast.exe"));
        assert_eq!(tick.apps[1].app, app("c:/slow.exe"));
    }

    #[test]
    fn prune_drops_apps_with_no_traffic_ever() {
        let mut agg = Aggregator::new(0);
        agg.record(&app("c:/x.exe"), None, 0, 0);
        agg.set_connections(&app("c:/x.exe"), 0);
        let _ = agg.flush(1000);
        agg.prune_idle();
        let tick = agg.flush(2000);
        assert!(tick.apps.is_empty());
    }
}
