use crate::model::{AppId, AppSample, ByteCounts, StatsTick};
use std::collections::HashMap;

/// accumulates per-app byte deltas between sample ticks and turns them into a
/// [`StatsTick`] on flush. the platform monitor calls [`Aggregator::record`] for
/// every attributed network event; the service's tracker calls
/// [`Aggregator::flush`] on a fixed cadence.
///
/// rates are computed over the real elapsed wall-clock window, not the nominal
/// cadence, so a late flush reports the correct bytes/sec instead of a spike.
/// the aggregator does not decide app lifetime: it keeps every app until the
/// tracker [`Aggregator::forget`]s it, and reports all of them each flush.
pub struct Aggregator {
    apps: HashMap<AppId, AppAccum>,
    window_start_ms: u64,
}

struct AppAccum {
    name: Option<String>,
    total: ByteCounts,
    window: ByteCounts,
}

impl Aggregator {
    pub fn new(now_ms: u64) -> Self {
        Aggregator {
            apps: HashMap::new(),
            window_start_ms: now_ms,
        }
    }

    fn entry(&mut self, app: &AppId) -> &mut AppAccum {
        self.apps.entry(app.clone()).or_insert_with(|| AppAccum {
            name: None,
            total: ByteCounts::default(),
            window: ByteCounts::default(),
        })
    }

    /// add a network event's byte deltas for one app
    pub fn record(&mut self, app: &AppId, name: Option<&str>, sent: u64, recv: u64) {
        let entry = self.entry(app);
        if entry.name.is_none() {
            if let Some(n) = name {
                entry.name = Some(n.to_string());
            }
        }
        let delta = ByteCounts { sent, recv };
        entry.total.add(delta);
        entry.window.add(delta);
    }

    /// ensure an app is tracked even with no bytes yet (e.g. it only holds open
    /// connections), so it appears in the next flush
    pub fn touch(&mut self, app: &AppId) {
        self.entry(app);
    }

    /// stop tracking an app; the tracker calls this once an app's grace elapses
    pub fn forget(&mut self, app: &AppId) {
        self.apps.remove(app);
    }

    /// produce a sample for every tracked app over the window since the last
    /// flush, then reset the window. lifecycle fields (`online`, `conns`) are
    /// left at defaults for the tracker to fill.
    pub fn flush(&mut self, now_ms: u64) -> StatsTick {
        let elapsed_ms = now_ms.saturating_sub(self.window_start_ms).max(1);
        let per_sec =
            |bytes: u64| -> u64 { ((bytes as u128 * 1000) / elapsed_ms as u128) as u64 };

        let mut samples: Vec<AppSample> = Vec::with_capacity(self.apps.len());
        let mut total_rate_sent = 0u64;
        let mut total_rate_recv = 0u64;

        for (app, accum) in self.apps.iter_mut() {
            let rate_sent = per_sec(accum.window.sent);
            let rate_recv = per_sec(accum.window.recv);
            total_rate_sent = total_rate_sent.saturating_add(rate_sent);
            total_rate_recv = total_rate_recv.saturating_add(rate_recv);
            samples.push(AppSample {
                app: app.clone(),
                name: accum.name.clone(),
                rate_sent,
                rate_recv,
                total: accum.total,
                connections: 0,
                online: false,
                conns: Vec::new(),
            });
            accum.window = ByteCounts::default();
        }

        self.window_start_ms = now_ms;
        StatsTick {
            at_ms: now_ms,
            total_rate_sent,
            total_rate_recv,
            apps: samples,
        }
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
    fn totals_accumulate_but_rate_resets_and_app_persists() {
        let mut agg = Aggregator::new(0);
        agg.record(&app("c:/x.exe"), None, 100, 0);
        let _ = agg.flush(1000);
        // idle window: app is still reported, now at rate 0, total retained
        let tick = agg.flush(2000);
        assert_eq!(tick.apps.len(), 1);
        assert_eq!(tick.apps[0].rate_sent, 0);
        assert_eq!(tick.apps[0].total.sent, 100);
        agg.record(&app("c:/x.exe"), None, 50, 0);
        let tick = agg.flush(3000);
        assert_eq!(tick.apps[0].total.sent, 150);
        assert_eq!(tick.apps[0].rate_sent, 50);
    }

    #[test]
    fn touch_tracks_a_connection_only_app() {
        let mut agg = Aggregator::new(0);
        agg.touch(&app("c:/conn.exe"));
        let tick = agg.flush(1000);
        assert_eq!(tick.apps.len(), 1);
        assert_eq!(tick.apps[0].total.total(), 0);
    }

    #[test]
    fn forget_drops_an_app() {
        let mut agg = Aggregator::new(0);
        agg.record(&app("c:/x.exe"), None, 100, 0);
        agg.forget(&app("c:/x.exe"));
        let tick = agg.flush(1000);
        assert!(tick.apps.is_empty());
    }
}
