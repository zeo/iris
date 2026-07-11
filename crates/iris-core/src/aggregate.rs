use crate::model::ByteCounts;
use std::collections::HashMap;

/// one process's byte deltas for a sample window, produced by [`Aggregator::flush`].
/// the service's tracker groups these by app path and attaches connections.
#[derive(Debug, Clone, PartialEq)]
pub struct PidSample {
    pub pid: u32,
    pub path: String,
    pub name: Option<String>,
    pub rate_sent: u64,
    pub rate_recv: u64,
    pub total: ByteCounts,
}

/// accumulates per-process byte deltas between sample ticks. the platform
/// monitor calls [`Aggregator::record`] for every attributed network event
/// (keyed by owning PID); the service's tracker calls [`Aggregator::flush`] on a
/// fixed cadence and rolls the per-process rows up into per-app tree nodes.
///
/// rates are computed over the real elapsed wall-clock window, not the nominal
/// cadence. the aggregator does not decide process lifetime: it keeps every
/// process until the tracker [`Aggregator::forget`]s it.
pub struct Aggregator {
    procs: HashMap<u32, PidAccum>,
    window_start_ms: u64,
}

struct PidAccum {
    path: String,
    name: Option<String>,
    total: ByteCounts,
    window: ByteCounts,
}

impl Aggregator {
    pub fn new(now_ms: u64) -> Self {
        Aggregator {
            procs: HashMap::new(),
            window_start_ms: now_ms,
        }
    }

    fn entry(&mut self, pid: u32, path: &str) -> &mut PidAccum {
        self.procs.entry(pid).or_insert_with(|| PidAccum {
            path: path.to_string(),
            name: None,
            total: ByteCounts::default(),
            window: ByteCounts::default(),
        })
    }

    /// add a network event's byte deltas for one process
    pub fn record(&mut self, pid: u32, path: &str, name: Option<&str>, sent: u64, recv: u64) {
        let entry = self.entry(pid, path);
        if entry.name.is_none() {
            if let Some(n) = name {
                entry.name = Some(n.to_string());
            }
        }
        let delta = ByteCounts { sent, recv };
        entry.total.add(delta);
        entry.window.add(delta);
    }

    /// ensure a process is tracked even with no bytes yet (it only holds open
    /// connections), so it appears in the next flush
    pub fn touch(&mut self, pid: u32, path: &str) {
        self.entry(pid, path);
    }

    /// stop tracking a process once its grace elapses
    pub fn forget(&mut self, pid: u32) {
        self.procs.remove(&pid);
    }

    /// produce a per-process sample for every tracked process over the window
    /// since the last flush, then reset the window
    pub fn flush(&mut self, now_ms: u64) -> Vec<PidSample> {
        let elapsed_ms = now_ms.saturating_sub(self.window_start_ms).max(1);
        let per_sec =
            |bytes: u64| -> u64 { ((bytes as u128 * 1000) / elapsed_ms as u128) as u64 };

        let mut out = Vec::with_capacity(self.procs.len());
        for (pid, accum) in self.procs.iter_mut() {
            out.push(PidSample {
                pid: *pid,
                path: accum.path.clone(),
                name: accum.name.clone(),
                rate_sent: per_sec(accum.window.sent),
                rate_recv: per_sec(accum.window.recv),
                total: accum.total,
            });
            accum.window = ByteCounts::default();
        }
        self.window_start_ms = now_ms;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_is_bytes_over_elapsed_seconds() {
        let mut agg = Aggregator::new(0);
        agg.record(100, "c:/x.exe", Some("X"), 1000, 2000);
        let out = agg.flush(1000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rate_sent, 1000);
        assert_eq!(out[0].rate_recv, 2000);
        assert_eq!(out[0].total.sent, 1000);
    }

    #[test]
    fn half_second_window_doubles_the_rate() {
        let mut agg = Aggregator::new(0);
        agg.record(1, "c:/x.exe", None, 500, 0);
        assert_eq!(agg.flush(500)[0].rate_sent, 1000);
    }

    #[test]
    fn totals_accumulate_but_rate_resets_and_proc_persists() {
        let mut agg = Aggregator::new(0);
        agg.record(1, "c:/x.exe", None, 100, 0);
        let _ = agg.flush(1000);
        let out = agg.flush(2000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rate_sent, 0);
        assert_eq!(out[0].total.sent, 100);
    }

    #[test]
    fn separate_pids_stay_separate() {
        let mut agg = Aggregator::new(0);
        agg.record(1, "c:/x.exe", None, 100, 0);
        agg.record(2, "c:/x.exe", None, 200, 0);
        let out = agg.flush(1000);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn touch_then_forget() {
        let mut agg = Aggregator::new(0);
        agg.touch(5, "c:/conn.exe");
        assert_eq!(agg.flush(1000).len(), 1);
        agg.forget(5);
        assert!(agg.flush(2000).is_empty());
    }
}
