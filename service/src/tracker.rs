//! turns the raw data sources into the per-app tree the UI renders. byte rates
//! come per-process from the ETW [`Aggregator`]; connections (with host names and
//! direction) come from the platform enumerator. processes are grouped under
//! their app, and each process carries its own online/offline lifecycle: one
//! that stops connecting enters a grace window (shown red) before it is dropped.

use iris_core::{AppId, Aggregator, AppSample, ByteCounts, Conn, ProcSample, StatsTick};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// how long a process lingers as "offline" after its last connection or byte
const GRACE_MS: u64 = 20_000;
/// how long a connection stays in the list after it drops from a snapshot, so
/// short-lived connections do not make the view churn every second
const CONN_GRACE_MS: u64 = 4_000;

type ConnKey = (String, u16, u16);

/// lock the shared aggregator, recovering the guard if the ETW callback thread
/// panicked while holding it. the accumulator is just byte counters, so a
/// poisoned lock must never crash the flush loop and stop monitoring. a free
/// function (not a `&self` method) so it borrows only the mutex, leaving the
/// tracker's other fields free to mutate alongside the guard.
fn lock_agg(agg: &Mutex<Aggregator>) -> MutexGuard<'_, Aggregator> {
    agg.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct Tracker {
    agg: Arc<Mutex<Aggregator>>,
    #[cfg(windows)]
    conns: iris_platform_win::ConnCounter,
    #[cfg(windows)]
    svc: iris_platform_win::ServiceMap,
    /// tick counter, so the service map is re-enumerated on a slow cadence
    ticks: u64,
    /// when each idle process went offline; absent while active. keyed by PID.
    offline_since: HashMap<u32, u64>,
    /// recently-seen connections per PID, held briefly past their last sighting
    conn_history: HashMap<u32, HashMap<ConnKey, (Conn, u64)>>,
    /// last known image path per PID, so graced connections keep their app
    pid_path: HashMap<u32, String>,
}

impl Tracker {
    #[cfg(windows)]
    pub fn new(agg: Arc<Mutex<Aggregator>>, dns: iris_platform_win::DnsMap) -> Self {
        Tracker {
            agg,
            conns: iris_platform_win::ConnCounter::new(dns),
            svc: iris_platform_win::ServiceMap::new(),
            ticks: 0,
            offline_since: HashMap::new(),
            conn_history: HashMap::new(),
            pid_path: HashMap::new(),
        }
    }

    #[cfg(not(windows))]
    pub fn new(agg: Arc<Mutex<Aggregator>>) -> Self {
        Tracker {
            agg,
            ticks: 0,
            offline_since: HashMap::new(),
            conn_history: HashMap::new(),
            pid_path: HashMap::new(),
        }
    }

    fn snapshot(&mut self) -> HashMap<u32, (String, Vec<Conn>)> {
        #[cfg(windows)]
        {
            self.conns.by_pid()
        }
        #[cfg(not(windows))]
        {
            HashMap::new()
        }
    }

    /// current connections per PID, each held for a short grace past its last
    /// sighting so the UI list stays stable instead of flickering every tick
    fn connections(&mut self, now: u64) -> HashMap<u32, (String, Vec<Conn>)> {
        let fresh = self.snapshot();
        for (pid, (path, conns)) in &fresh {
            self.pid_path.insert(*pid, path.clone());
            let hist = self.conn_history.entry(*pid).or_default();
            for c in conns {
                let key = (c.remote.addr.to_string(), c.remote.port, c.local_port);
                hist.insert(key, (c.clone(), now));
            }
        }
        // age out stale connections and empty pids
        for hist in self.conn_history.values_mut() {
            hist.retain(|_, (_, seen)| now.saturating_sub(*seen) <= CONN_GRACE_MS);
        }
        self.conn_history.retain(|_, h| !h.is_empty());
        self.pid_path.retain(|pid, _| self.conn_history.contains_key(pid));

        self.conn_history
            .iter()
            .filter_map(|(pid, hist)| {
                let path = self.pid_path.get(pid)?.clone();
                let mut conns: Vec<Conn> = hist.values().map(|(c, _)| c.clone()).collect();
                conns.sort_by_key(|c| c.remote.port);
                Some((*pid, (path, conns)))
            })
            .collect()
    }

    pub fn tick(&mut self, now: u64) -> StatsTick {
        // service to pid bindings are stable, so re-enumerate them only every
        // tenth tick (~10s) rather than on every sample
        #[cfg(windows)]
        if self.ticks.is_multiple_of(10) {
            self.svc.refresh();
        }
        self.ticks = self.ticks.wrapping_add(1);

        let conns_by_pid = self.connections(now);

        {
            let mut a = lock_agg(&self.agg);
            for (pid, (path, _)) in &conns_by_pid {
                a.touch(*pid, path);
            }
        }
        let pid_samples = lock_agg(&self.agg).flush(now);

        let mut apps: HashMap<String, AppAcc> = HashMap::new();
        let mut expired: Vec<u32> = Vec::new();

        for ps in pid_samples {
            let conns = conns_by_pid.get(&ps.pid).map(|(_, c)| c.clone()).unwrap_or_default();
            let active = !conns.is_empty() || ps.rate_sent > 0 || ps.rate_recv > 0;

            if active {
                self.offline_since.remove(&ps.pid);
            } else {
                self.offline_since.entry(ps.pid).or_insert(now);
            }
            if let Some(&since) = self.offline_since.get(&ps.pid) {
                if now.saturating_sub(since) > GRACE_MS {
                    expired.push(ps.pid);
                    continue;
                }
            }

            #[cfg(windows)]
            let service = self.svc.get(ps.pid).map(|names| names.join(", "));
            #[cfg(not(windows))]
            let service: Option<String> = None;

            let proc = ProcSample {
                pid: ps.pid,
                service,
                rate_sent: ps.rate_sent,
                rate_recv: ps.rate_recv,
                total: ps.total,
                online: active,
                conns,
            };
            let acc = apps.entry(ps.path).or_default();
            if acc.name.is_none() {
                acc.name = ps.name;
            }
            acc.total.add(proc.total);
            acc.rate_sent = acc.rate_sent.saturating_add(proc.rate_sent);
            acc.rate_recv = acc.rate_recv.saturating_add(proc.rate_recv);
            acc.online |= proc.online;
            acc.connections += proc.conns.len() as u32;
            acc.procs.push(proc);
        }

        if !expired.is_empty() {
            let mut a = lock_agg(&self.agg);
            for pid in &expired {
                a.forget(*pid);
                self.offline_since.remove(pid);
            }
        }

        let mut out: Vec<AppSample> = apps
            .into_iter()
            .map(|(path, acc)| {
                let mut procs = acc.procs;
                procs.sort_by_key(|p| std::cmp::Reverse(p.rate_sent + p.rate_recv));
                AppSample {
                    app: AppId::from_path(&path),
                    name: acc.name,
                    rate_sent: acc.rate_sent,
                    rate_recv: acc.rate_recv,
                    total: acc.total,
                    connections: acc.connections,
                    online: acc.online,
                    processes: procs,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            (b.rate_sent + b.rate_recv)
                .cmp(&(a.rate_sent + a.rate_recv))
                .then_with(|| b.total.total().cmp(&a.total.total()))
        });

        let total_sent = out.iter().fold(0u64, |n, a| n.saturating_add(a.rate_sent));
        let total_recv = out.iter().fold(0u64, |n, a| n.saturating_add(a.rate_recv));
        StatsTick {
            at_ms: now,
            total_rate_sent: total_sent,
            total_rate_recv: total_recv,
            apps: out,
        }
    }

    pub fn clear_cache(&mut self) {
        #[cfg(windows)]
        self.conns.clear_cache();
    }
}

#[derive(Default)]
struct AppAcc {
    name: Option<String>,
    total: ByteCounts,
    rate_sent: u64,
    rate_recv: u64,
    online: bool,
    connections: u32,
    procs: Vec<ProcSample>,
}
