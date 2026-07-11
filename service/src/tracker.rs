//! turns the raw data sources into the per-app tree the UI renders. byte rates
//! come per-process from the ETW [`Aggregator`]; connections (with host names and
//! direction) come from the platform enumerator. processes are grouped under
//! their app, and each process carries its own online/offline lifecycle: one
//! that stops connecting enters a grace window (shown red) before it is dropped.

use iris_core::{AppId, Aggregator, AppSample, ByteCounts, Conn, ProcSample, StatsTick};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// how long a process lingers as "offline" after its last connection or byte
const GRACE_MS: u64 = 20_000;

pub struct Tracker {
    agg: Arc<Mutex<Aggregator>>,
    #[cfg(windows)]
    conns: iris_platform_win::ConnCounter,
    /// when each idle process went offline; absent while active. keyed by PID.
    offline_since: HashMap<u32, u64>,
}

impl Tracker {
    #[cfg(windows)]
    pub fn new(agg: Arc<Mutex<Aggregator>>, dns: iris_platform_win::DnsMap) -> Self {
        Tracker {
            agg,
            conns: iris_platform_win::ConnCounter::new(dns),
            offline_since: HashMap::new(),
        }
    }

    #[cfg(not(windows))]
    pub fn new(agg: Arc<Mutex<Aggregator>>) -> Self {
        Tracker {
            agg,
            offline_since: HashMap::new(),
        }
    }

    fn connections(&mut self) -> HashMap<u32, (String, Vec<Conn>)> {
        #[cfg(windows)]
        {
            self.conns.by_pid()
        }
        #[cfg(not(windows))]
        {
            HashMap::new()
        }
    }

    pub fn tick(&mut self, now: u64) -> StatsTick {
        let conns_by_pid = self.connections();

        {
            let mut a = self.agg.lock().expect("aggregator poisoned");
            for (pid, (path, _)) in &conns_by_pid {
                a.touch(*pid, path);
            }
        }
        let pid_samples = self.agg.lock().expect("aggregator poisoned").flush(now);

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

            let proc = ProcSample {
                pid: ps.pid,
                rate_sent: ps.rate_sent,
                rate_recv: ps.rate_recv,
                total: ps.total,
                online: active,
                conns,
            };
            let acc = apps.entry(ps.path).or_insert_with(AppAcc::default);
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
            let mut a = self.agg.lock().expect("aggregator poisoned");
            for pid in &expired {
                a.forget(*pid);
                self.offline_since.remove(pid);
            }
        }

        let mut out: Vec<AppSample> = apps
            .into_iter()
            .map(|(path, acc)| {
                let mut procs = acc.procs;
                procs.sort_by(|a, b| (b.rate_sent + b.rate_recv).cmp(&(a.rate_sent + a.rate_recv)));
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
