//! per-app allow/block enforcement on Linux. nftables has no match for "this
//! executable" the way the Windows Filtering Platform keys on an app id, so iris
//! decides per connection in userspace, the model OpenSnitch established: a small
//! nftables table queues the first packet of every new flow to NFQUEUE, and a
//! verdict thread resolves that packet to the owning process, matches it against
//! the rule set, and returns accept or drop.
//!
//! queues are fail-closed while rules are active, and worker loss terminates the
//! engine so systemd can restart it. the rules are installed only while at least
//! one rule exists, so a stock install with no rules adds zero per-packet overhead.
//! this type is named `Wfp` to match the Windows firewall seam the service calls.

use crate::proc::PidCache;
use crate::sockets;
use iris_core::{AppId, Direction, EngineError, EngineResult, RuleAction};
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

const TABLE: &str = "iris";
const QUEUE_OUT: u16 = 17410;
const QUEUE_IN: u16 = 17411;
const WORKER_COUNT: u8 = 2;

/// one enforced rule: which action applies to an app in a direction
#[derive(Clone, Copy, PartialEq)]
enum Enforce {
    Block,
    Allow,
}

/// the shared rule set the verdict threads consult. the forward maps (per
/// direction, app id -> action) are what the hot verdict path reads; the id index
/// lets removal by synthetic id map back to the app+direction it enforced, so the
/// store's remove(ids) works exactly as it does against Windows filter ids.
#[derive(Default)]
struct RuleMap {
    out: HashMap<String, Enforce>,
    inbound: HashMap<String, Enforce>,
    by_id: HashMap<u64, (String, Direction)>,
}

impl RuleMap {
    fn lookup(&self, dir: Direction, key: &str) -> Option<Enforce> {
        match dir {
            Direction::Outbound => self.out.get(key).copied(),
            Direction::Inbound => self.inbound.get(key).copied(),
        }
    }

    fn insert(&mut self, id: u64, key: String, dir: Direction, action: Enforce) {
        match dir {
            Direction::Outbound => self.out.insert(key.clone(), action),
            Direction::Inbound => self.inbound.insert(key.clone(), action),
        };
        self.by_id.insert(id, (key, dir));
    }

    fn remove_id(&mut self, id: u64) {
        if let Some((key, dir)) = self.by_id.remove(&id) {
            if self
                .by_id
                .values()
                .any(|(other_key, other_dir)| other_key == &key && *other_dir == dir)
            {
                return;
            }
            match dir {
                Direction::Outbound => self.out.remove(&key),
                Direction::Inbound => self.inbound.remove(&key),
            };
        }
    }

    fn is_empty(&self) -> bool {
        self.out.is_empty() && self.inbound.is_empty()
    }
}

pub struct Wfp {
    rules: Arc<Mutex<RuleMap>>,
    stop: Arc<AtomicBool>,
    ready_workers: Arc<AtomicU8>,
    threads: Vec<std::thread::JoinHandle<()>>,
    next_id: AtomicU64,
    /// whether the nftables queue hook is currently installed
    hooked: bool,
}

// the verdict threads own their netlink queues; access to the shared rule map is
// behind a mutex, so a Send assertion for the handle is sound
unsafe impl Send for Wfp {}

impl Wfp {
    /// start the verdict threads and provision (empty) enforcement state. the
    /// nftables hook is not installed until the first rule is added.
    pub fn open() -> EngineResult<Wfp> {
        ensure_modules();
        let rules = Arc::new(Mutex::new(RuleMap::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let ready_workers = Arc::new(AtomicU8::new(0));
        let mut threads = Vec::new();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        for (queue, dir) in [
            (QUEUE_OUT, Direction::Outbound),
            (QUEUE_IN, Direction::Inbound),
        ] {
            let rules = rules.clone();
            let stop = stop.clone();
            let ready_workers = ready_workers.clone();
            let ready_tx = ready_tx.clone();
            let handle = std::thread::Builder::new()
                .name(format!("iris-verdict-{queue}"))
                .spawn(move || verdict_loop(queue, dir, rules, stop, ready_workers, ready_tx))
                .map_err(|e| EngineError::Os(format!("cannot start verdict thread: {e}")))?;
            threads.push(handle);
        }
        drop(ready_tx);
        for _ in 0..WORKER_COUNT {
            match ready_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    stop.store(true, Ordering::Release);
                    return Err(EngineError::Os(e));
                }
                Err(e) => {
                    stop.store(true, Ordering::Release);
                    return Err(EngineError::Os(format!(
                        "verdict worker stopped during startup: {e}"
                    )));
                }
            }
        }
        Ok(Wfp {
            rules,
            stop,
            ready_workers,
            threads,
            next_id: AtomicU64::new(1),
            hooked: false,
        })
    }

    /// wipe every iris rule and remove the nftables hook, leaving a clean slate.
    /// called on startup before rules re-apply, so a previous run's table never
    /// keeps enforcing.
    pub fn reset(&mut self) -> EngineResult<()> {
        *self.rules.lock().unwrap_or_else(|e| e.into_inner()) = RuleMap::default();
        remove_table();
        self.hooked = false;
        Ok(())
    }

    /// enforce a rule for one app+direction; returns a synthetic id the store
    /// keeps so it can remove the rule later. the actual matching lives in the
    /// verdict thread, so this just updates the shared map and (re)installs the
    /// hook when the rule set becomes non-empty.
    pub fn apply(
        &mut self,
        path: &str,
        direction: Direction,
        action: RuleAction,
    ) -> EngineResult<Vec<u64>> {
        self.ensure_healthy()?;
        let key = AppId::from_path(path).0;
        let enforce = match action {
            RuleAction::Block => Enforce::Block,
            RuleAction::Allow => Enforce::Allow,
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut map = self.rules.lock().unwrap_or_else(|e| e.into_inner());
            map.insert(id, key, direction, enforce);
        }
        if let Err(e) = self.sync_hook() {
            self.rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove_id(id);
            return Err(e);
        }
        Ok(vec![id])
    }

    /// remove the rules backing the given ids, mapping each id back to the
    /// app+direction it enforced, then re-sync the hook
    pub fn remove(&mut self, filter_ids: &[u64]) -> EngineResult<()> {
        self.ensure_healthy()?;
        {
            let mut map = self.rules.lock().unwrap_or_else(|e| e.into_inner());
            for id in filter_ids {
                map.remove_id(*id);
            }
        }
        self.sync_hook()
    }

    /// install the nftables queue hook when at least one rule exists, remove it
    /// when none do, so idle installs pay nothing per packet
    fn sync_hook(&mut self) -> EngineResult<()> {
        self.ensure_healthy()?;
        let empty = self
            .rules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty();
        if empty && self.hooked {
            remove_table();
            self.hooked = false;
        } else if !empty && !self.hooked {
            install_table()?;
            self.hooked = true;
        }
        Ok(())
    }

    fn ensure_healthy(&self) -> EngineResult<()> {
        if self.ready_workers.load(Ordering::Acquire) != WORKER_COUNT {
            return Err(EngineError::Os(
                "firewall verdict worker is unavailable".into(),
            ));
        }
        Ok(())
    }

    pub fn is_healthy(&self) -> bool {
        self.ready_workers.load(Ordering::Acquire) == WORKER_COUNT
    }
}

impl Drop for Wfp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        remove_table();
        // the verdict threads block in recv; they exit when their queue closes on
        // process teardown. detach rather than join so drop never hangs.
        self.threads.clear();
    }
}

/// make sure the netfilter modules the hook and verdict path need are loaded;
/// best-effort, since a monolithic kernel has them built in
fn ensure_modules() {
    for module in ["nfnetlink_queue", "nf_conntrack", "nf_tables"] {
        let _ = Command::new("modprobe").arg(module).status();
    }
}

/// the ruleset installed while rules exist: queue the first packet of every new
/// flow to userspace in each direction. a priority just before the standard
/// filter hook lets iris decide before
/// a distro firewall.
fn install_table() -> EngineResult<()> {
    let ruleset = format!(
        "table inet {TABLE} {{
    chain output {{
        type filter hook output priority -10; policy accept;
        ct state new queue num {QUEUE_OUT}
    }}
    chain input {{
        type filter hook input priority -10; policy accept;
        ct state new queue num {QUEUE_IN}
    }}
}}
"
    );
    run_nft(&ruleset)
}

fn remove_table() {
    // ignore failure: the table may not exist, which is the desired end state
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .output();
}

fn run_nft(ruleset: &str) -> EngineResult<()> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| EngineError::Os(format!("cannot run nft: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(ruleset.as_bytes())
            .map_err(|e| EngineError::Os(format!("cannot write nft ruleset: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| EngineError::Os(format!("nft did not complete: {e}")))?;
    if !out.status.success() {
        return Err(EngineError::Os(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// the NFQUEUE verdict loop for one direction. resolves each queued packet to the
/// owning executable and accepts or drops per the rule map; anything it cannot
/// resolve is accepted, so a lookup miss never silently cuts traffic.
fn verdict_loop(
    queue: u16,
    dir: Direction,
    rules: Arc<Mutex<RuleMap>>,
    stop: Arc<AtomicBool>,
    ready_workers: Arc<AtomicU8>,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let mut nfq = match nfq::Queue::open() {
        Ok(q) => q,
        Err(e) => {
            let _ = ready.send(Err(format!("cannot open NFQUEUE {queue}: {e}")));
            return;
        }
    };
    if let Err(e) = nfq.bind(queue) {
        let _ = ready.send(Err(format!("cannot bind NFQUEUE {queue}: {e}")));
        return;
    }
    ready_workers.fetch_add(1, Ordering::Release);
    let _ = ready.send(Ok(()));
    let mut resolver = Resolver::new();
    tracing::info!("firewall verdict thread on queue {queue} ready");
    while !stop.load(Ordering::Relaxed) {
        let mut msg = match nfq.recv() {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("NFQUEUE {queue} recv ended: {e}");
                break;
            }
        };
        let verdict = decide(msg.get_payload(), dir, &rules, &mut resolver);
        msg.set_verdict(verdict);
        if let Err(e) = nfq.verdict(msg) {
            tracing::debug!("NFQUEUE {queue} verdict failed: {e}");
            break;
        }
    }
    ready_workers.fetch_sub(1, Ordering::Release);
}

fn decide(
    packet: &[u8],
    dir: Direction,
    rules: &Arc<Mutex<RuleMap>>,
    resolver: &mut Resolver,
) -> nfq::Verdict {
    let Some(local) = local_endpoint(packet, dir) else {
        return nfq::Verdict::Accept;
    };
    let Some(exe) = resolver.exe_for(local) else {
        return nfq::Verdict::Accept;
    };
    let key = AppId::from_path(&exe).0;
    let map = rules.lock().unwrap_or_else(|e| e.into_inner());
    match map.lookup(dir, &key) {
        Some(Enforce::Block) => nfq::Verdict::Drop,
        _ => nfq::Verdict::Accept,
    }
}

/// the local (this-host) address+port of a queued packet: the source for an
/// outbound packet, the destination for an inbound one
fn local_endpoint(packet: &[u8], dir: Direction) -> Option<(IpAddr, u16)> {
    let (src, dst, sport, dport) = parse_tuple(packet)?;
    Some(match dir {
        Direction::Outbound => (src, sport),
        Direction::Inbound => (dst, dport),
    })
}

/// parse an IPv4 or IPv6 packet enough to get the addresses and ports
fn parse_tuple(pkt: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16)> {
    if pkt.is_empty() {
        return None;
    }
    match pkt[0] >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff != 0 {
                return None;
            }
            let proto = pkt[9];
            if !is_l4(proto) || pkt.len() < ihl + 4 {
                return None;
            }
            let src = IpAddr::from([pkt[12], pkt[13], pkt[14], pkt[15]]);
            let dst = IpAddr::from([pkt[16], pkt[17], pkt[18], pkt[19]]);
            let l4 = &pkt[ihl..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            Some((src, dst, sport, dport))
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let (_, offset) = ipv6_transport(pkt, pkt[6], 40)?;
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&pkt[8..24]);
            d.copy_from_slice(&pkt[24..40]);
            let l4 = pkt.get(offset..offset + 4)?;
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            Some((IpAddr::from(s), IpAddr::from(d), sport, dport))
        }
        _ => None,
    }
}

fn ipv6_transport(pkt: &[u8], mut next: u8, mut offset: usize) -> Option<(u8, usize)> {
    loop {
        match next {
            value if is_l4(value) => return Some((value, offset)),
            0 | 43 | 60 => {
                let header = pkt.get(offset..offset + 2)?;
                next = header[0];
                offset = offset.checked_add((header[1] as usize + 1) * 8)?;
            }
            44 => {
                let header = pkt.get(offset..offset + 8)?;
                let fragment = u16::from_be_bytes([header[2], header[3]]);
                if fragment & 0xfff8 != 0 {
                    return None;
                }
                next = header[0];
                offset = offset.checked_add(8)?;
            }
            51 => {
                let header = pkt.get(offset..offset + 2)?;
                next = header[0];
                offset = offset.checked_add((header[1] as usize + 2) * 4)?;
            }
            _ => return None,
        }
        if offset > pkt.len() {
            return None;
        }
    }
}

#[cfg(test)]
mod packet_tests {
    use super::parse_tuple;

    #[test]
    fn parses_ports_after_an_ipv6_extension_header() {
        let mut packet = vec![0u8; 52];
        packet[0] = 0x60;
        packet[6] = 0;
        packet[40] = libc::IPPROTO_TCP as u8;
        packet[41] = 0;
        packet[48..50].copy_from_slice(&1234u16.to_be_bytes());
        packet[50..52].copy_from_slice(&443u16.to_be_bytes());
        let (_, _, source, destination) = parse_tuple(&packet).unwrap();
        assert_eq!((source, destination), (1234, 443));
    }

    #[test]
    fn rejects_noninitial_ipv4_fragments() {
        let mut packet = vec![0u8; 24];
        packet[0] = 0x45;
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        packet[9] = libc::IPPROTO_TCP as u8;
        assert!(parse_tuple(&packet).is_none());
    }
}

fn is_l4(proto: u8) -> bool {
    proto == libc::IPPROTO_TCP as u8 || proto == libc::IPPROTO_UDP as u8
}

/// resolves a packet's local endpoint to the owning executable
struct Resolver {
    cache: PidCache,
    by_local: HashMap<(IpAddr, u16), u32>,
    owners: HashMap<u64, u32>,
    stamp: std::time::Instant,
}

impl Resolver {
    fn new() -> Self {
        Resolver {
            cache: PidCache::new(),
            by_local: HashMap::new(),
            owners: HashMap::new(),
            stamp: std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap_or_else(std::time::Instant::now),
        }
    }

    fn refresh(&mut self) {
        self.owners = crate::proc::socket_inode_owners();
        self.by_local.clear();
        for s in sockets::dump_for_attribution() {
            self.by_local
                .entry((s.local.0, s.local.1))
                .or_insert(s.inode as u32);
        }
        // periodically drop the pid->path cache so a reused pid cannot keep a
        // stale executable path
        self.cache.clear();
        self.stamp = std::time::Instant::now();
    }

    fn exe_for(&mut self, local: (IpAddr, u16)) -> Option<String> {
        if self.stamp.elapsed() > std::time::Duration::from_millis(200) {
            self.refresh();
        }
        if let Some(exe) = self.cached_exe(local) {
            return Some(exe);
        }
        self.refresh();
        self.cached_exe(local)
    }

    fn cached_exe(&mut self, local: (IpAddr, u16)) -> Option<String> {
        // try the exact local address first, then any socket on the port (a
        // wildcard-bound socket shows 0.0.0.0 in sock_diag)
        let inode = self
            .by_local
            .get(&local)
            .or_else(|| {
                let wild = if local.0.is_ipv4() {
                    IpAddr::from([0, 0, 0, 0])
                } else {
                    IpAddr::from([0u8; 16])
                };
                self.by_local.get(&(wild, local.1))
            })
            .copied()?;
        let pid = *self.owners.get(&(inode as u64))?;
        crate::proc::image_path_of(pid).or_else(|| self.cache.resolve(pid))
    }
}
