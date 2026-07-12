//! per-app allow/block enforcement on Linux. nftables has no match for "this
//! executable" the way the Windows Filtering Platform keys on an app id, so iris
//! decides per connection in userspace, the model OpenSnitch established: a small
//! nftables table queues the first packet of every new flow to NFQUEUE, and a
//! verdict thread resolves that packet to the owning process, matches it against
//! the rule set, and returns accept or drop.
//!
//! the queue rules carry the `bypass` flag, so if the verdict thread is not
//! listening packets pass rather than the machine losing all networking; and the
//! rules are installed only while at least one rule exists, so a stock install
//! with no rules adds zero per-packet overhead. this type is named `Wfp` to match
//! the Windows firewall seam the service calls through.

use crate::proc::PidCache;
use crate::sockets;
use iris_core::{AppId, Direction, EngineError, EngineResult, RuleAction};
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const TABLE: &str = "iris";
const QUEUE_OUT: u16 = 0;
const QUEUE_IN: u16 = 1;

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
        let mut threads = Vec::new();
        for (queue, dir) in [(QUEUE_OUT, Direction::Outbound), (QUEUE_IN, Direction::Inbound)] {
            let rules = rules.clone();
            let stop = stop.clone();
            let handle = std::thread::Builder::new()
                .name(format!("iris-verdict-{queue}"))
                .spawn(move || verdict_loop(queue, dir, rules, stop))
                .map_err(|e| EngineError::Os(format!("cannot start verdict thread: {e}")))?;
            threads.push(handle);
        }
        Ok(Wfp {
            rules,
            stop,
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
        self.sync_hook()?;
        Ok(vec![id])
    }

    /// remove the rules backing the given ids, mapping each id back to the
    /// app+direction it enforced, then re-sync the hook
    pub fn remove(&mut self, filter_ids: &[u64]) -> EngineResult<()> {
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
/// flow to userspace in each direction, with bypass so a missing listener fails
/// open. a priority just before the standard filter hook lets iris decide before
/// a distro firewall.
fn install_table() -> EngineResult<()> {
    let ruleset = format!(
        "table inet {TABLE} {{
    chain output {{
        type filter hook output priority -10; policy accept;
        ct state new queue num {QUEUE_OUT} bypass
    }}
    chain input {{
        type filter hook input priority -10; policy accept;
        ct state new queue num {QUEUE_IN} bypass
    }}
}}
"
    );
    // recreate cleanly so a stale table never doubles the hook
    remove_table();
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
fn verdict_loop(queue: u16, dir: Direction, rules: Arc<Mutex<RuleMap>>, stop: Arc<AtomicBool>) {
    let mut nfq = match nfq::Queue::open() {
        Ok(q) => q,
        Err(e) => {
            tracing::error!("cannot open NFQUEUE {queue}: {e}");
            return;
        }
    };
    if let Err(e) = nfq.bind(queue) {
        tracing::error!("cannot bind NFQUEUE {queue}: {e}");
        return;
    }
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
            if pkt.len() < 44 {
                return None;
            }
            let next = pkt[6];
            if !is_l4(next) {
                return None;
            }
            let mut s = [0u8; 16];
            let mut d = [0u8; 16];
            s.copy_from_slice(&pkt[8..24]);
            d.copy_from_slice(&pkt[24..40]);
            let l4 = &pkt[40..];
            let sport = u16::from_be_bytes([l4[0], l4[1]]);
            let dport = u16::from_be_bytes([l4[2], l4[3]]);
            Some((IpAddr::from(s), IpAddr::from(d), sport, dport))
        }
        _ => None,
    }
}

fn is_l4(proto: u8) -> bool {
    proto == libc::IPPROTO_TCP as u8 || proto == libc::IPPROTO_UDP as u8
}

/// resolves a packet's local endpoint to the owning executable, caching the
/// socket table and inode->pid map briefly so a burst of new connections does not
/// dump sock_diag per packet
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
        for s in sockets::dump() {
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
