//! the Linux byte monitor, the counterpart to the Windows ETW monitor. it fills
//! the shared aggregator with per-process throughput and captures the DNS names
//! processes resolve, from three background threads:
//!
//! - accounting polls sock_diag once a second and diffs each TCP socket's
//!   tcp_info byte counters, attributing the delta to the owning pid; UDP bytes
//!   come from conntrack where it is available. this feeds the identical
//!   [`Aggregator`], so the service is unchanged
//! - a sock_diag destroy subscription records the final counter delta when an
//!   observed TCP socket closes between accounting snapshots
//! - a perf tracepoint records the process and tuple for connections whose full
//!   lifetime falls between snapshots, so the destroy record remains attributable
//! - the DNS sniffer reads DNS responses off a packet socket and records each
//!   answered address under the host name that produced it.

use crate::adapters::AdapterMap;
use crate::ct;
use crate::dns::{self, DnsMap};
use crate::proc::{self, PidCache};
use crate::sockets::{self, SockInfo};
use crate::trace::{DatagramBytes, DatagramListener, FlowKey, FlowOwner, OwnerListener};
use iris_core::{AdapterKind, Aggregator, Direction, Endpoint, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Monitor {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    cache: Arc<Mutex<PidCache>>,
    adapters: Arc<AdapterMap>,
    recent_flows: Arc<Mutex<Vec<RecentFlow>>>,
}

#[derive(Clone)]
pub struct RecentFlow {
    pub path: String,
    pub remote: Endpoint,
    pub direction: Direction,
}

#[derive(Clone)]
struct AccountingShared {
    cache: Arc<Mutex<PidCache>>,
    adapters: Arc<AdapterMap>,
    recent_flows: Arc<Mutex<Vec<RecentFlow>>>,
}

impl Monitor {
    pub fn start(agg: Arc<Mutex<Aggregator>>, dns_map: DnsMap) -> anyhow::Result<Monitor> {
        let stop = Arc::new(AtomicBool::new(false));
        let cache = Arc::new(Mutex::new(PidCache::new()));
        let adapters = Arc::new(AdapterMap::new());
        let recent_flows = Arc::new(Mutex::new(Vec::new()));
        let shared = AccountingShared {
            cache: cache.clone(),
            adapters: adapters.clone(),
            recent_flows: recent_flows.clone(),
        };
        ct::enable_acct();

        let mut threads = Vec::new();
        let (tcp_tx, tcp_rx) = std::sync::mpsc::channel();

        let close_listener = sockets::DestroyListener::open()
            .inspect_err(|error| tracing::warn!("TCP close accounting unavailable: {error}"))
            .ok();
        let owner_listener = OwnerListener::open()
            .inspect_err(|error| tracing::warn!("short TCP attribution unavailable: {error}"))
            .ok();
        let datagram_listener = DatagramListener::open()
            .inspect_err(|error| tracing::warn!("event-backed UDP accounting unavailable: {error}"))
            .ok();
        let udp_events_active = Arc::new(AtomicBool::new(datagram_listener.is_some()));
        if close_listener.is_some() || owner_listener.is_some() || datagram_listener.is_some() {
            let stop = stop.clone();
            let udp_events_active = udp_events_active.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("iris-net-events".into())
                    .spawn(move || {
                        network_event_loop(
                            stop,
                            owner_listener,
                            close_listener,
                            datagram_listener,
                            udp_events_active,
                            tcp_tx,
                        )
                    })?,
            );
        }

        let acct = {
            let stop = stop.clone();
            let snapshots = dns_map.clone();
            let udp_events_active = udp_events_active.clone();
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("iris-acct".into())
                .spawn(move || {
                    accounting_loop(stop, agg, shared, snapshots, tcp_rx, udp_events_active)
                })?
        };
        threads.push(acct);

        // the DNS sniffer needs a packet socket (CAP_NET_RAW); if it cannot open
        // one the connection view still works on raw addresses, so this is a warn
        match DnsSniffer::open() {
            Ok(sniffer) => {
                let stop = stop.clone();
                let handle = std::thread::Builder::new()
                    .name("iris-dns".into())
                    .spawn(move || sniffer.run(stop, dns_map))?;
                threads.push(handle);
                tracing::info!("DNS name capture running");
            }
            Err(e) => tracing::warn!("DNS name capture unavailable: {e}"),
        }

        tracing::info!("byte monitor running");
        Ok(Monitor {
            stop,
            threads,
            cache,
            adapters,
            recent_flows,
        })
    }

    /// clear the pid->path cache; called periodically to bound pid-reuse staleness
    pub fn clear_cache(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
    }

    /// rebuild the address-to-adapter table on a slow cadence
    pub fn refresh_adapters(&self) {
        self.adapters.refresh();
    }

    pub fn take_recent_flows(&self) -> Vec<RecentFlow> {
        self.recent_flows
            .lock()
            .map(|mut flows| std::mem::take(&mut *flows))
            .unwrap_or_default()
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in std::mem::take(&mut self.threads) {
            let _ = t.join();
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// per-socket byte baseline kept between polls, so a socket's cumulative
/// tcp_info counters become per-window deltas. keyed by the socket cookie.
#[derive(Default, Clone, Copy)]
struct Baseline {
    sent: u64,
    recv: u64,
    missed: u8,
}

fn accounting_loop(
    stop: Arc<AtomicBool>,
    agg: Arc<Mutex<Aggregator>>,
    shared: AccountingShared,
    snapshots: DnsMap,
    network_events: std::sync::mpsc::Receiver<NetworkEvent>,
    udp_events_active: Arc<AtomicBool>,
) {
    let AccountingShared {
        cache,
        adapters,
        recent_flows,
    } = shared;
    let mut tcp_seen: HashMap<u64, Baseline> = HashMap::new();
    let mut tcp_owners: HashMap<u64, TcpOwner> = HashMap::new();
    let mut flow_owners: HashMap<FlowKey, (TcpOwner, std::time::Instant)> = HashMap::new();
    let mut pending_closed: HashMap<FlowKey, (SockInfo, std::time::Instant)> = HashMap::new();
    let mut udp_seen: HashMap<UdpKey, Baseline> = HashMap::new();
    let mut primed = false;
    let mut udp_event_was_active = udp_events_active.load(Ordering::Relaxed);

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(1));
        let owners = proc::socket_inode_owners();
        let mut socks = sockets::dump_for_attribution();
        crate::fw::publish_attribution(&owners, &socks);
        socks.retain(|socket| !socket.is_listener());
        dns::record_sockets(&snapshots, &socks, &owners);

        for event in network_events.try_iter() {
            match event {
                NetworkEvent::Owner(owner) => {
                    let path = resolve_path(&cache, owner.pid).unwrap_or(owner.path);
                    flow_owners.insert(
                        owner.key,
                        (
                            TcpOwner {
                                pid: owner.pid,
                                path,
                                kind: adapters.kind_for(owner.key.local.0, owner.key.remote.0),
                            },
                            std::time::Instant::now(),
                        ),
                    );
                }
                NetworkEvent::Closed(socket) => {
                    let owner = closed_owner(&socket, &tcp_seen, &tcp_owners, &flow_owners);
                    let remote = socket.remote;
                    if !account_closed_tcp(&socket, &tcp_seen, &tcp_owners, &flow_owners, &agg) {
                        pending_closed.insert(
                            FlowKey {
                                local: socket.local,
                                remote: socket.remote,
                            },
                            (socket, std::time::Instant::now()),
                        );
                    } else if let Some(owner) = owner {
                        record_recent_flow(&recent_flows, &owner.path, remote);
                    }
                }
                NetworkEvent::Datagram(bytes) => {
                    if bytes.sent != 0 || bytes.recv != 0 {
                        let path = resolve_path(&cache, bytes.pid).unwrap_or(bytes.path);
                        agg.lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .record(
                                bytes.pid,
                                &path,
                                None,
                                AdapterKind::Other,
                                bytes.sent,
                                bytes.recv,
                            );
                    }
                }
            }
        }
        pending_closed.retain(|_, (socket, queued)| {
            let owner = closed_owner(socket, &tcp_seen, &tcp_owners, &flow_owners);
            if account_closed_tcp(socket, &tcp_seen, &tcp_owners, &flow_owners, &agg) {
                if let Some(owner) = owner {
                    record_recent_flow(&recent_flows, &owner.path, socket.remote);
                }
                false
            } else {
                queued.elapsed() < Duration::from_secs(5)
            }
        });
        flow_owners.retain(|_, (_, seen)| seen.elapsed() < Duration::from_secs(30));
        account_tcp(
            &socks,
            &owners,
            &mut tcp_seen,
            &agg,
            &cache,
            &adapters,
            primed,
        );
        tcp_owners.retain(|cookie, _| tcp_seen.contains_key(cookie));
        tcp_owners.extend(tcp_owner_map(&socks, &owners, &cache, &adapters));
        let event_accounted_udp = udp_events_active.load(Ordering::Relaxed);
        if !event_accounted_udp {
            account_udp(
                &socks,
                &owners,
                &mut udp_seen,
                &agg,
                &cache,
                &adapters,
                primed && !udp_event_was_active,
            );
        }
        udp_event_was_active = event_accounted_udp;
        primed = true;
    }
}

#[derive(Clone)]
struct TcpOwner {
    pid: u32,
    path: String,
    kind: iris_core::AdapterKind,
}

fn tcp_owner_map(
    socks: &[SockInfo],
    owners: &HashMap<u64, u32>,
    cache: &Mutex<PidCache>,
    adapters: &AdapterMap,
) -> HashMap<u64, TcpOwner> {
    let mut tracked = HashMap::new();
    for socket in socks.iter().filter(|socket| socket.is_tcp()) {
        let Some(&pid) = owners.get(&(socket.inode as u64)) else {
            continue;
        };
        let Some(path) = resolve_path(cache, pid) else {
            continue;
        };
        tracked.insert(
            socket.cookie,
            TcpOwner {
                pid,
                path,
                kind: adapters.kind_for(socket.local.0, socket.remote.0),
            },
        );
    }
    tracked
}

fn closed_owner(
    socket: &SockInfo,
    seen: &HashMap<u64, Baseline>,
    owners: &HashMap<u64, TcpOwner>,
    flow_owners: &HashMap<FlowKey, (TcpOwner, std::time::Instant)>,
) -> Option<TcpOwner> {
    if seen.contains_key(&socket.cookie) {
        return owners.get(&socket.cookie).cloned();
    }
    flow_owners
        .get(&FlowKey {
            local: socket.local,
            remote: socket.remote,
        })
        .map(|(owner, _)| owner.clone())
}

fn record_recent_flow(recent_flows: &Mutex<Vec<RecentFlow>>, path: &str, remote: (IpAddr, u16)) {
    let flow = RecentFlow {
        path: path.to_owned(),
        remote: Endpoint {
            addr: remote.0,
            port: remote.1,
            protocol: Protocol::Tcp,
        },
        direction: Direction::Outbound,
    };
    if let Ok(mut flows) = recent_flows.lock() {
        flows.push(flow);
        if flows.len() > 256 {
            flows.drain(..128);
        }
    }
}

fn account_closed_tcp(
    socket: &SockInfo,
    seen: &HashMap<u64, Baseline>,
    owners: &HashMap<u64, TcpOwner>,
    flow_owners: &HashMap<FlowKey, (TcpOwner, std::time::Instant)>,
    agg: &Mutex<Aggregator>,
) -> bool {
    let Some((sent, recv)) = socket.bytes else {
        return true;
    };
    let (sent, recv, owner) = match seen.get(&socket.cookie) {
        Some(base) => {
            let Some(owner) = owners.get(&socket.cookie) else {
                return false;
            };
            (
                sent.saturating_sub(base.sent),
                recv.saturating_sub(base.recv),
                owner,
            )
        }
        None => {
            let key = FlowKey {
                local: socket.local,
                remote: socket.remote,
            };
            let Some((owner, _)) = flow_owners.get(&key) else {
                return false;
            };
            (sent, recv, owner)
        }
    };
    if sent == 0 && recv == 0 {
        return true;
    }
    agg.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .record(owner.pid, &owner.path, None, owner.kind, sent, recv);
    true
}

enum NetworkEvent {
    Owner(FlowOwner),
    Closed(SockInfo),
    Datagram(DatagramBytes),
}

fn network_event_loop(
    stop: Arc<AtomicBool>,
    mut owners: Option<OwnerListener>,
    mut closes: Option<sockets::DestroyListener>,
    mut datagrams: Option<DatagramListener>,
    udp_events_active: Arc<AtomicBool>,
    sender: std::sync::mpsc::Sender<NetworkEvent>,
) {
    let mut found_owners = Vec::new();
    let mut closed = Vec::new();
    let mut bytes = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let mut waited = false;
        if let Some(listener) = owners.as_mut() {
            match listener.receive(100, &mut found_owners) {
                Ok(()) => waited = true,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    tracing::warn!("short TCP attribution stopped: {error}");
                    owners = None;
                }
            }
        }
        for owner in found_owners.drain(..) {
            if sender.send(NetworkEvent::Owner(owner)).is_err() {
                return;
            }
        }

        if let Some(listener) = datagrams.as_mut() {
            match listener.receive(if waited { 0 } else { 100 }, &mut bytes) {
                Ok(()) => waited = true,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    tracing::warn!("event-backed UDP accounting stopped: {error}");
                    datagrams = None;
                    udp_events_active.store(false, Ordering::Relaxed);
                }
            }
        }
        for datagram in bytes.drain(..) {
            if sender.send(NetworkEvent::Datagram(datagram)).is_err() {
                return;
            }
        }

        while let Some(listener) = closes.as_mut() {
            match listener.receive(&mut closed) {
                Ok(()) => {
                    for socket in closed.drain(..) {
                        if sender.send(NetworkEvent::Closed(socket)).is_err() {
                            return;
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    tracing::warn!("TCP close accounting stopped: {error}");
                    closes = None;
                    break;
                }
            }
        }
        if !waited {
            std::thread::sleep(Duration::from_millis(200));
        }
        if owners.is_none() && closes.is_none() && datagrams.is_none() {
            udp_events_active.store(false, Ordering::Relaxed);
            return;
        }
    }
    udp_events_active.store(false, Ordering::Relaxed);
}

fn resolve_path(cache: &Mutex<PidCache>, pid: u32) -> Option<String> {
    cache.lock().ok()?.resolve(pid)
}

fn account_tcp(
    socks: &[SockInfo],
    owners: &HashMap<u64, u32>,
    seen: &mut HashMap<u64, Baseline>,
    agg: &Mutex<Aggregator>,
    cache: &Mutex<PidCache>,
    adapters: &AdapterMap,
    count_new: bool,
) {
    // keep a vanished socket briefly so its asynchronous destroy event can
    // still match the last owner and baseline if userspace scheduling lags
    let mut live: HashMap<u64, Baseline> = seen
        .iter()
        .filter_map(|(cookie, baseline)| {
            let missed = baseline.missed.saturating_add(1);
            (missed <= 2).then_some((
                *cookie,
                Baseline {
                    missed,
                    ..*baseline
                },
            ))
        })
        .collect();
    for s in socks {
        let Some((cur_sent, cur_recv)) = s.bytes else {
            continue;
        };
        if !s.is_tcp() {
            continue;
        }
        let (d_sent, d_recv) = byte_delta(cur_sent, cur_recv, seen.get(&s.cookie), count_new);
        live.insert(
            s.cookie,
            Baseline {
                sent: cur_sent,
                recv: cur_recv,
                missed: 0,
            },
        );
        if d_sent == 0 && d_recv == 0 {
            continue;
        }
        let Some(&pid) = owners.get(&(s.inode as u64)) else {
            continue;
        };
        let Some(path) = resolve_path(cache, pid) else {
            continue;
        };
        let kind = adapters.kind_for(s.local.0, s.remote.0);
        if let Ok(mut a) = agg.lock() {
            a.record(pid, &path, None, kind, d_sent, d_recv);
        }
    }
    *seen = live;
}

fn byte_delta(sent: u64, recv: u64, base: Option<&Baseline>, count_new: bool) -> (u64, u64) {
    match base {
        Some(base) => (
            sent.saturating_sub(base.sent),
            recv.saturating_sub(base.recv),
        ),
        None if count_new => (sent, recv),
        None => (0, 0),
    }
}

/// key a udp conntrack flow by its original tuple so its counters diff across polls
#[derive(PartialEq, Eq, Hash, Clone)]
struct UdpKey {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}

fn account_udp(
    socks: &[SockInfo],
    owners: &HashMap<u64, u32>,
    seen: &mut HashMap<UdpKey, Baseline>,
    agg: &Mutex<Aggregator>,
    cache: &Mutex<PidCache>,
    adapters: &AdapterMap,
    count_new: bool,
) {
    // index udp sockets by local port so a conntrack flow can find its owner
    let mut by_local_port: HashMap<u16, u32> = HashMap::new();
    for s in socks {
        if s.is_tcp() {
            continue;
        }
        if let Some(&pid) = owners.get(&(s.inode as u64)) {
            by_local_port.entry(s.local.1).or_insert(pid);
        }
    }

    let mut live = HashMap::new();
    for flow in ct::dump() {
        if !matches!(flow.protocol, iris_core::Protocol::Udp) {
            continue;
        }
        let key = UdpKey {
            src: flow.orig_src,
            dst: flow.orig_dst,
            sport: flow.sport,
            dport: flow.dport,
        };
        let (d_orig, d_reply) =
            byte_delta(flow.orig_bytes, flow.reply_bytes, seen.get(&key), count_new);
        live.insert(
            key,
            Baseline {
                sent: flow.orig_bytes,
                recv: flow.reply_bytes,
                missed: 0,
            },
        );
        if d_orig == 0 && d_reply == 0 {
            continue;
        }
        // the initiator's source port is the local socket; that side sent the
        // orig bytes and received the reply bytes
        let Some(&pid) = by_local_port.get(&flow.sport) else {
            continue;
        };
        let Some(path) = resolve_path(cache, pid) else {
            continue;
        };
        let kind = adapters.kind_for(flow.orig_src, flow.orig_dst);
        if let Ok(mut a) = agg.lock() {
            a.record(pid, &path, None, kind, d_orig, d_reply);
        }
    }
    *seen = live;
}

// ---- DNS response sniffer ----

/// a packet socket that reads DNS responses and records answered addresses under
/// the host that was queried
struct DnsSniffer {
    fd: std::os::fd::OwnedFd,
}

impl DnsSniffer {
    fn open() -> std::io::Result<DnsSniffer> {
        use std::os::fd::FromRawFd;
        // SOCK_DGRAM strips the link header so the buffer starts at IPv4 or IPv6
        const ETH_P_ALL: u16 = 0x0003;
        let proto = i32::from(ETH_P_ALL.to_be());
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                proto,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        // keep only dns responses in the kernel so recv wakes for those alone
        // instead of every packet on the host; best effort, the userspace parse
        // still guards the payload if the kernel ever refuses the program
        attach_dns_filter(&fd);
        // wake out of recv once a second so the stop flag is honoured promptly
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            use std::os::fd::AsRawFd;
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }
        Ok(DnsSniffer { fd })
    }

    fn run(self, stop: Arc<AtomicBool>, dns_map: DnsMap) {
        use std::os::fd::AsRawFd;
        let mut buf = vec![0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n <= 0 {
                continue; // timeout or transient error; re-check the stop flag
            }
            parse_dns_packet(&buf[..n as usize], &dns_map);
        }
    }
}

/// attach a classic-BPF program that passes only UDP packets sourced from port
/// 53 (IPv4 and IPv6), dropping everything else before it is copied to userspace.
///
/// the socket sees every link type at once (loopback, ethernet, wifi, tun), so
/// the program reads through the kernel's `SKF_NET_OFF` magic offset, which is
/// relative to the L3 header and therefore link-layer agnostic. the IPv4 source
/// port is reached with an IHL-indexed load; IPv6 uses the fixed 40-byte header.
/// only the first IPv4 fragment (offset 0) carries the L4 header, so later
/// fragments are dropped, matching the non-reassembling userspace parser.
///
/// failure is non-fatal: without the filter the socket still delivers dns, just
/// alongside all other traffic that the userspace parser then discards.
fn attach_dns_filter(fd: &std::os::fd::OwnedFd) {
    use std::os::fd::AsRawFd;
    // offsets into the kernel's synthetic areas: auxiliary data (skb->protocol)
    // and the start of the network-layer header
    const SKF_AD_OFF: i32 = -0x1000;
    const SKF_AD_PROTOCOL: i32 = 0;
    const SKF_NET_OFF: i32 = -0x10_0000;
    const fn i(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    // codes are the classic-BPF encoding; the program was validated on-kernel to
    // pass v4 and v6 dns and drop udp on other ports, tcp, and icmp
    let prog = [
        i(0x28, 0, 0, (SKF_AD_OFF + SKF_AD_PROTOCOL) as u32), // A = ethertype
        i(0x15, 1, 0, 0x0000_0800),                          // IPv4 -> ipv4 block
        i(0x15, 7, 12, 0x0000_86dd),                         // IPv6 -> ipv6 block else drop
        i(0x30, 0, 0, (SKF_NET_OFF + 9) as u32),             // A = ipv4 protocol
        i(0x15, 0, 10, 0x0000_0011),                         // UDP? else drop
        i(0x28, 0, 0, (SKF_NET_OFF + 6) as u32),             // A = flags+frag offset
        i(0x45, 8, 0, 0x0000_1fff),                          // fragment? drop
        i(0xb1, 0, 0, (SKF_NET_OFF) as u32),                 // X = IPv4 header length
        i(0x48, 0, 0, (SKF_NET_OFF) as u32),                 // A = udp source port
        i(0x15, 4, 5, 0x0000_0035),                          // port 53? accept else drop
        i(0x30, 0, 0, (SKF_NET_OFF + 6) as u32),             // A = ipv6 next header
        i(0x15, 0, 3, 0x0000_0011),                          // UDP? else drop
        i(0x28, 0, 0, (SKF_NET_OFF + 40) as u32),            // A = udp source port
        i(0x15, 0, 1, 0x0000_0035),                          // port 53? accept else drop
        i(0x06, 0, 0, 0x0004_0000),                          // accept (256k)
        i(0x06, 0, 0, 0x0000_0000),                          // drop
    ];
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as u32,
        )
    };
    if rc != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "could not attach the dns capture filter; falling back to userspace filtering"
        );
    }
}

/// parse an IPv4 or IPv6 UDP DNS response
fn parse_dns_packet(pkt: &[u8], dns_map: &DnsMap) {
    let udp = match pkt.first().map(|byte| byte >> 4) {
        Some(4) if pkt.len() >= 20 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if pkt[9] != libc::IPPROTO_UDP as u8 || pkt.len() < ihl + 8 {
                return;
            }
            &pkt[ihl..]
        }
        Some(6) if pkt.len() >= 48 => {
            if pkt[6] != libc::IPPROTO_UDP as u8 {
                return;
            }
            &pkt[40..]
        }
        _ => return,
    };
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    if src_port != 53 {
        return;
    }
    let payload = &udp[8..];
    parse_dns_message(payload, dns_map);
}

fn parse_dns_message(msg: &[u8], dns_map: &DnsMap) {
    if msg.len() < 12 {
        return;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut off = 12;

    // the first question's name is the host that was looked up
    let (qname, after_q) = read_name(msg, off);
    let Some(qname) = qname else { return };
    off = after_q;
    // skip the rest of the first question (qtype, qclass) and any further ones
    off += 4;
    for _ in 1..qd {
        let (_, next) = read_name(msg, off);
        off = next + 4;
        if off > msg.len() {
            return;
        }
    }

    for _ in 0..an {
        let (_, name_end) = read_name(msg, off);
        off = name_end;
        if off + 10 > msg.len() {
            return;
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        off += 10;
        if off + rdlen > msg.len() {
            return;
        }
        let rdata = &msg[off..off + rdlen];
        match (rtype, rdlen) {
            (1, 4) => {
                let ip = IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]);
                dns::record(dns_map, &qname, ip);
            }
            (28, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                dns::record(dns_map, &qname, IpAddr::from(o));
            }
            _ => {}
        }
        off += rdlen;
    }
}

/// read a DNS name starting at `off`, following one level of compression
/// pointers. returns the dotted name and the offset just past the name in the
/// record stream (pointers do not advance the stream past the two pointer bytes).
fn read_name(msg: &[u8], mut off: usize) -> (Option<String>, usize) {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut stream_end = off;
    let mut guard = 0;
    loop {
        if off >= msg.len() || guard > 128 {
            return (None, stream_end.max(off));
        }
        guard += 1;
        let len = msg[off] as usize;
        if len == 0 {
            if !jumped {
                stream_end = off + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            // a compression pointer; record where the stream continues, then jump
            if off + 1 >= msg.len() {
                return (None, stream_end.max(off));
            }
            if !jumped {
                stream_end = off + 2;
            }
            let ptr = ((len & 0x3f) << 8) | msg[off + 1] as usize;
            off = ptr;
            jumped = true;
            continue;
        }
        off += 1;
        if off + len > msg.len() {
            return (None, stream_end.max(off));
        }
        labels.push(String::from_utf8_lossy(&msg[off..off + len]).into_owned());
        off += len;
    }
    if labels.is_empty() {
        return (None, stream_end);
    }
    (Some(labels.join(".")), stream_end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iris_core::{AdapterKind, Protocol};

    #[test]
    fn closed_socket_adds_bytes_after_the_last_poll() {
        let mut seen = HashMap::new();
        seen.insert(
            9,
            Baseline {
                sent: 100,
                recv: 200,
                missed: 0,
            },
        );
        let mut owners = HashMap::new();
        owners.insert(
            9,
            TcpOwner {
                pid: 42,
                path: "/usr/bin/browser".into(),
                kind: AdapterKind::Wifi,
            },
        );
        let socket = SockInfo {
            protocol: Protocol::Tcp,
            state: 7,
            local: (IpAddr::from([192, 0, 2, 2]), 40000),
            remote: (IpAddr::from([198, 51, 100, 4]), 443),
            uid: 1000,
            inode: 0,
            cookie: 9,
            bytes: Some((350, 600)),
        };
        let aggregator = Mutex::new(Aggregator::new(0));

        account_closed_tcp(&socket, &seen, &owners, &HashMap::new(), &aggregator);
        let sample = aggregator.lock().unwrap().flush(1000).procs.pop().unwrap();
        assert_eq!(sample.pid, 42);
        assert_eq!(sample.total.sent, 250);
        assert_eq!(sample.total.recv, 400);
    }

    #[test]
    fn short_socket_uses_tracepoint_owner_and_full_counters() {
        let socket = SockInfo {
            protocol: Protocol::Tcp,
            state: 7,
            local: (IpAddr::from([192, 0, 2, 2]), 40000),
            remote: (IpAddr::from([198, 51, 100, 4]), 443),
            uid: 1000,
            inode: 0,
            cookie: 9,
            bytes: Some((350, 600)),
        };
        let mut flow_owners = HashMap::new();
        flow_owners.insert(
            FlowKey {
                local: socket.local,
                remote: socket.remote,
            },
            (
                TcpOwner {
                    pid: 42,
                    path: "/usr/bin/browser".into(),
                    kind: AdapterKind::Wifi,
                },
                std::time::Instant::now(),
            ),
        );
        let aggregator = Mutex::new(Aggregator::new(0));

        account_closed_tcp(
            &socket,
            &HashMap::new(),
            &HashMap::new(),
            &flow_owners,
            &aggregator,
        );
        let sample = aggregator.lock().unwrap().flush(1000).procs.pop().unwrap();
        assert_eq!(sample.total.sent, 350);
        assert_eq!(sample.total.recv, 600);
    }

    #[test]
    fn new_socket_counts_from_zero_after_the_initial_baseline() {
        assert_eq!(byte_delta(400, 700, None, false), (0, 0));
        assert_eq!(byte_delta(400, 700, None, true), (400, 700));
        let base = Baseline {
            sent: 300,
            recv: 500,
            missed: 0,
        };
        assert_eq!(byte_delta(400, 700, Some(&base), true), (100, 200));
    }

    // a dns response for example.com whose single answer is an A record for the
    // given rdata, the answer name compressed back to the question at offset 12
    fn a_response(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0];
        m.push(7);
        m.extend_from_slice(b"example");
        m.push(3);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        m.extend_from_slice(&[0xc0, 0x0c]);
        m.extend_from_slice(&rtype.to_be_bytes());
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x01, 0x2c]);
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(rdata);
        m
    }

    #[test]
    fn records_a_and_aaaa_answers_under_the_queried_name() {
        let map = dns::new_map();
        parse_dns_message(&a_response(1, &[1, 2, 3, 4]), &map);
        parse_dns_message(&a_response(28, &[0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), &map);
        assert_eq!(dns::lookup(&map, &IpAddr::from([1, 2, 3, 4])).as_deref(), Some("example.com"));
        assert_eq!(
            dns::lookup(&map, &IpAddr::from([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn malformed_dns_is_dropped_without_panicking() {
        let map = dns::new_map();
        // a compression pointer that jumps to itself must terminate, not hang
        let mut loopy = vec![0, 0, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0];
        loopy.extend_from_slice(&[1, b'a', 0, 0x00, 0x01, 0x00, 0x01]);
        let here = loopy.len() as u8;
        loopy.extend_from_slice(&[0xc0, here]);
        parse_dns_message(&loopy, &map);

        // rdlen that runs past the buffer, both slightly and wildly
        let mut trunc = a_response(1, &[1, 2, 3, 4]);
        trunc.truncate(trunc.len() - 2);
        parse_dns_message(&trunc, &map);
        let mut over = a_response(1, &[1, 2, 3, 4]);
        let n = over.len();
        over[n - 6] = 0xff;
        over[n - 5] = 0xff;
        parse_dns_message(&over, &map);

        // headers too short to hold counts or a question
        parse_dns_message(&[], &map);
        parse_dns_message(&[0u8; 4], &map);

        // none of the malformed inputs should have recorded anything
        assert!(dns::lookup(&map, &IpAddr::from([1, 2, 3, 4])).is_none());
    }
}
