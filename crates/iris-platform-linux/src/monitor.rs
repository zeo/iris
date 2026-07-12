//! the Linux byte monitor, the counterpart to the Windows ETW monitor. it fills
//! the shared aggregator with per-process throughput and captures the DNS names
//! processes resolve, from two background threads:
//!
//! - accounting polls sock_diag once a second and diffs each TCP socket's
//!   tcp_info byte counters, attributing the delta to the owning pid; UDP bytes
//!   come from conntrack where it is available. this is a poll where ETW is a
//!   push, but it feeds the identical [`Aggregator`], so the service is unchanged.
//! - the DNS sniffer reads DNS responses off a packet socket and records each
//!   answered address under the host name that produced it.

use crate::adapters::AdapterMap;
use crate::ct;
use crate::dns::{self, DnsMap};
use crate::proc::{self, PidCache};
use crate::sockets::{self, SockInfo};
use iris_core::Aggregator;
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
}

impl Monitor {
    pub fn start(agg: Arc<Mutex<Aggregator>>, dns_map: DnsMap) -> anyhow::Result<Monitor> {
        let stop = Arc::new(AtomicBool::new(false));
        let cache = Arc::new(Mutex::new(PidCache::new()));
        let adapters = Arc::new(AdapterMap::new());
        ct::enable_acct();

        let mut threads = Vec::new();

        let acct = {
            let stop = stop.clone();
            let cache = cache.clone();
            let adapters = adapters.clone();
            std::thread::Builder::new()
                .name("iris-acct".into())
                .spawn(move || accounting_loop(stop, agg, cache, adapters))?
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
}

fn accounting_loop(
    stop: Arc<AtomicBool>,
    agg: Arc<Mutex<Aggregator>>,
    cache: Arc<Mutex<PidCache>>,
    adapters: Arc<AdapterMap>,
) {
    let mut tcp_seen: HashMap<u64, Baseline> = HashMap::new();
    let mut udp_seen: HashMap<UdpKey, Baseline> = HashMap::new();

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(1));
        let owners = proc::socket_inode_owners();
        let socks = sockets::dump();

        account_tcp(&socks, &owners, &mut tcp_seen, &agg, &cache, &adapters);
        account_udp(&socks, &owners, &mut udp_seen, &agg, &cache, &adapters);
    }
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
) {
    let mut live = HashMap::new();
    for s in socks {
        let Some((cur_sent, cur_recv)) = s.bytes else {
            continue;
        };
        if !s.is_tcp() {
            continue;
        }
        // a socket we have not seen this session contributes no history: record
        // its current counters as the baseline and no delta
        let Some(base) = seen.get(&s.cookie).copied() else {
            live.insert(
                s.cookie,
                Baseline {
                    sent: cur_sent,
                    recv: cur_recv,
                },
            );
            continue;
        };
        let d_sent = cur_sent.saturating_sub(base.sent);
        let d_recv = cur_recv.saturating_sub(base.recv);
        live.insert(
            s.cookie,
            Baseline {
                sent: cur_sent,
                recv: cur_recv,
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
        let Some(base) = seen.get(&key).copied() else {
            live.insert(
                key,
                Baseline {
                    sent: flow.orig_bytes,
                    recv: flow.reply_bytes,
                },
            );
            continue;
        };
        let d_orig = flow.orig_bytes.saturating_sub(base.sent);
        let d_reply = flow.reply_bytes.saturating_sub(base.recv);
        live.insert(
            key,
            Baseline {
                sent: flow.orig_bytes,
                recv: flow.reply_bytes,
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
