//! a small IP -> hostname map fed by the DNS response sniffer in [`crate::monitor`],
//! so a connection can show the name the process actually looked up (e.g.
//! updates.example.net) rather than the bare address. it keeps the same service
//! surface as the Windows map and also shares the monitor's socket snapshot.

use crate::sockets::SockInfo;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Clone)]
pub struct DnsMap {
    names: Arc<Mutex<HashMap<IpAddr, String>>>,
    sockets: Arc<RwLock<Option<SocketSnapshot>>>,
}

#[derive(Clone)]
pub(crate) struct SocketSnapshot {
    pub socks: Vec<SockInfo>,
    pub owners: HashMap<u64, u32>,
}

pub fn new_map() -> DnsMap {
    DnsMap {
        names: Arc::new(Mutex::new(HashMap::new())),
        sockets: Arc::new(RwLock::new(None)),
    }
}

/// v4-mapped v6 addresses (::ffff:a.b.c.d) collapse to their v4 form so lookups
/// by the connection table's v4 address hit
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// map a resolved address to the host name that produced it
pub fn record(map: &DnsMap, host: &str, ip: IpAddr) {
    if host.is_empty() {
        return;
    }
    let Ok(mut guard) = map.names.lock() else {
        return;
    };
    guard.insert(normalize(ip), host.to_string());
    // bound memory: DNS churn is unbounded over a long session. evict roughly
    // half rather than clearing every learned name at once, which would blank
    // the whole connection view back to raw IPs until DNS re-populates.
    if guard.len() > 8192 {
        let victims: Vec<IpAddr> = guard.keys().take(guard.len() - 4096).copied().collect();
        for victim in victims {
            guard.remove(&victim);
        }
    }
}

pub fn lookup(map: &DnsMap, ip: &IpAddr) -> Option<String> {
    map.names.lock().ok()?.get(ip).cloned()
}

pub(crate) fn record_sockets(map: &DnsMap, socks: &[SockInfo], owners: &HashMap<u64, u32>) {
    if let Ok(mut snapshot) = map.sockets.write() {
        *snapshot = Some(SocketSnapshot {
            socks: socks.to_vec(),
            owners: owners.clone(),
        });
    }
}

pub(crate) fn sockets(map: &DnsMap) -> Option<SocketSnapshot> {
    map.sockets.read().ok()?.clone()
}
