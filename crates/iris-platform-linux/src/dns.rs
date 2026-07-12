//! a small IP -> hostname map fed by the DNS response sniffer in [`crate::monitor`],
//! so a connection can show the name the process actually looked up (e.g.
//! updates.example.net) rather than the bare address. identical in shape to the
//! Windows crate's map so the service uses it the same way.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

pub type DnsMap = Arc<Mutex<HashMap<IpAddr, String>>>;

pub fn new_map() -> DnsMap {
    Arc::new(Mutex::new(HashMap::new()))
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
    let Ok(mut guard) = map.lock() else {
        return;
    };
    guard.insert(normalize(ip), host.to_string());
    // bound memory: DNS churn is unbounded over a long session
    if guard.len() > 8192 {
        guard.clear();
    }
}

pub fn lookup(map: &DnsMap, ip: &IpAddr) -> Option<String> {
    map.lock().ok()?.get(ip).cloned()
}
