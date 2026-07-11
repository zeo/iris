//! a small IP -> hostname map fed by the DNS-Client ETW provider, so a
//! connection can show the name the process actually looked up (e.g.
//! updates.example.net) rather than the bare address.

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
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// parse a DNS-Client `QueryResults` string ("type: 5 cname;::ffff:1.2.3.4;...")
/// and map every resolved address to `host`
pub fn record_results(map: &DnsMap, host: &str, results: &str) {
    if host.is_empty() {
        return;
    }
    let Ok(mut guard) = map.lock() else {
        return;
    };
    for tok in results.split(';') {
        let tok = tok.trim();
        if tok.is_empty() || tok.starts_with("type:") {
            continue;
        }
        if let Ok(ip) = tok.parse::<IpAddr>() {
            guard.insert(normalize(ip), host.to_string());
        }
    }
    // bound memory: DNS churn is unbounded over a long session
    if guard.len() > 8192 {
        guard.clear();
    }
}

pub fn lookup(map: &DnsMap, ip: &IpAddr) -> Option<String> {
    map.lock().ok()?.get(ip).cloned()
}
