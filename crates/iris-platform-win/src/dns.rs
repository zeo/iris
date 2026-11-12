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
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
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
    // bound memory: DNS churn is unbounded over a long session. evict roughly
    // half before inserting, so the names just resolved always survive and the
    // view never blanks back to raw ips
    if guard.len() >= 8192 {
        let victims: Vec<IpAddr> = guard.keys().take(guard.len() - 4096).copied().collect();
        for victim in victims {
            guard.remove(&victim);
        }
    }
    for tok in results.split(';') {
        let tok = tok.trim();
        if tok.is_empty() || tok.starts_with("type:") {
            continue;
        }
        if let Ok(ip) = tok.parse::<IpAddr>() {
            guard.insert(normalize(ip), host.to_string());
        }
    }
}

pub fn lookup(map: &DnsMap, ip: &IpAddr) -> Option<String> {
    map.lock().ok()?.get(ip).cloned()
}

#[cfg(test)]
mod tests {
    use super::{lookup, new_map, record_results};

    #[test]
    fn a_full_map_keeps_the_newest_names() {
        let map = new_map();
        for i in 0..8192u32 {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000u32 + i);
            record_results(&map, "old.example", &ip.to_string());
        }
        record_results(&map, "new.example", "198.51.100.7");
        assert_eq!(
            lookup(&map, &"198.51.100.7".parse().unwrap()),
            Some("new.example".to_string())
        );
        let len = map.lock().unwrap().len();
        assert!((4096..=8192).contains(&len), "map holds {len} names");
    }

    #[test]
    fn mapped_v6_answers_resolve_by_their_v4_address() {
        let map = new_map();
        record_results(&map, "cdn.example", "type: 5 cname;::ffff:203.0.113.9;");
        assert_eq!(
            lookup(&map, &"203.0.113.9".parse().unwrap()),
            Some("cdn.example".to_string())
        );
    }
}
