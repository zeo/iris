//! maps local IP addresses to the kind of adapter that owns them, so a network
//! flow (which the byte monitor sees by address) can be attributed to Wi-Fi,
//! ethernet, or a VPN tunnel. addresses come from getifaddrs; the interface kind
//! is read from sysfs (the wireless directory, the tun flag, the ARP hardware
//! type) with a name-based fallback for the tunnel drivers that do not announce
//! themselves. the table rebuilds on a slow cadence plus a rate-limited rebuild
//! on a lookup miss, so a tunnel that just came up is attributed within seconds.

use iris_core::AdapterKind;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// how long a lookup miss must wait before it may trigger another enumeration
const MISS_REFRESH_MS: u64 = 2_000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct AdapterMap {
    by_ip: RwLock<HashMap<IpAddr, AdapterKind>>,
    last_refresh_ms: AtomicU64,
}

impl AdapterMap {
    pub fn new() -> Self {
        let map = AdapterMap {
            by_ip: RwLock::new(HashMap::new()),
            last_refresh_ms: AtomicU64::new(0),
        };
        map.refresh();
        map
    }

    /// rebuild the address table from the live interface list
    pub fn refresh(&self) {
        let fresh = enumerate();
        if let Ok(mut m) = self.by_ip.write() {
            *m = fresh;
        }
        self.last_refresh_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// classify a flow by its addresses. `local` is the end expected to be ours;
    /// when it misses (the table can lag an interface change) the other end is
    /// tried before giving up.
    pub fn kind_for(&self, local: IpAddr, other: IpAddr) -> AdapterKind {
        if local.is_loopback() || other.is_loopback() {
            return AdapterKind::Loopback;
        }
        if let Some(kind) = self.lookup(local, other) {
            return kind;
        }
        let last = self.last_refresh_ms.load(Ordering::Relaxed);
        if now_ms().saturating_sub(last) >= MISS_REFRESH_MS
            && self
                .last_refresh_ms
                .compare_exchange(last, now_ms(), Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.refresh();
            if let Some(kind) = self.lookup(local, other) {
                return kind;
            }
        }
        AdapterKind::Other
    }

    fn lookup(&self, a: IpAddr, b: IpAddr) -> Option<AdapterKind> {
        let m = self.by_ip.read().ok()?;
        m.get(&a).or_else(|| m.get(&b)).copied()
    }
}

impl Default for AdapterMap {
    fn default() -> Self {
        Self::new()
    }
}

fn enumerate() -> HashMap<IpAddr, AdapterKind> {
    let mut map = HashMap::new();
    // classification is per interface, so cache each interface's kind while we
    // walk its (possibly several) addresses
    let mut kinds: HashMap<String, AdapterKind> = HashMap::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            tracing::warn!("getifaddrs failed");
            return map;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
                continue;
            }
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            let ip = match sockaddr_ip(ifa.ifa_addr) {
                Some(ip) => ip,
                None => continue,
            };
            let kind = *kinds
                .entry(name.clone())
                .or_insert_with(|| classify(&name));
            map.insert(ip, kind);
        }
        libc::freeifaddrs(head);
    }
    map
}

unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    match (*sa).sa_family as i32 {
        libc::AF_INET => {
            let sin = &*(sa as *const libc::sockaddr_in);
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            let sin6 = &*(sa as *const libc::sockaddr_in6);
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// classify an interface by its sysfs attributes, then its name. loopback and
/// wireless announce themselves cleanly; tunnels are recognised by the `tun_flags`
/// file, the ARPHRD_NONE hardware type, or a known driver name.
fn classify(ifname: &str) -> AdapterKind {
    if ifname == "lo" {
        return AdapterKind::Loopback;
    }
    let base = Path::new("/sys/class/net").join(ifname);
    if base.join("wireless").is_dir() || base.join("phy80211").exists() {
        return AdapterKind::Wifi;
    }
    // tun/tap and wireguard interfaces expose tun_flags or report the "no ARP
    // hardware" type; either marks a tunnel that usually carries app traffic
    let arphrd = fs::read_to_string(base.join("type"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    if base.join("tun_flags").exists() || arphrd == Some(ARPHRD_NONE) {
        return AdapterKind::Vpn;
    }
    if is_vpn_name(ifname) {
        return AdapterKind::Vpn;
    }
    match arphrd {
        Some(ARPHRD_LOOPBACK) => AdapterKind::Loopback,
        Some(ARPHRD_ETHER) => AdapterKind::Ethernet,
        Some(ARPHRD_PPP) => AdapterKind::Vpn,
        _ => AdapterKind::Other,
    }
}

const ARPHRD_ETHER: u32 = 1;
const ARPHRD_PPP: u32 = 512;
const ARPHRD_LOOPBACK: u32 = 772;
const ARPHRD_NONE: u32 = 0xFFFE;

fn is_vpn_name(name: &str) -> bool {
    const PREFIXES: [&str; 8] = ["tun", "tap", "wg", "ppp", "tailscale", "zt", "utun", "gpd"];
    let lower = name.to_lowercase();
    PREFIXES.iter().any(|p| lower.starts_with(p))
        || ["vpn", "wireguard", "zerotier", "warp"]
            .iter()
            .any(|m| lower.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_names_match_tunnel_drivers() {
        assert!(is_vpn_name("tun0"));
        assert!(is_vpn_name("wg0"));
        assert!(is_vpn_name("tailscale0"));
        assert!(is_vpn_name("ppp0"));
        assert!(!is_vpn_name("eth0"));
        assert!(!is_vpn_name("enp3s0"));
        assert!(!is_vpn_name("wlan0"));
    }

    #[test]
    fn loopback_short_circuits_and_the_table_populates() {
        let map = AdapterMap::new();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let remote: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(map.kind_for(lo, remote), AdapterKind::Loopback);
        // a live box always has at least the loopback address up
        assert!(!map.by_ip.read().unwrap().is_empty());
    }
}
