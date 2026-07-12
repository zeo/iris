//! maps local IP addresses to the kind of adapter that owns them, so ETW
//! network events (which carry addresses, not interfaces) can be attributed to
//! Wi-Fi, ethernet, or a VPN tunnel. the table rebuilds on a slow cadence plus
//! a rate-limited rebuild on a lookup miss, so a VPN that just came up is
//! attributed within a couple of seconds.

use iris_core::AdapterKind;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::NetworkManagement::IpHelper::{
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL,
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL,
};

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

    /// rebuild the address table from the live adapter list
    pub fn refresh(&self) {
        let fresh = enumerate();
        if let Ok(mut m) = self.by_ip.write() {
            *m = fresh;
        }
        self.last_refresh_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// classify a flow by its addresses. `local` is the end expected to be ours
    /// for the event's direction; when it misses (the table can lag an adapter
    /// change) the other end is tried before giving up.
    pub fn kind_for(&self, local: IpAddr, other: IpAddr) -> AdapterKind {
        if local.is_loopback() || other.is_loopback() {
            return AdapterKind::Loopback;
        }
        if let Some(kind) = self.lookup(local, other) {
            return kind;
        }
        // an unknown local address usually means an adapter appeared since the
        // last rebuild; refresh at most once per window (the CAS keeps a burst
        // of misses across callback threads down to one enumeration) and retry
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
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut map = HashMap::new();
    // the adapter blob holds 8-byte fields; u64 storage keeps the cast aligned
    let mut buf: Vec<u64> = Vec::new();
    let mut size: u32 = 16 * 1024;
    unsafe {
        loop {
            buf.resize((size as usize).div_ceil(8), 0);
            let ret = GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            );
            if ret == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            if ret != NO_ERROR.0 {
                tracing::warn!("GetAdaptersAddresses failed: {ret}");
                return map;
            }
            break;
        }

        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !adapter.is_null() {
            let a = &*adapter;
            adapter = a.Next;
            if a.OperStatus != IfOperStatusUp {
                continue;
            }
            let kind = classify(a.IfType, &label(a));
            let mut unicast = a.FirstUnicastAddress;
            while !unicast.is_null() {
                let sockaddr = (*unicast).Address.lpSockaddr;
                unicast = (*unicast).Next;
                if sockaddr.is_null() {
                    continue;
                }
                let family = (*sockaddr).sa_family;
                let ip = if family == AF_INET {
                    let sin = &*(sockaddr as *const SOCKADDR_IN);
                    Some(IpAddr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes()))
                } else if family == AF_INET6 {
                    let sin6 = &*(sockaddr as *const SOCKADDR_IN6);
                    Some(IpAddr::from(sin6.sin6_addr.u.Byte))
                } else {
                    None
                };
                if let Some(ip) = ip {
                    map.insert(ip, kind);
                }
            }
        }
    }
    map
}

/// the driver description plus the user-facing name, lowercased; either can
/// carry the vpn hint for TAP-style drivers
fn label(a: &windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH) -> String {
    let mut s = String::new();
    unsafe {
        if !a.Description.is_null() {
            if let Ok(d) = a.Description.to_string() {
                s.push_str(&d);
            }
        }
        if !a.FriendlyName.is_null() {
            s.push(' ');
            if let Ok(f) = a.FriendlyName.to_string() {
                s.push_str(&f);
            }
        }
    }
    s.to_lowercase()
}

fn classify(if_type: u32, label: &str) -> AdapterKind {
    match if_type {
        IF_TYPE_SOFTWARE_LOOPBACK => AdapterKind::Loopback,
        IF_TYPE_IEEE80211 => AdapterKind::Wifi,
        // the built-in windows vpn transports (sstp/l2tp/ikev2) arrive as ppp;
        // wintun (wireguard, tailscale) registers prop-virtual; other tunnel
        // interfaces rarely carry app traffic, so vpn is the honest bucket
        IF_TYPE_PPP | IF_TYPE_PROP_VIRTUAL | IF_TYPE_TUNNEL => AdapterKind::Vpn,
        // openvpn-style TAP drivers register as plain ethernet; the label is
        // the only thing that gives them away
        IF_TYPE_ETHERNET_CSMACD if is_vpn_label(label) => AdapterKind::Vpn,
        IF_TYPE_ETHERNET_CSMACD => AdapterKind::Ethernet,
        _ if is_vpn_label(label) => AdapterKind::Vpn,
        _ => AdapterKind::Other,
    }
}

fn is_vpn_label(label: &str) -> bool {
    [
        "vpn",
        "wintun",
        "wireguard",
        "tap-windows",
        "openvpn",
        "tailscale",
        "zerotier",
        "hamachi",
        "warp",
    ]
    .iter()
    .any(|mark| label.contains(mark))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_interface_types() {
        assert_eq!(classify(IF_TYPE_IEEE80211, ""), AdapterKind::Wifi);
        assert_eq!(
            classify(
                IF_TYPE_ETHERNET_CSMACD,
                "intel(r) ethernet connection i219-v"
            ),
            AdapterKind::Ethernet
        );
        assert_eq!(
            classify(IF_TYPE_ETHERNET_CSMACD, "tap-windows adapter v9"),
            AdapterKind::Vpn
        );
        assert_eq!(
            classify(IF_TYPE_PROP_VIRTUAL, "wintun userspace tunnel"),
            AdapterKind::Vpn
        );
        assert_eq!(
            classify(IF_TYPE_PPP, "wan miniport (sstp)"),
            AdapterKind::Vpn
        );
        assert_eq!(
            classify(IF_TYPE_SOFTWARE_LOOPBACK, ""),
            AdapterKind::Loopback
        );
        assert_eq!(classify(999, "some usb modem"), AdapterKind::Other);
    }

    #[test]
    fn loopback_short_circuits_and_the_table_populates() {
        let map = AdapterMap::new();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let remote: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(map.kind_for(lo, remote), AdapterKind::Loopback);
        // a live box always has at least one address-bearing interface up
        assert!(!map.by_ip.read().unwrap().is_empty());
    }
}
