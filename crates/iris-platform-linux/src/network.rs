//! which network the machine is on, for network profiles. the default route's
//! gateway names it: its hardware address stays the same for one router and
//! differs between a home router and a cafe's, which an address like
//! 192.168.1.1 does not. read from procfs, so no privilege or netlink needed.

use iris_core::NetworkIdentity;
use std::net::Ipv4Addr;

/// the network behind the lowest-metric ipv4 default route, if any
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn current_network() -> Option<NetworkIdentity> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    let (interface, gateway) = default_route(&routes)?;
    let mac = gateway.and_then(|gateway| {
        let arp = std::fs::read_to_string("/proc/net/arp").ok()?;
        neighbor_mac(&arp, gateway, &interface)
    });
    Some(match (gateway, mac) {
        (Some(gateway), Some(mac)) => NetworkIdentity {
            key: format!("mac:{mac}"),
            label: format!("{interface} via {gateway}"),
        },
        // a tunnel or point-to-point link has no neighbor to name it by
        _ => NetworkIdentity {
            key: format!("if:{interface}"),
            label: interface,
        },
    })
}

/// `/proc/net/route` rows are `Iface Destination Gateway Flags RefCnt Use
/// Metric ...` with addresses as little-endian hex
fn default_route(table: &str) -> Option<(String, Option<Ipv4Addr>)> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (interface, destination, gateway, metric) =
                (fields.first()?, fields.get(1)?, fields.get(2)?, fields.get(6)?);
            if *destination != "00000000" {
                return None;
            }
            let gateway = Ipv4Addr::from(u32::from_str_radix(gateway, 16).ok()?.to_le_bytes());
            let metric: u32 = metric.parse().ok()?;
            Some((metric, interface.to_string(), (!gateway.is_unspecified()).then_some(gateway)))
        })
        .min_by_key(|(metric, _, _)| *metric)
        .map(|(_, interface, gateway)| (interface, gateway))
}

/// `/proc/net/arp` rows are `IP HWtype Flags HWaddress Mask Device`
fn neighbor_mac(table: &str, gateway: Ipv4Addr, interface: &str) -> Option<String> {
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (address, mac, device) = (fields.first()?, fields.get(3)?, fields.get(5)?);
        (address.parse::<Ipv4Addr>().ok()? == gateway
            && *device == interface
            && *mac != "00:00:00:00:00:00")
            .then(|| mac.to_lowercase())
    })
}

#[cfg(test)]
mod tests {
    use super::{default_route, neighbor_mac};
    use std::net::Ipv4Addr;

    const ROUTES: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

    const ARP: &str = "IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         AA:BB:CC:00:11:22     *        eth0
192.168.1.1      0x1         0x2         de:ad:be:ef:00:01     *        wlan0
";

    #[test]
    fn picks_the_lowest_metric_default_route() {
        let (interface, gateway) = default_route(ROUTES).expect("default route");
        assert_eq!(interface, "eth0");
        assert_eq!(gateway, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(default_route("Iface\tDestination\n").is_none());
    }

    #[test]
    fn finds_the_gateway_neighbor_on_its_interface() {
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(neighbor_mac(ARP, gateway, "eth0").as_deref(), Some("aa:bb:cc:00:11:22"));
        assert!(neighbor_mac(ARP, gateway, "wlan0").is_none());
    }

    #[test]
    fn a_tunnel_default_route_has_no_gateway() {
        let tunnel = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\nwg0\t00000000\t00000000\t0001\t0\t0\t50\n";
        assert_eq!(default_route(tunnel), Some(("wg0".to_string(), None)));
    }
}
