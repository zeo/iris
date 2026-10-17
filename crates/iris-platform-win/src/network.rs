//! which network the machine is on, for network profiles. the default route's
//! gateway names it: its hardware address stays the same for one router and
//! differs between a home router and a cafe's, which an address like
//! 192.168.1.1 does not.

use iris_core::NetworkIdentity;
use std::net::Ipv4Addr;
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias, FreeMibTable, GetIpForwardTable2,
    GetIpNetEntry2, ResolveIpNetEntry2, MIB_IPFORWARD_TABLE2, MIB_IPNET_ROW2,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::AF_INET;

/// the network behind the lowest-metric ipv4 default route, if any
pub fn current_network() -> Option<NetworkIdentity> {
    let (interface, gateway) = default_route()?;
    let alias = interface_alias(interface).unwrap_or_else(|| format!("interface {interface}"));
    Some(match gateway.and_then(|gateway| gateway_mac(interface, gateway).map(|mac| (gateway, mac))) {
        Some((gateway, mac)) => NetworkIdentity {
            key: format!("mac:{mac}"),
            label: format!("{alias} via {gateway}"),
        },
        // a tunnel or point-to-point link has no neighbor to name it by
        None => NetworkIdentity {
            key: format!("if:{alias}"),
            label: alias,
        },
    })
}

fn default_route() -> Option<(u32, Option<Ipv4Addr>)> {
    unsafe {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if GetIpForwardTable2(AF_INET, &mut table).is_err() || table.is_null() {
            return None;
        }
        let rows = std::slice::from_raw_parts(
            (*table).Table.as_ptr(),
            (*table).NumEntries as usize,
        );
        let best = rows
            .iter()
            .filter(|row| row.DestinationPrefix.PrefixLength == 0 && !row.Loopback)
            .min_by_key(|row| row.Metric)
            .map(|row| {
                let hop = Ipv4Addr::from(row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
                (row.InterfaceIndex, (!hop.is_unspecified()).then_some(hop))
            });
        FreeMibTable(table as *const _);
        best
    }
}

fn gateway_mac(interface: u32, gateway: Ipv4Addr) -> Option<String> {
    unsafe {
        let mut row = MIB_IPNET_ROW2 {
            InterfaceIndex: interface,
            ..Default::default()
        };
        row.Address.Ipv4.sin_family = AF_INET;
        row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(gateway.octets());
        // the neighbor cache usually holds the gateway already; ask the
        // stack to resolve it only when it does not
        if GetIpNetEntry2(&mut row).is_err() && ResolveIpNetEntry2(&mut row, None).is_err() {
            return None;
        }
        let length = (row.PhysicalAddressLength as usize).min(row.PhysicalAddress.len());
        let mac = &row.PhysicalAddress[..length];
        (!mac.is_empty() && mac.iter().any(|byte| *byte != 0)).then(|| format_mac(mac))
    }
}

fn interface_alias(interface: u32) -> Option<String> {
    unsafe {
        let mut luid = NET_LUID_LH::default();
        ConvertInterfaceIndexToLuid(interface, &mut luid).ok().ok()?;
        let mut alias = [0u16; 257];
        ConvertInterfaceLuidToAlias(&luid, &mut alias).ok().ok()?;
        let end = alias.iter().position(|unit| *unit == 0).unwrap_or(alias.len());
        Some(String::from_utf16_lossy(&alias[..end]))
    }
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::{current_network, format_mac};

    #[test]
    fn formats_hardware_addresses_lowercase() {
        assert_eq!(format_mac(&[0x00, 0x1A, 0x2b, 0xff, 0x10, 0x01]), "00:1a:2b:ff:10:01");
    }

    #[test]
    fn reads_the_current_network_without_privilege() {
        // runs against the real stack: a machine with no default route gives
        // none, anything else must give a usable key
        if let Some(network) = current_network() {
            assert!(network.key.starts_with("mac:") || network.key.starts_with("if:"));
            assert!(!network.label.is_empty());
        }
    }
}
