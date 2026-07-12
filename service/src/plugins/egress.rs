//! resolves a plugin's granted egress into concrete endpoints and keeps the
//! child pinned to them with WFP. names re-resolve on a slow cadence so a
//! rotated DNS record does not strand a healthy plugin, while the pin itself
//! stays fail-closed: no pin, no child.

use crate::platform::{AppPin, PluginNet};
use crate::plugins::supervisor::PluginRuntime;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Mutex;

/// one shared dynamic WFP session pinning every plugin child
pub struct Pinner {
    net: Mutex<PluginNet>,
}

/// a pinned plugin's resolve state, owned by its refresh task
pub struct PinState {
    pin: AppPin,
    exe: PathBuf,
    entries: Vec<String>,
    addrs: BTreeSet<SocketAddr>,
    allow_dns: bool,
}

impl PinState {
    /// literal-only grants never change; only named hosts need re-resolving
    pub fn needs_refresh(&self) -> bool {
        self.allow_dns
    }
}

impl Pinner {
    pub fn open() -> Result<Pinner, String> {
        match PluginNet::open() {
            Ok(net) => Ok(Pinner {
                net: Mutex::new(net),
            }),
            Err(e) => Err(e.to_string()),
        }
    }

    /// resolve the grant and pin the child's binary. blocking (DNS); run on a
    /// blocking thread.
    pub fn pin(&self, rt: &PluginRuntime) -> Result<PinState, String> {
        let entries = rt.effective_egress();
        let allow_dns = entries.iter().any(|e| host_is_name(e));
        let addrs = resolve(&entries);
        let exe = rt.manifest.entry_path(&rt.dir);
        let allowed: Vec<SocketAddr> = addrs.iter().copied().collect();
        let pin = self
            .net
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pin(&exe, &allowed, allow_dns)
            .map_err(|e| e.to_string())?;
        Ok(PinState {
            pin,
            exe,
            entries,
            addrs,
            allow_dns,
        })
    }

    /// re-resolve and swap the permits when the endpoint set moved; returns
    /// whether anything changed. blocking (DNS).
    pub fn refresh(&self, state: &mut PinState) -> Result<bool, String> {
        let addrs = resolve(&state.entries);
        if addrs == state.addrs {
            return Ok(false);
        }
        let allowed: Vec<SocketAddr> = addrs.iter().copied().collect();
        self.net
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .repin(&state.exe, &mut state.pin, &allowed, state.allow_dns)
            .map_err(|e| e.to_string())?;
        state.addrs = addrs;
        Ok(true)
    }
}

/// resolve every `host:port` grant entry; a host that fails to resolve is
/// logged and skipped, and the slow refresh retries it
fn resolve(entries: &[String]) -> BTreeSet<SocketAddr> {
    let mut out = BTreeSet::new();
    for entry in entries {
        let Some((host, port)) = split_entry(entry) else {
            continue;
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            out.insert(SocketAddr::new(ip, port));
            continue;
        }
        match (host, port).to_socket_addrs() {
            Ok(addrs) => out.extend(addrs),
            Err(e) => tracing::warn!("egress host {host} did not resolve: {e}"),
        }
    }
    out
}

/// split a validated `host:port` entry, unbracketing an ipv6 literal
fn split_entry(entry: &str) -> Option<(&str, u16)> {
    let (host, port) = entry.rsplit_once(':')?;
    let port = port.parse().ok()?;
    Some((host.trim_start_matches('[').trim_end_matches(']'), port))
}

fn host_is_name(entry: &str) -> bool {
    split_entry(entry).is_some_and(|(host, _)| host.parse::<IpAddr>().is_err())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_entries_resolve_without_dns() {
        let addrs = resolve(&["192.0.2.7:443".into(), "[2001:db8::1]:8443".into()]);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&"192.0.2.7:443".parse().unwrap()));
        assert!(addrs.contains(&"[2001:db8::1]:8443".parse().unwrap()));
    }

    #[test]
    fn named_hosts_are_flagged_for_dns() {
        assert!(host_is_name("api.example.com:443"));
        assert!(!host_is_name("192.0.2.7:443"));
        assert!(!host_is_name("[2001:db8::1]:8443"));
    }
}
