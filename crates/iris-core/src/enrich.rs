//! the enrichment contract: how extra facts get attached to the things Iris
//! shows. an [`Enricher`] takes a target (an endpoint or an app) and returns
//! [`Annotation`]s that the UI renders in the connection detail drawer. first
//! party enrichers are compiled into the service behind this trait; later,
//! out-of-process plugins present through the same trait via a proxy, so the
//! registry cannot tell a built-in from a plugin apart.

use crate::model::AppId;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// what an annotation is attached to. endpoint facts (scope, geo, reputation)
/// are ip-scoped so they cache once per address.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnrichTarget {
    Endpoint(IpAddr),
    App(AppId),
}

/// which target shapes an enricher handles, so the registry only asks it about
/// targets it can answer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    Endpoint,
    App,
}

/// how prominently the UI should treat an annotation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Danger,
}

/// the rendered form of an annotation's value
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnnotationValue {
    Text(String),
    Badge(String),
    Link { label: String, url: String },
}

/// one fact an enricher attaches to a target. `key` is namespaced by the
/// enricher id so two enrichers never collide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotation {
    pub key: String,
    pub label: String,
    pub value: AnnotationValue,
    pub severity: Severity,
}

impl Annotation {
    pub fn text(key: &str, label: &str, value: impl Into<String>, severity: Severity) -> Self {
        Annotation {
            key: key.to_string(),
            label: label.to_string(),
            value: AnnotationValue::Text(value.into()),
            severity,
        }
    }
}

/// the in-service enrichment contract. a compiled-in enricher implements it
/// directly; the registry calls [`Enricher::enrich`] off the hot path and caches
/// the result, so a slow enricher never stalls the per-second tick.
pub trait Enricher: Send + Sync {
    fn id(&self) -> &str;
    fn targets(&self) -> &[TargetKind];
    fn enrich(&self, target: &EnrichTarget) -> Vec<Annotation>;
}

/// an enricher that also wants to see the live stream (for stateful analysis or
/// raising its own alerts). optional; most enrichers only need [`Enricher`].
pub trait Observer: Send + Sync {
    fn id(&self) -> &str;
    fn on_tick(&self, _tick: &crate::StatsTick) {}
    fn on_alert(&self, _alert: &crate::Alert) {}
}

/// a parsed set of addresses and CIDR prefixes: the shape of the watchlist
/// file (one entry per line, `#` starts a comment)
#[derive(Debug, Default)]
pub struct IpSet {
    v4: Vec<(u32, u8)>,
    v6: Vec<(u128, u8)>,
}

impl IpSet {
    /// parse entries, returning the set and any lines that did not parse
    pub fn parse(text: &str) -> (IpSet, Vec<String>) {
        let mut set = IpSet::default();
        let mut rejected = Vec::new();
        for line in text.lines() {
            let entry = line.split('#').next().unwrap_or("").trim();
            if entry.is_empty() {
                continue;
            }
            if set.add(entry).is_none() {
                rejected.push(entry.to_string());
            }
        }
        (set, rejected)
    }

    fn add(&mut self, entry: &str) -> Option<()> {
        let (addr, prefix) = match entry.split_once('/') {
            Some((a, p)) => (a, Some(p.trim().parse::<u8>().ok()?)),
            None => (entry, None),
        };
        match addr.trim().parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => {
                let p = prefix.unwrap_or(32);
                if p > 32 {
                    return None;
                }
                self.v4.push((u32::from(v4), p));
            }
            IpAddr::V6(v6) => {
                let p = prefix.unwrap_or(128);
                if p > 128 {
                    return None;
                }
                self.v6.push((u128::from(v6), p));
            }
        }
        Some(())
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        fn hit_v4(x: u32, net: u32, p: u8) -> bool {
            p == 0 || (x >> (32 - p as u32)) == (net >> (32 - p as u32))
        }
        fn hit_v6(x: u128, net: u128, p: u8) -> bool {
            p == 0 || (x >> (128 - p as u32)) == (net >> (128 - p as u32))
        }
        match ip {
            IpAddr::V4(v4) => {
                let x = u32::from(*v4);
                self.v4.iter().any(|(net, p)| hit_v4(x, *net, *p))
            }
            IpAddr::V6(v6) => {
                let x = u128::from(*v6);
                self.v6.iter().any(|(net, p)| hit_v6(x, *net, *p))
            }
        }
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// human-readable network scope of an address (loopback, the LAN, the public
/// internet, ...). pure logic, kept here so it is unit-testable without a host.
pub fn ip_scope(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                "Loopback"
            } else if v4.is_private() {
                "Private network"
            } else if v4.is_link_local() {
                "Link-local"
            } else if v4.is_multicast() {
                "Multicast"
            } else if v4.is_unspecified() {
                "Unspecified"
            } else {
                "Public internet"
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                "Loopback"
            } else if v6.is_unspecified() {
                "Unspecified"
            } else if v6.is_multicast() {
                "Multicast"
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                // unique local fc00::/7
                "Private network"
            } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                // link-local fe80::/10
                "Link-local"
            } else {
                "Public internet"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_common_addresses() {
        assert_eq!(ip_scope(&"127.0.0.1".parse().unwrap()), "Loopback");
        assert_eq!(ip_scope(&"192.168.1.4".parse().unwrap()), "Private network");
        assert_eq!(ip_scope(&"10.0.0.9".parse().unwrap()), "Private network");
        assert_eq!(ip_scope(&"8.8.8.8".parse().unwrap()), "Public internet");
        assert_eq!(ip_scope(&"::1".parse().unwrap()), "Loopback");
        assert_eq!(ip_scope(&"fe80::1".parse().unwrap()), "Link-local");
        assert_eq!(ip_scope(&"fc00::1".parse().unwrap()), "Private network");
        assert_eq!(ip_scope(&"2606:4700:4700::1111".parse().unwrap()), "Public internet");
    }

    #[test]
    fn ip_set_matches_addresses_and_prefixes() {
        let (set, rejected) = IpSet::parse(
            "# c2 ranges\n203.0.113.7\n198.51.100.0/24  # documentation net\n2001:db8::/32\n\nnot-an-ip\n10.0.0.1/40\n",
        );
        assert_eq!(rejected, vec!["not-an-ip".to_string(), "10.0.0.1/40".to_string()]);
        assert_eq!(set.len(), 3);
        assert!(set.contains(&"203.0.113.7".parse().unwrap()));
        assert!(!set.contains(&"203.0.113.8".parse().unwrap()));
        assert!(set.contains(&"198.51.100.200".parse().unwrap()));
        assert!(!set.contains(&"198.51.101.1".parse().unwrap()));
        assert!(set.contains(&"2001:db8:dead::beef".parse().unwrap()));
        assert!(!set.contains(&"2001:db9::1".parse().unwrap()));
        assert!(IpSet::parse("").0.is_empty());
    }

    #[test]
    fn annotation_serializes_stably() {
        let a = Annotation::text("net.scope", "Network", "Public internet", Severity::Info);
        let json = serde_json::to_string(&a).unwrap();
        let back: Annotation = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}
