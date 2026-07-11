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
    fn annotation_serializes_stably() {
        let a = Annotation::text("net.scope", "Network", "Public internet", Severity::Info);
        let json = serde_json::to_string(&a).unwrap();
        let back: Annotation = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}
