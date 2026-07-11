//! compiled-in, first-party enrichers. these ship in the signed service binary,
//! so their trust boundary is the same as trusting the service itself; the
//! registry still asks each only about the target kinds it declares. anything
//! that needs the network or a secret is an out-of-process plugin instead, never
//! a built-in.

use iris_core::enrich::ip_scope;
use iris_core::{Annotation, EnrichTarget, Enricher, Severity, TargetKind};

/// labels each endpoint with its network scope (loopback, the LAN, the public
/// internet), so a connection row shows at a glance whether traffic is leaving
/// the machine. offline and instant, so it runs for every endpoint.
pub struct NetworkScope;

impl Enricher for NetworkScope {
    fn id(&self) -> &str {
        "iris.network-scope"
    }

    fn targets(&self) -> &[TargetKind] {
        &[TargetKind::Endpoint]
    }

    fn enrich(&self, target: &EnrichTarget) -> Vec<Annotation> {
        let EnrichTarget::Endpoint(ip) = target else {
            return Vec::new();
        };
        vec![Annotation::text("net.scope", "Network", ip_scope(ip), Severity::Info)]
    }
}
