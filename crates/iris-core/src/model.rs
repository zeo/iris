use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// transport protocol for a flow or connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// direction of traffic relative to this host
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// the kind of network adapter a flow's local address is bound to, for the
/// per-adapter traffic breakdown
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterKind {
    Ethernet,
    Wifi,
    Vpn,
    Loopback,
    Other,
}

impl AdapterKind {
    /// the wire/storage name, matching the serde form
    pub fn as_str(self) -> &'static str {
        match self {
            AdapterKind::Ethernet => "ethernet",
            AdapterKind::Wifi => "wifi",
            AdapterKind::Vpn => "vpn",
            AdapterKind::Loopback => "loopback",
            AdapterKind::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<AdapterKind> {
        match s {
            "ethernet" => Some(AdapterKind::Ethernet),
            "wifi" => Some(AdapterKind::Wifi),
            "vpn" => Some(AdapterKind::Vpn),
            "loopback" => Some(AdapterKind::Loopback),
            "other" => Some(AdapterKind::Other),
            _ => None,
        }
    }
}

/// stable identity of an application image
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AppId(pub String);

impl AppId {
    /// normalize a raw image path according to the host filesystem
    pub fn from_path(path: &str) -> Self {
        let path = path.trim();
        #[cfg(windows)]
        return AppId(path.to_lowercase());
        #[cfg(not(windows))]
        return AppId(path.to_owned());
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// the final path component, for display when no friendly name is known
    pub fn file_name(&self) -> &str {
        self.0
            .rsplit(['\\', '/'])
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.0)
    }
}

#[cfg(test)]
mod app_id_tests {
    use super::AppId;

    #[test]
    fn trims_image_paths() {
        assert_eq!(
            AppId::from_path("  /opt/Iris/app  ").as_str(),
            normalized("/opt/Iris/app")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn preserves_case_on_case_sensitive_hosts() {
        assert_ne!(
            AppId::from_path("/opt/Foo/app"),
            AppId::from_path("/opt/foo/app")
        );
    }

    fn normalized(_path: &str) -> &str {
        #[cfg(windows)]
        return "/opt/iris/app";
        #[cfg(not(windows))]
        return _path;
    }
}

/// a distinct remote endpoint a flow talks to
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

/// cumulative byte counters
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteCounts {
    pub sent: u64,
    pub recv: u64,
}

impl ByteCounts {
    pub fn add(&mut self, other: ByteCounts) {
        self.sent = self.sent.saturating_add(other.sent);
        self.recv = self.recv.saturating_add(other.recv);
    }

    pub fn total(&self) -> u64 {
        self.sent.saturating_add(self.recv)
    }
}

/// one open connection a process holds, for the activity drill-down
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conn {
    pub remote: Endpoint,
    /// the hostname the process resolved this endpoint from (captured from DNS),
    /// shown ahead of the raw address when known
    pub host: Option<String>,
    pub local_port: u16,
    pub direction: Direction,
    pub state: ConnState,
}

/// one running process under an app: its own throughput, totals, and connections
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcSample {
    pub pid: u32,
    /// the Windows service(s) hosted in this process, when it is a service host
    /// like svchost.exe, so the UI names the service instead of a bare pid
    pub service: Option<String>,
    pub rate_sent: u64,
    pub rate_recv: u64,
    pub total: ByteCounts,
    pub online: bool,
    pub conns: Vec<Conn>,
}

/// one app row for a sample tick: the aggregate across its processes, plus the
/// per-process breakdown for the tree. pushed to the UI ~1/sec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppSample {
    pub app: AppId,
    /// friendly display name if resolved, else None
    pub name: Option<String>,
    /// bytes/sec over the sample window, summed across processes
    pub rate_sent: u64,
    pub rate_recv: u64,
    /// cumulative counters for the session
    pub total: ByteCounts,
    /// open connection count across all processes
    pub connections: u32,
    /// whether any process is active now; false while the app lingers in the
    /// post-disconnect grace window
    pub online: bool,
    /// the app's processes, each with its own rate, totals, and connections
    pub processes: Vec<ProcSample>,
}

/// one adapter kind's row in a sample tick: live rates plus session totals
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterSample {
    pub kind: AdapterKind,
    pub rate_sent: u64,
    pub rate_recv: u64,
    pub total: ByteCounts,
}

/// one monitor sample tick: a wall-clock stamp plus every active app's sample
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatsTick {
    /// milliseconds since unix epoch, stamped by the monitor
    pub at_ms: u64,
    /// aggregate across all apps this tick
    pub total_rate_sent: u64,
    pub total_rate_recv: u64,
    pub apps: Vec<AppSample>,
    /// traffic split by adapter kind, for kinds seen this session
    pub adapters: Vec<AdapterSample>,
}

/// a live connection row for the activity table's drill-down
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveConnection {
    pub app: AppId,
    pub local_port: u16,
    pub remote: Endpoint,
    pub direction: Direction,
    pub state: ConnState,
}

/// TCP connection state, coarse-grained (UDP is always Active)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnState {
    Listen,
    Active,
    Closing,
}
