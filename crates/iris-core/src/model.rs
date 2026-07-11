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

/// stable identity of an application: its on-disk image path, lowercased and
/// normalized. the firewall keys rules on this and history rows reference it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AppId(pub String);

impl AppId {
    /// normalize a raw image path into a stable id (lowercase, forward-agnostic)
    pub fn from_path(path: &str) -> Self {
        AppId(path.trim().to_lowercase())
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

/// a running process the monitor attributes traffic to. keyed on (pid,
/// start_time) so pid reuse across process lifetimes never merges two apps.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: u32,
    /// process creation time as a raw FILETIME-style tick, opaque to core
    pub start_tick: u64,
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

/// one monitor sample tick: a wall-clock stamp plus every active app's sample
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatsTick {
    /// milliseconds since unix epoch, stamped by the monitor
    pub at_ms: u64,
    /// aggregate across all apps this tick
    pub total_rate_sent: u64,
    pub total_rate_recv: u64,
    pub apps: Vec<AppSample>,
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
