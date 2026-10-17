use crate::model::{AppId, Direction, Endpoint, Protocol};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// how the firewall treats an application it has no decision for
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallMode {
    /// deny the connection until the user answers its prompt
    #[default]
    Ask,
    /// let it connect and raise the prompt afterwards
    Notify,
    /// deny every non-loopback connection, whatever the rules say
    Lockdown,
}

impl FirewallMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            FirewallMode::Ask => "ask",
            FirewallMode::Notify => "notify",
            FirewallMode::Lockdown => "lockdown",
        }
    }

    pub fn parse(s: &str) -> Option<FirewallMode> {
        match s {
            "ask" => Some(FirewallMode::Ask),
            "notify" => Some(FirewallMode::Notify),
            "lockdown" => Some(FirewallMode::Lockdown),
            _ => None,
        }
    }
}

/// an address or network a rule is limited to
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// `10.0.0.0/8`, `2001:db8::/32`, or a bare address for a single host
    pub fn parse(s: &str) -> Option<Cidr> {
        let (addr, prefix) = match s.trim().split_once('/') {
            Some((addr, prefix)) => (addr.parse::<IpAddr>().ok()?, Some(prefix.parse::<u8>().ok()?)),
            None => (s.trim().parse::<IpAddr>().ok()?, None),
        };
        let width = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(width);
        (prefix <= width).then(|| Cidr { addr: mask(addr, prefix), prefix })
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        addr.is_ipv4() == self.addr.is_ipv4() && mask(addr, self.prefix) == self.addr
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4) & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(bits.into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6) & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(bits.into())
        }
    }
}

/// an inclusive remote port range; a single port has `start == end`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// `443` or `8000-8100`
    pub fn parse(s: &str) -> Option<PortRange> {
        let (start, end) = match s.trim().split_once('-') {
            Some((start, end)) => (start.trim().parse().ok()?, end.trim().parse().ok()?),
            None => {
                let port = s.trim().parse().ok()?;
                (port, port)
            }
        };
        (start <= end).then_some(PortRange { start, end })
    }

    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

/// what part of an app's traffic a rule covers. every field left empty means
/// the rule covers all of the app's traffic in its direction
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<Cidr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<PortRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
}

impl RuleScope {
    pub fn is_whole_app(&self) -> bool {
        *self == RuleScope::default()
    }

    pub fn matches(&self, remote: &Endpoint) -> bool {
        self.remote.is_none_or(|cidr| cidr.contains(remote.addr))
            && self.ports.is_none_or(|ports| ports.contains(remote.port))
            && self.protocol.is_none_or(|protocol| protocol == remote.protocol)
    }
}

/// how long a rule stays in force
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RuleLifetime {
    #[default]
    Permanent,
    /// dropped when the engine next starts
    UntilRestart,
    /// dropped once the wall clock passes this instant
    Until { at_ms: u64 },
}

impl RuleLifetime {
    pub fn is_permanent(&self) -> bool {
        *self == RuleLifetime::Permanent
    }

    pub fn expired(&self, now_ms: u64) -> bool {
        matches!(self, RuleLifetime::Until { at_ms } if *at_ms <= now_ms)
    }
}

/// what a firewall rule does to matching traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Block,
}

/// a per-application firewall rule the Protect tab manages. one rule pins one
/// app's traffic in one direction to allow or block. the platform layer maps
/// this onto WFP filters (windows) or nftables (linux) and records the backing
/// filter id so it can be removed without re-enumerating.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub app: AppId,
    pub direction: Direction,
    pub action: RuleAction,
    /// friendly label shown in the UI, defaults to the app file name
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "RuleScope::is_whole_app")]
    pub scope: RuleScope,
    #[serde(default, skip_serializing_if = "RuleLifetime::is_permanent")]
    pub lifetime: RuleLifetime,
}

impl Rule {
    pub fn new(app: AppId, direction: Direction, action: RuleAction) -> Self {
        Rule {
            app,
            direction,
            action,
            label: None,
            scope: RuleScope::default(),
            lifetime: RuleLifetime::Permanent,
        }
    }

    pub fn block_outbound(app: AppId) -> Self {
        Rule::new(app, Direction::Outbound, RuleAction::Block)
    }

    /// two rules occupy the same slot, so adding one replaces the other
    pub fn same_slot(&self, other: &Rule) -> bool {
        self.app == other.app && self.direction == other.direction && self.scope == other.scope
    }
}

/// how a plugin-proposed rule was disposed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalState {
    Pending,
    Accepted,
    Rejected,
}

impl ProposalState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProposalState::Pending => "pending",
            ProposalState::Accepted => "accepted",
            ProposalState::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> Option<ProposalState> {
        match s {
            "pending" => Some(ProposalState::Pending),
            "accepted" => Some(ProposalState::Accepted),
            "rejected" => Some(ProposalState::Rejected),
            _ => None,
        }
    }
}

/// a rule a plugin suggested. a plugin never touches enforcement itself: the
/// proposal sits pending until the user accepts it (an elevated action, the
/// same as adding a rule by hand) or dismisses it. `source` is the proposing
/// plugin's authenticated name, stamped by the service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleProposal {
    pub id: i64,
    pub source: String,
    pub rule: Rule,
    pub reason: String,
    pub at_ms: u64,
    pub state: ProposalState,
}

/// a rule as stored, carrying the platform-assigned filter identities so it can
/// be re-applied on service restart and deleted by id
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredRule {
    pub id: i64,
    pub rule: Rule,
    /// opaque platform filter ids (one WFP filter per IP family); empty when the
    /// rule is disabled or not applied
    #[serde(default)]
    pub filter_ids: Vec<u64>,
    /// whether the rule is currently enforced in the OS
    pub enabled: bool,
}

/// one entry in a rules backup file, the shape the Protect tab's export writes.
/// machine-local details (rule ids, platform filter ids) stay out so a backup
/// restores cleanly on another machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupRule {
    pub app: String,
    pub direction: Direction,
    pub action: RuleAction,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "RuleScope::is_whole_app")]
    pub scope: RuleScope,
}

fn enabled_by_default() -> bool {
    true
}

impl BackupRule {
    pub fn to_rule(&self) -> Rule {
        Rule {
            scope: self.scope,
            ..Rule::new(AppId::from_path(&self.app), self.direction, self.action)
        }
    }
}

/// largest backup file worth reading; a real backup is a few kilobytes
pub const BACKUP_MAX_BYTES: u64 = 1024 * 1024;

/// parse a rules backup, rejecting shapes that would import as nonsense
pub fn parse_backup(json: &str) -> Result<Vec<BackupRule>, String> {
    let entries: Vec<BackupRule> =
        serde_json::from_str(json).map_err(|e| format!("not a rules backup: {e}"))?;
    if entries.is_empty() {
        return Err("the file has no rules in it".to_string());
    }
    for (n, entry) in entries.iter().enumerate() {
        if entry.app.trim().is_empty() {
            return Err(format!("rule {} has an empty application path", n + 1));
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_parses_the_export_shape() {
        let json = r#"[
            {"app":"c:\\apps\\a.exe","direction":"outbound","action":"block","enabled":false},
            {"app":"c:\\apps\\b.exe","direction":"inbound","action":"allow","enabled":true}
        ]"#;
        let entries = parse_backup(json).expect("valid backup");
        assert_eq!(entries.len(), 2);
        assert!(!entries[0].enabled);
        assert_eq!(entries[0].action, RuleAction::Block);
        let rule = entries[1].to_rule();
        assert_eq!(rule.app, AppId::from_path("c:\\apps\\b.exe"));
        assert_eq!(rule.direction, Direction::Inbound);
    }

    #[test]
    fn cidr_parses_and_masks() {
        let net = Cidr::parse("10.1.2.3/8").expect("cidr");
        assert_eq!(net.to_string(), "10.0.0.0/8");
        assert!(net.contains("10.200.0.1".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        assert!(!net.contains("::a01:203".parse().unwrap()));
        assert_eq!(Cidr::parse("1.2.3.4").unwrap().prefix, 32);
        assert_eq!(Cidr::parse("2001:db8::1/32").unwrap().to_string(), "2001:db8::/32");
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("example.com").is_none());
    }

    #[test]
    fn ports_parse_single_and_ranges() {
        assert_eq!(PortRange::parse("443"), Some(PortRange { start: 443, end: 443 }));
        assert!(PortRange::parse("8000-8100").unwrap().contains(8050));
        assert!(PortRange::parse("90-80").is_none());
        assert!(PortRange::parse("70000").is_none());
    }

    #[test]
    fn scope_matches_every_set_field() {
        let scope = RuleScope {
            remote: Cidr::parse("192.168.0.0/16"),
            ports: PortRange::parse("53"),
            protocol: Some(Protocol::Udp),
        };
        let hit = Endpoint { addr: "192.168.1.1".parse().unwrap(), port: 53, protocol: Protocol::Udp };
        assert!(scope.matches(&hit));
        assert!(!scope.matches(&Endpoint { protocol: Protocol::Tcp, ..hit }));
        assert!(!scope.matches(&Endpoint { port: 443, ..hit }));
        assert!(RuleScope::default().matches(&hit));
    }

    #[test]
    fn legacy_rules_read_as_whole_app_and_permanent() {
        let json = r#"{"app":"c:\\a.exe","direction":"outbound","action":"block","label":null}"#;
        let rule: Rule = serde_json::from_str(json).expect("legacy rule");
        assert!(rule.scope.is_whole_app());
        assert!(rule.lifetime.is_permanent());
        assert_eq!(serde_json::to_string(&rule).unwrap(), json);
    }

    #[test]
    fn timed_rules_expire() {
        let lifetime = RuleLifetime::Until { at_ms: 100 };
        assert!(!lifetime.expired(99));
        assert!(lifetime.expired(100));
        assert!(!RuleLifetime::UntilRestart.expired(u64::MAX));
    }

    #[test]
    fn backup_defaults_enabled_when_absent() {
        let json = r#"[{"app":"c:\\apps\\a.exe","direction":"outbound","action":"block"}]"#;
        assert!(parse_backup(json).expect("valid backup")[0].enabled);
    }

    #[test]
    fn backup_rejects_junk() {
        assert!(parse_backup("").is_err());
        assert!(parse_backup("{\"app\":\"x\"}").is_err());
        assert!(parse_backup("[]").is_err());
        let blank = r#"[{"app":"  ","direction":"outbound","action":"block"}]"#;
        assert!(parse_backup(blank)
            .unwrap_err()
            .contains("empty application path"));
    }
}
