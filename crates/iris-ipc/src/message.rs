use iris_core::{
    AdapterKind, Alert, Annotation, AppId, ByteCounts, EnrichTarget, FirewallMode, HostUsage, KnownApp, Profile, ProfileState, RateCap,
    Panel, Quota, QuotaLimit, Rule, RuleAction, RuleLifetime, RuleProposal, RuleScope, StatsTick, StoredRule, UsageBucket,
    UsageQuery,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// bump when the wire shape changes incompatibly. the UI refuses to drive a
/// service whose protocol differs, so a partial update never mismatches schemas.
/// v2 added the enrichment channel (annotations for endpoints/apps); v3 added
/// the per-adapter breakdown carried in every tick; v4 added plugin management;
/// v5 added rule proposals and plugin panels.
/// v6 added durable app inventory and compact host summaries.
/// v7 added bulk app forget, install state on the inventory, and the delegated
/// rule-management grant that replaces a UAC prompt per rule change.
/// v8 separates promptable alerts from decisions deferred during fullscreen.
/// v9 adds the byte-capture degraded push.
/// v10 adds rule scopes and lifetimes, and the firewall mode.
/// v11 adds per-host usage history.
/// v12 adds network profiles.
/// v13 adds per-app upload caps.
/// v14 adds the engine health query.
/// v15 always sends rule scopes, lifetimes, and profile modes, which bincode
/// could not decode while they were skipped when empty, and adds data quotas.
/// v16 adds download caps.
/// v17 adds per-connection rates.
/// v18 carries the firewall mode in every tick, adds a totals-only tick
/// subscription, removes the unused connection list and prompt suppression
/// messages, lets a prompt answer carry a host scope and a lifetime, and adds
/// the addresses a host name resolved to.
pub const PROTOCOL_VERSION: u32 = 18;

/// conditions that quietly undermine the engine, for the UI to surface
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Health {
    /// the history database could not open, so nothing recorded survives a restart
    pub history_in_memory: bool,
    /// windows firewall profiles that block outbound by default, which
    /// overrides iris's allows
    pub outbound_blocked: Vec<String>,
}

/// what the UI shows for one installed plugin: its declared identity and
/// capabilities, plus whether the user has consented and enabled it
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    /// what the manifest declares it may do (the ceiling)
    pub capabilities: Vec<String>,
    /// declared egress hosts (`host:port`)
    pub egress: Vec<String>,
    /// whether a consent grant exists for it
    pub granted: bool,
    /// whether it is currently switched on
    pub enabled: bool,
}

/// a UI -> service message. every request carries a correlation `req` id the
/// service echoes in its [`Reply`]; control messages that need no reply use 0.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// first frame on connect; negotiates protocol version
    Hello {
        protocol: u32,
    },
    /// begin receiving [`ServerMessage::Tick`] pushes
    Subscribe,
    /// stop receiving ticks
    Unsubscribe,
    /// receive [`ServerMessage::Totals`] in place of full ticks, for a client
    /// that shows only aggregate throughput
    SubscribeTotals,
    ListRules {
        req: u64,
    },
    ListApps {
        req: u64,
    },
    ForgetApp {
        req: u64,
        path: String,
    },
    /// drop several apps from the inventory at once (the inactive-app sweep)
    ForgetApps {
        req: u64,
        paths: Vec<String>,
    },
    /// whether the calling desktop account may change rules without elevating
    GetRuleGrant {
        req: u64,
    },
    /// record or revoke the delegated rule-management grant. only honored on the
    /// admin channel, so establishing it costs one elevation.
    SetRuleGrant {
        req: u64,
        granted: bool,
    },
    AddRule {
        req: u64,
        rule: Rule,
    },
    GetFirewallMode {
        req: u64,
    },
    GetProfiles {
        req: u64,
    },
    ListCaps {
        req: u64,
    },
    GetHealth {
        req: u64,
    },
    /// cap an app's upload and download, lifting each with none. privileged
    SetCap {
        req: u64,
        app: AppId,
        up_bytes_per_sec: Option<u64>,
        down_bytes_per_sec: Option<u64>,
    },
    ListQuotas {
        req: u64,
    },
    /// set or clear an app's data quota, which blocks the app once spent, so
    /// it is privileged. with no app it sets the machine-wide data plan, which
    /// only warns
    SetQuota {
        req: u64,
        app: Option<AppId>,
        limit: Option<QuotaLimit>,
    },
    /// replace the network profiles and the manual choice. privileged, since
    /// switching profile changes which rules are enforced
    SetProfiles {
        req: u64,
        profiles: Vec<Profile>,
        manual: Option<String>,
    },
    /// ask, notify, or lockdown. privileged like a rule change
    SetFirewallMode {
        req: u64,
        mode: FirewallMode,
    },
    RemoveRule {
        req: u64,
        id: i64,
    },
    SetRuleEnabled {
        req: u64,
        id: i64,
        enabled: bool,
    },
    GetUsage {
        req: u64,
        query: UsageQuery,
    },
    ListAlerts {
        req: u64,
        unacked_only: bool,
    },
    /// pending connection decisions that have not been deferred from the
    /// desktop prompt surface
    ListPromptAlerts {
        req: u64,
    },
    AckAlert {
        req: u64,
        id: i64,
    },
    /// answer a pending prompt; the scope may only narrow to the prompt's own
    /// remote address
    DecideAlert {
        req: u64,
        id: i64,
        action: RuleAction,
        scope: RuleScope,
        lifetime: RuleLifetime,
    },
    /// terminate a single TCP connection (privileged)
    KillConnection {
        req: u64,
        local_port: u16,
        remote_addr: String,
        remote_port: u16,
    },
    /// fetch any cached annotations for these targets, and enqueue a background
    /// resolve for the ones not cached yet (results arrive as pushes)
    GetEnrichment {
        req: u64,
        targets: Vec<EnrichTarget>,
    },
    /// keepalive; service replies with the same `req`
    Ping {
        req: u64,
    },
    /// the addresses the engine has seen `host` resolve to, from its DNS map
    HostAddresses {
        req: u64,
        host: String,
    },
    /// traffic per app and remote host over a window, for one app or all
    GetHostUsage {
        req: u64,
        app: Option<AppId>,
        from_ms: u64,
        to_ms: u64,
    },
    /// per-adapter-kind traffic totals over a window
    GetAdapterUsage {
        req: u64,
        from_ms: u64,
        to_ms: u64,
    },
    /// enumerate installed plugins and their consent state
    ListPlugins {
        req: u64,
    },
    /// record the user's consent for a plugin (the caps and egress they approved)
    GrantPlugin {
        req: u64,
        id: String,
        caps: Vec<String>,
        egress: Vec<String>,
    },
    /// switch a granted plugin on or off
    SetPluginEnabled {
        req: u64,
        id: String,
        enabled: bool,
    },
    /// recent plugin rule proposals, pending first
    ListProposals {
        req: u64,
    },
    /// settle a pending proposal. accepting enforces a rule, so it is only
    /// honored on the admin pipe; the telemetry pipe may only reject.
    ResolveProposal {
        req: u64,
        id: i64,
        accept: bool,
    },
    /// fetch a plugin's panel view-model for its tab
    GetPluginPanel {
        req: u64,
        id: String,
    },
}

/// a service -> UI message: either an unsolicited push (`Tick`, `Alert`,
/// `Welcome`) or a `Reply` correlated to a client request by `req`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerMessage {
    /// response to `Hello`; carries the engine build for the version gate
    Welcome {
        protocol: u32,
        engine_version: String,
    },
    /// live sample push
    Tick(StatsTick),
    /// the aggregate rates of a tick, sent in its place to a totals subscriber
    Totals {
        at_ms: u64,
        total_rate_sent: u64,
        total_rate_recv: u64,
        mode: FirewallMode,
    },
    /// durable alert push (also delivered on next connect if unacked)
    Alert(Alert),
    /// annotations resolved for a target, pushed as enrichers finish off the
    /// hot path (never stapled onto `Tick`)
    Enrichment {
        target: EnrichTarget,
        annotations: Vec<Annotation>,
    },
    /// a plugin proposed a rule; pushed so the review UI updates live
    Proposal(RuleProposal),
    /// byte capture is degraded: connection lists keep flowing but per-app
    /// throughput and usage history are incomplete. pushed on entering and
    /// leaving the degraded state so the UI can say what is wrong.
    CaptureDegraded { degraded: bool },
    /// correlated response to a client request
    Reply { req: u64, result: Reply },
}

/// the payload of a correlated [`ServerMessage::Reply`]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Reply {
    Ok,
    Pong,
    Rules(Vec<StoredRule>),
    Apps(Vec<KnownApp>),
    RuleAdded(StoredRule),
    Alerts(Vec<Alert>),
    Usage(Vec<UsageBucket>),
    /// cached annotations, one entry per requested target that had any
    Enrichment(Vec<(EnrichTarget, Vec<Annotation>)>),
    Error(String),
    /// per-adapter-kind totals, biggest first
    AdapterUsage(Vec<(AdapterKind, ByteCounts)>),
    /// installed plugins and their consent state
    Plugins(Vec<PluginInfo>),
    /// recent rule proposals, newest first
    Proposals(Vec<RuleProposal>),
    /// a plugin's panel view-model
    Panel(Panel),
    /// how many apps a bulk forget actually removed
    Forgotten(usize),
    /// whether the delegated rule-management grant is in force
    RuleGrant(bool),
    FirewallMode(FirewallMode),
    Profiles(ProfileState),
    Caps(Vec<RateCap>),
    Quotas(Vec<Quota>),
    Health(Health),
    /// per-host totals, biggest first
    HostUsage(Vec<HostUsage>),
    HostAddresses(Vec<IpAddr>),
}
