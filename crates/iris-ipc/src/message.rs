use iris_core::{
    AdapterKind, Alert, Annotation, ByteCounts, EnrichTarget, LiveConnection, Panel, Rule,
    RuleProposal, StatsTick, StoredRule, UsageBucket, UsageQuery,
};
use serde::{Deserialize, Serialize};

/// bump when the wire shape changes incompatibly. the UI refuses to drive a
/// service whose protocol differs, so a partial update never mismatches schemas.
/// v2 added the enrichment channel (annotations for endpoints/apps); v3 added
/// the per-adapter breakdown carried in every tick; v4 added plugin management;
/// v5 added rule proposals and plugin panels.
pub const PROTOCOL_VERSION: u32 = 5;

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
    ListConnections {
        req: u64,
    },
    ListRules {
        req: u64,
    },
    AddRule {
        req: u64,
        rule: Rule,
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
    AckAlert {
        req: u64,
        id: i64,
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
    /// correlated response to a client request
    Reply { req: u64, result: Reply },
}

/// the payload of a correlated [`ServerMessage::Reply`]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Reply {
    Ok,
    Pong,
    Connections(Vec<LiveConnection>),
    Rules(Vec<StoredRule>),
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
}
