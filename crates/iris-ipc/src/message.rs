use iris_core::{Alert, LiveConnection, Rule, StatsTick, StoredRule, UsageBucket, UsageQuery};
use serde::{Deserialize, Serialize};

/// bump when the wire shape changes incompatibly. the UI refuses to drive a
/// service whose protocol differs, so a partial update never mismatches schemas.
pub const PROTOCOL_VERSION: u32 = 1;

/// a UI -> service message. every request carries a correlation `req` id the
/// service echoes in its [`Reply`]; control messages that need no reply use 0.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// first frame on connect; negotiates protocol version
    Hello { protocol: u32 },
    /// begin receiving [`ServerMessage::Tick`] pushes
    Subscribe,
    /// stop receiving ticks
    Unsubscribe,
    ListConnections { req: u64 },
    ListRules { req: u64 },
    AddRule { req: u64, rule: Rule },
    RemoveRule { req: u64, id: i64 },
    SetRuleEnabled { req: u64, id: i64, enabled: bool },
    GetUsage { req: u64, query: UsageQuery },
    ListAlerts { req: u64, unacked_only: bool },
    AckAlert { req: u64, id: i64 },
    /// terminate a single TCP connection (privileged)
    KillConnection {
        req: u64,
        local_port: u16,
        remote_addr: String,
        remote_port: u16,
    },
    /// keepalive; service replies with the same `req`
    Ping { req: u64 },
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
    Error(String),
}
