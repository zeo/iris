//! the wire protocol between the service and out-of-process plugins. a plugin
//! is a separate binary the service spawns under a restricted token; it talks
//! back over its own named pipe (never the telemetry or admin pipe, which carry
//! a different trust class) using the same length-prefixed bincode framing.
//!
//! the handshake authenticates the process, not the pipe: at spawn the service
//! generates a random token and hands it to the child through the
//! `IRIS_PLUGIN_TOKEN` environment variable; the child's first frame must be
//! [`PluginMessage::Register`] carrying it back. anything else drops the
//! connection. the service stamps the authenticated plugin id onto everything
//! the plugin emits, so a plugin cannot speak in another's name.

use iris_core::{Alert, Annotation, EnrichTarget, Rule, StatsTick};
use serde::{Deserialize, Serialize};

/// bump when the plugin wire shape changes incompatibly. independent of the UI
/// pipe's `PROTOCOL_VERSION`; plugins declare compatibility in their manifest.
/// v2 added rule proposals.
pub const PLUGIN_PROTOCOL_VERSION: u32 = 2;

/// the env var carrying the spawn-time auth token to the child, cleared by the
/// SDK as soon as it is read
pub const TOKEN_ENV: &str = "IRIS_PLUGIN_TOKEN";

/// which live streams a plugin wants pushed, further limited by its grant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamKind {
    Ticks,
    Alerts,
}

/// plugin -> service
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PluginMessage {
    /// first frame after connect; anything else drops the pipe
    Register {
        id: String,
        protocol: u32,
        token: String,
        /// capabilities the plugin wants this session, each of which must be
        /// inside its granted set (manifest ceiling intersected with consent)
        caps: Vec<String>,
    },
    /// begin receiving the requested streams (subject to `observe:*` caps)
    Subscribe { streams: Vec<StreamKind> },
    /// unsolicited annotations from a stream-watching plugin
    Enrichment {
        target: EnrichTarget,
        annotations: Vec<Annotation>,
    },
    /// response to [`HostMessage::EnrichRequest`]
    EnrichReply {
        req: u64,
        annotations: Vec<Annotation>,
    },
    /// raise a durable alert (subject to `emit:alerts`); the host stamps the
    /// source from the authenticated id, never from the wire
    RaiseAlert { message: String },
    /// suggest a firewall rule (subject to `emit:rule-proposals`). the host
    /// only records it for the user's review; nothing is enforced until an
    /// elevated caller accepts.
    ProposeRule { rule: Rule, reason: String },
    /// keepalive response
    Pong { req: u64 },
}

/// service -> plugin
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HostMessage {
    /// registration accepted; `granted` is the effective capability set
    Registered {
        granted: Vec<String>,
        engine_version: String,
    },
    /// registration refused; the pipe closes after this frame
    Rejected { reason: String },
    /// a live event on a subscribed stream
    Event(PluginEvent),
    /// resolve annotations for a target (subject to `enrich:*` caps)
    EnrichRequest { req: u64, target: EnrichTarget },
    /// keepalive; reply with [`PluginMessage::Pong`]
    Ping { req: u64 },
}

/// one event on a subscribed stream
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PluginEvent {
    Tick(StatsTick),
    Alert(Alert),
}
