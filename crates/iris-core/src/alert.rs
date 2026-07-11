use crate::model::{AppId, Endpoint};
use serde::{Deserialize, Serialize};

/// why an alert was raised
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AlertKind {
    /// an application connected to the network for the first time ever
    NewApp { app: AppId },
    /// a rule blocked an application's connection attempt
    Blocked { app: AppId, remote: Endpoint },
}

/// a durable alert. persisted so it survives a UI that is closed when the event
/// fires, then surfaced (and toasted) on next UI launch if still unacknowledged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub id: i64,
    /// milliseconds since unix epoch
    pub at_ms: u64,
    pub kind: AlertKind,
    pub acknowledged: bool,
}
