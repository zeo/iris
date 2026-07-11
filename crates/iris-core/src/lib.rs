//! platform-neutral domain models and engine traits for iris.
//!
//! this crate holds the vocabulary the rest of the app is built on: the data
//! shapes that cross the IPC boundary ([`model`]), the firewall [`rule`] and
//! [`alert`] types, the platform [`engine`] traits (`NetworkMonitor`,
//! `FirewallController`) that a per-OS backend implements, and the [`aggregate`]
//! logic that turns raw network events into sample ticks. nothing here touches
//! the OS, so it compiles and tests on any target.

pub mod aggregate;
pub mod alert;
pub mod engine;
pub mod error;
pub mod model;
pub mod rule;
pub mod usage;

pub use aggregate::{Aggregator, PidSample};
pub use alert::{Alert, AlertKind};
pub use engine::{FirewallController, MonitorSink, NetworkMonitor};
pub use error::{EngineError, EngineResult};
pub use model::{
    AppId, AppSample, ByteCounts, Conn, ConnState, Direction, Endpoint, LiveConnection, ProcSample,
    Protocol, StatsTick,
};
pub use rule::{Rule, RuleAction, StoredRule};
pub use usage::{Granularity, UsageBucket, UsageQuery};
