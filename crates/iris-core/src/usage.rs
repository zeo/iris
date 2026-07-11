use crate::model::{AppId, ByteCounts};
use serde::{Deserialize, Serialize};

/// time resolution of a usage rollup. history is downsampled minute -> hour ->
/// day as it ages to keep the store bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Granularity {
    Minute,
    Hour,
    Day,
}

impl Granularity {
    /// bucket width in milliseconds
    pub fn width_ms(self) -> u64 {
        match self {
            Granularity::Minute => 60_000,
            Granularity::Hour => 3_600_000,
            Granularity::Day => 86_400_000,
        }
    }

    /// snap a timestamp down to the start of its bucket
    pub fn bucket_start(self, at_ms: u64) -> u64 {
        let w = self.width_ms();
        at_ms - (at_ms % w)
    }
}

/// a request for historical usage over a window at some resolution
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageQuery {
    /// restrict to one app, or None for all apps aggregated
    pub app: Option<AppId>,
    pub from_ms: u64,
    pub to_ms: u64,
    pub granularity: Granularity,
}

/// one rollup row: an app's bytes within a single time bucket
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageBucket {
    pub app: AppId,
    pub bucket_start_ms: u64,
    pub bytes: ByteCounts,
}
