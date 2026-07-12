//! the declarative view-model a plugin returns for its panel tab. a plugin
//! never ships markup or script into the webview: it describes its state in
//! this small widget vocabulary and the UI renders it with the same primitives
//! the built-in tabs use, so a plugin panel inherits the design language and
//! can do nothing a built-in view could not.

use crate::enrich::Severity;
use serde::{Deserialize, Serialize};

/// one block in a plugin panel, rendered top to bottom
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Widget {
    /// a single prominent figure, e.g. lookups performed
    Stat { label: String, value: String },
    /// label/value pairs, e.g. configuration or per-host counters
    Kv(Vec<(String, String)>),
    /// a small table; rows are clipped to the column count when rendered
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// a row of severity-tinted badges, e.g. verdict counts
    BadgeRow(Vec<(String, Severity)>),
    /// a mini trend line over the plugin's own series
    Sparkline { label: String, points: Vec<f64> },
    /// a sentence of free text, e.g. a status or hint
    Note(String),
}

/// what a plugin's tab shows; requested on demand, never pushed
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Panel {
    pub title: String,
    pub widgets: Vec<Widget>,
}
