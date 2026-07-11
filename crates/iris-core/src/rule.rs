use crate::model::{AppId, Direction};
use serde::{Deserialize, Serialize};

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
}

impl Rule {
    pub fn block_outbound(app: AppId) -> Self {
        Rule {
            app,
            direction: Direction::Outbound,
            action: RuleAction::Block,
            label: None,
        }
    }
}

/// a rule as stored, carrying the platform-assigned filter identity so it can be
/// re-applied on service restart and deleted by id
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredRule {
    pub id: i64,
    pub rule: Rule,
    /// opaque platform filter id (WFP filter id on windows); None until applied
    pub filter_id: Option<u64>,
    /// whether the rule is currently enforced in the OS
    pub enabled: bool,
}
