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
}

fn enabled_by_default() -> bool {
    true
}

impl BackupRule {
    pub fn to_rule(&self) -> Rule {
        Rule {
            app: AppId::from_path(&self.app),
            direction: self.direction,
            action: self.action,
            label: None,
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
        assert!(parse_backup(blank).unwrap_err().contains("empty application path"));
    }
}
