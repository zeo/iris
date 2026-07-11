//! the firewall rule store. holds iris's rules, persists them as JSON under
//! %ProgramData%\Iris, and drives the platform WFP controller to enforce them.
//! on startup it wipes any leftover iris filters and re-applies the enabled
//! rules, so the JSON file is the single source of truth.

use iris_core::{Rule, StoredRule};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct Persisted {
    rule: Rule,
    enabled: bool,
}

pub struct RuleStore {
    #[cfg(windows)]
    wfp: Option<iris_platform_win::Wfp>,
    rules: Vec<StoredRule>,
    next_id: i64,
    path: PathBuf,
}

impl RuleStore {
    pub fn new() -> Self {
        let path = store_path();

        #[cfg(windows)]
        let mut wfp = match iris_platform_win::Wfp::open() {
            Ok(mut w) => {
                let _ = w.reset();
                Some(w)
            }
            Err(e) => {
                tracing::error!("WFP unavailable (rules will not be enforced): {e}");
                None
            }
        };

        let persisted: Vec<Persisted> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let mut rules = Vec::new();
        let mut next_id = 1i64;
        for p in persisted {
            let id = next_id;
            next_id += 1;
            let filter_ids = if p.enabled {
                #[cfg(windows)]
                {
                    apply(wfp.as_mut(), &p.rule)
                }
                #[cfg(not(windows))]
                {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            rules.push(StoredRule {
                id,
                rule: p.rule,
                filter_ids,
                enabled: p.enabled,
            });
        }

        RuleStore {
            #[cfg(windows)]
            wfp,
            rules,
            next_id,
            path,
        }
    }

    pub fn list(&self) -> Vec<StoredRule> {
        self.rules.clone()
    }

    /// add (or replace) a rule for an app+direction and enforce it now
    pub fn add(&mut self, rule: Rule) -> StoredRule {
        // replace any existing rule for the same app + direction
        let dupes: Vec<usize> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.rule.app == rule.app && r.rule.direction == rule.direction)
            .map(|(i, _)| i)
            .collect();
        for i in dupes.into_iter().rev() {
            let old = self.rules.remove(i);
            self.unapply(&old.filter_ids);
        }

        let id = self.next_id;
        self.next_id += 1;
        let filter_ids = self.apply_rule(&rule);
        let stored = StoredRule {
            id,
            rule,
            filter_ids,
            enabled: true,
        };
        self.rules.push(stored.clone());
        self.save();
        stored
    }

    pub fn remove(&mut self, id: i64) {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            let removed = self.rules.remove(pos);
            self.unapply(&removed.filter_ids);
            self.save();
        }
    }

    pub fn set_enabled(&mut self, id: i64, enabled: bool) -> Option<StoredRule> {
        let pos = self.rules.iter().position(|r| r.id == id)?;
        if enabled && !self.rules[pos].enabled {
            let rule = self.rules[pos].rule.clone();
            let ids = self.apply_rule(&rule);
            self.rules[pos].filter_ids = ids;
            self.rules[pos].enabled = true;
        } else if !enabled && self.rules[pos].enabled {
            let ids = std::mem::take(&mut self.rules[pos].filter_ids);
            self.unapply(&ids);
            self.rules[pos].enabled = false;
        }
        self.save();
        Some(self.rules[pos].clone())
    }

    fn apply_rule(&mut self, rule: &Rule) -> Vec<u64> {
        #[cfg(windows)]
        {
            apply(self.wfp.as_mut(), rule)
        }
        #[cfg(not(windows))]
        {
            let _ = rule;
            Vec::new()
        }
    }

    fn unapply(&mut self, ids: &[u64]) {
        #[cfg(windows)]
        {
            if let Some(w) = self.wfp.as_mut() {
                let _ = w.remove(ids);
            }
        }
        #[cfg(not(windows))]
        {
            let _ = ids;
        }
    }

    fn save(&self) {
        let persisted: Vec<Persisted> = self
            .rules
            .iter()
            .map(|r| Persisted {
                rule: r.rule.clone(),
                enabled: r.enabled,
            })
            .collect();
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&persisted) {
            let _ = std::fs::write(&self.path, json);
        }
    }
}

impl Default for RuleStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
fn apply(wfp: Option<&mut iris_platform_win::Wfp>, rule: &Rule) -> Vec<u64> {
    match wfp {
        Some(w) => w
            .apply(rule.app.as_str(), rule.direction, rule.action)
            .unwrap_or_else(|e| {
                tracing::error!("failed to enforce rule for {}: {e}", rule.app.as_str());
                Vec::new()
            }),
        None => Vec::new(),
    }
}

fn store_path() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(base).join("Iris").join("rules.json")
}
