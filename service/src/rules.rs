//! the firewall rule store. holds iris's rules, persists them as JSON under
//! %ProgramData%\Iris, and drives the platform WFP controller to enforce them.
//! on startup it wipes any leftover iris filters and re-applies the enabled
//! rules, so the JSON file is the single source of truth.

use iris_core::{Rule, StoredRule};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct Persisted {
    /// stable rule id, persisted so a UI-cached id still targets the right rule
    /// after the service restarts. legacy files without it default to 0 and get
    /// a fresh id assigned on load.
    #[serde(default)]
    id: i64,
    rule: Rule,
    enabled: bool,
}

/// outcome of reading the rules file, keeping "no file yet" distinct from "file
/// present but unreadable" so a corrupt file never masquerades as an empty rule
/// set and silently drops all firewall enforcement.
enum Loaded {
    Empty,
    Rules(Vec<Persisted>),
    Corrupt,
}

fn load_persisted(path: &Path) -> Loaded {
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Empty,
        Err(e) => {
            tracing::error!("cannot read rules file {}: {e}", path.display());
            Loaded::Corrupt
        }
        Ok(s) if s.trim().is_empty() => Loaded::Empty,
        Ok(s) => match serde_json::from_str::<Vec<Persisted>>(&s) {
            Ok(v) => Loaded::Rules(v),
            Err(e) => {
                tracing::error!("rules file {} is corrupt: {e}", path.display());
                Loaded::Corrupt
            }
        },
    }
}

fn back_up_corrupt(path: &Path) {
    let bak = path.with_extension("json.corrupt");
    match std::fs::rename(path, &bak) {
        Ok(()) => tracing::warn!("moved corrupt rules file to {}", bak.display()),
        Err(e) => tracing::error!("could not set aside corrupt rules file: {e}"),
    }
}

pub struct RuleStore {
    #[cfg(has_platform)]
    wfp: Option<crate::platform::Wfp>,
    rules: Vec<StoredRule>,
    next_id: i64,
    path: PathBuf,
}

impl RuleStore {
    pub fn new() -> anyhow::Result<Self> {
        let path = store_path();
        let loaded = load_persisted(&path);

        #[cfg(has_platform)]
        let mut wfp = Some(crate::platform::Wfp::open()?);

        // a corrupt file is the one case we must not reset on: we cannot know the
        // intended rules, so leaving the last-good filters enforcing and starting
        // with an empty in-memory set is the fail-safe. otherwise wipe stale
        // filters and re-apply from the file (the single source of truth).
        let persisted: Vec<Persisted> = match loaded {
            Loaded::Rules(v) => {
                #[cfg(has_platform)]
                if let Some(w) = wfp.as_mut() {
                    w.reset()?;
                }
                v
            }
            Loaded::Empty => {
                #[cfg(has_platform)]
                if let Some(w) = wfp.as_mut() {
                    w.reset()?;
                }
                Vec::new()
            }
            Loaded::Corrupt => {
                back_up_corrupt(&path);
                Vec::new()
            }
        };

        // honor ids already in the file so they stay stable across restarts, and
        // assign fresh ones only to legacy (id 0) entries
        let mut next_id = 1i64;
        for p in &persisted {
            next_id = next_id.max(p.id + 1);
        }
        let mut rules = Vec::new();
        for p in persisted {
            let id = if p.id > 0 {
                p.id
            } else {
                let x = next_id;
                next_id += 1;
                x
            };
            let filter_ids = if p.enabled {
                #[cfg(has_platform)]
                {
                    apply(wfp.as_mut(), &p.rule)?
                }
                #[cfg(not(has_platform))]
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

        Ok(RuleStore {
            #[cfg(has_platform)]
            wfp,
            rules,
            next_id,
            path,
        })
    }

    pub fn list(&self) -> Vec<StoredRule> {
        self.rules.clone()
    }

    #[cfg(target_os = "linux")]
    pub fn enforcement_healthy(&self) -> bool {
        self.wfp
            .as_ref()
            .is_some_and(crate::platform::Wfp::is_healthy)
    }

    #[cfg(target_os = "linux")]
    pub fn take_pending_receiver(
        &mut self,
    ) -> Option<std::sync::mpsc::Receiver<crate::platform::PendingConnection>> {
        self.wfp
            .as_mut()
            .and_then(crate::platform::Wfp::take_pending_receiver)
    }

    #[cfg(target_os = "linux")]
    pub fn trust_apps(&self, paths: &[String]) {
        if let Some(wfp) = &self.wfp {
            wfp.trust_apps(paths);
        }
    }

    #[cfg(target_os = "linux")]
    pub fn forget_trusted_app(&self, path: &str) {
        if let Some(wfp) = &self.wfp {
            wfp.forget_app(path);
        }
    }

    /// add (or replace) a rule for an app+direction and enforce it now
    pub fn add(&mut self, rule: Rule) -> anyhow::Result<StoredRule> {
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
            self.unapply(&old.filter_ids)?;
        }

        let id = self.next_id;
        self.next_id += 1;
        let filter_ids = self.apply_rule(&rule)?;
        let stored = StoredRule {
            id,
            rule,
            filter_ids,
            enabled: true,
        };
        self.rules.push(stored.clone());
        self.save()?;
        Ok(stored)
    }

    /// remove a rule; returns whether a rule with that id existed, so the caller
    /// can tell the UI the truth instead of a blanket success
    pub fn remove(&mut self, id: i64) -> anyhow::Result<bool> {
        if let Some(pos) = self.rules.iter().position(|r| r.id == id) {
            let removed = self.rules.remove(pos);
            self.unapply(&removed.filter_ids)?;
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn set_enabled(&mut self, id: i64, enabled: bool) -> anyhow::Result<Option<StoredRule>> {
        let Some(pos) = self.rules.iter().position(|r| r.id == id) else {
            return Ok(None);
        };
        if enabled && !self.rules[pos].enabled {
            let rule = self.rules[pos].rule.clone();
            let ids = self.apply_rule(&rule)?;
            self.rules[pos].filter_ids = ids;
            self.rules[pos].enabled = true;
        } else if !enabled && self.rules[pos].enabled {
            let ids = std::mem::take(&mut self.rules[pos].filter_ids);
            self.unapply(&ids)?;
            self.rules[pos].enabled = false;
        }
        self.save()?;
        Ok(Some(self.rules[pos].clone()))
    }

    fn apply_rule(&mut self, rule: &Rule) -> anyhow::Result<Vec<u64>> {
        #[cfg(has_platform)]
        {
            Ok(apply(self.wfp.as_mut(), rule)?)
        }
        #[cfg(not(has_platform))]
        {
            let _ = rule;
            Ok(Vec::new())
        }
    }

    fn unapply(&mut self, ids: &[u64]) -> anyhow::Result<()> {
        #[cfg(has_platform)]
        {
            if let Some(w) = self.wfp.as_mut() {
                w.remove(ids)?;
            }
        }
        #[cfg(not(has_platform))]
        {
            let _ = ids;
        }
        Ok(())
    }

    fn save(&self) -> anyhow::Result<()> {
        let persisted: Vec<Persisted> = self
            .rules
            .iter()
            .map(|r| Persisted {
                id: r.id,
                rule: r.rule.clone(),
                enabled: r.enabled,
            })
            .collect();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&persisted)?;
        // write a temp file then rename over the target so a crash mid-write can
        // never truncate the live rules file into something that parses as empty
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes())?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(has_platform)]
fn apply(wfp: Option<&mut crate::platform::Wfp>, rule: &Rule) -> iris_core::EngineResult<Vec<u64>> {
    match wfp {
        Some(w) => w.apply(rule.app.as_str(), rule.direction, rule.action),
        None => Err(iris_core::EngineError::NotInitialized),
    }
}

fn store_path() -> PathBuf {
    crate::paths::rules_file()
}
