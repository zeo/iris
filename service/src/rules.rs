//! the firewall rule store. holds iris's rules, persists them as JSON under
//! %ProgramData%\Iris, and drives the platform WFP controller to enforce them.
//! on startup it wipes any leftover iris filters and re-applies the enabled
//! rules, so the JSON file is the single source of truth.

use iris_core::{
    active_profile, effective_mode, EngineError, FirewallMode, NetworkIdentity, Profile,
    ProfileState, Rule, RuleLifetime, StoredRule,
};
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
    mode: FirewallMode,
    profiles: SavedProfiles,
    network: Option<NetworkIdentity>,
    /// the profile in force, which decides which profile-tagged rules apply
    active: Option<String>,
    caps: crate::caps::CapStore,
}

fn mode_path() -> PathBuf {
    crate::paths::rules_file().with_file_name("mode.json")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SavedProfiles {
    #[serde(default)]
    profiles: Vec<Profile>,
    #[serde(default)]
    manual: Option<String>,
}

fn profiles_path() -> PathBuf {
    crate::paths::rules_file().with_file_name("profiles.json")
}

fn load_profiles() -> SavedProfiles {
    std::fs::read_to_string(profiles_path())
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

/// write json beside the rules file through a temp file, so a crash mid-write
/// never leaves a truncated one behind
fn write_atomic(path: &Path, json: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(has_platform)]
fn current_network() -> Option<NetworkIdentity> {
    crate::platform::current_network()
}

#[cfg(not(has_platform))]
fn current_network() -> Option<NetworkIdentity> {
    None
}

/// the saved mode, or the ask-first default when none was saved or it is unreadable
fn load_mode() -> FirewallMode {
    std::fs::read_to_string(mode_path())
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
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
        let profiles = load_profiles();
        let network = current_network();
        let active = active_profile(&profiles.profiles, profiles.manual.as_deref(), network.as_ref())
            .map(|profile| profile.name.clone());
        let mut rules = Vec::new();
        let now = now_ms();
        let mut dropped = false;
        for p in persisted {
            // a session rule ends with the engine run that made it, and a timed
            // rule that ran out while the engine was down is simply gone
            if p.rule.lifetime == RuleLifetime::UntilRestart || p.rule.lifetime.expired(now) {
                dropped = true;
                continue;
            }
            let id = if p.id > 0 {
                p.id
            } else {
                let x = next_id;
                next_id += 1;
                x
            };
            let filter_ids = if p.enabled && p.rule.applies_in(active.as_deref()) {
                #[cfg(has_platform)]
                {
                    match apply(wfp.as_mut(), &p.rule) {
                        Ok(ids) => ids,
                        Err(EngineError::NotFound(error)) => {
                            tracing::warn!(
                                app = %p.rule.app.0,
                                "rule deferred until the application returns: {error}"
                            );
                            Vec::new()
                        }
                        Err(error) => return Err(error.into()),
                    }
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

        let store = RuleStore {
            #[cfg(has_platform)]
            wfp,
            rules,
            next_id,
            path,
            mode: load_mode(),
            profiles,
            network,
            active,
            caps: crate::caps::CapStore::open(),
        };
        #[cfg(target_os = "linux")]
        if let Some(wfp) = store.wfp.as_ref() {
            for (app, mark) in store.caps.marks() {
                wfp.set_cap_mark(app.as_str(), Some(mark));
            }
        }
        // persist the drops above so a session rule cannot return on a crash.
        // only then: rewriting after a corrupt file would replace the fail-safe
        // with an empty rule set
        if dropped {
            store.save()?;
        }
        Ok(store)
    }

    /// the mode in force: the global choice, unless the active profile sets
    /// its own and the global choice is not lockdown
    pub fn mode(&self) -> FirewallMode {
        effective_mode(self.mode, self.active_profile())
    }

    fn active_profile(&self) -> Option<&Profile> {
        let name = self.active.as_deref()?;
        self.profiles.profiles.iter().find(|profile| profile.name == name)
    }

    /// switch how undecided apps are treated, or lock everything down, and
    /// remember it across restarts
    pub fn set_mode(&mut self, mode: FirewallMode) -> anyhow::Result<()> {
        self.enforce_mode(effective_mode(mode, self.active_profile()))?;
        self.mode = mode;
        write_atomic(&mode_path(), &serde_json::to_vec(&mode)?)
    }

    /// bring the platform in line with the saved mode; run once at startup
    pub fn restore_mode(&mut self) -> anyhow::Result<()> {
        self.enforce_mode(self.mode())
    }

    pub fn caps(&self) -> Vec<iris_core::RateCap> {
        self.caps.list()
    }

    pub fn set_cap(&mut self, app: iris_core::AppId, up_bytes_per_sec: Option<u64>) -> anyhow::Result<()> {
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let mark = self.caps.set(app.clone(), up_bytes_per_sec)?;
        #[cfg(target_os = "linux")]
        if let Some(wfp) = self.wfp.as_ref() {
            wfp.set_cap_mark(app.as_str(), mark);
        }
        Ok(())
    }

    /// keep upload caps on the interface the default route uses
    pub fn follow_route(&mut self) {
        self.caps.follow_route();
    }

    pub fn profile_state(&self) -> ProfileState {
        ProfileState {
            profiles: self.profiles.profiles.clone(),
            manual: self.profiles.manual.clone(),
            active: self.active.clone(),
            network: self.network.clone(),
            mode: self.mode(),
        }
    }

    /// replace the profile list and the manual choice, then re-evaluate
    pub fn set_profiles(&mut self, profiles: Vec<Profile>, manual: Option<String>) -> anyhow::Result<()> {
        let mut names = std::collections::HashSet::new();
        for profile in &profiles {
            if profile.name.trim().is_empty() {
                anyhow::bail!("a profile needs a name");
            }
            if !names.insert(profile.name.as_str()) {
                anyhow::bail!("two profiles are named {}", profile.name);
            }
        }
        let saved = SavedProfiles { profiles, manual };
        write_atomic(&profiles_path(), &serde_json::to_vec_pretty(&saved)?)?;
        self.profiles = saved;
        self.settle_profile()
    }

    /// note the network now in use; switches profile when it changed which one
    /// applies
    pub fn observe_network(&mut self, network: Option<NetworkIdentity>) -> anyhow::Result<()> {
        if network == self.network {
            return Ok(());
        }
        tracing::info!(
            network = network.as_ref().map_or("none", |network| network.label.as_str()),
            "network changed"
        );
        self.network = network;
        self.settle_profile()
    }

    /// recompute the active profile and, when it moved, enforce exactly the
    /// rules that belong to it and its mode
    fn settle_profile(&mut self) -> anyhow::Result<()> {
        let active = active_profile(
            &self.profiles.profiles,
            self.profiles.manual.as_deref(),
            self.network.as_ref(),
        )
        .map(|profile| profile.name.clone());
        let mode_before = self.mode();
        let switched = active != self.active;
        if switched {
            tracing::info!(profile = active.as_deref().unwrap_or("none"), "network profile active");
            self.active = active;
            self.sync_profile_rules()?;
        }
        let mode = self.mode();
        if switched || mode != mode_before {
            self.enforce_mode(mode)?;
        }
        Ok(())
    }

    fn sync_profile_rules(&mut self) -> anyhow::Result<()> {
        for index in 0..self.rules.len() {
            let stored = &self.rules[index];
            let wanted = stored.enabled && stored.rule.applies_in(self.active.as_deref());
            let applied = !stored.filter_ids.is_empty();
            if wanted && !applied {
                let rule = stored.rule.clone();
                match self.apply_rule(&rule) {
                    Ok(ids) => self.rules[index].filter_ids = ids,
                    // the app is gone; the deferred retry picks it up later
                    Err(error) if is_not_found(&error) => {}
                    Err(error) => return Err(error),
                }
            } else if !wanted && applied {
                let ids = std::mem::take(&mut self.rules[index].filter_ids);
                self.unapply(&ids)?;
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn enforce_mode(&mut self, mode: FirewallMode) -> anyhow::Result<()> {
        let Some(wfp) = self.wfp.as_mut() else {
            anyhow::bail!("firewall enforcement is unavailable");
        };
        // lockdown leaves ask in place underneath, so leaving it lands back on
        // the safer of the two
        wfp.set_ask_mode(mode != FirewallMode::Notify)?;
        wfp.set_lockdown(mode == FirewallMode::Lockdown)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn enforce_mode(&mut self, mode: FirewallMode) -> anyhow::Result<()> {
        match self.wfp.as_ref() {
            Some(wfp) => {
                wfp.set_mode(mode);
                Ok(())
            }
            None => anyhow::bail!("firewall enforcement is unavailable"),
        }
    }

    #[cfg(not(has_platform))]
    fn enforce_mode(&mut self, _mode: FirewallMode) -> anyhow::Result<()> {
        Ok(())
    }

    /// drop timed rules whose time is up; returns how many went
    pub fn expire(&mut self, now_ms: u64) -> anyhow::Result<usize> {
        let expired: Vec<i64> = self
            .rules
            .iter()
            .filter(|stored| stored.rule.lifetime.expired(now_ms))
            .map(|stored| stored.id)
            .collect();
        for id in &expired {
            self.remove(*id)?;
        }
        Ok(expired.len())
    }

    pub fn list(&self) -> Vec<StoredRule> {
        self.rules.clone()
    }

    #[cfg(windows)]
    pub fn retry_deferred(&mut self) -> anyhow::Result<usize> {
        let pending: Vec<(usize, Rule)> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, stored)| {
                stored.enabled
                    && stored.filter_ids.is_empty()
                    && stored.rule.applies_in(self.active.as_deref())
            })
            .map(|(index, stored)| (index, stored.rule.clone()))
            .collect();
        let mut restored = 0;
        for (index, rule) in pending {
            match apply(self.wfp.as_mut(), &rule) {
                Ok(ids) => {
                    self.rules[index].filter_ids = ids;
                    restored += 1;
                }
                Err(EngineError::NotFound(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(restored)
    }

    #[cfg(target_os = "linux")]
    pub fn enforcement_healthy(&self) -> bool {
        self.wfp
            .as_ref()
            .is_some_and(crate::platform::Wfp::is_healthy)
    }

    /// the stream of connections held or denied pending a user decision. on
    /// Linux the nfqueue verdict threads produce it; on Windows it is the
    /// classify-drop subscription behind ask mode. either way the service turns
    /// each one into a prompt.
    #[cfg(has_platform)]
    pub fn take_pending_receiver(
        &mut self,
    ) -> Option<std::sync::mpsc::Receiver<crate::platform::PendingConnection>> {
        #[cfg(target_os = "linux")]
        {
            self.wfp
                .as_mut()
                .and_then(crate::platform::Wfp::take_pending_receiver)
        }
        #[cfg(windows)]
        {
            self.wfp
                .as_mut()
                .and_then(crate::platform::Wfp::take_denied_receiver)
        }
    }

    /// whether an application with no decision yet is denied until the user
    /// answers, rather than allowed and reported afterwards
    #[cfg(has_platform)]
    pub fn ask_mode(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            // the nfqueue hook holds undecided flows unless notify lets them by
            self.wfp
                .as_ref()
                .is_some_and(|wfp| wfp.mode() != FirewallMode::Notify)
        }
        #[cfg(windows)]
        {
            self.wfp
                .as_ref()
                .is_some_and(crate::platform::Wfp::ask_mode_active)
        }
    }

    /// carry forward the applications the user already accepted, so enabling
    /// ask-before-connect does not retroactively deny a machine's worth of
    /// software. Linux keeps them in the verdict map; Windows seeds permits
    /// underneath the user's own rules.
    #[cfg(target_os = "linux")]
    pub fn trust_apps(&self, paths: &[String]) {
        if let Some(wfp) = &self.wfp {
            wfp.trust_apps(paths);
        }
    }

    #[cfg(windows)]
    pub fn trust_apps(&mut self, paths: &[String]) {
        if let Some(wfp) = self.wfp.as_mut() {
            wfp.trust_apps(paths);
        }
    }

    #[cfg(target_os = "linux")]
    pub fn forget_trusted_app(&self, path: &str) {
        if let Some(wfp) = &self.wfp {
            wfp.forget_app(path);
        }
    }

    /// add (or replace) a rule for an app, direction, and scope and enforce it now
    pub fn add(&mut self, rule: Rule) -> anyhow::Result<StoredRule> {
        let dupes: Vec<usize> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.rule.same_slot(&rule))
            .map(|(i, _)| i)
            .collect();
        for i in dupes.into_iter().rev() {
            let old = self.rules.remove(i);
            self.unapply(&old.filter_ids)?;
        }

        let id = self.next_id;
        self.next_id += 1;
        let filter_ids = if rule.applies_in(self.active.as_deref()) {
            self.apply_rule(&rule)?
        } else {
            Vec::new()
        };
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
            if rule.applies_in(self.active.as_deref()) {
                self.rules[pos].filter_ids = self.apply_rule(&rule)?;
            }
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
        Some(w) => w.apply(rule.app.as_str(), rule.direction, rule.action, &rule.scope),
        None => Err(iris_core::EngineError::NotInitialized),
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    matches!(error.downcast_ref::<EngineError>(), Some(EngineError::NotFound(_)))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn store_path() -> PathBuf {
    crate::paths::rules_file()
}
