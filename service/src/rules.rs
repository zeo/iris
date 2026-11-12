//! the firewall rule store. holds iris's rules, persists them as JSON under
//! %ProgramData%\Iris, and drives the platform WFP controller to enforce them.
//! on startup it wipes any leftover iris filters and re-applies the enabled
//! rules, so the JSON file is the single source of truth.

use iris_core::{
    active_profile, effective_mode, AlertKind, AppId, Direction, EngineError, FirewallMode,
    NetworkIdentity, PortRange, Profile, ProfileState, Quota, QuotaLimit, Rule, RuleAction,
    RuleLifetime, RuleScope, StoredRule, WatchReason,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[cfg(all(has_platform, not(test)))]
use crate::platform::Wfp;
#[cfg(all(has_platform, test))]
use fake::Wfp;

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
    wfp: Option<Wfp>,
    rules: Vec<StoredRule>,
    next_id: i64,
    path: PathBuf,
    mode: FirewallMode,
    profiles: SavedProfiles,
    network: Option<NetworkIdentity>,
    /// the profile in force, which decides which profile-tagged rules apply
    active: Option<String>,
    /// the last profile switch or mode change did not fully take, so the next
    /// network check runs it again even if nothing moved
    unsettled: bool,
    caps: crate::caps::CapStore,
    quotas: crate::quota::QuotaBook,
}

fn mode_path(rules: &Path) -> PathBuf {
    rules.with_file_name("mode.json")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SavedProfiles {
    #[serde(default)]
    profiles: Vec<Profile>,
    #[serde(default)]
    manual: Option<String>,
}

fn profiles_path(rules: &Path) -> PathBuf {
    rules.with_file_name("profiles.json")
}

fn load_profiles(rules: &Path) -> SavedProfiles {
    std::fs::read_to_string(profiles_path(rules))
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

/// write json beside the rules file through a temp file, so a crash mid-write
/// never leaves a truncated one behind
pub(crate) fn write_atomic(path: &Path, json: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(all(has_platform, not(test)))]
fn current_network() -> Option<NetworkIdentity> {
    crate::platform::current_network()
}

#[cfg(any(not(has_platform), test))]
fn current_network() -> Option<NetworkIdentity> {
    None
}

/// the saved mode, or the ask-first default when none was saved or it is unreadable
fn load_mode(rules: &Path) -> FirewallMode {
    std::fs::read_to_string(mode_path(rules))
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

impl RuleStore {
    pub fn new() -> anyhow::Result<Self> {
        Self::open_at(store_path(), crate::caps::CapStore::open, crate::quota::QuotaBook::open)
    }

    /// load the rules file at `path`, with its mode and profile files beside
    /// it. caps and quotas come from the given openers, called after the rules
    /// are in force, so tests can pass ones that touch nothing on the machine
    fn open_at(
        path: PathBuf,
        open_caps: fn() -> crate::caps::CapStore,
        open_quotas: fn() -> crate::quota::QuotaBook,
    ) -> anyhow::Result<Self> {
        let loaded = load_persisted(&path);

        #[cfg(has_platform)]
        let mut wfp = Some(Wfp::open()?);

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
        let profiles = load_profiles(&path);
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
                        // the reset above already lifted every filter, so one
                        // refused rule must not stop the engine enforcing the rest
                        Err(error) => {
                            tracing::warn!(
                                app = %p.rule.app.0,
                                "rule deferred after it failed to apply: {error}"
                            );
                            Vec::new()
                        }
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

        let mode = load_mode(&path);
        let store = RuleStore {
            #[cfg(has_platform)]
            wfp,
            rules,
            next_id,
            path,
            mode,
            profiles,
            network,
            active,
            unsettled: false,
            caps: open_caps(),
            quotas: open_quotas(),
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
        write_atomic(&mode_path(&self.path), &serde_json::to_vec(&mode)?)
    }

    /// bring the platform in line with the saved mode; run once at startup.
    /// a failure is retried on the next network check
    pub fn restore_mode(&mut self) -> anyhow::Result<()> {
        let result = self.enforce_mode(self.mode());
        self.unsettled = result.is_err();
        result
    }

    pub fn caps(&self) -> Vec<iris_core::RateCap> {
        self.caps.list()
    }

    pub fn set_cap(
        &mut self,
        app: iris_core::AppId,
        up_bytes_per_sec: Option<u64>,
        down_bytes_per_sec: Option<u64>,
    ) -> anyhow::Result<()> {
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let mark = self.caps.set(app.clone(), up_bytes_per_sec, down_bytes_per_sec)?;
        #[cfg(target_os = "linux")]
        if let Some(wfp) = self.wfp.as_ref() {
            wfp.set_cap_mark(app.as_str(), mark);
        }
        Ok(())
    }

    pub fn quotas(&self, now_ms: u64) -> Vec<Quota> {
        self.quotas.list(now_ms)
    }

    /// set or clear an app's quota, or the machine's with no app, lifting any
    /// block the old quota put in force
    pub fn set_quota(&mut self, app: Option<AppId>, limit: Option<QuotaLimit>) -> anyhow::Result<()> {
        for id in self.quotas.set(app, limit)? {
            self.remove(id)?;
        }
        Ok(())
    }

    /// count quota use, block the apps that spent theirs, and return the
    /// alerts to raise. `usage` sums bytes over `[from, to)`
    pub fn check_quotas(&mut self, now_ms: u64, usage: impl Fn(Option<&AppId>, u64, u64) -> u64) -> Vec<AlertKind> {
        let reached = self.quotas.check(now_ms, crate::quota::utc_offset_ms, usage);
        reached
            .into_iter()
            .map(|reached| {
                if let Some(app) = reached.app.as_ref().filter(|_| reached.percent >= 100) {
                    self.block_for_quota(app, reached.until_ms);
                }
                AlertKind::Watch { reason: WatchReason::Quota, app: reached.app.clone(), message: reached.message() }
            })
            .collect()
    }

    /// block an app both ways until its quota period ends. the full port range
    /// gives the block its own slot, so it neither replaces the user's own rule
    /// for the app nor loses to it
    fn block_for_quota(&mut self, app: &AppId, until_ms: u64) {
        let mut ids = Vec::new();
        for direction in [Direction::Outbound, Direction::Inbound] {
            let rule = Rule {
                app: app.clone(),
                direction,
                action: RuleAction::Block,
                label: Some("Data quota".into()),
                scope: RuleScope { ports: Some(PortRange { start: 0, end: u16::MAX }), ..RuleScope::default() },
                lifetime: RuleLifetime::Until { at_ms: until_ms },
                profile: None,
            };
            match self.add(rule) {
                Ok(stored) => ids.push(stored.id),
                Err(error) => tracing::warn!(app = %app.0, "could not block an app over its quota: {error}"),
            }
        }
        self.quotas.record_blocks(app, ids);
    }

    /// keep upload caps on the interface the default route uses
    pub fn follow_route(&mut self) {
        self.caps.follow_route();
    }

    /// point download caps at the capped apps' live connections, returning an
    /// alert when they pause for an anti-cheat or resume after it
    pub fn follow_flows(&mut self, apps: &[iris_core::AppSample]) -> Option<AlertKind> {
        self.caps.follow_flows(apps)
    }

    /// unload the download driver before the engine exits
    #[cfg(windows)]
    pub fn release_download_caps(&mut self) {
        self.caps.release_downloads();
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
        write_atomic(&profiles_path(&self.path), &serde_json::to_vec_pretty(&saved)?)?;
        self.profiles = saved;
        self.settle_profile()
    }

    /// note the network now in use; switches profile when it changed which one
    /// applies, and finishes a switch that did not fully take
    pub fn observe_network(&mut self, network: Option<NetworkIdentity>) -> anyhow::Result<()> {
        if network != self.network {
            tracing::info!(
                network = network.as_ref().map_or("none", |network| network.label.as_str()),
                "network changed"
            );
            self.network = network;
        } else if !self.unsettled {
            return Ok(());
        }
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
        }
        let mode = self.mode();
        if switched || self.unsettled || mode != mode_before {
            // enforce the mode even when a rule failed, so a stricter profile
            // still takes hold
            let synced = self.sync_profile_rules();
            let enforced = self.enforce_mode(mode);
            self.unsettled = synced.is_err() || enforced.is_err();
            synced?;
            enforced?;
        }
        Ok(())
    }

    fn sync_profile_rules(&mut self) -> anyhow::Result<()> {
        let mut failure = None;
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
                    // the deferred retry keeps trying it too
                    Err(error) => {
                        tracing::warn!(app = %rule.app.0, "rule deferred after it failed to apply: {error}");
                    }
                }
            } else if !wanted && applied {
                let ids = self.rules[index].filter_ids.clone();
                match self.unapply(&ids) {
                    Ok(()) => self.rules[index].filter_ids.clear(),
                    // keep going so one stuck filter does not hold back the rest
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
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

    /// apply enabled rules that have no filters yet; returns how many took, or
    /// the first error after trying them all
    #[cfg(has_platform)]
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
        let mut failure = None;
        for (index, rule) in pending {
            match apply(self.wfp.as_mut(), &rule) {
                Ok(ids) => {
                    self.rules[index].filter_ids = ids;
                    restored += 1;
                }
                Err(EngineError::NotFound(_)) => {}
                // keep going so one rule that cannot apply does not hold back the rest
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        match failure {
            Some(error) => Err(error.into()),
            None => Ok(restored),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn enforcement_healthy(&self) -> bool {
        self.wfp
            .as_ref()
            .is_some_and(Wfp::is_healthy)
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
                .and_then(Wfp::take_pending_receiver)
        }
        #[cfg(windows)]
        {
            self.wfp
                .as_mut()
                .and_then(Wfp::take_denied_receiver)
        }
    }

    /// every connection an iris filter dropped, for the blocked log
    #[cfg(windows)]
    pub fn take_blocked_receiver(
        &mut self,
    ) -> Option<std::sync::mpsc::Receiver<crate::platform::PendingConnection>> {
        self.wfp.as_mut().and_then(Wfp::take_blocked_receiver)
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
                .is_some_and(Wfp::ask_mode_active)
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
        // take each rule in the slot out of force before dropping it, so a
        // failure leaves the store matching what the firewall enforces
        let mut replaced = Vec::new();
        while let Some(pos) = self.rules.iter().position(|r| r.rule.same_slot(&rule)) {
            let ids = self.rules[pos].filter_ids.clone();
            if let Err(error) = self.unapply(&ids) {
                self.put_back(replaced);
                return Err(error);
            }
            replaced.push(self.rules.remove(pos));
        }

        let id = self.next_id;
        self.next_id += 1;
        let filter_ids = if rule.applies_in(self.active.as_deref()) {
            match self.apply_rule(&rule) {
                Ok(ids) => ids,
                Err(error) => {
                    self.put_back(replaced);
                    return Err(error);
                }
            }
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

    /// re-enforce the rules a failed replace already took out, so the failure
    /// leaves the rule set as it was
    fn put_back(&mut self, replaced: Vec<StoredRule>) {
        for mut stored in replaced {
            if !stored.filter_ids.is_empty() {
                let rule = stored.rule.clone();
                stored.filter_ids = match self.apply_rule(&rule) {
                    Ok(ids) => ids,
                    Err(error) => {
                        tracing::warn!(app = %rule.app.0, "rule deferred after a failed replace: {error}");
                        Vec::new()
                    }
                };
            }
            self.rules.push(stored);
        }
    }

    /// remove a rule; returns whether a rule with that id existed, so the caller
    /// can tell the UI the truth instead of a blanket success
    pub fn remove(&mut self, id: i64) -> anyhow::Result<bool> {
        let Some(pos) = self.rules.iter().position(|r| r.id == id) else {
            return Ok(false);
        };
        let ids = self.rules[pos].filter_ids.clone();
        self.unapply(&ids)?;
        self.rules.remove(pos);
        self.save()?;
        Ok(true)
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
            let ids = self.rules[pos].filter_ids.clone();
            self.unapply(&ids)?;
            self.rules[pos].filter_ids.clear();
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
fn apply(wfp: Option<&mut Wfp>, rule: &Rule) -> iris_core::EngineResult<Vec<u64>> {
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

#[cfg(all(test, has_platform))]
mod fake {
    use iris_core::{Direction, EngineError, EngineResult, RuleAction, RuleScope};
    use std::collections::BTreeSet;

    /// the platform firewall as the rule store sees it, kept in memory: it
    /// hands out filter ids, tracks which are live, treats an app path
    /// containing "missing" as gone from disk, and always refuses one
    /// containing "broken"
    #[derive(Default)]
    pub struct Wfp {
        next: u64,
        pub live: BTreeSet<u64>,
        /// make every remove fail without touching the live set
        pub fail_remove: bool,
        /// make the next apply fail, then work again
        pub fail_next_apply: bool,
        /// make set_ask_mode and set_lockdown fail before changing anything
        #[cfg(windows)]
        pub fail_mode: bool,
        #[cfg(windows)]
        ask: bool,
        #[cfg(target_os = "linux")]
        mode: std::cell::Cell<iris_core::FirewallMode>,
    }

    impl Wfp {
        pub fn open() -> EngineResult<Wfp> {
            Ok(Wfp::default())
        }

        pub fn reset(&mut self) -> EngineResult<()> {
            self.live.clear();
            Ok(())
        }

        pub fn apply(
            &mut self,
            path: &str,
            _direction: Direction,
            _action: RuleAction,
            _scope: &RuleScope,
        ) -> EngineResult<Vec<u64>> {
            if std::mem::take(&mut self.fail_next_apply) {
                return Err(EngineError::Os("apply refused".into()));
            }
            if path.contains("missing") {
                return Err(EngineError::NotFound(path.to_string()));
            }
            if path.contains("broken") {
                return Err(EngineError::Os(format!("refused {path}")));
            }
            self.next += 1;
            self.live.insert(self.next);
            Ok(vec![self.next])
        }

        pub fn remove(&mut self, filter_ids: &[u64]) -> EngineResult<()> {
            if self.fail_remove {
                return Err(EngineError::Os("remove refused".into()));
            }
            for id in filter_ids {
                self.live.remove(id);
            }
            Ok(())
        }

        #[cfg(windows)]
        pub fn set_ask_mode(&mut self, enabled: bool) -> EngineResult<()> {
            if self.fail_mode {
                return Err(EngineError::Os("mode refused".into()));
            }
            self.ask = enabled;
            Ok(())
        }

        #[cfg(windows)]
        pub fn set_lockdown(&mut self, _enabled: bool) -> EngineResult<()> {
            if self.fail_mode {
                return Err(EngineError::Os("mode refused".into()));
            }
            Ok(())
        }

        #[cfg(windows)]
        pub fn ask_mode_active(&self) -> bool {
            self.ask
        }

        #[cfg(windows)]
        pub fn take_denied_receiver(
            &mut self,
        ) -> Option<std::sync::mpsc::Receiver<crate::platform::PendingConnection>> {
            None
        }

        #[cfg(windows)]
        pub fn take_blocked_receiver(
            &mut self,
        ) -> Option<std::sync::mpsc::Receiver<crate::platform::PendingConnection>> {
            None
        }

        #[cfg(windows)]
        pub fn trust_apps(&mut self, _paths: &[String]) {}

        #[cfg(target_os = "linux")]
        pub fn set_mode(&self, mode: iris_core::FirewallMode) {
            self.mode.set(mode);
        }

        #[cfg(target_os = "linux")]
        pub fn mode(&self) -> iris_core::FirewallMode {
            self.mode.get()
        }

        #[cfg(target_os = "linux")]
        pub fn is_healthy(&self) -> bool {
            true
        }

        #[cfg(target_os = "linux")]
        pub fn take_pending_receiver(
            &mut self,
        ) -> Option<std::sync::mpsc::Receiver<crate::platform::PendingConnection>> {
            None
        }

        #[cfg(target_os = "linux")]
        pub fn set_cap_mark(&self, _path: &str, _mark: Option<u32>) {}

        #[cfg(target_os = "linux")]
        pub fn trust_apps(&self, _paths: &[String]) {}

        #[cfg(target_os = "linux")]
        pub fn forget_app(&self, _path: &str) {}
    }
}

#[cfg(all(test, has_platform))]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("iris-rules-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open(dir: &Path) -> RuleStore {
        RuleStore::open_at(dir.join("rules.json"), crate::caps::CapStore::empty, crate::quota::QuotaBook::default)
            .unwrap()
    }

    fn rule(path: &str) -> Rule {
        Rule {
            app: AppId::from_path(path),
            direction: Direction::Outbound,
            action: RuleAction::Allow,
            label: None,
            scope: RuleScope::default(),
            lifetime: RuleLifetime::Permanent,
            profile: None,
        }
    }

    fn profile(name: &str) -> Profile {
        Profile { name: name.into(), networks: Vec::new(), mode: None }
    }

    fn write_rules(dir: &Path, rules: &[(i64, Rule)]) {
        let persisted: Vec<Persisted> = rules
            .iter()
            .map(|(id, rule)| Persisted { id: *id, rule: rule.clone(), enabled: true })
            .collect();
        std::fs::write(dir.join("rules.json"), serde_json::to_vec(&persisted).unwrap()).unwrap();
    }

    fn live(store: &RuleStore) -> Vec<u64> {
        store.wfp.as_ref().unwrap().live.iter().copied().collect()
    }

    fn firewall(store: &mut RuleStore) -> &mut Wfp {
        store.wfp.as_mut().unwrap()
    }

    #[test]
    fn a_new_store_keeps_added_rules_across_a_reopen() {
        let dir = scratch("reopen");
        let mut store = open(&dir);
        assert!(store.list().is_empty());
        let stored = store.add(rule(r"C:\apps\editor.exe")).unwrap();
        assert!(!stored.filter_ids.is_empty());
        assert!(stored.enabled);
        assert_eq!(live(&store), stored.filter_ids);
        drop(store);
        let store = open(&dir);
        let rules = store.list();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, stored.id);
        assert!(rules[0].enabled);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_mode_and_profiles_are_saved_beside_the_rules_file() {
        let dir = scratch("side-files");
        let mut store = open(&dir);
        assert!(store.set_mode(FirewallMode::Notify).is_ok());
        assert!(dir.join("mode.json").exists());
        assert!(store.set_profiles(vec![profile("home")], None).is_ok());
        assert!(dir.join("profiles.json").exists());
        drop(store);
        let store = open(&dir);
        assert_eq!(store.mode(), FirewallMode::Notify);
        assert_eq!(store.profile_state().profiles.len(), 1);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_corrupt_rules_file_is_set_aside_and_not_rewritten() {
        let dir = scratch("corrupt");
        std::fs::write(dir.join("rules.json"), b"not json").unwrap();
        let store = open(&dir);
        assert!(store.list().is_empty());
        assert!(dir.join("rules.json.corrupt").exists());
        assert!(!dir.join("rules.json").exists());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn session_and_lapsed_rules_are_dropped_and_the_drop_is_saved() {
        let dir = scratch("dropped");
        let session = Rule { lifetime: RuleLifetime::UntilRestart, ..rule(r"C:\apps\chat.exe") };
        let lapsed = Rule { lifetime: RuleLifetime::Until { at_ms: 1 }, ..rule(r"C:\apps\game.exe") };
        write_rules(&dir, &[(1, rule(r"C:\apps\editor.exe")), (2, session), (3, lapsed)]);
        let store = open(&dir);
        let rules = store.list();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, 1);
        let saved: Vec<Persisted> =
            serde_json::from_str(&std::fs::read_to_string(dir.join("rules.json")).unwrap()).unwrap();
        assert_eq!(saved.len(), 1);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_rule_for_a_missing_app_waits_without_filters() {
        let dir = scratch("missing-app");
        write_rules(&dir, &[(1, rule(r"C:\apps\missing.exe"))]);
        let store = open(&dir);
        let rules = store.list();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].enabled);
        assert!(rules[0].filter_ids.is_empty());
        assert!(live(&store).is_empty());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_rule_that_fails_to_apply_at_startup_is_deferred() {
        let dir = scratch("startup-broken");
        write_rules(&dir, &[(1, rule(r"C:\apps\broken.exe")), (2, rule(r"C:\apps\editor.exe"))]);
        let store = open(&dir);
        let rules = store.list();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].enabled);
        assert!(rules[0].filter_ids.is_empty());
        assert!(!rules[1].filter_ids.is_empty());
        assert_eq!(live(&store), rules[1].filter_ids);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retrying_deferred_rules_goes_past_one_that_keeps_failing() {
        let dir = scratch("retry-broken");
        write_rules(&dir, &[(1, rule(r"C:\apps\broken.exe")), (2, rule(r"C:\apps\editor.exe"))]);
        let mut store = open(&dir);
        // as if the editor's filters had never gone in
        store.rules[1].filter_ids.clear();
        assert!(store.retry_deferred().is_err());
        let rules = store.list();
        assert!(rules[0].filter_ids.is_empty());
        assert!(!rules[1].filter_ids.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn adding_in_the_same_slot_replaces_the_old_rule_and_its_filters() {
        let dir = scratch("same-slot");
        let mut store = open(&dir);
        let allow = store.add(rule(r"C:\apps\editor.exe")).unwrap();
        let block = store.add(Rule { action: RuleAction::Block, ..rule(r"C:\apps\editor.exe") }).unwrap();
        let rules = store.list();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule.action, RuleAction::Block);
        assert_eq!(rules[0].id, block.id);
        assert_ne!(rules[0].id, allow.id);
        assert_eq!(live(&store), block.filter_ids);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn disabling_and_removing_take_the_filters_out() {
        let dir = scratch("disable-remove");
        let mut store = open(&dir);
        let stored = store.add(rule(r"C:\apps\editor.exe")).unwrap();
        let disabled = store.set_enabled(stored.id, false).unwrap().unwrap();
        assert!(disabled.filter_ids.is_empty());
        assert!(!disabled.enabled);
        assert!(live(&store).is_empty());
        let enabled = store.set_enabled(stored.id, true).unwrap().unwrap();
        assert!(!enabled.filter_ids.is_empty());
        assert_eq!(live(&store), enabled.filter_ids);
        assert!(store.remove(stored.id).unwrap());
        assert!(store.list().is_empty());
        assert!(live(&store).is_empty());
        assert!(!store.remove(stored.id).unwrap());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn profile_rules_follow_the_active_profile() {
        let dir = scratch("profile-rules");
        let mut store = open(&dir);
        let stored = store.add(Rule { profile: Some("home".into()), ..rule(r"C:\apps\editor.exe") }).unwrap();
        assert!(stored.filter_ids.is_empty());
        store.set_profiles(vec![profile("home")], Some("home".into())).unwrap();
        assert!(!store.list()[0].filter_ids.is_empty());
        store.set_profiles(vec![profile("home")], None).unwrap();
        assert!(store.list()[0].filter_ids.is_empty());
        assert!(live(&store).is_empty());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_remove_keeps_the_rule_and_its_filters() {
        let dir = scratch("failed-remove");
        let mut store = open(&dir);
        let stored = store.add(rule(r"C:\apps\editor.exe")).unwrap();
        firewall(&mut store).fail_remove = true;
        assert!(store.remove(stored.id).is_err());
        let rules = store.list();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].filter_ids, stored.filter_ids);
        assert_eq!(live(&store), stored.filter_ids);
        firewall(&mut store).fail_remove = false;
        assert!(store.remove(stored.id).unwrap());
        drop(store);
        let store = open(&dir);
        assert!(store.list().is_empty());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_disable_keeps_the_filters_in_force() {
        let dir = scratch("failed-disable");
        let mut store = open(&dir);
        let stored = store.add(rule(r"C:\apps\editor.exe")).unwrap();
        firewall(&mut store).fail_remove = true;
        assert!(store.set_enabled(stored.id, false).is_err());
        let rules = store.list();
        assert!(rules[0].enabled);
        assert_eq!(rules[0].filter_ids, stored.filter_ids);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_replace_that_cannot_remove_the_old_rule_keeps_it() {
        let dir = scratch("replace-remove");
        let mut store = open(&dir);
        let allow = store.add(rule(r"C:\apps\editor.exe")).unwrap();
        firewall(&mut store).fail_remove = true;
        assert!(store.add(Rule { action: RuleAction::Block, ..rule(r"C:\apps\editor.exe") }).is_err());
        let rules = store.list();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, allow.id);
        assert_eq!(rules[0].rule.action, RuleAction::Allow);
        assert_eq!(rules[0].filter_ids, allow.filter_ids);
        assert_eq!(live(&store), allow.filter_ids);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_replace_that_cannot_apply_the_new_rule_puts_the_old_one_back() {
        let dir = scratch("replace-apply");
        let mut store = open(&dir);
        let allow = store.add(rule(r"C:\apps\editor.exe")).unwrap();
        firewall(&mut store).fail_next_apply = true;
        assert!(store.add(Rule { action: RuleAction::Block, ..rule(r"C:\apps\editor.exe") }).is_err());
        let rules = store.list();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, allow.id);
        assert_eq!(rules[0].rule.action, RuleAction::Allow);
        assert!(!rules[0].filter_ids.is_empty());
        assert_eq!(live(&store), rules[0].filter_ids);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_profile_switch_keeps_the_filters_it_could_not_remove() {
        let dir = scratch("failed-switch");
        let mut store = open(&dir);
        store.add(Rule { profile: Some("home".into()), ..rule(r"C:\apps\editor.exe") }).unwrap();
        store.set_profiles(vec![profile("home")], Some("home".into())).unwrap();
        assert!(!store.list()[0].filter_ids.is_empty());
        firewall(&mut store).fail_remove = true;
        assert!(store.set_profiles(vec![profile("home")], None).is_err());
        let rules = store.list();
        assert!(!rules[0].filter_ids.is_empty());
        assert_eq!(rules[0].filter_ids, live(&store));
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_profile_switch_that_failed_partway_finishes_on_the_next_check() {
        let dir = scratch("switch-retry");
        let mut store = open(&dir);
        store.add(Rule { profile: Some("home".into()), ..rule(r"C:\apps\editor.exe") }).unwrap();
        assert!(store.set_profiles(vec![profile("home")], Some("home".into())).is_ok());
        assert!(!store.list()[0].filter_ids.is_empty());
        firewall(&mut store).fail_remove = true;
        assert!(store.set_profiles(vec![profile("home")], None).is_err());
        firewall(&mut store).fail_remove = false;
        assert!(store.observe_network(None).is_ok());
        assert!(store.list()[0].filter_ids.is_empty());
        assert!(live(&store).is_empty());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_rule_that_fails_during_a_switch_is_left_for_the_retry() {
        let dir = scratch("switch-broken");
        let mut store = open(&dir);
        store.add(Rule { profile: Some("home".into()), ..rule(r"C:\apps\broken.exe") }).unwrap();
        store.add(Rule { profile: Some("home".into()), ..rule(r"C:\apps\editor.exe") }).unwrap();
        assert!(store.set_profiles(vec![profile("home")], Some("home".into())).is_ok());
        let rules = store.list();
        assert!(rules[0].filter_ids.is_empty());
        assert!(!rules[1].filter_ids.is_empty());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_profile_mode_that_failed_to_enforce_is_retried() {
        let dir = scratch("profile-mode-retry");
        let mut store = open(&dir);
        store.restore_mode().unwrap();
        assert!(store.ask_mode());
        firewall(&mut store).fail_mode = true;
        let work = Profile { name: "work".into(), networks: Vec::new(), mode: Some(FirewallMode::Notify) };
        assert!(store.set_profiles(vec![work], Some("work".into())).is_err());
        assert!(store.ask_mode());
        firewall(&mut store).fail_mode = false;
        assert!(store.observe_network(None).is_ok());
        assert!(!store.ask_mode());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_mode_that_failed_at_startup_is_retried() {
        let dir = scratch("startup-mode-retry");
        let mut store = open(&dir);
        firewall(&mut store).fail_mode = true;
        assert!(store.restore_mode().is_err());
        assert!(!store.ask_mode());
        firewall(&mut store).fail_mode = false;
        assert!(store.observe_network(None).is_ok());
        assert!(store.ask_mode());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
