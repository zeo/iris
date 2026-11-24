//! firewall-rule mutations from the unprivileged UI.
//!
//! a rule change is privileged, so it needs authority the UI does not have. two
//! routes lead there. the direct one is the telemetry channel, which the engine
//! accepts once the user has elevated a single time to authorize this account
//! (see the engine's `grant` module); that is the common case and costs no
//! prompt. when no grant is on file the engine refuses, and the change is
//! relayed through the bundled engine run elevated (a UAC prompt on Windows, a
//! polkit prompt on Linux) over the admin-only endpoint. arguments are passed as
//! argv, so a path never needs shell quoting.

use crate::ipc::{try_unelevated, EngineCmd};
use iris_core::{AppId, Cidr, Direction, FirewallMode, PortRange, Protocol, Rule, RuleAction, RuleLifetime, RuleScope};

/// run `cmd` over the telemetry channel, falling back to one elevated run of
/// the engine with `args` if the grant is not in force
pub(crate) async fn mutate(cmd: EngineCmd, args: Vec<String>) -> Result<(), String> {
    if try_unelevated(cmd).await? {
        return Ok(());
    }
    crate::elevate::run_engine(args).await
}

/// the optional narrowing and lifetime the Protect tab's rule editor sends
#[derive(Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleOptions {
    remote: Option<String>,
    ports: Option<String>,
    protocol: Option<String>,
    /// minutes until the rule lapses, or 0 for until the engine restarts
    minutes: Option<u64>,
    /// the network profile the rule belongs to
    profile: Option<String>,
}

impl RuleOptions {
    pub(crate) fn scope(&self) -> Result<RuleScope, String> {
        fn text(value: &Option<String>) -> Option<&str> {
            value.as_deref().map(str::trim).filter(|v| !v.is_empty())
        }
        Ok(RuleScope {
            remote: text(&self.remote)
                .map(|remote| Cidr::parse(remote).ok_or(format!("{remote} is not an IP address or network")))
                .transpose()?,
            ports: text(&self.ports)
                .map(|ports| PortRange::parse(ports).ok_or(format!("{ports} is not a port or port range")))
                .transpose()?,
            protocol: match text(&self.protocol) {
                None => None,
                Some("tcp") => Some(Protocol::Tcp),
                Some("udp") => Some(Protocol::Udp),
                Some(other) => return Err(format!("{other} is not tcp or udp")),
            },
        })
    }

    pub(crate) fn lifetime(&self) -> RuleLifetime {
        match self.minutes {
            None => RuleLifetime::Permanent,
            Some(0) => RuleLifetime::UntilRestart,
            Some(minutes) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_millis() as u64)
                    .unwrap_or(0);
                RuleLifetime::Until { at_ms: now.saturating_add(minutes.saturating_mul(60_000)) }
            }
        }
    }
}

pub async fn rule_add(
    path: String,
    direction: String,
    action: String,
    options: Option<RuleOptions>,
) -> Result<(), String> {
    // map to a fixed vocabulary so only known tokens reach the elevated run
    let (dir, direction) = if direction == "inbound" {
        ("inbound", Direction::Inbound)
    } else {
        ("outbound", Direction::Outbound)
    };
    let (act, action) = if action == "allow" {
        ("allow", RuleAction::Allow)
    } else {
        ("block", RuleAction::Block)
    };
    let options = options.unwrap_or_default();
    let rule = Rule {
        scope: options.scope()?,
        lifetime: options.lifetime(),
        profile: options.profile.filter(|profile| !profile.trim().is_empty()),
        ..Rule::new(AppId::from_path(&path), direction, action)
    };
    let args = if rule.scope.is_whole_app() && rule.lifetime.is_permanent() && rule.profile.is_none() {
        vec!["--rule-add".into(), path, dir.into(), act.into()]
    } else {
        let json = serde_json::to_string(&rule).map_err(|error| error.to_string())?;
        vec!["--rule-add-json".into(), json]
    };
    mutate(EngineCmd::AddRule(rule), args).await
}

pub async fn set_cap(
    path: String,
    up_bytes_per_sec: Option<u64>,
    down_bytes_per_sec: Option<u64>,
) -> Result<(), String> {
    let rate = |rate: Option<u64>| rate.map_or_else(|| "off".to_string(), |rate| rate.to_string());
    let args = vec!["--cap".into(), path.clone(), rate(up_bytes_per_sec), rate(down_bytes_per_sec)];
    mutate(EngineCmd::SetCap(path, up_bytes_per_sec, down_bytes_per_sec), args).await
}

pub async fn set_quota(
    path: Option<String>,
    limit: Option<iris_core::QuotaLimit>,
) -> Result<(), String> {
    let cmd = EngineCmd::SetQuota(path.clone(), limit);
    // the machine-wide quota only warns, so the engine takes it without elevation
    let Some(path) = path else {
        return try_unelevated(cmd).await.map(drop);
    };
    let limit = match limit {
        Some(limit) => serde_json::to_string(&limit).map_err(|error| error.to_string())?,
        None => "off".into(),
    };
    mutate(cmd, vec!["--quota".into(), path, limit]).await
}

pub async fn set_profiles(
    app: ceri::AppHandle,
    profiles: Vec<iris_core::Profile>,
    manual: Option<String>,
) -> Result<(), String> {
    let json = serde_json::json!({ "profiles": profiles, "manual": manual }).to_string();
    let args = vec!["--profiles-json".into(), json];
    mutate(EngineCmd::SetProfiles(profiles, manual), args).await?;
    if let Ok(mode) = crate::ipc::firewall_mode().await {
        crate::refresh_mode_menu(&app, mode);
    }
    Ok(())
}

pub async fn firewall_mode() -> Result<FirewallMode, String> {
    crate::ipc::firewall_mode().await
}

pub async fn set_firewall_mode(app: ceri::AppHandle, mode: String) -> Result<(), String> {
    let mode = FirewallMode::parse(&mode).ok_or("unknown firewall mode")?;
    let args = vec!["--firewall-mode".into(), mode.as_str().into()];
    mutate(EngineCmd::SetFirewallMode(mode), args).await?;
    crate::refresh_mode_menu(&app, mode);
    Ok(())
}

pub async fn rule_remove(id: i64) -> Result<(), String> {
    let args = vec!["--rule-remove".into(), id.to_string()];
    mutate(EngineCmd::RemoveRule(id), args).await
}

pub async fn rule_set_enabled(id: i64, enabled: bool) -> Result<(), String> {
    let args = vec!["--rule-enable".into(), id.to_string(), enabled.to_string()];
    mutate(EngineCmd::SetRuleEnabled(id, enabled), args).await
}

/// the one elevated step that buys the user out of every later prompt, and the
/// same call in reverse to hand the authority back
pub async fn set_rule_grant(granted: bool) -> Result<(), String> {
    let args = vec!["--grant-rules".into(), granted.to_string()];
    crate::elevate::run_engine(args).await
}

/// accept a plugin's rule proposal: the enforcement half runs elevated over the
/// admin endpoint, exactly like adding the rule by hand
pub async fn proposal_accept(id: i64) -> Result<(), String> {
    let args = vec!["--proposal-accept".into(), id.to_string()];
    mutate(EngineCmd::ResolveProposal(id, true), args).await
}

/// pick a rules backup file and restore it in one elevated run (a single prompt
/// for the whole file). returns the rule count, or None if the picker was
/// cancelled.
pub async fn rule_import() -> Result<Option<usize>, String> {
    let picked = crate::runtime()
        .spawn_blocking(|| {
            ceri::FileDialog {
                filters: vec![ceri::FileFilter { name: "rules backup".into(), extensions: vec!["json".into()] }],
                // the export drops its file in Downloads, so start the picker there
                default_path: ceri::dirs::downloads(),
                ..ceri::FileDialog::default()
            }
            .open_files()
        })
        .await
        .map_err(|e| format!("file picker failed: {e}"))??;

    let Some(path) = picked.and_then(|files| files.into_iter().next()) else { return Ok(None) };

    // parse before elevating so a malformed file fails with a precise error here
    // instead of a prompt followed by a bare exit code
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read the file: {e}"))?;
    if meta.len() > iris_core::BACKUP_MAX_BYTES {
        return Err("that file is too large to be a rules backup".into());
    }
    let json = std::fs::read_to_string(&path).map_err(|e| format!("cannot read the file: {e}"))?;
    let count = iris_core::parse_backup(&json)?.len();

    let args = vec!["--rule-import".into(), path.to_string_lossy().into_owned()];
    crate::elevate::run_engine(args).await?;
    Ok(Some(count))
}
