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
use iris_core::{AppId, Direction, Rule, RuleAction};

/// run `cmd` over the telemetry channel, falling back to one elevated run of
/// the engine with `args` if the grant is not in force
async fn mutate(
    app: tauri::AppHandle,
    cmd: EngineCmd,
    args: Vec<String>,
) -> Result<(), String> {
    if try_unelevated(&app, cmd).await? {
        return Ok(());
    }
    crate::elevate::run_engine(app, args).await
}

#[tauri::command]
pub async fn rule_add(
    app: tauri::AppHandle,
    path: String,
    direction: String,
    action: String,
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
    let rule = Rule {
        app: AppId::from_path(&path),
        direction,
        action,
        label: None,
    };
    let args = vec!["--rule-add".into(), path, dir.into(), act.into()];
    mutate(app, EngineCmd::AddRule(rule), args).await
}

#[tauri::command]
pub async fn rule_remove(app: tauri::AppHandle, id: i64) -> Result<(), String> {
    let args = vec!["--rule-remove".into(), id.to_string()];
    mutate(app, EngineCmd::RemoveRule(id), args).await
}

#[tauri::command]
pub async fn rule_set_enabled(app: tauri::AppHandle, id: i64, enabled: bool) -> Result<(), String> {
    let args = vec!["--rule-enable".into(), id.to_string(), enabled.to_string()];
    mutate(app, EngineCmd::SetRuleEnabled(id, enabled), args).await
}

/// the one elevated step that buys the user out of every later prompt, and the
/// same call in reverse to hand the authority back
#[tauri::command]
pub async fn set_rule_grant(app: tauri::AppHandle, granted: bool) -> Result<(), String> {
    let args = vec!["--grant-rules".into(), granted.to_string()];
    crate::elevate::run_engine(app, args).await
}

/// accept a plugin's rule proposal: the enforcement half runs elevated over the
/// admin endpoint, exactly like adding the rule by hand
#[tauri::command]
pub async fn proposal_accept(app: tauri::AppHandle, id: i64) -> Result<(), String> {
    let args = vec!["--proposal-accept".into(), id.to_string()];
    mutate(app, EngineCmd::ResolveProposal(id, true), args).await
}

/// pick a rules backup file and restore it in one elevated run (a single prompt
/// for the whole file). returns the rule count, or None if the picker was
/// cancelled.
#[tauri::command]
pub async fn rule_import(app: tauri::AppHandle) -> Result<Option<usize>, String> {
    use tauri::Manager;
    use tauri_plugin_dialog::DialogExt;

    let handle = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = handle.dialog().file().add_filter("rules backup", &["json"]);
        // the export drops its file in Downloads, so start the picker there
        if let Ok(dir) = handle.path().download_dir() {
            dialog = dialog.set_directory(dir);
        }
        dialog.blocking_pick_file()
    })
    .await
    .map_err(|e| format!("file picker failed: {e}"))?;

    let Some(file) = picked else { return Ok(None) };
    let path = file
        .simplified()
        .into_path()
        .map_err(|e| format!("unusable file path: {e}"))?;

    // parse before elevating so a malformed file fails with a precise error here
    // instead of a prompt followed by a bare exit code
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read the file: {e}"))?;
    if meta.len() > iris_core::BACKUP_MAX_BYTES {
        return Err("that file is too large to be a rules backup".into());
    }
    let json = std::fs::read_to_string(&path).map_err(|e| format!("cannot read the file: {e}"))?;
    let count = iris_core::parse_backup(&json)?.len();

    let args = vec!["--rule-import".into(), path.to_string_lossy().into_owned()];
    crate::elevate::run_engine(app, args).await?;
    Ok(Some(count))
}
