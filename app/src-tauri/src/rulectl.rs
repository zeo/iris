//! elevated firewall-rule mutations. the UI runs unprivileged, so changing a rule
//! launches the bundled engine elevated (a UAC prompt on Windows, a polkit prompt
//! on Linux) to relay the change over the admin-only endpoint. the service accepts
//! mutations only there, so a rule change genuinely requires elevation and an
//! unprivileged process cannot install an OS-enforced filter behind the user's
//! back. arguments are passed as argv, so a path never needs shell quoting.

#[tauri::command]
pub async fn rule_add(
    app: tauri::AppHandle,
    path: String,
    direction: String,
    action: String,
) -> Result<(), String> {
    // map to a fixed vocabulary so only known tokens reach the elevated run
    let dir = if direction == "inbound" { "inbound" } else { "outbound" };
    let act = if action == "allow" { "allow" } else { "block" };
    let args = vec!["--rule-add".into(), path, dir.into(), act.into()];
    crate::elevate::run_engine(app, args).await
}

#[tauri::command]
pub async fn rule_remove(app: tauri::AppHandle, id: i64) -> Result<(), String> {
    crate::elevate::run_engine(app, vec!["--rule-remove".into(), id.to_string()]).await
}

#[tauri::command]
pub async fn rule_set_enabled(app: tauri::AppHandle, id: i64, enabled: bool) -> Result<(), String> {
    let args = vec![
        "--rule-enable".into(),
        id.to_string(),
        enabled.to_string(),
    ];
    crate::elevate::run_engine(app, args).await
}

/// accept a plugin's rule proposal: the enforcement half runs elevated over the
/// admin endpoint, exactly like adding the rule by hand
#[tauri::command]
pub async fn proposal_accept(app: tauri::AppHandle, id: i64) -> Result<(), String> {
    crate::elevate::run_engine(app, vec!["--proposal-accept".into(), id.to_string()]).await
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
