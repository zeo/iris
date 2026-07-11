//! elevated firewall-rule mutations. the UI runs unprivileged, so changing a
//! rule launches the bundled engine elevated (a UAC prompt) to relay the change
//! over the admin-only pipe. the service accepts mutations only on that pipe, so
//! a rule change genuinely requires elevation and an unprivileged process cannot
//! install a SYSTEM-enforced filter behind the user's back.

#[cfg(windows)]
fn quote_path(path: &str) -> Result<String, String> {
    // a real Windows path cannot contain a double quote; rejecting it keeps the
    // value from breaking out of its quoting in the elevated command line
    if path.contains('"') {
        return Err("invalid application path".into());
    }
    Ok(format!("\"{path}\""))
}

#[cfg(windows)]
#[tauri::command]
pub async fn rule_add(
    app: tauri::AppHandle,
    path: String,
    direction: String,
    action: String,
) -> Result<(), String> {
    // map to a fixed vocabulary so only known tokens reach the command line
    let dir = if direction == "inbound" { "inbound" } else { "outbound" };
    let act = if action == "allow" { "allow" } else { "block" };
    let params = format!("--rule-add {} {dir} {act}", quote_path(&path)?);
    crate::svcctl::run_engine_elevated(app, params).await
}

#[cfg(windows)]
#[tauri::command]
pub async fn rule_remove(app: tauri::AppHandle, id: i64) -> Result<(), String> {
    crate::svcctl::run_engine_elevated(app, format!("--rule-remove {id}")).await
}

#[cfg(windows)]
#[tauri::command]
pub async fn rule_set_enabled(app: tauri::AppHandle, id: i64, enabled: bool) -> Result<(), String> {
    crate::svcctl::run_engine_elevated(app, format!("--rule-enable {id} {enabled}")).await
}

/// pick a rules backup file and restore it in one elevated run (a single UAC
/// prompt for the whole file). returns the rule count, or None if the picker
/// was cancelled.
#[cfg(windows)]
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

    // parse before elevating so a malformed file fails with a precise error
    // here instead of a UAC prompt followed by a bare exit code
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read the file: {e}"))?;
    if meta.len() > iris_core::BACKUP_MAX_BYTES {
        return Err("that file is too large to be a rules backup".into());
    }
    let json = std::fs::read_to_string(&path).map_err(|e| format!("cannot read the file: {e}"))?;
    let count = iris_core::parse_backup(&json)?.len();

    let params = format!("--rule-import {}", quote_path(&path.to_string_lossy())?);
    crate::svcctl::run_engine_elevated(app, params).await?;
    Ok(Some(count))
}

#[cfg(not(windows))]
#[tauri::command]
pub fn rule_add(
    _app: tauri::AppHandle,
    _path: String,
    _direction: String,
    _action: String,
) -> Result<(), String> {
    Err("rule control is Windows-only".into())
}

#[cfg(not(windows))]
#[tauri::command]
pub fn rule_remove(_app: tauri::AppHandle, _id: i64) -> Result<(), String> {
    Err("rule control is Windows-only".into())
}

#[cfg(not(windows))]
#[tauri::command]
pub fn rule_set_enabled(_app: tauri::AppHandle, _id: i64, _enabled: bool) -> Result<(), String> {
    Err("rule control is Windows-only".into())
}

#[cfg(not(windows))]
#[tauri::command]
pub fn rule_import(_app: tauri::AppHandle) -> Result<Option<usize>, String> {
    Err("rule control is Windows-only".into())
}
