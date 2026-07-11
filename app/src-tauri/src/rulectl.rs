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
