//! install / uninstall the engine service from the UI. the service binary ships
//! alongside the app as a bundled resource; these commands run it elevated (a UAC
//! prompt on Windows, a polkit prompt on Linux) with `--install` / `--uninstall`,
//! so a freshly-installed app can bring its own background engine up with one
//! click.

#[tauri::command]
pub async fn install_service(app: tauri::AppHandle) -> Result<(), String> {
    crate::elevate::run_engine(app, vec!["--install".into()]).await
}

#[tauri::command]
pub async fn uninstall_service(app: tauri::AppHandle) -> Result<(), String> {
    crate::elevate::run_engine(app, vec!["--uninstall".into()]).await
}
