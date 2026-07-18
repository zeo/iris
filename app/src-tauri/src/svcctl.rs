//! install / uninstall the engine service from the UI. the service binary ships
//! alongside the app as a bundled resource; these commands run it elevated (a UAC
//! prompt on Windows, a polkit prompt on Linux) with `--install` / `--uninstall`,
//! so a freshly-installed app can bring its own background engine up with one
//! click.

#[tauri::command]
pub async fn install_service(app: tauri::AppHandle) -> Result<(), String> {
    crate::elevate::run_engine(app, vec!["--install".into()]).await?;
    // once the engine is on boot, bring the app up at login too (quietly, into the
    // tray) so connection prompts and alerts can always surface even when the
    // window was never opened this session. best-effort: a failure here must not
    // fail the install, since the service itself is already up.
    if let Err(err) = crate::startup::set_launch_at_login(true) {
        tracing::warn!("enabled service but could not set launch at login: {err}");
    }
    Ok(())
}

#[tauri::command]
pub async fn uninstall_service(app: tauri::AppHandle) -> Result<(), String> {
    crate::elevate::run_engine(app, vec!["--uninstall".into()]).await
}
