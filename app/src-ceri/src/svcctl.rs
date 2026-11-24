//! install / uninstall the engine service from the UI. the service binary ships
//! alongside the app as a bundled resource; these commands run it elevated (a UAC
//! prompt on Windows, a polkit prompt on Linux) with `--install` / `--uninstall`,
//! so a freshly-installed app can bring its own background engine up with one
//! click.

pub async fn install_service() -> Result<(), String> {
    crate::elevate::run_engine(vec!["--install".into()]).await?;
    // once the engine is on boot, bring the app up at login too (quietly, into the
    // tray) so connection prompts and alerts can always surface even when the
    // window was never opened this session. best-effort: a failure here must not
    // fail the install, since the service itself is already up.
    if let Err(err) = crate::startup::set_launch_at_login(true) {
        tracing::warn!("enabled service but could not set launch at login: {err}");
    }
    Ok(())
}

/// hand outbound decisions back to iris on the windows firewall profiles that
/// block by default and are not held by group policy
pub async fn reset_outbound() -> Result<(), String> {
    crate::elevate::run_engine(vec!["--reset-outbound".into()]).await
}

pub async fn uninstall_service() -> Result<(), String> {
    crate::elevate::run_engine(vec!["--uninstall".into()]).await
}
