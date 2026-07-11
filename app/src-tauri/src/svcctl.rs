//! install / uninstall the engine service from the UI. the service binary ships
//! alongside the app as a bundled resource; these commands run it elevated (a
//! UAC prompt) with `--install` / `--uninstall`, so a freshly-installed app can
//! bring its own background engine up with one click.

#[cfg(windows)]
#[tauri::command]
pub fn install_service(app: tauri::AppHandle) -> Result<(), String> {
    run_elevated(&app, "--install")
}

#[cfg(windows)]
#[tauri::command]
pub fn uninstall_service(app: tauri::AppHandle) -> Result<(), String> {
    run_elevated(&app, "--uninstall")
}

#[cfg(not(windows))]
#[tauri::command]
pub fn install_service(_app: tauri::AppHandle) -> Result<(), String> {
    Err("service control is Windows-only".into())
}

#[cfg(not(windows))]
#[tauri::command]
pub fn uninstall_service(_app: tauri::AppHandle) -> Result<(), String> {
    Err("service control is Windows-only".into())
}

#[cfg(windows)]
fn run_elevated(app: &tauri::AppHandle, arg: &str) -> Result<(), String> {
    use tauri::Manager;
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let exe = app
        .path()
        .resolve("engine/iris-engine.exe", tauri::path::BaseDirectory::Resource)
        .map_err(|e| format!("engine binary not found: {e}"))?;

    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(arg);
    let ret = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(params.as_ptr()),
            PCWSTR::null(),
            SW_HIDE,
        )
    };
    // ShellExecuteW returns a value > 32 on success
    if ret.0 as isize > 32 {
        Ok(())
    } else {
        Err("could not elevate (the prompt may have been declined)".into())
    }
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
