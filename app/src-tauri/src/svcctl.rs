//! install / uninstall the engine service from the UI. the service binary ships
//! alongside the app as a bundled resource; these commands run it elevated (a
//! UAC prompt) with `--install` / `--uninstall`, so a freshly-installed app can
//! bring its own background engine up with one click.

#[cfg(windows)]
#[tauri::command]
pub async fn install_service(app: tauri::AppHandle) -> Result<(), String> {
    run_engine_elevated(app, "--install".into()).await
}

#[cfg(windows)]
#[tauri::command]
pub async fn uninstall_service(app: tauri::AppHandle) -> Result<(), String> {
    run_engine_elevated(app, "--uninstall".into()).await
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

/// run the bundled engine binary elevated with `params` (a full parameter
/// string) and wait for it to finish. shared by service install/uninstall and by
/// the elevated rule mutations in `rulectl`.
#[cfg(windows)]
pub(crate) async fn run_engine_elevated(
    app: tauri::AppHandle,
    params: String,
) -> Result<(), String> {
    use tauri::Manager;

    let exe = app
        .path()
        .resolve("engine/iris-engine.exe", tauri::path::BaseDirectory::Resource)
        .map_err(|e| format!("engine binary not found: {e}"))?;

    // ShellExecuteExW + waiting on the elevated process both block, so run them
    // off the UI thread; the closure reports whether the operation truly finished
    tauri::async_runtime::spawn_blocking(move || elevate_and_wait(&exe, &params))
        .await
        .map_err(|e| format!("elevation task failed: {e}"))?
}

/// launch the engine elevated with `params` and wait for it to finish, mapping
/// its exit code to success or failure. reporting Ok the moment ShellExecute
/// returns (as a bare launch would) tells the UI the operation succeeded when the
/// elevated run may still have failed.
#[cfg(windows)]
fn elevate_and_wait(exe: &std::path::Path, arg: &str) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(arg);
    unsafe {
        let mut sei: SHELLEXECUTEINFOW = std::mem::zeroed();
        sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = PCWSTR(verb.as_ptr());
        sei.lpFile = PCWSTR(file.as_ptr());
        sei.lpParameters = PCWSTR(params.as_ptr());
        sei.nShow = SW_HIDE.0;

        ShellExecuteExW(&mut sei)
            .map_err(|_| "could not elevate (the prompt may have been declined)".to_string())?;

        let proc = sei.hProcess;
        if proc.is_invalid() {
            return Err("the elevated process did not start".into());
        }
        let wait = WaitForSingleObject(proc, 60_000);
        let mut code: u32 = 0;
        let got_code = GetExitCodeProcess(proc, &mut code).is_ok();
        let _ = CloseHandle(proc);

        if wait != WAIT_OBJECT_0 {
            return Err("the service operation timed out".into());
        }
        if got_code && code == 0 {
            Ok(())
        } else {
            Err(format!("the engine reported failure (exit code {code})"))
        }
    }
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
