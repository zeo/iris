//! run the bundled engine binary with elevation and wait for it to finish. this
//! is how the unprivileged UI performs the privileged operations (installing the
//! service, mutating rules): it launches the engine elevated, which relays the
//! change to the running service over the admin endpoint. on Windows elevation is
//! a UAC prompt via ShellExecute "runas"; on Linux it is a polkit prompt via
//! pkexec. reporting success only after the elevated run actually exits zero
//! keeps the UI honest when the prompt is declined or the operation fails.

use tauri::Manager;

/// the bundled engine binary's resource-relative path, per OS
#[cfg(windows)]
const ENGINE_RESOURCE: &str = "engine/iris-engine.exe";
#[cfg(not(windows))]
const ENGINE_RESOURCE: &str = "engine/iris-engine";

/// resolve the bundled engine, then run it elevated with `args`, blocking until
/// it exits
pub(crate) async fn run_engine(app: tauri::AppHandle, args: Vec<String>) -> Result<(), String> {
    let exe = app
        .path()
        .resolve(ENGINE_RESOURCE, tauri::path::BaseDirectory::Resource)
        .map_err(|e| format!("engine binary not found: {e}"))?;

    tauri::async_runtime::spawn_blocking(move || elevate_and_wait(&exe, &args))
        .await
        .map_err(|e| format!("elevation task failed: {e}"))?
}

#[cfg(target_os = "linux")]
fn elevate_and_wait(exe: &std::path::Path, args: &[String]) -> Result<(), String> {
    use std::process::Command;
    // pkexec raises a polkit prompt and runs the engine as root; the engine then
    // relays the mutation over the root-only admin socket
    let status = Command::new("pkexec")
        .arg(exe)
        .args(args)
        .status()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "pkexec is not installed".to_string()
            } else {
                format!("could not run pkexec: {error}")
            }
        })?;
    match status.code() {
        Some(0) => Ok(()),
        Some(126) => Err("the authentication prompt was dismissed".to_string()),
        Some(127) => Err("authorization failed".to_string()),
        Some(code) => Err(format!("the engine reported failure (exit code {code})")),
        None => Err("the elevated process was terminated".to_string()),
    }
}

#[cfg(windows)]
fn elevate_and_wait(exe: &std::path::Path, args: &[String]) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let params = join_windows(args)?;
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(&params);
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

/// join argv into a single command-line string for ShellExecute, quoting args
/// that need it. a double quote inside an argument is rejected rather than
/// escaped, since none of iris's arguments legitimately contain one.
#[cfg(windows)]
fn join_windows(args: &[String]) -> Result<String, String> {
    let mut out = String::new();
    for (i, arg) in args.iter().enumerate() {
        if arg.contains('"') {
            return Err("invalid argument".into());
        }
        if i > 0 {
            out.push(' ');
        }
        if arg.is_empty() || arg.contains(|c: char| c.is_whitespace()) {
            out.push('"');
            out.push_str(arg);
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }
    Ok(out)
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
