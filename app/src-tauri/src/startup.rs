//! launch-at-login, backed by the per-user Run key. enabling adds a `--tray`
//! flag so a login launch comes up quietly in the tray rather than popping the
//! window open every boot.

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const VALUE_NAME: windows::core::PCWSTR = windows::core::w!("Iris");

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
#[tauri::command]
pub fn get_launch_at_login() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ};

    let sub = wide(RUN_KEY);
    let mut size: u32 = 0;
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(sub.as_ptr()),
            VALUE_NAME,
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    };
    rc == ERROR_SUCCESS || rc == ERROR_MORE_DATA
}

#[cfg(windows)]
#[tauri::command]
pub fn set_launch_at_login(enabled: bool) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows::Win32::System::Registry::{
        RegDeleteKeyValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ,
    };

    let sub = wide(RUN_KEY);
    if enabled {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let command = wide(&format!("\"{}\" --tray", exe.display()));
        let bytes = (command.len() * std::mem::size_of::<u16>()) as u32;
        let rc = unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                PCWSTR(sub.as_ptr()),
                VALUE_NAME,
                REG_SZ.0,
                Some(command.as_ptr() as *const core::ffi::c_void),
                bytes,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(format!("could not enable launch at login ({})", rc.0));
        }
    } else {
        let rc = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, PCWSTR(sub.as_ptr()), VALUE_NAME) };
        if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
            return Err(format!("could not disable launch at login ({})", rc.0));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
#[tauri::command]
pub fn get_launch_at_login() -> bool {
    false
}

#[cfg(not(windows))]
#[tauri::command]
pub fn set_launch_at_login(_enabled: bool) -> Result<(), String> {
    Err("launch at login is Windows-only".into())
}
