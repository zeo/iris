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

// on Linux launch-at-login is an XDG autostart desktop entry under
// ~/.config/autostart; enabling it writes an entry that runs the app with
// --tray, disabling removes the file.
#[cfg(target_os = "linux")]
fn autostart_file() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
        })?;
    Some(base.join("autostart").join("iris.desktop"))
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub fn get_launch_at_login() -> bool {
    autostart_file().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(target_os = "linux")]
#[tauri::command]
pub fn set_launch_at_login(enabled: bool) -> Result<(), String> {
    let path = autostart_file().ok_or("no config directory")?;
    if enabled {
        let exe = std::env::var_os("APPIMAGE")
            .map(std::path::PathBuf::from)
            .map(Ok)
            .unwrap_or_else(std::env::current_exe)
            .map_err(|e| e.to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let entry = format!(
            "[Desktop Entry]\nType=Application\nName=Iris\nExec=\"{}\" --tray\nX-GNOME-Autostart-enabled=true\nTerminal=false\n",
            exe.display().to_string().replace('\\', "\\\\").replace('"', "\\\"")
        );
        std::fs::write(&path, entry).map_err(|e| e.to_string())?;
    } else {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux")))]
#[tauri::command]
pub fn get_launch_at_login() -> bool {
    false
}

#[cfg(not(any(windows, target_os = "linux")))]
#[tauri::command]
pub fn set_launch_at_login(_enabled: bool) -> Result<(), String> {
    Err("launch at login is not supported on this platform".into())
}
