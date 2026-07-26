use std::path::PathBuf;
use std::process::Command;

use serde::Deserialize;

#[derive(Deserialize)]
struct Release {
    version: String,
}

#[derive(serde::Serialize)]
pub struct Update {
    version: String,
}

#[tauri::command]
pub fn check_installer_update() -> Result<Option<Update>, String> {
    let installer = installer_path().ok_or_else(|| "shared updater is not installed".to_string())?;
    let status = Command::new(&installer)
        .args(["status", "iris", "--json"])
        .output()
        .map_err(|error| format!("read installer status: {error}"))?;
    let receipts: Vec<serde_json::Value> = serde_json::from_slice(&status.stdout)
        .map_err(|error| format!("read installer status: {error}"))?;
    if !status.status.success() || receipts.is_empty() {
        return Err("Iris is still owned by its legacy or system package".into());
    }
    let output = Command::new(installer)
        .args(["check", "iris", "--json"])
        .output()
        .map_err(|error| format!("start updater: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let release: Release = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("read updater response: {error}"))?;
    let current = env!("CARGO_PKG_VERSION");
    if version_tuple(&release.version) <= version_tuple(current) {
        return Ok(None);
    }
    Ok(Some(Update { version: release.version }))
}

#[tauri::command]
pub fn install_installer_update(app: tauri::AppHandle) -> Result<(), String> {
    let installer = installer_path().ok_or_else(|| "shared updater is not installed".to_string())?;
    Command::new(installer)
        .args(["update", "iris", "--quiet", "--wait-pid", &std::process::id().to_string()])
        .spawn()
        .map_err(|error| format!("start updater: {error}"))?;
    app.exit(0);
    Ok(())
}

fn installer_path() -> Option<PathBuf> {
    let name = if cfg!(windows) { "rot-installer.exe" } else { "rot-installer" };
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join(name));
            candidates.push(parent.join("installer").join(name));
        }
    }
    #[cfg(windows)]
    {
        if let Some(root) = std::env::var_os("ProgramFiles") {
            candidates.push(PathBuf::from(root).join("rot").join("installer").join(name));
        }
        if let Some(root) = std::env::var_os("LOCALAPPDATA") {
            candidates.push(PathBuf::from(root).join("Programs").join("rot-installer").join(name));
        }
    }
    #[cfg(target_os = "linux")]
    {
        candidates.push(PathBuf::from("/opt/rot/installer").join(name));
        if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
            candidates.push(PathBuf::from(data).join("rot/apps/installer").join(name));
        } else if let Some(home) = std::env::var_os("HOME") {
            candidates.push(PathBuf::from(home).join(".local/share/rot/apps/installer").join(name));
        }
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn version_tuple(version: &str) -> Vec<u64> {
    version.trim_start_matches('v').split('.')
        .map(|part| part.split('-').next().unwrap_or("0").parse().unwrap_or(0))
        .collect()
}
