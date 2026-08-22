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
pub async fn check_installer_update() -> Result<Option<Update>, String> {
    // a hung installer subprocess (network stall, antivirus scan) must not pin
    // a blocking-pool thread and leave the settings check spinning forever;
    // the frontend treats this like any other unreachable feed
    let job = tauri::async_runtime::spawn_blocking(check_installer_update_blocking);
    match tokio::time::timeout(std::time::Duration::from_secs(30), job).await {
        Ok(result) => result.map_err(|error| format!("updater task failed: {error}"))?,
        Err(_) => Err("the updater did not respond in time".into()),
    }
}

fn check_installer_update_blocking() -> Result<Option<Update>, String> {
    let installer = installer_path().ok_or_else(|| "shared updater is not installed".to_string())?;
    let mut status = Command::new(&installer)
        .args(["status", "iris", "--json"])
        .output()
        .map_err(|error| format!("read installer status: {error}"))?;
    let mut receipts: Vec<serde_json::Value> = serde_json::from_slice(&status.stdout)
        .map_err(|error| format!("read installer status: {error}"))?;
    if status.status.success() && receipts.is_empty() && installer_is_bundled(&installer) {
        adopt_bundled_installer(&installer)?;
        status = Command::new(&installer)
            .args(["status", "iris", "--json"])
            .output()
            .map_err(|error| format!("read installer status: {error}"))?;
        receipts = serde_json::from_slice(&status.stdout)
            .map_err(|error| format!("read installer status: {error}"))?;
    }
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

fn installer_is_bundled(installer: &std::path::Path) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
        .is_some_and(|parent| installer.parent() == Some(parent.as_path()))
}

fn adopt_bundled_installer(installer: &std::path::Path) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let root = executable
        .parent()
        .ok_or_else(|| "application path has no parent".to_string())?;
    let status = Command::new(installer)
        .args(["adopt", "iris", "--scope", "machine", "--root"])
        .arg(root)
        .args(["--version", env!("CARGO_PKG_VERSION")])
        .status()
        .map_err(|error| format!("start installer migration: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("installer migration exited with {status}"))
}

fn version_tuple(version: &str) -> Vec<u64> {
    version.trim_start_matches('v').split('.')
        .map(|part| part.split('-').next().unwrap_or("0").parse().unwrap_or(0))
        .collect()
}
