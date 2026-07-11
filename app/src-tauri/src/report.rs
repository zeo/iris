//! writes a generated text report (a CSV export) into the user's Downloads
//! folder and returns the path, so the UI can then reveal it in the file
//! manager. the UI builds the contents; this only decides where it lands.

use tauri::Manager;

#[tauri::command]
pub fn export_csv(app: tauri::AppHandle, name: String, contents: String) -> Result<String, String> {
    let dir = app
        .path()
        .download_dir()
        .map_err(|_| "could not locate the Downloads folder".to_string())?;
    // strip any path separators from the caller's name so the file can only land
    // inside Downloads, never at an attacker-chosen path
    let safe = name
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("iris-export.csv");
    let path = dir.join(safe);
    std::fs::write(&path, contents).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}
