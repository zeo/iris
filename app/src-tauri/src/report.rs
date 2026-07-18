//! writes a generated text file (a CSV usage export, a JSON rule backup) into the
//! user's Downloads folder and returns the path, so the UI can then reveal it in
//! the file manager. the UI builds the contents; this only decides where it lands.

use tauri::Manager;

#[tauri::command]
pub fn save_download(
    app: tauri::AppHandle,
    name: String,
    contents: String,
) -> Result<String, String> {
    let dir = app
        .path()
        .download_dir()
        .map_err(|_| "could not locate the Downloads folder".to_string())?;
    // the caller controls `name`; keep the write inside Downloads and reject
    // anything that could escape it, target an NTFS alternate data stream, or drop
    // a hidden control file. only the two export formats the UI produces are let
    // through, so a stray or hostile name falls back to a fixed safe filename.
    let base = name.rsplit(['\\', '/']).next().unwrap_or_default();
    let ext_ok = std::path::Path::new(base)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("csv") || ext.eq_ignore_ascii_case("json"));
    let clean = !base.is_empty()
        && base != "."
        && !base.contains("..")
        && !base.contains(':')
        && !base.chars().any(char::is_control);
    let safe = if clean && ext_ok { base } else { "iris-export.csv" };
    let path = dir.join(safe);
    std::fs::write(&path, contents).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().into_owned())
}
