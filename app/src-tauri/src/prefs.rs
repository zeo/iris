//! the few UI preferences the host itself acts on, saved beside the app config
//! so they hold from boot, before (or without) the main window ever opening

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::Manager;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostPrefs {
    pub notifications: bool,
    pub tray_graph: bool,
    pub info_cards: InfoCards,
}

impl Default for HostPrefs {
    fn default() -> Self {
        HostPrefs { notifications: true, tray_graph: true, info_cards: InfoCards::default() }
    }
}

/// which kinds of alert raise a passing card; decisions always get theirs
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct InfoCards {
    pub new_app: bool,
    pub watch: bool,
    pub quota: bool,
    pub caps: bool,
    pub plugin: bool,
}

impl Default for InfoCards {
    fn default() -> Self {
        InfoCards { new_app: true, watch: true, quota: true, caps: true, plugin: true }
    }
}

#[derive(Default)]
pub struct PrefsState(Mutex<HostPrefs>);

fn path(app: &tauri::AppHandle) -> Option<PathBuf> {
    Some(app.path().app_config_dir().ok()?.join("host-prefs.json"))
}

/// the saved prefs, or the defaults when none are saved or the file is unreadable
pub fn load(app: &tauri::AppHandle) -> HostPrefs {
    let prefs = path(app)
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|json| serde_json::from_slice(&json).ok())
        .unwrap_or_default();
    *app.state::<PrefsState>().0.lock().unwrap_or_else(|error| error.into_inner()) = prefs;
    prefs
}

pub fn current(app: &tauri::AppHandle) -> HostPrefs {
    app.try_state::<PrefsState>()
        .map(|state| *state.0.lock().unwrap_or_else(|error| error.into_inner()))
        .unwrap_or_default()
}

/// the saved prefs for the settings page, or none before the host first saved any
#[tauri::command]
pub fn host_prefs(app: tauri::AppHandle) -> Option<HostPrefs> {
    path(&app).is_some_and(|path| path.exists()).then(|| current(&app))
}

/// change and save the prefs; a failed write only costs the change at next boot
pub fn update(app: &tauri::AppHandle, change: impl FnOnce(&mut HostPrefs)) {
    let state = app.state::<PrefsState>();
    let mut prefs = state.0.lock().unwrap_or_else(|error| error.into_inner());
    let before = *prefs;
    change(&mut prefs);
    if *prefs == before {
        return;
    }
    let Some(path) = path(app) else {
        return;
    };
    let saved = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(&path, serde_json::to_vec(&*prefs).unwrap_or_default()));
    if let Err(error) = saved {
        tracing::warn!("could not save host preferences: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::{HostPrefs, InfoCards};

    #[test]
    fn missing_fields_keep_their_defaults() {
        let prefs: HostPrefs =
            serde_json::from_str(r#"{"tray_graph":false,"info_cards":{"new_app":false}}"#).unwrap();
        let info_cards = InfoCards { new_app: false, ..InfoCards::default() };
        assert_eq!(prefs, HostPrefs { notifications: true, tray_graph: false, info_cards });
    }
}
