//! the Iris desktop shell. this crate is the thin Tauri host: it opens the
//! window, exposes the small command surface the UI needs, and (from slice 2)
//! bridges the UI to the privileged engine service over the named-pipe IPC.

/// build and run the Tauri application
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iris=info".into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running Iris");
}
