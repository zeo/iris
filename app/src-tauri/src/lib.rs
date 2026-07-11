//! the Iris desktop shell. this crate is the thin Tauri host: it opens the
//! window, exposes the small command surface the UI needs, and bridges the UI to
//! the privileged engine service over the named-pipe IPC.

mod icon;
mod ipc;
mod net;

/// build and run the Tauri application
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iris=info,iris_ipc=info".into()),
        )
        .init();

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(32);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(ipc::StatusState::default())
        .manage(ipc::Commander(cmd_tx))
        .invoke_handler(tauri::generate_handler![
            ipc::engine_status,
            ipc::list_rules,
            ipc::add_rule,
            ipc::remove_rule,
            ipc::set_rule_enabled,
            net::reverse_dns,
            icon::app_icon
        ])
        .setup(move |app| {
            ipc::spawn(app.handle().clone(), cmd_rx);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Iris");
}
