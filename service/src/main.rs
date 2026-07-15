//! the iris engine host. runs as a Windows service in production and in the
//! foreground with `--console` for development. it owns the OS integration
//! (ETW monitor, WFP rules) and serves the UI over the named-pipe IPC.

mod adminclient;
mod engine;
#[cfg(windows)]
mod install;
mod monitor;
mod paths;
#[cfg(has_platform)]
mod platform;
mod plugins;
mod rules;
mod server;
#[cfg(windows)]
mod svc;
#[cfg(target_os = "linux")]
mod systemd;
mod tracker;

use engine::Engine;
use iris_store::Store;
use rules::RuleStore;
use std::sync::{Arc, Mutex};

fn open_store() -> Store {
    let dir = paths::data_dir();
    let _ = std::fs::create_dir_all(&dir);
    Store::open(&paths::store_file()).unwrap_or_else(|e| {
        tracing::error!("history store unavailable, using in-memory: {e}");
        Store::open_in_memory().expect("in-memory store")
    })
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    // the SCM discards stdout, so the service path logs to a file; console and
    // one-shot runs keep the terminal
    init_logging(!has("--console") && args.len() == 1);

    #[cfg(windows)]
    {
        if has("--install") {
            return install::install();
        }
        if has("--uninstall") {
            return install::uninstall();
        }
    }
    #[cfg(target_os = "linux")]
    {
        if has("--install") {
            return systemd::install();
        }
        if has("--uninstall") {
            return systemd::uninstall();
        }
    }

    // elevated one-shot rule mutations (launched by the UI with an elevation
    // prompt: a UAC dialog on Windows, a polkit prompt via pkexec on Linux)
    if let Some(idx) = args
        .iter()
        .position(|a| a.starts_with("--rule-") || a == "--proposal-accept")
    {
        return adminclient::run(&args[idx..]);
    }

    if has("--console") {
        return run_console();
    }

    #[cfg(windows)]
    {
        svc::run()
    }
    #[cfg(target_os = "linux")]
    {
        systemd::run()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        run_console()
    }
}

/// share one append handle across the subscriber's writer calls
struct LogFile(std::sync::Arc<std::fs::File>);

impl std::io::Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut &*self.0, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut &*self.0)
    }
}

/// how large the engine log may grow before it rolls to engine.log.1
const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;

fn init_logging(to_file: bool) {
    let filter =
        || tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if to_file {
        let dir = paths::log_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("engine.log");
        // roll a grown log at startup so it never eats the disk
        if std::fs::metadata(&path)
            .map(|m| m.len() > LOG_ROTATE_BYTES)
            .unwrap_or(false)
        {
            let _ = std::fs::rename(&path, dir.join("engine.log.1"));
        }
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let file = std::sync::Arc::new(file);
            tracing_subscriber::fmt()
                .with_env_filter(filter())
                .with_ansi(false)
                .with_writer(move || LogFile(file.clone()))
                .init();
            return;
        }
    }
    tracing_subscriber::fmt().with_env_filter(filter()).init();
}

fn run_console() -> anyhow::Result<()> {
    tracing::info!("iris-engine starting (console mode)");
    let rt = engine_runtime()?;
    rt.block_on(run_engine())
}

pub(crate) fn engine_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}

/// the engine's async main: monitor, plugin host, and both IPC servers, run to
/// the first one that ends. shared by the console path and the platform service
/// hosts (SCM on Windows, systemd on Linux).
pub(crate) async fn run_engine() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    paths::ensure_runtime_dirs()?;
    let engine = Engine::new();
    let store = Arc::new(Mutex::new(open_store()));
    let (enrich, panels, supervisor) = plugins::build(store.clone(), engine.clone());
    let rules = RuleStore::new()?;
    #[cfg(target_os = "linux")]
    rules.trust_apps(
        &store
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .trusted_apps(),
    );
    let rules = Arc::new(Mutex::new(rules));
    monitor::spawn(engine.clone(), rules.clone(), store.clone(), enrich.clone());
    tokio::select! {
        r = server::serve(engine, rules.clone(), store.clone(), enrich, panels) => r,
        r = server::serve_admin(rules.clone(), store) => r,
        r = supervisor.serve() => r,
        r = watch_enforcement(rules) => r,
    }
}

#[cfg(target_os = "linux")]
async fn watch_enforcement(rules: Arc<Mutex<RuleStore>>) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let healthy = rules
            .lock()
            .map(|rules| rules.enforcement_healthy())
            .unwrap_or(false);
        if !healthy {
            anyhow::bail!("firewall enforcement worker stopped");
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn watch_enforcement(_rules: Arc<Mutex<RuleStore>>) -> anyhow::Result<()> {
    std::future::pending().await
}
