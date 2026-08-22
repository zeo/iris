//! the iris engine host. runs as a Windows service in production and in the
//! foreground with `--console` for development. it owns the OS integration
//! (ETW monitor, WFP rules) and serves the UI over the named-pipe IPC.

mod adminclient;
mod engine;
mod grant;
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
        .position(|a| a.starts_with("--rule-") || a == "--proposal-accept" || a == "--grant-rules")
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

/// load the rules and bring enforcement up to its intended state.
///
/// every host has to go through here, not just `RuleStore::new`: the apps the
/// user already accepted must be carried forward before ask-before-connect is
/// switched on, or the catch-all deny would cut off a machine's worth of
/// software that was working a moment ago.
pub(crate) fn open_rules(store: &Arc<Mutex<Store>>) -> anyhow::Result<Arc<Mutex<RuleStore>>> {
    #[cfg(windows)]
    let mut rules = RuleStore::new()?;
    #[cfg(not(windows))]
    let rules = RuleStore::new()?;

    #[cfg(has_platform)]
    rules.trust_apps(
        &store
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .trusted_apps(),
    );
    #[cfg(not(has_platform))]
    let _ = store;

    // ask-before-connect: an application with no decision is denied until the
    // user answers, the same guarantee the Linux nfqueue hook gives structurally.
    // a failure here must not take the engine down, or a WFP problem would leave
    // the machine with no monitoring at all.
    #[cfg(windows)]
    if let Err(error) = rules.set_ask_mode(true) {
        tracing::error!("ask-before-connect unavailable, new apps stay allowed: {error}");
    }

    Ok(Arc::new(Mutex::new(rules)))
}

/// the engine's async main: monitor, plugin host, and both IPC servers, run to
/// the first one that ends. shared by the console path and the platform service
/// hosts (SCM on Windows, systemd on Linux).
pub(crate) async fn run_engine() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    paths::ensure_runtime_dirs()?;
    std::fs::create_dir_all(paths::plugins_dir())?;
    paths::secure_state()?;
    let engine = Engine::new();
    let store = Arc::new(Mutex::new(open_store()));
    let (enrich, panels, supervisor) = plugins::build(store.clone(), engine.clone());
    let rules = open_rules(&store)?;
    monitor::spawn(engine.clone(), rules.clone(), store.clone(), enrich.clone());
    tokio::select! {
        r = server::serve(engine, rules.clone(), store.clone(), enrich, panels) => r,
        r = server::serve_admin(rules.clone(), store) => r,
        r = supervisor.serve() => r,
        r = watch_rules(rules) => r,
    }
}

#[cfg(any(windows, target_os = "linux"))]
pub(crate) async fn watch_rules(rules: Arc<Mutex<RuleStore>>) -> anyhow::Result<()> {
    // enforcement is sampled every second on Linux; require a run of bad
    // samples before concluding the verdict workers are really gone, so one
    // slow poll or a worker mid-restart does not tear down the whole engine.
    #[cfg(target_os = "linux")]
    let mut unhealthy_streak = 0u32;
    loop {
        #[cfg(windows)]
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        #[cfg(target_os = "linux")]
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        #[cfg(windows)]
        let mut rules = rules.lock().unwrap_or_else(|error| error.into_inner());
        #[cfg(target_os = "linux")]
        {
            let healthy = rules
                .lock()
                .map(|rules| rules.enforcement_healthy())
                // a poisoned guard means some rule call panicked; treat it like
                // an unhealthy sample rather than killing monitoring outright
                .unwrap_or(false);
            if healthy {
                unhealthy_streak = 0;
            } else {
                unhealthy_streak += 1;
                tracing::warn!(
                    streak = unhealthy_streak,
                    "firewall enforcement is unhealthy"
                );
            }
            const MAX_UNHEALTHY_SAMPLES: u32 = 15;
            if unhealthy_streak >= MAX_UNHEALTHY_SAMPLES {
                anyhow::bail!("firewall enforcement worker stopped");
            }
        }
        #[cfg(windows)]
        match rules.retry_deferred() {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "restored deferred firewall rules"),
            Err(error) => tracing::warn!("could not retry deferred firewall rules: {error}"),
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn watch_rules(_rules: Arc<Mutex<RuleStore>>) -> anyhow::Result<()> {
    std::future::pending().await
}
