//! the iris engine host. runs as a Windows service in production and in the
//! foreground with `--console` for development. it owns the OS integration
//! (ETW monitor, WFP rules) and serves the UI over the named-pipe IPC.

mod adminclient;
mod caps;
mod engine;
mod grant;
#[cfg(windows)]
mod install;
mod monitor;
mod paths;
#[cfg(has_platform)]
mod platform;
mod plugins;
mod quota;
mod rules;
mod server;
#[cfg(windows)]
mod shaper;
#[cfg(windows)]
mod svc;
#[cfg(target_os = "linux")]
mod systemd;
mod tracker;
mod watch;

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
        if has("--clear-firewall") {
            return install::clear_firewall();
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
    if let Some(idx) = args.iter().position(|a| adminclient::FLAGS.contains(&a.as_str())) {
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

/// how large the engine log may grow before it rolls to engine.log.1
const LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024;

/// an append-only log that rolls to `.1` once it passes the size limit, so a
/// service running for weeks never eats the disk
struct RollingLog {
    path: std::path::PathBuf,
    file: std::fs::File,
    len: u64,
}

impl RollingLog {
    fn open(path: std::path::PathBuf) -> std::io::Result<RollingLog> {
        // a locked .1 only means this file keeps growing until the next roll
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_ROTATE_BYTES) {
            let _ = std::fs::rename(&path, path.with_extension("log.1"));
        }
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        let len = file.metadata()?.len();
        Ok(RollingLog { path, file, len })
    }
}

impl std::io::Write for RollingLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.len > LOG_ROTATE_BYTES {
            // keep writing to the old file if the roll fails rather than lose lines
            if let Ok(rolled) = RollingLog::open(self.path.clone()) {
                *self = rolled;
            }
        }
        let written = self.file.write(buf)?;
        self.len += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn init_logging(to_file: bool) {
    let filter =
        || tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if to_file && paths::ensure_data_dir().is_ok() {
        let dir = paths::log_dir();
        let _ = std::fs::create_dir_all(&dir);
        if let Ok(log) = RollingLog::open(dir.join("engine.log")) {
            tracing_subscriber::fmt()
                .with_env_filter(filter())
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(log))
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
    #[allow(unused_mut)]
    let mut rules = RuleStore::new()?;

    #[cfg(has_platform)]
    rules.trust_apps(
        &store
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .trusted_apps(),
    );
    #[cfg(not(has_platform))]
    let _ = store;

    // the saved firewall mode, ask-before-connect unless the user chose
    // otherwise. a failure here must not take the engine down, or a WFP problem
    // would leave the machine with no monitoring at all.
    #[cfg(has_platform)]
    if let Err(error) = rules.restore_mode() {
        tracing::error!(mode = rules.mode().as_str(), "firewall mode unavailable: {error}");
    }

    Ok(Arc::new(Mutex::new(rules)))
}

/// the engine's async main: monitor, plugin host, and both IPC servers, run to
/// the first one that ends. shared by the console path and the platform service
/// hosts (SCM on Windows, systemd on Linux).
pub(crate) async fn run_engine() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    paths::ensure_runtime_dirs()?;
    paths::ensure_data_dir()?;
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0);
        // read outside the lock and off the reactor: resolving the gateway's
        // hardware address can wait on an arp reply
        let network = tokio::task::spawn_blocking(crate::platform::current_network)
            .await
            .unwrap_or(None);
        // the rule lock can be held across a powershell round-trip by a cap
        // change, so wait for it on a blocking thread too
        let rules = rules.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let mut rules = rules.lock().unwrap_or_else(|error| error.into_inner());
            if let Err(error) = rules.observe_network(network) {
                tracing::warn!("could not switch network profile: {error}");
            }
            rules.follow_route();
            match rules.expire(now) {
                Ok(0) => {}
                Ok(count) => tracing::info!(count, "removed expired firewall rules"),
                Err(error) => tracing::warn!("could not remove expired firewall rules: {error}"),
            }
            match rules.retry_deferred() {
                Ok(0) => {}
                Ok(count) => tracing::info!(count, "restored deferred firewall rules"),
                Err(error) => tracing::warn!("could not retry deferred firewall rules: {error}"),
            }
        })
        .await;
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) async fn watch_rules(_rules: Arc<Mutex<RuleStore>>) -> anyhow::Result<()> {
    std::future::pending().await
}

#[cfg(test)]
mod tests {
    use super::{RollingLog, LOG_ROTATE_BYTES};
    use std::io::Write;

    #[test]
    fn the_log_rolls_once_it_passes_the_limit() {
        let dir = std::env::temp_dir().join(format!("iris-log-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("engine.log");
        let mut log = RollingLog::open(path.clone()).unwrap();
        let chunk = vec![b'x'; 1024 * 1024];
        while log.len <= LOG_ROTATE_BYTES {
            log.write_all(&chunk).unwrap();
        }
        log.write_all(b"after the roll\n").unwrap();
        assert!(std::fs::metadata(path.with_extension("log.1")).unwrap().len() > LOG_ROTATE_BYTES);
        assert_eq!(std::fs::read(&path).unwrap(), b"after the roll\n");
        drop(log);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
