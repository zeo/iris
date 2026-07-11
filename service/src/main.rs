//! the iris engine host. runs as a Windows service in production and in the
//! foreground with `--console` for development. it owns the OS integration
//! (ETW monitor, WFP rules) and serves the UI over the named-pipe IPC.

mod engine;
#[cfg(windows)]
mod install;
mod monitor;
mod plugins;
mod rules;
mod server;
mod tracker;
#[cfg(windows)]
mod svc;

use engine::Engine;
use iris_store::Store;
use rules::RuleStore;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn open_store() -> Store {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let dir = PathBuf::from(base).join("Iris");
    let _ = std::fs::create_dir_all(&dir);
    Store::open(&dir.join("iris.db")).unwrap_or_else(|e| {
        tracing::error!("history store unavailable, using in-memory: {e}");
        Store::open_in_memory().expect("in-memory store")
    })
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    init_logging();

    #[cfg(windows)]
    {
        if has("--install") {
            return install::install();
        }
        if has("--uninstall") {
            return install::uninstall();
        }
    }

    if has("--console") {
        return run_console();
    }

    #[cfg(windows)]
    {
        svc::run()
    }
    #[cfg(not(windows))]
    {
        run_console()
    }
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iris_service=info,iris_ipc=info".into()),
        )
        .init();
}

fn run_console() -> anyhow::Result<()> {
    tracing::info!("iris-engine starting (console mode)");
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let engine = Engine::new();
        let store = Arc::new(Mutex::new(open_store()));
        let enrich = plugins::builtin_registry();
        monitor::spawn(engine.clone(), store.clone(), enrich.clone());
        let rules = Arc::new(Mutex::new(RuleStore::new()));
        server::serve(engine, rules, store, enrich).await
    })
}
