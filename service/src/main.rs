//! the iris engine host. runs as a Windows service in production and in the
//! foreground with `--console` for development. it owns the OS integration
//! (ETW monitor, WFP rules) and serves the UI over the named-pipe IPC.

mod engine;
mod monitor;
mod server;
mod tracker;
#[cfg(windows)]
mod svc;

use engine::Engine;

fn main() -> anyhow::Result<()> {
    let console = std::env::args().any(|a| a == "--console");
    init_logging();

    if console {
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
        monitor::spawn(engine.clone());
        server::serve(engine).await
    })
}
