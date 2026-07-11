use crate::engine::Engine;
use crate::server;
use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "IrisEngine";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// enter the SCM dispatch loop. only succeeds when launched by the service
/// control manager; run with `--console` for development instead.
pub fn run() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service exited with error: {e}");
    }
}

fn status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accepted,
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn run_service() -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    let handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;

    status_handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    ))?;

    let rt = tokio::runtime::Runtime::new()?;
    let failed = rt.block_on(async {
        let engine = Engine::new();
        let store = std::sync::Arc::new(std::sync::Mutex::new(crate::open_store()));
        let enrich = crate::plugins::builtin_registry();
        crate::monitor::spawn(engine.clone(), store.clone(), enrich.clone());
        let rules = std::sync::Arc::new(std::sync::Mutex::new(crate::rules::RuleStore::new()));
        tokio::select! {
            r = server::serve(engine, rules.clone(), store, enrich) => {
                match r {
                    Err(e) => {
                        tracing::error!("serve loop failed: {e}");
                        true
                    }
                    // serve only returns Ok on a graceful shutdown path; a bare
                    // return here means the listener ended unexpectedly
                    Ok(()) => {
                        tracing::error!("serve loop ended unexpectedly");
                        true
                    }
                }
            }
            r = server::serve_admin(rules) => {
                tracing::error!("admin serve loop ended: {r:?}");
                true
            }
            _ = wait_for_stop(stop_rx) => {
                tracing::info!("stop requested");
                false
            }
        }
    });

    // report a service-specific error on failure so the SCM recovery policy
    // (restart with backoff, configured at install) actually engages; a clean
    // stop reports success so a user-requested stop stays stopped
    let exit_code = if failed {
        ServiceExitCode::ServiceSpecific(1)
    } else {
        ServiceExitCode::Win32(0)
    };
    status_handle.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
    ))?;
    Ok(())
}

// bridge the SCM's synchronous stop signal onto the async runtime
async fn wait_for_stop(rx: mpsc::Receiver<()>) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = rx.recv();
    })
    .await;
}
