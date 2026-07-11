//! ties the platform network monitor to the engine: raw byte events accumulate
//! in a shared aggregator, and a timer flushes them into a sample tick once a
//! second, published to every subscribed UI.

use crate::engine::Engine;
use iris_core::Aggregator;
use iris_ipc::ServerMessage;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// start monitoring and the flush loop. on Windows this opens the ETW trace
/// (which needs admin); if it cannot start, the engine still runs and simply
/// reports no traffic rather than failing outright.
pub fn spawn(engine: Engine) {
    let agg = Arc::new(Mutex::new(Aggregator::new(now_ms())));

    #[cfg(windows)]
    let monitor = match iris_platform_win::Monitor::start(agg.clone()) {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::error!("network monitor unavailable: {e}");
            None
        }
    };

    tokio::spawn(async move {
        #[cfg(windows)]
        let monitor = monitor; // keep the trace alive for the task's lifetime
        let mut ticks: u64 = 0;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let tick = {
                let mut a = agg.lock().expect("aggregator poisoned");
                a.flush(now_ms())
            };
            engine.publish(ServerMessage::Tick(tick));

            ticks += 1;
            // every 30s: drop idle apps and refresh PID->path so a reused PID
            // stops resolving to a dead process
            if ticks % 30 == 0 {
                if let Ok(mut a) = agg.lock() {
                    a.prune_idle();
                }
                #[cfg(windows)]
                if let Some(m) = monitor.as_ref() {
                    m.clear_cache();
                }
            }
        }
    });
}
