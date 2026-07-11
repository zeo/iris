//! ties the platform data sources to the engine: the ETW byte monitor fills a
//! shared aggregator, the [`Tracker`] merges that with live connections and the
//! online/offline lifecycle, and a one-second timer publishes the resulting
//! sample tick to every subscribed UI.

use crate::engine::Engine;
use crate::tracker::Tracker;
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
/// (which needs admin) for byte counts; connection enumeration works without it,
/// so the activity view still populates if ETW cannot start.
pub fn spawn(engine: Engine) {
    let agg = Arc::new(Mutex::new(Aggregator::new(now_ms())));

    #[cfg(windows)]
    let byte_monitor = match iris_platform_win::Monitor::start(agg.clone()) {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::error!("byte monitor unavailable (connections still shown): {e}");
            None
        }
    };

    let mut tracker = Tracker::new(agg);

    tokio::spawn(async move {
        #[cfg(windows)]
        let byte_monitor = byte_monitor; // keep the ETW trace alive for the loop
        let mut ticks: u64 = 0;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let tick = tracker.tick(now_ms());
            engine.publish(ServerMessage::Tick(tick));

            ticks += 1;
            if ticks % 30 == 0 {
                tracker.clear_cache();
                #[cfg(windows)]
                if let Some(m) = byte_monitor.as_ref() {
                    m.clear_cache();
                }
            }
        }
    });
}
