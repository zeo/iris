use crate::proc::PidCache;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use iris_core::{Aggregator, AppId};
use std::sync::{Arc, Mutex};

// Microsoft-Windows-Kernel-Network. a manifest provider, so it enables in a
// normal user-mode trace (given admin rights) rather than the legacy kernel
// logger.
const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

#[derive(Clone, Copy)]
enum Dir {
    Sent,
    Recv,
}

// KERNEL_NETWORK_TASK send/recv event ids: TCP v4 10/11, TCP v6 26/27,
// UDP v4 42/43, UDP v6 58/59. all carry PID + size + the endpoint tuple.
fn direction(event_id: u16) -> Option<Dir> {
    match event_id {
        10 | 26 | 42 | 58 => Some(Dir::Sent),
        11 | 27 | 43 | 59 => Some(Dir::Recv),
        _ => None,
    }
}

/// a running ETW network monitor. records per-app byte deltas into a shared
/// [`Aggregator`]; the service flushes that into sample ticks on a timer.
/// dropping (or `stop`) ends the trace.
pub struct Monitor {
    trace: Option<UserTrace>,
    cache: Arc<Mutex<PidCache>>,
}

impl Monitor {
    pub fn start(agg: Arc<Mutex<Aggregator>>) -> anyhow::Result<Monitor> {
        let cache = Arc::new(Mutex::new(PidCache::new()));
        let cb_agg = agg;
        let cb_cache = cache.clone();

        let callback = move |record: &EventRecord, locator: &SchemaLocator| {
            on_event(record, locator, &cb_agg, &cb_cache);
        };

        let provider = Provider::by_guid(KERNEL_NETWORK_GUID)
            .add_callback(callback)
            .build();

        let trace = UserTrace::new()
            .named("iris-net".to_string())
            .enable(provider)
            .start_and_process()
            .map_err(|e| anyhow::anyhow!("failed to start ETW trace (admin required): {e:?}"))?;

        tracing::info!("ETW kernel-network monitor running");
        Ok(Monitor {
            trace: Some(trace),
            cache,
        })
    }

    /// clear the PID->path cache; the monitor's owner calls this periodically so
    /// a reused PID cannot keep resolving to a dead process's image
    pub fn clear_cache(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
    }

    pub fn stop(mut self) {
        if let Some(t) = self.trace.take() {
            let _ = t.stop();
        }
    }
}

fn on_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    agg: &Arc<Mutex<Aggregator>>,
    cache: &Arc<Mutex<PidCache>>,
) {
    let Some(dir) = direction(record.event_id()) else {
        return;
    };
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);

    let pid: u32 = match parser.try_parse("PID") {
        Ok(p) => p,
        Err(_) => return,
    };
    let size: u32 = match parser.try_parse("size") {
        Ok(s) => s,
        Err(_) => return,
    };
    if pid == 0 || size == 0 {
        return;
    }

    let path = cache.lock().ok().and_then(|mut c| c.resolve(pid));
    let Some(path) = path else {
        return;
    };
    let app = AppId::from_path(&path);

    if let Ok(mut a) = agg.lock() {
        match dir {
            Dir::Sent => a.record(&app, None, size as u64, 0),
            Dir::Recv => a.record(&app, None, 0, size as u64),
        }
    }
}
