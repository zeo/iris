use crate::adapters::AdapterMap;
use crate::dns::{self, DnsMap};
use crate::proc::PidCache;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use iris_core::{AdapterKind, Aggregator};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
    WNODE_FLAG_TRACED_GUID,
};

// Microsoft-Windows-Kernel-Network: per-app byte counts. manifest provider, so
// it enables in a normal user-mode trace given admin rights.
const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
// Microsoft-Windows-DNS-Client: the names processes resolve, for host labels.
const DNS_CLIENT_GUID: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
// DNS query-completed event that carries QueryName + resolved addresses
const DNS_QUERY_COMPLETE: u16 = 3008;

#[derive(Clone, Copy)]
enum Dir {
    Sent,
    Recv,
}

// KERNEL_NETWORK_TASK send/recv ids: TCP v4 10/11, TCP v6 26/27, UDP v4 42/43,
// UDP v6 58/59.
fn direction(event_id: u16) -> Option<Dir> {
    match event_id {
        10 | 26 | 42 | 58 => Some(Dir::Sent),
        11 | 27 | 43 | 59 => Some(Dir::Recv),
        _ => None,
    }
}

/// a running ETW monitor: attributes network bytes to processes and records the
/// DNS names they resolve. the two providers run in separate sessions so a DNS
/// session that fails to start never takes byte capture down with it. dropping
/// (or `stop`) ends both.
pub struct Monitor {
    net_trace: Option<UserTrace>,
    dns_trace: Option<UserTrace>,
    cache: Arc<Mutex<PidCache>>,
    adapters: Arc<AdapterMap>,
}

impl Monitor {
    pub fn start(agg: Arc<Mutex<Aggregator>>, dns_map: DnsMap) -> anyhow::Result<Monitor> {
        let cache = Arc::new(Mutex::new(PidCache::new()));
        let adapters = Arc::new(AdapterMap::new());

        // byte counts, required
        let net_agg = agg;
        let net_cache = cache.clone();
        let net_adapters = adapters.clone();
        let net_cb = move |record: &EventRecord, locator: &SchemaLocator| {
            on_net_event(record, locator, &net_agg, &net_cache, &net_adapters);
        };
        let net_provider = Provider::by_guid(KERNEL_NETWORK_GUID)
            .add_callback(net_cb)
            .build();
        // stop any leaked session from a previous ungraceful exit, else the
        // create fails with AlreadyExist and byte capture silently dies
        stop_stale_session("iris-net");
        stop_stale_session("iris-dns");

        let net_trace = UserTrace::new()
            .named("iris-net".to_string())
            .enable(net_provider)
            .start_and_process()
            .map_err(|e| anyhow::anyhow!("failed to start ETW network trace (admin required): {e:?}"))?;
        tracing::info!("ETW network trace running");

        // DNS names, best effort; the connection view still works on raw ip
        let dns_cb = move |record: &EventRecord, locator: &SchemaLocator| {
            on_dns_event(record, locator, &dns_map);
        };
        let dns_provider = Provider::by_guid(DNS_CLIENT_GUID)
            .add_callback(dns_cb)
            .build();
        let dns_trace = UserTrace::new()
            .named("iris-dns".to_string())
            .enable(dns_provider)
            .start_and_process()
            .map_err(|e| tracing::warn!("DNS name capture unavailable: {e:?}"))
            .ok();

        Ok(Monitor {
            net_trace: Some(net_trace),
            dns_trace,
            cache,
            adapters,
        })
    }

    /// clear the PID->path cache; called periodically to bound PID-reuse staleness
    pub fn clear_cache(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
    }

    /// rebuild the address-to-adapter table; called on a slow cadence so an
    /// adapter change is picked up even without a lookup miss
    pub fn refresh_adapters(&self) {
        self.adapters.refresh();
    }

    pub fn stop(mut self) {
        if let Some(t) = self.net_trace.take() {
            let _ = t.stop();
        }
        if let Some(t) = self.dns_trace.take() {
            let _ = t.stop();
        }
    }
}

// stop a real-time ETW session by name if it leaked from an ungraceful exit,
// ignoring the "not found" case, so the fresh trace can be created
fn stop_stale_session(name: &str) {
    unsafe {
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        const NAME_ROOM: usize = 1024;
        let size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * NAME_ROOM;
        // EVENT_TRACE_PROPERTIES holds 64-bit fields and needs 8-byte alignment,
        // which a Vec<u8> does not guarantee; back the blob with u64 storage so
        // the cast pointer is properly aligned
        let mut buf = vec![0u64; size.div_ceil(std::mem::size_of::<u64>())];
        let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*props).Wnode.BufferSize = size as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        (*props).LogFileNameOffset =
            (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + NAME_ROOM) as u32;
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name_w.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

fn on_net_event(
    record: &EventRecord,
    locator: &SchemaLocator,
    agg: &Arc<Mutex<Aggregator>>,
    cache: &Arc<Mutex<PidCache>>,
    adapters: &Arc<AdapterMap>,
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

    // the event stamps the packet's addresses; hand the end expected to be
    // local first, and the map falls back to the other end on a miss
    let kind = match (
        parser.try_parse::<IpAddr>("saddr"),
        parser.try_parse::<IpAddr>("daddr"),
    ) {
        (Ok(s), Ok(d)) => match dir {
            Dir::Sent => adapters.kind_for(s, d),
            Dir::Recv => adapters.kind_for(d, s),
        },
        _ => AdapterKind::Other,
    };

    if let Ok(mut a) = agg.lock() {
        match dir {
            Dir::Sent => a.record(pid, &path, None, kind, size as u64, 0),
            Dir::Recv => a.record(pid, &path, None, kind, 0, size as u64),
        }
    }
}

fn on_dns_event(record: &EventRecord, locator: &SchemaLocator, map: &DnsMap) {
    if record.event_id() != DNS_QUERY_COMPLETE {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let host: String = match parser.try_parse("QueryName") {
        Ok(h) => h,
        Err(_) => return,
    };
    let results: String = parser.try_parse("QueryResults").unwrap_or_default();
    dns::record_results(map, &host, &results);
}
