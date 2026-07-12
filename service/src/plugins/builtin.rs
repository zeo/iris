//! compiled-in, first-party enrichers. these ship in the signed service binary,
//! so their trust boundary is the same as trusting the service itself; the
//! registry still asks each only about the target kinds it declares. anything
//! that needs the network or a secret is an out-of-process plugin instead, never
//! a built-in.

use iris_core::enrich::ip_scope;
use iris_core::{Annotation, AnnotationValue, EnrichTarget, Enricher, IpSet, Severity, TargetKind};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

/// labels each endpoint with its network scope (loopback, the LAN, the public
/// internet), so a connection row shows at a glance whether traffic is leaving
/// the machine. offline and instant, so it runs for every endpoint.
pub struct NetworkScope;

impl Enricher for NetworkScope {
    fn id(&self) -> &str {
        "iris.network-scope"
    }

    fn targets(&self) -> &[TargetKind] {
        &[TargetKind::Endpoint]
    }

    fn enrich(&self, target: &EnrichTarget) -> Vec<Annotation> {
        let EnrichTarget::Endpoint(ip) = target else {
            return Vec::new();
        };
        vec![Annotation::text("net.scope", "Network", ip_scope(ip), Severity::Info)]
    }
}

/// labels public endpoints with their country from the bundled DB-IP Country
/// Lite database (CC-BY-4.0). offline: the database is memory-loaded once at
/// service start, so no lookup ever touches the network.
pub struct Geo {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl Geo {
    pub fn new() -> Self {
        let reader = Self::locate().and_then(|path| {
            maxminddb::Reader::open_readfile(&path)
                .inspect(|_| tracing::info!("country database loaded from {}", path.display()))
                .inspect_err(|e| tracing::warn!("country database at {} unreadable: {e}", path.display()))
                .ok()
        });
        if reader.is_none() {
            tracing::warn!("country database not found; endpoints stay without a country");
        }
        Geo { reader }
    }

    /// an admin-managed override under ProgramData wins; otherwise the database
    /// ships in the app's resources, next to the engine in dev (target\debug)
    /// and one level up from engine\ in an installed tree
    fn locate() -> Option<PathBuf> {
        let mut candidates = Vec::new();
        if let Ok(base) = std::env::var("ProgramData") {
            candidates.push(PathBuf::from(base).join("Iris").join("geo").join("dbip-country.mmdb"));
        }
        if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
            candidates.push(dir.join("resources").join("geo").join("dbip-country.mmdb"));
            candidates.push(dir.join("..").join("resources").join("geo").join("dbip-country.mmdb"));
        }
        candidates.into_iter().find(|p| p.is_file())
    }
}

impl Default for Geo {
    fn default() -> Self {
        Self::new()
    }
}

impl Enricher for Geo {
    fn id(&self) -> &str {
        "iris.geo"
    }

    fn targets(&self) -> &[TargetKind] {
        &[TargetKind::Endpoint]
    }

    fn enrich(&self, target: &EnrichTarget) -> Vec<Annotation> {
        let EnrichTarget::Endpoint(ip) = target else {
            return Vec::new();
        };
        let Some(reader) = &self.reader else {
            return Vec::new();
        };
        // only public addresses have a country; skip the doomed lookups
        if ip_scope(ip) != "Public internet" {
            return Vec::new();
        }
        let Ok(record) = reader.lookup::<maxminddb::geoip2::Country>(*ip) else {
            return Vec::new();
        };
        let Some(name) = record
            .country
            .and_then(|c| c.names)
            .and_then(|n| n.get("en").map(|s| s.to_string()))
        else {
            return Vec::new();
        };
        vec![Annotation::text("geo.country", "Country", name, Severity::Info)]
    }
}

/// how often the watchlist file's mtime is re-checked at most
const WATCHLIST_RECHECK: Duration = Duration::from_secs(5);

/// flags endpoints on the user's watchlist: %ProgramData%\Iris\watchlist.txt,
/// one address or CIDR per line, `#` comments. offline by design; the file is
/// reloaded when its modification time changes. a hit is danger-severity, so
/// the monitor also raises an alert the first time such an endpoint is seen.
pub struct Watchlist {
    path: PathBuf,
    state: Mutex<WatchlistState>,
}

struct WatchlistState {
    set: IpSet,
    modified: Option<SystemTime>,
    checked: Option<Instant>,
}

impl Watchlist {
    pub fn new() -> Self {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        Watchlist {
            path: PathBuf::from(base).join("Iris").join("watchlist.txt"),
            state: Mutex::new(WatchlistState {
                set: IpSet::default(),
                modified: None,
                checked: None,
            }),
        }
    }

    /// reload the list when the file changed, re-statting at most every few
    /// seconds so the per-endpoint path stays cheap
    fn refresh(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(at) = state.checked {
            if at.elapsed() < WATCHLIST_RECHECK {
                return;
            }
        }
        state.checked = Some(Instant::now());
        let modified = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if modified == state.modified {
            return;
        }
        state.modified = modified;
        let text = std::fs::read_to_string(&self.path).unwrap_or_default();
        let (set, rejected) = IpSet::parse(&text);
        for line in &rejected {
            tracing::warn!("watchlist entry not understood: {line}");
        }
        tracing::info!(entries = set.len(), "watchlist loaded");
        state.set = set;
    }

    fn hit(&self, ip: &std::net::IpAddr) -> bool {
        self.refresh();
        self.state.lock().unwrap_or_else(|e| e.into_inner()).set.contains(ip)
    }
}

impl Default for Watchlist {
    fn default() -> Self {
        Self::new()
    }
}

impl Enricher for Watchlist {
    fn id(&self) -> &str {
        "iris.watchlist"
    }

    fn targets(&self) -> &[TargetKind] {
        &[TargetKind::Endpoint]
    }

    fn enrich(&self, target: &EnrichTarget) -> Vec<Annotation> {
        let EnrichTarget::Endpoint(ip) = target else {
            return Vec::new();
        };
        if !self.hit(ip) {
            return Vec::new();
        }
        vec![Annotation {
            key: "watchlist.hit".to_string(),
            label: "Watchlist".to_string(),
            value: AnnotationValue::Badge("Watched".to_string()),
            severity: Severity::Danger,
        }]
    }
}
