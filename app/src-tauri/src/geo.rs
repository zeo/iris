//! offline IP -> country lookup using the bundled DB-IP Country Lite database
//! (CC-BY-4.0). the reader is memory-mapped once and shared; lookups run in the
//! UI process.

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;
use tauri::Manager;

/// managed handle to the in-memory country database, if it loaded
pub struct GeoDb(pub Option<Reader<Vec<u8>>>);

pub fn load(app: &tauri::AppHandle) -> GeoDb {
    let path = app
        .path()
        .resolve("resources/geo/dbip-country.mmdb", tauri::path::BaseDirectory::Resource);
    let reader = path.ok().and_then(|p| open(&p));
    if reader.is_none() {
        tracing::warn!("country database not found; geo lookups will be unresolved");
    }
    GeoDb(reader)
}

fn open(path: &Path) -> Option<Reader<Vec<u8>>> {
    Reader::open_readfile(path).ok()
}

/// country name (english) for an ip, or None if unknown / db missing
#[tauri::command]
pub fn geo_country(state: tauri::State<'_, GeoDb>, ip: String) -> Option<String> {
    let db = state.inner().0.as_ref()?;
    let addr: IpAddr = ip.parse().ok()?;
    let record: geoip2::Country = db.lookup(addr).ok()?;
    let country = record.country?;
    country
        .names?
        .get("en")
        .map(|s| s.to_string())
}
