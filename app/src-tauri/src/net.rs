//! small UI-side network helpers exposed as commands. these run in the
//! unprivileged UI process, not the engine.

use std::time::Duration;

/// reverse-resolve an IP to a hostname (PTR lookup). returns None if there is no
/// record, the lookup fails, or it takes too long (many cloud IPs have no PTR).
/// runs on a blocking pool and is capped so the UI never sits on "resolving…".
#[tauri::command]
pub async fn reverse_dns(ip: String) -> Option<String> {
    let job = tauri::async_runtime::spawn_blocking(move || {
        let addr: std::net::IpAddr = ip.parse().ok()?;
        let name = dns_lookup::lookup_addr(&addr).ok()?;
        // lookup_addr echoes the ip back when there is no PTR record
        if name == ip || name.is_empty() {
            None
        } else {
            Some(name)
        }
    });
    match tokio::time::timeout(Duration::from_secs(3), job).await {
        Ok(Ok(name)) => name,
        _ => None,
    }
}
