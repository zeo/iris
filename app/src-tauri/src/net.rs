//! small UI-side network helpers exposed as commands. these run in the
//! unprivileged UI process, not the engine.

/// reverse-resolve an IP to a hostname (PTR lookup). returns None if there is no
/// record or the lookup fails. runs on a blocking pool so DNS latency never
/// stalls the UI.
#[tauri::command]
pub async fn reverse_dns(ip: String) -> Option<String> {
    tauri::async_runtime::spawn_blocking(move || {
        let addr: std::net::IpAddr = ip.parse().ok()?;
        let name = dns_lookup::lookup_addr(&addr).ok()?;
        // lookup_addr echoes the ip back when there is no PTR record; treat that
        // as unresolved
        if name == ip {
            None
        } else {
            Some(name)
        }
    })
    .await
    .ok()
    .flatten()
}
