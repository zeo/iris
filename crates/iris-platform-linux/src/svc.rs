//! maps process ids to the systemd unit that owns them, so a process managed by
//! a service shows the unit name (e.g. `NetworkManager.service`) rather than a
//! bare pid, mirroring the Windows service-host mapping. the unit comes from the
//! process's cgroup, which systemd names after the unit. rebuilt on a slow
//! cadence since the pid-to-unit binding is stable for the life of the process.

use std::collections::HashMap;
use std::fs;

pub struct ServiceMap {
    by_pid: HashMap<u32, Vec<String>>,
}

impl ServiceMap {
    pub fn new() -> Self {
        ServiceMap {
            by_pid: HashMap::new(),
        }
    }

    /// the unit hosting `pid`, if any
    pub fn get(&self, pid: u32) -> Option<&[String]> {
        self.by_pid.get(&pid).map(Vec::as_slice)
    }

    /// re-scan /proc for cgroup unit membership; keeps the last good map on a
    /// read failure
    pub fn refresh(&mut self) {
        let mut map: HashMap<u32, Vec<String>> = HashMap::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return;
        };
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            if let Some(unit) = unit_of(pid) {
                map.entry(pid).or_default().push(unit);
            }
        }
        self.by_pid = map;
    }
}

impl Default for ServiceMap {
    fn default() -> Self {
        Self::new()
    }
}

/// the systemd unit a pid belongs to, parsed from /proc/<pid>/cgroup. systemd
/// encodes the unit as the last `*.service`, `*.socket`, or `*.scope` path
/// component of the cgroup, so a shared manager process names the unit it runs
/// under. user apps live under `*.scope`/`app-*.scope`, which we skip so only
/// real services are labelled.
fn unit_of(pid: u32) -> Option<String> {
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    // cgroup v2 is a single `0::<path>` line; v1 has many `n:controller:<path>`
    // lines. either way the systemd path is what we want, and the name= or unified
    // hierarchy carries it
    for line in cgroup.lines() {
        let path = line.rsplit_once("::").map(|(_, p)| p).or_else(|| {
            // v1: hid:controllers:path, take the path after the second colon
            let mut it = line.splitn(3, ':');
            it.next();
            let controllers = it.next()?;
            if controllers.is_empty() || controllers.contains("name=systemd") {
                it.next()
            } else {
                None
            }
        });
        let Some(path) = path else { continue };
        if let Some(unit) = service_component(path) {
            return Some(unit);
        }
    }
    None
}

/// the innermost `*.service` component of a cgroup path, if the process is under
/// a system service
fn service_component(path: &str) -> Option<String> {
    path.split('/')
        .rfind(|c| c.ends_with(".service"))
        .map(|c| c.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_innermost_service_unit() {
        assert_eq!(
            service_component("/system.slice/NetworkManager.service"),
            Some("NetworkManager.service".to_string())
        );
        assert_eq!(
            service_component("/system.slice/system-getty.slice/getty@tty1.service"),
            Some("getty@tty1.service".to_string())
        );
    }

    #[test]
    fn ignores_user_scopes_and_slices() {
        assert_eq!(service_component("/user.slice/user-1000.slice"), None);
        assert_eq!(
            service_component("/user.slice/user-1000.slice/session-2.scope"),
            None
        );
    }
}
