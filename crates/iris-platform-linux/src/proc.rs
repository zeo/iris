//! resolves pids to their executable image path and builds the socket-inode ->
//! pid index the connection enumerator and byte monitor use to attribute a
//! kernel socket to the process that owns it.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// resolves a pid to its executable image path, caching results so the hot
/// attribution path does not readlink per socket. the cache is cleared
/// periodically by the monitor to bound the window in which pid reuse could
/// misattribute traffic to the wrong app.
pub struct PidCache {
    map: HashMap<u32, Option<String>>,
}

impl PidCache {
    pub fn new() -> Self {
        PidCache {
            map: HashMap::new(),
        }
    }

    pub fn resolve(&mut self, pid: u32) -> Option<String> {
        if let Some(hit) = self.map.get(&pid) {
            return hit.clone();
        }
        let path = image_path_of(pid);
        self.map.insert(pid, path.clone());
        path
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }
}

impl Default for PidCache {
    fn default() -> Self {
        Self::new()
    }
}

/// the running process's executable, resolved from /proc/<pid>/exe. a kernel
/// thread or an exited process has no readable exe and returns None (which the
/// cache remembers only until the next clear, so a racing exit self-heals).
pub fn image_path_of(pid: u32) -> Option<String> {
    let target = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let mut s = target.to_string_lossy().into_owned();
    // the kernel appends " (deleted)" to the target of a running binary whose
    // file was replaced or removed; strip it so the app id stays stable across
    // an in-place update
    if let Some(stripped) = s.strip_suffix(" (deleted)") {
        s = stripped.to_string();
    }
    Some(s)
}

/// index every socket inode currently held open to the pid that owns it, by
/// walking /proc/<pid>/fd and reading the `socket:[inode]` symlinks. one pass
/// per monitor tick keeps the socket -> process mapping the attribution needs.
pub fn socket_inode_owners() -> HashMap<u64, u32> {
    let mut out = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        index_pid_sockets(pid, &mut out);
    }
    out
}

fn index_pid_sockets(pid: u32, out: &mut HashMap<u64, u32>) {
    let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));
    let Ok(fds) = fs::read_dir(&fd_dir) else {
        return;
    };
    for fd in fds.flatten() {
        let Ok(target) = fs::read_link(fd.path()) else {
            continue;
        };
        // fd symlinks that point at a socket read as "socket:[12345]"
        if let Some(inode) = parse_socket_inode(&target.to_string_lossy()) {
            // the first pid seen owns it; a socket shared across a fork shows
            // under whichever pid /proc enumerates first, which is good enough
            // for attribution and matches how ss picks a holder
            out.entry(inode).or_insert(pid);
        }
    }
}

fn parse_socket_inode(link: &str) -> Option<u64> {
    let rest = link.strip_prefix("socket:[")?;
    let num = rest.strip_suffix(']')?;
    num.parse().ok()
}
