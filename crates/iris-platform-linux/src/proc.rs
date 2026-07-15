//! resolves pids to their executable image path and builds the socket-inode ->
//! pid index the connection enumerator and byte monitor use to attribute a
//! kernel socket to the process that owns it.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

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
    if let Ok(environ) = fs::read(format!("/proc/{pid}/environ")) {
        if let Some(appimage) = appimage_from_environ(Path::new(&s), &environ) {
            if fs::metadata(appimage).is_ok_and(|metadata| metadata.is_file()) {
                return Some(appimage.to_owned());
            }
        }
    }
    if let Some(appimage) = appimage_from_ancestors(pid, Path::new(&s)) {
        return Some(appimage);
    }
    Some(s)
}

fn appimage_from_environ<'a>(target: &Path, environ: &'a [u8]) -> Option<&'a str> {
    let variable = |name: &[u8]| {
        environ
            .split(|byte| *byte == 0)
            .find_map(|entry| entry.strip_prefix(name))
            .and_then(|path| std::str::from_utf8(path).ok())
    };
    let appdir = Path::new(variable(b"APPDIR=")?);
    let appimage = variable(b"APPIMAGE=")?;
    let mounted = appdir
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".mount_"));
    (mounted && target.starts_with(appdir) && Path::new(appimage).is_absolute()).then_some(appimage)
}

fn appimage_from_ancestors(pid: u32, target: &Path) -> Option<String> {
    let mount = appimage_mount(target)?;
    let mut ancestor = parent_pid(pid)?;
    for _ in 0..12 {
        if let Ok(environ) = fs::read(format!("/proc/{ancestor}/environ")) {
            if let Some(appimage) = appimage_from_environ(target, &environ) {
                if fs::metadata(appimage).is_ok_and(|metadata| metadata.is_file()) {
                    return Some(appimage.to_owned());
                }
            }
        }
        let path = fs::read_link(format!("/proc/{ancestor}/exe")).ok()?;
        let appimage = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("appimage"));
        if appimage
            && !path.starts_with(mount)
            && fs::metadata(&path).is_ok_and(|metadata| metadata.is_file())
        {
            return Some(path.to_string_lossy().into_owned());
        }
        ancestor = parent_pid(ancestor)?;
    }
    None
}

fn appimage_mount(target: &Path) -> Option<&Path> {
    target.ancestors().find(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".mount_"))
    })
}

fn parent_pid(pid: u32) -> Option<u32> {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PPid:")?.trim().parse().ok())
        .filter(|parent| *parent != 0)
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

#[cfg(test)]
mod tests {
    use super::{appimage_from_environ, appimage_mount};
    use std::path::Path;

    #[test]
    fn maps_a_mounted_appimage_child_to_the_bundle() {
        let environ =
            b"HOME=/home/one\0APPDIR=/tmp/.mount_ReservAbC\0APPIMAGE=/opt/Reservoir.AppImage\0";
        assert_eq!(
            appimage_from_environ(
                Path::new("/tmp/.mount_ReservAbC/usr/libexec/WebKitWebProcess"),
                environ
            ),
            Some("/opt/Reservoir.AppImage")
        );
    }

    #[test]
    fn ignores_spoofed_or_unrelated_appimage_variables() {
        let outside = b"APPDIR=/tmp/.mount_ReservAbC\0APPIMAGE=/opt/Reservoir.AppImage\0";
        assert_eq!(
            appimage_from_environ(Path::new("/usr/bin/browser"), outside),
            None
        );
        let ordinary_dir = b"APPDIR=/opt/reservoir\0APPIMAGE=/opt/Reservoir.AppImage\0";
        assert_eq!(
            appimage_from_environ(Path::new("/opt/reservoir/browser"), ordinary_dir),
            None
        );
        let relative = b"APPDIR=/tmp/.mount_ReservAbC\0APPIMAGE=Reservoir.AppImage\0";
        assert_eq!(
            appimage_from_environ(Path::new("/tmp/.mount_ReservAbC/usr/bin/browser"), relative),
            None
        );
    }

    #[test]
    fn finds_the_temporary_appimage_mount_root() {
        assert_eq!(
            appimage_mount(Path::new("/tmp/.mount_heliumdEMJGD/opt/helium/helium")),
            Some(Path::new("/tmp/.mount_heliumdEMJGD"))
        );
        assert_eq!(appimage_mount(Path::new("/usr/bin/browser")), None);
    }
}
