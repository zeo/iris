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
        if let Some(claim) = appimage_from_environ(Path::new(&s), &environ) {
            if is_appimage_mount(pid, claim.appdir)
                && fs::metadata(claim.appimage).is_ok_and(|metadata| metadata.is_file())
            {
                return Some(claim.appimage.to_owned());
            }
        }
    }
    if let Some(appimage) = appimage_from_ancestors(pid, Path::new(&s)) {
        return Some(appimage);
    }
    if is_webkit_helper(Path::new(&s)) {
        if let Some(parent) = parent_pid(pid).and_then(image_path_of) {
            return Some(parent);
        }
    }
    Some(s)
}

/// an AppImage identity claimed by a process's `APPDIR`/`APPIMAGE` environment.
/// the values are attacker-controllable, so the caller must still confirm
/// `appdir` is a real AppImage mount (`is_appimage_mount`) before trusting it.
struct AppImageClaim<'a> {
    appdir: &'a Path,
    appimage: &'a str,
}

fn appimage_from_environ<'e>(target: &Path, environ: &'e [u8]) -> Option<AppImageClaim<'e>> {
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
    (mounted && target.starts_with(appdir) && Path::new(appimage).is_absolute())
        .then_some(AppImageClaim { appdir, appimage })
}

/// whether `dir` is the mount point of an AppImage fuse mount in the target
/// process's namespace. a process can set `APPDIR`/`APPIMAGE` to borrow a trusted
/// AppImage's identity (and its firewall rules), so we only trust them when APPDIR
/// is a genuine fuse mount, not a plain directory any process can mkdir. reading
/// the target's own mountinfo keeps this correct regardless of the engine
/// service's mount namespace. forging a fuse mount is a much higher bar than a
/// bare directory, though not an absolute guarantee.
fn is_appimage_mount(pid: u32, dir: &Path) -> bool {
    fs::read_to_string(format!("/proc/{pid}/mountinfo"))
        .is_ok_and(|mountinfo| mountinfo_declares_fuse_mount(&mountinfo, dir))
}

fn mountinfo_declares_fuse_mount(mountinfo: &str, dir: &Path) -> bool {
    mountinfo.lines().any(|line| {
        // fields: id parent major:minor root MOUNTPOINT opts [optional...] - fstype ..
        let mount_point = line.split(' ').nth(4);
        let fstype = line.split(" - ").nth(1).and_then(|tail| tail.split(' ').next());
        mount_point.is_some_and(|point| Path::new(point) == dir)
            && fstype.is_some_and(|fstype| fstype.starts_with("fuse"))
    })
}

fn appimage_from_ancestors(pid: u32, target: &Path) -> Option<String> {
    let mount = appimage_mount(target)?;
    let mut ancestor = parent_pid(pid)?;
    for _ in 0..12 {
        if let Ok(environ) = fs::read(format!("/proc/{ancestor}/environ")) {
            if let Some(claim) = appimage_from_environ(target, &environ) {
                if is_appimage_mount(ancestor, claim.appdir)
                    && fs::metadata(claim.appimage).is_ok_and(|metadata| metadata.is_file())
                {
                    return Some(claim.appimage.to_owned());
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

fn is_webkit_helper(target: &Path) -> bool {
    let webkit_dir = target
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("webkit2gtk-"));
    let helper = target
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "WebKitWebProcess" | "WebKitNetworkProcess" | "WebKitGPUProcess"
            )
        });
    webkit_dir && helper
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
    use super::{
        appimage_from_environ, appimage_mount, is_webkit_helper, mountinfo_declares_fuse_mount,
    };
    use std::path::Path;

    #[test]
    fn maps_a_mounted_appimage_child_to_the_bundle() {
        let environ =
            b"HOME=/home/user\0APPDIR=/tmp/.mount_SampleAbC\0APPIMAGE=/opt/Sample.AppImage\0";
        let claim = appimage_from_environ(
            Path::new("/tmp/.mount_SampleAbC/usr/libexec/WebKitWebProcess"),
            environ,
        );
        assert_eq!(claim.map(|claim| claim.appimage), Some("/opt/Sample.AppImage"));
    }

    #[test]
    fn ignores_spoofed_or_unrelated_appimage_variables() {
        let outside = b"APPDIR=/tmp/.mount_SampleAbC\0APPIMAGE=/opt/Sample.AppImage\0";
        assert!(appimage_from_environ(Path::new("/usr/bin/browser"), outside).is_none());
        let ordinary_dir = b"APPDIR=/opt/sample\0APPIMAGE=/opt/Sample.AppImage\0";
        assert!(appimage_from_environ(Path::new("/opt/sample/browser"), ordinary_dir).is_none());
        let relative = b"APPDIR=/tmp/.mount_SampleAbC\0APPIMAGE=Sample.AppImage\0";
        assert!(
            appimage_from_environ(Path::new("/tmp/.mount_SampleAbC/usr/bin/browser"), relative)
                .is_none()
        );
    }

    #[test]
    fn trusts_only_a_fuse_mount_at_the_appdir() {
        let dir = Path::new("/tmp/.mount_SampleAbC");
        let mounts = "36 35 0:32 / /tmp/.mount_SampleAbC ro,nosuid shared:1 - fuse.iris iris ro\n\
                      22 21 0:21 / /tmp rw shared:2 - tmpfs tmpfs rw\n";
        assert!(mountinfo_declares_fuse_mount(mounts, dir));
        // a directory that is not a mount point at all is rejected
        assert!(!mountinfo_declares_fuse_mount(mounts, Path::new("/tmp/.mount_Fake")));
        // a non-fuse mount conjured at the path (e.g. a bind mount) is rejected
        let bind = "40 35 0:33 / /tmp/.mount_SampleAbC rw - ext4 /dev/sda1 rw\n";
        assert!(!mountinfo_declares_fuse_mount(bind, dir));
    }

    #[test]
    fn finds_the_temporary_appimage_mount_root() {
        assert_eq!(
            appimage_mount(Path::new("/tmp/.mount_ExamplefEMJGD/opt/example/example")),
            Some(Path::new("/tmp/.mount_ExamplefEMJGD"))
        );
        assert_eq!(appimage_mount(Path::new("/usr/bin/browser")), None);
    }

    #[test]
    fn recognizes_only_webkit_runtime_helpers() {
        assert!(is_webkit_helper(Path::new(
            "/usr/libexec/webkit2gtk-4.1/WebKitNetworkProcess"
        )));
        assert!(is_webkit_helper(Path::new(
            "/tmp/.mount_App/usr/libexec/webkit2gtk-4.1/WebKitWebProcess"
        )));
        assert!(!is_webkit_helper(Path::new(
            "/home/user/WebKitNetworkProcess"
        )));
        assert!(!is_webkit_helper(Path::new(
            "/usr/libexec/webkit2gtk-4.1/MiniBrowser"
        )));
    }
}
