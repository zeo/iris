//! launch a plugin child under a dedicated unprivileged account. the engine runs
//! as root, but a plugin must never. the child is dropped to the `iris-plugin`
//! user and group with every supplementary group cleared, `no_new_privs` set so
//! it can never regain privilege through a setuid binary, resource limits capped,
//! and a parent-death signal so it dies with the engine. it reaches iris only by
//! connecting to the plugin socket, whose directory group admits exactly this
//! account, and authenticates with a spawn-time token.

use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// the account plugins run as. created by the installer; the spawn fails closed
/// if it is missing so a plugin never inherits the engine's root.
const PLUGIN_USER: &str = "iris-plugin";

/// a running restricted child. dropping it does not kill the child; call
/// [`RestrictedChild::terminate`] for that.
pub struct RestrictedChild {
    child: Child,
}

// the child handle is only touched behind the supervisor's per-plugin mutex
unsafe impl Send for RestrictedChild {}

impl RestrictedChild {
    /// true while the process is still running
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// exit code once the process has exited, else None
    pub fn exit_code(&mut self) -> Option<u32> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.code().unwrap_or(-1) as u32),
            _ => None,
        }
    }

    /// force the child to exit
    pub fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for RestrictedChild {
    fn drop(&mut self) {
        // std leaves a dropped Child running and unreaped; a respawn drops the
        // old handle, so kill and reap here or the previous plugin process would
        // linger as a zombie
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

/// a cryptographically-random hex token, used to authenticate a spawned plugin
/// back to the engine. falls back to an empty string only if the OS RNG is
/// unreadable, which the caller treats as a spawn failure.
pub fn random_token() -> String {
    use std::io::Read;
    let mut bytes = [0u8; 32];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)) {
        Ok(()) => {}
        Err(e) => {
            tracing::error!("cannot read /dev/urandom: {e}");
            return String::new();
        }
    }
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// spawn `exe` as the sandboxed plugin user, injecting `extra_env` (the plugin
/// auth token) into an otherwise-cleared environment.
pub fn spawn_restricted(exe: &Path, extra_env: &[(String, String)]) -> io::Result<RestrictedChild> {
    let (uid, gid) = plugin_ids()?;
    let cwd = exe.parent().map(Path::to_path_buf);

    let mut cmd = Command::new(exe);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("IRIS_SANDBOX", "1");
    if let Some(dir) = &cwd {
        cmd.current_dir(dir);
        cmd.env("HOME", dir);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    // everything in the pre-exec runs in the forked child before exec; it must
    // stay async-signal-safe (no allocation, no locks), so all values are
    // captured by copy and only raw libc calls are made
    unsafe {
        cmd.pre_exec(move || drop_privileges(uid, gid));
    }

    let child = cmd.spawn()?;
    Ok(RestrictedChild { child })
}

/// resolve the plugin account's uid/gid, failing closed if it is not present so
/// a plugin can never run with the engine's privileges
fn plugin_ids() -> io::Result<(u32, u32)> {
    let name = std::ffi::CString::new(PLUGIN_USER).unwrap();
    // getpwnam returns a pointer into a static buffer; we read the two fields we
    // need immediately and copy them out before any other libc call
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("plugin account '{PLUGIN_USER}' does not exist; plugins cannot be sandboxed"),
        ));
    }
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    if uid == 0 || gid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("plugin account '{PLUGIN_USER}' must not be root"),
        ));
    }
    Ok((uid, gid))
}

/// drop to the plugin account and lock the child down. runs in the forked child.
fn drop_privileges(uid: u32, gid: u32) -> io::Result<()> {
    unsafe {
        // never gain privilege through a setuid/setgid binary after this point
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        cap_resources();
        // detach from any controlling terminal so the child cannot signal the
        // session or read terminal input
        libc::setsid();
        // clear every supplementary group, then set the primary gid, before
        // dropping the uid (which would forbid the gid change)
        if libc::setgroups(1, &gid) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setgid(gid) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            return Err(io::Error::last_os_error());
        }
        // a defence in depth: confirm the uid actually stuck and cannot be
        // restored (setuid from non-root is one-way, but verify rather than trust)
        if libc::setuid(0) == 0 {
            return Err(io::Error::other("failed to drop root irrevocably"));
        }
        // PDEATHSIG is cleared by the credential change above, so arm it now: the
        // child gets SIGKILL if the engine exits
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
    }
    Ok(())
}

/// cap the resources a plugin can consume so a buggy or hostile one cannot
/// exhaust the host
unsafe fn cap_resources() {
    let set = |res: libc::__rlimit_resource_t, soft: u64, hard: u64| {
        let lim = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        libc::setrlimit(res, &lim);
    };
    set(libc::RLIMIT_NPROC, 64, 64);
    set(libc::RLIMIT_NOFILE, 256, 256);
    set(libc::RLIMIT_CORE, 0, 0);
    // 512 MiB address space is generous for an enricher and still bounds a leak
    set(libc::RLIMIT_AS, 512 * 1024 * 1024, 512 * 1024 * 1024);
}
