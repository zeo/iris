//! where iris keeps its state, per OS. on Windows this is `%ProgramData%\Iris`;
//! on Linux it is `/var/lib/iris` for persistent state and `/run/iris` for the
//! sockets. one module so the store, rules file, logs, and plugin root agree.

use std::path::PathBuf;

/// the persistent data root: the history db, rules file, and plugin directory
/// all live under here
pub fn data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        PathBuf::from(base).join("Iris")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/iris")
    }
}

/// the engine log directory
pub fn log_dir() -> PathBuf {
    data_dir().join("logs")
}

/// the installed-plugin root, one directory per plugin id
pub fn plugins_dir() -> PathBuf {
    data_dir().join("plugins")
}

/// the rules file
pub fn rules_file() -> PathBuf {
    data_dir().join("rules.json")
}

/// the history database
pub fn store_file() -> PathBuf {
    data_dir().join("iris.db")
}

/// create the socket runtime directories with the ownership and modes the
/// endpoint security depends on: `/run/iris` world-traversable, `/run/iris/admin`
/// root-only (so only root can reach the admin socket, enforcing elevation), and
/// `/run/iris/plugins` group-owned by the sandbox account (so only plugin
/// children can reach the plugin socket). idempotent; best-effort per directory.
#[cfg(target_os = "linux")]
pub fn ensure_runtime_dirs() {
    use std::os::unix::fs::PermissionsExt;

    let run = PathBuf::from("/run/iris");
    let _ = std::fs::create_dir_all(&run);
    let _ = std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755));

    let admin = run.join("admin");
    let _ = std::fs::create_dir_all(&admin);
    let _ = std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o700));

    let plugins = run.join("plugins");
    let _ = std::fs::create_dir_all(&plugins);
    // group-own by the sandbox account and give the group traverse+read so a
    // plugin child can reach the socket the engine binds inside
    if let Some(gid) = plugin_gid() {
        let _ = chown(&plugins, 0, gid);
    }
    let _ = std::fs::set_permissions(&plugins, std::fs::Permissions::from_mode(0o750));
}

/// the gid of the plugin sandbox account, if it exists
#[cfg(target_os = "linux")]
pub fn plugin_gid() -> Option<u32> {
    let name = std::ffi::CString::new("iris-plugin").ok()?;
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    Some(unsafe { (*pw).pw_gid })
}

/// group-own the plugin socket by the sandbox account and make it group
/// read/write, so only a plugin child can connect. best-effort: without the
/// account the socket keeps its default (root-only) ownership, which fails safe.
#[cfg(target_os = "linux")]
pub fn grant_plugin_socket(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(gid) = plugin_gid() {
        let p = std::path::Path::new(path);
        let _ = chown(p, 0, gid);
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o660));
    }
}

#[cfg(target_os = "linux")]
fn chown(path: &std::path::Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
