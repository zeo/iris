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

#[cfg(target_os = "linux")]
fn desktop_uid_file() -> PathBuf {
    data_dir().join("desktop.uid")
}

#[cfg(target_os = "linux")]
pub fn desktop_uid() -> std::io::Result<u32> {
    let raw = std::fs::read_to_string(desktop_uid_file())?;
    raw.trim()
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid desktop uid"))
}

#[cfg(target_os = "linux")]
pub fn record_desktop_uid(uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    std::io::Write::write_all(
        &mut options.open(desktop_uid_file())?,
        uid.to_string().as_bytes(),
    )
}

#[cfg(target_os = "linux")]
pub fn secure_state() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // no account may list the state root, but plugin children need to traverse
    // it to reach their root-owned executable below `plugins`
    std::fs::set_permissions(data_dir(), std::fs::Permissions::from_mode(0o711))?;
    let plugins = plugins_dir();
    let gid = plugin_gid().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "iris-plugin account missing")
    })?;
    chown(&plugins, 0, gid)?;
    std::fs::set_permissions(&plugins, std::fs::Permissions::from_mode(0o750))?;
    for path in [
        store_file(),
        data_dir().join("iris.db-wal"),
        data_dir().join("iris.db-shm"),
        rules_file(),
        desktop_uid_file(),
    ] {
        match std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// create the socket runtime directories with the ownership and modes the
/// endpoint security depends on: `/run/iris` world-traversable, `/run/iris/admin`
/// root-only (so only root can reach the admin socket, enforcing elevation), and
/// `/run/iris/plugins` group-owned by the sandbox account (so only plugin
/// children can reach the plugin socket)
#[cfg(target_os = "linux")]
pub fn ensure_runtime_dirs() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let run = PathBuf::from("/run/iris");
    std::fs::create_dir_all(&run)?;
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755))?;

    let admin = run.join("admin");
    std::fs::create_dir_all(&admin)?;
    std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o700))?;

    let plugins = run.join("plugins");
    std::fs::create_dir_all(&plugins)?;
    // group-own by the sandbox account and give the group traverse+read so a
    // plugin child can reach the socket the engine binds inside
    if let Some(gid) = plugin_gid() {
        chown(&plugins, 0, gid)?;
    }
    std::fs::set_permissions(&plugins, std::fs::Permissions::from_mode(0o750))?;
    Ok(())
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

/// group-own the plugin socket by the sandbox account
#[cfg(target_os = "linux")]
pub fn grant_plugin_socket(path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let gid = plugin_gid().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "iris-plugin account missing")
    })?;
    let path = std::path::Path::new(path);
    chown(path, 0, gid)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
}

#[cfg(target_os = "linux")]
pub fn grant_telemetry_socket(path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let uid = desktop_uid()?;
    let gid = primary_gid(uid)?;
    let path = std::path::Path::new(path);
    chown(path, 0, gid)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
}

#[cfg(target_os = "linux")]
fn primary_gid(uid: u32) -> std::io::Result<u32> {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "desktop account missing",
        ));
    }
    Ok(unsafe { (*pw).pw_gid })
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
