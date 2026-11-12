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

#[cfg(windows)]
const STATE_ROOT: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;GX;;;RC)";
#[cfg(windows)]
const PRIVATE: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
#[cfg(windows)]
const PLUGINS: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;RC)";

/// make sure the state root exists and is ours before anything is written
/// under it. a missing root is created with its protected DACL already in place,
/// so there is no moment where the inherited ProgramData ACL lets users add to it
#[cfg(windows)]
pub fn ensure_data_dir() -> std::io::Result<()> {
    let root = data_dir();
    match std::fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_secure_dir(&root)?,
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    check_owned(&root)
}

#[cfg(not(windows))]
pub fn ensure_data_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir())
}

#[cfg(windows)]
fn create_secure_dir(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::CreateDirectoryW;

    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let sddl: Vec<u16> = STATE_ROOT.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &mut descriptor,
            None,
        )
        .map_err(std::io::Error::other)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        let created = CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&attributes));
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        match created {
            // someone created it in between; check_owned judges what they made
            Err(error) if error.code() == ERROR_ALREADY_EXISTS.to_hresult() => Ok(()),
            result => result.map_err(std::io::Error::other),
        }
    }
}

#[cfg(windows)]
pub fn secure_state() -> std::io::Result<()> {
    // an owner can always rewrite a DACL, so the protected DACL only holds when
    // SYSTEM or Administrators own every entry; ensure_data_dir and set_tree_acl
    // refuse anything else instead of trusting it
    let root = data_dir();
    let plugins = plugins_dir();
    ensure_data_dir()?;
    set_acl(&root, STATE_ROOT)?;
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let path = entry.path();
        if path == plugins {
            set_tree_acl(&path, PLUGINS)?;
        } else {
            set_tree_acl(&path, PRIVATE)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn set_tree_acl(path: &std::path::Path, sddl: &str) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    use std::os::windows::fs::MetadataExt;
    if metadata.file_attributes() & 0x400 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "refusing reparse point in protected state: {}",
                path.display()
            ),
        ));
    }
    check_owned(path)?;
    if metadata.is_file() && has_multiple_links(path)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "refusing hard-linked file in protected state: {}",
                path.display()
            ),
        ));
    }
    set_acl(path, sddl)?;
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            set_tree_acl(&entry?.path(), sddl)?;
        }
    }
    Ok(())
}

/// SYSTEM and the Administrators group are the only owners the state may have:
/// an owner can always rewrite the DACL, so any other owner defeats it
#[cfg(windows)]
fn trusted_owner(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-32-544")
}

/// refuse a path that is a reparse point or that someone other than SYSTEM or
/// Administrators owns
#[cfg(windows)]
fn check_owned(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    if std::fs::symlink_metadata(path)?.file_attributes() & 0x400 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "refusing reparse point in protected state: {}",
                path.display()
            ),
        ));
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let sid = unsafe {
        let code = GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut descriptor,
        );
        if code != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(code.0 as i32));
        }
        // the owner sid lives inside the descriptor, so read it before freeing
        let sid = crate::grant::sid_to_string(owner);
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        sid?
    };
    if !trusted_owner(&sid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by {sid}, not SYSTEM or Administrators; delete it and start the service again",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn has_multiple_links(path: &std::path::Path) -> std::io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let file = std::fs::File::open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info)
            .map_err(std::io::Error::other)?;
    }
    Ok(info.nNumberOfLinks > 1)
}

#[cfg(windows)]
fn set_acl(path: &std::path::Path, sddl: &str) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &mut descriptor,
            None,
        )
        .map_err(std::io::Error::other)?;
        let applied = SetFileSecurityW(
            PCWSTR(path.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
        .ok()
        .map_err(std::io::Error::other);
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        applied
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn secure_state() -> std::io::Result<()> {
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

#[cfg(all(test, windows))]
mod tests {
    use super::{check_owned, trusted_owner};

    #[test]
    fn only_system_and_administrators_may_own_the_state() {
        assert!(trusted_owner("S-1-5-18"));
        assert!(trusted_owner("S-1-5-32-544"));
        assert!(!trusted_owner("S-1-5-32-545"));
        assert!(!trusted_owner("S-1-5-21-1-2-3-1001"));
        assert!(!trusted_owner("S-1-1-0"));
    }

    #[test]
    fn a_junction_is_refused() {
        let base = std::env::temp_dir().join(format!("iris-owner-test-{}", std::process::id()));
        let target = base.join("target");
        let link = base.join("link");
        std::fs::create_dir_all(&target).unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .status()
            .unwrap();
        assert!(made.success());
        let error = check_owned(&link).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        std::fs::remove_dir(&link).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }
}
