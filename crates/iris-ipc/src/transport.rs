//! async named-pipe transport shared by the service (listener) and UI (client).
//! frames are the same length-prefixed bincode as [`crate::codec`], read and
//! written over tokio. the duplex stream splits into independent recv/send
//! halves so the service can push ticks while a reader handles commands.

use crate::codec::MAX_FRAME_LEN;
use crate::{ADMIN_PIPE_NAME, PIPE_NAME, PLUGIN_PIPE_NAME};
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericFilePath, ListenerOptions};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use interprocess::local_socket::tokio::{Listener, RecvHalf, SendHalf, Stream};

// the security descriptors below apply only on Windows; on other targets the
// endpoint access is enforced by unix socket and directory permissions, so these
// are passed to the ignoring `listen_with` fallback and never read.

// the telemetry pipe: SYSTEM + Administrators full, read/write to interactively
// logged-on users (the unprivileged UI), medium integrity label so sandboxed
// low-integrity processes are excluded.
#[cfg_attr(not(windows), allow(dead_code))]
const TELEMETRY_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)S:(ML;;NW;;;ME)";
// the admin pipe: SYSTEM and Administrators only, no interactive-user grant. a
// non-elevated process (even an admin user's, whose UAC-filtered token has the
// Administrators SID as deny-only) cannot open it, so the OS enforces "elevation
// required" for the privileged rule mutations carried here, with no impersonation
// code on the service side.
#[cfg_attr(not(windows), allow(dead_code))]
const ADMIN_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)";
// the plugin pipe: SYSTEM only in the DACL, with a low integrity label so the
// restricted plugin children (SYSTEM user, privileges stripped, low IL) can
// still open it. per-plugin identity is the spawn-time token, not the pipe.
#[cfg_attr(not(windows), allow(dead_code))]
const PLUGIN_SDDL: &str = "D:(A;;GA;;;SY)S:(ML;;NW;;;LW)";

// on non-Windows the endpoints are unix sockets; access is enforced by the mode
// of the socket file and its parent directory, set after bind. the telemetry
// socket is world read/write (the desktop-user UI reaches the root engine); the
// admin and plugin sockets sit in restricted directories the service creates.
// these are ignored on Windows, where the security descriptor governs access.
#[cfg_attr(windows, allow(dead_code))]
const TELEMETRY_MODE: u32 = 0o666;
#[cfg_attr(windows, allow(dead_code))]
const ADMIN_MODE: u32 = 0o600;
#[cfg_attr(windows, allow(dead_code))]
const PLUGIN_MODE: u32 = 0o660;

/// bind the service listener for the unprivileged telemetry pipe.
pub fn listen() -> io::Result<Listener> {
    listen_with(PIPE_NAME, TELEMETRY_SDDL, TELEMETRY_MODE)
}

/// bind the service listener for the admin-only pipe that carries rule mutations.
pub fn listen_admin() -> io::Result<Listener> {
    listen_with(ADMIN_PIPE_NAME, ADMIN_SDDL, ADMIN_MODE)
}

/// bind the service listener for the out-of-process plugin pipe.
pub fn listen_plugins() -> io::Result<Listener> {
    listen_with(PLUGIN_PIPE_NAME, PLUGIN_SDDL, PLUGIN_MODE)
}

#[cfg(windows)]
fn listen_with(name: &str, sddl: &str, _mode: u32) -> io::Result<Listener> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    use widestring::U16CString;

    let fs_name = name.to_fs_name::<GenericFilePath>()?;
    let wide =
        U16CString::from_str(sddl).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let sd = SecurityDescriptor::deserialize(wide.as_ucstr())?;
    ListenerOptions::new()
        .name(fs_name)
        .security_descriptor(sd)
        .create_tokio()
}

#[cfg(not(windows))]
fn listen_with(name: &str, _sddl: &str, mode: u32) -> io::Result<Listener> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    let path = Path::new(name);
    // the runtime directory is created by the service host with the right
    // ownership; make sure it at least exists so a bare console run works
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    // a leftover socket from an unclean exit makes bind fail with EADDRINUSE;
    // the directory permissions, not the stale node, are the security boundary
    let _ = fs::remove_file(path);

    let fs_name = name.to_fs_name::<GenericFilePath>()?;
    let listener = ListenerOptions::new().name(fs_name).create_tokio()?;
    // interprocess binds under the process umask; set the intended mode
    // explicitly so a restrictive umask cannot lock the UI out and a permissive
    // one cannot widen the admin socket
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// connect the UI client to the telemetry pipe.
pub async fn connect() -> io::Result<Stream> {
    connect_to(PIPE_NAME).await
}

/// connect to the admin pipe (only an elevated caller can open it).
pub async fn connect_admin() -> io::Result<Stream> {
    connect_to(ADMIN_PIPE_NAME).await
}

/// connect a plugin child back to the service's plugin pipe.
pub async fn connect_plugins() -> io::Result<Stream> {
    connect_to(PLUGIN_PIPE_NAME).await
}

async fn connect_to(pipe: &str) -> io::Result<Stream> {
    let name = pipe.to_fs_name::<GenericFilePath>()?;
    Stream::connect(name).await
}

/// accept the next client on a listener. wraps the interprocess trait method so
/// callers need not import its traits.
pub async fn accept(listener: &Listener) -> io::Result<Stream> {
    listener.accept().await
}

/// split a duplex stream into independent recv/send halves for concurrent read
/// and write.
pub fn split(stream: Stream) -> (RecvHalf, SendHalf) {
    stream.split()
}

/// write one length-prefixed bincode frame.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let payload =
        bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if payload.len() as u64 > MAX_FRAME_LEN as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    w.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    w.write_all(&payload).await?;
    w.flush().await?;
    Ok(())
}

/// read one frame, or `Ok(None)` on a clean EOF at a frame boundary.
pub async fn read_frame<R, T>(r: &mut R) -> io::Result<Option<T>>
where
    R: AsyncReadExt + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    let msg =
        bincode::deserialize(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}
