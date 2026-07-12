//! the framed wire protocol shared by the iris service and UI.
//!
//! [`message`] defines the two message enums and the negotiated
//! [`PROTOCOL_VERSION`]; [`codec`] provides length-prefixed bincode framing over
//! any sync `Read`/`Write` (the named-pipe transport lives in the service and
//! app crates). keeping the protocol in its own crate means both sides share one
//! source of truth for the wire shape.

pub mod codec;
pub mod message;
pub mod plugin;
#[cfg(feature = "transport")]
pub mod transport;

pub use codec::{encode, read_frame, write_frame, CodecError, MAX_FRAME_LEN};
pub use message::{ClientMessage, Reply, ServerMessage, PROTOCOL_VERSION};

/// the telemetry endpoint the unprivileged UI connects to for live stats,
/// reads, and connection kills. on Windows it is a named pipe whose DACL grants
/// interactively-logged-on users and admins with a medium integrity label; on
/// Linux it is a group-restricted Unix socket and the engine verifies the
/// connecting account through peer credentials
#[cfg(windows)]
pub const PIPE_NAME: &str = r"\\.\pipe\iris-engine";
#[cfg(not(windows))]
pub const PIPE_NAME: &str = "/run/iris/engine.sock";

/// the admin-only endpoint that carries privileged rule mutations. on Windows
/// its DACL grants SYSTEM and Administrators only; on Linux it lives in a
/// root-only directory (`/run/iris/admin`, mode 0700 root) so only a process
/// running as root can traverse to it. either way the OS enforces that rule
/// changes require elevation, with no impersonation code on the service side.
#[cfg(windows)]
pub const ADMIN_PIPE_NAME: &str = r"\\.\pipe\iris-engine-admin";
#[cfg(not(windows))]
pub const ADMIN_PIPE_NAME: &str = "/run/iris/admin/engine.sock";

/// the endpoint out-of-process plugins connect back on. on Windows its DACL
/// grants SYSTEM only with a low integrity label so the restricted child fits;
/// on Linux it lives in a directory owned by the dedicated plugin group
/// (`/run/iris/plugins`, mode 0750) so only the sandboxed plugin user can
/// connect. per-plugin identity comes from the spawn-time token handshake.
#[cfg(windows)]
pub const PLUGIN_PIPE_NAME: &str = r"\\.\pipe\iris-plugins";
#[cfg(not(windows))]
pub const PLUGIN_PIPE_NAME: &str = "/run/iris/plugins/plugins.sock";
