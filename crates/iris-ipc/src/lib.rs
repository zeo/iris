//! the framed wire protocol shared by the iris service and UI.
//!
//! [`message`] defines the two message enums and the negotiated
//! [`PROTOCOL_VERSION`]; [`codec`] provides length-prefixed bincode framing over
//! any sync `Read`/`Write` (the named-pipe transport lives in the service and
//! app crates). keeping the protocol in its own crate means both sides share one
//! source of truth for the wire shape.

pub mod codec;
pub mod message;
#[cfg(feature = "transport")]
pub mod transport;

pub use codec::{encode, read_frame, write_frame, CodecError, MAX_FRAME_LEN};
pub use message::{ClientMessage, Reply, ServerMessage, PROTOCOL_VERSION};

/// the telemetry named-pipe the unprivileged UI connects to for live stats,
/// reads, and connection kills. its DACL grants interactively-logged-on users
/// (the UI's context) and admins, with a medium integrity label so sandboxed
/// low-integrity processes cannot reach it.
pub const PIPE_NAME: &str = r"\\.\pipe\iris-engine";

/// the admin-only named-pipe that carries privileged rule mutations. its DACL
/// grants SYSTEM and Administrators only, so a non-elevated process cannot open
/// it and rule changes therefore require elevation, enforced by the OS.
pub const ADMIN_PIPE_NAME: &str = r"\\.\pipe\iris-engine-admin";
