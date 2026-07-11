//! the framed wire protocol shared by the iris service and UI.
//!
//! [`message`] defines the two message enums and the negotiated
//! [`PROTOCOL_VERSION`]; [`codec`] provides length-prefixed bincode framing over
//! any sync `Read`/`Write` (the named-pipe transport lives in the service and
//! app crates). keeping the protocol in its own crate means both sides share one
//! source of truth for the wire shape.

pub mod codec;
pub mod message;

pub use codec::{encode, read_frame, write_frame, CodecError, MAX_FRAME_LEN};
pub use message::{ClientMessage, Reply, ServerMessage, PROTOCOL_VERSION};

/// the named-pipe path the service listens on and the UI connects to. the
/// service applies a DACL restricting it to the interactive user.
pub const PIPE_NAME: &str = r"\\.\pipe\iris-engine";
