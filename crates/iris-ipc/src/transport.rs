//! async named-pipe transport shared by the service (listener) and UI (client).
//! frames are the same length-prefixed bincode as [`crate::codec`], read and
//! written over tokio. the duplex stream splits into independent recv/send
//! halves so the service can push ticks while a reader handles commands.

use crate::codec::MAX_FRAME_LEN;
use crate::PIPE_NAME;
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::{GenericFilePath, ListenerOptions};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use interprocess::local_socket::tokio::{Listener, RecvHalf, SendHalf, Stream};

/// bind the service listener to the iris pipe.
///
/// note: this uses the default pipe security descriptor, which is correct when
/// the service and UI run in the same session (development / console mode). the
/// installed LocalSystem service widens the DACL to the interactive user at
/// setup time via the platform layer.
pub fn listen() -> io::Result<Listener> {
    let name = PIPE_NAME.to_fs_name::<GenericFilePath>()?;
    ListenerOptions::new().name(name).create_tokio()
}

/// connect the UI client to the iris pipe.
pub async fn connect() -> io::Result<Stream> {
    let name = PIPE_NAME.to_fs_name::<GenericFilePath>()?;
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
