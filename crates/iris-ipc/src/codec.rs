use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{self, Read, Write};
use thiserror::Error;

/// hard cap on a single frame so a corrupt or hostile length prefix can't drive
/// an unbounded allocation. real frames (a stats tick, a rule list) are kilobytes.
pub const MAX_FRAME_LEN: u32 = 8 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("encode/decode: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("frame length {0} exceeds max {MAX_FRAME_LEN}")]
    FrameTooLarge(u32),
}

/// serialize a message into a length-prefixed frame: a 4-byte little-endian
/// length followed by the bincode payload.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, CodecError> {
    let payload = bincode::serialize(msg)?;
    let len = payload.len();
    if len as u64 > MAX_FRAME_LEN as u64 {
        return Err(CodecError::FrameTooLarge(len as u32));
    }
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&(len as u32).to_le_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// write one framed message to a sync stream
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), CodecError> {
    let frame = encode(msg)?;
    w.write_all(&frame)?;
    w.flush()?;
    Ok(())
}

/// read one framed message from a sync stream. returns `Ok(None)` on a clean EOF
/// at a frame boundary (peer closed the pipe).
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>, CodecError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(CodecError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    let msg = bincode::deserialize(&payload)?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{ClientMessage, PROTOCOL_VERSION};
    use std::io::Cursor;

    #[test]
    fn frame_roundtrips_through_a_cursor() {
        let msg = ClientMessage::Hello {
            protocol: PROTOCOL_VERSION,
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).unwrap();

        let mut cur = Cursor::new(buf);
        let got: ClientMessage = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(got, msg);
        // second read hits clean EOF
        let none: Option<ClientMessage> = read_frame(&mut cur).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn two_frames_read_back_in_order() {
        let a = ClientMessage::Subscribe;
        let b = ClientMessage::Ping { req: 7 };
        let mut buf = Vec::new();
        write_frame(&mut buf, &a).unwrap();
        write_frame(&mut buf, &b).unwrap();

        let mut cur = Cursor::new(buf);
        let ra: ClientMessage = read_frame(&mut cur).unwrap().unwrap();
        let rb: ClientMessage = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(ra, a);
        assert_eq!(rb, b);
    }

    #[test]
    fn oversize_length_prefix_is_rejected() {
        let mut framed = (MAX_FRAME_LEN + 1).to_le_bytes().to_vec();
        framed.extend_from_slice(&[0u8; 8]);
        let mut cur = Cursor::new(framed);
        let r: Result<Option<ClientMessage>, _> = read_frame(&mut cur);
        assert!(matches!(r, Err(CodecError::FrameTooLarge(_))));
    }
}
