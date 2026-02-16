use std::io::{Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::messages::PROTOCOL_VERSION;

pub const DEFAULT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("protocol version mismatch: got {got}, expected {expected}")]
    VersionMismatch { got: u16, expected: u16 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<M> {
    pub version: u16,
    pub message: M,
}

pub fn encode_envelope<M: Serialize>(message: &M) -> Result<Vec<u8>, FrameError> {
    encode_envelope_with_version(message, PROTOCOL_VERSION)
}

pub fn encode_envelope_with_version<M: Serialize>(
    message: &M,
    version: u16,
) -> Result<Vec<u8>, FrameError> {
    let env = Envelope { version, message };
    Ok(postcard::to_stdvec(&env)?)
}

pub fn split_envelope(bytes: &[u8]) -> Result<(u16, &[u8]), FrameError> {
    let (version, rest) = postcard::take_from_bytes::<u16>(bytes)?;
    Ok((version, rest))
}

pub fn decode_message<M: DeserializeOwned>(bytes: &[u8]) -> Result<M, FrameError> {
    Ok(postcard::from_bytes(bytes)?)
}

pub fn decode_envelope_with_expected_version<M: DeserializeOwned>(
    bytes: &[u8],
    expected_version: u16,
) -> Result<M, FrameError> {
    let (got, rest) = split_envelope(bytes)?;
    if got != expected_version {
        return Err(FrameError::VersionMismatch {
            got,
            expected: expected_version,
        });
    }
    decode_message(rest)
}

pub fn decode_envelope<M: DeserializeOwned>(bytes: &[u8]) -> Result<M, FrameError> {
    decode_envelope_with_expected_version(bytes, PROTOCOL_VERSION)
}

pub fn write_len_prefixed_frame(writer: &mut impl Write, payload: &[u8]) -> Result<(), FrameError> {
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    Ok(())
}

pub fn read_len_prefixed_frame(reader: &mut impl Read) -> Result<Vec<u8>, FrameError> {
    read_len_prefixed_frame_with_limit(reader, DEFAULT_MAX_FRAME_BYTES)
}

pub fn read_len_prefixed_frame_with_limit(
    reader: &mut impl Read,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame_bytes {
        return Err(FrameError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame too large",
        )));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{AgentToPop, Heartbeat};

    #[test]
    fn envelope_roundtrip() {
        let msg = AgentToPop::Heartbeat(Heartbeat {
            now_ms: 123,
            stats: Default::default(),
        });
        let bytes = encode_envelope(&msg).unwrap();
        let decoded: AgentToPop = decode_envelope(&bytes).unwrap();
        match decoded {
            AgentToPop::Heartbeat(hb) => assert_eq!(hb.now_ms, 123),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn len_prefixed_framing_roundtrip() {
        let payload = b"abc";
        let mut buf = Vec::new();
        write_len_prefixed_frame(&mut buf, payload).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_len_prefixed_frame(&mut cursor).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn len_prefixed_framing_rejects_oversized_frame() {
        let max = 16usize;
        let too_large: u32 = (max as u32) + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&too_large.to_be_bytes());

        let mut cursor = std::io::Cursor::new(buf);
        let err = read_len_prefixed_frame_with_limit(&mut cursor, max).unwrap_err();
        match err {
            FrameError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
            other => panic!("expected io invalid input, got {other:?}"),
        }
    }

    #[test]
    fn len_prefixed_framing_rejects_oversized_frame_default_limit() {
        assert!(DEFAULT_MAX_FRAME_BYTES < u32::MAX as usize);
        let too_large: u32 = (DEFAULT_MAX_FRAME_BYTES as u32) + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&too_large.to_be_bytes());

        let mut cursor = std::io::Cursor::new(buf);
        let err = read_len_prefixed_frame(&mut cursor).unwrap_err();
        match err {
            FrameError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
            other => panic!("expected io invalid input, got {other:?}"),
        }
    }
}
