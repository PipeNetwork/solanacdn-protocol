use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::frame::{FrameError, decode_envelope, encode_envelope};

pub const UDP_TOKEN_LEN: usize = 16;
pub const UDP_IPV6_MIN_MTU: usize = 1280;
pub const UDP_IPV6_OVERHEAD: usize = 48; // IPv6(40) + UDP(8)
pub const MAX_UDP_PAYLOAD_PUBLIC: usize = UDP_IPV6_MIN_MTU - UDP_IPV6_OVERHEAD;

pub fn clamp_public_udp_payload(n: usize) -> usize {
    n.clamp(64, MAX_UDP_PAYLOAD_PUBLIC)
}

pub fn encode_udp_datagram<M: Serialize>(
    token: [u8; UDP_TOKEN_LEN],
    message: &M,
) -> Result<Vec<u8>, FrameError> {
    let payload = encode_envelope(message)?;
    let mut out = Vec::with_capacity(UDP_TOKEN_LEN + payload.len());
    out.extend_from_slice(&token);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_udp_datagram<M: DeserializeOwned>(
    bytes: &[u8],
) -> Result<([u8; UDP_TOKEN_LEN], M), FrameError> {
    if bytes.len() < UDP_TOKEN_LEN {
        return Err(FrameError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "udp datagram too short",
        )));
    }
    let mut token = [0u8; UDP_TOKEN_LEN];
    token.copy_from_slice(&bytes[..UDP_TOKEN_LEN]);
    let msg = decode_envelope(&bytes[UDP_TOKEN_LEN..])?;
    Ok((token, msg))
}
