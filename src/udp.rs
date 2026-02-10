use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::frame::{
    FrameError, decode_envelope, decode_envelope_with_expected_version, encode_envelope,
    encode_envelope_with_version,
};

pub const UDP_TOKEN_LEN: usize = 16;

pub fn encode_udp_datagram_with_version<M: Serialize>(
    token: [u8; UDP_TOKEN_LEN],
    version: u16,
    message: &M,
) -> Result<Vec<u8>, FrameError> {
    let payload = encode_envelope_with_version(message, version)?;
    let mut out = Vec::with_capacity(UDP_TOKEN_LEN + payload.len());
    out.extend_from_slice(&token);
    out.extend_from_slice(&payload);
    Ok(out)
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

pub fn decode_udp_datagram_with_version<M: DeserializeOwned>(
    bytes: &[u8],
    expected_version: u16,
) -> Result<([u8; UDP_TOKEN_LEN], M), FrameError> {
    if bytes.len() < UDP_TOKEN_LEN {
        return Err(FrameError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "udp datagram too short",
        )));
    }
    let mut token = [0u8; UDP_TOKEN_LEN];
    token.copy_from_slice(&bytes[..UDP_TOKEN_LEN]);

    let msg: M = decode_envelope_with_expected_version(&bytes[UDP_TOKEN_LEN..], expected_version)?;
    Ok((token, msg))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{messages, messages_v4};

    #[test]
    fn udp_datagrams_are_versioned() {
        let token = [7u8; UDP_TOKEN_LEN];

        let msg_v4 = messages_v4::PopToAgent::DirectShredsProbe { pop_now_ms: 1 };
        let bytes_v4 =
            encode_udp_datagram_with_version(token, messages_v4::PROTOCOL_VERSION, &msg_v4)
                .unwrap();

        let (decoded_token, decoded_v4): ([u8; UDP_TOKEN_LEN], messages_v4::PopToAgent) =
            decode_udp_datagram_with_version(&bytes_v4, messages_v4::PROTOCOL_VERSION).unwrap();
        assert_eq!(decoded_token, token);
        match decoded_v4 {
            messages_v4::PopToAgent::DirectShredsProbe { pop_now_ms } => assert_eq!(pop_now_ms, 1),
            other => panic!("expected DirectShredsProbe, got {other:?}"),
        }

        let err = decode_udp_datagram_with_version::<messages_v4::PopToAgent>(
            &bytes_v4,
            messages::PROTOCOL_VERSION,
        )
        .unwrap_err();
        match err {
            FrameError::VersionMismatch { got, expected } => {
                assert_eq!(got, messages_v4::PROTOCOL_VERSION);
                assert_eq!(expected, messages::PROTOCOL_VERSION);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }

        let msg_v5 = messages::PopToAgent::DirectShredsProbe { pop_now_ms: 2 };
        let bytes_v5 =
            encode_udp_datagram_with_version(token, messages::PROTOCOL_VERSION, &msg_v5).unwrap();

        let (decoded_token, decoded_v5): ([u8; UDP_TOKEN_LEN], messages::PopToAgent) =
            decode_udp_datagram_with_version(&bytes_v5, messages::PROTOCOL_VERSION).unwrap();
        assert_eq!(decoded_token, token);
        match decoded_v5 {
            messages::PopToAgent::DirectShredsProbe { pop_now_ms } => assert_eq!(pop_now_ms, 2),
            other => panic!("expected DirectShredsProbe, got {other:?}"),
        }
    }
}
