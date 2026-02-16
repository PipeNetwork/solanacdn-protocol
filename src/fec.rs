use raptorq::{Decoder, EncoderBuilder, EncodingPacket, ObjectTransmissionInformation};

pub const DEFAULT_MAX_PACKET_BYTES: u16 = 1024;
pub const DEFAULT_REPAIR_PACKETS_PER_BLOCK: u32 = 2;
pub const DEFAULT_MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;

pub type OtiBytes = [u8; 12];

pub fn safe_fec_packet_bytes_public() -> u16 {
    let budget = crate::udp::MAX_UDP_PAYLOAD_PUBLIC;
    let overhead = crate::udp::UDP_TOKEN_LEN + 64; // conservative envelope + postcard overhead
    let max = budget.saturating_sub(overhead);
    max.min(u16::MAX as usize).max(256) as u16
}

pub fn clamp_fec_packet_bytes_public(n: u16) -> u16 {
    let max = safe_fec_packet_bytes_public();
    n.min(max).max(256)
}

#[derive(Debug, thiserror::Error)]
pub enum FecError {
    #[error("fec object too large: {transfer_length} bytes (max {max_bytes})")]
    ObjectTooLarge { transfer_length: u64, max_bytes: usize },
}

pub fn encode_raptorq(
    data: &[u8],
    max_packet_bytes: u16,
    repair_packets_per_block: u32,
) -> (OtiBytes, Vec<Vec<u8>>) {
    let mut builder = EncoderBuilder::new();
    builder.set_max_packet_size(max_packet_bytes);
    let encoder = builder.build(data);
    let oti = encoder.get_config().serialize();
    let packets = encoder.get_encoded_packets(repair_packets_per_block);
    let packets = packets.into_iter().map(|p| p.serialize()).collect();
    (oti, packets)
}

#[derive(Clone, Debug)]
pub struct RaptorqDecoder {
    inner: Decoder,
}

impl RaptorqDecoder {
    pub fn new(oti: OtiBytes) -> Result<Self, FecError> {
        Self::new_with_limit(oti, DEFAULT_MAX_OBJECT_BYTES)
    }

    pub fn new_with_limit(oti: OtiBytes, max_object_bytes: usize) -> Result<Self, FecError> {
        let oti = ObjectTransmissionInformation::deserialize(&oti);
        let transfer_length = oti.transfer_length();
        if transfer_length > max_object_bytes as u64 {
            return Err(FecError::ObjectTooLarge {
                transfer_length,
                max_bytes: max_object_bytes,
            });
        }
        Ok(Self {
            inner: Decoder::new(oti),
        })
    }

    pub fn push_packet(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        self.inner.decode(EncodingPacket::deserialize(packet))
    }

    pub fn result(&self) -> Option<Vec<u8>> {
        self.inner.get_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raptorq_roundtrip_recovers_with_single_packet_loss() {
        let data: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
        let (oti, packets) = encode_raptorq(&data, DEFAULT_MAX_PACKET_BYTES, 2);
        assert!(packets.len() >= 3);

        let mut dec = RaptorqDecoder::new(oti).unwrap();
        let mut out = None;
        for (i, packet) in packets.iter().enumerate() {
            if i == 0 {
                continue; // drop one packet
            }
            if let Some(v) = dec.push_packet(packet) {
                out = Some(v);
                break;
            }
        }

        let out = out.or_else(|| dec.result()).expect("decode result");
        assert_eq!(out, data);
    }

    #[test]
    fn raptorq_decoder_rejects_oversized_object() {
        let transfer = (DEFAULT_MAX_OBJECT_BYTES as u64) + 1;
        let mut oti = [0u8; 12];
        oti[0] = ((transfer >> 32) & 0xFF) as u8;
        oti[1] = ((transfer >> 24) & 0xFF) as u8;
        oti[2] = ((transfer >> 16) & 0xFF) as u8;
        oti[3] = ((transfer >> 8) & 0xFF) as u8;
        oti[4] = (transfer & 0xFF) as u8;

        let err = RaptorqDecoder::new_with_limit(oti, DEFAULT_MAX_OBJECT_BYTES).unwrap_err();
        match err {
            FecError::ObjectTooLarge {
                transfer_length,
                max_bytes,
            } => {
                assert_eq!(transfer_length, transfer);
                assert_eq!(max_bytes, DEFAULT_MAX_OBJECT_BYTES);
            }
        }
    }
}
