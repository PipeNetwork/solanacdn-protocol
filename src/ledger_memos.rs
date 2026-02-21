use serde::{Deserialize, Serialize};

use crate::crypto::PubkeyBytes;
use crate::messages::FairBatchWitness;

pub const FAIR_LEDGER_WITNESS_MAGIC: [u8; 8] = *b"SCDNWITN";
pub const FAIR_LEDGER_WITNESS_VERSION: u8 = 1;

/// Ledger-anchored witness receipt for fair slashing/auditing.
///
/// This is intended to be carried in a Solana memo-program instruction data payload.
///
/// Encoding: `bincode::serialize(&FairLedgerWitnessMemo { .. })`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairLedgerWitnessMemoPayload {
    pub magic: [u8; 8],
    pub version: u8,
    pub witness_pop_pubkey: PubkeyBytes,
    pub witness: FairBatchWitness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairLedgerWitnessMemo {
    pub payload: FairLedgerWitnessMemoPayload,
}

impl FairLedgerWitnessMemo {
    pub fn verify(&self) -> bool {
        if self.payload.magic != FAIR_LEDGER_WITNESS_MAGIC
            || self.payload.version != FAIR_LEDGER_WITNESS_VERSION
        {
            return false;
        }
        self.payload
            .witness
            .verify(self.payload.witness_pop_pubkey)
            .is_ok()
    }
}

pub fn encode_fair_ledger_witness_memo(
    witness_pop_pubkey: PubkeyBytes,
    witness: &FairBatchWitness,
) -> Option<Vec<u8>> {
    if witness.verify(witness_pop_pubkey).is_err() {
        return None;
    }
    let memo = FairLedgerWitnessMemo {
        payload: FairLedgerWitnessMemoPayload {
            magic: FAIR_LEDGER_WITNESS_MAGIC,
            version: FAIR_LEDGER_WITNESS_VERSION,
            witness_pop_pubkey,
            witness: witness.clone(),
        },
    };
    bincode::serialize(&memo).ok()
}

pub fn decode_fair_ledger_witness_memo(bytes: &[u8]) -> Option<FairLedgerWitnessMemo> {
    bincode::deserialize(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_nonce_16;
    use crate::messages::{FairBatchAttestationPayload, FairBatchWitness, FairBatchWitnessPayload};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn ledger_witness_memo_roundtrip_and_verify() {
        let mut rng = OsRng;
        let pop_signing_key = SigningKey::generate(&mut rng);
        let pop_pubkey = PubkeyBytes::from(pop_signing_key.verifying_key());

        let witness_payload = FairBatchWitnessPayload {
            attestation: FairBatchAttestationPayload {
                origin_pop_id: "pop-test-1".to_string(),
                flow_id: 0,
                batch_id: u128::from_le_bytes(random_nonce_16()),
                tx_seq_start: 1,
                tx_count: 2,
                tx_merkle_root: [7u8; 32],
                created_at_ms: 123,
                batch_ms: 25,
                target_slot: Some(42),
            },
            leader_pubkey: PubkeyBytes([9u8; 32]),
            pop_time_ms: 456,
        };
        let witness = FairBatchWitness::sign(witness_payload, &pop_signing_key).unwrap();

        let bytes = encode_fair_ledger_witness_memo(pop_pubkey, &witness).expect("encode");
        assert!(bytes.starts_with(&FAIR_LEDGER_WITNESS_MAGIC));

        let decoded = decode_fair_ledger_witness_memo(&bytes).expect("decode");
        assert!(decoded.verify());

        let mut corrupted = decoded.clone();
        corrupted.payload.witness_pop_pubkey = PubkeyBytes([8u8; 32]);
        assert!(!corrupted.verify());
    }
}
