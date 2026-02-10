use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::crypto::{CryptoError, PubkeyBytes, SignatureBytes, random_nonce_16};

/// Protocol version for the block-engine (builder) side-channel.
///
/// This is intentionally distinct from `messages::PROTOCOL_VERSION` to avoid coupling the
/// builder feature to the core SolanaCDN agent/POP protocol.
pub const BUILDER_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, thiserror::Error)]
pub enum BuilderFrameError {
    #[error("postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("protocol version mismatch: got {got}, expected {expected}")]
    VersionMismatch { got: u16, expected: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<M> {
    pub version: u16,
    pub message: M,
}

pub fn encode_envelope<M: Serialize>(message: &M) -> Result<Vec<u8>, BuilderFrameError> {
    let env = Envelope {
        version: BUILDER_PROTOCOL_VERSION,
        message,
    };
    Ok(postcard::to_stdvec(&env)?)
}

pub fn decode_envelope<M: DeserializeOwned>(bytes: &[u8]) -> Result<M, BuilderFrameError> {
    let env: Envelope<M> = postcard::from_bytes(bytes)?;
    if env.version != BUILDER_PROTOCOL_VERSION {
        return Err(BuilderFrameError::VersionMismatch {
            got: env.version,
            expected: BUILDER_PROTOCOL_VERSION,
        });
    }
    Ok(env.message)
}

pub type BundleId = [u8; 32];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub bundle_id: BundleId,
    /// Inclusive slot range.
    pub min_slot: u64,
    pub max_slot: u64,
    /// Absolute expiry (ms since UNIX epoch).
    pub expires_at_ms: u64,
    /// Declared tip amount used for ordering (validator re-checks via simulation).
    pub declared_tip_lamports: u64,
    /// Optional targeting hint (validator identity pubkey).
    #[serde(default)]
    pub target_validator: Option<PubkeyBytes>,
    /// Ordered list of raw Solana transactions (wire format), including a tip transaction.
    pub txs: Vec<Vec<u8>>,
    /// Optional searcher identity (bundle signer).
    #[serde(default)]
    pub searcher_pubkey: Option<PubkeyBytes>,
    /// Optional signature over the bundle contents.
    #[serde(default)]
    pub signature: Option<SignatureBytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BundleSigPayload {
    bundle_id: BundleId,
    min_slot: u64,
    max_slot: u64,
    expires_at_ms: u64,
    declared_tip_lamports: u64,
    #[serde(default)]
    target_validator: Option<PubkeyBytes>,
    txs: Vec<Vec<u8>>,
    #[serde(default)]
    searcher_pubkey: Option<PubkeyBytes>,
}

impl Bundle {
    pub fn sign(mut self, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let payload = BundleSigPayload {
            bundle_id: self.bundle_id,
            min_slot: self.min_slot,
            max_slot: self.max_slot,
            expires_at_ms: self.expires_at_ms,
            declared_tip_lamports: self.declared_tip_lamports,
            target_validator: self.target_validator,
            txs: self.txs.clone(),
            searcher_pubkey: Some(PubkeyBytes::from(signing_key.verifying_key())),
        };
        let bytes = postcard::to_stdvec(&payload)?;
        let sig = signing_key.sign(&bytes);
        self.searcher_pubkey = payload.searcher_pubkey;
        self.signature = Some(SignatureBytes::from(sig));
        Ok(self)
    }

    pub fn verify_signature(&self) -> Result<PubkeyBytes, CryptoError> {
        let searcher_pubkey = self.searcher_pubkey.ok_or(CryptoError::MissingSignerPubkey)?;
        let signature = self.signature.ok_or(CryptoError::MissingSignature)?;
        let payload = BundleSigPayload {
            bundle_id: self.bundle_id,
            min_slot: self.min_slot,
            max_slot: self.max_slot,
            expires_at_ms: self.expires_at_ms,
            declared_tip_lamports: self.declared_tip_lamports,
            target_validator: self.target_validator,
            txs: self.txs.clone(),
            searcher_pubkey: Some(searcher_pubkey),
        };
        let bytes = postcard::to_stdvec(&payload)?;
        searcher_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(searcher_pubkey)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaderWindow {
    /// Inclusive slot range the validator is actively building for.
    pub min_slot: u64,
    pub max_slot: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloAck {
    pub server_time_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorHello {
    pub validator_identity: PubkeyBytes,
    pub timestamp_ms: u64,
    pub nonce: [u8; 16],
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ValidatorHelloSigPayload {
    validator_identity: PubkeyBytes,
    timestamp_ms: u64,
    nonce: [u8; 16],
}

impl ValidatorHello {
    pub fn sign(timestamp_ms: u64, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let nonce = random_nonce_16();
        let payload = ValidatorHelloSigPayload {
            validator_identity: PubkeyBytes::from(signing_key.verifying_key()),
            timestamp_ms,
            nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        let sig = signing_key.sign(&bytes);
        Ok(Self {
            validator_identity: payload.validator_identity,
            timestamp_ms,
            nonce,
            signature: SignatureBytes::from(sig),
        })
    }

    pub fn verify_signature(&self) -> Result<(), CryptoError> {
        let payload = ValidatorHelloSigPayload {
            validator_identity: self.validator_identity,
            timestamp_ms: self.timestamp_ms,
            nonce: self.nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        self.validator_identity
            .to_verifying_key()?
            .verify_strict(&bytes, &self.signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearcherHello {
    /// Optional searcher identity. If present, `signature` must also be present.
    #[serde(default)]
    pub searcher_pubkey: Option<PubkeyBytes>,
    pub timestamp_ms: u64,
    pub nonce: [u8; 16],
    #[serde(default)]
    pub signature: Option<SignatureBytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SearcherHelloSigPayload {
    searcher_pubkey: PubkeyBytes,
    timestamp_ms: u64,
    nonce: [u8; 16],
}

impl SearcherHello {
    pub fn sign(timestamp_ms: u64, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let nonce = random_nonce_16();
        let payload = SearcherHelloSigPayload {
            searcher_pubkey: PubkeyBytes::from(signing_key.verifying_key()),
            timestamp_ms,
            nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        let sig = signing_key.sign(&bytes);
        Ok(Self {
            searcher_pubkey: Some(payload.searcher_pubkey),
            timestamp_ms,
            nonce,
            signature: Some(SignatureBytes::from(sig)),
        })
    }

    pub fn verify_signature(&self) -> Result<Option<PubkeyBytes>, CryptoError> {
        let Some(searcher_pubkey) = self.searcher_pubkey else {
            return Ok(None);
        };
        let Some(signature) = self.signature else {
            return Err(CryptoError::MissingSignature);
        };
        let payload = SearcherHelloSigPayload {
            searcher_pubkey,
            timestamp_ms: self.timestamp_ms,
            nonce: self.nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        searcher_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(Some(searcher_pubkey))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SearcherToEngine {
    Hello(SearcherHello),
    SubmitBundle(Bundle),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EngineToSearcher {
    HelloAck(HelloAck),
    Ok,
    Error(EngineError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ValidatorToEngine {
    Hello(ValidatorHello),
    LeaderWindow(LeaderWindow),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EngineToValidator {
    HelloAck(HelloAck),
    Bundle(Bundle),
    Error(EngineError),
}

pub fn slot_ranges_intersect(a_min: u64, a_max: u64, b_min: u64, b_max: u64) -> bool {
    let a0 = a_min.min(a_max);
    let a1 = a_min.max(a_max);
    let b0 = b_min.min(b_max);
    let b1 = b_min.max(b_max);
    a0 <= b1 && b0 <= a1
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn envelope_roundtrip() {
        let hello = SearcherHello {
            searcher_pubkey: None,
            timestamp_ms: 123,
            nonce: [9u8; 16],
            signature: None,
        };
        let msg = SearcherToEngine::Hello(hello);
        let bytes = encode_envelope(&msg).unwrap();
        let decoded: SearcherToEngine = decode_envelope(&bytes).unwrap();
        match decoded {
            SearcherToEngine::Hello(h) => assert_eq!(h.timestamp_ms, 123),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn validator_hello_sign_and_verify_works() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let hello = ValidatorHello::sign(123, &key).unwrap();
        hello.verify_signature().unwrap();
        assert_eq!(
            hello.validator_identity,
            PubkeyBytes::from(key.verifying_key())
        );
    }

    #[test]
    fn bundle_sign_and_verify_works() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let bundle = Bundle {
            bundle_id: [1u8; 32],
            min_slot: 10,
            max_slot: 12,
            expires_at_ms: 1234,
            declared_tip_lamports: 5,
            target_validator: None,
            txs: vec![vec![0u8; 4]],
            searcher_pubkey: None,
            signature: None,
        };
        let signed = bundle.sign(&key).unwrap();
        let signer = signed.verify_signature().unwrap();
        assert_eq!(signer, PubkeyBytes::from(key.verifying_key()));
    }

    #[test]
    fn slot_ranges_intersect_basic() {
        assert!(slot_ranges_intersect(10, 20, 20, 30));
        assert!(slot_ranges_intersect(20, 10, 30, 20));
        assert!(!slot_ranges_intersect(1, 2, 3, 4));
    }
}
