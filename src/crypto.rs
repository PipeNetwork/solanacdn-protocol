use std::fs;
use std::path::Path;

use ed25519_dalek::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("invalid keypair length: {0} (expected 64)")]
    InvalidKeypairLength(usize),
    #[error("public key mismatch")]
    PublicKeyMismatch,
    #[error("delegation cert is missing")]
    DelegationCertMissing,
    #[error("delegate pubkey is missing")]
    DelegatePubkeyMissing,
    #[error("delegation cert does not match payload")]
    DelegationCertMismatch,
    #[error("delegation cert is not valid at the provided timestamp")]
    DelegationNotValidAtTime,
    #[error("invalid verifying key bytes")]
    InvalidVerifyingKey,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("missing signer pubkey")]
    MissingSignerPubkey,
    #[error("missing signature")]
    MissingSignature,
    #[error("missing nonce")]
    MissingNonce,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PubkeyBytes(pub [u8; 32]);

impl PubkeyBytes {
    pub fn to_verifying_key(self) -> Result<VerifyingKey, CryptoError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidVerifyingKey)
    }

    /// Encode the pubkey as a base58 string (Solana format).
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}

impl From<VerifyingKey> for PubkeyBytes {
    fn from(value: VerifyingKey) -> Self {
        Self(value.to_bytes())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SignatureBytes(pub [u8; 64]);

impl SignatureBytes {
    pub fn to_signature(self) -> Signature {
        Signature::from_bytes(&self.0)
    }
}

impl From<Signature> for SignatureBytes {
    fn from(value: Signature) -> Self {
        Self(value.to_bytes())
    }
}

impl Serialize for SignatureBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = SignatureBytes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("64-byte ed25519 signature")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let bytes: [u8; 64] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &self))?;
                Ok(SignatureBytes(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 64];
                for (i, out) in bytes.iter_mut().enumerate() {
                    *out = seq
                        .next_element::<u8>()?
                        .ok_or_else(|| <A::Error as serde::de::Error>::invalid_length(i, &self))?;
                }

                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(<A::Error as serde::de::Error>::invalid_length(65, &self));
                }

                Ok(SignatureBytes(bytes))
            }
        }

        deserializer.deserialize_bytes(SigVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationPayload {
    pub validator_pubkey: PubkeyBytes,
    pub delegate_pubkey: PubkeyBytes,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    /// Optional POP scope identifier (e.g. region or POP id).
    pub scope: Option<String>,
    /// Random nonce to make certificates unique.
    pub nonce: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegationCert {
    pub payload: DelegationPayload,
    pub signature: SignatureBytes,
}

impl DelegationCert {
    pub fn sign(
        validator_key: &SigningKey,
        payload: DelegationPayload,
    ) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = validator_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
        })
    }

    pub fn verify(&self) -> Result<(), CryptoError> {
        let validator_vk = self.payload.validator_pubkey.to_verifying_key()?;
        let bytes = postcard::to_stdvec(&self.payload)?;
        let sig = self.signature.to_signature();
        validator_vk
            .verify_strict(&bytes, &sig)
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}

pub fn random_nonce_16() -> [u8; 16] {
    let mut out = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

/// Loads a Solana JSON keypair file (64-byte array) into an Ed25519 signing key.
pub fn load_solana_keypair_file(path: impl AsRef<Path>) -> Result<SigningKey, CryptoError> {
    let s = fs::read_to_string(path)?;
    let bytes: Vec<u8> = serde_json::from_str(&s)?;
    if bytes.len() != 64 {
        return Err(CryptoError::InvalidKeypairLength(bytes.len()));
    }

    let secret: [u8; 32] = bytes[0..32].try_into().expect("slice length checked");
    let public: [u8; 32] = bytes[32..64].try_into().expect("slice length checked");

    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    if verifying_key.to_bytes() != public {
        return Err(CryptoError::PublicKeyMismatch);
    }

    Ok(signing_key)
}

/// Loads a delegation certificate from a file.
///
/// Accepts either JSON (serde) or binary postcard encoding.
pub fn load_delegation_cert_file(path: impl AsRef<Path>) -> Result<DelegationCert, CryptoError> {
    let bytes = fs::read(path)?;
    if let Ok(cert) = serde_json::from_slice::<DelegationCert>(&bytes) {
        return Ok(cert);
    }
    Ok(postcard::from_bytes::<DelegationCert>(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn delegation_cert_roundtrip_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let payload = DelegationPayload {
            validator_pubkey: PubkeyBytes::from(key.verifying_key()),
            delegate_pubkey: PubkeyBytes([7u8; 32]),
            not_before_ms: 1,
            not_after_ms: 2,
            scope: Some("test".to_string()),
            nonce: random_nonce_16(),
        };
        let cert = DelegationCert::sign(&key, payload).unwrap();
        cert.verify().unwrap();

        let bytes = postcard::to_stdvec(&cert).unwrap();
        let decoded: DelegationCert = postcard::from_bytes(&bytes).unwrap();
        decoded.verify().unwrap();
    }

    #[test]
    fn signature_helpers_work() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let msg = b"hello";
        let sig = SignatureBytes::from(key.sign(msg));
        let vk = PubkeyBytes::from(key.verifying_key());
        let sig2 = sig.to_signature();
        vk.to_verifying_key()
            .unwrap()
            .verify_strict(msg, &sig2)
            .unwrap();
    }

    #[test]
    fn load_delegation_cert_file_accepts_json() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let cert = DelegationCert::sign(
            &key,
            DelegationPayload {
                validator_pubkey: PubkeyBytes::from(key.verifying_key()),
                delegate_pubkey: PubkeyBytes([2u8; 32]),
                not_before_ms: 1,
                not_after_ms: 2,
                scope: None,
                nonce: random_nonce_16(),
            },
        )
        .unwrap();

        let path = std::env::temp_dir().join(format!(
            "solanacdn-delegation-cert-{}.json",
            rand::random::<u64>()
        ));
        std::fs::write(&path, serde_json::to_vec(&cert).unwrap()).unwrap();

        let loaded = load_delegation_cert_file(&path).unwrap();
        loaded.verify().unwrap();

        let _ = std::fs::remove_file(&path);
    }
}
