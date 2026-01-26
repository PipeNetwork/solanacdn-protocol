use ed25519_dalek::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("invalid verifying key bytes")]
    InvalidVerifyingKey,
    #[error("signature verification failed")]
    VerificationFailed,
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
    pub fn sign(validator_key: &SigningKey, payload: DelegationPayload) -> Result<Self, CryptoError> {
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
