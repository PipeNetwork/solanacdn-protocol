use std::net::SocketAddr;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::crypto::CryptoError;
use crate::crypto::{DelegationCert, PubkeyBytes, SignatureBytes, random_nonce_16};

pub const PROTOCOL_VERSION: u16 = 8;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum StreamKind {
    Control,
    Shreds,
    Votes,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ShredId {
    pub slot: u64,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ShredKind {
    Tvu,
    Gossip,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shred {
    pub id: ShredId,
    pub kind: ShredKind,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShredBatch {
    pub batch_id: u128,
    pub created_at_ms: u64,
    pub shreds: Vec<Shred>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteDatagram {
    pub flow_id: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UdpFecChunk {
    pub object_id: u64,
    /// Serialized `raptorq::ObjectTransmissionInformation` (12 bytes).
    pub oti: [u8; 12],
    /// Serialized `raptorq::EncodingPacket` (`payload_id` + symbol bytes).
    pub packet: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HeartbeatStats {
    pub published_shred_batches: u64,
    pub pushed_shred_batches: u64,
    pub tunneled_vote_packets: u64,
    pub rx_vote_packets: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct PopStatsSnapshot {
    pub rx_shred_batches: u64,
    pub rx_shred_batches_deduped: u64,
    pub tx_shred_batches: u64,
    pub tx_shred_batches_dropped: u64,
    pub tx_shred_payloads_direct: u64,
    pub tx_shred_payloads_direct_dropped: u64,
    pub mesh_rx_shred_batches: u64,
    pub mesh_rx_shred_batches_deduped: u64,
    pub mesh_tx_shred_batches: u64,
    pub mesh_tx_shred_batches_dropped: u64,
    pub mesh_tx_forward_packets: u64,
    pub mesh_tx_forward_direct: u64,
    pub mesh_tx_forward_broadcast: u64,
    pub mesh_tx_forward_dropped: u64,
    pub rx_vote_datagrams: u64,
    pub tx_vote_datagrams: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct DirectShredsStats {
    pub tx_payloads: u64,
    pub tx_payloads_dropped: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct PopHeartbeatAck {
    pub pop_now_ms: u64,
    pub stats: PopStatsSnapshot,
    #[serde(default)]
    pub direct_shreds: Option<DirectShredsStats>,
}

/// Leader schedule report from agent to POP.
/// Agent reports the slots where its validator is an upcoming leader.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaderScheduleReport {
    /// The validator's identity pubkey (base58 encoded).
    pub validator_identity: String,
    /// Current slot at the time of this report.
    pub current_slot: u64,
    /// List of upcoming slots where this validator is the leader.
    /// Typically covers the next epoch's worth of leader slots.
    pub leader_slots: Vec<u64>,
    /// TPU port on the validator for transaction injection.
    pub tpu_port: u16,
    /// TPU forward port (optional, for forwarding to next leader).
    #[serde(default)]
    pub tpu_fwd_port: Option<u16>,
}

/// A raw transaction to be relayed to a validator's TPU.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayTransaction {
    /// Unique transaction ID for deduplication.
    pub tx_id: u64,
    /// Raw serialized transaction bytes (wire format).
    pub payload: Vec<u8>,
    /// Target slot (optional hint for prioritization).
    #[serde(default)]
    pub target_slot: Option<u64>,
}

/// A transaction delivered as part of a fair-ordered micro-batch.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairTx {
    /// First signature in the Solana transaction message (unique tx identifier).
    pub sig: SignatureBytes,
    /// Raw serialized transaction bytes (wire format).
    pub payload: Vec<u8>,
}

/// POP-signed attestation binding a fair batch to a monotonic per-origin sequence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchAttestationPayload {
    /// POP that produced the original `FairBatch`.
    pub origin_pop_id: String,
    /// Flow identifier within the origin POP (e.g. per-user/per-session).
    ///
    /// When unset, defaults to 0 (single-flow).
    #[serde(default)]
    pub flow_id: u128,
    /// Batch ID being attested.
    pub batch_id: u128,
    /// POP-assigned monotonic sequence number of `txs[0]` for this origin POP+flow.
    pub tx_seq_start: u64,
    /// Number of transactions in this batch.
    pub tx_count: u32,
    /// Merkle root committing to the ordered list of tx signatures.
    pub tx_merkle_root: [u8; 32],
    /// POP wall-clock timestamp when the batch was created (ms since Unix epoch).
    pub created_at_ms: u64,
    /// Intended micro-batch window (ms).
    pub batch_ms: u16,
    /// Optional target slot hint (best-effort).
    #[serde(default)]
    pub target_slot: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchAttestation {
    pub payload: FairBatchAttestationPayload,
    pub signature: SignatureBytes,
}

impl FairBatchAttestation {
    pub fn sign(
        payload: FairBatchAttestationPayload,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
        })
    }

    pub fn verify(&self, pop_pubkey: PubkeyBytes) -> Result<(), CryptoError> {
        let bytes = postcard::to_stdvec(&self.payload)?;
        pop_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &self.signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}

/// A POP-produced micro-batch of transactions intended to be ordered fairly by the leader.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatch {
    /// POP that produced this batch.
    pub origin_pop_id: String,
    /// Flow identifier within the origin POP (e.g. per-user/per-session).
    ///
    /// When unset, defaults to 0 (single-flow).
    #[serde(default)]
    pub flow_id: u128,
    /// POP-local unique identifier for this batch.
    pub batch_id: u128,
    /// POP-assigned monotonic sequence number of `txs[0]` for this origin POP+flow.
    pub tx_seq_start: u64,
    /// POP wall-clock timestamp when the batch was created (ms since Unix epoch).
    pub created_at_ms: u64,
    /// Intended micro-batch window (ms).
    pub batch_ms: u16,
    /// Optional target slot hint (best-effort).
    #[serde(default)]
    pub target_slot: Option<u64>,
    /// POP-signed attestation binding `(origin_pop_id, tx_seq_start)` and the ordered tx list.
    pub attestation: FairBatchAttestation,
    /// Ordered transactions.
    pub txs: Vec<FairTx>,
}

/// POP-signed witness that a specific leader was assigned/delivered a fair batch.
///
/// This is intended for slashing/auditing to detect "received but never committed" behavior: if
/// a leader's ledger does not contain a matching on-chain commit for a witnessed batch, auditors
/// may treat it as a violation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchWitnessPayload {
    /// POP-signed attestation committing to the batch contents and POP-local ordering metadata.
    pub attestation: FairBatchAttestationPayload,
    /// Validator identity pubkey that this batch was routed to (expected leader).
    pub leader_pubkey: PubkeyBytes,
    /// POP wall-clock timestamp when the witness was produced (ms since Unix epoch).
    pub pop_time_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchWitness {
    pub payload: FairBatchWitnessPayload,
    pub signature: SignatureBytes,
}

impl FairBatchWitness {
    pub fn sign(payload: FairBatchWitnessPayload, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
        })
    }

    pub fn verify(&self, pop_pubkey: PubkeyBytes) -> Result<(), CryptoError> {
        let bytes = postcard::to_stdvec(&self.payload)?;
        pop_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &self.signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum FairSeqCancelReason {
    /// No specific reason provided.
    Unknown,
    /// Transaction expired (e.g. blockhash too old).
    Expired,
    /// Transaction is invalid (e.g. sanitization failure).
    Invalid,
    /// Transaction was canceled by the client.
    ClientCanceled,
    /// Transaction was dropped by the POP/mesh and will not be delivered.
    Dropped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairSeqCancelPayload {
    /// POP that owns this per-origin sequence.
    pub origin_pop_id: String,
    /// Flow identifier within the origin POP (e.g. per-user/per-session).
    ///
    /// When unset, defaults to 0 (single-flow).
    #[serde(default)]
    pub flow_id: u128,
    /// POP-assigned monotonic sequence number being canceled.
    pub tx_seq: u64,
    pub reason: FairSeqCancelReason,
    /// POP wall-clock timestamp when the cancel was produced (ms since Unix epoch).
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairSeqCancel {
    pub payload: FairSeqCancelPayload,
    pub signature: SignatureBytes,
}

impl FairSeqCancel {
    pub fn sign(
        payload: FairSeqCancelPayload,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
        })
    }

    pub fn verify(&self, pop_pubkey: PubkeyBytes) -> Result<(), CryptoError> {
        let bytes = postcard::to_stdvec(&self.payload)?;
        pop_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &self.signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}

/// POP-signed checkpoint for a per-origin fair TX sequence used for leader handoff/resync.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairSeqHandoffPayload {
    /// POP that owns this per-origin sequence.
    pub origin_pop_id: String,
    /// Flow identifier within the origin POP (e.g. per-user/per-session).
    #[serde(default)]
    pub flow_id: u128,
    /// Sequence number the agent should expect next (inclusive).
    pub next_tx_seq: u64,
    /// POP wall-clock timestamp when the handoff was produced (ms since Unix epoch).
    pub created_at_ms: u64,
    /// Optional leader-signed compact commit that justifies this checkpoint.
    ///
    /// Agents may use this to safely advance `expected_next` across leader changes without
    /// trusting POP wall-clock time.
    #[serde(default)]
    pub last_receipt_commit: Option<FairBatchReceiptCommit>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairSeqHandoff {
    pub payload: FairSeqHandoffPayload,
    pub signature: SignatureBytes,
}

impl FairSeqHandoff {
    pub fn sign(payload: FairSeqHandoffPayload, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
        })
    }

    pub fn verify(&self, pop_pubkey: PubkeyBytes) -> Result<(), CryptoError> {
        let bytes = postcard::to_stdvec(&self.payload)?;
        pop_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &self.signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}

/// Agent request for POP to resync/close a per-origin fair TX sequence gap.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairSeqResyncRequest {
    /// POP that owns this per-origin sequence.
    pub origin_pop_id: String,
    /// Flow identifier within the origin POP (e.g. per-user/per-session).
    #[serde(default)]
    pub flow_id: u128,
    /// Sequence number the agent expects next (inclusive).
    pub expected_next_tx_seq: u64,
    /// Agent wall-clock timestamp when the request was produced (ms since Unix epoch).
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchCommitPayload {
    /// POP that produced the original `FairBatch`.
    pub origin_pop_id: String,
    /// Flow identifier within the origin POP (e.g. per-user/per-session).
    ///
    /// When unset, defaults to 0 (single-flow).
    #[serde(default)]
    pub flow_id: u128,
    /// Batch ID being committed.
    pub batch_id: u128,
    /// Ordering index of `tx_sigs[0]` (inclusive).
    ///
    /// When `AgentCapabilities.tx_fair_fifo_per_origin_flow` is true, this is the POP-provided
    /// per-origin+flow sequence number (`FairBatch.tx_seq_start`).
    ///
    /// Otherwise, this may be a leader-assigned global ordering index.
    pub order_start: u64,
    /// Optional target slot hint (best-effort).
    #[serde(default)]
    pub target_slot: Option<u64>,
    /// Transaction signatures in the committed order.
    pub tx_sigs: Vec<SignatureBytes>,
    /// Validator identity pubkey that signed this commit.
    pub leader_pubkey: PubkeyBytes,
    /// Leader wall-clock timestamp when the commit was produced (ms since Unix epoch).
    pub leader_time_ms: u64,
}

/// Leader-signed compact commitment to a fair batch order (Merkle root + count).
///
/// This is intended for low-latency per-transaction receipts where shipping the full `tx_sigs`
/// list is too large (e.g. UDP).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchReceiptCommitPayload {
    /// POP that produced the original `FairBatch`.
    pub origin_pop_id: String,
    /// Flow identifier within the origin POP (e.g. per-user/per-session).
    ///
    /// When unset, defaults to 0 (single-flow).
    #[serde(default)]
    pub flow_id: u128,
    /// Batch ID being committed.
    pub batch_id: u128,
    /// Ordering index of the first tx in the batch (inclusive).
    ///
    /// When `AgentCapabilities.tx_fair_fifo_per_origin_flow` is true, this is the POP-provided
    /// per-origin+flow sequence number (`FairBatch.tx_seq_start`).
    ///
    /// Otherwise, this may be a leader-assigned global ordering index.
    pub order_start: u64,
    /// Optional target slot hint (best-effort).
    #[serde(default)]
    pub target_slot: Option<u64>,
    /// Number of transactions in the batch (leaf count).
    pub tx_count: u32,
    /// Merkle root committing to the ordered list of tx signatures (see POP/agent implementation).
    pub tx_merkle_root: [u8; 32],
    /// Validator identity pubkey that signed this commit.
    pub leader_pubkey: PubkeyBytes,
    /// Leader wall-clock timestamp when the commit was produced (ms since Unix epoch).
    pub leader_time_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchReceiptCommit {
    pub payload: FairBatchReceiptCommitPayload,
    pub signature: SignatureBytes,
}

impl FairBatchReceiptCommit {
    pub fn sign(
        payload: FairBatchReceiptCommitPayload,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
        })
    }

    pub fn verify(&self) -> Result<(), CryptoError> {
        let bytes = postcard::to_stdvec(&self.payload)?;
        self.payload
            .leader_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &self.signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FairBatchRejectReason {
    Unknown,
    TooManyTxs,
    TotalBytesExceeded,
    InvalidAttestation,
    AttestationMismatch,
    TxSigMismatch,
    DuplicateSig,
    AlreadySeen,
    InvalidWireTx,
    MerkleRootMismatch,
    InternalError,
}

/// Leader-signed rejection of an entire `FairBatch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchRejectPayload {
    /// POP that produced the original `FairBatch`.
    pub origin_pop_id: String,
    /// Flow identifier within the origin POP (e.g. per-user/per-session).
    ///
    /// When unset, defaults to 0 (single-flow).
    #[serde(default)]
    pub flow_id: u128,
    /// Batch ID being rejected.
    pub batch_id: u128,
    /// Ordering index of the first tx in the batch (inclusive).
    ///
    /// When `AgentCapabilities.tx_fair_fifo_per_origin_flow` is true, this is the POP-provided
    /// per-origin+flow sequence number (`FairBatch.tx_seq_start`).
    pub order_start: u64,
    /// Optional target slot hint (best-effort).
    #[serde(default)]
    pub target_slot: Option<u64>,
    /// Rejection reason (best-effort, for client UX/telemetry).
    pub reason: FairBatchRejectReason,
    /// Validator identity pubkey that signed this rejection.
    pub leader_pubkey: PubkeyBytes,
    /// Leader wall-clock timestamp when the rejection was produced (ms since Unix epoch).
    pub leader_time_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchReject {
    pub payload: FairBatchRejectPayload,
    pub signature: SignatureBytes,
}

impl FairBatchReject {
    pub fn sign(payload: FairBatchRejectPayload, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
        })
    }

    pub fn verify(&self) -> Result<(), CryptoError> {
        let bytes = postcard::to_stdvec(&self.payload)?;
        self.payload
            .leader_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &self.signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}

/// Merkle proof of inclusion for a tx signature within a `FairBatchReceiptCommit`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairMerkleProof {
    /// Leaf index within the batch (0-based).
    pub index: u32,
    /// Sibling hashes from the leaf layer up to (but excluding) the root.
    pub siblings: Vec<[u8; 32]>,
}

/// Per-transaction fair ordering receipt suitable for client consumption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairTxReceipt {
    /// Transaction signature.
    pub tx_sig: SignatureBytes,
    /// Flow identifier within the origin POP (e.g. per-user/per-session).
    ///
    /// When unset, defaults to 0 (single-flow).
    #[serde(default)]
    pub flow_id: u128,
    /// Batch ID being committed.
    pub batch_id: u128,
    /// Ordering index of this transaction.
    ///
    /// When `AgentCapabilities.tx_fair_fifo_per_origin_flow` is true, this is the POP-provided
    /// per-origin+flow sequence number (`FairBatch.tx_seq_start + leaf_index`).
    pub order_ix: u64,
    /// Optional target slot hint (best-effort).
    #[serde(default)]
    pub target_slot: Option<u64>,
    /// Leader-signed compact batch commitment.
    pub commit: FairBatchReceiptCommit,
    /// Merkle inclusion proof for `tx_sig` at `order_ix - commit.payload.order_start`.
    pub merkle_proof: FairMerkleProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchCommit {
    pub payload: FairBatchCommitPayload,
    pub signature: SignatureBytes,
    #[serde(default)]
    pub receipt_commit: Option<FairBatchReceiptCommit>,
}

impl FairBatchCommit {
    pub fn sign(payload: FairBatchCommitPayload, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
            receipt_commit: None,
        })
    }

    pub fn verify(&self) -> Result<(), CryptoError> {
        let bytes = postcard::to_stdvec(&self.payload)?;
        self.payload
            .leader_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &self.signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Heartbeat {
    pub now_ms: u64,
    pub stats: HeartbeatStats,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthRequestPayload {
    pub validator_pubkey: PubkeyBytes,
    pub delegate_pubkey: Option<PubkeyBytes>,
    pub delegation_cert: Option<DelegationCert>,
    pub timestamp_ms: u64,
    pub nonce: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub payload: AuthRequestPayload,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug)]
pub struct VerifiedAuth {
    pub validator_pubkey: PubkeyBytes,
    pub active_pubkey: PubkeyBytes,
    pub delegate_pubkey: Option<PubkeyBytes>,
}

impl AuthRequest {
    pub fn sign(
        payload: AuthRequestPayload,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
        })
    }

    /// Verifies the signature and (if present) the delegation chain.
    ///
    /// Time-based replay protection should be enforced by the POP using
    /// `payload.timestamp_ms` + `payload.nonce` and a server-side window.
    pub fn verify_chain(&self) -> Result<VerifiedAuth, CryptoError> {
        let AuthRequestPayload {
            validator_pubkey,
            delegate_pubkey,
            delegation_cert,
            ..
        } = &self.payload;

        let active_pubkey = match (delegate_pubkey, delegation_cert) {
            (None, None) => *validator_pubkey,
            (Some(_), None) => return Err(CryptoError::DelegationCertMissing),
            (None, Some(_)) => return Err(CryptoError::DelegatePubkeyMissing),
            (Some(delegate_pk), Some(cert)) => {
                cert.verify()?;
                if cert.payload.validator_pubkey != *validator_pubkey {
                    return Err(CryptoError::DelegationCertMismatch);
                }
                if cert.payload.delegate_pubkey != *delegate_pk {
                    return Err(CryptoError::DelegationCertMismatch);
                }
                if self.payload.timestamp_ms < cert.payload.not_before_ms
                    || self.payload.timestamp_ms > cert.payload.not_after_ms
                {
                    return Err(CryptoError::DelegationNotValidAtTime);
                }
                *delegate_pk
            }
        };

        let bytes = postcard::to_stdvec(&self.payload)?;
        let sig = self.signature.to_signature();
        active_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &sig)
            .map_err(|_| CryptoError::VerificationFailed)?;

        Ok(VerifiedAuth {
            validator_pubkey: *validator_pubkey,
            active_pubkey,
            delegate_pubkey: *delegate_pubkey,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthOk {
    pub pop_id: String,
    /// POP identity pubkey used to sign fair ordering attestations/certificates.
    pub pop_pubkey: PubkeyBytes,
    pub server_time_ms: u64,
    /// Per-session token used to authenticate UDP data-plane datagrams.
    pub udp_token: [u8; 16],
    /// POP UDP listen port for shred batches (agent→POP and POP→agent).
    pub udp_shreds_port: u16,
    /// POP UDP listen port for vote datagrams (agent→POP and POP→agent).
    pub udp_votes_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthError {
    pub code: String,
    pub message: String,
}

/// Extended auth request that includes a short-lived Pipe control-plane session token.
///
/// This enables near-immediate revocation: POPs will drop sessions once the token expires unless
/// the agent refreshes it periodically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthWithSessionToken {
    pub auth: AuthRequest,
    pub session_token: String,
}

/// Refresh a short-lived session token for an already-authenticated session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthRefresh {
    pub session_token: String,
}

/// MCP data-availability request: distribute a lane checkpoint to validators so they can attest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpDaRequest {
    pub epoch: u64,
    pub slot: u64,
    pub lane_id: u8,
    pub checkpoint_ix: u16,
    pub checkpoint_id: [u8; 32],
    /// Encoded `McpCheckpointV1` bytes (Agave MCP wire format).
    pub checkpoint_bytes: Vec<u8>,
}

/// MCP data-availability attestation for a lane checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpDaAttest {
    pub epoch: u64,
    pub slot: u64,
    pub lane_id: u8,
    pub checkpoint_ix: u16,
    pub checkpoint_id: [u8; 32],
    pub validator_pubkey: PubkeyBytes,
    pub sig: SignatureBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum AgentToPop {
    Auth(AuthRequest),
    Heartbeat(Heartbeat),
    /// Advertise the agent's UDP ports for receiving shreds/vote responses from the POP.
    RegisterUdpPorts {
        shreds_port: u16,
        votes_port: u16,
    },
    /// Advertise the validator's shred ingress ports for direct POP→validator UDP injection.
    ///
    /// When `direct_shreds` is true, POPs may send raw shred UDP payloads directly to the agent's
    /// observed `peer_ip` on these ports (rather than sending `PushShredBatch` back to the agent
    /// for reinjection).
    RegisterValidatorPorts {
        tvu_port: u16,
        gossip_port: u16,
        direct_shreds: bool,
    },
    PublishShredBatch(ShredBatch),
    /// RaptorQ-encoded chunks of an `AgentToPop` message, carried over the UDP shreds port.
    PublishShredFecChunk(UdpFecChunk),
    PublishVoteDatagram(VoteDatagram),
    SubscribeShreds,
    UnsubscribeShreds,
    /// Identify the role of this QUIC stream within the connection.
    StreamHello(StreamKind),
    /// Report validator's upcoming leader slots for smart TX routing.
    LeaderSchedule(LeaderScheduleReport),
    /// Auth + Pipe session token (preferred when Pipe control-plane auth is enabled).
    AuthWithSessionToken(AuthWithSessionToken),
    /// Refresh Pipe session token for an active session.
    AuthRefresh(AuthRefresh),
    /// Leader-signed commit/receipt for a previously received `FairBatch`.
    FairBatchCommit(FairBatchCommit),
    /// Leader-signed ACK (compact receipt commit) for a previously received `FairBatch`.
    FairBatchAck(FairBatchReceiptCommit),
    /// Leader-signed rejection of an entire `FairBatch`.
    FairBatchReject(FairBatchReject),
    /// Per-session capabilities advertised by the agent/validator.
    Capabilities(AgentCapabilities),
    /// Subscribe to leader-signed fair ordering commits (used for slashing/auditing).
    SubscribeFairCommits,
    /// Stop receiving leader-signed fair ordering commits.
    UnsubscribeFairCommits,
    /// Subscribe to leader-signed fair ordering ACKs (used for slashing/auditing).
    SubscribeFairAcks,
    /// Stop receiving leader-signed fair ordering ACKs.
    UnsubscribeFairAcks,
    /// Subscribe to leader-signed fair batch rejections (used for client UX/auditing).
    SubscribeFairRejects,
    /// Stop receiving leader-signed fair batch rejections.
    UnsubscribeFairRejects,
    /// Subscribe to POP-signed fair batch witnesses (used for slashing/auditing).
    SubscribeFairWitnesses,
    /// Stop receiving POP-signed fair batch witnesses.
    UnsubscribeFairWitnesses,
    /// Request POP to close a per-origin fair TX sequence gap (send cancels and/or a handoff checkpoint).
    FairSeqResyncRequest(FairSeqResyncRequest),
    /// MCP data-availability request (checkpoint distribution).
    McpDaRequest(McpDaRequest),
    /// MCP data-availability attestation for a checkpoint.
    McpDaAttest(McpDaAttest),
    /// Subscribe to MCP data-availability requests over SolanaCDN.
    SubscribeMcpDa,
    /// Stop receiving MCP data-availability requests over SolanaCDN.
    UnsubscribeMcpDa,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum PopToAgent {
    AuthOk(AuthOk),
    AuthError(AuthError),
    HeartbeatAck(PopHeartbeatAck),
    PushShredBatch(ShredBatch),
    /// RaptorQ-encoded chunks of a `PopToAgent` message, carried over the UDP shreds port.
    PushShredFecChunk(UdpFecChunk),
    /// Periodic probe sent over the UDP shreds port when direct injection is enabled.
    ///
    /// Used by the agent to learn/update POP egress IPs for pcap ignore lists in NAT/LB setups.
    DirectShredsProbe {
        pop_now_ms: u64,
    },
    PushVoteDatagram(VoteDatagram),
    /// Relay a transaction to the validator's TPU for block production.
    RelayTransaction(RelayTransaction),
    /// POP-produced fair-ordered micro-batch (leader signs a commit/receipt).
    FairBatch(FairBatch),
    /// POP-signed witness that a specific leader was assigned/delivered a fair batch.
    FairBatchWitness(FairBatchWitness),
    /// POP-signed cancellation certificate for a missing/invalid fair tx sequence number.
    FairSeqCancel(FairSeqCancel),
    /// Leader-signed commit/receipt for a previously received `FairBatch`.
    FairBatchCommit(FairBatchCommit),
    /// Leader-signed ACK (compact receipt commit) for a previously received `FairBatch`.
    FairBatchAck(FairBatchReceiptCommit),
    /// Leader-signed rejection of an entire `FairBatch`.
    FairBatchReject(FairBatchReject),
    /// POP-signed checkpoint for leader handoff/resync of per-origin fair TX sequencing.
    FairSeqHandoff(FairSeqHandoff),
    /// MCP data-availability request (checkpoint distribution).
    McpDaRequest(McpDaRequest),
    /// MCP data-availability attestation for a checkpoint.
    McpDaAttest(McpDaAttest),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AgentCapabilities {
    /// If true, the validator is running with fair TX ordering enabled (e.g. `--fair`).
    ///
    /// When enabled, the agent will honor `FairBatch` ordering and respond with `FairBatchCommit`.
    #[serde(default)]
    pub tx_fair_ordering: bool,
    /// If true, the validator enforces strict FIFO/non-overtake ordering per `origin_pop_id`
    /// using POP-provided monotonic sequence numbers.
    #[serde(default)]
    pub tx_fair_fifo_per_origin: bool,
    /// If true, the validator enforces strict FIFO/non-overtake ordering per `(origin_pop_id, flow_id)`
    /// using POP-provided monotonic sequence numbers.
    #[serde(default)]
    pub tx_fair_fifo_per_origin_flow: bool,
    /// If true, the validator supports POP-signed handoff/resync checkpoints (`FairSeqHandoff`).
    #[serde(default)]
    pub tx_fair_seq_handoff: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopMeshHello {
    pub pop_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopMeshTreeUpdate {
    pub root_id: String,
    pub root_cost: u32,
    pub parent_id: Option<String>,
}

/// POP↔POP mesh link probe used for clock offset + one-way delay estimation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MeshLinkProbe {
    pub seq: u64,
    /// Sender timestamp (ms since Unix epoch) in the sender's clock domain.
    pub t0_ms: u64,
}

/// Acknowledge a `MeshLinkProbe` with receiver timestamps.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct MeshLinkProbeAck {
    pub seq: u64,
    /// Sender timestamp (ms since Unix epoch) echoed back from the probe.
    pub t0_ms: u64,
    /// Receiver timestamp (ms since Unix epoch) when the probe was received.
    pub t1_ms: u64,
    /// Receiver timestamp (ms since Unix epoch) when this ACK was sent.
    pub t2_ms: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxPacketForwardStatus {
    Accepted,
    DroppedQueueFull,
    DroppedNoIngress,
    DroppedFairUnavailable,
    DroppedHomePopUnavailable,
    DroppedInvalidPayload,
}

fn serialize_sent_at_ms<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_u64(*value)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum PopToPop {
    Hello(PopMeshHello),
    TreeUpdate(PopMeshTreeUpdate),
    ShredBatch {
        origin_pop_id: String,
        batch: ShredBatch,
        /// Best-effort send timestamp (ms since Unix epoch) for this mesh hop.
        /// Used for one-way delay telemetry. Defaults to 0 for backward compatibility.
        #[serde(default, serialize_with = "serialize_sent_at_ms")]
        sent_at_ms: u64,
    },
    /// Forward a builder bundle across the POP mesh (searcher → engine → validators).
    ///
    /// Used to deliver bundles to validators connected to remote POPs without requiring
    /// searchers to connect to every POP globally.
    BuilderBundleForward {
        origin_pop_id: String,
        bundle: crate::builder::Bundle,
    },
    VoteDatagramForward {
        origin_pop_id: String,
        origin_session_id: u64,
        datagram: VoteDatagram,
    },
    VoteDatagramResponse {
        origin_pop_id: String,
        origin_session_id: u64,
        datagram: VoteDatagram,
    },
    /// Forward a raw Solana transaction packet across the POP mesh.
    ///
    /// Used for "home POP" routing when POPs inject directly to validator TPUs to reduce
    /// duplicate injections across multiple POPs.
    TxPacketForward {
        origin_pop_id: String,
        home_pop_id: String,
        tx_key: u64,
        payload: Vec<u8>,
        /// Best-effort send timestamp (ms since Unix epoch) for this mesh hop.
        /// Used for one-way delay telemetry. Defaults to 0 for backward compatibility.
        #[serde(default, serialize_with = "serialize_sent_at_ms")]
        sent_at_ms: u64,
    },
    /// Forward a leader-signed commit/receipt for a `FairBatch` across the POP mesh.
    ///
    /// Used to return ordering receipts to the POP that accepted a retail transaction when
    /// home-POP routing is enabled (and for broader receipt propagation/monitoring).
    FairBatchCommitForward {
        target_pop_id: String,
        commit: FairBatchCommit,
    },
    /// Gossip a leader-signed commit/receipt for a `FairBatch` across the POP mesh.
    ///
    /// Used to propagate receipts network-wide for slashing/auditing.
    FairBatchCommitGossip {
        origin_pop_id: String,
        commit: FairBatchCommit,
    },
    /// Gossip a leader-signed ACK/receipt commit for a `FairBatch` across the POP mesh.
    ///
    /// Used to propagate compact ordering ACKs network-wide for slashing/auditing.
    FairBatchAckGossip {
        origin_pop_id: String,
        ack: FairBatchReceiptCommit,
    },
    /// Forward a leader-signed rejection of an entire `FairBatch` across the POP mesh.
    ///
    /// Used to return "reject" signals to the POP that accepted a retail transaction when
    /// home-POP routing is enabled.
    FairBatchRejectForward {
        target_pop_id: String,
        reject: FairBatchReject,
    },
    /// Gossip a leader-signed rejection of an entire `FairBatch` across the POP mesh.
    ///
    /// Used to propagate rejects network-wide for auditing/telemetry.
    FairBatchRejectGossip {
        origin_pop_id: String,
        reject: FairBatchReject,
    },
    /// Forward a raw Solana transaction packet across the POP mesh (v2 with policy flags).
    ///
    /// This is used by fair-ordering HTTP submit paths to prevent silent downgrade: when
    /// `require_fair=true`, the home POP must not fall back to legacy relay.
    TxPacketForwardV2 {
        origin_pop_id: String,
        home_pop_id: String,
        tx_key: u64,
        /// Flow identifier within the origin POP (e.g. per-user/per-session).
        ///
        /// When unset, defaults to 0 (single-flow).
        #[serde(default)]
        flow_id: u128,
        payload: Vec<u8>,
        require_fair: bool,
        /// Best-effort send timestamp (ms since Unix epoch) for this mesh hop.
        /// Used for one-way delay telemetry. Defaults to 0 for backward compatibility.
        #[serde(default, serialize_with = "serialize_sent_at_ms")]
        sent_at_ms: u64,
    },
    /// Acknowledge/deny a `TxPacketForwardV2` delivery attempt.
    ///
    /// Used to provide fast "accepted for fair" vs "rejected" signals back to the originating POP
    /// (for HTTP submit UX) when home-POP routing is enabled.
    TxPacketForwardResult {
        target_pop_id: String,
        tx_key: u64,
        tx_sig: SignatureBytes,
        require_fair: bool,
        status: TxPacketForwardStatus,
    },
    /// Forward an MCP DA request across the POP mesh (leader → validators).
    McpDaRequestForward {
        origin_pop_id: String,
        origin_session_id: u64,
        request: McpDaRequest,
    },
    /// Forward an MCP DA attestation across the POP mesh (validators → leader).
    McpDaAttestForward {
        target_pop_id: String,
        target_session_id: u64,
        attest: McpDaAttest,
    },
    /// Mesh link probe used for clock offset + one-way delay telemetry.
    LinkProbe(MeshLinkProbe),
    /// ACK for `LinkProbe` containing receiver timestamps.
    LinkProbeAck(MeshLinkProbeAck),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopInfo {
    pub pop_id: String,
    pub public_addr: SocketAddr,
    pub last_seen_ms: u64,
    #[serde(default)]
    pub capabilities: PopCapabilities,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopAnnounce {
    pub pop_id: String,
    pub public_addr: SocketAddr,
    pub now_ms: u64,
    #[serde(default)]
    pub capabilities: PopCapabilities,
    #[serde(default)]
    pub pop_pubkey: Option<PubkeyBytes>,
    #[serde(default)]
    pub nonce: Option<[u8; 16]>,
    #[serde(default)]
    pub signature: Option<SignatureBytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PopAnnounceSigPayload {
    pop_id: String,
    public_addr: SocketAddr,
    now_ms: u64,
    capabilities: PopCapabilities,
    nonce: [u8; 16],
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PopCapabilities {
    /// POP accepts raw Solana transactions over `tx_relay.listen_udp` and can forward/inject them.
    #[serde(default)]
    pub tx_relay: bool,
}

impl PopAnnounce {
    pub fn sign(mut self, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let nonce = random_nonce_16();
        let payload = PopAnnounceSigPayload {
            pop_id: self.pop_id.clone(),
            public_addr: self.public_addr,
            now_ms: self.now_ms,
            capabilities: self.capabilities.clone(),
            nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        let sig = signing_key.sign(&bytes);

        self.pop_pubkey = Some(PubkeyBytes::from(signing_key.verifying_key()));
        self.nonce = Some(nonce);
        self.signature = Some(SignatureBytes::from(sig));
        Ok(self)
    }

    pub fn verify_signature(&self) -> Result<PubkeyBytes, CryptoError> {
        let pop_pubkey = self.pop_pubkey.ok_or(CryptoError::MissingSignerPubkey)?;
        let nonce = self.nonce.ok_or(CryptoError::MissingNonce)?;
        let signature = self.signature.ok_or(CryptoError::MissingSignature)?;

        let payload = PopAnnounceSigPayload {
            pop_id: self.pop_id.clone(),
            public_addr: self.public_addr,
            now_ms: self.now_ms,
            capabilities: self.capabilities.clone(),
            nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        pop_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(pop_pubkey)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopList {
    pub pops: Vec<PopInfo>,
}

/// Builder/Block-engine POP info (separate from the core SolanaCDN POP registry).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderPopInfo {
    pub pop_id: String,
    pub public_addr: SocketAddr,
    pub last_seen_ms: u64,
    /// QUIC endpoint for `pipe-solana-validator` sessions (engine → validator pushes).
    pub validator_quic_addr: SocketAddr,
    /// QUIC endpoint for searcher submissions (searcher → engine).
    pub searcher_quic_addr: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderPopList {
    pub pops: Vec<BuilderPopInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderPopAnnounce {
    pub pop_id: String,
    pub public_addr: SocketAddr,
    pub validator_quic_addr: SocketAddr,
    pub searcher_quic_addr: SocketAddr,
    pub now_ms: u64,
    #[serde(default)]
    pub pop_pubkey: Option<PubkeyBytes>,
    #[serde(default)]
    pub nonce: Option<[u8; 16]>,
    #[serde(default)]
    pub signature: Option<SignatureBytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BuilderPopAnnounceSigPayload {
    pop_id: String,
    public_addr: SocketAddr,
    validator_quic_addr: SocketAddr,
    searcher_quic_addr: SocketAddr,
    now_ms: u64,
    nonce: [u8; 16],
}

impl BuilderPopAnnounce {
    pub fn sign(mut self, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let nonce = random_nonce_16();
        let payload = BuilderPopAnnounceSigPayload {
            pop_id: self.pop_id.clone(),
            public_addr: self.public_addr,
            validator_quic_addr: self.validator_quic_addr,
            searcher_quic_addr: self.searcher_quic_addr,
            now_ms: self.now_ms,
            nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        let sig = signing_key.sign(&bytes);

        self.pop_pubkey = Some(PubkeyBytes::from(signing_key.verifying_key()));
        self.nonce = Some(nonce);
        self.signature = Some(SignatureBytes::from(sig));
        Ok(self)
    }

    pub fn verify_signature(&self) -> Result<PubkeyBytes, CryptoError> {
        let pop_pubkey = self.pop_pubkey.ok_or(CryptoError::MissingSignerPubkey)?;
        let nonce = self.nonce.ok_or(CryptoError::MissingNonce)?;
        let signature = self.signature.ok_or(CryptoError::MissingSignature)?;

        let payload = BuilderPopAnnounceSigPayload {
            pop_id: self.pop_id.clone(),
            public_addr: self.public_addr,
            validator_quic_addr: self.validator_quic_addr,
            searcher_quic_addr: self.searcher_quic_addr,
            now_ms: self.now_ms,
            nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        pop_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(pop_pubkey)
    }
}

/// Builder validator-session announcement (ephemeral directory entry).
///
/// A POP should periodically announce active validator sessions so other POPs can route bundles
/// to the validator's connected POPs (redundancy=2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderValidatorSessionAnnounce {
    pub pop_id: String,
    pub validator_identity: PubkeyBytes,
    pub now_ms: u64,
    #[serde(default)]
    pub pop_pubkey: Option<PubkeyBytes>,
    #[serde(default)]
    pub nonce: Option<[u8; 16]>,
    #[serde(default)]
    pub signature: Option<SignatureBytes>,
    /// Validator countersignature proof (derived from validator hello).
    #[serde(default)]
    pub validator_proof: Option<BuilderValidatorSessionProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BuilderValidatorSessionAnnounceSigPayload {
    pop_id: String,
    validator_identity: PubkeyBytes,
    now_ms: u64,
    nonce: [u8; 16],
}

/// Validator countersignature proof for builder session announcements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderValidatorSessionProof {
    pub validator_identity: PubkeyBytes,
    pub timestamp_ms: u64,
    pub nonce: [u8; 16],
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BuilderValidatorSessionProofSigPayload {
    validator_identity: PubkeyBytes,
    timestamp_ms: u64,
    nonce: [u8; 16],
}

impl BuilderValidatorSessionProof {
    pub fn verify_signature(&self) -> Result<(), CryptoError> {
        let payload = BuilderValidatorSessionProofSigPayload {
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

impl From<&crate::builder::ValidatorHello> for BuilderValidatorSessionProof {
    fn from(hello: &crate::builder::ValidatorHello) -> Self {
        Self {
            validator_identity: hello.validator_identity,
            timestamp_ms: hello.timestamp_ms,
            nonce: hello.nonce,
            signature: hello.signature,
        }
    }
}

impl BuilderValidatorSessionAnnounce {
    pub fn sign(mut self, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let nonce = random_nonce_16();
        let payload = BuilderValidatorSessionAnnounceSigPayload {
            pop_id: self.pop_id.clone(),
            validator_identity: self.validator_identity,
            now_ms: self.now_ms,
            nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        let sig = signing_key.sign(&bytes);

        self.pop_pubkey = Some(PubkeyBytes::from(signing_key.verifying_key()));
        self.nonce = Some(nonce);
        self.signature = Some(SignatureBytes::from(sig));
        Ok(self)
    }

    pub fn verify_signature(&self) -> Result<PubkeyBytes, CryptoError> {
        let pop_pubkey = self.pop_pubkey.ok_or(CryptoError::MissingSignerPubkey)?;
        let nonce = self.nonce.ok_or(CryptoError::MissingNonce)?;
        let signature = self.signature.ok_or(CryptoError::MissingSignature)?;

        let payload = BuilderValidatorSessionAnnounceSigPayload {
            pop_id: self.pop_id.clone(),
            validator_identity: self.validator_identity,
            now_ms: self.now_ms,
            nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        pop_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(pop_pubkey)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderValidatorPopsRequest {
    pub validator_identity: PubkeyBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderValidatorPopInfo {
    pub pop_id: String,
    pub public_addr: SocketAddr,
    pub last_seen_ms: u64,
    /// QUIC endpoint for `pipe-solana-validator` sessions (engine → validator pushes).
    pub validator_quic_addr: SocketAddr,
    /// QUIC endpoint for searcher submissions (searcher → engine).
    pub searcher_quic_addr: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderValidatorPopList {
    pub validator_identity: PubkeyBytes,
    pub pops: Vec<BuilderValidatorPopInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizePopSession {
    pub pop_id: String,
    pub validator_pubkey: PubkeyBytes,
    pub active_pubkey: PubkeyBytes,
    pub delegate_pubkey: Option<PubkeyBytes>,
    pub timestamp_ms: u64,
    pub nonce: [u8; 16],
    #[serde(default)]
    pub pop_pubkey: Option<PubkeyBytes>,
    #[serde(default)]
    pub signature: Option<SignatureBytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuthorizePopSessionSigPayload {
    pop_id: String,
    validator_pubkey: PubkeyBytes,
    active_pubkey: PubkeyBytes,
    delegate_pubkey: Option<PubkeyBytes>,
    timestamp_ms: u64,
    nonce: [u8; 16],
}

impl AuthorizePopSession {
    pub fn sign(mut self, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let payload = AuthorizePopSessionSigPayload {
            pop_id: self.pop_id.clone(),
            validator_pubkey: self.validator_pubkey,
            active_pubkey: self.active_pubkey,
            delegate_pubkey: self.delegate_pubkey,
            timestamp_ms: self.timestamp_ms,
            nonce: self.nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        let sig = signing_key.sign(&bytes);

        self.pop_pubkey = Some(PubkeyBytes::from(signing_key.verifying_key()));
        self.signature = Some(SignatureBytes::from(sig));
        Ok(self)
    }

    pub fn verify_signature(&self) -> Result<PubkeyBytes, CryptoError> {
        let pop_pubkey = self.pop_pubkey.ok_or(CryptoError::MissingSignerPubkey)?;
        let signature = self.signature.ok_or(CryptoError::MissingSignature)?;

        let payload = AuthorizePopSessionSigPayload {
            pop_id: self.pop_id.clone(),
            validator_pubkey: self.validator_pubkey,
            active_pubkey: self.active_pubkey,
            delegate_pubkey: self.delegate_pubkey,
            timestamp_ms: self.timestamp_ms,
            nonce: self.nonce,
        };
        let bytes = postcard::to_stdvec(&payload)?;
        pop_pubkey
            .to_verifying_key()?
            .verify_strict(&bytes, &signature.to_signature())
            .map_err(|_| CryptoError::VerificationFailed)?;
        Ok(pop_pubkey)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlRequest {
    AnnouncePop(PopAnnounce),
    ListPops,
    AuthorizePopSession(AuthorizePopSession),
    /// Announce a POP that runs the optional builder/block-engine service.
    AnnounceBuilderPop(BuilderPopAnnounce),
    /// List POPs that run the optional builder/block-engine service.
    ListBuilderPops,
    /// Announce an active validator session on a builder POP (ephemeral; TTL-based).
    AnnounceBuilderValidatorSession(BuilderValidatorSessionAnnounce),
    /// Lookup builder POPs that currently have an active session for a validator identity.
    LookupBuilderValidatorPops(BuilderValidatorPopsRequest),
    /// Fetch the current centralized policy for SolanaCDN agents (kill switch + denylist).
    GetAgentPolicy,
    /// Fetch the current searcher IP allowlist for builder bundle submissions.
    GetSearcherAllowlist,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlResponse {
    Ok,
    PopList(PopList),
    Error(ControlError),
    /// List of POPs that run the optional builder/block-engine service.
    BuilderPopList(BuilderPopList),
    /// List of builder POPs that currently have an active session for a validator identity.
    BuilderValidatorPopList(BuilderValidatorPopList),
    AgentPolicy(AgentPolicySnapshot),
    SearcherAllowlist(SearcherAllowlistSnapshot),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentPolicySnapshot {
    pub kill_switch: bool,
    pub disabled_validators: Vec<PubkeyBytes>,
    pub updated_at_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SearcherAllowlistSnapshot {
    pub allowed_ips: Vec<String>,
    pub updated_at_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoError, DelegationCert, DelegationPayload, PubkeyBytes};

    #[test]
    fn auth_request_validator_only_verifies() {
        let validator_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let payload = AuthRequestPayload {
            validator_pubkey: PubkeyBytes::from(validator_key.verifying_key()),
            delegate_pubkey: None,
            delegation_cert: None,
            timestamp_ms: 1,
            nonce: [9u8; 16],
        };
        let req = AuthRequest::sign(payload, &validator_key).unwrap();
        let verified = req.verify_chain().unwrap();
        assert_eq!(verified.active_pubkey, verified.validator_pubkey);
        assert!(verified.delegate_pubkey.is_none());
    }

    #[test]
    fn auth_request_delegated_verifies() {
        let validator_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let delegate_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let cert_payload = DelegationPayload {
            validator_pubkey: PubkeyBytes::from(validator_key.verifying_key()),
            delegate_pubkey: PubkeyBytes::from(delegate_key.verifying_key()),
            not_before_ms: 1,
            not_after_ms: 2,
            scope: None,
            nonce: [1u8; 16],
        };
        let cert = DelegationCert::sign(&validator_key, cert_payload).unwrap();

        let payload = AuthRequestPayload {
            validator_pubkey: PubkeyBytes::from(validator_key.verifying_key()),
            delegate_pubkey: Some(PubkeyBytes::from(delegate_key.verifying_key())),
            delegation_cert: Some(cert),
            timestamp_ms: 1,
            nonce: [7u8; 16],
        };
        let req = AuthRequest::sign(payload, &delegate_key).unwrap();
        let verified = req.verify_chain().unwrap();
        assert_ne!(verified.active_pubkey, verified.validator_pubkey);
        assert_eq!(
            verified.active_pubkey,
            PubkeyBytes::from(delegate_key.verifying_key())
        );
        assert_eq!(
            verified.delegate_pubkey,
            Some(PubkeyBytes::from(delegate_key.verifying_key()))
        );
    }

    #[test]
    fn pop_announce_sign_and_verify_works() {
        let pop_key = SigningKey::from_bytes(&[7u8; 32]);
        let announce = PopAnnounce {
            pop_id: "pop-1".to_string(),
            public_addr: "127.0.0.1:4444".parse().unwrap(),
            now_ms: 123,
            capabilities: Default::default(),
            pop_pubkey: None,
            nonce: None,
            signature: None,
        };

        let signed = announce.sign(&pop_key).unwrap();
        assert_eq!(
            signed.verify_signature().unwrap(),
            PubkeyBytes::from(pop_key.verifying_key())
        );

        let mut tampered = signed.clone();
        tampered.pop_id = "pop-2".to_string();
        assert!(matches!(
            tampered.verify_signature(),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn pop_announce_signature_covers_capabilities() {
        let pop_key = SigningKey::from_bytes(&[7u8; 32]);
        let announce = PopAnnounce {
            pop_id: "pop-1".to_string(),
            public_addr: "127.0.0.1:4444".parse().unwrap(),
            now_ms: 123,
            capabilities: PopCapabilities { tx_relay: true },
            pop_pubkey: None,
            nonce: None,
            signature: None,
        };

        let signed = announce.sign(&pop_key).unwrap();
        signed.verify_signature().unwrap();

        let mut tampered = signed.clone();
        tampered.capabilities.tx_relay = false;
        assert!(matches!(
            tampered.verify_signature(),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn authorize_pop_session_sign_and_verify_works() {
        let pop_key = SigningKey::from_bytes(&[7u8; 32]);
        let req = AuthorizePopSession {
            pop_id: "pop-1".to_string(),
            validator_pubkey: PubkeyBytes([1u8; 32]),
            active_pubkey: PubkeyBytes([1u8; 32]),
            delegate_pubkey: None,
            timestamp_ms: 123,
            nonce: [9u8; 16],
            pop_pubkey: None,
            signature: None,
        };

        let signed = req.sign(&pop_key).unwrap();
        assert_eq!(
            signed.verify_signature().unwrap(),
            PubkeyBytes::from(pop_key.verifying_key())
        );

        let mut tampered = signed.clone();
        tampered.timestamp_ms = 124;
        assert!(matches!(
            tampered.verify_signature(),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn builder_validator_session_announce_sign_and_verify_works() {
        let pop_key = SigningKey::from_bytes(&[7u8; 32]);
        let announce = BuilderValidatorSessionAnnounce {
            pop_id: "pop-1".to_string(),
            validator_identity: PubkeyBytes([2u8; 32]),
            now_ms: 123,
            pop_pubkey: None,
            nonce: None,
            signature: None,
            validator_proof: None,
        };

        let signed = announce.sign(&pop_key).unwrap();
        assert_eq!(
            signed.verify_signature().unwrap(),
            PubkeyBytes::from(pop_key.verifying_key())
        );

        let mut tampered = signed.clone();
        tampered.validator_identity = PubkeyBytes([3u8; 32]);
        assert!(matches!(
            tampered.verify_signature(),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn fair_seq_handoff_sign_verify_roundtrip() {
        let pop_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let leader_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let receipt_payload = FairBatchReceiptCommitPayload {
            origin_pop_id: "pop-1".to_string(),
            flow_id: 42,
            batch_id: 7,
            order_start: 100,
            target_slot: None,
            tx_count: 3,
            tx_merkle_root: [1u8; 32],
            leader_pubkey: PubkeyBytes::from(leader_key.verifying_key()),
            leader_time_ms: 123,
        };
        let receipt_commit = FairBatchReceiptCommit::sign(receipt_payload, &leader_key).unwrap();
        receipt_commit.verify().unwrap();

        let payload = FairSeqHandoffPayload {
            origin_pop_id: "pop-1".to_string(),
            flow_id: 42,
            next_tx_seq: 103,
            created_at_ms: 456,
            last_receipt_commit: Some(receipt_commit),
        };
        let handoff = FairSeqHandoff::sign(payload, &pop_key).unwrap();

        handoff
            .verify(PubkeyBytes::from(pop_key.verifying_key()))
            .unwrap();

        let mut tampered = handoff.clone();
        tampered.payload.next_tx_seq = 999;
        assert!(tampered
            .verify(PubkeyBytes::from(pop_key.verifying_key()))
            .is_err());
    }

    #[test]
    fn fair_batch_reject_sign_verify_roundtrip() {
        let leader_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let payload = FairBatchRejectPayload {
            origin_pop_id: "pop-1".to_string(),
            flow_id: 42,
            batch_id: 7,
            order_start: 100,
            target_slot: Some(123),
            reason: FairBatchRejectReason::InvalidWireTx,
            leader_pubkey: PubkeyBytes::from(leader_key.verifying_key()),
            leader_time_ms: 456,
        };
        let reject = FairBatchReject::sign(payload, &leader_key).unwrap();
        reject.verify().unwrap();

        let mut tampered = reject.clone();
        tampered.payload.batch_id = 8;
        assert!(tampered.verify().is_err());
    }
}
