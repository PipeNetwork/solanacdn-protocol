use std::net::SocketAddr;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{CryptoError, DelegationCert, PubkeyBytes, SignatureBytes};

pub const PROTOCOL_VERSION: u16 = 3;

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

/// A POP-produced micro-batch of transactions intended to be ordered fairly by the leader.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatch {
    /// POP that produced this batch.
    pub origin_pop_id: String,
    /// POP-local unique identifier for this batch.
    pub batch_id: u128,
    /// POP wall-clock timestamp when the batch was created (ms since Unix epoch).
    pub created_at_ms: u64,
    /// Intended micro-batch window (ms).
    pub batch_ms: u16,
    /// Optional target slot hint (best-effort).
    #[serde(default)]
    pub target_slot: Option<u64>,
    /// Ordered transactions.
    pub txs: Vec<FairTx>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FairBatchCommitPayload {
    /// POP that produced the original `FairBatch`.
    pub origin_pop_id: String,
    /// Batch ID being committed.
    pub batch_id: u128,
    /// Leader-assigned global ordering index of `tx_sigs[0]` (inclusive).
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
    /// Batch ID being committed.
    pub batch_id: u128,
    /// Leader-assigned global ordering index of the first tx in the batch (inclusive).
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
    /// Batch ID being committed.
    pub batch_id: u128,
    /// Global ordering index of this transaction.
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

impl AuthRequest {
    pub fn sign(payload: AuthRequestPayload, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        let bytes = postcard::to_stdvec(&payload)?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            payload,
            signature: SignatureBytes::from(signature),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthOk {
    pub pop_id: String,
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
    RegisterUdpPorts { shreds_port: u16, votes_port: u16 },
    /// Advertise the validator's shred ingress ports for direct POP→validator UDP injection.
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
    /// Per-session capabilities advertised by the agent/validator.
    Capabilities(AgentCapabilities),
    /// Subscribe to leader-signed fair ordering commits (used for slashing/auditing).
    SubscribeFairCommits,
    /// Stop receiving leader-signed fair ordering commits.
    UnsubscribeFairCommits,
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
    DirectShredsProbe { pop_now_ms: u64 },
    PushVoteDatagram(VoteDatagram),
    /// Relay a transaction to the validator's TPU for block production.
    RelayTransaction(RelayTransaction),
    /// POP-produced fair-ordered micro-batch (leader signs a commit/receipt).
    FairBatch(FairBatch),
    /// Leader-signed commit/receipt for a previously received `FairBatch`.
    FairBatchCommit(FairBatchCommit),
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
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PopCapabilities {
    /// POP accepts raw Solana transactions over `tx_relay.listen_udp` and can forward/inject them.
    #[serde(default)]
    pub tx_relay: bool,
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
pub struct PopList {
    pub pops: Vec<PopInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlRequest {
    /// Placeholder to preserve variant indices with the full control protocol.
    AnnouncePop(()),
    ListPops,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ControlResponse {
    Ok,
    PopList(PopList),
    Error(ControlError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_nonce_16;

    #[test]
    fn auth_request_sign_roundtrip() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let payload = AuthRequestPayload {
            validator_pubkey: PubkeyBytes::from(key.verifying_key()),
            delegate_pubkey: None,
            delegation_cert: None,
            timestamp_ms: 1,
            nonce: random_nonce_16(),
        };
        let req = AuthRequest::sign(payload, &key).unwrap();
        let bytes = postcard::to_stdvec(&req).unwrap();
        let decoded: AuthRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.payload.timestamp_ms, 1);
    }
}
