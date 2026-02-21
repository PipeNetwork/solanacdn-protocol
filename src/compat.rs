//! Compatibility helpers between protocol versions.
//!
//! The wire format for `postcard`-encoded structs is not self-describing, so schema evolution is
//! not automatically backwards compatible. When supporting multiple envelope versions concurrently,
//! callers must decode into the matching versioned message types and convert explicitly.

use crate::{messages, messages_v4};

pub fn pop_to_agent_v5_from_v4(msg: messages_v4::PopToAgent) -> messages::PopToAgent {
    match msg {
        messages_v4::PopToAgent::AuthOk(v) => messages::PopToAgent::AuthOk(auth_ok_v5_from_v4(v)),
        messages_v4::PopToAgent::AuthError(v) => {
            messages::PopToAgent::AuthError(messages::AuthError {
                code: v.code,
                message: v.message,
            })
        }
        messages_v4::PopToAgent::HeartbeatAck(v) => {
            messages::PopToAgent::HeartbeatAck(pop_heartbeat_ack_v5_from_v4(v))
        }
        messages_v4::PopToAgent::PushShredBatch(v) => {
            messages::PopToAgent::PushShredBatch(shred_batch_v5_from_v4(v))
        }
        messages_v4::PopToAgent::PushShredFecChunk(v) => {
            messages::PopToAgent::PushShredFecChunk(udp_fec_chunk_v5_from_v4(v))
        }
        messages_v4::PopToAgent::DirectShredsProbe { pop_now_ms } => {
            messages::PopToAgent::DirectShredsProbe { pop_now_ms }
        }
        messages_v4::PopToAgent::PushVoteDatagram(v) => {
            messages::PopToAgent::PushVoteDatagram(vote_datagram_v5_from_v4(v))
        }
        messages_v4::PopToAgent::RelayTransaction(v) => {
            messages::PopToAgent::RelayTransaction(relay_transaction_v5_from_v4(v))
        }
        messages_v4::PopToAgent::FairBatch(v) => {
            messages::PopToAgent::FairBatch(fair_batch_v5_from_v4(v))
        }
        messages_v4::PopToAgent::FairSeqCancel(v) => {
            messages::PopToAgent::FairSeqCancel(fair_seq_cancel_v5_from_v4(v))
        }
        messages_v4::PopToAgent::FairBatchCommit(v) => {
            messages::PopToAgent::FairBatchCommit(fair_batch_commit_v5_from_v4(v))
        }
    }
}

pub fn agent_to_pop_v4_from_v5(msg: messages::AgentToPop) -> Option<messages_v4::AgentToPop> {
    match msg {
        messages::AgentToPop::Auth(v) => Some(messages_v4::AgentToPop::Auth(auth_request_v4_from_v5(
            v,
        ))),
        messages::AgentToPop::Heartbeat(v) => Some(messages_v4::AgentToPop::Heartbeat(
            heartbeat_v4_from_v5(v),
        )),
        messages::AgentToPop::RegisterUdpPorts {
            shreds_port,
            votes_port,
        } => Some(messages_v4::AgentToPop::RegisterUdpPorts {
            shreds_port,
            votes_port,
        }),
        messages::AgentToPop::RegisterValidatorPorts {
            tvu_port,
            gossip_port,
            direct_shreds,
        } => Some(messages_v4::AgentToPop::RegisterValidatorPorts {
            tvu_port,
            gossip_port,
            direct_shreds,
        }),
        messages::AgentToPop::PublishShredBatch(v) => Some(messages_v4::AgentToPop::PublishShredBatch(
            shred_batch_v4_from_v5(v),
        )),
        messages::AgentToPop::PublishShredFecChunk(v) => Some(
            messages_v4::AgentToPop::PublishShredFecChunk(udp_fec_chunk_v4_from_v5(v)),
        ),
        messages::AgentToPop::PublishVoteDatagram(v) => Some(messages_v4::AgentToPop::PublishVoteDatagram(
            vote_datagram_v4_from_v5(v),
        )),
        messages::AgentToPop::SubscribeShreds => Some(messages_v4::AgentToPop::SubscribeShreds),
        messages::AgentToPop::UnsubscribeShreds => Some(messages_v4::AgentToPop::UnsubscribeShreds),
        messages::AgentToPop::StreamHello(v) => Some(messages_v4::AgentToPop::StreamHello(
            stream_kind_v4_from_v5(v),
        )),
        messages::AgentToPop::LeaderSchedule(v) => Some(messages_v4::AgentToPop::LeaderSchedule(
            leader_schedule_report_v4_from_v5(v),
        )),
        messages::AgentToPop::AuthWithSessionToken(v) => Some(
            messages_v4::AgentToPop::AuthWithSessionToken(auth_with_session_token_v4_from_v5(v)),
        ),
        messages::AgentToPop::AuthRefresh(v) => Some(messages_v4::AgentToPop::AuthRefresh(
            auth_refresh_v4_from_v5(v),
        )),
        messages::AgentToPop::FairBatchCommit(v) => Some(messages_v4::AgentToPop::FairBatchCommit(
            fair_batch_commit_v4_from_v5(v),
        )),
        messages::AgentToPop::Capabilities(v) => Some(messages_v4::AgentToPop::Capabilities(
            agent_capabilities_v4_from_v5(v),
        )),
        messages::AgentToPop::SubscribeFairCommits => Some(messages_v4::AgentToPop::SubscribeFairCommits),
        messages::AgentToPop::UnsubscribeFairCommits => {
            Some(messages_v4::AgentToPop::UnsubscribeFairCommits)
        }
        // v7-only
        messages::AgentToPop::FairBatchAck(_)
        | messages::AgentToPop::SubscribeFairAcks
        | messages::AgentToPop::UnsubscribeFairAcks => None,
        // v5-only
        messages::AgentToPop::FairSeqResyncRequest(_v) => None,
        messages::AgentToPop::SubscribeFairWitnesses | messages::AgentToPop::UnsubscribeFairWitnesses => {
            None
        }
        // POP-only extensions (not supported in v4)
        messages::AgentToPop::McpDaRequest(_)
        | messages::AgentToPop::McpDaAttest(_)
        | messages::AgentToPop::SubscribeMcpDa
        | messages::AgentToPop::UnsubscribeMcpDa => None,
    }
}

pub fn agent_to_pop_v5_from_v4(msg: messages_v4::AgentToPop) -> messages::AgentToPop {
    match msg {
        messages_v4::AgentToPop::Auth(v) => messages::AgentToPop::Auth(auth_request_v5_from_v4(v)),
        messages_v4::AgentToPop::Heartbeat(v) => {
            messages::AgentToPop::Heartbeat(heartbeat_v5_from_v4(v))
        }
        messages_v4::AgentToPop::RegisterUdpPorts {
            shreds_port,
            votes_port,
        } => messages::AgentToPop::RegisterUdpPorts {
            shreds_port,
            votes_port,
        },
        messages_v4::AgentToPop::RegisterValidatorPorts {
            tvu_port,
            gossip_port,
            direct_shreds,
        } => messages::AgentToPop::RegisterValidatorPorts {
            tvu_port,
            gossip_port,
            direct_shreds,
        },
        messages_v4::AgentToPop::PublishShredBatch(v) => {
            messages::AgentToPop::PublishShredBatch(shred_batch_v5_from_v4(v))
        }
        messages_v4::AgentToPop::PublishShredFecChunk(v) => {
            messages::AgentToPop::PublishShredFecChunk(udp_fec_chunk_v5_from_v4(v))
        }
        messages_v4::AgentToPop::PublishVoteDatagram(v) => {
            messages::AgentToPop::PublishVoteDatagram(vote_datagram_v5_from_v4(v))
        }
        messages_v4::AgentToPop::SubscribeShreds => messages::AgentToPop::SubscribeShreds,
        messages_v4::AgentToPop::UnsubscribeShreds => messages::AgentToPop::UnsubscribeShreds,
        messages_v4::AgentToPop::StreamHello(v) => {
            messages::AgentToPop::StreamHello(stream_kind_v5_from_v4(v))
        }
        messages_v4::AgentToPop::LeaderSchedule(v) => {
            messages::AgentToPop::LeaderSchedule(leader_schedule_report_v5_from_v4(v))
        }
        messages_v4::AgentToPop::AuthWithSessionToken(v) => {
            messages::AgentToPop::AuthWithSessionToken(auth_with_session_token_v5_from_v4(v))
        }
        messages_v4::AgentToPop::AuthRefresh(v) => {
            messages::AgentToPop::AuthRefresh(auth_refresh_v5_from_v4(v))
        }
        messages_v4::AgentToPop::FairBatchCommit(v) => {
            messages::AgentToPop::FairBatchCommit(fair_batch_commit_v5_from_v4(v))
        }
        messages_v4::AgentToPop::Capabilities(v) => {
            messages::AgentToPop::Capabilities(agent_capabilities_v5_from_v4(v))
        }
        messages_v4::AgentToPop::SubscribeFairCommits => messages::AgentToPop::SubscribeFairCommits,
        messages_v4::AgentToPop::UnsubscribeFairCommits => messages::AgentToPop::UnsubscribeFairCommits,
    }
}

pub fn pop_to_agent_v4_from_v5(msg: messages::PopToAgent) -> Option<messages_v4::PopToAgent> {
    match msg {
        messages::PopToAgent::AuthOk(v) => Some(messages_v4::PopToAgent::AuthOk(auth_ok_v4_from_v5(
            v,
        ))),
        messages::PopToAgent::AuthError(v) => Some(messages_v4::PopToAgent::AuthError(
            messages_v4::AuthError {
                code: v.code,
                message: v.message,
            },
        )),
        messages::PopToAgent::HeartbeatAck(v) => Some(messages_v4::PopToAgent::HeartbeatAck(
            pop_heartbeat_ack_v4_from_v5(v),
        )),
        messages::PopToAgent::PushShredBatch(v) => Some(messages_v4::PopToAgent::PushShredBatch(
            shred_batch_v4_from_v5(v),
        )),
        messages::PopToAgent::PushShredFecChunk(v) => Some(messages_v4::PopToAgent::PushShredFecChunk(
            udp_fec_chunk_v4_from_v5(v),
        )),
        messages::PopToAgent::DirectShredsProbe { pop_now_ms } => {
            Some(messages_v4::PopToAgent::DirectShredsProbe { pop_now_ms })
        }
        messages::PopToAgent::PushVoteDatagram(v) => Some(messages_v4::PopToAgent::PushVoteDatagram(
            vote_datagram_v4_from_v5(v),
        )),
        messages::PopToAgent::RelayTransaction(v) => Some(messages_v4::PopToAgent::RelayTransaction(
            relay_transaction_v4_from_v5(v),
        )),
        messages::PopToAgent::FairBatch(v) => fair_batch_v4_from_v5(v).map(messages_v4::PopToAgent::FairBatch),
        messages::PopToAgent::FairBatchWitness(_v) => None,
        messages::PopToAgent::FairSeqCancel(v) => fair_seq_cancel_v4_from_v5(v).map(messages_v4::PopToAgent::FairSeqCancel),
        messages::PopToAgent::FairBatchCommit(v) => Some(messages_v4::PopToAgent::FairBatchCommit(
            fair_batch_commit_v4_from_v5(v),
        )),
        messages::PopToAgent::FairBatchAck(_) => None,
        // v5-only
        messages::PopToAgent::FairSeqHandoff(_v) => None,
        // POP-only extensions (not supported in v4)
        messages::PopToAgent::McpDaRequest(_)
        | messages::PopToAgent::McpDaAttest(_) => None,
    }
}

fn stream_kind_v4_from_v5(v: messages::StreamKind) -> messages_v4::StreamKind {
    match v {
        messages::StreamKind::Control => messages_v4::StreamKind::Control,
        messages::StreamKind::Shreds => messages_v4::StreamKind::Shreds,
        messages::StreamKind::Votes => messages_v4::StreamKind::Votes,
    }
}

fn stream_kind_v5_from_v4(v: messages_v4::StreamKind) -> messages::StreamKind {
    match v {
        messages_v4::StreamKind::Control => messages::StreamKind::Control,
        messages_v4::StreamKind::Shreds => messages::StreamKind::Shreds,
        messages_v4::StreamKind::Votes => messages::StreamKind::Votes,
    }
}

fn shred_id_v5_from_v4(v: messages_v4::ShredId) -> messages::ShredId {
    messages::ShredId {
        slot: v.slot,
        index: v.index,
    }
}

fn shred_id_v4_from_v5(v: messages::ShredId) -> messages_v4::ShredId {
    messages_v4::ShredId {
        slot: v.slot,
        index: v.index,
    }
}

fn shred_kind_v5_from_v4(v: messages_v4::ShredKind) -> messages::ShredKind {
    match v {
        messages_v4::ShredKind::Tvu => messages::ShredKind::Tvu,
        messages_v4::ShredKind::Gossip => messages::ShredKind::Gossip,
    }
}

fn shred_kind_v4_from_v5(v: messages::ShredKind) -> messages_v4::ShredKind {
    match v {
        messages::ShredKind::Tvu => messages_v4::ShredKind::Tvu,
        messages::ShredKind::Gossip => messages_v4::ShredKind::Gossip,
    }
}

fn shred_v5_from_v4(v: messages_v4::Shred) -> messages::Shred {
    messages::Shred {
        id: shred_id_v5_from_v4(v.id),
        kind: shred_kind_v5_from_v4(v.kind),
        payload: v.payload,
    }
}

fn shred_v4_from_v5(v: messages::Shred) -> messages_v4::Shred {
    messages_v4::Shred {
        id: shred_id_v4_from_v5(v.id),
        kind: shred_kind_v4_from_v5(v.kind),
        payload: v.payload,
    }
}

fn shred_batch_v5_from_v4(v: messages_v4::ShredBatch) -> messages::ShredBatch {
    messages::ShredBatch {
        batch_id: v.batch_id,
        created_at_ms: v.created_at_ms,
        shreds: v.shreds.into_iter().map(shred_v5_from_v4).collect(),
    }
}

fn shred_batch_v4_from_v5(v: messages::ShredBatch) -> messages_v4::ShredBatch {
    messages_v4::ShredBatch {
        batch_id: v.batch_id,
        created_at_ms: v.created_at_ms,
        shreds: v.shreds.into_iter().map(shred_v4_from_v5).collect(),
    }
}

fn vote_datagram_v5_from_v4(v: messages_v4::VoteDatagram) -> messages::VoteDatagram {
    messages::VoteDatagram {
        flow_id: v.flow_id,
        src: v.src,
        dst: v.dst,
        payload: v.payload,
    }
}

fn vote_datagram_v4_from_v5(v: messages::VoteDatagram) -> messages_v4::VoteDatagram {
    messages_v4::VoteDatagram {
        flow_id: v.flow_id,
        src: v.src,
        dst: v.dst,
        payload: v.payload,
    }
}

fn udp_fec_chunk_v5_from_v4(v: messages_v4::UdpFecChunk) -> messages::UdpFecChunk {
    messages::UdpFecChunk {
        object_id: v.object_id,
        oti: v.oti,
        packet: v.packet,
    }
}

fn udp_fec_chunk_v4_from_v5(v: messages::UdpFecChunk) -> messages_v4::UdpFecChunk {
    messages_v4::UdpFecChunk {
        object_id: v.object_id,
        oti: v.oti,
        packet: v.packet,
    }
}

fn heartbeat_v4_from_v5(v: messages::Heartbeat) -> messages_v4::Heartbeat {
    messages_v4::Heartbeat {
        now_ms: v.now_ms,
        stats: messages_v4::HeartbeatStats {
            published_shred_batches: v.stats.published_shred_batches,
            pushed_shred_batches: v.stats.pushed_shred_batches,
            tunneled_vote_packets: v.stats.tunneled_vote_packets,
            rx_vote_packets: v.stats.rx_vote_packets,
        },
    }
}

fn heartbeat_v5_from_v4(v: messages_v4::Heartbeat) -> messages::Heartbeat {
    messages::Heartbeat {
        now_ms: v.now_ms,
        stats: messages::HeartbeatStats {
            published_shred_batches: v.stats.published_shred_batches,
            pushed_shred_batches: v.stats.pushed_shred_batches,
            tunneled_vote_packets: v.stats.tunneled_vote_packets,
            rx_vote_packets: v.stats.rx_vote_packets,
        },
    }
}

fn auth_request_v4_from_v5(v: messages::AuthRequest) -> messages_v4::AuthRequest {
    messages_v4::AuthRequest {
        payload: messages_v4::AuthRequestPayload {
            validator_pubkey: v.payload.validator_pubkey,
            delegate_pubkey: v.payload.delegate_pubkey,
            delegation_cert: v.payload.delegation_cert,
            timestamp_ms: v.payload.timestamp_ms,
            nonce: v.payload.nonce,
        },
        signature: v.signature,
    }
}

fn auth_request_v5_from_v4(v: messages_v4::AuthRequest) -> messages::AuthRequest {
    messages::AuthRequest {
        payload: messages::AuthRequestPayload {
            validator_pubkey: v.payload.validator_pubkey,
            delegate_pubkey: v.payload.delegate_pubkey,
            delegation_cert: v.payload.delegation_cert,
            timestamp_ms: v.payload.timestamp_ms,
            nonce: v.payload.nonce,
        },
        signature: v.signature,
    }
}

fn auth_ok_v5_from_v4(v: messages_v4::AuthOk) -> messages::AuthOk {
    messages::AuthOk {
        pop_id: v.pop_id,
        pop_pubkey: v.pop_pubkey,
        server_time_ms: v.server_time_ms,
        udp_token: v.udp_token,
        udp_shreds_port: v.udp_shreds_port,
        udp_votes_port: v.udp_votes_port,
    }
}

fn auth_ok_v4_from_v5(v: messages::AuthOk) -> messages_v4::AuthOk {
    messages_v4::AuthOk {
        pop_id: v.pop_id,
        pop_pubkey: v.pop_pubkey,
        server_time_ms: v.server_time_ms,
        udp_token: v.udp_token,
        udp_shreds_port: v.udp_shreds_port,
        udp_votes_port: v.udp_votes_port,
    }
}

fn pop_heartbeat_ack_v5_from_v4(v: messages_v4::PopHeartbeatAck) -> messages::PopHeartbeatAck {
    messages::PopHeartbeatAck {
        pop_now_ms: v.pop_now_ms,
        stats: messages::PopStatsSnapshot {
            rx_shred_batches: v.stats.rx_shred_batches,
            rx_shred_batches_deduped: v.stats.rx_shred_batches_deduped,
            tx_shred_batches: v.stats.tx_shred_batches,
            tx_shred_batches_dropped: v.stats.tx_shred_batches_dropped,
            tx_shred_payloads_direct: v.stats.tx_shred_payloads_direct,
            tx_shred_payloads_direct_dropped: v.stats.tx_shred_payloads_direct_dropped,
            mesh_rx_shred_batches: v.stats.mesh_rx_shred_batches,
            mesh_rx_shred_batches_deduped: v.stats.mesh_rx_shred_batches_deduped,
            mesh_tx_shred_batches: v.stats.mesh_tx_shred_batches,
            mesh_tx_shred_batches_dropped: v.stats.mesh_tx_shred_batches_dropped,
            mesh_tx_forward_packets: v.stats.mesh_tx_forward_packets,
            mesh_tx_forward_direct: v.stats.mesh_tx_forward_direct,
            mesh_tx_forward_broadcast: v.stats.mesh_tx_forward_broadcast,
            mesh_tx_forward_dropped: v.stats.mesh_tx_forward_dropped,
            rx_vote_datagrams: v.stats.rx_vote_datagrams,
            tx_vote_datagrams: v.stats.tx_vote_datagrams,
        },
        direct_shreds: v.direct_shreds.map(|s| messages::DirectShredsStats {
            tx_payloads: s.tx_payloads,
            tx_payloads_dropped: s.tx_payloads_dropped,
        }),
    }
}

fn pop_heartbeat_ack_v4_from_v5(v: messages::PopHeartbeatAck) -> messages_v4::PopHeartbeatAck {
    messages_v4::PopHeartbeatAck {
        pop_now_ms: v.pop_now_ms,
        stats: messages_v4::PopStatsSnapshot {
            rx_shred_batches: v.stats.rx_shred_batches,
            rx_shred_batches_deduped: v.stats.rx_shred_batches_deduped,
            tx_shred_batches: v.stats.tx_shred_batches,
            tx_shred_batches_dropped: v.stats.tx_shred_batches_dropped,
            tx_shred_payloads_direct: v.stats.tx_shred_payloads_direct,
            tx_shred_payloads_direct_dropped: v.stats.tx_shred_payloads_direct_dropped,
            mesh_rx_shred_batches: v.stats.mesh_rx_shred_batches,
            mesh_rx_shred_batches_deduped: v.stats.mesh_rx_shred_batches_deduped,
            mesh_tx_shred_batches: v.stats.mesh_tx_shred_batches,
            mesh_tx_shred_batches_dropped: v.stats.mesh_tx_shred_batches_dropped,
            mesh_tx_forward_packets: v.stats.mesh_tx_forward_packets,
            mesh_tx_forward_direct: v.stats.mesh_tx_forward_direct,
            mesh_tx_forward_broadcast: v.stats.mesh_tx_forward_broadcast,
            mesh_tx_forward_dropped: v.stats.mesh_tx_forward_dropped,
            rx_vote_datagrams: v.stats.rx_vote_datagrams,
            tx_vote_datagrams: v.stats.tx_vote_datagrams,
        },
        direct_shreds: v.direct_shreds.map(|s| messages_v4::DirectShredsStats {
            tx_payloads: s.tx_payloads,
            tx_payloads_dropped: s.tx_payloads_dropped,
        }),
    }
}

fn relay_transaction_v5_from_v4(v: messages_v4::RelayTransaction) -> messages::RelayTransaction {
    messages::RelayTransaction {
        tx_id: v.tx_id,
        payload: v.payload,
        target_slot: v.target_slot,
    }
}

fn relay_transaction_v4_from_v5(v: messages::RelayTransaction) -> messages_v4::RelayTransaction {
    messages_v4::RelayTransaction {
        tx_id: v.tx_id,
        payload: v.payload,
        target_slot: v.target_slot,
    }
}

fn fair_batch_attestation_v5_from_v4(
    v: messages_v4::FairBatchAttestation,
) -> messages::FairBatchAttestation {
    messages::FairBatchAttestation {
        payload: messages::FairBatchAttestationPayload {
            origin_pop_id: v.payload.origin_pop_id,
            flow_id: 0,
            batch_id: v.payload.batch_id,
            tx_seq_start: v.payload.tx_seq_start,
            tx_count: v.payload.tx_count,
            tx_merkle_root: v.payload.tx_merkle_root,
            created_at_ms: v.payload.created_at_ms,
            batch_ms: v.payload.batch_ms,
            target_slot: v.payload.target_slot,
        },
        signature: v.signature,
    }
}

fn fair_batch_attestation_v4_from_v5(
    v: messages::FairBatchAttestation,
) -> Option<messages_v4::FairBatchAttestation> {
    if v.payload.flow_id != 0 {
        return None;
    }
    Some(messages_v4::FairBatchAttestation {
        payload: messages_v4::FairBatchAttestationPayload {
            origin_pop_id: v.payload.origin_pop_id,
            batch_id: v.payload.batch_id,
            tx_seq_start: v.payload.tx_seq_start,
            tx_count: v.payload.tx_count,
            tx_merkle_root: v.payload.tx_merkle_root,
            created_at_ms: v.payload.created_at_ms,
            batch_ms: v.payload.batch_ms,
            target_slot: v.payload.target_slot,
        },
        signature: v.signature,
    })
}

fn fair_tx_v5_from_v4(v: messages_v4::FairTx) -> messages::FairTx {
    messages::FairTx {
        sig: v.sig,
        payload: v.payload,
    }
}

fn fair_tx_v4_from_v5(v: messages::FairTx) -> messages_v4::FairTx {
    messages_v4::FairTx {
        sig: v.sig,
        payload: v.payload,
    }
}

fn fair_batch_v5_from_v4(v: messages_v4::FairBatch) -> messages::FairBatch {
    messages::FairBatch {
        origin_pop_id: v.origin_pop_id,
        flow_id: 0,
        batch_id: v.batch_id,
        tx_seq_start: v.tx_seq_start,
        created_at_ms: v.created_at_ms,
        batch_ms: v.batch_ms,
        target_slot: v.target_slot,
        attestation: fair_batch_attestation_v5_from_v4(v.attestation),
        txs: v.txs.into_iter().map(fair_tx_v5_from_v4).collect(),
    }
}

fn fair_batch_v4_from_v5(v: messages::FairBatch) -> Option<messages_v4::FairBatch> {
    if v.flow_id != 0 {
        return None;
    }
    Some(messages_v4::FairBatch {
        origin_pop_id: v.origin_pop_id,
        batch_id: v.batch_id,
        tx_seq_start: v.tx_seq_start,
        created_at_ms: v.created_at_ms,
        batch_ms: v.batch_ms,
        target_slot: v.target_slot,
        attestation: fair_batch_attestation_v4_from_v5(v.attestation)?,
        txs: v.txs.into_iter().map(fair_tx_v4_from_v5).collect(),
    })
}

fn fair_seq_cancel_v5_from_v4(v: messages_v4::FairSeqCancel) -> messages::FairSeqCancel {
    messages::FairSeqCancel {
        payload: messages::FairSeqCancelPayload {
            origin_pop_id: v.payload.origin_pop_id,
            flow_id: 0,
            tx_seq: v.payload.tx_seq,
            reason: match v.payload.reason {
                messages_v4::FairSeqCancelReason::Unknown => messages::FairSeqCancelReason::Unknown,
                messages_v4::FairSeqCancelReason::Expired => messages::FairSeqCancelReason::Expired,
                messages_v4::FairSeqCancelReason::Invalid => messages::FairSeqCancelReason::Invalid,
                messages_v4::FairSeqCancelReason::ClientCanceled => {
                    messages::FairSeqCancelReason::ClientCanceled
                }
                messages_v4::FairSeqCancelReason::Dropped => messages::FairSeqCancelReason::Dropped,
            },
            created_at_ms: v.payload.created_at_ms,
        },
        signature: v.signature,
    }
}

fn fair_seq_cancel_v4_from_v5(v: messages::FairSeqCancel) -> Option<messages_v4::FairSeqCancel> {
    if v.payload.flow_id != 0 {
        return None;
    }
    Some(messages_v4::FairSeqCancel {
        payload: messages_v4::FairSeqCancelPayload {
            origin_pop_id: v.payload.origin_pop_id,
            tx_seq: v.payload.tx_seq,
            reason: match v.payload.reason {
                messages::FairSeqCancelReason::Unknown => messages_v4::FairSeqCancelReason::Unknown,
                messages::FairSeqCancelReason::Expired => messages_v4::FairSeqCancelReason::Expired,
                messages::FairSeqCancelReason::Invalid => messages_v4::FairSeqCancelReason::Invalid,
                messages::FairSeqCancelReason::ClientCanceled => {
                    messages_v4::FairSeqCancelReason::ClientCanceled
                }
                messages::FairSeqCancelReason::Dropped => messages_v4::FairSeqCancelReason::Dropped,
            },
            created_at_ms: v.payload.created_at_ms,
        },
        signature: v.signature,
    })
}

fn fair_batch_receipt_commit_v5_from_v4(
    v: messages_v4::FairBatchReceiptCommit,
) -> messages::FairBatchReceiptCommit {
    messages::FairBatchReceiptCommit {
        payload: messages::FairBatchReceiptCommitPayload {
            origin_pop_id: v.payload.origin_pop_id,
            flow_id: 0,
            batch_id: v.payload.batch_id,
            order_start: v.payload.order_start,
            target_slot: v.payload.target_slot,
            tx_count: v.payload.tx_count,
            tx_merkle_root: v.payload.tx_merkle_root,
            leader_pubkey: v.payload.leader_pubkey,
            leader_time_ms: v.payload.leader_time_ms,
        },
        signature: v.signature,
    }
}

fn fair_batch_receipt_commit_v4_from_v5(
    v: messages::FairBatchReceiptCommit,
) -> Option<messages_v4::FairBatchReceiptCommit> {
    if v.payload.flow_id != 0 {
        return None;
    }
    Some(messages_v4::FairBatchReceiptCommit {
        payload: messages_v4::FairBatchReceiptCommitPayload {
            origin_pop_id: v.payload.origin_pop_id,
            batch_id: v.payload.batch_id,
            order_start: v.payload.order_start,
            target_slot: v.payload.target_slot,
            tx_count: v.payload.tx_count,
            tx_merkle_root: v.payload.tx_merkle_root,
            leader_pubkey: v.payload.leader_pubkey,
            leader_time_ms: v.payload.leader_time_ms,
        },
        signature: v.signature,
    })
}

fn fair_batch_commit_v5_from_v4(v: messages_v4::FairBatchCommit) -> messages::FairBatchCommit {
    messages::FairBatchCommit {
        payload: messages::FairBatchCommitPayload {
            origin_pop_id: v.payload.origin_pop_id,
            flow_id: 0,
            batch_id: v.payload.batch_id,
            order_start: v.payload.order_start,
            target_slot: v.payload.target_slot,
            tx_sigs: v.payload.tx_sigs,
            leader_pubkey: v.payload.leader_pubkey,
            leader_time_ms: v.payload.leader_time_ms,
        },
        signature: v.signature,
        receipt_commit: v
            .receipt_commit
            .map(fair_batch_receipt_commit_v5_from_v4),
    }
}

fn fair_batch_commit_v4_from_v5(v: messages::FairBatchCommit) -> messages_v4::FairBatchCommit {
    messages_v4::FairBatchCommit {
        payload: messages_v4::FairBatchCommitPayload {
            origin_pop_id: v.payload.origin_pop_id,
            batch_id: v.payload.batch_id,
            order_start: v.payload.order_start,
            target_slot: v.payload.target_slot,
            tx_sigs: v.payload.tx_sigs,
            leader_pubkey: v.payload.leader_pubkey,
            leader_time_ms: v.payload.leader_time_ms,
        },
        signature: v.signature,
        receipt_commit: v
            .receipt_commit
            .and_then(fair_batch_receipt_commit_v4_from_v5),
    }
}

fn agent_capabilities_v4_from_v5(v: messages::AgentCapabilities) -> messages_v4::AgentCapabilities {
    messages_v4::AgentCapabilities {
        tx_fair_ordering: v.tx_fair_ordering,
        tx_fair_fifo_per_origin: v.tx_fair_fifo_per_origin,
    }
}

fn agent_capabilities_v5_from_v4(v: messages_v4::AgentCapabilities) -> messages::AgentCapabilities {
    messages::AgentCapabilities {
        tx_fair_ordering: v.tx_fair_ordering,
        tx_fair_fifo_per_origin: v.tx_fair_fifo_per_origin,
        tx_fair_fifo_per_origin_flow: false,
        tx_fair_seq_handoff: false,
    }
}

fn leader_schedule_report_v4_from_v5(
    v: messages::LeaderScheduleReport,
) -> messages_v4::LeaderScheduleReport {
    messages_v4::LeaderScheduleReport {
        validator_identity: v.validator_identity,
        current_slot: v.current_slot,
        leader_slots: v.leader_slots,
        tpu_port: v.tpu_port,
        tpu_fwd_port: v.tpu_fwd_port,
    }
}

fn leader_schedule_report_v5_from_v4(
    v: messages_v4::LeaderScheduleReport,
) -> messages::LeaderScheduleReport {
    messages::LeaderScheduleReport {
        validator_identity: v.validator_identity,
        current_slot: v.current_slot,
        leader_slots: v.leader_slots,
        tpu_port: v.tpu_port,
        tpu_fwd_port: v.tpu_fwd_port,
    }
}

fn auth_with_session_token_v4_from_v5(
    v: messages::AuthWithSessionToken,
) -> messages_v4::AuthWithSessionToken {
    messages_v4::AuthWithSessionToken {
        auth: auth_request_v4_from_v5(v.auth),
        session_token: v.session_token,
    }
}

fn auth_with_session_token_v5_from_v4(
    v: messages_v4::AuthWithSessionToken,
) -> messages::AuthWithSessionToken {
    messages::AuthWithSessionToken {
        auth: auth_request_v5_from_v4(v.auth),
        session_token: v.session_token,
    }
}

fn auth_refresh_v4_from_v5(v: messages::AuthRefresh) -> messages_v4::AuthRefresh {
    messages_v4::AuthRefresh {
        session_token: v.session_token,
    }
}

fn auth_refresh_v5_from_v4(v: messages_v4::AuthRefresh) -> messages::AuthRefresh {
    messages::AuthRefresh {
        session_token: v.session_token,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SignatureBytes;

    #[test]
    fn v4_to_v5_pop_to_agent_fair_batch_maps_flow_id_zero() {
        let v4 = messages_v4::PopToAgent::FairBatch(messages_v4::FairBatch {
            origin_pop_id: "pop-1".to_string(),
            batch_id: 1,
            tx_seq_start: 2,
            created_at_ms: 3,
            batch_ms: 4,
            target_slot: None,
            attestation: messages_v4::FairBatchAttestation {
                payload: messages_v4::FairBatchAttestationPayload {
                    origin_pop_id: "pop-1".to_string(),
                    batch_id: 1,
                    tx_seq_start: 2,
                    tx_count: 0,
                    tx_merkle_root: [0u8; 32],
                    created_at_ms: 3,
                    batch_ms: 4,
                    target_slot: None,
                },
                signature: SignatureBytes([0u8; 64]),
            },
            txs: Vec::new(),
        });
        let v5 = pop_to_agent_v5_from_v4(v4);
        match v5 {
            messages::PopToAgent::FairBatch(b) => assert_eq!(b.flow_id, 0),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
