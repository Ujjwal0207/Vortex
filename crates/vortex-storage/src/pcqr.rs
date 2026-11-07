use std::collections::HashMap;
use std::path::Path;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use vortex_core::hash::HashDigest;
use vortex_core::{error::Result, VortexError};
use crate::partition::{PartitionLog, DEFAULT_MAX_SEGMENT_BYTES};

/// A cryptographic replication pulse emitted by the partition leader.
///
/// Contains the payload byte slice along with its Blake3 leaf digest,
/// monotonic leader epoch, commit timestamp, and the resulting MMR bagged root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MMRCommitPulse {
    pub partition_id: u32,
    pub leader_epoch: u32,
    pub offset: u64,
    pub mmr_root: HashDigest,
    pub blake3_hash: HashDigest,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

/// Acknowledgment sent from a follower node to the leader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationAck {
    pub replica_id: String,
    pub partition_id: u32,
    pub leader_epoch: u32,
    pub acked_offset: u64,
    pub acked_mmr_root: HashDigest,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Replication synchronization status of a replica node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaStatus {
    InSync,
    CatchingUp {
        lag: u64,
    },
    QuarantinedFork {
        divergent_offset: u64,
        expected_root: HashDigest,
        actual_root: HashDigest,
    },
}

/// State tracking for an individual replica in the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaState {
    pub replica_id: String,
    pub last_offset: u64,
    pub last_mmr_root: HashDigest,
    pub last_leader_epoch: u32,
    pub status: ReplicaStatus,
}

/// Manages quorum acknowledgment tracking ($Q = \lfloor N / 2 \rfloor + 1$) for partition commits.
pub struct QuorumCommitTracker {
    cluster_size: usize,
    quorum_size: usize,
    pulses: HashMap<u64, MMRCommitPulse>,
    /// offset -> (replica_id -> acknowledged mmr_root)
    acks: HashMap<u64, HashMap<String, HashDigest>>,
    highest_committed: Option<u64>,
}

impl QuorumCommitTracker {
    /// Creates a new quorum tracker for a cluster of size `cluster_size`.
    pub fn new(cluster_size: usize) -> Self {
        let cluster_size = cluster_size.max(1);
        let quorum_size = (cluster_size / 2) + 1;
        Self {
            cluster_size,
            quorum_size,
            pulses: HashMap::new(),
            acks: HashMap::new(),
            highest_committed: None,
        }
    }

    pub fn quorum_size(&self) -> usize {
        self.quorum_size
    }

    pub fn cluster_size(&self) -> usize {
        self.cluster_size
    }

    /// Registers a newly generated pulse from the leader.
    pub fn register_pulse(&mut self, pulse: MMRCommitPulse) {
        let offset = pulse.offset;
        self.pulses.insert(offset, pulse);
        self.acks.entry(offset).or_default();
    }

    /// Records an acknowledgment from a replica. Returns `Some(offset)` if this ack promoted
    /// the offset to quorum-committed status.
    pub fn record_ack(&mut self, ack: ReplicationAck) -> Result<Option<u64>> {
        if !ack.success {
            return Ok(None);
        }

        let pulse = match self.pulses.get(&ack.acked_offset) {
            Some(p) => p,
            None => {
                // Pulse not found or already purged
                return Ok(None);
            }
        };

        if pulse.mmr_root != ack.acked_mmr_root {
            return Err(VortexError::SecurityViolation {
                reason: format!(
                    "Zero-divergence violation: replica {} acknowledged offset {} with divergent root. Expected {:?}, got {:?}",
                    ack.replica_id, ack.acked_offset, pulse.mmr_root, ack.acked_mmr_root
                ),
            });
        }

        let replica_map = self.acks.entry(ack.acked_offset).or_default();
        replica_map.insert(ack.replica_id, ack.acked_mmr_root);

        // Count acks matching expected root
        let matching_acks = replica_map
            .values()
            .filter(|&root| *root == pulse.mmr_root)
            .count();

        if matching_acks >= self.quorum_size {
            let is_new_commit = match self.highest_committed {
                Some(prev) => ack.acked_offset > prev,
                None => true,
            };

            if is_new_commit {
                self.highest_committed = Some(ack.acked_offset);
                return Ok(Some(ack.acked_offset));
            }
        }

        Ok(None)
    }

    pub fn highest_committed_offset(&self) -> Option<u64> {
        self.highest_committed
    }

    pub fn is_quorum_committed(&self, offset: u64, expected_root: &HashDigest) -> bool {
        if let Some(replica_map) = self.acks.get(&offset) {
            let matching_acks = replica_map
                .values()
                .filter(|&root| *root == *expected_root)
                .count();
            matching_acks >= self.quorum_size
        } else {
            false
        }
    }
}

/// Enforces the Vortex Zero-Divergence invariant: history is NEVER truncated or rewritten.
#[derive(Debug, Default, Clone, Copy)]
pub struct ZeroDivergenceValidator;

impl ZeroDivergenceValidator {
    pub fn new() -> Self {
        Self
    }

    /// Validates that an append does not attempt to rewrite an already committed historical offset
    /// with a divergent MMR root.
    pub fn validate_append(
        &self,
        current_offset: u64,
        current_root: &HashDigest,
        incoming_offset: u64,
        incoming_root: &HashDigest,
    ) -> Result<()> {
        if incoming_offset <= current_offset && incoming_root != current_root {
            return Err(VortexError::SecurityViolation {
                reason: format!(
                    "Zero-divergence violation: incoming pulse at offset {} carries divergent MMR root. Expected {:?}, got {:?}. History truncation is forbidden. Node quarantined as corrupt fork.",
                    incoming_offset, current_root, incoming_root
                ),
            });
        }
        Ok(())
    }
}

/// Evaluates node eligibility during leader election failover without log truncation.
pub struct PcqrElectionValidator;

impl PcqrElectionValidator {
    /// A candidate is eligible to become leader if:
    /// 1. It is not quarantined as a corrupt fork.
    /// 2. Its leader epoch is >= the target election epoch.
    /// 3. Its committed log offset is >= the quorum watermark offset.
    pub fn is_candidate_eligible(
        candidate: &ReplicaState,
        min_epoch: u32,
        min_offset: u64,
    ) -> bool {
        if matches!(candidate.status, ReplicaStatus::QuarantinedFork { .. }) {
            return false;
        }

        if candidate.last_leader_epoch < min_epoch {
            return false;
        }

        candidate.last_offset >= min_offset
    }
}

/// Leader replicator coordinating local partition writes and pulse generation.
pub struct PcqrLeaderReplicator {
    node_id: String,
    partition: PartitionLog,
    tracker: QuorumCommitTracker,
}

impl PcqrLeaderReplicator {
    pub fn new<P: AsRef<Path>>(node_id: &str, dir: P, cluster_size: usize) -> Result<Self> {
        let partition = PartitionLog::open_or_create(dir.as_ref(), "pcqr_topic", 0, DEFAULT_MAX_SEGMENT_BYTES)?;
        let tracker = QuorumCommitTracker::new(cluster_size);
        Ok(Self {
            node_id: node_id.to_string(),
            partition,
            tracker,
        })
    }

    /// Appends a record to the leader's local partition and produces an `MMRCommitPulse`.
    pub fn replicate_record(
        &mut self,
        partition_id: u32,
        leader_epoch: u32,
        payload: &[u8],
    ) -> Result<MMRCommitPulse> {
        let record = self.partition.append(None, Bytes::copy_from_slice(payload))?;
        let blake3_hash = *blake3::hash(payload).as_bytes();
        let mmr_root = self.partition.active_mmr_root();

        let pulse = MMRCommitPulse {
            partition_id,
            leader_epoch,
            offset: record.offset,
            mmr_root,
            blake3_hash,
            timestamp: record.timestamp,
            payload: payload.to_vec(),
        };

        self.tracker.register_pulse(pulse.clone());

        // Self-ack as leader
        let self_ack = ReplicationAck {
            replica_id: self.node_id.clone(),
            partition_id,
            leader_epoch,
            acked_offset: record.offset,
            acked_mmr_root: mmr_root,
            success: true,
            error_message: None,
        };
        let _ = self.tracker.record_ack(self_ack);

        Ok(pulse)
    }

    /// Records an acknowledgment from a follower replica.
    pub fn record_replica_ack(&mut self, ack: ReplicationAck) -> Result<Option<u64>> {
        self.tracker.record_ack(ack)
    }

    pub fn committed_offset(&self) -> Option<u64> {
        self.tracker.highest_committed_offset()
    }
}

/// Follower node processing replication pulses from the leader.
pub struct PcqrFollowerNode {
    node_id: String,
    partition: PartitionLog,
    validator: ZeroDivergenceValidator,
    status: ReplicaStatus,
}

impl PcqrFollowerNode {
    pub fn new<P: AsRef<Path>>(node_id: &str, dir: P) -> Result<Self> {
        let partition = PartitionLog::open_or_create(dir.as_ref(), "pcqr_topic", 0, DEFAULT_MAX_SEGMENT_BYTES)?;
        Ok(Self {
            node_id: node_id.to_string(),
            partition,
            validator: ZeroDivergenceValidator::new(),
            status: ReplicaStatus::InSync,
        })
    }

    pub fn status(&self) -> &ReplicaStatus {
        &self.status
    }

    /// Processes an incoming pulse from the leader, verifying zero-divergence before appending.
    pub fn handle_pulse(&mut self, pulse: &MMRCommitPulse) -> Result<ReplicationAck> {
        if let ReplicaStatus::QuarantinedFork { .. } = self.status {
            return Ok(ReplicationAck {
                replica_id: self.node_id.clone(),
                partition_id: pulse.partition_id,
                leader_epoch: pulse.leader_epoch,
                acked_offset: pulse.offset,
                acked_mmr_root: [0u8; 32],
                success: false,
                error_message: Some("Node is in QuarantinedFork state".to_string()),
            });
        }

        let next_offset = self.partition.next_offset();
        if next_offset > 0 {
            let current_root = self.partition.active_mmr_root();
            if let Err(e) = self.validator.validate_append(
                next_offset.saturating_sub(1),
                &current_root,
                pulse.offset,
                &pulse.mmr_root,
            ) {
                self.status = ReplicaStatus::QuarantinedFork {
                    divergent_offset: pulse.offset,
                    expected_root: current_root,
                    actual_root: pulse.mmr_root,
                };
                return Ok(ReplicationAck {
                    replica_id: self.node_id.clone(),
                    partition_id: pulse.partition_id,
                    leader_epoch: pulse.leader_epoch,
                    acked_offset: pulse.offset,
                    acked_mmr_root: pulse.mmr_root,
                    success: false,
                    error_message: Some(e.to_string()),
                });
            }
        }

        // Append locally to follower partition using the leader's exact timestamp
        let record = self.partition.append_with_timestamp(
            None,
            Bytes::copy_from_slice(&pulse.payload),
            Some(pulse.timestamp),
        )?;
        let computed_mmr_root = self.partition.active_mmr_root();

        // Verify that computed MMR root matches leader's pulse mmr_root
        if computed_mmr_root != pulse.mmr_root {
            self.status = ReplicaStatus::QuarantinedFork {
                divergent_offset: record.offset,
                expected_root: pulse.mmr_root,
                actual_root: computed_mmr_root,
            };
            return Ok(ReplicationAck {
                replica_id: self.node_id.clone(),
                partition_id: pulse.partition_id,
                leader_epoch: pulse.leader_epoch,
                acked_offset: record.offset,
                acked_mmr_root: computed_mmr_root,
                success: false,
                error_message: Some("Computed follower MMR root diverged from leader pulse".to_string()),
            });
        }

        Ok(ReplicationAck {
            replica_id: self.node_id.clone(),
            partition_id: pulse.partition_id,
            leader_epoch: pulse.leader_epoch,
            acked_offset: record.offset,
            acked_mmr_root: computed_mmr_root,
            success: true,
            error_message: None,
        })
    }
}
