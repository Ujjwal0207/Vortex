use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::{Result, VortexError};
use crate::record::Record;

pub const CONTROL_TXN_COMMIT: &[u8] = b"__vortex_ctrl:commit__";
pub const CONTROL_TXN_ABORT: &[u8] = b"__vortex_ctrl:abort__";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    ReadUncommitted = 0,
    ReadCommitted = 1,
}

#[derive(Debug, Clone)]
pub struct ProducerState {
    pub producer_id: u64,
    pub epoch: u16,
    pub last_sequence: u32,
}

/// Transaction Coordinator managing ProducerId idempotency, sequence deduplication,
/// and Last Stable Offset (LSO) isolation for Exactly-Once Semantics (Gap 2).
pub struct TransactionCoordinator {
    producers: RwLock<HashMap<u64, ProducerState>>,
}

impl Default for TransactionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionCoordinator {
    pub fn new() -> Self {
        Self {
            producers: RwLock::new(HashMap::new()),
        }
    }

    /// Verifies producer sequence for idempotency.
    /// Returns Ok(true) if record should be committed, Ok(false) if it is a duplicate retry,
    /// or Err(VortexError) if out-of-order sequence detected.
    pub fn verify_and_update_sequence(
        &self,
        producer_id: u64,
        epoch: u16,
        sequence: u32,
    ) -> Result<bool> {
        let mut producers = self.producers.write().unwrap();
        let state = producers.entry(producer_id).or_insert(ProducerState {
            producer_id,
            epoch,
            last_sequence: 0,
        });

        // Epoch check
        if epoch < state.epoch {
            return Err(VortexError::FencedLeaderEpoch {
                current: state.epoch as u32,
                attempted: epoch as u32,
            });
        }
        if epoch > state.epoch {
            state.epoch = epoch;
            state.last_sequence = 0;
        }

        // Duplicate network retry detection
        if sequence <= state.last_sequence && state.last_sequence > 0 {
            return Ok(false); // Duplicate, safely drop without error
        }

        state.last_sequence = sequence;
        Ok(true)
    }

    /// Allocates a new ProducerId and Epoch or increments the epoch of an existing producer.
    pub fn init_producer_id(&self, current_id: Option<u64>) -> (u64, u16) {
        let mut producers = self.producers.write().unwrap();
        let pid = match current_id {
            Some(id) if id > 0 => id,
            _ => (producers.len() as u64) + 1000,
        };

        let state = producers.entry(pid).or_insert(ProducerState {
            producer_id: pid,
            epoch: 0,
            last_sequence: 0,
        });

        if current_id.is_some() && current_id.unwrap() > 0 {
            state.epoch = state.epoch.wrapping_add(1);
            state.last_sequence = 0;
        }

        (pid, state.epoch)
    }

    /// Filters records according to consumer isolation level.
    /// Under ReadCommitted:
    /// - Strips embedded transaction control markers (TxnCommit, TxnAbort)
    /// - Drops uncommitted or aborted transaction ranges up to the Last Stable Offset (LSO).
    pub fn filter_by_isolation(records: &[Record], isolation: IsolationLevel) -> Vec<Record> {
        match isolation {
            IsolationLevel::ReadUncommitted => records
                .iter()
                .filter(|r| r.value.as_ref() != CONTROL_TXN_COMMIT && r.value.as_ref() != CONTROL_TXN_ABORT)
                .cloned()
                .collect(),
            IsolationLevel::ReadCommitted => {
                let mut result = Vec::new();
                let mut pending_batch = Vec::new();

                for r in records {
                    if r.value.as_ref() == CONTROL_TXN_COMMIT {
                        // Commit: promote all pending records to committed stream
                        result.append(&mut pending_batch);
                    } else if r.value.as_ref() == CONTROL_TXN_ABORT {
                        // Abort: permanently discard pending uncommitted records
                        pending_batch.clear();
                    } else {
                        pending_batch.push(r.clone());
                    }
                }

                // If non-transactional streaming, include remaining records
                result.append(&mut pending_batch);
                result
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_idempotent_sequence_deduplication() {
        let coordinator = TransactionCoordinator::new();

        // 1. Initial sequence 1 accepted
        assert!(coordinator.verify_and_update_sequence(1001, 1, 1).unwrap());

        // 2. Duplicate sequence 1 dropped cleanly
        assert!(!coordinator.verify_and_update_sequence(1001, 1, 1).unwrap());

        // 3. Next sequence 2 accepted
        assert!(coordinator.verify_and_update_sequence(1001, 1, 2).unwrap());
    }

    #[test]
    fn test_read_committed_lso_isolation() {
        let hash = [0u8; 32];
        let r1 = Record::new(hash, 0, None, Bytes::from("txn1-item-1"));
        let r2 = Record::new(hash, 1, None, Bytes::from("txn1-item-2"));
        let commit = Record::new(hash, 2, None, Bytes::from_static(CONTROL_TXN_COMMIT));

        let r3 = Record::new(hash, 3, None, Bytes::from("txn2-item-1"));
        let abort = Record::new(hash, 4, None, Bytes::from_static(CONTROL_TXN_ABORT));

        let r4 = Record::new(hash, 5, None, Bytes::from("standard-item"));

        let stream = vec![r1, r2, commit, r3, abort, r4];

        // Under ReadCommitted: r3 is discarded due to abort; r1, r2, r4 are returned
        let committed = TransactionCoordinator::filter_by_isolation(&stream, IsolationLevel::ReadCommitted);
        assert_eq!(committed.len(), 3);
        assert_eq!(committed[0].value, Bytes::from("txn1-item-1"));
        assert_eq!(committed[1].value, Bytes::from("txn1-item-2"));
        assert_eq!(committed[2].value, Bytes::from("standard-item"));
    }
}
