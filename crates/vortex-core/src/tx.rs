use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::{Result, VortexError};
use crate::record::Record;

pub const CONTROL_TXN_COMMIT: &[u8] = b"__vortex_ctrl:commit__";
pub const CONTROL_TXN_ABORT: &[u8] = b"__vortex_ctrl:abort__";

/// Attribute bitfields for transactional records and control markers (Gap 2 / EOS)
pub const FLAG_TRANSACTIONAL: u16 = 0x0001;
pub const FLAG_CONTROL_RECORD: u16 = 0x0002;

/// Standard control record markers
pub const CONTROL_TXN_COMMIT_MARKER: u8 = 0;
pub const CONTROL_TXN_ABORT_MARKER: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerTxnMeta {
    pub producer_id: u64,
    pub producer_epoch: u16,
    pub sequence_num: u32,
}

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

    /// Calculates the Last Stable Offset (LSO) for a partition.
    /// Defined as the earliest first-offset of any currently open in-flight transaction.
    /// If no transactions are in-flight, LSO equals the partition High Watermark.
    pub fn calculate_lso(high_watermark: u64, in_flight_txns: &HashMap<u64, u64>) -> u64 {
        if in_flight_txns.is_empty() {
            high_watermark
        } else {
            *in_flight_txns.values().min().unwrap_or(&high_watermark)
        }
    }

    /// The current `Record` format has no transaction metadata. ReadCommitted
    /// therefore fails closed; records reaching this function are returned only
    /// for ReadUncommitted. Do not infer control markers from user payload bytes.
    pub fn filter_by_isolation(records: &[Record], isolation: IsolationLevel) -> Vec<Record> {
        match isolation {
            IsolationLevel::ReadUncommitted => records.to_vec(),
            IsolationLevel::ReadCommitted => Vec::new(),
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
    fn read_committed_fails_closed_without_transaction_metadata() {
        let hash = [0u8; 32];
        let records = vec![
            Record::new(hash, 0, None, Bytes::from_static(CONTROL_TXN_COMMIT)),
            Record::new(hash, 1, None, Bytes::from_static(CONTROL_TXN_ABORT)),
        ];
        assert!(TransactionCoordinator::filter_by_isolation(&records, IsolationLevel::ReadCommitted).is_empty());
        assert_eq!(TransactionCoordinator::filter_by_isolation(&records, IsolationLevel::ReadUncommitted), records);
    }

    #[test]
    fn test_calculate_lso() {
        let mut in_flight = HashMap::new();
        // 1. No open transactions -> LSO equals high watermark
        assert_eq!(TransactionCoordinator::calculate_lso(100, &in_flight), 100);

        // 2. Open transaction at offset 40 -> LSO is 40
        in_flight.insert(101, 40);
        assert_eq!(TransactionCoordinator::calculate_lso(100, &in_flight), 40);

        // 3. Another transaction at offset 60 -> LSO remains 40 (minimum)
        in_flight.insert(102, 60);
        assert_eq!(TransactionCoordinator::calculate_lso(100, &in_flight), 40);

        // 4. First transaction commits/aborts -> LSO advances to 60
        in_flight.remove(&101);
        assert_eq!(TransactionCoordinator::calculate_lso(100, &in_flight), 60);

        // 5. All transactions complete -> LSO advances to high watermark
        in_flight.remove(&102);
        assert_eq!(TransactionCoordinator::calculate_lso(100, &in_flight), 100);
    }
}
