use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum VortexError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Corrupted record CRC at offset {offset}: expected {expected:#010x}, found {actual:#010x}")]
    CorruptedRecordCrc {
        offset: u64,
        expected: u32,
        actual: u32,
    },

    #[error("Cryptographic lineage broken at offset {offset}: expected prev_hash {expected}, got {actual}")]
    CryptographicLineageBroken {
        offset: u64,
        expected: String,
        actual: String,
    },

    #[error("Buffer underflow: needed {needed} bytes, only had {available}")]
    BufferUnderflow {
        needed: usize,
        available: usize,
    },

    #[error("Invalid magic byte sequence: expected {expected:#010x}, got {actual:#010x}")]
    InvalidMagic {
        expected: u32,
        actual: u32,
    },

    #[error("Segment file full: current size {current_size} exceeds max {max_size}")]
    SegmentFull {
        current_size: u64,
        max_size: u64,
    },

    #[error("Offset out of bounds: requested {requested}, log range is [{base_offset}..{next_offset})")]
    OffsetOutOfBounds {
        requested: u64,
        base_offset: u64,
        next_offset: u64,
    },

    #[error("Schema validation failure for topic '{topic}': {reason}")]
    SchemaValidationFailed {
        topic: String,
        reason: String,
    },

    #[error("Poison pill detected: {reason}")]
    PoisonPillDetected {
        reason: String,
    },

    #[error("Topic '{0}' not found")]
    TopicNotFound(String),

    #[error("Partition {partition} for topic '{topic}' not found")]
    PartitionNotFound {
        topic: String,
        partition: u32,
    },
}

pub type Result<T> = std::result::Result<T, VortexError>;
