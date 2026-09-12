pub mod error;
pub mod hash;
pub mod record;

pub use error::{Result, VortexError};
pub use hash::{compute_genesis_hash, compute_record_hash, verify_record_integrity, HashDigest};
pub use record::{Record, RECORD_HEADER_SIZE};
