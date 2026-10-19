pub mod batch_io;
pub mod compaction;
pub mod gateway;
pub mod keyring;
pub mod partition;
pub mod scrubber;
pub mod segment;
pub mod tiered;
pub mod verifier;
pub mod watermark;
pub mod witness;

pub use batch_io::{BatchedPositionalIo, BatchedWriteRequest};
pub use compaction::{
    compute_state_merkle_root, deduplicate_records, ChangelogCompactor, CompactionAnchor,
};
pub use gateway::{ActionGateway, PolicyEngine, SimplePolicyEngine};
pub use keyring::TwoSlotKeyring;
pub use partition::{AppendResult, PartitionLog, PartitionVerifyReport, DEFAULT_MAX_SEGMENT_BYTES};
pub use scrubber::{ScrubReport, Scrubber};
pub use segment::{IndexEntry, Segment, HEADER_INDEX_REGION_SIZE, SEGMENT_MAGIC};
pub use tiered::{ExtractedSegmentArchive, SegmentArchiveManifest, TieredArchiveManager};
pub use verifier::{EvidenceVerificationReport, OfflineVerifier};
pub use watermark::{
    check_ingress_watermark, get_disk_usage_percent, WATERMARK_FREEZE_PERCENT,
    WATERMARK_INGRESS_SHED_PERCENT, WATERMARK_SOFT_WARN_PERCENT,
};
pub use witness::{IndependentWitness, WitnessState};



