pub mod arrow_parquet;
pub mod batch_io;
pub mod compaction;
pub mod fd_pool;
pub mod gateway;
pub mod keyring;
pub mod linger;
pub mod partition;
pub mod pcqr;
pub mod scrubber;
pub mod segment;
pub mod tiered;
pub mod verifier;
pub mod watermark;
pub mod witness;
pub mod witness_notary;
pub mod zero_copy;
pub mod zk_audit;

pub use arrow_parquet::{
    export_partition_arrow_ipc, export_partition_parquet, project_partition_to_arrow,
    ArrowColumnarBatch, ArrowExportStats, ParquetExportStats, ARROW_CONTINUATION_TOKEN,
    COL_MMR_ROOT, COL_OFFSET, COL_PAYLOAD, COL_RECORD_HASH, COL_TIMESTAMP, PARQUET_MAGIC,
};
pub use batch_io::{BatchedPositionalIo, BatchedWriteRequest, SqpollConfig, SqpollStats, SqpollSubmissionRing};
pub use compaction::{
    compute_state_merkle_root, deduplicate_records, ChangelogCompactor, CompactionAnchor,
};
pub use fd_pool::FdPool;
pub use gateway::{ActionGateway, AgentBudgetConfig, AgentBudgetGovernor, PolicyEngine, SimplePolicyEngine};
pub use keyring::TwoSlotKeyring;
pub use linger::AdaptiveLingerQueue;
pub use partition::{AppendResult, PartitionLog, PartitionVerifyReport, DEFAULT_MAX_SEGMENT_BYTES};
pub use pcqr::{
    MMRCommitPulse, PcqrElectionValidator, PcqrFollowerNode, PcqrLeaderReplicator,
    QuorumCommitTracker, ReplicaState, ReplicaStatus, ReplicationAck, ZeroDivergenceValidator,
};
pub use scrubber::{ScrubReport, Scrubber};
pub use segment::{IndexEntry, Segment, HEADER_INDEX_REGION_SIZE, SEGMENT_MAGIC};
pub use tiered::{ExtractedSegmentArchive, SegmentArchiveManifest, TieredArchiveManager};
pub use verifier::{EvidenceVerificationReport, OfflineVerifier};
pub use watermark::{
    check_ingress_watermark, get_disk_usage_percent, WATERMARK_FREEZE_PERCENT,
    WATERMARK_INGRESS_SHED_PERCENT, WATERMARK_SOFT_WARN_PERCENT,
};
pub use witness::{IndependentWitness, WitnessState};
pub use witness_notary::{WitnessNotaryEngine, WitnessNotaryPulse, WitnessNotaryRecord};
pub use zero_copy::ZeroCopySplicer;
pub use zk_audit::ZkAuditEngine;



