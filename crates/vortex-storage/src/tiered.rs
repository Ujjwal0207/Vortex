use blake3::Hasher;
use bytes::{Buf, BufMut, BytesMut};
use crc32fast::Hasher as Crc32Hasher;

use vortex_core::{error::Result, HashDigest, VortexError};
use crate::segment::Segment;

pub const ARCHIVE_BUNDLE_MAGIC: u32 = 0x5654_5842; // "VTXB"
pub const ARCHIVE_BUNDLE_VERSION: u8 = 1;

/// Manifest header describing an individual segment stored within an archive bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentArchiveManifest {
    pub base_offset: u64,
    pub next_offset: u64,
    pub genesis_hash: HashDigest,
    pub last_record_hash: HashDigest,
    pub mmr_root: HashDigest,
    pub data_length: u64,
    pub crc32: u32,
}

/// Extracted segment data unpacked from an archive bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedSegmentArchive {
    pub manifest: SegmentArchiveManifest,
    pub data: Vec<u8>,
}

/// Tiered Cloud Storage Manager that implements deterministic entropy prefix sharding
/// and multi-segment archive bundle consolidation.
///
/// Resolves Flaw 6.6 ("Cloud Object Storage Prefix Hotspotting & Rate Limiting"):
/// 1. Prepends deterministic 8-character Blake3 entropy hashes to S3/GCS object keys,
///    sharding uploads across billions of internal S3 partition prefixes and eliminating 503 SlowDown throttling.
/// 2. Coalesces sealed segments into consolidated `.vtxarc` bundles, slashing PUT API request volume and cloud costs.
pub struct TieredArchiveManager;

impl TieredArchiveManager {
    /// Generates a deterministic, entropy-sharded cloud object storage key.
    /// Format: `vtx-tier/{entropy_prefix:8}/{topic}/p{partition:05}/{base_offset:020}_{end_offset:020}.vtxarc`
    pub fn generate_sharded_object_key(
        topic: &str,
        partition: u32,
        base_offset: u64,
        end_offset: u64,
    ) -> String {
        let mut hasher = Hasher::new();
        hasher.update(b"VORTEX_S3_ENTROPY_V1:");
        hasher.update(topic.as_bytes());
        hasher.update(&partition.to_be_bytes());
        hasher.update(&base_offset.to_be_bytes());
        let digest = hasher.finalize();
        let hex_entropy = hex::encode(&digest.as_bytes()[0..4]); // 8 hex characters

        format!(
            "vtx-tier/{}/{}/p{:05}/{:020}_{:020}.vtxarc",
            hex_entropy, topic, partition, base_offset, end_offset
        )
    }

    /// Coalesces multiple sealed segments into a single consolidated binary archive bundle.
    pub fn create_bundle(segments: &[&Segment]) -> Result<Vec<u8>> {
        if segments.is_empty() {
            return Err(VortexError::Io("cannot create empty archive bundle".into()));
        }

        let mut manifest_entries = Vec::with_capacity(segments.len());
        let mut payloads = Vec::with_capacity(segments.len());

        for seg in segments {
            let data_len = seg.size();
            let mut seg_bytes = vec![0u8; data_len as usize];
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileExt;
                seg.file
                    .read_exact_at(&mut seg_bytes, 0)
                    .map_err(|e| VortexError::Io(e.to_string()))?;
            }

            let mut crc_hasher = Crc32Hasher::new();
            crc_hasher.update(&seg_bytes);
            let crc = crc_hasher.finalize();

            let manifest = SegmentArchiveManifest {
                base_offset: seg.base_offset,
                next_offset: seg.next_offset,
                genesis_hash: seg.genesis_hash,
                last_record_hash: seg.last_record_hash,
                mmr_root: seg.mmr_root(),
                data_length: data_len,
                crc32: crc,
            };

            manifest_entries.push(manifest);
            payloads.push(seg_bytes);
        }

        // Header format:
        // [magic: 4B] + [version: 1B] + [segment_count: 4B]
        let mut header = BytesMut::new();
        header.put_u32(ARCHIVE_BUNDLE_MAGIC);
        header.put_u8(ARCHIVE_BUNDLE_VERSION);
        header.put_u32(manifest_entries.len() as u32);

        // Encode manifest table
        // Each entry: [base: 8B] + [next: 8B] + [genesis: 32B] + [last_hash: 32B] + [mmr_root: 32B] + [len: 8B] + [crc: 4B] = 124B
        for m in &manifest_entries {
            header.put_u64(m.base_offset);
            header.put_u64(m.next_offset);
            header.put_slice(&m.genesis_hash);
            header.put_slice(&m.last_record_hash);
            header.put_slice(&m.mmr_root);
            header.put_u64(m.data_length);
            header.put_u32(m.crc32);
        }

        let mut bundle = header.to_vec();
        for p in payloads {
            bundle.extend_from_slice(&p);
        }

        Ok(bundle)
    }

    /// Unpacks an archive bundle and validates CRC32 and metadata for all contained segments.
    pub fn unpack_bundle(bundle_bytes: &[u8]) -> Result<Vec<ExtractedSegmentArchive>> {
        if bundle_bytes.len() < 9 {
            return Err(VortexError::Io("archive bundle header too short".into()));
        }

        let mut reader = bundle_bytes;
        let magic = reader.get_u32();
        if magic != ARCHIVE_BUNDLE_MAGIC {
            return Err(VortexError::InvalidMagic {
                expected: ARCHIVE_BUNDLE_MAGIC,
                actual: magic,
            });
        }

        let version = reader.get_u8();
        if version != ARCHIVE_BUNDLE_VERSION {
            return Err(VortexError::Io(format!("unsupported archive bundle version {version}")));
        }

        let seg_count = reader.get_u32() as usize;
        let manifest_size = seg_count * 124;
        if reader.remaining() < manifest_size {
            return Err(VortexError::Io("truncated archive manifest table".into()));
        }

        let mut manifests = Vec::with_capacity(seg_count);
        for _ in 0..seg_count {
            let base_offset = reader.get_u64();
            let next_offset = reader.get_u64();

            let mut genesis_hash = [0u8; 32];
            reader.copy_to_slice(&mut genesis_hash);

            let mut last_record_hash = [0u8; 32];
            reader.copy_to_slice(&mut last_record_hash);

            let mut mmr_root = [0u8; 32];
            reader.copy_to_slice(&mut mmr_root);

            let data_length = reader.get_u64();
            let crc32 = reader.get_u32();

            manifests.push(SegmentArchiveManifest {
                base_offset,
                next_offset,
                genesis_hash,
                last_record_hash,
                mmr_root,
                data_length,
                crc32,
            });
        }

        let mut extracted = Vec::with_capacity(seg_count);
        for m in manifests {
            let len = m.data_length as usize;
            if reader.remaining() < len {
                return Err(VortexError::Io("truncated segment payload in archive bundle".into()));
            }

            let seg_data = reader[..len].to_vec();
            reader.advance(len);

            let mut crc_hasher = Crc32Hasher::new();
            crc_hasher.update(&seg_data);
            let computed_crc = crc_hasher.finalize();
            if computed_crc != m.crc32 {
                return Err(VortexError::CorruptedRecordCrc {
                    offset: m.base_offset,
                    expected: m.crc32,
                    actual: computed_crc,
                });
            }

            extracted.push(ExtractedSegmentArchive {
                manifest: m,
                data: seg_data,
            });
        }

        Ok(extracted)
    }
}

// Minimal internal hex encoder to avoid pulling in external hex crate if not already present
mod hex {
    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for b in data {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use bytes::Bytes;
    use vortex_core::compute_genesis_hash;

    #[test]
    fn test_sharded_object_key_distribution_and_determinism() {
        let key1 = TieredArchiveManager::generate_sharded_object_key("telemetry", 0, 0, 1000);
        let key2 = TieredArchiveManager::generate_sharded_object_key("telemetry", 0, 0, 1000);
        let key3 = TieredArchiveManager::generate_sharded_object_key("telemetry", 1, 0, 1000);
        let key4 = TieredArchiveManager::generate_sharded_object_key("orders", 0, 0, 1000);

        // Determinism
        assert_eq!(key1, key2);

        // Different partitions and topics produce different uniform entropy prefixes
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);

        // Prefix structure: starts with "vtx-tier/{8_hex}/"
        assert!(key1.starts_with("vtx-tier/"));
        let parts: Vec<&str> = key1.split('/').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[1].len(), 8); // 8-char hex entropy prefix
    }

    #[test]
    fn test_archive_bundle_coalesce_and_unpack_roundtrip() {
        let dir = tempdir().unwrap();
        let genesis0 = compute_genesis_hash("test-topic", 0);

        // Create 2 segments with data
        let mut seg0 = Segment::open_or_create(dir.path(), 0, genesis0).unwrap();
        seg0.append(None, Bytes::from_static(b"seg0-data1")).unwrap();
        seg0.append(None, Bytes::from_static(b"seg0-data2")).unwrap();

        let genesis1 = seg0.last_record_hash;
        let mut seg1 = Segment::open_or_create(dir.path(), 2, genesis1).unwrap();
        seg1.append(None, Bytes::from_static(b"seg1-data1")).unwrap();
        seg1.append(None, Bytes::from_static(b"seg1-data2")).unwrap();

        // Coalesce into bundle
        let bundle_bytes = TieredArchiveManager::create_bundle(&[&seg0, &seg1]).unwrap();
        assert!(!bundle_bytes.is_empty());

        // Unpack bundle and verify
        let unpacked = TieredArchiveManager::unpack_bundle(&bundle_bytes).unwrap();
        assert_eq!(unpacked.len(), 2);

        assert_eq!(unpacked[0].manifest.base_offset, 0);
        assert_eq!(unpacked[0].manifest.next_offset, 2);
        assert_eq!(unpacked[0].manifest.mmr_root, seg0.mmr_root());

        assert_eq!(unpacked[1].manifest.base_offset, 2);
        assert_eq!(unpacked[1].manifest.next_offset, 4);
        assert_eq!(unpacked[1].manifest.mmr_root, seg1.mmr_root());

        // Tampering with payload fails CRC validation
        let mut tampered_bundle = bundle_bytes.clone();
        let last_idx = tampered_bundle.len() - 1;
        tampered_bundle[last_idx] ^= 0xFF;
        assert!(TieredArchiveManager::unpack_bundle(&tampered_bundle).is_err());
    }
}
