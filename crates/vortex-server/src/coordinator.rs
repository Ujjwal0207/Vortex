use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use vortex_core::error::{Result, VortexError};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GroupMemberState {
    pub member_id: String,
    pub instance_id: Option<String>,
    pub member_epoch: u32,
    pub heartbeat_expiry: Instant,
    pub assigned_partitions: Vec<(String, u32)>,
}

#[allow(dead_code)]
pub struct ConsumerGroupState {
    pub group_id: String,
    pub group_epoch: u32,
    pub members: HashMap<String, GroupMemberState>,
    pub subscriptions: HashMap<String, u32>, // Topic -> PartitionCount
    pub committed_offsets: HashMap<(String, u32), i64>,
}

impl ConsumerGroupState {
    pub fn new(group_id: &str) -> Self {
        Self {
            group_id: group_id.to_string(),
            group_epoch: 1,
            members: HashMap::new(),
            subscriptions: HashMap::new(),
            committed_offsets: HashMap::new(),
        }
    }

    /// Rebalances all subscribed topics deterministically across active members.
    /// Updates member assignments and advances group_epoch for member-epoch fencing.
    pub fn rebalance(&mut self) {
        if self.members.is_empty() {
            return;
        }

        self.group_epoch += 1;
        let mut member_ids: Vec<String> = self.members.keys().cloned().collect();
        member_ids.sort();

        // Clear current assignments
        for m in self.members.values_mut() {
            m.assigned_partitions.clear();
            m.member_epoch = self.group_epoch;
        }

        // Collect and sort topics deterministically
        let mut topics: Vec<(String, u32)> = self
            .subscriptions
            .iter()
            .map(|(t, p)| (t.clone(), *p))
            .collect();
        topics.sort_by(|a, b| a.0.cmp(&b.0));

        // Deterministically round-robin assign partitions across active members
        for (topic, partition_count) in topics {
            for p in 0..partition_count {
                let member_idx = (p as usize) % member_ids.len();
                let target_member = &member_ids[member_idx];
                if let Some(m) = self.members.get_mut(target_member) {
                    m.assigned_partitions.push((topic.clone(), p));
                }
            }
        }
    }
}

/// In-Broker Next-Gen Consumer Group Coordinator (Gap 6 / KIP-848 Parity).
/// Eliminates Stop-the-World consumer rebalance storms and provides member-epoch fencing
/// against stale ghost consumers.
pub struct ConsumerGroupCoordinator {
    groups: RwLock<HashMap<String, ConsumerGroupState>>,
    offsets_wal: Mutex<OffsetsWal>,
    data_dir: std::path::PathBuf,
    heartbeat_timeout: Duration,
    max_wal_bytes: std::sync::atomic::AtomicU64,
}

struct OffsetsWal {
    file: File,
    end: u64,
}

const OFFSETS_WAL_MAGIC: u32 = 0x564f_4631; // "VOF1"
const OFFSETS_WAL_HEADER_SIZE: usize = 12;
const MAX_OFFSETS_WAL_RECORD_SIZE: usize = 1024 * 1024;
pub const DEFAULT_MAX_OFFSETS_WAL_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

impl ConsumerGroupCoordinator {
    pub fn new(data_dir: &Path, heartbeat_timeout: Duration) -> Result<Self> {
        fs::create_dir_all(data_dir).map_err(|e| VortexError::Io(e.to_string()))?;

        // Clean up any incomplete compaction tmp file from a previous abrupt shutdown
        let tmp_path = data_dir.join("consumer_offsets.wal.tmp");
        let _ = fs::remove_file(tmp_path);

        let wal_path = data_dir.join("consumer_offsets.wal");
        let wal = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&wal_path)
            .map_err(|e| VortexError::Io(e.to_string()))?;
        let (groups, wal_end) = replay_offsets_wal(&wal)?;

        Ok(Self {
            groups: RwLock::new(groups),
            offsets_wal: Mutex::new(OffsetsWal { file: wal, end: wal_end }),
            data_dir: data_dir.to_path_buf(),
            heartbeat_timeout,
            max_wal_bytes: std::sync::atomic::AtomicU64::new(DEFAULT_MAX_OFFSETS_WAL_BYTES),
        })
    }

    /// Registers or heartbeats a consumer member within a group.
    /// If member is new or subscriptions changed, triggers unified partition rebalance.
    pub fn register_or_heartbeat(
        &self,
        group_id: &str,
        member_id: &str,
        instance_id: Option<String>,
        topics: &[String],
        partition_count: u32,
    ) -> Result<GroupMemberState> {
        let mut groups = self.groups.write().unwrap();
        let group = groups
            .entry(group_id.to_string())
            .or_insert_with(|| ConsumerGroupState::new(group_id));

        let expiry = Instant::now() + self.heartbeat_timeout;
        let is_new = !group.members.contains_key(member_id);

        let member = group
            .members
            .entry(member_id.to_string())
            .or_insert_with(|| GroupMemberState {
                member_id: member_id.to_string(),
                instance_id,
                member_epoch: group.group_epoch,
                heartbeat_expiry: expiry,
                assigned_partitions: Vec::new(),
            });

        member.heartbeat_expiry = expiry;

        let mut subscriptions_changed = false;
        for topic in topics {
            let entry = group
                .subscriptions
                .entry(topic.clone())
                .or_insert(partition_count);
            if *entry != partition_count && partition_count > 0 {
                *entry = partition_count;
                subscriptions_changed = true;
            }
        }

        if is_new || subscriptions_changed {
            group.rebalance();
        }

        Ok(group.members.get(member_id).cloned().unwrap())
    }

    /// Commits an offset for (topic, partition) with generation-epoch fencing.
    /// Stale or expired ghost consumers are immediately rejected with FencedMemberEpoch.
    pub fn commit_offset(
        &self,
        group_id: &str,
        member_id: &str,
        member_epoch: u32,
        topic: &str,
        partition: u32,
        offset: i64,
    ) -> Result<()> {
        if offset < 0 {
            return Err(VortexError::SecurityViolation {
                reason: format!("Committed offset must be non-negative, got {offset}"),
            });
        }
        let mut groups = self.groups.write().unwrap();
        let group = groups.get_mut(group_id).ok_or_else(|| {
            VortexError::SecurityViolation {
                reason: format!("Unknown consumer group '{}'", group_id),
            }
        })?;

        let member = group.members.get(member_id).ok_or_else(|| {
            VortexError::SecurityViolation {
                reason: format!("Unknown consumer member '{}' in group '{}'", member_id, group_id),
            }
        })?;
        if member.heartbeat_expiry <= Instant::now() {
            return Err(VortexError::SecurityViolation {
                reason: format!("Expired consumer member '{}' in group '{}'", member_id, group_id),
            });
        }
        // Validate member epoch fencing before any durable write.
        if member_epoch != member.member_epoch {
            return Err(VortexError::FencedMemberEpoch {
                group_id: group_id.to_string(),
                member_id: member_id.to_string(),
                current: member.member_epoch,
                attempted: member_epoch,
            });
        }

        let wal_record = encode_offsets_wal_record(group_id, topic, partition, offset)?;
        let mut wal = self.offsets_wal.lock().unwrap();
        let wal_start = wal.end;
        if let Err(e) = write_all_at(&wal.file, &wal_record, wal_start)
            .and_then(|_| wal.file.sync_data())
        {
            // Avoid placing later frames after a partially written record. If rollback
            // itself fails, fail this commit and let startup's checksum validation stop
            // the broker rather than silently skipping potentially durable state.
            wal.file.set_len(wal_start).map_err(|truncate| {
                VortexError::Io(format!(
                    "offset WAL write failed ({e}); rollback failed ({truncate})"
                ))
            })?;
            return Err(VortexError::Io(e.to_string()));
        }
        wal.end = wal_start + wal_record.len() as u64;

        group
            .committed_offsets
            .insert((topic.to_string(), partition), offset);

        if wal.end >= self.max_wal_bytes.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = self.compact_wal_locked(&groups, &mut wal);
        }

        Ok(())
    }

    /// Sets maximum WAL file size in bytes before automatic compaction triggers.
    #[allow(dead_code)]
    pub fn set_max_wal_bytes(&self, max_bytes: u64) {
        self.max_wal_bytes.store(max_bytes, std::sync::atomic::Ordering::Relaxed);
    }

    /// Explicitly triggers atomic copy-on-write offset WAL compaction.
    #[allow(dead_code)]
    pub fn compact_wal(&self) -> Result<()> {
        let groups = self.groups.read().unwrap();
        let mut wal = self.offsets_wal.lock().unwrap();
        self.compact_wal_locked(&groups, &mut wal)
    }

    fn compact_wal_locked(
        &self,
        groups: &HashMap<String, ConsumerGroupState>,
        wal: &mut OffsetsWal,
    ) -> Result<()> {
        let wal_path = self.data_dir.join("consumer_offsets.wal");
        let tmp_path = self.data_dir.join("consumer_offsets.wal.tmp");

        let tmp_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| VortexError::Io(format!("failed to create offset WAL compaction tmp file: {e}")))?;

        let mut offset = 0u64;
        let mut sorted_groups: Vec<&String> = groups.keys().collect();
        sorted_groups.sort();

        for group_id in sorted_groups {
            if let Some(group_state) = groups.get(group_id) {
                let mut offsets: Vec<(&(String, u32), &i64)> = group_state.committed_offsets.iter().collect();
                offsets.sort_by(|a, b| a.0.cmp(b.0));
                for ((topic, partition), committed_offset) in offsets {
                    let record = encode_offsets_wal_record(group_id, topic, *partition, *committed_offset)?;
                    write_all_at(&tmp_file, &record, offset).map_err(|e| VortexError::Io(e.to_string()))?;
                    offset += record.len() as u64;
                }
            }
        }

        tmp_file.sync_data().map_err(|e| VortexError::Io(format!("failed to sync compacted offset WAL tmp file: {e}")))?;
        drop(tmp_file);

        fs::rename(&tmp_path, &wal_path).map_err(|e| VortexError::Io(format!("failed to atomically replace offset WAL: {e}")))?;

        let new_wal = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .map_err(|e| VortexError::Io(format!("failed to re-open compacted offset WAL: {e}")))?;

        wal.file = new_wal;
        wal.end = offset;

        Ok(())
    }

    /// Fetches the committed offset for (topic, partition).
    pub fn fetch_offset(&self, group_id: &str, topic: &str, partition: u32) -> Option<i64> {
        let groups = self.groups.read().unwrap();
        let group = groups.get(group_id)?;
        group
            .committed_offsets
            .get(&(topic.to_string(), partition))
            .copied()
    }

    /// Evicts expired members that haven't sent a heartbeat within the timeout window.
    /// Triggers a unified rebalance for any group whose membership changed.
    #[allow(dead_code)]
    pub fn evict_expired_members(&self) -> Vec<String> {
        let mut evicted = Vec::new();
        let now = Instant::now();
        let mut groups = self.groups.write().unwrap();

        for group in groups.values_mut() {
            let stale: Vec<String> = group
                .members
                .iter()
                .filter(|(_, m)| m.heartbeat_expiry < now)
                .map(|(id, _)| id.clone())
                .collect();

            if !stale.is_empty() {
                for id in &stale {
                    group.members.remove(id);
                    evicted.push(id.clone());
                }
                group.rebalance();
            }
        }

        evicted
    }

    /// Explicitly removes a member from the consumer group upon client shutdown.
    /// Rebalances remaining members and increments group_epoch for member-epoch fencing.
    pub fn leave_group(&self, group_id: &str, member_id: &str) -> Result<()> {
        let mut groups = self.groups.write().unwrap();
        if let Some(group) = groups.get_mut(group_id) {
            if group.members.remove(member_id).is_some() {
                group.rebalance();
            }
        }
        Ok(())
    }
}

fn encode_offsets_wal_record(
    group_id: &str,
    topic: &str,
    partition: u32,
    offset: i64,
) -> Result<Vec<u8>> {
    let group = group_id.as_bytes();
    let topic = topic.as_bytes();
    let group_len = u16::try_from(group.len()).map_err(|_| {
        VortexError::Io("consumer group ID is too long for offsets WAL".into())
    })?;
    let topic_len = u16::try_from(topic.len())
        .map_err(|_| VortexError::Io("topic name is too long for offsets WAL".into()))?;

    let mut body = Vec::with_capacity(16 + group.len() + topic.len());
    body.extend_from_slice(&group_len.to_be_bytes());
    body.extend_from_slice(&topic_len.to_be_bytes());
    body.extend_from_slice(&partition.to_be_bytes());
    body.extend_from_slice(&offset.to_be_bytes());
    body.extend_from_slice(group);
    body.extend_from_slice(topic);

    if body.len() > MAX_OFFSETS_WAL_RECORD_SIZE {
        return Err(VortexError::Io("consumer offset record exceeds WAL limit".into()));
    }
    let body_len = u32::try_from(body.len())
        .map_err(|_| VortexError::Io("consumer offset record exceeds WAL format".into()))?;
    let crc = crc32fast::hash(&body);
    let mut record = Vec::with_capacity(OFFSETS_WAL_HEADER_SIZE + body.len());
    record.extend_from_slice(&OFFSETS_WAL_MAGIC.to_be_bytes());
    record.extend_from_slice(&body_len.to_be_bytes());
    record.extend_from_slice(&crc.to_be_bytes());
    record.extend_from_slice(&body);
    Ok(record)
}

fn replay_offsets_wal(wal: &File) -> Result<(HashMap<String, ConsumerGroupState>, u64)> {
    let file_len = wal
        .metadata()
        .map_err(|e| VortexError::Io(e.to_string()))?
        .len();
    let mut groups = HashMap::new();
    let mut position = 0u64;

    while position < file_len {
        let frame_start = position;
        let mut header = [0u8; OFFSETS_WAL_HEADER_SIZE];
        match read_exact_at(wal, &mut header, frame_start) {
            Ok(()) => position += OFFSETS_WAL_HEADER_SIZE as u64,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                wal.set_len(frame_start)
                    .map_err(|e| VortexError::Io(e.to_string()))?;
                break;
            }
            Err(e) => return Err(VortexError::Io(e.to_string())),
        }

        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        let body_len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
        let expected_crc = u32::from_be_bytes(header[8..12].try_into().unwrap());
        if magic != OFFSETS_WAL_MAGIC || !(16..=MAX_OFFSETS_WAL_RECORD_SIZE).contains(&body_len) {
            return Err(VortexError::Io(format!(
                "invalid consumer offsets WAL frame at byte {frame_start}"
            )));
        }
        if position.saturating_add(body_len as u64) > file_len {
            wal.set_len(frame_start)
                .map_err(|e| VortexError::Io(e.to_string()))?;
            break;
        }

        let mut body = vec![0; body_len];
        if let Err(e) = read_exact_at(wal, &mut body, position) {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                wal.set_len(frame_start)
                    .map_err(|e| VortexError::Io(e.to_string()))?;
                break;
            }
            return Err(VortexError::Io(e.to_string()));
        }
        position += body_len as u64;
        if crc32fast::hash(&body) != expected_crc {
            return Err(VortexError::Io(format!(
                "consumer offsets WAL checksum mismatch at byte {frame_start}"
            )));
        }

        let group_len = u16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
        let topic_len = u16::from_be_bytes(body[2..4].try_into().unwrap()) as usize;
        let expected_len = 16usize
            .checked_add(group_len)
            .and_then(|n| n.checked_add(topic_len));
        if expected_len != Some(body.len()) {
            return Err(VortexError::Io(format!(
                "malformed consumer offsets WAL record at byte {frame_start}"
            )));
        }
        let partition = u32::from_be_bytes(body[4..8].try_into().unwrap());
        let offset = i64::from_be_bytes(body[8..16].try_into().unwrap());
        let group_id = std::str::from_utf8(&body[16..16 + group_len])
            .map_err(|e| VortexError::Io(format!("invalid group ID in offsets WAL: {e}")))?;
        let topic = std::str::from_utf8(&body[16 + group_len..])
            .map_err(|e| VortexError::Io(format!("invalid topic in offsets WAL: {e}")))?;

        groups.entry(group_id.to_string())
            .or_insert_with(|| ConsumerGroupState::new(group_id))
            .committed_offsets
            .insert((topic.to_string(), partition), offset);
    }

    Ok((groups, position))
}

fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buffer.is_empty() {
        match file.read_at(buffer, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(bytes_read) => {
                offset += bytes_read as u64;
                buffer = &mut buffer[bytes_read..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_at(file: &File, mut buffer: &[u8], mut offset: u64) -> io::Result<()> {
    while !buffer.is_empty() {
        match file.write_at(buffer, offset) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(bytes_written) => {
                offset += bytes_written as u64;
                buffer = &buffer[bytes_written..];
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    fn test_consumer_group_cooperative_rebalance_and_fencing() {
        let dir = tempfile::tempdir().unwrap();
        let coordinator = ConsumerGroupCoordinator::new(dir.path(), Duration::from_secs(30)).unwrap();
        let group = "analytics-workers";

        // 1. First worker joins -> assigned both partition 0 and 1
        let member1 = coordinator
            .register_or_heartbeat(group, "worker-1", None, &["clicks".into()], 2)
            .unwrap();
        assert_eq!(member1.assigned_partitions.len(), 2);
        assert_eq!(member1.member_epoch, 2);

        // 2. Commit offset from worker-1 succeeds
        coordinator
            .commit_offset(group, "worker-1", member1.member_epoch, "clicks", 0, 100)
            .unwrap();
        assert_eq!(coordinator.fetch_offset(group, "clicks", 0), Some(100));

        // 3. Second worker joins -> cooperative rebalance divides partitions
        let member2 = coordinator
            .register_or_heartbeat(group, "worker-2", None, &["clicks".into()], 2)
            .unwrap();
        assert_eq!(member2.assigned_partitions.len(), 1);
        assert_eq!(member2.member_epoch, 3);

        // Refresh worker-1
        let member1_refreshed = coordinator
            .register_or_heartbeat(group, "worker-1", None, &["clicks".into()], 2)
            .unwrap();
        assert_eq!(member1_refreshed.assigned_partitions.len(), 1);
        assert_eq!(member1_refreshed.member_epoch, 3);

        // 4. Stale commit with old epoch (2) MUST be fenced and rejected!
        let stale_err = coordinator
            .commit_offset(group, "worker-1", 2, "clicks", 0, 105)
            .unwrap_err();
        assert!(matches!(stale_err, VortexError::FencedMemberEpoch { .. }));

        // 5. Valid commit with active epoch (3) succeeds
        coordinator
            .commit_offset(group, "worker-1", 3, "clicks", 0, 105)
            .unwrap();
        assert_eq!(coordinator.fetch_offset(group, "clicks", 0), Some(105));
    }

    #[test]
    fn committed_offsets_survive_restart_and_partial_tail_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        {
            let coordinator = ConsumerGroupCoordinator::new(dir.path(), Duration::from_secs(30)).unwrap();
            let member = coordinator
                .register_or_heartbeat("group", "member", None, &["topic".into()], 1)
                .unwrap();
            coordinator
                .commit_offset("group", "member", member.member_epoch, "topic", 0, 42)
                .unwrap();
        }

        let wal_path = dir.path().join("consumer_offsets.wal");
        OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .unwrap()
            .write_all(&[0x56, 0x4f, 0x46])
            .unwrap();

        let recovered = ConsumerGroupCoordinator::new(dir.path(), Duration::from_secs(30)).unwrap();
        assert_eq!(recovered.fetch_offset("group", "topic", 0), Some(42));
        assert!(recovered.commit_offset("group", "missing", 1, "topic", 0, 99).is_err());
    }

    #[test]
    fn test_consumer_group_multi_topic_rebalance_and_leave() {
        let dir = tempfile::tempdir().unwrap();
        let coordinator = ConsumerGroupCoordinator::new(dir.path(), Duration::from_secs(30)).unwrap();
        let group = "multi-topic-group";
        let topics = vec!["orders".to_string(), "payments".to_string()];

        // 1. Worker 1 registers for both topics (2 partitions each -> 4 total)
        let m1 = coordinator
            .register_or_heartbeat(group, "worker-1", None, &topics, 2)
            .unwrap();
        assert_eq!(m1.assigned_partitions.len(), 4);
        assert_eq!(m1.member_epoch, 2);

        // 2. Worker 2 registers -> partitions evenly divided (2 partitions each)
        let m2 = coordinator
            .register_or_heartbeat(group, "worker-2", None, &topics, 2)
            .unwrap();
        assert_eq!(m2.assigned_partitions.len(), 2);
        assert_eq!(m2.member_epoch, 3);

        // Refresh Worker 1
        let m1_refreshed = coordinator
            .register_or_heartbeat(group, "worker-1", None, &topics, 2)
            .unwrap();
        assert_eq!(m1_refreshed.assigned_partitions.len(), 2);
        assert_eq!(m1_refreshed.member_epoch, 3);

        // 3. Worker 1 leaves -> remaining Worker 2 picks up all 4 partitions
        coordinator.leave_group(group, "worker-1").unwrap();

        let m2_after_leave = coordinator
            .register_or_heartbeat(group, "worker-2", None, &[], 2)
            .unwrap();
        assert_eq!(m2_after_leave.assigned_partitions.len(), 4);
        assert_eq!(m2_after_leave.member_epoch, 4);

        // 4. Stale commit from left worker is rejected
        let err = coordinator
            .commit_offset(group, "worker-1", 3, "orders", 0, 50)
            .unwrap_err();
        assert!(matches!(err, VortexError::SecurityViolation { .. }));
    }

    #[test]
    fn test_consumer_group_expiry_rebalance() {
        let dir = tempfile::tempdir().unwrap();
        let coordinator =
            ConsumerGroupCoordinator::new(dir.path(), Duration::from_millis(50)).unwrap();
        let group = "expiry-group";
        let topics = vec!["telemetry".to_string()];

        coordinator
            .register_or_heartbeat(group, "w-1", None, &topics, 2)
            .unwrap();
        coordinator
            .register_or_heartbeat(group, "w-2", None, &topics, 2)
            .unwrap();

        std::thread::sleep(Duration::from_millis(60));

        // Heartbeat w-2 to keep it alive
        coordinator
            .register_or_heartbeat(group, "w-2", None, &[], 2)
            .unwrap();

        let evicted = coordinator.evict_expired_members();
        assert_eq!(evicted, vec!["w-1"]);

        // Surviving w-2 now owns all 2 partitions
        let w2_state = coordinator
            .register_or_heartbeat(group, "w-2", None, &[], 2)
            .unwrap();
        assert_eq!(w2_state.assigned_partitions.len(), 2);
    }

    #[test]
    fn test_consumer_offsets_wal_compaction() {
        let dir = tempfile::tempdir().unwrap();
        let coordinator = ConsumerGroupCoordinator::new(dir.path(), Duration::from_secs(30)).unwrap();
        // Set low threshold to trigger auto-compaction
        coordinator.set_max_wal_bytes(250);

        let group = "compaction-group";
        let member = coordinator
            .register_or_heartbeat(group, "c-1", None, &["topic".into()], 1)
            .unwrap();

        // Commit 20 sequential offsets to exceed threshold and trigger auto-compaction
        for i in 1..=20 {
            coordinator
                .commit_offset(group, "c-1", member.member_epoch, "topic", 0, i * 10)
                .unwrap();
        }

        // The latest committed offset is 200
        assert_eq!(coordinator.fetch_offset(group, "topic", 0), Some(200));

        let wal_path = dir.path().join("consumer_offsets.wal");
        let auto_compacted_size = std::fs::metadata(&wal_path).unwrap().len();
        // Auto-compaction kept WAL bounded near threshold (< 300 bytes), far less than 20 raw records (> 950 bytes)
        assert!(
            auto_compacted_size <= 300,
            "Auto-compacted WAL size was {auto_compacted_size}"
        );

        // Explicit compaction shrinks file to strictly one record (< 100 bytes)
        coordinator.compact_wal().unwrap();
        let strictly_compacted_size = std::fs::metadata(&wal_path).unwrap().len();
        assert!(
            strictly_compacted_size < 100,
            "Strictly compacted WAL size was {strictly_compacted_size}"
        );

        // Recover in a new coordinator instance from disk
        let recovered = ConsumerGroupCoordinator::new(dir.path(), Duration::from_secs(30)).unwrap();
        assert_eq!(recovered.fetch_offset(group, "topic", 0), Some(200));
    }
}
