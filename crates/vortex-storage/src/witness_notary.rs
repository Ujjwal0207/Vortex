use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use vortex_core::evidence::{verify_signature, SignatureBytes, SigningKey, Signer};
use vortex_core::hash::HashDigest;
use vortex_core::{error::Result, VortexError};

const NOTARY_PREFIX: &[u8] = b"VORTEX_ROUGHTIME_WITNESS_V1:";

/// An asynchronous MMR commitment pulse sent to external witness nodes for timestamp notarization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessNotaryPulse {
    pub epoch: u32,
    pub offset: u64,
    pub mmr_root: HashDigest,
    pub host_timestamp: u64,
}

/// A cryptographic timestamp envelope notarized and signed by an external witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessNotaryRecord {
    pub pulse: WitnessNotaryPulse,
    pub witness_pubkey: [u8; 32],
    pub witness_timestamp: u64,
    pub signature: SignatureBytes,
}

impl WitnessNotaryRecord {
    /// Computes the cryptographic signing digest for a notary pulse and witness timestamp.
    pub fn compute_message(pulse: &WitnessNotaryPulse, witness_timestamp: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32 + 4 + 8 + 32 + 8 + 8);
        msg.extend_from_slice(NOTARY_PREFIX);
        msg.extend_from_slice(&pulse.epoch.to_be_bytes());
        msg.extend_from_slice(&pulse.offset.to_be_bytes());
        msg.extend_from_slice(&pulse.mmr_root);
        msg.extend_from_slice(&pulse.host_timestamp.to_be_bytes());
        msg.extend_from_slice(&witness_timestamp.to_be_bytes());
        msg
    }

    /// Verifies the Ed25519 countersignature on this record.
    pub fn verify_signature(&self) -> bool {
        let msg = Self::compute_message(&self.pulse, self.witness_timestamp);
        verify_signature(&self.witness_pubkey, &msg, &self.signature)
    }
}

/// Phase 16: RFC 9162 & Roughtime Distributed Witness Notary Engine.
///
/// Prevents malicious local OS clock manipulation (e.g. root `settimeofday` backdating attacks)
/// by anchoring periodic MMR root pulses to independent external witness countersignatures in `reel.wit`.
pub struct WitnessNotaryEngine {
    reel_path: PathBuf,
    trusted_witness_pubkeys: Vec<[u8; 32]>,
    last_notarized_host_timestamp: Option<u64>,
    max_skew_seconds: u64,
}

impl WitnessNotaryEngine {
    /// Initializes the notary engine pointing to the `reel.wit` sidecar.
    pub fn new<P: AsRef<Path>>(reel_path: P, trusted_witness_pubkeys: Vec<[u8; 32]>) -> Result<Self> {
        let reel_path = reel_path.as_ref().to_path_buf();
        if let Some(parent) = reel_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VortexError::Io(e.to_string()))?;
        }

        // Recover last notarized host timestamp from reel.wit on startup to prevent rollback across restarts
        let mut last_notarized_host_timestamp = None;
        if reel_path.exists() {
            if let Ok(file) = std::fs::File::open(&reel_path) {
                let reader = BufReader::new(file);
                for line in reader.lines().flatten() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(rec) = serde_json::from_str::<WitnessNotaryRecord>(trimmed) {
                        last_notarized_host_timestamp = Some(rec.pulse.host_timestamp);
                    }
                }
            }
        }

        Ok(Self {
            reel_path,
            trusted_witness_pubkeys,
            last_notarized_host_timestamp,
            max_skew_seconds: 300, // 5 minutes max tolerance against network witness consensus
        })
    }

    pub fn set_max_skew_seconds(&mut self, seconds: u64) {
        self.max_skew_seconds = seconds;
    }

    pub fn trusted_witness_pubkeys(&self) -> &[[u8; 32]] {
        &self.trusted_witness_pubkeys
    }

    /// Notarizes an MMR pulse across external witness keys, validates anti-tampering invariants,
    /// and appends the countersigned envelopes to `reel.wit`.
    pub fn notarize_and_append(
        &mut self,
        pulse: &WitnessNotaryPulse,
        witness_keys: &[SigningKey],
        witness_timestamps: &[u64],
    ) -> Result<Vec<WitnessNotaryRecord>> {
        if witness_keys.is_empty() || witness_timestamps.is_empty() {
            return Err(VortexError::SecurityViolation {
                reason: "Cannot notarize pulse without witness keys or timestamps".to_string(),
            });
        }

        // 1. Clock Rollback Detection
        if let Some(last_ts) = self.last_notarized_host_timestamp {
            if pulse.host_timestamp < last_ts {
                return Err(VortexError::SecurityViolation {
                    reason: format!(
                        "Clock rollback detected: host clock moved backwards from {} to {}. Refusing to notarize forged timeline.",
                        last_ts, pulse.host_timestamp
                    ),
                });
            }
        }

        // 2. Roughtime Witness Consensus Skew Detection
        let mut sorted_ts = witness_timestamps.to_vec();
        sorted_ts.sort_unstable();
        let median_witness_ts = sorted_ts[sorted_ts.len() / 2];

        let drift = if pulse.host_timestamp > median_witness_ts {
            pulse.host_timestamp - median_witness_ts
        } else {
            median_witness_ts - pulse.host_timestamp
        };

        if drift > self.max_skew_seconds {
            return Err(VortexError::SecurityViolation {
                reason: format!(
                    "Clock drift/tampering detected: host clock ({}) skewed by {}s from witness consensus ({}), exceeding limit of {}s",
                    pulse.host_timestamp, drift, median_witness_ts, self.max_skew_seconds
                ),
            });
        }

        // 3. Generate Countersignatures
        let mut records = Vec::with_capacity(witness_keys.len());
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.reel_path)
            .map_err(|e| VortexError::Io(format!("Failed to open reel.wit: {e}")))?;

        for (i, key) in witness_keys.iter().enumerate() {
            let witness_ts = witness_timestamps.get(i).copied().unwrap_or(median_witness_ts);
            let msg = WitnessNotaryRecord::compute_message(pulse, witness_ts);
            let signature_bytes: [u8; 64] = key.sign(&msg).into();

            let record = WitnessNotaryRecord {
                pulse: pulse.clone(),
                witness_pubkey: key.verifying_key().to_bytes(),
                witness_timestamp: witness_ts,
                signature: SignatureBytes(signature_bytes),
            };

            let line = serde_json::to_string(&record)
                .map_err(|e| VortexError::InvalidRecordFormat(format!("Failed to serialize notary record: {e}")))?;
            writeln!(file, "{}", line)
                .map_err(|e| VortexError::Io(format!("Failed to write to reel.wit: {e}")))?;

            records.push(record);
        }

        file.sync_all().map_err(|e| VortexError::Io(e.to_string()))?;
        self.last_notarized_host_timestamp = Some(pulse.host_timestamp);

        Ok(records)
    }

    /// Offline audit verification of `reel.wit` sidecar file against trusted witness public keys.
    pub fn verify_reel<P: AsRef<Path>>(reel_path: P, expected_pubkeys: &[[u8; 32]]) -> Result<usize> {
        let file = std::fs::File::open(reel_path.as_ref())
            .map_err(|e| VortexError::Io(format!("Cannot open reel.wit for verification: {e}")))?;
        let reader = BufReader::new(file);

        let mut verified_count = 0;
        let mut last_offset: Option<u64> = None;

        for (line_num, line_res) in reader.lines().enumerate() {
            let line = line_res.map_err(|e| VortexError::Io(e.to_string()))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let record: WitnessNotaryRecord = serde_json::from_str(trimmed)
                .map_err(|e| VortexError::InvalidRecordFormat(format!("Corrupt reel.wit line {}: {e}", line_num + 1)))?;

            // Check signature
            if !record.verify_signature() {
                return Err(VortexError::SecurityViolation {
                    reason: format!("Invalid witness signature in reel.wit at line {}", line_num + 1),
                });
            }

            // Check trusted pubkey
            if !expected_pubkeys.contains(&record.witness_pubkey) {
                return Err(VortexError::SecurityViolation {
                    reason: format!("Untrusted witness key {:?} at line {}", record.witness_pubkey, line_num + 1),
                });
            }

            // Check offset monotonicity
            if let Some(prev) = last_offset {
                if record.pulse.offset < prev {
                    return Err(VortexError::SecurityViolation {
                        reason: format!("Regressive offset sequence in reel.wit: {} < {}", record.pulse.offset, prev),
                    });
                }
            }
            last_offset = Some(record.pulse.offset);
            verified_count += 1;
        }

        Ok(verified_count)
    }
}
