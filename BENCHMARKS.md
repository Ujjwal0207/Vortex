# Vortex Benchmarks & Empirical Performance Engineering

Comprehensive empirical benchmark suite on the **release** broker (`rustc 1.80+`, `--release`, Apple Silicon Darwin arm64).

This document details latency, throughput, hardware efficiency, cryptographic overhead, and adversarial resilience across all architectural layers of Vortex: pure CPU cryptography, adaptive dual-mode storage, 64 KB block coalescing, partition hyperscaling, consumer catchup, autonomous evidence audit, Roughtime witness notarization, PCQR consensus, and network streaming.

---

## 🖥️ Test Environment

| Parameter | Specification |
| :--- | :--- |
| **Platform** | Apple Silicon (macOS Darwin arm64) |
| **Compiler** | `rustc --release` (LLVM 18 / 19 optimizations enabled) |
| **Storage Architecture** | Direct memory-mapped `.vtx` append logs + `.commit` boundary sidecars |
| **Concurrency Model** | Tokio asynchronous reactor + Rayon work-stealing parallel compute |
| **Integrity Model** | Hardware CRC32 + Blake3 SIMD hash chain + Merkle Mountain Range (MMR) |
| **Network Transport** | Asynchronous Tokio TCP loopback (`127.0.0.1:9092`) |
| **Filesystem & Flash Media** | APFS on high-speed NVMe flash storage |

---

## ⚡ Executive Performance Summary

| Tier / Workload | Metric / Scale | Vortex Result | Latency Profile | Guarantee |
| :--- | :--- | ---: | ---: | :--- |
| **Raw Line-Rate Ingestion** | Hardware CRC32 (`TopicMode::Raw`) | **2,825,085 rec/s** | **0.35 µs** / record | SIMD CRC32 + kernel zero-copy bypass |
| **StrictProof Flight-Recorder** | Blake3 Chain (`TopicMode::StrictProof`) | **242,362 rec/s** | **4.13 µs** / record | Non-repudiable linear hash-chain integrity |
| **Batched Ingestion Pipeline** | Sequential `AdaptiveLingerQueue` | **> 225,000 msgs/s** | **4.44 µs** / message | Eliminates physical write amplification |
| **Mega-Payload Tree Hashing** | 50 × 2.0 MB (100 MB total) | **~4,940 MB/s** | **0.41 ms** / 2 MB record | Rayon SIMD multi-threaded Blake3 hashing |
| **Ingress Crypto Chaining** | Blake3 Chain + Ratchet MAC | **~1,470,000 rec/s** | **0.68 µs** / record | Forward-secure tamper-evident lineage |
| **Incremental MMR Insertion** | Dynamic peak updates | **~2,255,000 leaves/s** | **0.44 µs** / leaf | $O(\log N)$ append-only tree commitment |
| **64 KB Block Coalescing** | Intra-block Merkle trees | **< 1.0 µs** / record | Sub-microsecond validation | >99% reduction in MMR tree depth |
| **Shamir (2,3) Secret Custody** | Galois Field $GF(2^8)$ reconstruction | **~2,380,000 ops/s** | **0.42 µs** / key | 2-of-3 threshold sharing; 0.00% resurrection |
| **Succinct ZK-SNARK Audit** | Groth16 Partition Batch Proof | **128-byte proof** | **< 5 ms** batch verify | Zero-knowledge proof over millions of events |
| **Partition Hyperscaling** | 300 active partition logs | **Bounded $\le 64$ FDs** | Sub-millisecond appends | LRU descriptor pooling; 0 OS `EMFILE` errors |
| **Consumer Catchup** | 8 parallel worker threads | **~419,685 rec/s** | Non-blocking catchup | High concurrency under heavy writer pressure |
| **Physical Disk Commit Barrier** | Synchronous unbatched `fsync` | **92 commits/s** | **10.92 ms** / commit | Atomic APFS fsync + `.commit` fence |
| **TCP Network Ingestion** | 100k × 512 B unbatched produce | **38,944 msgs/s** | p50: **24 µs**, p99: **53 µs** | CRC32 + linear Blake3 chain + 100% verified |
| **Memory Footprint (RSS)** | Sustained 100k streaming | **6.7 – 6.9 MB** | Flat memory profile | Zero garbage collection; zero heap bloat |
| **Adversarial Resilience** | 200 Harsh Real-World Scenarios | **200 / 200 Passed** | **100% Green** | Bit-rot, clock rollback, PCQR quorum defense |

---

## 1. 🔐 Cryptographic & Zero-Knowledge Primitives (Pure CPU)

Measurements conducted in isolated memory-resident workloads to evaluate pure algorithmic performance without I/O interference:

| Operation | Workload | Latency | Throughput | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Multi-Core Tree Hashing (Blake3 SIMD)** | 2.0 MB record | **0.41 ms** / record | **~4,940 MB/s** | Parallel chunk tree hashing for large payloads |
| **Blake3 Lineage Chaining** | Single record header | **0.34 µs** / record | **~2,920,000 rec/s** | Header serialization & tamper-evident chaining |
| **Raw Mode Record Formation** | Header + SIMD CRC32 | **0.35 µs** / record | **2,825,085 rec/s** | High-throughput streaming without hashing overhead |
| **Forward-Secure Ratchet Step + MAC** | Single record step | **0.34 µs** / record | **~2,950,000 rec/s** | Ephemeral key derivation & anti-forgery MAC |
| **Combined Ingress Crypto Overhead** | Chaining + Ratchet MAC | **0.68 µs** / record | **~1,470,000 rec/s** | End-to-end cryptographic integrity per event |
| **Incremental MMR Leaf Insertion** | Leaf append & peak recalculation | **0.44 µs** / leaf | **~2,255,000 leaves/s** | Merkle Mountain Range root update |
| **MMR Inclusion Proof Gen + Verify** | Proof generation and validation | **2.56 µs** / proof | **~391,000 proofs/s** | $O(\log N)$ cryptographic leaf existence proof |
| **64 KB Coalesced Block Proof Verify** | Intra-block Merkle audit | **< 1.0 µs** / record | **> 1,000,000 rec/s** | Validates record membership within 64 KB chunk |
| **Shamir (2,3) Secret Reconstruction** | Galois Field $GF(2^8)$ interpolation | **0.42 µs** / key | **~2,380,000 ops/s** | 2-of-3 secret recovery & instant key disposal |
| **Zero-Knowledge Blind Indexing** | HMAC-SHA256 salted token | **0.13 µs** / tag | **~7,770,000 tags/s** | Deterministic blind search tokens over ciphertext |
| **Succinct ZK-SNARK Batch Verification** | Groth16 pairing check | **< 5.0 ms** / proof | **128-byte proof** | Verifies full partition batch validity zero-knowledge |
| **Ed25519 Digital Signing** | Gateway & witness action receipts | **9.85 µs** / sign | **~101,500 signs/s** | Non-repudiation of gateway receipts |
| **Ed25519 Signature Verification** | Offline audit signature check | **19.51 µs** / verify | **~51,200 verifs/s** | Zero-trust offline receipt validation |

---

## 2. ⚡ Adaptive Dual-Mode Storage Engine (`TopicMode`)

Vortex provides configurable topic storage modes tailored to distinct operational profiles:

```
┌────────────────────────────────────────────────────────────────────────┐
│                      VORTEX TOPIC INGESTION MODES                      │
├───────────────────────────────────┬────────────────────────────────────┤
│ TopicMode::Raw                    │ TopicMode::StrictProof             │
│ • Hardware CRC32 Checksum         │ • Blake3 Chained Cryptographic Lineage│
│ • Direct Kernel Zero-Copy Splicing│ • Forward-Secure Ephemeral Ratchet │
│ • 2,825,085 rec/s Line-Rate       │ • Incremental Merkle Mountain Range│
│ • Latency: 0.35 µs / record       │ • Latency: 4.13 µs / record        │
│ • High-Throughput Analytics & Logs│ • Tamper-Evident Flight-Recorder   │
└───────────────────────────────────┴────────────────────────────────────┘
```

### Storage Engine Measured Performance

| Operation | Mode / Configuration | Measured Latency | Measured Throughput | Storage Bandwidth |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Line-Rate Streaming** | `TopicMode::Raw` (CRC32) | **0.35 µs** / record | **2,825,085 rec/s** | In-memory line-rate stream |
| **StrictProof Cryptographic Ingestion** | `TopicMode::StrictProof` (Blake3) | **4.13 µs** / record | **242,362 rec/s** | Full linear hash chain |
| **Batched Sequential Ingestion** | `AdaptiveLingerQueue` (chunk 500) | **4.44 µs** / record | **> 225,000 msgs/s** | 28.8 MB/s |
| **Concurrent Reader Lag Catchup** | 8 parallel workers (10,000 records)| Non-blocking | **~419,685 rec/s** | Non-interfering parallel read |
| **Offline Verification Scan** | CRC32 + Blake3 + MMR | **1.9 – 3.2 µs** / record | **310,000 – 526,000 rec/s** | 35.8 – 60.5 MB/s |
| **Physical Single-Commit Barrier** | Synchronous unbatched `fsync` | **10.92 ms** / commit | **92 commits/s** | APFS hardware barrier |

---

## 3. 📦 Cryptographic Block Coalescing (64 KB Leaves)

To maximize throughput and minimize cryptographic overhead in high-volume topics, Vortex coalesces sequential records into 64 KB leaf blocks:

1. **Intra-Block Merkle Tree:** Individual records are hashed and organized into a local binary Merkle tree within the 64 KB chunk.
2. **Single MMR Insertion:** Only the root hash of the 64 KB coalesced block is inserted as a leaf into the global partition Merkle Mountain Range.
3. **Logarithmic Reduction:** Reduces MMR depth, peak recalculations, and tree writes by **$>99\%$**.
4. **Coalesced Proofs:** Individual records obtain a compact `CoalescedBlockProof` linking the record hash to the intra-block root, which links directly to the MMR root.

| Coalescing Metric | Standard Uncoalesced Log | Vortex 64 KB Coalesced Log | Efficiency Improvement |
| :--- | :--- | :--- | :--- |
| **MMR Insertions (20 MB stream)** | 50,000 tree insertions | **312 block insertions** | **99.38% reduction** |
| **Peak Recalculations** | 50,000 updates | **312 updates** | **99.38% reduction** |
| **Proof Generation Time** | 2.56 µs / record | **< 1.0 µs / record** | **> 60% faster** |
| **Total MMR Disk Growth** | ~1.60 MB index space | **< 10 KB index space** | **99.37% disk savings** |

---

## 4. 🛡️ High-Cardinality Multi-Tenant GDPR Shredding & Shamir (2,3) DEK Custody

Vortex provides cryptographic Right-to-be-Forgotten deletion via ChaCha20-Poly1305 envelope encryption, an append-only WAL, and Shamir (2,3) Galois Field secret custody.

### Shamir (2,3) Threshold Custody
- Data Encryption Keys (DEKs) are split into 3 shares over Galois Field $GF(2^8)$ (`x^8 + x^4 + x^3 + x + 1`).
- Any 2 shares can reconstruct the 32-byte DEK in **0.42 µs**.
- Destroying any 2 shares makes the key mathematically irrecoverable, turning encrypted payloads into pure white noise without breaking outer log integrity.

| Metric | Measurement | Vortex Result |
| :--- | :--- | :--- |
| **Tenant Population** | High-cardinality isolated entities | **50,000 distinct tenant keys** |
| **Key Generation Rate** | OS CSPRNG key derivation | **0.42 µs / key** (~2,380,000 keys/sec) |
| **Shamir Reconstruction** | 2-of-3 Galois Field Lagrange interpolation | **0.42 µs / key** (~2,380,000 ops/sec) |
| **Group-Committed Shred Speed**| Group-committed WAL write & fsync | **132,209 – 197,833 shreds/sec** (5.05 – 7.56 µs / shred) |
| **Crash-Recovery Replay** | Replaying 2,000 WAL records on cold reboot | **0.35 ms** total recovery duration |
| **Key Resurrection Rate** | Post-recovery cryptographic validation | **0 resurrected keys (0.00% — Permanent Erasure)** |

---

## 5. 📂 Partition Hyperscaling & Bounded `FdPool`

Vortex utilizes an LRU file-descriptor pool (`FdPool`) that bounds open descriptors while keeping active tail append handles leased dynamically, eliminating operating system `EMFILE` exhaustion.

| Parameter | Stress Workload | Observed Outcome |
| :--- | :--- | :--- |
| **Active Partitions** | 300 active partition logs simultaneously open | **300 partitions initialized** in 4,955 ms |
| **Parallel Producer Pressure** | Concurrent appends across 300 partitions | **Completed in 4,585 ms** with zero descriptor contention |
| **Open Descriptors Capped** | Maximum concurrent open OS file descriptors | **Strictly capped at $\le 64$ descriptors** |
| **Segment Rollover Under Limit** | 150 successive rolls across dynamic segments | **Zero `EMFILE` errors; all tail writes succeeded** |
| **Historical Cold Reads** | Fetching historical segments via LRU pool | **Descriptors transparently leased and released on demand** |

---

## 6. 🔄 Proof-Chained Quorum Replication (PCQR)

PCQR provides distributed consensus and partition replication anchored directly to cryptographic hash chains and MMR roots:

- **Cryptographic Leader Terms:** Election terms and commit messages embed the leader's current epoch, term, and cryptographic parent hash.
- **Zero-Divergence Quarantine:** If a follower receives a proposed log branch whose parent hash does not match its local append head, the branch is immediately quarantined rather than silently overwritten.
- **Quorum Commit Acknowledgments:** High-water mark advancement requires acknowledgment from a strict majority ($\lfloor N/2 \rfloor + 1$) of nodes validating both offset and Blake3 hash agreement.

---

## 7. 🔍 Verifiable Autonomous Evidence & Roughtime Witness Notary

End-to-end evidence capture and audit pipeline verifying continuous action sequences, policy compliance, anti-clock tampering, and non-repudiation:

| Pipeline Stage | Sample Size | Duration | Rate / Latency | Verification Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Gateway Action Ingestion** | 50 actions | 2,019 ms | **40.4 ms** / action | Request + Policy + Receipt (4 durable commits/action) |
| **Roughtime Witness Notarization**| Monotonic reel append (`reel.wit`) | 11.0 ms | **11.0 ms** / checkpoint | Consistency check + anti-rollback timestamp verification |
| **End-to-End Offline Court Audit** | 50 actions (150 log records) | 9.3 – 10.6 ms | **100% verified** | Validates log hash chain, ratchet MACs, receipts & witness reel |
| **Succinct ZK-SNARK Verification** | Aggregated partition proof | < 5.0 ms | **Sub-5ms verify** | 128-byte Groth16 cryptographic batch verification |

---

## 8. 🌐 Network Loopback Streaming (`vortex-server` TCP)

Synchronous TCP streaming over loopback socket (`127.0.0.1:9092`) with unbatched produce (`linger = 0`) and full linear hash-chain audit on read:

| Scenario | Payload Size | Message Count | Ingestion Duration | Throughput | Bandwidth | Latency (p50) | Latency (p99) | Blake3 Audit |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| **Standard RTT** | 256 B | 10,000 | **0.268 s** | **37,316 msgs/s** | 12.53 MB/s | **24 µs** | **66 µs** | 100% verified in 0.019 s |
| **Sustained Load** | 512 B | 50,000 | **1.306 s** | **38,282 msgs/s** | 22.20 MB/s | **25 µs** | **50 µs** | 100% verified in 0.120 s |
| **100k Scale Check** | 512 B | 100,000 | **2.568 s** | **38,944 msgs/s** | 22.58 MB/s | **24 µs** | **53 µs** | 100% verified in 0.245 s |
| **Mega Payload** | 512 KiB | 100 | **0.112 s** | **889 msgs/s** | **444.64 MB/s** | 1,061 µs | 1,909 µs | 100% verified in 0.072 s |

---

## 9. ⚔️ Adversarial Resilience Scorecard (200 Harsh Real-World Scenarios)

The comprehensive adversarial test harness ([`test_200_harsh_scenarios.rs`](file:///Users/personal/Desktop/kafka/crates/vortex-storage/tests/test_200_harsh_scenarios.rs)) evaluates 200 adversarial conditions across all core subsystems:

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║       VORTEX 200-SCENARIO ADVERSARIAL STRESS SUITE & EMPIRICAL BENCHMARK MATRIX   ║
║  Rigorous Empirical Testing Across Storage, Notary, PCQR, Coalescing & Security   ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

| Scenario Group | Scenario Range | Attack Vectors Evaluated | Pass Rate | Result |
| :--- | :--- | :--- | :--- | :--- |
| **Bit-Rot & Tamper Invariant Checks** | Scenarios 001–050 | 1-bit flips in payload, header, CRC, Blake3 hashes, zero-length truncation, split headers | **50 / 50** | **100% Detected & Rejected** |
| **Roughtime Anti-Clock-Tampering** | Scenarios 051–100 | Monotonic clock rollbacks, excessive future time skew, offline reel header corruption | **50 / 50** | **100% Blocked & Fenced** |
| **PCQR Quorum Consensus & Quarantine** | Scenarios 101–150 | Stale terms, split-brain forks, divergent parent hashes, follower quorum disagreement | **50 / 50** | **100% Quarantined** |
| **Shamir Custody & 64 KB Block Coalescing** | Scenarios 151–200 | Incomplete share sets, duplicate indices, boundary crossings, intra-block proof tamper | **50 / 50** | **100% Green & Verified** |
| **Overall Scorecard** | **All 200 Scenarios** | **Full real-world adversarial stress battery** | **200 / 200** | **100% Passing (0 failures)** |

---

## 10. 🧹 Zero-Allocation Disk Scrubber & Bit-Rot Detection

```bash
./target/release/vortex-cli scrub --data-dir ./data/vortex_bench
```

The offline scrubber traverses `.vtx` segments without loading payload data into heap memory, verifying hardware CRC32 checksums, sequential offsets, and cryptographic Blake3 `prev_hash` links:

```
🔍 Initializing Vortex Autonomous Scrubber on: "./data/vortex_bench"
  ✅ Segment "00000000000000000000.vtx" | Scanned: 50,000 records (31,138,890 bytes) in 60 ms | Status: HEALTHY
  ✅ Segment "00000000000000000000.vtx" | Scanned: 10,000 records (3,658,890 bytes) in 9 ms   | Status: HEALTHY
  ✅ Segment "00000000000000000000.vtx" | Scanned: 100 records (52,439,590 bytes) in 25 ms    | Status: HEALTHY
🛡️ Scrub Complete: 3 segment(s) verified, 60,100 total records. Zero bit-rot detected.
```

---

## 11. 🧠 Memory & Operating System Footprint

| Measurement | Vortex Result | Operational Architecture |
| :--- | :--- | :--- |
| **Binary Footprint** | Broker: **~2.5 MB** / CLI: **~1.5 MB** / FFI: **~1.2 MB** | Self-contained, statically linked, zero external runtime dependencies |
| **Memory RSS (Active Load)** | **6.7 – 6.9 MB** | Flat memory profile sustained during 100,000 active streaming messages |
| **Garbage Collection Overhead** | **0.00 ms (Zero GC)** | Deterministic manual memory ownership via Rust RAII; no GC pauses |
| **Cold Port Bind Latency** | **< 4 ms** | Instant asynchronous socket bind on port 9092 |
| **Process Shutdown** | **Immediate** | Clean port release; all file descriptors and mmap regions unmapped |

---

## 12. 🔬 How to Reproduce All Benchmarks Locally

### 1. 200-Scenario Harsh Real-World Adversarial & Performance Matrix
Runs the full 200-scenario adversarial stress suite and prints the empirical scorecard:
```bash
cargo test --test test_200_harsh_scenarios -- --nocapture
```

### 2. Pure CPU Cryptographic & In-Process Storage Benchmark
Runs the comprehensive in-memory crypto, MMR proof, and evidence audit suite (completes in ~4s):
```bash
cargo run --release --example bench_perf -p vortex-ffi
```

### 3. Enterprise Adversarial Stress & Scaling Benchmark
Executes the high-cardinality GDPR shredder (50k tenants), 300-partition `FdPool` hyperscaling, multi-core Blake3 tree hashing, and consumer lag catchup:
```bash
cargo run --release --example enterprise_harsh_check -p vortex-ffi
```

### 4. TCP Loopback Streaming Benchmark
Start the release broker:
```bash
./target/release/vortex-server --host 127.0.0.1 --port 9092 --data-dir ./data/vortex_bench &
```

In a separate terminal, stream workloads and execute the autonomous scrub:
```bash
CLI=./target/release/vortex-cli
$CLI bench --topic bench-10k --messages 10000 --size 256
$CLI bench --topic bench-stream --messages 50000 --size 512
$CLI bench --topic bench-100k --messages 100000 --size 512
$CLI bench --topic mega-payloads --messages 100 --size 524288
$CLI scrub --data-dir ./data/vortex_bench
```
