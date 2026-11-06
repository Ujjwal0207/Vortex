# Vortex Benchmarks & Performance Engineering

Comprehensive empirical benchmark suite on the **release** broker (`rustc 1.80+`, `--release`, Apple Silicon Darwin arm64).

This document details latency, throughput, hardware efficiency, and cryptographic overhead across all architectural layers of Vortex: pure CPU cryptography, in-process storage engine, partition hyperscaling, consumer catchup, autonomous evidence audit, and TCP network streaming.

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

---

## ⚡ Executive Performance Summary

| Tier / Workload | Metric / Scale | Result | Latency Profile | Guarantee |
| :--- | :--- | ---: | ---: | :--- |
| **Mega-Payload Tree Hashing** | 50 × 2.0 MB (100 MB total) | **~4,940 MB/s** | 0.41 ms / 2 MB record | Rayon SIMD multi-threaded Blake3 hashing |
| **Ingress Crypto Chaining** | Blake3 Chain + Ratchet MAC | **~1,470,000 rec/s** | 0.68 µs / record | Forward-secure tamper-evident lineage |
| **Incremental MMR Insertion** | Dynamic peak updates | **~2,255,000 leaves/s** | 0.44 µs / leaf | $O(\log N)$ append-only tree commitment |
| **MMR Inclusion Proofs** | Proof generation + verification | **~391,000 proofs/s** | 2.56 µs / proof | Cryptographic historical auditability |
| **GDPR Key Shredding** | 50,000 tenant entity keys | **~197,800 shreds/s** | 5.05 µs / shred | Group-committed WAL; 0.00% resurrection |
| **Partition Hyperscaling** | 300 active partition logs | **Bounded $\le 64$ FDs** | Sub-millisecond appends | LRU descriptor pooling; 0 OS `EMFILE` errors |
| **Consumer Catchup** | 8 parallel worker threads | **~419,685 rec/s** | Non-blocking catchup | High concurrency under heavy writer pressure |
| **TCP Network Ingestion** | 100k × 512 B unbatched produce | **38,944 msgs/s** | p50: **24 µs**, p99: **53 µs** | CRC32 + linear Blake3 chain + 100% verified |
| **Memory Footprint (RSS)** | Sustained 100k streaming | **6.7 – 6.9 MB** | Flat memory profile | Zero garbage collection; zero heap bloat |

---

## 1. 🔐 Cryptographic & Zero-Knowledge Primitives (Pure CPU)

Measurements conducted in isolated memory-resident workloads to evaluate pure algorithmic performance without I/O interference:

| Operation | Workload | Latency | Throughput | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Multi-Core Tree Hashing (Blake3 SIMD)** | 2.0 MB record | **0.41 ms** / record | **~4,940 MB/s** | Parallel chunk tree hashing for large payloads |
| **Blake3 Lineage Chaining** | Single record header | **0.34 µs** / record | **~2,920,000 rec/s** | Header serialization & tamper-evident chaining |
| **Forward-Secure Ratchet Step + MAC** | Single record step | **0.34 µs** / record | **~2,950,000 rec/s** | Ephemeral key derivation & anti-forgery MAC |
| **Combined Ingress Crypto Overhead** | Chaining + Ratchet MAC | **0.68 µs** / record | **~1,470,000 rec/s** | End-to-end cryptographic integrity per event |
| **Incremental MMR Leaf Insertion** | Leaf append & peak recalculation | **0.44 µs** / leaf | **~2,255,000 leaves/s** | Merkle Mountain Range root update |
| **MMR Inclusion Proof Gen + Verify** | Proof generation and validation | **2.56 µs** / proof | **~391,000 proofs/s** | $O(\log N)$ cryptographic leaf existence proof |
| **Zero-Knowledge Blind Indexing** | HMAC-SHA256 salted token | **0.13 µs** / tag | **~7,770,000 tags/s** | Deterministic blind search tokens over ciphertext |
| **ChaCha20-Poly1305 Shredding** | Encrypt + memory zeroization | **0.91 µs** / entity | **~1,097,000 ops/s** | In-memory cryptographic envelope disposal |
| **Ed25519 Digital Signing** | Gateway & witness action receipts | **9.85 µs** / sign | **~101,500 signs/s** | Non-repudiation of gateway receipts |
| **Ed25519 Signature Verification** | Offline audit signature check | **19.51 µs** / verify | **~51,200 verifs/s** | Zero-trust offline receipt validation |

---

## 2. 🛡️ High-Cardinality Multi-Tenant GDPR Shredding

Vortex implements cryptographic Right-to-be-Forgotten deletion via ChaCha20-Poly1305 envelope encryption and an append-only WAL. Erasing an entity key turns all historical encrypted payloads into irreversible mathematical white noise without breaking the outer Blake3 hash chain.

| Metric | Measurement | Result |
| :--- | :--- | :--- |
| **Tenant Population** | High-cardinality isolated entities | **50,000 distinct tenant keys** |
| **Key Generation Rate** | OS CSPRNG key derivation | **0.42 µs / key** (~2,380,000 keys/sec) |
| **Group-Committed Shred Speed** | Group-committed WAL write & fsync | **132,209 – 197,833 shreds/sec** (5.05 – 7.56 µs / shred) |
| **Crash-Recovery Replay** | Replaying 2,000 WAL records on cold reboot | **0.35 ms** total recovery duration |
| **Key Resurrection Rate** | Post-recovery cryptographic validation | **0 resurrected keys (0.00% — Permanent Erasure)** |

---

## 3. 📂 Partition Hyperscaling & Bounded `FdPool`

Traditional storage systems hold open file descriptors for every active partition log, rapidly exhausting operating system limits (`EMFILE`) under high partition counts. Vortex utilizes an LRU file-descriptor pool (`FdPool`) that bounds open descriptors while keeping active tail append handles leased dynamically.

| Parameter | Stress Workload | Observed Outcome |
| :--- | :--- | :--- |
| **Active Partitions** | 300 active partition logs simultaneously open | **300 partitions initialized** in 4,955 ms |
| **Parallel Producer Pressure** | Concurrent appends across 300 partitions | **Completed in 4,585 ms** with zero descriptor contention |
| **Open Descriptors Capped** | Maximum concurrent open OS file descriptors | **Strictly capped at $\le 64$ descriptors** |
| **Segment Rollover Under Limit** | 150 successive rolls across dynamic segments | **Zero `EMFILE` errors; all tail writes succeeded** |
| **Historical Cold Reads** | Fetching historical segments via LRU pool | **Descriptors transparently leased and released on demand** |

---

## 4. 🚀 Concurrent Lagging Consumer Catchup

To evaluate reader isolation under active write contention, 8 concurrent worker threads performed catchup reads across 10,000 preloaded historical records while writer threads continued appending to the log:

| Metric | Result | Notes |
| :--- | :--- | :--- |
| **Preloaded History** | **10,000 records** | Fully indexed with 64 KB sparse index entries |
| **Concurrent Readers** | **8 parallel workers** | Non-blocking concurrent consumers |
| **Total Records Fetched** | **33,856 records** | Multi-threaded interleaved range reads |
| **Total Elapsed Duration** | **93.04 ms** | Sub-100ms total wall-clock execution |
| **Aggregate Catchup Throughput** | **~363,870 – 419,685 rec/sec** | Sustained high-throughput parallel read bandwidth |

---

## 5. 🏛️ In-Process Storage Engine Performance (`libvortex` C-ABI)

Direct storage engine throughput measured bypassing the network stack via the embeddable C-ABI:

| Operation | Workload | Latency / Commit | Throughput | Bandwidth |
| :--- | :--- | :--- | :--- | :--- |
| **Batched Sequential Append** | 10,000 records (chunk size 500) | **25.4 µs** / record | **39,344 rec/s** | 4.35 MB/s |
| **Offline Verification Scan** | 10,000 records (CRC32 + Blake3 + MMR) | **1.9 – 3.2 µs** / record | **310,000 – 526,000 rec/s** | 35.8 – 60.5 MB/s |
| **Physical Single-Commit Sync** | 20 individual atomic commits | **10.4 – 11.1 ms** / commit | ~90 – 96 commits/s | Atomic APFS fsync + `.commit` fence |

---

## 6. 🔍 Verifiable Autonomous Evidence & Witness Pipeline

End-to-end evidence capture and audit pipeline verifying continuous action sequences, policy compliance, and non-repudiation:

| Pipeline Stage | Sample Size | Duration | Rate / Latency | Verification Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Gateway Action Ingestion** | 50 actions | 2,019 ms | **40.4 ms** / action | Request + Policy + Receipt (4 durable commits/action) |
| **Witness Checkpoint & Countersign** | Tree size: 150 records | 11.0 ms | **11.0 ms** / checkpoint | Consistency check + monotonic Ed25519 countersignature |
| **End-to-End Offline Court Audit** | 50 actions (150 log records) | 9.3 – 10.6 ms | **100% verified** | Validates log hash chain, ratchet MACs, receipts & witness reel |

---

## 7. 🌐 Network Loopback Streaming (`vortex-server` TCP)

Synchronous TCP streaming over loopback socket (`127.0.0.1:9092`) with unbatched produce (`linger = 0`) and full linear hash-chain audit on read:

| Scenario | Payload Size | Message Count | Ingestion Duration | Throughput | Bandwidth | Latency (p50) | Latency (p99) | Blake3 Audit |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| **Standard RTT** | 256 B | 10,000 | **0.268 s** | **37,316 msgs/s** | 12.53 MB/s | **24 µs** | **66 µs** | 100% verified in 0.019 s |
| **Sustained Load** | 512 B | 50,000 | **1.306 s** | **38,282 msgs/s** | 22.20 MB/s | **25 µs** | **50 µs** | 100% verified in 0.120 s |
| **100k Scale Check** | 512 B | 100,000 | **2.568 s** | **38,944 msgs/s** | 22.58 MB/s | **24 µs** | **53 µs** | 100% verified in 0.245 s |
| **Mega Payload** | 512 KiB | 100 | **0.112 s** | **889 msgs/s** | **444.64 MB/s** | 1,061 µs | 1,909 µs | 100% verified in 0.072 s |

*Note: For the 100k × 512 B run, p95 latency was **32 µs**. Total payload on disk was **62,288,890 bytes** (~62.3 MB including headers). The sparse index contained ~970 entries (one every 64 KB).*

---

## 8. 🧹 Zero-Allocation Disk Scrubber & Bit-Rot Detection

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

**Adversarial Bit-Rot Injection Check:**
- An injected single-byte bit flip at byte position 65,656 in a historical segment immediately invalidates both the hardware CRC32 and Blake3 parent hash chain.
- The segment is instantly quarantined, preventing silent corruption from spreading down the stream.

---

## 9. 🧠 Memory & Operating System Footprint

| Measurement | Result | Notes |
| :--- | :--- | :--- |
| **Binary Footprint** | Broker: **~2.5 MB** / CLI: **~1.5 MB** / FFI: **~1.2 MB** | Self-contained, statically linked, zero external runtime dependencies |
| **Memory RSS (Active Load)** | **6.7 – 6.9 MB** | Sustained during 100,000 active streaming messages |
| **Garbage Collection Overhead** | **0.00 ms (Zero GC)** | Deterministic manual memory ownership via Rust RAII |
| **Cold Port Bind Latency** | **&lt; 4 ms** | Instant socket bind on port 9092 |
| **Process Shutdown** | **Immediate** | Clean port release; all file descriptors and mmap regions unmapped |

---

## 10. 🔬 How to Reproduce All Benchmarks

### 1. Pure CPU Cryptographic & In-Process Storage Benchmark
Runs the comprehensive in-memory crypto, MMR proof, and evidence audit suite (completes in ~4s):
```bash
cargo run --release --example bench_perf -p vortex-ffi
```

### 2. Enterprise Adversarial Stress & Scaling Benchmark
Executes the high-cardinality GDPR shredder (50k tenants), 300-partition `FdPool` hyperscaling, multi-core Blake3 tree hashing, and consumer lag catchup:
```bash
cargo run --release --example enterprise_harsh_check -p vortex-ffi
```

### 3. TCP Loopback Streaming Benchmark
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
