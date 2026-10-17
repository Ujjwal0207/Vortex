# Vortex benchmarks (release, loopback)

Fresh end-to-end suite on the **release** broker (`rustc 1.98.1`, `--release`, TCP loopback `127.0.0.1:9092`).

**How to read this:** every ingest number is **one produce per TCP round-trip** (`linger = 0`). Not a batched client. Integrity is CRC32 plus a **linear** Blake3 `prev_hash` chain. After each ingest, `vortex-cli bench` re-reads records; `vortex-cli scrub` then walks the `.vtx` files on disk.

Data dir used for this suite: `./data/vortex_bench`.

---

## Environment

| | |
| :--- | :--- |
| Platform | Apple Silicon (macOS Darwin arm64) |
| Compiler | `rustc 1.98.1` `--release` |
| Transport | TCP loopback, port **9092** |
| Producer | Single synchronous pipeline |
| Integrity | CRC32 + Blake3 record chain |

---

## Headline ingest

| Scenario | Size | Count | Time | Throughput | Bandwidth | p50 | p99 | Blake3 audit |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| Standard RTT | 256 B | 10,000 | **0.268 s** | **37,316 msgs/s** | 12.53 MB/s | **24 µs** | **66 µs** | 100% in 0.019 s |
| Sustained load | 512 B | 50,000 | **1.306 s** | **38,282 msgs/s** | 22.20 MB/s | **25 µs** | **50 µs** | 100% in 0.120 s |
| 100k scale | 512 B | 100,000 | **2.568 s** | **38,944 msgs/s** | 22.58 MB/s | **24 µs** | **53 µs** | 100% in 0.245 s |
| Large payload | 512 KiB | 100 | **0.112 s** | 889 msgs/s | **444.64 MB/s** | 1,061 µs | 1,909 µs | 100% in 0.072 s |

100k p95 was **32 µs**. Payload on disk for 100k × 512 B was **62,288,890 bytes** (~62.3 MB including headers).

---

## Run details

### 1. Standard RTT — 10,000 × 256 B

```bash
./target/release/vortex-cli bench --topic bench-10k --messages 10000 --size 256
```

| Metric | Result |
| :--- | :--- |
| Ingest time | **0.268 s** |
| Throughput | **37,316 msgs/s** |
| Bandwidth | **12.53 MB/s** |
| p50 / p99 | **24 µs / 66 µs** |
| Chain audit | **✅ 100% of 10,000** in **0.019 s** |

### 2. Sustained load — 50,000 × 512 B

```bash
./target/release/vortex-cli bench --topic bench-stream --messages 50000 --size 512
```

| Metric | Result |
| :--- | :--- |
| Ingest time | **1.306 s** |
| Throughput | **38,282 msgs/s** |
| Bandwidth | **22.20 MB/s** |
| p50 / p99 | **25 µs / 50 µs** |
| Chain audit | **✅ 100% of 50,000** in **0.120 s** |

### 3. 100,000 × 512 B (live scale check)

```bash
./target/release/vortex-cli bench --topic bench-100k --messages 100000 --size 512
```

```
🚀 Ingesting 100,000 events...
  -> Progress:  20.0% (20,000 / 100,000 events)
  -> Progress:  40.0% (40,000 / 100,000 events)
  -> Progress:  60.0% (60,000 / 100,000 events)
  -> Progress:  80.0% (80,000 / 100,000 events)
  -> Progress: 100.0% (100,000 / 100,000 events)
📊 ---------------- BENCHMARK RESULTS ----------------
  Total Duration       : 2.568 s
  Throughput           : 38,944.15 msgs/sec
  Bandwidth            : 22.58 MB/sec
  Latency (p50)        : 24 µs (0.024 ms)
  Latency (p95)        : 32 µs (0.032 ms)
  Latency (p99)        : 53 µs (0.053 ms)
✅ AUDIT PASSED: 100% of 100,000 records cryptographically verified
   with zero bit-rot in 0.245s
```

Sparse index at 62.3 MB: ~970 entries (one per 64 KB). Region A holds 4,080 slots (~23% used).

### 4. Large payload — 100 × 512 KiB

```bash
./target/release/vortex-cli bench --topic mega-payloads --messages 100 --size 524288
```

| Metric | Result |
| :--- | :--- |
| Ingest time | **0.112 s** |
| Throughput | **889 msgs/s** |
| Bandwidth | **444.64 MB/s** |
| p50 / p99 | **1,061 µs / 1,909 µs** |
| Chain audit | **✅ 100% of 100** in **0.072 s** |

---

## Disk scrub (after ingest)

```bash
./target/release/vortex-cli scrub --data-dir ./data/vortex_bench
```

First pass (10k + 50k + mega, **60,100** records):

```
🔍 Initializing Vortex Autonomous Scrubber on: "./data/vortex_bench"
  ✅ Segment "00000000000000000000.vtx" | Scanned: 50,000 records (31,138,890 bytes) in 60 ms | Status: HEALTHY
  ✅ Segment "00000000000000000000.vtx" | Scanned: 10,000 records (3,658,890 bytes) in 9 ms   | Status: HEALTHY
  ✅ Segment "00000000000000000000.vtx" | Scanned: 100 records (52,439,590 bytes) in 25 ms    | Status: HEALTHY
🛡️ Scrub Complete: 3 segment(s) verified, 60,100 total records. Zero bit-rot detected.
```

100k topic:

```
🔍 Initializing Vortex Autonomous Scrubber on: "./data/vortex_bench/bench-100k"
  ✅ Segment "00000000000000000000.vtx" | Scanned: 100,000 records (62,288,890 bytes) in 133 ms | Status: HEALTHY
🛡️ Scrub Complete: 1 segment(s) verified, 100,000 total records. Zero bit-rot detected.
```

---

## Memory & process

| Measurement | Result |
| :--- | :--- |
| RSS during 10k+50k+mega (~87 MB on disk, 60,100 records) | **6,992 KB (~6.9 MB)** |
| RSS during 100k × 512 B | **~6.7 MB** |
| Cold bind of port 9092 | **&lt; 4 ms** |
| Shutdown | Port 9092 released; no leaked FDs reported |

Broker streams into mmap / append-only `.vtx` files; it does not keep the full log as a heap copy.

---

## Reproduce

Broker:

```bash
./target/release/vortex-server --host 127.0.0.1 --port 9092 --data-dir ./data/vortex_bench
```

Clients (separate terminal):

```bash
CLI=./target/release/vortex-cli
$CLI bench --topic bench-10k --messages 10000 --size 256
$CLI bench --topic bench-stream --messages 50000 --size 512
$CLI bench --topic bench-100k --messages 100000 --size 512
$CLI bench --topic mega-payloads --messages 100 --size 524288
$CLI scrub --data-dir ./data/vortex_bench
```

---

## Earlier recovery note

A previous lab `kill -9` during writes still recovered the same data directory through offset `99999` with no duplicate keys in that test. It was not re-run as part of this suite.
