# 🌀 Vortex: Official Performance Benchmarks & Verification Report

This document records performance, tail latency, memory, and hash-chain audit times for the **Vortex** broker as run on the author's machine.

**How to read this:** ingest numbers are **one produce per TCP round-trip** on loopback — not a batched client. Integrity is CRC32 plus a **linear** Blake3 `prev_hash` chain (not a Merkle tree).

---

## 💻 Test Environment

* **Platform:** Apple Silicon (macOS Darwin arm64)
* **Compiler:** `rustc 1.98.1` (`--release` profile)
* **Transport:** TCP loopback (`127.0.0.1:9092`)
* **Concurrency:** Single synchronous producer
* **Integrity:** CRC32 + Blake3 record chain (`prev_hash` / `record_hash`)

---

## 📦 Build artifacts (this tree, `--release`)

| Artifact | Size (as measured) |
| :--- | :--- |
| `vortex-server` | **~2.5 MB** |
| `vortex-cli` | **~1.5 MB** |
| Cold start (listen) | **< 10 ms** |
| RSS after 100k msgs / ~100 MB data | **9.9 MB** (`ps`) |

---

## 📊 Run 1 — 10,000 messages (256 B)

```bash
./target/release/vortex-cli bench --topic bench-10k --messages 10000 --size 256
```

| Metric | Result |
| :--- | :--- |
| **Total ingestion time** | **0.252 s** |
| **Throughput** | **39,704.15 msgs/s** |
| **Bandwidth** | **13.33 MB/s** |
| **p50** | **22 µs (0.022 ms)** |
| **p95** | **40 µs (0.040 ms)** |
| **p99** | **58 µs (0.058 ms)** |
| **Chain audit** | **✅ 100% of 10,000 records** |
| **Audit time** | **0.018 s** (~555,000 records/s) |

---

## 🚀 Run 2 — 50,000 messages (512 B)

```bash
./target/release/vortex-cli bench --topic bench-stream --messages 50000 --size 512
```

| Metric | Result |
| :--- | :--- |
| **Total ingestion time** | **1.18 s** |
| **Throughput** | **42,342 msgs/s** |
| **Bandwidth** | **24.55 MB/s** |
| **p50** | **21 µs (0.021 ms)** |
| **p99** | **54 µs (0.054 ms)** |
| **Chain audit** | **✅ 100% of 50,000 records** |
| **Audit time** | **0.118 s** |

---

## 📈 Run 3 — 100,000 messages (512 B)

```bash
./target/release/vortex-cli bench --topic huge-100k --messages 100000 --size 512
```

| Metric | Result |
| :--- | :--- |
| **Total ingestion time** | **2.296 s** |
| **Throughput** | **43,560.99 msgs/s** |
| **Bandwidth** | **25.26 MB/s** |
| **p50** | **22 µs (0.022 ms)** |
| **p95** | **28 µs (0.028 ms)** |
| **p99** | **40 µs (0.040 ms)** |
| **Chain audit** | **✅ 100% of 100,000 records** |
| **Audit time** | **0.229 s** (~436,680 records/s) |

---

## ⚡ Run 4 — Mega-payload (100 × 512 KiB)

```bash
./target/release/vortex-cli bench --topic mega-payloads --messages 100 --size 524288
```

| Metric | Result |
| :--- | :--- |
| **Total ingestion time** | **0.057 s** (52 MB in 57 ms) |
| **Throughput** | **1,743.48 msgs/s** |
| **Bandwidth** | **871.90 MB/s** |
| **p50** | **540 µs (0.540 ms)** |
| **p99** | **1,075 µs (1.075 ms)** |
| **Chain audit** | **✅ 100% of 100 records** |
| **Audit time** | **0.073 s** |

---

## 🛡️ Chaos & stress

### Memory (100k messages)

* **RSS: 9.9 MB** after 100,000 messages and ~100 MB of data (`ps aux`).

### Hard crash (`kill -9`)

* Broker killed with `SIGKILL` during writes.
* Restart on the same data directory recovered indexes and served reads through offset **`99999`**, with **no corrupt records and no duplicate keys** in that test.

---

## Footprint snapshot (Vortex, this machine)

Same numbers that used to sit in the comparison table — kept here as **Vortex measurements**, not a bake-off.

| What we measured | Vortex (this repo, loopback unless noted) |
| :--- | :--- |
| Broker binary | **~2.5 MB** |
| CLI binary | **~1.5 MB** |
| RSS at 100k msgs | **~9.9 MB** |
| Cold start | **< 10 ms** |
| p50 (sync produce, 256–512 B) | **21–22 µs** |
| p99 (sync produce, 256–512 B) | **40–58 µs** |
| Peak ingest bandwidth (512 KiB payloads) | **871.90 MB/s** |
| Files per segment | **1 × `.vtx`** |
| Ingress rejects | routed to `{topic}.__quarantine` |
| Record integrity | CRC32 + Blake3 `prev_hash` chain |
