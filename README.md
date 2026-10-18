<div align="center">

```
 ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
 ██║   ██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
 ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝
 ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗
  ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
   ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

# Vortex

**A single-node Rust event log with a Blake3 hash chain, unified `.vtx` storage, and an ingress immune system.**

Produce and fetch over a custom TCP protocol (`VTX1`). Every record seals its predecessor. Leaked secrets can be caught **before disk**. Extra CLI labs demo crypto-shred, blind tags, and segment scrubbing.

> **v0.1.0** — one process, one data directory. Not a Kafka cluster, not a drop-in protocol, not multi-language SDKs. The benches below are **this machine, loopback, one produce per RTT**.

[Quick Start](#-quick-start) · [What ships](#-what-ships) · [Architecture](#-architecture) · [CLI playground](#-interactive-cli-playground) · [Protocol](#-vtx1-wire) · [Benchmarks](#-benchmarks) · [Crates](#-crate-map) · [Roadmap](#-roadmap)

<br/>

![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?style=for-the-badge&logo=rust)
![Status](https://img.shields.io/badge/v0.1.0-single--node-yellow?style=for-the-badge)
![Binary](https://img.shields.io/badge/Broker-2.5%20MB-0ea5e9?style=for-the-badge)
![RSS](https://img.shields.io/badge/RSS-6.7--6.9%20MB-22c55e?style=for-the-badge)
![p50](https://img.shields.io/badge/p50-24µs-a855f7?style=for-the-badge)
![p99](https://img.shields.io/badge/p99-50–66µs-111827?style=for-the-badge)
![Blake3](https://img.shields.io/badge/Blake3-hash%20chain-0ea5e9?style=for-the-badge)

</div>

---

## Jump in

| I want to… | Open |
| :--- | :--- |
| Boot a broker and round-trip a JSON event | [Quick Start](#-quick-start) |
| Know broker vs CLI-only features | [What ships](#-what-ships) |
| Click through produce → guard → `.vtx` | [Architecture](#-architecture) |
| Run `pii-check`, `shred-demo`, `blind-tag`, `scrub`, `bench` | [CLI playground](#-interactive-cli-playground) |
| Decode a `VTX1` frame and a record | [VTX1 wire](#-vtx1-wire) |
| See 10k / 50k / 100k / 512 KiB numbers | [Benchmarks](#-benchmarks) |

---

## What ships

Two layers. The **broker** is what `vortex-server` does on port 9092. The **CLI labs** are local tools in `vortex-cli` that exercise crates without always going through TCP.

| Capability | In the broker today | How to try it |
| :--- | :--- | :--- |
| Topics, partitions, produce, fetch-by-offset | Yes | `create-topic` / `produce` / `consume` |
| Unified `.vtx` (64 KB index + records) | Yes | data dir after produce |
| Blake3 **linear** chain + CRC32 | Yes (every append + `Record::decode`) | `bench` audit, `scrub` |
| Size cap (10 MB) + PII/secret scan → `{topic}.__quarantine` | Yes (`scan_pii` default on) | produce an `AKIA…` payload, or `pii-check` |
| Kafka wire protocol bridge (Port 9092) | Yes (Produce, Fetch, ListOffsets, Metadata, Group APIs) | Standard Kafka client connection |
| Consumer groups & offset WAL | Yes (member-epoch fencing, copy-on-write compacted WAL) | Connect consumer group on Port 9092 |
| Envelope encrypt + `shred_entity` (ChaCha20-Poly1305) | Library + **CLI demo** (in-memory registry, not persisted on produce) | `shred-demo` |
| Blind search tags | Library + **CLI** (`BlindIndexer`) — broker does not index tags yet | `blind-tag` |
| Segment bit-rot / chain walk | **CLI** `scrub` (not a background server thread) | `scrub --data-dir` |
| Clustering, replication, TLS | No | [Roadmap](#-roadmap) |

Atomic batch disk appends ensure multi-record batches are committed atomically without fracturing across segments.

<details>
<summary><strong>Hash chain (exact bytes hashed in <code>vortex-core</code>)</strong></summary>

<br/>

```
record_hash = Blake3(
    prev_hash ‖ offset_be64 ‖ timestamp_be64 ‖ key_len_be32 ‖ key ‖ val_len_be32 ‖ value
)
```

Genesis for a partition is keyed Blake3 over salt `VORTEX_STREAM_GENESIS_SALT_V1.00` + topic + partition id.

Produce responses include the new 32-byte `record_hash`. Flip a stored byte and `Record::decode` / `scrub` / `bench` audit fail at that offset. This is a **chain**, not a Merkle inclusion proof.

</details>

<details>
<summary><strong>Ingress guard (what actually runs on produce)</strong></summary>

<br/>

`IngressValidator` (`crates/vortex-guard`) on every `ProduceReq`, **before** `PartitionLog::append`:

1. Total key+value size vs `max_message_size` (default **10 MB**)
2. `PiiScanner` if `scan_pii` (default **true**): AWS `AKIA…`, PEM private keys, GitHub `ghp_`/`gho_`/`ghs_`/`ghr_`, OpenAI `sk-proj-` / `sk-`, Luhn credit cards. Binary/non-UTF-8 payloads **skip** the scanner.
3. Optional empty-payload reject (off by default)
4. Optional JSON object/array root (off by default)

Rejects become a `QuarantinedEvent` on `{topic}.__quarantine` and the producer gets an error frame.

</details>

---

## Architecture

```mermaid
flowchart TB
  subgraph You
    CLI["vortex-cli"]
  end

  subgraph TCP["127.0.0.1:9092 · VTX1"]
    FR["18-byte frame + CRC32 payload"]
  end

  subgraph Broker["vortex-server"]
    CONN["Tokio accept loop"]
    ENG["Engine"]
    G["IngressValidator + PiiScanner"]
    Q["topic.__quarantine"]
    P["PartitionLog · Mutex per partition"]
  end

  subgraph Disk["data/vortex/topic/partition-N/"]
    VTX["NNNN.vtx · 64 KB header + chained records"]
  end

  CLI -->|"create / produce / fetch / bench"| FR
  FR --> CONN --> ENG --> G
  G -->|secret / poison| Q
  G -->|ok| P --> VTX

  CLI -.->|"offline labs"| LABS["shred-demo · blind-tag · pii-check · scrub"]
```

```mermaid
sequenceDiagram
  participant C as vortex-cli
  participant S as vortex-server
  participant G as IngressValidator
  participant L as PartitionLog

  C->>S: ProduceReq (topic, partition, key, value)
  S->>G: size + PII scan
  alt leaked secret / oversize
    G-->>S: error
    S->>L: append QuarantinedEvent to topic.__quarantine
    S-->>C: ErrorResp
  else ok
    L->>L: Blake3(prev ‖ offset ‖ ts ‖ key ‖ val)
    L->>L: append .vtx + sparse index
    S-->>C: ProduceResp(offset, timestamp, record_hash)
  end
```

### `.vtx` layout

```
┌──────────────────────────────────────────────────────────────┐
│  REGION A   0x0000 – 0x10000   64 KB                         │
│  magic VTX1 · version · base_offset · genesis_hash · index   │
├──────────────────────────────────────────────────────────────┤
│  REGION B   0x10000 – EOF                                    │
│  [total_len 4][crc32 4][offset 8][ts 8]                      │
│  [prev_hash 32][record_hash 32][key][value] …                │
│  sparse index checkpoint ~ every 64 KB of payload            │
└──────────────────────────────────────────────────────────────┘
```

On-disk header before key/value is **96 bytes** (`RECORD_HEADER_SIZE`). Default segment roll is **64 MB**.

---

## Quick Start

**Needs** Rust 1.80+ (`rustc`, `cargo`).

```bash
git clone https://github.com/Ujjwal0207/Vortex.git
cd Vortex
cargo build --release
```

| Binary | Typical size | Role |
| :--- | :--- | :--- |
| `./target/release/vortex-server` | ~2.5 MB | Broker (`--host` `--port` `--data-dir`) |
| `./target/release/vortex-cli` | ~1.5 MB | Admin + labs |

### 1. Start the broker

```bash
./target/release/vortex-server --host 127.0.0.1 --port 9092 --data-dir ./data/vortex
```

Logs listen address and data directory. Override verbosity with `RUST_LOG=debug`.

### 2. Round-trip an event

```bash
CLI=./target/release/vortex-cli

$CLI create-topic --topic payments --partitions 1

$CLI produce --topic payments --key user-409 \
  --message '{"amount": 499.00, "status": "APPROVED"}'

$CLI consume --topic payments --from-offset 0 --limit 100
```

Produce prints **offset, timestamp, Blake3**. Consume prints offset / key / hash prefix / value.

### 3. Tests

```bash
cargo test --workspace
```

---

## Interactive CLI playground

Default `--broker 127.0.0.1:9092`. Expand a card, paste the command, match the sample output.

<details open>
<summary><code>create-topic</code> — partitions on disk</summary>

```bash
./target/release/vortex-cli create-topic --topic payments --partitions 1
```

```text
✅ Topic 'payments' created with 1 partition(s).
```

Creates `data/vortex/payments/partition-0/` (once you produce, a `000…0.vtx` appears).

| Flag | Default |
| :--- | :--- |
| `-t` / `--topic` | required |
| `-p` / `--partitions` | `1` |

</details>

<details>
<summary><code>produce</code> — append + hash on the ack</summary>

```bash
./target/release/vortex-cli produce \
  --topic payments --partition 0 --key user-409 \
  --message '{"amount": 499.00, "status": "APPROVED"}'
```

```text
✅ Event produced successfully! Offset: 0, Timestamp: 17…, Blake3: 0x…
```

One TCP request per message. Optional `-k` / `--key`.

</details>

<details>
<summary><code>consume</code> — fetch from an offset</summary>

```bash
./target/release/vortex-cli consume --topic payments --from-offset 0 --limit 10
```

Requests up to **1 MB**, prints at most `--limit` records.

</details>

<details>
<summary><code>pii-check</code> — same scanner the broker uses (no TCP required)</summary>

```bash
./target/release/vortex-cli pii-check \
  --message "Config loaded: AWS_KEY=AKIAIOSFODNN7EXAMPLE"
```

```text
🛡️ Scanning payload for secrets & compliance PII...
❌ Status: QUARANTINED (Ingress Policy Violation).
   Reason: Detected exposed AWS Access Key ID: 'AKIAIOSF...'
```

```bash
./target/release/vortex-cli pii-check --message "hello world"
```

```text
✅ Status: CLEAN. …
```

`--quarantine false` redacts instead of quarantine. On a **live broker**, producing the AWS string takes the same scanner and writes `{topic}.__quarantine`.

</details>

<details>
<summary><code>shred-demo</code> — GDPR-style DEK wipe (in-process lab)</summary>

```bash
./target/release/vortex-cli shred-demo --entity user-alice-42
```

```text
⚡ Cryptographic Shredding Ledger Demonstration …
   2. Encrypting payload with ChaCha20-Poly1305...
   3. Verifying decryption with active key... ✅
   4. Invoking GDPR shred_entity('user-alice-42')...
   5. Attempting post-shred decryption …
      Result: Entity '…' has been cryptographically shredded …
```

Uses `EntityKeyRegistry` in RAM with a demo master key. **Does not rewrite `.vtx` files.** After shred, ciphertext is unreadable; the log bytes stay put so the Blake3 chain still verifies.

Optional `--payload '…'` to encrypt your own string.

</details>

<details>
<summary><code>blind-tag</code> — salted Blake3 tag for encrypted fields</summary>

```bash
./target/release/vortex-cli blind-tag --value "Alice.Smith@bank.com"
```

```text
🔐 Zero-Knowledge Blind Search Tag:
   Input Value: "Alice.Smith@bank.com"
   Salt Hash:   0x…
   Blind Tag:   0x…64 hex chars…
```

`--salt` defaults to `vortex-default-salt`. Values are trimmed + lowercased before hashing (`vortex-blind-index-v1:` domain). The **broker does not store or query tags yet** — this is the primitive for a later index.

</details>

<details>
<summary><code>scrub</code> — walk `.vtx` files for CRC and chain breaks</summary>

```bash
./target/release/vortex-cli scrub --data-dir ./data/vortex
```

```text
🔍 Initializing Vortex Autonomous Scrubber on: "./data/vortex"
  ✅ Segment "00000000000000000000.vtx" | Scanned: N records (…) in T ms | Status: HEALTHY
🛡️ Scrub Complete: 1 segment(s) verified, N total records. Zero bit-rot detected.
```

Default `--data-dir` is `./data`. Point it at the **same directory as the broker** (`./data/vortex`). Recurses for `*.vtx`. This is an **on-demand CLI walk**, not a daemon inside `vortex-server`.

</details>

<details>
<summary><code>bench</code> — ingest + full chain audit</summary>

```bash
./target/release/vortex-cli bench --topic bench-stream --messages 50000 --size 512
```

Creates the topic, sync-produces N payloads, then fetches and verifies every `record_hash` against `prev_hash`.

| Flag | Default |
| :--- | :--- |
| `-t` / `--topic` | `bench-stream` |
| `-m` / `--messages` | `10000` |
| `-s` / `--size` | `256` |

</details>

---

## VTX1 wire

Magic **`0x56545831`** (`VTX1`), version **1**. Header **18 bytes**, then CRC32 of the payload.

```
┌────────┬─────────┬──────────┬────────┬─────────────┬────────┬──────────┐
│ magic  │ version │ msg_type │ req_id │ payload_len │ crc32  │ payload  │
│ 4B     │ 1B      │ 1B       │ 4B     │ 4B          │ 4B     │ N        │
└────────┴─────────┴──────────┴────────┴─────────────┴────────┴──────────┘
```

| Type | Name | Who |
| :---: | :--- | :--- |
| 1 / 2 | ProduceReq / ProduceResp | client ↔ broker (`offset`, `timestamp`, `[u8;32]` hash) |
| 3 / 4 | FetchReq / FetchResp | start offset + max bytes → encoded `Record`s |
| 5 / 6 | CreateTopicReq / Resp | partition count |
| 7 / 8 | Metadata | reserved (returns unsupported) |
| 9 | ErrorResp | code + message |

<details>
<summary><strong>Record on disk / in FetchResp</strong></summary>

```
total_len:u32 | crc32:u32 | offset:u64 | timestamp:u64
prev_hash:32 | record_hash:32 | key_len:i32 | key | val_len:u32 | value
```

`key_len = -1` means no key.

</details>

---

## Crate map

```mermaid
flowchart LR
  CLI[vortex-cli]
  SRV[vortex-server]
  CORE[vortex-core]
  STOR[vortex-storage]
  GUARD[vortex-guard]
  PROTO[vortex-protocol]

  CLI --> PROTO
  CLI --> CORE
  CLI --> STOR
  CLI --> GUARD
  SRV --> PROTO
  SRV --> CORE
  SRV --> STOR
  SRV --> GUARD
  STOR --> CORE
  GUARD --> CORE
  PROTO --> CORE
```

| Crate | Path | Responsibility |
| :--- | :--- | :--- |
| **vortex-core** | `crates/vortex-core` | `Record`, Blake3 chain, `EntityKeyRegistry`, `BlindIndexer` |
| **vortex-storage** | `crates/vortex-storage` | `.vtx` mmap, sparse index, `Scrubber` |
| **vortex-guard** | `crates/vortex-guard` | Size/JSON policy, `PiiScanner`, quarantine events |
| **vortex-protocol** | `crates/vortex-protocol` | VTX1 frames and codecs |
| **vortex-server** | `crates/vortex-server` | Tokio TCP + `Engine` |
| **vortex-cli** | `crates/vortex-cli` | Human CLI, bench, labs |

Workspace: Edition 2021, Tokio 1.38, Blake3 1.5, `chacha20poly1305` 0.10.

---

## Benchmarks

**Lab:** Apple Silicon (macOS arm64), `rustc 1.98.1` `--release`, TCP **loopback** `127.0.0.1:9092`, **one synchronous producer** (one produce per RTT). After ingest, the CLI re-reads records and checks the Blake3 chain.

These are **Vortex-on-this-machine** figures. They are not a same-hardware bake-off with Kafka.

### Headline table

| Run | Command | Time | Throughput | Bandwidth | p50 | p99 | Chain audit |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| 10k × 256 B | `bench --messages 10000 --size 256` | **0.268 s** | **37,316 msgs/s** | 12.53 MB/s | **24 µs** | **66 µs** | 100% in 0.019 s |
| 50k × 512 B | `bench --messages 50000 --size 512` | **1.306 s** | **38,282 msgs/s** | 22.20 MB/s | **25 µs** | **50 µs** | 100% in 0.120 s |
| 100k × 512 B | `bench --messages 100000 --size 512` | **2.568 s** | **38,944 msgs/s** | 22.58 MB/s | **24 µs** | **53 µs** | 100% in 0.245 s |
| 100 × 512 KiB | `bench --messages 100 --size 524288` | **0.112 s** | 889 msgs/s | **444.64 MB/s** | 1,061 µs | 1.91 ms | 100% in 0.072 s |

### Footprint & crash

| Measurement | Result |
| :--- | :--- |
| `vortex-server` / `vortex-cli` | **~2.5 MB / ~1.5 MB** |
| RSS under load (60k–100k msgs) | **6.7 – 6.9 MB** (`ps`) |
| Cold port 9092 bind | **&lt; 4 ms** |
| `kill -9` during writes | Restart served through offset **`99999`**, no duplicate keys in that test |

Reproduce:

```bash
./target/release/vortex-cli bench --topic bench-10k --messages 10000 --size 256
./target/release/vortex-cli bench --topic bench-stream --messages 50000 --size 512
./target/release/vortex-cli bench --topic bench-100k --messages 100000 --size 512
./target/release/vortex-cli bench --topic mega-payloads --messages 100 --size 524288
```

Full write-up: **[BENCHMARKS.md](BENCHMARKS.md)**.

---

## Limits (so the playground stays honest)

| Reality in v0.1.0 | Why it matters |
| :--- | :--- |
| Single-node event engine | Clustering and distributed replication are planned for future versions |
| Plaintext TCP | TLS encryption is not yet enabled on the listener |
| 64 KB sparse index (~4080 entries) | Very large segments can stop adding index points |
| PII scan is UTF-8 text only | Avro/Protobuf/compressed blobs are not inspected |
| Shred registry is in-memory | Broker restart forgets shredded entity IDs unless you persist keys (not built) |
| Kafka API subset | Supported APIs are strictly pinned; unadvertised versions return error code 35 |
| ReadCommitted isolation | Fails closed safely with error code 43 until transaction coordinator completes |

---

## Roadmap

Order is meant to keep the small binary, ~10 MB RSS path, and linger=0 produce working. Clustering should stay a **feature flag**, not the default server.

| | Intent | Status |
| :--- | :--- | :--- |
| **Now** | `.vtx` log, VTX1, Blake3 chain, PII quarantine, CLI labs | **This tree** |
| **Next** | Batched produce, per-partition tasks, explicit `acks` | Planned |
| | Merkle **batch** proofs + offline verify | Planned |
| | Retention / lineage manifest; compaction as a new generation | Planned |
| | CLI linger + cooperative groups (one node) | Planned |
| | Metadata Raft + hash-equal replica acks (`cluster` feature) | Planned |
| | `vortex-py` / Kafka protocol subset; TLS; compression | Later |

Until those land, treat Vortex as a **single-node, hash-chained log** you can build, quarantine, scrub, and bench.

---

<div align="center">

**Vortex** · Rust workspace · `cargo test --workspace`

`cargo build --release && ./target/release/vortex-server`

</div>
