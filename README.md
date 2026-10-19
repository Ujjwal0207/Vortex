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

**A high-assurance, tamper-evident log engine and offline-verifiable evidence camera for autonomous service actions.**

*Engineered in Rust with Blake3 hash chaining, forward-secure ratchets, Merkle Mountain Ranges, and independent witness notarization.*

<br/>

[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/v0.1.0-production--ready%20core-yellow?style=for-the-badge)](https://github.com/Ujjwal0207/Vortex)
[![Binary Size](https://img.shields.io/badge/Broker-2.5%20MB-0ea5e9?style=for-the-badge)](file:///Users/personal/Desktop/kafka/crates/vortex-server)
[![Memory RSS](https://img.shields.io/badge/RSS-6.7--6.9%20MB-22c55e?style=for-the-badge)](file:///Users/personal/Desktop/kafka/BENCHMARKS.md)
[![p50 Latency](https://img.shields.io/badge/p50-24µs-a855f7?style=for-the-badge)](file:///Users/personal/Desktop/kafka/BENCHMARKS.md)
[![p99 Latency](https://img.shields.io/badge/p99-50--66µs-111827?style=for-the-badge)](file:///Users/personal/Desktop/kafka/BENCHMARKS.md)
[![Cryptography](https://img.shields.io/badge/Crypto-Blake3%20%7C%20Ed25519%20%7C%20ChaCha20-blue?style=for-the-badge)](file:///Users/personal/Desktop/kafka/crates/vortex-core)

<br/>

[Quick Start](#-quick-start) · [Core Capabilities](#-core-capabilities) · [System Architecture](#-system-architecture) · [Verifiable Evidence Pipeline](#-verifiable-evidence-pipeline) · [CLI Playground](#-interactive-cli-playground) · [C-ABI & Embeddable Engine](#-c-abi--embeddable-engine-libvortex) · [Cryptographic Trust Model](#-cryptographic-trust-model) · [Benchmarks](#-benchmarks--performance) · [Crate Ecosystem](#-crate-ecosystem)

</div>

---

## ⚡ Interactive Jump In

| I want to… | Section | Command / Target |
| :--- | :--- | :--- |
| **Run the full autonomous evidence demo** | [Quick Start](#1-run-the-end-to-end-evidence-pipeline-demo) | `vortex-cli agent-demo --output-dir ./demo_output` |
| **Audit an exported court bundle offline** | [Offline Audit](#2-perform-an-offline-zero-trust-audit) | `vortex-cli verify-evidence -d ./demo_output/court_bundle` |
| **Understand the 5-stage action evidence lifecycle** | [Evidence Pipeline](#-verifiable-evidence-pipeline) | Request → Policy → Executor → Checkpoint → Witness |
| **See physical `.vtx` disk & header layout** | [Storage Architecture](#unified-vtx-file-format) | 64 KB sparse index + 96-byte record headers |
| **Test GDPR cryptographic key shredding** | [Interactive Labs](#shred-demo--gdpr-cryptographic-key-shredding) | `vortex-cli shred-demo --entity user-alice-42` |
| **Check pre-disk secret & PII quarantine** | [Interactive Labs](#pii-check--pre-disk-secret-leak--pii-scanner) | `vortex-cli pii-check --message "AWS_KEY=AKIA..."` |
| **Embed Vortex via C-ABI / FFI in other runtimes** | [C-ABI Engine](#-c-abi--embeddable-engine-libvortex) | `vtx_open()`, `vtx_append()`, `vtx_verify_partition_with_seed()` |
| **Review formal guarantees and limits** | [Trust Boundary](#what-vortex-proves-vs-what-it-cannot-prove) | Complete truth table of verified vs unprovable claims |

---

## 🌟 Core Capabilities

### 1. 🛡️ Verifiable Action Evidence Camera
Traditional logging records what a service *asserts* happened. Vortex records **tamper-evident cryptographic evidence**:
- **Argument Commitment Privacy:** Tool call parameters are committed via `blake3::hash(args)`. Plaintext remains private while cryptographic commitment is anchored permanently.
- **Signed Executor Receipts:** Outcomes are signed directly by the executor service with Ed25519 keys; the gateway cannot fabricate or alter execution results.
- **Independent Witness Notarization:** Checkpoints are notarized by independent witnesses utilizing RFC 9162 consistency proofs over Merkle Mountain Ranges.
- **Three-Verdict Verification:** Offline audits output strict verdicts: `✅ Verified`, `❌ Rejected` (policy blocked), or `⚠️ Incomplete` (missing executor receipts or dropped actions). **Incomplete actions are never reported as success.**

### 2. 🔐 Continuous Cryptographic Lineage
- **Linear Blake3 Hash Chain:** Every record permanently seals the hash of its predecessor. Any flipped bit or torn write renders the entire subsequent log invalid.
- **Forward-Secure Ratchet ("Forge the Past Dies"):** Writer authentication MACs are generated via a forward-advancing cryptographic ratchet seeded with OS CSPRNG entropy (`getrandom`). Even if the active host key is compromised, historical records cannot be forged.
- **Two-Slot Crash-Safe Keyring:** Crash-resilient atomic slot updates guarantee state recovery across sudden power failure without key desynchronization.

### 3. 🌲 Logarithmic Merkle Mountain Ranges (MMR)
- **O(log N) Inclusion Proofs:** Authenticate that any historical record exists at a specific leaf index without scanning the log.
- **RFC 9162 Append-Only Consistency Proofs:** Cryptographically prove that the log at size $M$ is a strict, unmodified prefix of the log at size $N$.

### 4. 🧹 Autonomous Immune System & Clean Room Guard
- **Pre-Disk Ingress Quarantine:** Scans payloads in memory before writing to disk. Leaked credentials (AWS keys, GitHub tokens, PEM private keys, Luhn-valid credit cards) are quarantined to `{topic}.__quarantine`.
- **Zero-Allocation Scrubber:** Audits storage segments on disk for bit-rot, torn tails, and broken hash links.

### 5. ⚡ Privacy-Preserving Computation & Shredding
- **Split-Knowledge Key Shredding:** Instant GDPR/CCPA Right-to-be-Forgotten deletion via ChaCha20-Poly1305 envelope encryption. Erasing the entity key makes payload data mathematically irreversible white noise while the Blake3 log chain remains intact.
- **Zero-Knowledge Blind Indexing:** Computes deterministic blinded search tags over encrypted fields for fast routing and indexing without decrypting sensitive payloads.
- **Order-Revealing Encryption (ORE):** Supports range queries and monotonic ordering directly over ciphertext.

---

## 🏛️ System Architecture

```mermaid
flowchart TB
    subgraph ClientLayer["1. Ingress & Client Boundary"]
        Agent["Autonomous Agent / Service"]
        CLI["vortex-cli"]
        C_SDK["C-ABI (libvortex)"]
    end

    subgraph GatewayLayer["2. Policy Gateway & Ingress Guard"]
        GW["Action Gateway"]
        POL["Sentinel Policy Engine"]
        PII["PII & Secret Scanner"]
        RCPT["Receipts Log (receipts.jsonl)"]
    end

    subgraph StorageEngine["3. Immutable Append-Only Storage (.vtx)"]
        PART["PartitionLog Engine"]
        MMR["Merkle Mountain Range (MMR)"]
        CHAIN["Blake3 Hash Chain"]
        KEYRING["Two-Slot Keyring (0600)"]
        MACS["partition.macs (Writer Authentication)"]
    end

    subgraph WitnessLayer["4. Independent Witness Ledger"]
        WIT["Independent Witness Daemon"]
        STATE["witness_state.json"]
        REEL["reel.wit (Countersigned Checkpoints)"]
    end

    subgraph AuditLayer["5. Zero-Trust Offline Verifier"]
        VERIFIER["vortex-cli verify-evidence"]
        REPORT["Evidence Audit Report (✅/❌/⚠️)"]
        BUNDLE["Court Bundle Packager"]
    end

    Agent -->|"1. ActionRequest"| GW
    CLI -->|"Produce / Admin"| GW
    C_SDK -->|"Direct Embed"| PART

    GW --> POL
    GW --> PII
    POL -->|"Policy Decision"| PART
    GW -->|"Signed GatewayReceipt"| RCPT
    GW -->|"Committed Request"| PART

    PART --> CHAIN
    PART --> MMR
    PART --> KEYRING
    KEYRING --> MACS

    GW -->|"SignedCheckpoint"| WIT
    WIT -->|"Request Consistency Proof"| MMR
    WIT -->|"Verify Extension"| STATE
    WIT -->|"Emit Countersignature"| REEL

    VERIFIER --> PART
    VERIFIER --> RCPT
    VERIFIER --> REEL
    VERIFIER --> REPORT
    REPORT --> BUNDLE
```

---

## 📸 Verifiable Evidence Pipeline

When an autonomous agent or service interacts with external tools or executes state-modifying actions through the Vortex Gateway, the interaction passes through five distinct cryptographic verification stages:

```mermaid
sequenceDiagram
    autonumber
    participant Agent as Agent / Service
    participant Gateway as Action Gateway
    participant Executor as Tool / Executor
    participant Log as Vortex Partition (.vtx)
    participant Witness as Independent Witness

    Agent->>Gateway: Submit ActionRequest (Agent ID, Tool, Args)
    Note over Gateway: Computes Blake3(Args) Commitment<br/>Evaluates Sentinel Security Policy
    Gateway->>Log: Commit Stage 1 (Request) & Stage 2 (PolicyDecision)
    Gateway-->>Agent: Return signed GatewayReceipt (Seq N, Allowed/Denied)

    alt Action is Permitted
        Gateway->>Executor: Dispatch tool invocation
        Executor->>Executor: Execute action & sign result commitment
        Executor-->>Gateway: Return signed ExecutorReceipt
        Gateway->>Log: Commit Stage 3 (ExecutorReceipt)
    else Action is Blocked
        Note over Gateway: Tool execution suppressed.<br/>Signed denial anchored in log.
    end

    Note over Gateway: Periodic Checkpoint Emission
    Gateway->>Gateway: Compute {tree_size, mmr_root} & sign Checkpoint
    Gateway->>Witness: Submit SignedCheckpoint
    Witness->>Log: Request MMR Consistency Proof (old_size → new_size)
    Note over Witness: Validates tree consistency.<br/>Rejects split-views or history shrinkage.
    Witness->>Witness: Sign WitnessCountersignature
    Witness-->>Gateway: Persist to reel.wit
```

### The Three Audit Verdicts

The offline verifier analyzes log continuity, receipts, and witness reels to produce a definitive classification for every action:

| Verdict | Meaning | Cryptographic Conditions |
| :---: | :--- | :--- |
| **`✅ Verified`** | **Complete & Notarized** | All 5 stages present; Gateway, Executor, and Witness signatures valid; monotonic sequence unbroken; leaf index anchored in witness reel. |
| **`❌ Rejected`** | **Explicitly Denied** | Security policy blocked execution; signed proof of denial committed to log; no tool execution occurred. |
| **`⚠️ Incomplete`** | **Unfulfilled / Severed** | Request was approved, but tool execution crashed, hung, or disconnected before the executor receipt was committed. **Never treated as success.** |

---

## 🚀 Quick Start

### Build Prerequisites
- **Rust 1.80+** (`rustc`, `cargo`)
- Operating Systems: macOS (Apple Silicon / Intel), Linux (x86_64, aarch64), Windows

```bash
git clone https://github.com/Ujjwal0207/Vortex.git
cd Vortex
cargo build --release
```

Compiled release binaries will be located in `./target/release/`:
- `vortex-cli`: CLI management tool, offline verifier, and interactive labs.
- `vortex-server`: High-performance TCP event broker daemon.
- `libvortex.dylib` / `libvortex.so`: Embedded C-ABI shared library.

---

### 1. Run the End-to-End Evidence Pipeline Demo

Run the automated simulation demonstrating 10 autonomous actions (successful execution, policy-blocked rogue tools, severed calls, witness consistency notarization, and court bundle packaging):

```bash
./target/release/vortex-cli agent-demo --output-dir ./demo_output
```

```text
===============================================================================
        VORTEX AUTONOMOUS ACTION VERIFIABLE EVIDENCE PIPELINE DEMO
===============================================================================

🔑 1. Initializing Cryptographic Identities & Escrowed Genesis Seed...
   • Gateway Ed25519 Pubkey: 0x9886cf1b89b209755e43e8a85acb7ee585f24a9aca85880adbf5fcb21d61283a
   • Executor Ed25519 Pubkey: 0x7c860e983bee3b981afdad13abeae872fa2348e6b31f46f7aed2bd2dcfc2c4bd
   • Witness Ed25519 Pubkey: 0xbbac7b42141e70f782352dc21d01132484e85824bb371d83def17661990d39d1

🛡️ 2. Starting Agent-Action Gateway with Security Policy (Sentinel v1.0)...
👁️ 3. Initializing Independent Witness (RFC 9162 Monotonic Ledger)...

⚡ 4. Routing 10 Autonomous Agent Tool Calls through Gateway Boundary...
   [ 1/10] Action act-001 | Agent: finance-agent   | Tool: transfer_funds              -> Allowed & Executed (Seq 0) ✅
   [ 2/10] Action act-002 | Agent: rogue-agent     | Tool: delete_production_database  -> BLOCKED by Sentinel Policy ❌
   [ 3/10] Action act-003 | Agent: k8s-operator    | Tool: deploy_container            -> Allowed & Executed (Seq 5) ✅
   [ 4/10] Action act-004 | Agent: data-pipeline   | Tool: ingest_telemetry            -> Allowed & Executed (Seq 8) ✅
   [ 5/10] Action act-005 | Agent: untrusted-plugin| Tool: exfiltrate_keys             -> BLOCKED by Sentinel Policy ❌
   [ 6/10] Action act-006 | Agent: secops-bot      | Tool: rotate_tls_cert             -> Allowed & Executed (Seq 13) ✅
   [ 7/10] Action act-007 | Agent: flaky-agent     | Tool: call_external_webhook       -> Allowed, but Tool Severed/Timed Out (Seq 16) ⚠️
   [ 8/10] Action act-008 | Agent: storage-janitor | Tool: prune_temp_files            -> Allowed & Executed (Seq 18) ✅
   [ 9/10] Action act-009 | Agent: analytics-agent | Tool: build_daily_report          -> Allowed & Executed (Seq 21) ✅
   [10/10] Action act-010 | Agent: monitor-agent   | Tool: assert_latency_sla          -> Allowed & Executed (Seq 24) ✅

🏛️ 5. Emitting Final Gateway Checkpoint & Performing Witness Consistency Audit...
   • Gateway Checkpoint: seq=1, tree_size=27, mmr_root=0xcd1ccca79c2e17b6
   • Generated MMR Consistency Proof: old_size=13, new_size=27, peak_proofs=3
   • Independent Witness VERIFIED consistency and countersigned into reel.wit ✅

🔍 6. Executing Zero-Trust Offline Verifier (No Daemons, No Network)...
===============================================================================
               VORTEX OFFLINE EVIDENCE AUDIT REPORT
===============================================================================
Topic/Partition:      agent-audit:0
Gateway Trust Root:   0x9886cf1b89b209755e43e8a85acb7ee585f24a9aca85880adbf5fcb21d61283a
Witness Trust Root:   0xbbac7b42141e70f782352dc21d01132484e85824bb371d83def17661990d39d1
Hash Chain Integrity: ✅ VALID (Blake3 + CRC32)
Forward Secrecy MACs: ✅ VERIFIED (Ratchet replayed)
Witness Countersigns: ✅ MONOTONIC & SIGNED
Witnessed Tree Size:  27 entries
-------------------------------------------------------------------------------
ACTION VERDICTS (10 total):
  ✅ Verified:   7
  ❌ Rejected:   2
  ⚠️ Incomplete: 1
-------------------------------------------------------------------------------
  [✅ VERIFIED] Action: act-001      | Agent: finance-agent   | Tool: transfer_funds             | Seq: 0  | WitCkpt: 0
  [❌ REJECTED] Action: act-002      | Agent: rogue-agent     | Tool: delete_production_database | Policy: sentinel-v1.0 | Reason: Tool 'delete_production_database' is blocked by security policy
  [✅ VERIFIED] Action: act-003      | Agent: k8s-operator    | Tool: deploy_container           | Seq: 5  | WitCkpt: 0
  [✅ VERIFIED] Action: act-004      | Agent: data-pipeline   | Tool: ingest_telemetry           | Seq: 8  | WitCkpt: 0
  [❌ REJECTED] Action: act-005      | Agent: untrusted-plugin| Tool: exfiltrate_keys            | Policy: sentinel-v1.0 | Reason: Tool 'exfiltrate_keys' is blocked by security policy
  [✅ VERIFIED] Action: act-006      | Agent: secops-bot      | Tool: rotate_tls_cert            | Seq: 13 | WitCkpt: 1
  [⚠️ INCOMPLETE] Action: act-007    | Missing: ["Stage 3: ExecutorReceipt"] | Details: Tool call has no signed executor receipt (unfulfilled or severed)
  [✅ VERIFIED] Action: act-008      | Agent: storage-janitor | Tool: prune_temp_files           | Seq: 18 | WitCkpt: 1
  [✅ VERIFIED] Action: act-009      | Agent: analytics-agent | Tool: build_daily_report         | Seq: 21 | WitCkpt: 1
  [✅ VERIFIED] Action: act-010      | Agent: monitor-agent   | Tool: assert_latency_sla         | Seq: 24 | WitCkpt: 1
===============================================================================
📦 7. Packaging Offline Court Bundle into '"./demo_output/court_bundle"'...
   • Court bundle successfully exported with partition log, receipts, witness reel, pubkeys, and README.md ✅
```

---

### 2. Perform an Offline Zero-Trust Audit

You can audit the exported evidence package offline with zero dependencies, without running any server or network daemons:

```bash
./target/release/vortex-cli verify-evidence \
  --data-dir ./demo_output/court_bundle \
  --topic agent-audit \
  --partition 0
```

---

## 🧰 Interactive CLI Playground

<details open>
<summary><strong><code>verify-evidence</code> — Zero-Trust Offline Audit</strong></summary>

Audits log segments, forward-secure ratchet MACs, executor receipts, and witness notarizations:

```bash
./target/release/vortex-cli verify-evidence \
  -d ./demo_output/court_bundle \
  -t agent-audit \
  -p 0
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-d`, `--data-dir` | `./demo_output/court_bundle` | Path to storage directory or court bundle |
| `-t`, `--topic` | `agent-audit` | Topic name |
| `-p`, `--partition` | `0` | Partition ID |
| `-r`, `--receipts` | `<data-dir>/receipts.jsonl` | Path to receipts ledger |
| `-w`, `--witness-reel`| `<data-dir>/reel.wit` | Path to witness notarization reel |
| `-k`, `--pubkeys` | `<data-dir>/pubkeys.toml` | Path to trusted Ed25519 public keys |

</details>

<details>
<summary><strong><code>agent-demo</code> — Automated Pipeline Simulation</strong></summary>

Executes an autonomous evidence lifecycle simulation:

```bash
./target/release/vortex-cli agent-demo --output-dir ./test_evidence
```

Generates `.vtx` storage files, commits policy and execution stages, notarizes checkpoints with an independent witness, prints the audit verdict report, and packages an exportable court bundle.

</details>

<details>
<summary><strong><code>pii-check</code> — Pre-Disk Secret Leak & PII Scanner</strong></summary>

Tests the exact regex and Luhn scanning engine used by the broker's ingress immunizer:

```bash
./target/release/vortex-cli pii-check --message "Config: AWS_KEY=AKIAIOSFODNN7EXAMPLE"
```

```text
🛡️ Scanning payload for secrets & compliance PII...
❌ Status: QUARANTINED (Ingress Policy Violation).
   Reason: Detected exposed AWS Access Key ID: 'AKIAIOSF...'
```

```bash
./target/release/vortex-cli pii-check --message "Clean application telemetry payload"
```

```text
🛡️ Scanning payload for secrets & compliance PII...
✅ Status: CLEAN. No exposed credentials, private keys, or credit cards detected.
```

</details>

<details>
<summary><strong><code>shred-demo</code> — GDPR Cryptographic Key Shredding</strong></summary>

Demonstrates sub-millisecond cryptographic entity deletion (Right-to-be-Forgotten):

```bash
./target/release/vortex-cli shred-demo --entity user-alice-42
```

```text
⚡ Cryptographic Shredding Ledger Demonstration (GDPR Right-to-be-Forgotten):
   1. Generating derived 256-bit DEK for entity 'user-alice-42'...
   2. Encrypting payload with ChaCha20-Poly1305...
      Ciphertext (73 bytes): 0xd9f482...
   3. Verifying decryption with active key...
      Decrypted: "Patient medical record: diagnosis=confidential" ✅
   4. Invoking GDPR shred_entity('user-alice-42')...
      DEK zeroized from memory and marked shredded ✅
   5. Attempting post-shred decryption of immutable log payload...
      Result: Entity 'user-alice-42' has been cryptographically shredded (GDPR Right-to-be-Forgotten) 🛡️
      The append-only log remains untouched and Blake3 hash chain intact,
      but the data payload is mathematically rendered irreversible white noise.
```

</details>

<details>
<summary><strong><code>blind-tag</code> — Zero-Knowledge Search Tag Generator</strong></summary>

Computes deterministic, salted blind index tags for search operations over encrypted fields:

```bash
./target/release/vortex-cli blind-tag --value "alice.smith@domain.com"
```

```text
🔐 Zero-Knowledge Blind Search Tag:
   Input Value: "alice.smith@domain.com"
   Salt Hash:   0x3a4f89...
   Blind Tag:   0x7d921b... (64 hex characters)
   Broker can index & route on this tag without decrypting plaintext.
```

</details>

<details>
<summary><strong><code>scrub</code> — Storage Integrity & Bit-Rot Scrubber</strong></summary>

Walks `.vtx` segments, re-verifying CRC32 checksums and validating Blake3 hash continuity:

```bash
./target/release/vortex-cli scrub --data-dir ./demo_output/vortex_data
```

```text
🔍 Initializing Vortex Autonomous Scrubber on: "./demo_output/vortex_data"
  ✅ Segment "00000000000000000000.vtx" | Scanned: 27 records (12840 bytes) in 2 ms | Status: HEALTHY
🛡️ Scrub Complete: 1 segment(s) verified, 27 total records. Zero bit-rot detected.
```

</details>

<details>
<summary><strong><code>bench</code> — High-Throughput Ingestion & Verification</strong></summary>

Streams events over TCP loopback and immediately re-reads records to audit the hash chain:

```bash
./target/release/vortex-cli bench --topic bench-stream --messages 50000 --size 512
```

```text
⚡ Benchmarking 50,000 messages (512 bytes each) on topic 'bench-stream'...
   Produced 50,000 messages in 1.306s (38,282 msgs/sec, 22.20 MB/sec)
   Auditing 50,000 Blake3 hash links...
   ✅ Verified 50,000 records in 0.120s (100% hash chain unbroken).
```

</details>

---

## 💾 Unified `.vtx` File Format

Vortex stores event streams in unified `.vtx` segment files that combine pre-allocated sparse index checkpoints with continuous, append-only record regions.

```
┌────────────────────────────────────────────────────────────────────────┐
│  REGION A: HEADER & SPARSE INDEX (Offset 0x0000 – 0x10000, 64 KB)      │
├──────────────┬─────────────┬──────────────┬──────────────┬─────────────┤
│ magic: u32   │ version: u8 │ reserved: 3B │ base_off: u64│ genesis: 32B│
│ (0x56545831) │ (0x01)      │ [0x00; 3]    │ (base offset)│ (root hash) │
├──────────────┴─────────────┴──────────────┴──────────────┴─────────────┤
│ Sparse Index Table: ~4,080 index entries (relative_offset, file_pos)   │
├────────────────────────────────────────────────────────────────────────┤
│  REGION B: APPEND-ONLY DATA (Offset 0x10000 – EOF)                     │
├──────────────┬─────────────┬──────────────┬──────────────┬─────────────┤
│ total_len:4B │ crc32: 4B   │ offset: 8B   │ timestamp: 8B│ prev_hash32B│
├──────────────┴─────────────┴──────────────┴──────────────┴─────────────┤
│ record_hash: 32B           │ key_len: i32 │ key bytes    │ val_len: 4B │
├────────────────────────────┴──────────────┴──────────────┴─────────────┤
│ payload bytes (JSON, Protobuf, Avro, or binary)                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Sidecar Authentication Ledger (`partition.macs`)
For every record written to `.vtx`, a corresponding 32-byte MAC is derived from the forward-secure ratchet and committed to `partition.macs`. During offline audit, the verifier replays the ratchet from offset 0 to prove writer authenticity across all stored records.

---

## 🔌 C-ABI & Embeddable Engine (`libvortex`)

Vortex exports a C-compatible FFI ABI via [`include/vortex.h`](file:///Users/personal/Desktop/kafka/include/vortex.h), allowing native integration into C, C++, Python, Go, and mobile applications:

```c
#include "vortex.h"
#include <stdio.h>
#include <string.h>

int main() {
    // Open or create partition log
    VtxPartition* part = vtx_open("./data", "sensor-feed", 0, 64 * 1024 * 1024);
    if (!part) {
        printf("Failed to initialize partition\n");
        return 1;
    }

    // Authenticated Append
    const char* key = "sensor-42";
    const char* val = "{\"temp\": 21.4, \"status\": \"nominal\"}";
    uint64_t offset = 0;
    uint8_t record_hash[32];
    uint8_t writer_mac[32];

    vtx_append(part, 
               (const uint8_t*)key, strlen(key),
               (const uint8_t*)val, strlen(val),
               &offset, record_hash, writer_mac);

    printf("Committed Record: offset=%llu\n", (unsigned long long)offset);

    // Generate and verify O(log N) MMR proof
    VtxProof* proof = vtx_prove(part, offset);
    if (proof) {
        uint8_t root[32];
        vtx_root(part, root);

        bool valid = vtx_verify_proof(proof, root, record_hash);
        printf("MMR Inclusion Proof Verified: %s\n", valid ? "YES" : "NO");
        vtx_free_proof(proof);
    }

    vtx_close(part);
    return 0;
}
```

Compile with `clang`:
```bash
clang -I./include main.c -L./target/release -lvortex -o app
LD_LIBRARY_PATH=./target/release ./app
```

---

## 🔒 Cryptographic Trust Model

### Mathematical Formulas

#### 1. Blake3 Linear Hash Chain
Each record commits to its predecessor and its physical metadata:
$$\text{record\_hash} = \text{Blake3}(\text{prev\_hash} \parallel \text{offset}_{\text{be64}} \parallel \text{ts}_{\text{be64}} \parallel \text{key\_len}_{\text{be32}} \parallel \text{key} \parallel \text{val\_len}_{\text{be32}} \parallel \text{value})$$

#### 2. Forward-Secure Ratchet
At offset $i$, the key advances via a one-way function. Old keys cannot be reconstructed:
$$K_{i+1} = \text{Blake3}(\text{"vortex-ratchet-step-v1"} \parallel K_i \parallel i_{\text{be64}})$$
$$\text{MAC}_i = \text{Blake3\_Keyed}_{K_i}(\text{encoded\_record}_i)$$

#### 3. MMR Leaf Commitment
MMR leaves bind record content to position:
$$\text{leaf\_hash}_i = \text{Blake3}(\text{"vortex-mmr-leaf-v1"} \parallel i_{\text{be64}} \parallel \text{record\_hash}_i)$$

---

### What Vortex Proves vs. What It Cannot Prove

| Claim | Guaranteed? | Cryptographic Boundary |
| :--- | :---: | :--- |
| **Integrity of Routed Actions** | ✅ **YES** | Every action routed through the gateway is hash-chained and committed to the MMR. |
| **No Silent Record Dropping** | ✅ **YES** | Continuous sequence numbers and witness consistency proofs detect any omitted records. |
| **Non-Repudiation of Tool Execution** | ✅ **YES** | The executor signs its own result commitment; the gateway cannot fabricate executor results. |
| **Historical Tamper Immunity** | ✅ **YES** | Forward-secure ratchet destroys past keys; attackers with current state cannot forge past MACs. |
| **Universal Event Observation** | ❌ **NO** | Actions that bypass the gateway are invisible. The trust boundary is explicitly the gateway interface. |
| **Truthfulness of External Services** | ❌ **NO** | A signed executor receipt proves the executor generated that result; it does not prove the executor itself was uncompromised. |

---

## 📊 Benchmarks & Performance

Vortex includes comprehensive benchmarking tools designed to measure throughput, latency, and cryptographic overhead across all tiers of the system. The test suite is calibrated to run safely and deterministically on modern developer laptops without triggering thermal throttling, excessive SSD write wear, or memory bloat.

### 1. Cryptographic & Zero-Knowledge Primitives (Pure CPU)

Measurements conducted on Apple Silicon (`rustc --release`) with isolated in-memory workloads:

| Cryptographic Primitive | Latency | Throughput | Purpose |
| :--- | :--- | :--- | :--- |
| **Blake3 Lineage Chaining** | **0.34 µs** / record | **~2,920,000 rec/s** | Record header serialization & tamper-evident chaining |
| **Forward-Secure Ratchet Step + MAC** | **0.34 µs** / record | **~2,950,000 rec/s** | Ephemeral key derivation & historical tamper immunity |
| **Total Ingress Cryptographic Overhead** | **0.68 µs** / record | **~1,470,000 rec/s** | Combined Blake3 chaining + ratchet MAC per message |
| **Incremental MMR Leaf Insertion** | **0.45 µs** / leaf | **~2,235,000 leaves/s** | Dynamic peak recalculation & tree root updates |
| **MMR Inclusion Proof Gen + Verify** | **2.56 µs** / proof | **~390,000 proofs/s** | Compact $O(\log N)$ tamper-evident inclusion validation |
| **Zero-Knowledge Blind Indexing** | **0.13 µs** / tag | **~7,560,000 tags/s** | Salted deterministic blind index token derivation |
| **Ephemeral Key Shredding** | **0.87 µs** / entity | **~1,150,000 ops/s** | ChaCha20-Poly1305 encryption & in-memory key zeroization |
| **Ed25519 Digital Signing** | **9.85 µs** / sign | **~101,500 signs/s** | Gateway action receipts & witness checkpoints |
| **Ed25519 Signature Verification** | **19.65 µs** / verify | **~50,800 verifs/s** | Zero-trust offline verification of signed receipts |

---

### 2. High-Throughput In-Process Storage Engine (`libvortex` C-ABI)

Direct storage engine performance bypassing network sockets via the embeddable C-ABI:

| Operation | Workload | Latency / Commit | Throughput | Bandwidth |
| :--- | :--- | :--- | :--- | :--- |
| **Batched Sequential Append** | 10,000 records (chunk size 500) | **25.4 µs** / record | **39,344 rec/s** | 4.35 MB/s |
| **Offline Verification Scan** | 10,000 records (CRC32 + Blake3 + MMR) | **3.2 µs** / record | **310,829 rec/s** | 35.8 MB/s |
| **Physical Single-Commit Sync** | 20 individual atomic commits | **10.4 ms** / commit | ~96 commits/s | Atomic APFS fsync + `.commit` fence |

---

### 3. Verifiable Autonomous Evidence & Witness Pipeline

End-to-end evidence capture and audit pipeline verifying continuous action sequences and non-repudiation:

| Pipeline Stage | Sample Size | Duration | Rate / Latency | Verification Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Gateway Action Ingestion** | 50 actions | 2,019 ms | **40.4 ms** / action | Request + Policy + Receipt (4 durable commits/action) |
| **Witness Checkpoint & Countersign** | Tree size: 150 records | 11.0 ms | **11.0 ms** / checkpoint | Consistency check + monotonic Ed25519 countersignature |
| **End-to-End Offline Court Audit** | 50 actions (150 log records) | 10.6 ms | **100% verified** | Validates log hash chain, ratchet MACs, receipts & witness reel |

---

### 4. Network Loopback Streaming (`vortex-server` TCP)

Synchronous TCP streaming over loopback socket (`127.0.0.1:9092`) with full linear hash-chain audit on read:

| Workload | Ingestion Time | Throughput | Bandwidth | Latency (p50) | Latency (p99) | Verification Time |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| **10k × 256 B** | 0.268 s | **37,316 msgs/s** | 12.53 MB/s | **24 µs** | **66 µs** | 100% verified in 0.019 s |
| **50k × 512 B** | 1.306 s | **38,282 msgs/s** | 22.20 MB/s | **25 µs** | **50 µs** | 100% verified in 0.120 s |
| **100k × 512 B** | 2.568 s | **38,944 msgs/s** | 22.58 MB/s | **24 µs** | **53 µs** | 100% verified in 0.245 s |
| **100 × 512 KiB** | 0.112 s | **889 msgs/s** | **444.64 MB/s** | 1,061 µs | 1.91 ms | 100% verified in 0.072 s |

---

### 5. Resource Footprint & Laptop Durability Profile

- **Binary Footprint:** Broker is `~2.5 MB`, CLI is `~1.5 MB`, embeddable `libvortex.dylib` is `~1.2 MB`.
- **Memory RSS:** `6.7 – 6.9 MB` active memory usage during sustained streaming.
- **Laptop-Friendly Testing:** The entire comprehensive benchmark (`cargo run --release --example bench_perf -p vortex-ffi`) finishes in under **4 seconds**, utilizing bounded temporary directories with automatic cleanup to prevent disk bloat and unnecessary SSD wear.
- **Crash Recovery:** Sudden `kill -9` during active ingestion recovers to the last valid commit marker with zero record duplication or torn tails.

---

### Running the Benchmarks Locally

```bash
# 1. Run the comprehensive in-process crypto, storage, and evidence benchmark (runs in ~4s):
cargo run --release --example bench_perf -p vortex-ffi

# 2. Run the network streaming benchmark against a live broker:
./target/release/vortex-server --data-dir ./data &
./target/release/vortex-cli bench --topic bench-stream --messages 50000 --size 512
```

---

## 📦 Crate Ecosystem

The Vortex workspace is organized into modular Rust crates:

```
crates/
├── vortex-core       # Blake3 hash chain, MMR, forward-secure ratchet, ORE, blind indexing, evidence schemas
├── vortex-storage    # .vtx memory mapping, crash-safe keyring, gateway, witness, offline verifier, scrubber
├── vortex-guard      # Ingress security policy, PII scanner, secret quarantine engine
├── vortex-protocol   # VTX1 binary frame codecs and message serialization
├── vortex-server     # Tokio asynchronous TCP event broker engine
├── vortex-cli        # CLI interface, benchmark suites, evidence demo, and offline verification tools
└── vortex-ffi        # C-ABI shared library (libvortex) and C headers (vortex.h)
```

---

<div align="center">

**Vortex** · Built with precision in Rust · All 98 workspace tests verified passing.

`cargo test --workspace`

</div>
