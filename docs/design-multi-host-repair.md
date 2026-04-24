# Multi-Host Repair Protocol Design

> bd-m5wf.5.1 — Consensus-free multi-host repair coordination with
> optimistic ownership and deterministic tiebreak.

## 1. Problem Statement

FrankenFS V1.x repair is single-host only: one host runs `ffs repair`
against a block device image, and a `.<image>.ffs-repair-owner.json`
coordination record prevents concurrent access. V1.2 needs multiple
hosts to coordinate repair of the same image (e.g., in a shared-storage
cluster or replicated-image scenario) without distributed consensus.

**Constraints:**
- No distributed consensus (Raft/Paxos) — too complex for a filesystem tool
- No external coordination service (etcd, ZooKeeper)
- Must tolerate host crashes, network partitions, stale leases
- Must use asupersync exclusively (no tokio)
- Symbol generation is already deterministic (same seed = same symbols)

## 2. Ownership Model

### 2.1 Lease-Based Ownership

Each repair group is independently owned. Ownership is expressed as a
**coordination record** stored adjacent to the image:

```
.<image>.ffs-repair-owner.json
```

Record format:

```json
{
  "version": 1,
  "host_id": "a1b2c3d4-5678-9abc-def0-123456789abc",
  "hostname": "worker-03",
  "pid": 12345,
  "claimed_at": "2026-03-14T02:00:00Z",
  "lease_ttl_secs": 300,
  "lease_version": 9,
  "repair_generation": 42,
  "groups_owned": [0, 1, 2, 3]
}
```

**Lifecycle:**
1. Host reads coordination record (or creates if absent)
2. If record is absent or expired (`claimed_at + lease_ttl_secs < now`):
   - Host writes its own record with a new `claimed_at`
   - Ownership acquired
3. If record is present and NOT expired:
   - Another process/host owns the image — back off
4. During repair, host periodically **renews** lease (updates `claimed_at`)
5. On completion or crash, lease expires naturally

A live claim incarnation is identified by `(host_id, pid,
repair_generation, lease_version)`. A same-host process with a different
`pid` is treated as a different claimant until the existing lease expires;
this prevents two local repair processes from renewing or releasing each
other's claim.

### 2.2 Conflict Detection

If two hosts race to claim an expired lease:

1. Both read the expired record
2. Both write their own record
3. On next read, each process verifies its own claim incarnation is in the record
4. If mismatch: higher `repair_generation` wins; if generations match, deterministic tiebreak applies — lower `host_id` (lexicographic UUID comparison) wins
5. Losing host releases and retries after a backoff period

This is **optimistic concurrency**: conflicts are detected after the fact,
not prevented. The deterministic tiebreak ensures convergence without
communication.

### 2.3 Per-Group Granularity

For future fine-grained parallelism, the ownership record includes
`groups_owned`. Multiple hosts could own disjoint group sets. V1.2
implements whole-image ownership; per-group ownership is a future
extension point.

## 3. Symbol Exchange Protocol

### 3.1 Purpose

When Host B needs repair symbols that Host A has already computed and
stored, it can request them over the network instead of re-encoding
locally (which requires reading all source blocks).

### 3.2 Message Format

Simple request-response over TCP with length-prefixed framing:

```
Request:
  [4 bytes: message_type = 0x01 (SYMBOL_REQUEST)]
  [4 bytes: payload_len]
  [16 bytes: fs_uuid]
  [4 bytes: group_id]
  [8 bytes: min_generation]

Response:
  [4 bytes: message_type = 0x02 (SYMBOL_RESPONSE)]
  [4 bytes: payload_len]
  [4 bytes: status (0=ok, 1=not_found, 2=stale)]
  [8 bytes: generation]
  [4 bytes: symbol_count]
  [N * (4 + symbol_size) bytes: (esi, symbol_data) pairs]
```

### 3.3 Transport

- TCP listener bound to configurable port (default: 9741)
- All I/O via asupersync `Cx` with cooperative checkpoints
- Connection lifecycle: connect → request → response → close
- No persistent connections, no multiplexing (simplicity over throughput)
- TLS optional (out of scope for V1.2, document extension point)

### 3.4 Deterministic Symbol Equivalence

Because symbol seeds are derived from `blake3(fs_uuid || group)`, two
hosts independently encoding the same group produce identical symbols.
This means:
- Symbol exchange is an **optimization** (avoid re-read), not a
  correctness requirement
- A host can always fall back to local re-encoding
- Symbol integrity can be verified by re-deriving the seed and comparing

## 4. Failure Mode Analysis

### 4.1 Host Crash During Repair

**Scenario:** Host A crashes mid-repair with an active lease.

**Mitigation:** Lease expires after `lease_ttl_secs` (default 300s).
Any host can then claim. The dual-slot descriptor in symbol storage
ensures crash-safe symbol writes (incomplete writes are detected by
checksum validation on the descriptor slot).

**Impact:** At most `lease_ttl_secs` delay before another host can
take over. No data corruption risk — symbol writes are atomic via
the dual-slot protocol.

### 4.2 Network Partition

**Scenario:** Host A owns the lease but is network-partitioned from
the storage. Host B sees an expired lease and claims it.

**Mitigation:** Host A's next lease renewal fails (write error to
coordination record). Host A detects this and stops repair. Host B
proceeds. If Host A comes back and sees Host B's record, deterministic
tiebreak resolves.

**Impact:** Brief period where both hosts may have done redundant work
on the same group. Not harmful — symbol encoding is idempotent.

### 4.3 Stale Ownership Record

**Scenario:** Coordination record on disk has `host_id` of a host that
no longer exists (decommissioned).

**Mitigation:** Lease TTL handles this. After `lease_ttl_secs`, any
live host can claim. No manual intervention needed.

### 4.4 Split-Brain (Two Active Owners)

**Scenario:** Due to clock skew, two hosts both believe the lease is
expired and claim simultaneously.

**Mitigation:** Deterministic tiebreak (lower UUID wins). Both hosts
verify ownership after write. Loser backs off. Worst case: both hosts
do redundant work for one scrub cycle. Symbol writes are idempotent
(same seed → same symbols), so no corruption.

**Invariant:** At most one process/host writes repair symbols to any given
group at a time, enforced by the coordination record + post-write
verification.

### 4.5 Clock Skew

**Scenario:** Host clocks differ by more than `lease_ttl_secs`.

**Mitigation:** Use monotonic lease counters in addition to timestamps.
Each claim increments `repair_generation`. A host with a higher
`repair_generation` always wins regardless of timestamp.

## 5. Implementation Plan

### 5.1 Ownership Module (`ffs-repair/src/ownership.rs`)

```rust
pub struct RepairOwnership {
    host_id: Uuid,
    hostname: String,
    record_path: PathBuf,
    lease_ttl: Duration,
}

impl RepairOwnership {
    pub fn try_acquire(cx: &Cx, image_path: &Path) -> Result<Option<OwnershipGuard>>;
    pub fn renew(cx: &Cx, guard: &OwnershipGuard) -> Result<()>;
    pub fn release(cx: &Cx, guard: OwnershipGuard) -> Result<()>;
    pub fn is_owned_by_us(cx: &Cx, image_path: &Path) -> Result<bool>;
}
```

### 5.2 Coordination Record (`ffs-repair/src/ownership.rs`)

```rust
#[derive(Serialize, Deserialize)]
pub struct CoordinationRecord {
    pub version: u32,
    pub host_id: String,
    pub hostname: String,
    pub pid: u32,
    pub claimed_at: String,  // ISO 8601
    pub lease_ttl_secs: u64,
    pub lease_version: u64,
    pub repair_generation: u64,
    pub groups_owned: Vec<u32>,
}
```

### 5.3 Symbol Exchange (`ffs-repair/src/exchange.rs`)

Deferred to bd-m5wf.5.3. This design document specifies the wire
format; implementation follows.

## 6. Non-Goals

- Distributed consensus (Raft, Paxos, etc.)
- Persistent connections or connection pooling
- Encryption/authentication (extension point documented)
- Per-group concurrent ownership by different hosts (future)
- Automatic host discovery (hosts must be configured explicitly)
