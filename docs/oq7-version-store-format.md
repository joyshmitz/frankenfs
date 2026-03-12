# OQ7 Decision Record: Durable Version-Store Persistence Format

**Status:** Accepted
**Date:** 2026-03-12
**Bead:** bd-h6nz.6.7
**Resolves:** OQ7 (COMPREHENSIVE_SPEC_FOR_FRANKENFS_V1.md §21.2)
**Depends on:** OQ1 (bd-h6nz.6.1, resolved 2026-03-12)

## Context

FrankenFS uses MVCC for snapshot-isolated block access. The in-memory
`MvccStore` holds versioned block data, but must persist committed versions
to survive restarts. The persistence format must be crash-safe, replayable,
and support GC/compaction.

## Decision

### Accepted Format: WAL v1 (Append-Only Commit Log)

The durable version-store uses an append-only Write-Ahead Log (WAL) with
per-record CRC32C integrity and checkpoint acceleration.

**Wire format (normative, spec §5.9.4):**

```
File Header (16 bytes):
  magic:          u32 LE  = 0x4D56_4357 ("MVCW")
  version:        u16 LE  = 1
  checksum_type:  u16 LE  = 0 (CRC32C)
  reserved:       8 bytes = 0

Commit Record (variable):
  record_len:     u32 LE  (excludes self)
  record_type:    u8      = 1 (COMMIT)
  commit_seq:     u64 LE  (strictly increasing)
  txn_id:         u64 LE
  num_writes:     u32 LE
  writes[]:       repeated {block_number: u64 LE, data_len: u32 LE, data: [u8]}
  record_crc32c:  u32 LE  (over record_type..writes)
```

**Canonicalization rules:**
1. Writes sorted by ascending block_number
2. At most one write per block_number per commit
3. Last staged bytes win if a transaction writes the same block multiple times
4. `commit_seq == u64::MAX` and `txn_id == u64::MAX` are reserved sentinels

### Crash Consistency

| Crash Point | Replay Result |
|-------------|---------------|
| Before append starts | Commit absent |
| Mid-record (truncated) | Commit absent; tail discarded |
| After append, before sync | Absent or present (never partial) |
| After sync returns | Commit present |

### Recovery Procedure

1. Validate file header (magic, version, checksum_type)
2. Scan records sequentially from offset 16
3. For each decodable record: verify CRC, check monotonicity, apply
4. On first NeedMore/Corrupted/non-monotonic: stop and truncate tail
5. Output: last_commit_seq, records_discarded

### Checkpoint + Compaction

Checkpoints provide fast startup by snapshotting the entire version store:

```
Checkpoint File:
  magic:        u32 LE  = 0x4D56_4350 ("MVCP")
  version:      u16 LE  = 1
  reserved:     u16     = 0
  next_txn:     u64 LE
  next_commit:  u64 LE
  num_blocks:   u32 LE
  blocks[]:     repeated {block_number, num_versions, versions[]}
  crc32c:       u32 LE  (over entire content)
```

Recovery: load checkpoint, then replay WAL from checkpoint's commit_seq + 1.

Compaction: barrier at GC watermark, emit new WAL with live versions only,
atomic rename.

### Durable Invariants (D1-D8)

| ID | Invariant |
|----|-----------|
| D1 | Commit sequence in durable stream is strictly increasing |
| D2 | A replayed commit is all-or-nothing (never partial writes) |
| D3 | Truncated/corrupt tail cannot mutate previously replayed state |
| D4 | One block appears at most once in a commit record |
| D5 | commit() success in crash-safe mode implies synced durable bytes |
| D6 | Replay is deterministic for identical byte input |
| D7 | next_commit_seq after replay is last_commit_seq + 1 |
| D8 | Reserved sentinel IDs (u64::MAX) are never accepted |

### Versioning and Evolution

1. `WAL_VERSION` controls incompatible wire changes
2. Reserved header bytes MUST be zero; readers MAY ignore non-zero for diagnostics
3. Unknown `record_type` is a hard replay boundary (discard tail)
4. Future checksum algorithms require new `checksum_type` value

## Alternatives Considered

### Alternative A: B-Tree / Indexed Versioning

**Rejected.** Tree-structured index with per-block version chains.

- Adds complexity to crash recovery (tree rebalancing mid-failure)
- Read-heavy during normal operation (index lookups per version query)
- Compaction requires tree restructuring

**Expected loss:** High implementation complexity, medium recovery risk.

### Alternative B: Column-Oriented Snapshots

**Rejected.** Store each snapshot as a separate column file.

- Requires materializing all snapshots before commit visibility
- Snapshot count explosion with high commit rate
- Backward-incompatible if schema changes

**Expected loss:** High storage overhead, high complexity.

### Alternative C: Raw Block Copies (No Commit Framing)

**Rejected.** Append block data without commit records.

- No atomic commit boundary; partial writes undetectable
- No version metadata (txn_id, commit_seq) for replay
- Cannot support multiple writes to same block in single transaction

**Expected loss:** Fatal — violates crash-safety requirement.

## Implementation Status

| Component | Location | Status |
|-----------|----------|--------|
| WAL encoding/decoding | ffs-mvcc/src/wal.rs | Production |
| WAL replay | ffs-mvcc/src/persist.rs | Production |
| Checkpoint save/load | ffs-mvcc/src/persist.rs | Production |
| PersistentMvccStore | ffs-mvcc/src/persist.rs | Production |
| Compression/dedup | ffs-mvcc/src/compression.rs | Production |
| Evidence ledger | ffs-mvcc/src/lib.rs | Production |
| Append-only writer (bd-h6nz.1.2) | — | Blocked, now unblocked |

## Validation Matrix

| Decision Rule | Invariant | Unit Test | E2E Scenario |
|---------------|-----------|-----------|--------------|
| WAL format v1 header | — | `wal_header_roundtrip` | `vs_format_header` |
| Commit record encode/decode | D1, D6 | `MVCC_DURABLE_WAL_001` | `vs_format_commit_roundtrip` |
| Truncated tail discarded | D2, D3 | `MVCC_DURABLE_WAL_002` | `vs_format_truncated_tail` |
| Corrupt CRC rejected | D2, D3 | `MVCC_DURABLE_WAL_003` | `vs_format_corrupt_crc` |
| Non-monotonic seq rejected | D1 | `MVCC_DURABLE_WAL_004` | `vs_format_monotonic` |
| Sync required for crash-safe | D5 | `MVCC_DURABLE_WAL_005` | `vs_format_sync_required` |
| Checkpoint + replay deterministic | D6, D7 | `MVCC_DURABLE_WAL_006` | `vs_format_checkpoint_replay` |
| Reserved sentinels rejected | D8 | `wal_rejects_reserved_sentinels` | `vs_format_sentinels` |
| Canonical write ordering | D4 | `wal_canonicalizes_writes` | — |

## Follow-On Implementation Beads

- **bd-h6nz.1.2** (Append-only durable MVCC log writer): NOW UNBLOCKED.
  Must implement WalWriter with buffered append, fsync strategy, short-write
  recovery, backpressure integration, and structured logging per spec §5.9.10.
- **bd-h6nz.6.8** (Integrate OQ decisions into specs): Must reference this
  decision record.

## Structured Logging Contract

| Event | Level | Required Fields |
|-------|-------|-----------------|
| `wal_append_start` | debug | operation_id, commit_seq, txn_id |
| `wal_append_ok` | info | operation_id, commit_seq, txn_id, bytes_written |
| `wal_sync_ok` | info | operation_id, commit_seq |
| `wal_sync_err` | error | operation_id, commit_seq, error_class |
| `wal_replay_start` | info | operation_id, wal_bytes |
| `wal_replay_record_discarded` | warn | operation_id, offset, reason |
| `wal_replay_complete` | info | operation_id, commits_replayed, records_discarded |
| `checkpoint_save_ok` | info | operation_id, blocks, versions |
| `checkpoint_load_ok` | info | operation_id, blocks, checkpoint_seq |
