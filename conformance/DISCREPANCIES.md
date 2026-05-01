# Known Conformance Divergences

> Every intentional deviation from the reference specification is documented here.
> Tests for accepted divergences use XFAIL, not SKIP.

## Active Divergences

### DISC-001: ext4 Journal Replay Scope
- **Reference:** Linux kernel replays JBD2 journal on every mount
- **Our impl:** Replays journal once at open, subsequent opens skip if clean
- **Impact:** Mount after unclean shutdown requires explicit replay
- **Resolution:** ACCEPTED — intentional for FUSE userspace model
- **Tests affected:** ext4_journal_recovery.rs
- **Review date:** 2026-03-18

### DISC-002: btrfs Transaction Log Behavior
- **Reference:** Linux kernel transaction log is write-ahead
- **Our impl:** MVCC store replaces transaction log semantics
- **Impact:** Different crash recovery model (MVCC WAL vs btrfs log)
- **Resolution:** ACCEPTED — MVCC is architectural choice per spec §11
- **Tests affected:** btrfs_transaction_* tests
- **Review date:** 2026-03-18

### DISC-003: ext4 mballoc Buddy Allocator Heuristics
- **Reference:** Linux kernel uses buddy system with complex heuristics
- **Our impl:** Simplified allocator without all buddy optimizations
- **Impact:** Allocation patterns may differ, fragmentation characteristics differ
- **Resolution:** ACCEPTED — semantically correct, performance differs
- **Tests affected:** alloc_pattern_* benchmarks
- **Review date:** 2026-03-27

### DISC-004: btrfs Delayed Refs Full Semantics
- **Reference:** Linux kernel queues all reference updates via delayed refs
- **Our impl:** V1 uses an explicit `DelayedRefQueue` + `BtrfsRef` model with bounded batch flushing into materialized extent refcounts instead of cloning the full kernel delayed-ref machinery
- **Impact:** Internal queue shape and scheduling differ from Linux, but supported allocator/transaction operations must be refcount-equivalent, retry-safe, and failure-atomic
- **Resolution:** ACCEPTED — V1 scoped model. Evidence includes deterministic queue/refcount tests, two 1000-case delayed-ref properties, 10,000-reference stress coverage, transaction failure nonvisibility, `delayed_ref_queue_failed_flush_is_atomic_for_refcounts`, and `delayed_ref_queue_insert_overflow_is_atomic` for retry-safe failed batches.
- **Tests affected:** `property_delayed_refs_seed_*`, `delayed_ref_queue_*`, `flush_delayed_refs_*`, `btrfs_tx_adversarial_delayed_ref_failure_leaves_no_visible_records`
- **Review date:** 2026-05-01

### DISC-005: FUSE Protocol Version
- **Reference:** Latest FUSE protocol supports up to 7.40
- **Our impl:** Targets FUSE 7.31 (libfuse 3.x baseline)
- **Impact:** Missing some newer operations (FUSE_COPY_FILE_RANGE, etc.)
- **Resolution:** ACCEPTED — sufficient for V1 scope
- **Tests affected:** fuse_e2e.rs capability tests
- **Review date:** 2026-04-13

## Resolved Divergences (Historical)

### DISC-R001: btrfs RAID56 Parity Rotation (RESOLVED)
- **Reference:** Linux kernel uses left-symmetric parity rotation
- **Our impl:** Originally used right rotation (increasing index)
- **Resolution:** FIXED in commit 862b145 — now matches upstream
- **Resolved date:** 2026-04-13

### DISC-R002: ext4 Directory Checksum Tail Validation (RESOLVED)
- **Reference:** Strict validation of dir_entry_tail
- **Our impl:** Originally allowed malformed tails
- **Resolution:** FIXED in commit 34deb14 — strict validation added
- **Resolved date:** 2026-04-13

---

## Divergence Policy

1. Every divergence gets a sequential ID (DISC-NNN)
2. Status: ACCEPTED | INVESTIGATING | WILL-FIX
3. Must list affected test cases
4. Must include review date (divergences can become stale)
5. Resolved divergences move to Historical section with DISC-RNNN IDs

*Last updated: 2026-04-15*
