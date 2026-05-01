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
- **Our impl:** Simplified delayed ref handling without full queueing
- **Impact:** Reference counting order may differ during heavy writes
- **Resolution:** INVESTIGATING — `bd-rchk2` must either prove the current bounded queue/refcount model with executable heavy-write evidence, implement missing delayed-ref lifecycle behavior, or split/accept a narrower divergence.
- **Tests affected:** btrfs_delayed_ref_* tests
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
