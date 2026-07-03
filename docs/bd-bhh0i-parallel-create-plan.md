# bd-bhh0i — Parallel metadata-write scaling: implementation plan

**Status:** design (no code landed). Owner-lane, loom-gated, multi-turn.
**Author:** BlackThrush. **Proven payoff:** ~7x (see Ceiling below).

This consolidates ~10 turns of investigation (see the `docs/NEGATIVE_EVIDENCE.md`
rows dated 2026-07-03, commits `dc92e926`, `5e72f0f0`, `73815b0d`) into an
executable plan. It is the **sole substantive remaining perf lever**: every other
single-node ext4/btrfs read/write path is at its floor (I/O, HW-crc, mature
libzstd) or owned by a dependency (asupersync `Cx::for_request`). Do NOT re-profile
those — the answer is always "floor or bd-bhh0i".

## Symptom

In-process parallel `create-bench` into `/` NEGATIVE-scales:

| threads | creates/s |
| --- | --- |
| 1 | ~118k |
| 2 | ~110k |
| 4 | ~70k |
| 8 | ~63–65k |
| 16 | ~59k |

16 threads is *slower* than 1. The kernel is ~8.3x faster @8t.

## Scope — this is ALL parallel ext4 metadata WRITES, not just create

Every ext4 mutation op takes the SAME whole-state `alloc_mutex.write()`, so they
ALL convoy on it under parallelism (verified 2026-07-03): `ext4_create`
(lib.rs:16881), `ext4_mknod` (17030), `ext4_mkdir` (17197), `ext4_unlink_impl`
(19116), `ext4_link` (19364), `ext4_symlink` (19481), `ext4_fallocate` (19794),
and rename. So the shard+spread fix below lifts the parallel ceiling for the WHOLE
metadata-write surface, not only create — the proven ~7x create ceiling is the
per-op measurement, and the mechanism (single-lock convoy) is identical for the
rest. That broadens the payoff and is a reason to do the shared-infrastructure
work once (shard the lock + spread allocation) rather than per-op.

## Ceiling: PROVEN ~7x (why this is worth the effort)

Independent-process ceiling test (safe, unsafe-free, reusable): run N single-thread
`create-bench` on N **separate** image copies concurrently, aggregate vs single.
Warm: 1 proc ~118k; **8 independent procs ~747k aggregate (~7x)**; 8 threads/1 proc
= 65k (negative). ⚠️ WARM it first — a cold first run measured a misleading 1.7x
(page-cache/binary warmup).

Conclusion: the create **work** parallelizes ~7x. The in-process collapse is
*entirely* in-process shared-state serialization, and frankenfs's per-op work is
competitive with the kernel — the whole gap is recoverable.

## Root cause (two serializers, both must be fixed)

1. **Whole-state `alloc_mutex.write()`** (`ext4_create`, lib.rs:16881) is held for
   the ENTIRE op — `create_inode` (bitmap+GD alloc) AND `ext4_add_dir_entry`. Under
   one lock, creates are fully serialized, so the negative scaling is pure lock
   convoy (parking + cache-line bounce on the contended `RwLock`), NOT MVCC
   conflicts (the lock currently prevents concurrency, so no two creates write
   blocks at once).

2. **Shared inode-table-block RMW** (latent, EXPOSED by fixing #1). `create_inode`
   = `prepare_inode` (persists inode BITMAP + group-desc via
   `ffs_alloc::alloc_inode_persist`, ffs-inode/src/lib.rs:316) THEN `write_inode`
   (persists inode CONTENT, :426). Order is bitmap-before-content, so moving the
   content write out of the lock is crash-consistency-NEUTRAL (the window already
   exists). BUT `write_inode` does a read-modify-write of the shared inode-table
   block, and a same-parent storm packs new inodes into ADJACENT slots of the SAME
   inode-table block. Once #1 is sharded, concurrent content writes conflict on that
   one block → MVCC FCW reject/retry → re-serialized (this is exactly the
   shared-block-RMW coherence failure that killed the two prior attempts —
   `op_batch` 931cb6d8 on the GDT block, `convoy` stale-bitmap — now shown to
   generalize from the GDT block to inode-table blocks).

Note: the shared-GDT-block constraint is ALREADY GONE — `gdt_persistence_deferred()`
(ffs-alloc:1720) skips the per-op GD write, flushing once at the durability
boundary. So the remaining shared block is the inode-table block.

## No cheap shortcut (checked)

The `alloc_mutex` is ALREADY `parking_lot::RwLock<Ext4AllocState>` (lib.rs:82, 904)
— the fast, contention-optimized lock. So there is NO lock-implementation shortcut
(std→parking_lot is already done). The convoy is the whole-state-lock *design* (one
lock over all alloc state, held for the entire op), not the lock impl — the fix is
genuinely the sharding below.

## The two-part fix

**Part A — shard `alloc_mutex` per group.** Replace the single
`RwLock<Ext4AllocState>` with per-group locks (an array/sharded map of
`RwLock<GroupAllocState>`) over the mutable per-group state (bitmap, free counts),
with the immutable `geo` shared read-only and `persist_ctx` (GDT flush) separately
synchronized. A create locks only its target group's shard → disjoint-group creates
proceed concurrently.

**Part B — spread inode allocation across groups.** `alloc_inode_persist` currently
allocates in the PARENT's group (locality). Add a spreading policy so concurrent
creates land in DIFFERENT groups (hence different inode-table blocks), avoiding the
Part-A-exposed shared-block RMW. Options: round-robin by a per-CPU/per-thread hint,
or hash(parent, name). MUST stay e2fsck-clean (inodes in a non-parent group are
valid ext4). Keep locality for the single-threaded path (spread only under
contention, or accept a small locality loss — measure both).

Either part alone is INSUFFICIENT: Part A without B re-serializes on the shared
inode-table block; Part B without A is neutral (the single lock still serializes).

## Crash-consistency & correctness

- Bitmap-before-content ordering is preserved (unchanged): an interrupted create
  leaves an allocated-but-unwritten inode = e2fsck-reclaimable orphan, same as today.
- `ext4_add_dir_entry` publishes the name AFTER the inode content is written, so no
  reader can observe a half-built inode (nothing looks it up until the name exists).
- Same-parent creates still contend on the PARENT dir block (the dir-entry insert
  RMWs it). This is inherent (the kernel serializes same-dir inserts too via the dir
  i_rwsem); the win targets the inode-alloc + inode-content parallelism, which is the
  bulk of the per-op work (crc + MVCC memmove).

## Gating (do not skip)

- **loom** model of the sharded alloc + spread + MVCC commit ordering (the
  publication gate is an in-order Condvar barrier, sharded.rs:72 — verify no
  deadlock/lost-update under reordering).
- `create-bench --threads {1,2,4,8,16}` scaling curve must go POSITIVE (target: 8t ≥
  4x single-thread; stretch: approach the ~7x independent-process ceiling).
- `create-bench 3000 → e2fsck -fn` CLEAN after parallel runs (0 orphans, 0 bitmap
  drift, correct free counts).
- Single-threaded create must NOT regress (the ~118k baseline).
- Full ffs-core create/mkdir/link/symlink/mknod + conformance 100/0/2.
- A/B via the independent-process ceiling test (warm) to confirm the in-process
  result approaches the cross-process ceiling.

## Risks

- HIGH: concurrency correctness (2 prior attempts corrupted → e2fsck dirty). This is
  why loom + e2fsck gating is mandatory and why it is NOT a single-turn rush-land.
- MEDIUM: spreading may hurt single-thread locality (extra group-descriptor cache
  misses) — measure and gate spread on contention if so.
- LOW: the per-group lock array memory overhead (one RwLock per group; groups count
  is small for typical images).

## Explicitly out of scope (already ruled out)

- Batching the eager commits — REFUTED (6f27affa: the heavy registered MVCC path is
  ~2x slower single-threaded; the Unregistered eager per-block commit is already
  cheap).
- Reducing per-read/per-op allocation churn — REFUTED (0778ddfc: alloc self-time
  overcounts; removing it is neutral-to-negative).
- asupersync `Cx::for_request` per-request cost (7.7% of every FUSE op) — real but
  DEPENDENCY-owned (`new_with_drivers` is `pub(crate)`); not a frankenfs-crate change.
