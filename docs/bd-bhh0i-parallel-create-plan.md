# bd-bhh0i — Parallel metadata-write scaling: implementation plan

**Status:** design (no production code landed). Owner-lane, loom-gated, multi-turn.
**Author:** BlackThrush. **Parallelism signal:** up to ~7x across independent
filesystem states; this is an upper-bound experiment, not a cutover payoff.

This consolidates ~10 turns of investigation (see the `docs/NEGATIVE_EVIDENCE.md`
rows dated 2026-07-03, commits `dc92e926`, `5e72f0f0`, `73815b0d`) into an
executable plan for this owner-gated profiled workload. It is not a global
performance ceiling or a reason to stop profiling: new workload classes and new
profiles may identify structurally different primitives elsewhere.

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

### Re-quantified 2026-07-03 (current `release-perf` v3+PGO binary)

Re-measured after the build-config wins landed, to confirm the wall persists and
size the fix target precisely:

- **ext4** create-bench 40k: 1t **100.3k/s** → 2t 77.8k → 4t 65.7k → 8t **54.6k**.
- **btrfs** create-bench 20k: 1t **77.2k/s** → 2t 60.1k → 4t 53.4k → 8t **48.8k**.
  The similar curve is routing evidence for a second concurrency problem, not
  proof of the same serializer: `Ext4AllocState` and the proposed per-group
  allocator exist only on ext4. A separate btrfs profile is required before
  claiming this ext4 decomposition helps btrfs.
- **Build-config did NOT move the wall**: target-cpu(~8.5%)+PGO(~10-24%) cut
  *instructions*, but the parallel curve is unchanged from `73815b0d` → pure
  contention, not instruction count. An instruction win cannot fix it.
- **Fix target quantified** (`perf record` @8t): the work that runs *serialized
  under `alloc_mutex.write()`* is `__memmove` 9.3% (MVCC version-block copy) +
  `commit` 3.8% + crc ~5% + `add_entry_reject_existing` 2.7% + `bitmap_find_free`
  1.0% ≈ **21% of create**. `RawRwLock::unlock_exclusive_slow` 0.73% (+kernel
  futex) confirms contention. Per-group sharding lets disjoint-group creates run
  this ~21% concurrently. That identifies a mechanism; it does not predict a
  speedup because queueing, publication, and newly exposed shared-block conflicts
  still require measurement. The crc/memmove work itself remains in each op.

## Scope hypothesis — parallel ext4 metadata writes, validated per operation

Every ext4 mutation op takes the SAME whole-state `alloc_mutex.write()`, so they
ALL convoy on it under parallelism (verified 2026-07-03): `ext4_create`
(lib.rs:16881), `ext4_mknod` (17030), `ext4_mkdir` (17197), `ext4_unlink_impl`
(19116), `ext4_link` (19364), `ext4_symlink` (19481), `ext4_fallocate` (19794),
and rename. That shared lock makes the design relevant beyond create, but it does
not prove the same speedup or even the same next bottleneck for every operation.
Each operation needs an independent profile, behavior gate, and measured A/B
before any broader performance claim.

## Independent-process parallelism signal (~7x upper bound, not a ceiling)

Independent-process upper-bound test (safe, unsafe-free, reusable): run N single-thread
`create-bench` on N **separate** image copies concurrently, aggregate vs single.
Warm: 1 proc ~118k; **8 independent procs ~747k aggregate (~7x)**; 8 threads/1 proc
= 65k (negative). ⚠️ WARM it first — a cold first run measured a misleading 1.7x
(page-cache/binary warmup).

Conclusion: create work on independent filesystem states can parallelize about
7x on this worker. The experiment removes shared-image coordination and therefore
cannot prove that this decomposition realizes that speedup, that serialization
explains the whole kernel gap, or that the gap is recoverable on one image.

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
  4x single-thread; the ~7x independent-process result is context, not a gate).
- `create-bench 3000 → e2fsck -fn` CLEAN after parallel runs (0 orphans, 0 bitmap
  drift, correct free counts).
- Single-threaded create must NOT regress (the ~118k baseline).
- Full ffs-core create/mkdir/link/symlink/mknod + conformance 100/0/2.
- A/B against the single-lock implementation on the same worker; retain the warm
  independent-process result only as an upper-bound context arm.

## De-risk pass 2026-07-10 (cod_ffs, no cutover)

This pass intentionally did not mutate the production metadata path. It added a
bench-only contention probe (`bd_bhh0i_contention`) and a bounded state model so
the owner can review the shape of the lock decomposition before any filesystem
cutover. Release-perf run was on RCH worker `hz2`.

Measurement boundary: the original probe uses synthetic `parking_lot`
allocation/group/publish mutexes and wall-clock timing around a 4 KiB `Vec`
allocation; that table remains routing evidence only. A follow-up bench-only
instrumentation path now records the real `ShardedMvccStore` shard-lock and
ordered-publication wait/hold histograms, plus safe jemalloc mutex counters, at
1/2/4/8 writers. The direct commit path does not acquire `active_snapshots`:
the current writable adapter is unregistered, so that lock is not silently
claimed as part of these rows. Remote perf self-time verification remains
blocked by the worker's `perf_event_paranoid=4` / missing CAP_PERFMON and must
be rerun on a permitted worker before any reject or optimization conclusion.

Measured lock wait histograms, microseconds:

| threads | current global alloc wait p95 | current global alloc wait p99 | decomposed group wait p95 | decomposed group wait p99 | decomposed publish wait p95 | decomposed publish wait p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.080 | 0.080 | 0.080 | 0.080 | 0.080 | 0.080 |
| 2 | 4.190 | 21.150 | 0.200 | 0.210 | 0.500 | 0.860 |
| 4 | 15.300 | 86.709 | 0.200 | 0.230 | 13.360 | 50.360 |
| 8 | 66.920 | 176.341 | 0.240 | 0.290 | 64.549 | 127.449 |

At 8 threads the current model has a global alloc-lock mean hold time of only
0.423 us, but p99 wait is 176.341 us, so the pain is convoy amplification rather
than the protected work itself. The decomposed group lock keeps the 8-thread p99
wait at 0.290 us for disjoint groups. The synthetic plain publish mutex then has
an 8-thread p99 wait of 127.449 us with a 0.137 us mean hold. That last number is
**routing-only**: the synthetic mutex is not `CommitPublicationGate`, and prior
real-path evidence measured the sharded MVCC path above the create target and a
publish-nowait candidate neutral. It therefore does not establish that the real
publication gate is the next bottleneck. Publication still needs correctness
modeling because it is part of the accepted lock graph, not because this probe
proved a performance bottleneck.

The bench's deterministic bounded model explored 168 two-thread terminal
interleavings for disjoint groups plus a global ordered publication lock:

- deadlocks: 0
- final-state conservation: true
- digest equality across current/decomposed simulated effects: true for 1/2/4/8
  thread measurements

That hand model has no invocation/response history or reader oracle, so it does
not prove linearizability. It remains useful owner-review evidence only.

### Bounded Loom writer proof and separate safety projections

`crates/ffs-core/tests/bd_bhh0i_lock_decomposition_model.rs` is the executable
model for the accepted lean eager-commit design. Loom substitutes its own
instrumented synchronization primitives; it does not execute the production
`parking_lot` implementations. The abstraction/simulation map is:

- outer allocator shared guard -> Loom `RwLock` read guard;
- proposed per-group exclusive guards -> Loom `Mutex` guards, always sorted;
- writer-side production shard `RwLock<W>` and metrics `RwLock<W>` -> Loom
  `Mutex` guards (same exclusive ownership and rank). Group and MVCC-shard sets
  are independently mapped and sorted, including a disjoint-group/shared-shard
  case. Every group effect maps to at least one shard and every installed shard
  payload is replayed against that group's sequential prefix; reader/shard
  interaction -> Loom `RwLock` in the separate visibility projection;
- production ready-prefix mutex/condition variable/atomic watermark -> Loom
  `Mutex`/`Condvar`/`AtomicUsize` with the same Release publication and Acquire
  snapshot boundary. A mutex-protected shadow removes redundant modeled atomic
  predicate branches; each prefix advance still performs the Release store read
  by snapshots.

The suite uses three separately checked finite projections rather than
multiplying every actor into one intractable model. They are not a formal proof
of arbitrary composition:

1. Two writers exercise `outer R -> groups(sorted) -> shards(sorted) -> metrics
   -> sequence/install -> drop shards -> ready-prefix publish`, while retaining
   every group guard through publication. Disjoint, same-group, opposing
   multi-group, cross-mapped group/shard, and early-abort cases replay returned
   allocation bits against a sequential bitmap allocator. A Loom-synchronized
   ghost history records every invocation and response; the sequence order must
   respect every recorded response-before-invocation edge. Every installed MVCC
   payload must also match its explicitly mapped group effect in the sequential
   replay. For these five enumerated configurations, exhaustive over modeled
   schedules, this proves the allocation-result/group-state and mapped-payload
   writer projection deadlock-free and linearizable.
2. A fully installed/ready sequence-2 state, a sequence-1 installer, and one
   reader force an out-of-order publication gap and prove that a snapshot
   returns the complete newest version at or below the Acquire-loaded contiguous
   prefix; installed-but-unpublished sequence 2 is hidden on both modeled shards.
3. A preseeded sequence-1 version plus a sequence-2 writer and registered reader
   exercises the real post-commit `active_snapshots -> shards` prune rank while
   the proposed group guard remains held. The registered snapshot's version is
   retained.

The writer projection's linearization point is each
`completed_prefix.store(sequence, Release)`. All shard versions are installed
and shard guards dropped before that point; the operation responds only after
its own sequence is in the completed prefix. The writer proof is bounded to two
groups, two independently mapped shards, two writers, and one operation per
writer. It exhausts schedules for the five enumerated configurations, not every
possible operation within those numeric bounds. The other projections add at
most one reader. Together they provide bounded evidence for the default sharded,
no-JBD2 bitmap-allocation primitive, not a composed proof of whole `ext4_create`,
multi-block crash atomicity, starvation freedom, the single-store/JBD2 path, or
compensation after an installed write. Failure is modeled only at the exact
early-abort point before metrics, sequence assignment, and install; it must leave
allocator and MVCC state unchanged. Those exclusions are explicit cutover
obligations, not inferred guarantees.

Gate result: RCH worker `ovh-a` passed all **7/7** final projections in **3.40
seconds**. `max_permutations`, `max_duration`, and `preemption_bound` are unset.
The per-execution branch bound is 1000; there is no permutation, duration, or
preemption sampling limit.

Incremental owner-reviewed plan, each step independently revertible:

1. Keep the bench-only histograms and bounded model. Rollback: remove the bench
   entries; no production behavior changes.
2. Add Loom models for the proposed primitive only, with no production code use.
   **Implemented as the bounded writer proof and separate safety projections
   above.** Rollback: remove the test target and its dev dependency. Gate: every
   finite projection exhausts without permutation, duration, or preemption
   sampling limits and without deadlock, lost update, prefix-visibility
   violation, or sequential-replay mismatch.
3. Factor `Ext4AllocState` into immutable geometry plus per-group mutable records
   while still protected by the existing single lock. Rollback: restore the old
   struct shape. Gate: conformance plus create/mkdir/link/symlink/mknod tests.
4. Add read-only contention counters around the existing single lock and publish
   gate. **Bench-only implementation:** the real sharded commit body is shared
   by uninstrumented ORIG and `commit_profiled`; worker-local log2 histograms
   avoid shared probe contention, and normal builds do not expose the recording
   entry point. Safe jemalloc JSON reports arena/bin mutex counters. Rollback:
   remove the feature and bench dependencies. Gate: exact commit-count/digest
   parity, profile self-time on a permitted worker, and no production FS change.
5. Introduce per-group locks behind an owner-disabled feature/config path, with
   production default still using the single lock. Rollback: disable the path.
   Gate: loom/shuttle model plus e2fsck-clean fixture mutations.
6. Add the allocation-spread policy behind the same disabled path. Rollback:
   disable spread. Gate: parallel create 1/2/4/8/16 curve, e2fsck -fn clean,
   single-thread create non-regression.
7. Only after owner ACK, flip the path for measurement. Rollback: one config
   revert to the single-lock implementation. Gate: same-worker release-perf A/B,
   conformance, e2fsck-clean parallel mutation fixtures, and no rename/link/mkdir
   regressions.

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
