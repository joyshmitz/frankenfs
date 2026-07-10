# Perf campaign status — read this first

## ✅ FINAL FRONTIER SUMMARY — 2026-07-10 (BlackThrush / cc_ffs) — ALL AXES MAPPED, HOLD

Every subsystem axis has been profiled/audited and is either a landed win or a
measured floor. **No clean, benchable, non-peer, non-owner-gated single-turn
solo micro-lever remains.** Holding — stop hunting. Detailed rows in
`docs/NEGATIVE_EVIDENCE.md` + `docs/progress/perf-negative-results.md`.

| Axis | Status | Key landed wins | Key rejects / floor evidence (IDs) |
| --- | --- | --- | --- |
| **Read / IO** | CLOSED — I/O-bound or cache-served | extent resolve binary-search + seq-hint; indirect memoized; arc_swap hot-inode/hot-parent borrow (31c57895, 0218b2d8) | read-copy coalescing neutral (9ae9f08f); O_DIRECT 1.00x **owner-gated bd-kdmu4**; zero-copy relaunch closed (policy/API, pz64v); cold-read = loop-device artifact (frankenfs-cold-read-honest-numbers) |
| **Compression** | CLOSED — codecs reuse contexts or stateless | zlib decoder reuse 1.43x; e2compr gzip decode 2.21x / encode 1.44x | LZO per-segment scratch reuse REJECT decode-dominated (**bd-cc-lzo**); zstd already reused |
| **Checksum** | CLOSED (this session, a5a97e12) — verify segmented, stamp no-copy, crc32c HW | zero-run-aware CRC family (253f2862, e4d192e4, 8221c6f4, 041f04f4); incremental dir-block csum 10.3x (56cb5f94 + wirings 4976d6d7/c9e12ff4/43b967e6); incremental crc32c 11.6x (ff222d17) | inode-csum stamp already no-copy (**bd-cc-inode-csum-stamp**); csum_seed cache = parity-tail (5998f96c, 183f7c38) |
| **Write-path** | CLOSED — commit-dominated (peer MVCC) | serialize_inode reslice 1.066x (61254de6); write_entry reslice 1.16x (ab0d6cae); add_entry SWAR | copy-elim e2e-neutral BOTH adapters (33c51394 FsMvccBlockDevice, 44ad26b2 TransactionBlockAdapter); serialize buf.fill = sub-noise + commit-swamped; **bd-bhh0i** parallel-create owner-gated; alloc = **peer lane** (af91cc18, 2d331770, b9389ced, fa8a8035, 6e9d6a8c) |
| **Metadata / dir** | CLOSED — parse/lookup/getattr done | AttrOnly parse 1.11x (8314ca8c); MetadataOnly note_index 1.24x (bc47b311); htree sort_unstable 1.47x (a4ba9241); SWAR name compare 1.80x (2ad5ec95) + casefold (3dcf558f) + overlapping-word (317b8fbe); has-zero validate (2a380996); lookup fully dissected (8419f2a7) | locate_inode strength-reduction NEUTRAL (a1bab91e, 2026-07-05); inode_to_attr construction FREE (19a20908); Arc<InodeAttr> turn ~10% REGRESSION (22387e32); bloom neg-lookup NEUTRAL (2e1fce5f); dx_hash floor (8d143aac); readdir per-entry name = flagged broad-surface SmallVec (jemalloc-refuted) |

**The only remaining headroom is NOT a solo micro-lever:**
1. **Peer-owned** — MVCC commit (the write bottleneck), ffs-alloc (most-recently-active peer lane), btrfs.rs (bd-xmh5g). Coordinate, don't collide.
2. **bd-bhh0i** parallel-create — a loom+e2fsck-gated multi-turn concurrency refactor (owner decision needed; see below).
3. **Structural unblock** — a returnable binary (fix rch artifact retrieval → its own remote target dir gives metadata-only retrieval) reopens the block-copy read path + enables v3+PGO production numbers (bd-b9dug).
4. **Scoped design task** — `Ext4DirEntry::name` → SmallVec (kills the readdir per-entry alloc; broad public-type surface, marginal given jemalloc).

**HOLD: no honest single-turn measured solo win remains.** Await an owner decision on (1)–(4).

> ## ⚠️ LOOP-GUARD (updated 2026-07-04, BlackThrush) — MOSTLY exhausted, but composite/multi-stage sub-paths still hide levers. Actually BENCH candidates; don't assume "covered".
>
> ⭐**CORRECTION**: an earlier version of this guard said the dig was fully
> EXHAUSTED. That was too strong — the "keep benching, don't assume covered"
> approach then produced **TWO** wins in the SAME scrub op: **e8932055 (~1.52x
> fsid pre-check, WORK-SKIP)** and **9f790529 (~1.37x superblock-block division
> hoist, WORK-HOIST)**. LESSON: a crate having SOME landed benches does NOT mean
> every sub-path is optimal. The scrub byte→word win optimized ZeroCheck (stage 1
> of the `CompositeValidator`) but nobody had touched `BtrfsTreeBlockValidator`
> (stage 2), and once that was cheap the per-block DIVISIONS in the sb validators
> became dominant. **Where to still look: COMPOSITE/multi-stage per-item paths,
> ESPECIALLY under dynamic dispatch (`dyn Trait`/`Box<dyn>`)** — LLVM can't
> inline/hoist across the opaque virtual call, so per-item loop-invariants
> (divisions, target addresses, parsed constants) and reject-heavy parses hide
> there. Two shapes proven: WORK-SKIP (gate expensive work behind a cheap
> discriminator) + WORK-HOIST (precompute a recomputed loop-invariant at
> construction). And **actually run the bench** rather than reasoning "it'll be
> neutral/covered" (measure-don't-reason applies to the DECISION TO BENCH).
> Infra: budget ~45min/bench under swarm saturation; run rch
> AND local in parallel, take whichever returns.
>
> A land-or-dig loop has fired ~10+ times. Most firings re-derive exhaustion, but
> real levers still surface (see above). Before spending another turn:
> - **LAND branch is EMPTY** (verified). No worktree holds an un-landed measured
>   win. ⚠️`frankenfs-opt-385d89cd`@`1938784f` ("RaptorQ no-corruption seed,
>   6.77x") LOOKS landable but is **SUPERSEDED** by `26da04a8`+`63723d88` already
>   on main — landing it DOWNGRADES main. The other ahead-of-main branches are
>   `MEASURED NEUTRAL` / incomplete WIP. See the NEGATIVE_EVIDENCE land-check row.
> - **DIG branch is CLOSED.** Every crate scanned (micro AND algorithmic):
>   ffs-btrfs/repair/ondisk/alloc/block all at their optimized floor (word-wise/
>   SWAR/ASCII-fast/lazy/direct-IO/binary-search/specialized-erasure-solvers
>   already landed); ffs-core/ffs-mvcc are peer-owned (present-index + bd-bhh0i,
>   IvoryBirch/SilverPine). alloc_extent max-fusion + chunk-map-cache + GF-SIMD +
>   alloc-churn micro-opts all refuted or blocked.
> - **The ONLY remaining wins are owner-decisions, not solo per-crate levers:**
>   1. authorize the multi-turn loom+e2fsck-gated **bd-bhh0i** parallel-write
>      project (biggest gap ~3.7–9x; peer-active),
>   2. approve scope for the **scrub allocation-gate** (`docs/design-scrub-allocation-gate.md`;
>      correctness-critical, BLOCK_UNINIT/flex_bg synthesis — multi-hour, not 60m),
>   3. grant a **vetted-unsafe SIMD module** (bd-416sl) to unblock the GF/erasure
>      kernel class.
>
> If you are the loop: there is no honest solo single-turn measured win to ship.
> Escalate one of the three decisions above rather than re-scanning the tree.
>
> **⚠️ Build-infra risk (2026-07-04): `/data` is at 83% (335G free) with 30
> Rust `target` dirs + 57 git worktrees accumulating** from the agent swarm.
> Rust target dirs are GB-scale each; when the volume fills, ALL builds — incl.
> this loop's own `rch`/`cargo bench` — fail. Owner should authorize a cleanup
> pass (`cargo clean` on stale `.scratch`/`.worktrees` checkouts + `git worktree
> prune` of the merged/superseded ones — deletion needs explicit permission per
> AGENTS.md RULE 1). Not urgent today; will become a hard blocker as the swarm
> keeps building.

> ## 2026-07-10 cod_ffs addendum
>
> `bd-bhh0i` remains owner-gated. The safe de-risk pass added no production path
> and performed no filesystem mutation. Current global alloc lock 8t p99 wait is
> **176.341 us** versus **0.290 us** for disjoint synthetic group locks. The
> synthetic publish-mutex p99 **127.449 us** is routing-only and does not prove
> the real publication gate is the next bottleneck. The old 168-interleaving
> hand model is now labeled final-state conservation, not linearizability.
> The whole 1/2/4/8 sweep is synthetic: it does not instrument actual MVCC locks
> or malloc-arena contention. Those production-shaped counters remain an owner
> de-risk obligation and require safe external or bench-only instrumentation.
>
> A bounded Loom suite now has seven finite projections: disjoint/same/opposing
> group lock order, independently cross-mapped shard locks, an exact early
> abort, hidden installed-but-unpublished versions, and
> registered-snapshot-safe pruning. A synchronized ghost invocation/response
> history makes the two-writer projection a bounded deadlock-free and
> linearizable proof for five enumerated configurations, exhaustive over modeled
> schedules rather than every possible two-group operation. Visibility and
> pruning are separate safety projections, not a formal composition.
> Whole-create/crash atomicity and post-install compensation remain owner
> cutover obligations, as do e2fsck-clean mutation fixtures.
>
> The write+fsync row's nominal **3.033x slower** result (71.744 us vs 23.654 us)
> is withdrawn as a fair current-source ratio: CV was **44.94% / 97.22%**, API
> and durability boundaries were unmatched, and the refined runs stopped during
> cold fat-LTO compile/link before the workload executable or `e2fsck` ran.
> `bd-fsync-journal-latency-gap-ptp4x` now records the fair retry gate.
>
> Xattr is the clearest safe new-workload gap: **0** mounted performance
> comparators, **4** internal microbenchmark families, and **1** mounted
> correctness smoke. Filed P1 `bd-mounted-xattr-workload-gap-fr6iq` for a
> read-only mounted get/list comparator with >=30 interleaved batches and
> `cv_pct < 5`.

**As of 2026-07-03 (BlackThrush).** A ~25-turn single-turn profile-and-optimize
campaign against ext4/btrfs. This is the one-glance synthesis; the chronological
detail is in `docs/NEGATIVE_EVIDENCE.md`, and the one open lever has its own plan
in `docs/bd-bhh0i-parallel-create-plan.md`.

## TL;DR

Single-turn *code* optimization is **exhausted** (every op on both filesystems at
its floor, verified at the hardware-counter level). Three veins were mined after the
whole-op floors: **build-config** (fat LTO landed; target-cpu=v3 + PGO surfaced and
scripted — noise-immune `perf stat` metric), **per-function allocs** (str2hashbuf,
serialize landed via criterion), and a **microarch verify phase** (every hot op
stall-analyzed; six promising levers built as real binaries and A/B-refuted — see
the verify-phase section). The **only** substantive *code* lever left is **bd-bhh0i**
(parallel metadata-write serialization, proven ~7x) — a multi-turn, loom-gated,
correctness-critical effort that must not be rushed into one commit (two prior
attempts corrupted the filesystem).

## Landed wins (all measured, gated, on `main`)

| win | commit | ratio |
| --- | --- | --- |
| ext4 rename skips redundant 2nd htree descent (preflight probe) | eb6a2229 | ~1.13x |
| btrfs zlib decode `miniz_oxide` → `zlib-rs` | 9c39e74f | ~2.95x cold |
| btrfs LZO decode `lzokay-native` → `lzo` crate | 0fc63561 | ~4.45x |
| (earlier) mkdir/mknod/link/symlink htree dedup, eager unlink/rmdir | — | 1.05–2.85x |
| `release-perf` fat LTO (thin→fat) | cd251273 | ~2–3% (instr) |
| `scripts/build-perf.sh` — validated one-command max-perf build | d8f898ce | see below |
| `str2hashbuf` → `[u32;8]` stack array (htree hash, per insert/lookup) | a6c4c505 | ~1.34x (fn) |
| `write_inode` serializes into a stack buffer (`serialize_inode_into`) | dab75bb3 | ~1.13x (fn) |
| btrfs `delete_from` leaf fast-path (skip removed item on COW copy) | a1a2a26c | ~1.5% btrfs unlink |

## Build-config levers (perf-stat-measured; the late vein)

The machine's wall-clock swung ±40%, hiding sub-10% wins. `perf stat`
instruction/cycle counts (deterministic for fixed work) exposed them:

- **fat LTO** — LANDED (cd251273): ~2–3% fewer instructions, broad.
- **target-cpu=x86-64-v3** — surfaced (4ec26bd4): ~8.5% create / ~3% lookup fewer
  instructions; portable to 2015+ CPUs (native gives nothing more). Opt-in: it
  removes the runtime scalar fallback frankenfs deliberately keeps (CPU-baseline
  = maintainer call), and Cargo can't scope `target-cpu` to one profile.
- **PGO** — surfaced (7f0c6ff4): **~10% create / ~24% lookup** fewer instructions;
  a two-stage release process, not a Cargo flag.
- **stacked (fat LTO + v3 + PGO)** — validated via `scripts/build-perf.sh`
  (d8f898ce): **create −14.3%, lookup −27%** vs plain fat-LTO, e2fsck-clean. Run
  `scripts/build-perf.sh` for the max-perf binary; the default build stays portable.
- allocator already jemalloc-optimal (0303500d); crc32c already optimal.

## Per-function + microarch verify phase (criterion + real-binary A/B)

After the whole-op floors, a re-profile reopened a **per-function** vein — criterion
(noise-robust on this loaded machine) surfaced masked per-call heap allocs in hot
functions. Two landed (both byte-identical, criterion-verified):

- **`str2hashbuf`** (a6c4c505): `vec![0;buf_size]` → `[u32;8]` stack array on the
  ext4 htree hash (every create/mkdir/rename/link/symlink insert + htree lookup) —
  −34% on the `dir_lookup` htree bench.
- **`serialize_inode_into`** (dab75bb3): `write_inode` serializes into a stack buffer
  instead of `vec![0;inode_size]` — −12.5% on a new `serialize_inode` bench.

Then every hot op was stall-analyzed (`perf stat` counters) and its promising levers
**built as real binaries and A/B'd** — six refuted, none shipped on a microbench:

- **lookup** = cache-miss-bound (37% miss, hashmap pointer-chasing), NOT dTLB-bound
  (THP refuted). **create** = user-side cache-stall-bound (`ext4_add_dir_entry` #1
  @18% = 4 KiB dir-leaf RMW memcpy + `dir_csum` crc), NOT syscall-bound. **btrfs
  lookup** = attr-cache + `read_inode_attr` (cache-latency floor). **btrfs write** =
  memmove/I/O-bound.
- Refuted with measurement: present-index inline-key (neutral), MVCC chain inline
  (3× slower reads), `prepare_inode` inline (slower), jemalloc THP (not TLB-bound),
  `btrfs_canonical_inode` inline (real-binary A/B neutral), **attr-cache
  `Arc<InodeAttr>`** (microbench said 6.6× faster, **real-binary A/B was +7% cycles**
  — 66402846).
- ⚠️**META-LESSON**: a *streaming* microbench (iterate all keys) exaggerates
  table-size/density and can INVERT the real-path result. Pure-function microbenches
  translate; structural cache-layout changes MUST be verified with a real-binary A/B.

## btrfs-write front (fresh, after ext4 exhausted)

btrfs metadata writes work and were profiled for the first time — a different world
from ext4: **COW-tree-node churn**, not crc/RMW. Throughput ladder is inherent
tree-op count: create ~77k/s > unlink ~38.5k > rename ~19k (rename does delete 4 +
insert 4 + rebalance ≈ 4× create).

- **Win**: `delete_from` leaf fast-path (a1a2a26c) — build the N−1 COW result skipping
  the removed item vs full-node `.clone()` + `Vec::remove` shift. Real-binary A/B:
  −1.5% cycles btrfs unlink (all 3 pairs), behavior-preserving (365+38 tests).
- **Refuted** (real-binary A/B): `BtrfsCowNode` leaf-Vec **pool** (instr −1.7% but
  cycles FLAT — jemalloc buffer-free cheap; the 17% `drop_glue` is item Arc-refcount,
  not buffer; 5829c6f5); `merge_adjacent_nodes` targeted-copy (NEUTRAL — merges are
  rare; **frequency, not pattern-fit, decides**; 80706777).
- **All hot COW ops audited optimal-or-inherent**: `insert_into` (bd-btrcow2), leaf
  `split` (`split_off`), `delete_from`-leaf (landed); the per-item Arc-refcount
  clone+drop (~22% of writes) is cheaper than the data-copy it replaces (a persistent
  vector would slow read-heavy btrfs's Vec-index — net loss). btrfs writes at COW floor.
- **Also refuted (real-binary A/B, fully gated inc. `btrfs check`)**: `BtrfsCowNode`
  leaf-Vec pool (cycles flat), `merge_adjacent_nodes` targeted-copy (rare),
  **staged-internal in-place** (eliminates 10.6% of COWs but NEUTRAL — 174adddb).
- ⚠️**META-LESSON #2 — COW/op COUNT ≠ COST**: the staged-internal candidate was *sized*
  at 10.6% of `insert_into` COWs, passed 365+38 tests + `btrfs check` clean, yet was
  neutral (~0.2% instr) — because those redundant COWs are cheap INTERNAL nodes, while
  cost lives in the LEAF Arc-item copies. Same trap as the node-pool (17% `drop_glue`
  was cheap buffer-free). SIZE cost-per-op-type before building, not count. Every
  count-based btrfs-write redundancy turned out cheap; the cost is in inherent ops.

## Lever categories — ALL closed

- **redundant-descent** — harvested (create/mkdir/mknod/link/symlink dedup; rename probe).
- **decode library** — swapped (zlib-rs, lzo); zstd already C-fast; brotli unused.
- **crc32c** — already optimal (crate 0.6.8, SSE4.2 3-way parallel).
- **SipHash→FxHash** — swept (no benchable hot-path default-hasher map left).
- **eager-vs-batched commit** — harvested (unlink/rmdir eager conversion).
- **copy / alloc / read elision** — REFUTED 4×: alloc-churn (0778ddfc), `load_full`
  (9513e82a), `write_block_owned` (8690f3f9), double-inode-read (9fb56052). Meta:
  `__memmove`/alloc self-time OVERCOUNTS; it does not translate to throughput.
- **build config** — MINED via `perf stat` (see the Build-config section above): fat
  LTO landed; target-cpu=v3 + PGO surfaced and scripted (`build-perf.sh`); allocator +
  crc already optimal. The initial fat-LTO wall-clock test was inconclusive (4aba3de2)
  until the perf-stat instruction metric resolved it.

## Floor map (every benchable op re-verified at its floor)

- **Metadata write** (create/mkdir/rename/unlink/rmdir/link/symlink/mknod): crc +
  MVCC-commit + inherent per-op work; single-thread syscall-bound at the durability
  boundary.
- **Data write**: MVCC-commit + syscall bound (write-bench 460k IOPS).
- **Reads**: ext4 rand-read I/O-bound; btrfs uncompressed I/O-bound; btrfs
  compressed = decode-then-cached (bd-4tw2n cache 55×); lookup + readdir at the
  parallel-safe-cache floor (arc_swap + ShardedCache are intentional). The
  pz64v zero-copy relaunch is closed as a policy/API blocker: incumbent safe
  direct reads re-measured at 18.7× over staged 1 MiB reads and `preadv`
  re-measured at 1.26× over staged 128 KiB scatter on RCH `hz2`, while the
  remaining page-cache / `copy_to_user` prize needs mmap or io_uring registered
  buffers plus an explicit audited-unsafe decision and, for true borrow
  zero-copy, a borrow-returning API.
- **fsck --force**: I/O-bound (78% kernel `copy_to_user`).

## Owner-gated create lever — bd-bhh0i (decision needed)

**Symptom:** in-process parallel create NEGATIVE-scales (1t 118k → 16t 59k). All
ext4 metadata-write ops convoy on the single whole-state `alloc_mutex.write()`.

**Independent-state upper bound:** ~7x (8 independent processes hit ~747k
aggregate vs 118k single). This proves available parallelism on separate images,
not that one shared-image cutover recovers the whole kernel gap.

**Fix (two-part, both required):** shard `alloc_mutex` per group AND spread inode
allocation so concurrent creates touch disjoint inode-table blocks (per-group
sharding alone re-serializes on shared inode-table-block RMW — the failure mode
that corrupted both prior attempts). Full plan + gating in
`docs/bd-bhh0i-parallel-create-plan.md`.

**Why not done here:** it is a loom-gated concurrency refactor (mandatory loom +
e2fsck gating), spans multiple turns, and its parallel result cannot even be
measured under this session's ±40% benchmark noise. Rushing it risks a third
filesystem-corrupting refutation.

## The decision

1. **Authorize the multi-turn bd-bhh0i effort** — land safe, loom+e2fsck-gated
   increments over several turns (ideally on a quiet machine for the final A/B), or
2. **Consider the single-turn perf campaign complete** — the frontier is fully
   mapped and the remaining gap is a known, planned, owner-lane concurrency project.

Everything reachable in single-turn increments has been landed or rigorously
refuted. There is no honest single-turn measured win left to ship.
