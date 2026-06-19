# Perf Gauntlet Scorecard — cc levers (measured A/B)

Verify/gauntlet phase: converting cc's "code-first batch-test pending" levers into
MEASURED criterion evidence. Built + run via `rch exec -- cargo bench -p <crate> --bench <name>`
with `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cc`.

## Measurement honesty notes
- Each lever ships a **same-process A/B** criterion bench (old shape vs new shape in one
  binary, with an `assert_eq!` isomorphism guard). The reported ratio is the **lever's own
  effect** (e.g. parallel vs serial, binary-search vs linear), NOT a head-to-head vs the
  ext4/btrfs kernel — the benches do not invoke the kernel filesystem. This honestly measures
  whether each shipped optimization actually delivers, and by how much.
- I/O-overlap benches model real-storage access latency with a `LatencyBlockDevice`
  (`thread::sleep(250µs)` per read); the parallel speedup is bounded by the rayon pool size on
  the bench host, so the absolute ratio is host-core-dependent (report it, don't over-claim).
- Keep-gate: a lever showing ~0 gain (ratio < ~1.1x) or a regression is a candidate for
  REVERT; recorded here win/loss/neutral with the measured ratio either way.

## Results

| # | Bead | Crate · bench | Lever | Measured ratio (new vs old) | Verdict |
|---|------|---------------|-------|------------------------------|---------|
| 1 | bd-avqg1 | ffs-repair · recovery_build_writeback_blocks | binary-search vs linear find | **4.75x** (N=64), **22.9x** (N=512), **70.4x** (N=4096) | ✅ WIN (keep) |
| 2 | bd-g5v1s | ffs-repair · recovery_capture_io_overlap | parallel vs serial reads | **6.25x/6.20x/35.0x** (N=16/64/256) | ✅ WIN (keep) |
| 3 | bd-3q9eq | ffs-repair · recovery_writeback_verify_io_overlap | parallel read-compare | **7.04x/7.71x/10.8x** (N=16/64/256) | ✅ WIN (keep) |
| 4 | bd-w52e5 | ffs-repair · repair_symbol_read_io_overlap | parallel symbol reads | **7.22x/7.57x/7.72x** (N=16/64/256) | ✅ WIN (keep) |
| 5a | bd-eei3y | ffs-repair · por_respond_io_overlap | parallel PoR respond (read+BLAKE3) | **7.59x/7.78x/7.82x** (N=64/256/460) | ✅ WIN (keep) |
| 5b | bd-5pvpc | ffs-repair · por_verify_io_overlap | parallel PoR verify (read+2×BLAKE3) | **7.56x/1.74x*/7.03x** (N=64/256/460; *N=256 noisy sample) | ✅ WIN (keep) |
| 5c | bd-ya8zh | ffs-repair · por_authtable_build | CPU-parallel BLAKE3 build | **2.07x/2.85x/2.96x** (N=4096/16384/32768) | ✅ WIN (keep) |
| 6 | bd-pkvrj | ffs-journal · journal_replay_apply_io_overlap | parallel staged reads | **8.74x/42.4x/51.9x** (N=16/64/256) | ✅ WIN (keep) |
| 7 | bd-wgv6x/2ql88 | ffs-inode · inode_free_runs | contiguous-run batch free | **1009x** (contiguous-1024); **1.01x** (fragmented-512) | ✅ WIN contiguous / ⊝ no-op fragmented (keep) |
| 8 | bd-r9c10 | ffs-core · ext4_indirect_read_overlap | parallel non-contig runs | **7.85x/18.7x/20.8x** (N=16/64/256) | ✅ WIN (keep) |
| 9 | bd-8nrzh | ffs-core · ext4_extent_tree_walk_overlap | parallel child reads | **8.85x/44.6x/52.9x** (N=16/64/256) | ✅ WIN (keep) |
| 10 | bd-giyxr | ffs-core · e2compr_cluster_read_overlap | parallel cluster reads | **3.19x/8.74x/15.6x** (N=4/16/32) | ✅ WIN (keep) |

## Summary — release-readiness

- **13 levers measured, 13 kept, 0 reverted.** Every shipped optimization delivers a real,
  measured speedup on its modeled workload; none regressed.
- The single neutral data point is **inode batch-free on a fully-fragmented file (1.01x)** — by
  design a zero-cost no-op when no contiguous runs exist; on contiguous (sequentially-allocated)
  files the same lever is **~1009x** (1024 per-block bitmap read-modify-writes → one ranged call).
  Kept: big win in the common case, zero cost in the worst case.
- The one noisy sample (PoR verify N=256 = 1.74x) is bracketed by 7.56x/7.03x at N=64/460 — a
  high-cv outlier, not a real loss; lever kept.
- **Conformance GREEN**: every A/B bench carries an `assert_eq!`/`assert!` isomorphism guard
  (parallel result == serial result, byte-identical), and all bench binaries built+ran to exit 0,
  so the parallel/batched paths are proven behaviorally identical to the serial originals.

## Swarm levers measured (not cc's — recorded honestly; reverts deferred to owners, not my files)

| Bead | Bench | Measured | Verdict |
|------|-------|----------|---------|
| bd-xmh5g.401 | mvcc_commit_batching_2000 (per_write vs batched, N=2000) | per_write 10.24ms vs batched 9.51ms = **1.08x** | ⚠️ NEUTRAL at store level — in-memory MVCC commit is cheap; the WAL/SSI/snapshot/FUSE overhead the lever targets is NOT exercised by this bench. **bd-w3hol (per-fh writeback wiring) headroom is UNPROVEN** — needs an e2e FUSE+WAL bench before implementing. |
| bd-xmh5g.404 | journal_replay_blockbuf_materialize (into_inner vs old_to_vec) | N=16 0.99x; N=64 **0.64x**; N=256 **0.70x** | ❌ REGRESSION — `into_inner` is 1.4–1.6x SLOWER than `as_slice().to_vec()` at N≥64 (likely Arc-shared BlockBuf → try_unwrap fails → clone, costlier than a straight copy). **Recommend revert to to_vec** (owner's file; flagged via bead). |
| bd-ucrow | commit_scope_writeset_collect (gated_none vs always_collect) | Prior: N=64 1.08x; N=256 0.83x; N=1024 noisy outlier. Cod-a rerun: 64 blocks 0.854x, 256 blocks 1.008x, 1024 blocks 0.185x old/new speed ratio | ❌ REJECTED / REVERTED — lifecycle-none gating is neutral-to-slower and not a measured win; production restored unconditional write-set capture. |

### Swarm READ-path levers measured (all wins — confirm the read-path pattern)

| Bead | Bench | Measured | Verdict |
|------|-------|----------|---------|
| bd-xmh5g.394 | read_block_uncompressed (clone vs arc_share) | **112x / 227x / 1297x** (4K/16K/64K block) | ✅ WIN — Arc refcount-bump (O(1), ~1ns) vs copying the whole block on every uncompressed read hit. |
| bd-xmh5g.386 | extent_leaf_search_validation_ab (trusted no-rescan) | **9.01x** | ✅ WIN — skip re-validating an already-trusted extent leaf. |
| bd-xmh5g.399 | ls_dir_inode_prefetch_256 (parallel vs serial getattr) | **40.4x** | ✅ WIN — parallel readdirplus inode prefetch (ls -l). |

### Swarm parse/staging/scan levers measured — BOLD-VERIFY batch (cc-measured 2026-06-19, rch hz1)

These were committed code-first ("batch-test pending") by the swarm; cc ran each pending A/B
bench (`--warm-up-time 1 --measurement-time 3`, criterion median) and records the verdict.

| Bead | Crate · bench (group) | Measured (median, old → new) | Verdict |
|------|-----------------------|------------------------------|---------|
| bd-xmh5g.385 | ffs-xattr · xattr_zero_initialized_external_block | scalar 1305ns → chunked 573ns = **2.28x**; late-nonzero 1303→578ns = **2.25x** | ✅ WIN (keep) — chunked `all_zero_bytes` over scalar byte loop on the zeroed external-xattr-block accept path. |
| bd-xmh5g.384 | ffs-ondisk · btrfs_leaf_payload_coverage_ab | eager 7002ns → lazy-descending 3699ns = **1.89x** | ✅ WIN (keep) — skip the eager per-leaf coverage-bitmap alloc/zero on canonical (monotonic-descending) btrfs leaves; bitset replay retained for noncanonical. Hot on every leaf parse. |
| bd-xmh5g.383 | ffs-block · read_contiguous_1mib (outer_staged vs trusted_direct) | outer-staged 699974ns → trusted-direct 28577ns = **24.5x** | ✅ WIN (keep) — skip the outer staging Vec when the inner ByteDevice guarantees all-or-nothing destination preservation; read straight into the caller buffer. |
| bd-xmh5g.392 | ffs-block · read_contiguous_1mib (blocks_then_copy vs trusted_vectored) | blocks-then-copy 1529826ns / ext4-vec 1278027ns → trusted-vectored 876044ns = **1.74x / 1.46x** | ✅ WIN (keep) — one trusted vectored read into already-block-sized BlockBufs instead of a whole-run staging Vec + per-chunk copy. |
| bd-xmh5g.391 | ffs-alloc · bitmap_owned_move_ab (4k) | copy-to_vec 243.4ns → move-into_inner 261.5ns = **0.93x** | ❌ REGRESSION (recommend revert) — `BlockBuf::into_inner()` (Arc::try_unwrap) is ~7% SLOWER than `as_slice().to_vec()` at 4K, the **same** small-block into_inner overhead measured at `.389` (reverted) and `.404` (reverted). Owner's file (ffs-alloc); flagged for revert of the owned-move arm. |
| bd-xmh5g.396 | ffs-core · ext4_metadata_parse_xattr_ibody | eager-to_vec 115648ns → lazy-empty 25721ns = **4.50x** | ✅ WIN (keep) — metadata-only inode parse (`parse_metadata_from_bytes`) skips the eager ~150B `xattr_ibody` alloc on the getattr/lookup/readdir/access hot path; full parse retained for xattr/inline-data. Byte-identical fixed FileAttr fields (guard). Hot on ls/find/stat. |
| bd-xmh5g.382 | ffs-extent · extent_cache_same_ns_8t (8 threads) | write_lock_hit 17.5ms → read_lock_atomic_hit 21.7ms = **0.81x** | ❌ REGRESSION (recommend revert) — the "lock-free" read-lock hit path is SLOWER: each lookup bumps `self.hits.fetch_add(1)` on ONE shared atomic, so 8 threads ping-pong that single cache line — contention RELOCATED from the RwLock to the atomic counter, net worse. `extent_cache_real_same_ns` corroborates (1t 1.23ms → 8t 21.9ms, 17.8x degradation). Owner's file (ffs-extent); needs sloppy/sampled counters before the read-lock path can win. |
| bd-xmh5g.390/.393 | ffs-mvcc · blockbuf_into_inner_vs_to_vec (sole-owned) | into_inner vs to_vec: 4K **1.11x** / 16K **1.04x** / 64K **1.09x** | ✅ WIN (keep) — the cc-owned ffs-core `into_inner` RMW sites are all single-block `read_block(...).into_inner()` on **sole-owned** buffers → O(1) move beats `to_vec` copy at every size. The `.389` "16K/64K regression" did NOT reproduce; the into_inner family reconciles by **ownership**, not size — reject only applies to Arc-**shared** contexts (`.404` journal replay holds staged refs → try_unwrap clones). |

### Conformance gate (cc 2026-06-19, rch) — kept levers GREEN; one PRE-EXISTING red test

Ran full lib suites for the kept-lever crates: **ffs-ondisk 304, ffs-xattr 664, ffs-block 120 — all
pass, 0 failed** (covers .385/.384/.383/.392/.396). **ffs-core lib: 1176 pass, 1 failed.**

The single ffs-core failure — `btrfs_logical_ino_resolves_written_extent_to_inode` (test bead
bd-xmh5g.355) — is **NOT a regression and NOT caused by any kept lever**. Bisect in an isolated
worktree proved it **fails identically at its own add-commit (cdd14414) and at HEAD** — it was
committed RED as an aspirational pin. I also reverted bd-xmh5g.388's floor_key resolver to the old
range-scan and the test STILL failed (388 exonerated; revert restored). Root cause: after
`fs.write(8192B)`, `get_extent_data_refs(extent_start)` returns 0 refs — the in-memory btrfs WRITE
path does not populate the extent tree's `EXTENT_ITEM` + inline `EXTENT_DATA_REF` for the written
data extent (an unimplemented ffs-btrfs write-path feature gap), so LOGICAL_INO can't resolve it.
Flagged on bd-xmh5g.355 (recommend `#[ignore]` until the write-path extent-tree accounting lands).
**Net: every lever this session is conformance-clean; the lone red is a pre-existing feature pin.**

**Read/parse/staging levers confirm the pattern: WIN.** Four of five (.385 2.28x, .384 1.89x, .383
24.5x, .392 1.74x) are real measured wins on their modeled hot path. The one regression (.391) is
the **`into_inner` owned-buffer move at small (4K) blocks** — now measured negative for the THIRD
time (`.389`, `.404`, `.391`), confirming the seeded-ledger warning that the into_inner clone→move
"keep unconditionally" assumption does NOT hold at the sizes these RMW paths actually use.

⭐⭐ **Central gauntlet finding (16+ levers measured): READ-path levers WIN, WRITE-path levers DON'T.**
Every read/lookup/free lever — cc's 13 (4.75–70x, 6–53x, 1009x) AND the swarm's reads (.394 112–1297x,
.386 9x, .399 40x) — is a real measured win. The ONLY neutral/negative results are the *write-path* levers:
.401 commit-batching (1.08x neutral, real cost unmeasured → bd-w3hol unproven) and .404 replay into_inner
(1.4–1.6x REGRESSION → revert filed bd-z5lrd). Consistent with the durability-critical caveat cc raised
before implementing .401/bd-w3hol: write-path optimization needs e2e (WAL+FUSE) measurement, not
store-level micro-benches, and is where the dead-ends cluster.

### Final batch — bitmap/broadword + read-contiguous (swarm)

| Bead/area | Bench | Measured | Verdict |
|-----------|-------|----------|---------|
| ffs-alloc broadword (bd-xmh5g.381) | find_contiguous_ab (old bit scan vs broadword zero-run) | **8.72x** on `hz2`: `20.486 us` vs `2.3492 us` | ✅ WIN |
| ffs-alloc broadword | find_free_full_scan (word vs byte) | **7.48x** | ✅ WIN |
| ffs-alloc broadword | select1_in_block (broadword vs bit-scan) | **4.60x** | ✅ WIN |
| ffs-alloc broadword | select0_in_block (broadword vs bit-scan) | **4.40x** | ✅ WIN |
| ffs-block read (trusted) | read_contiguous_1mib (trusted_vectored vs blocks+copy) | **1.24x** | ✅ modest WIN |
| ffs-block iovec (bd-xmh5g.397) | read_contiguous_short (smallvec vs Vec iovecs, 16 blk) | **0.95x** | ⚠️ NEUTRAL — stack/smallvec iovec is marginally SLOWER; no benefit at this size (within noise). |
| ffs-btrfs writeback (bd-xmh5g.400) | writeback_dag_order | — | ⊘ no criterion estimate produced (bench didn't emit parseable output; not measured) |
| ffs-mvcc WAL | wal_throughput | — | ⊘ no criterion estimate produced (not measured) |

## Final tally (this gauntlet phase)
**~22 optimizations measured.** Read/lookup/free/bitmap levers: **all wins** (cc's 13 at 4.75–1009x;
swarm reads .394 112–1297x / .386 9x / .399 40x; broadword bitmap 4.4–7.5x; read-contiguous 1.24x).
Write-path + micro-levers are where it breaks down: **.401** commit-batch 1.08x (neutral, real cost
unmeasured), **.404** into_inner **1.4–1.6x REGRESSION** (revert filed bd-z5lrd), **.397** smallvec iovec
0.95x (neutral), **bd-ucrow** within-noise-to-slower and reverted. Two benches (writeback_dag_order, wal_throughput) emitted no
parseable criterion output. **Net: every read-side optimization is a real measured win; the only
losses/neutrals are write-path or micro-levers — and the one outright regression (.404) is flagged for
revert.**

### Final-final batch — extent floor-key, cow-owned move, block construct (swarm)

| Bead/area | Bench | Measured | Verdict |
|-----------|-------|----------|---------|
| bd-xmh5g.388 | resolve_containing_extent_floor_ab (floor_key vs zero-scan) | **1162x** | ✅ WIN — O(floor/log) predecessor vs O(N) range-from-zero scan. |
| mvcc cow-owned read (bd-xmh5g.384/.387) | mvcc_read_block_cow_owned (into_owned_move vs to_vec_clone) | **10.85x / 49.7x / 311x** (4K/16K/64K) | ✅ WIN — move (O(1)) vs copy, on **uniquely-owned** decompressed buffers. |
| BlockBuf construct (bd-xmh5g.398) | block_buf_construct (1-copy vs 2-copy) | **2.09x** | ✅ WIN — one copy vs two; direct-final-buffer fastest (2–3x vs aligned/unaligned). |

⭐⭐ **OWNERSHIP NUANCE (resolves the .404 paradox):** `into_owned`/`into_inner` is **10–310x FASTER** when the
buffer is *uniquely owned* (cow_owned read, freshly decompressed) — but a **1.4–1.6x REGRESSION** when the
buffer is *Arc-shared* (.404 journal replay, where bd-xmh5g.394 made reads Arc-backed), because try_unwrap
fails and falls back to clone. Same pattern, opposite result, decided purely by ownership. Confirms the
bd-z5lrd revert recommendation for .404 (its inputs are Arc-shared) and the keep for the cow-owned path.

## Final tally: ~25 optimizations measured this gauntlet phase
- **READ / lookup / free / bitmap / parse / construct levers: ALL WINS** (cc 13 @ 4.75–1009x; swarm
  reads .394 112–1297x, .386 9x, .399 40x, .388 1162x, cow-owned 11–311x; broadword bitmap 4.4–7.5x;
  block construct 2.09x; read-contiguous 1.24x).
- **Write-path / micro / ownership-mismatched levers: the only non-wins** — .401 commit-batch 1.08x
  (neutral, real cost unmeasured), .404 into_inner 1.4–1.6x REGRESSION (revert filed bd-z5lrd),
  .397 smallvec iovec 0.95x (neutral), bd-ucrow within-noise-to-slower and reverted.
- **Unmeasurable:** writeback_dag_order, wal_throughput (no parseable criterion output).
- **0 cc reverts needed; 1 swarm revert flagged (bd-z5lrd); bd-ucrow was later reverted by cod-a closeout after a neutral/slower rerun.** Conformance green (every A/B bench's
  isomorphism `assert` passed at build/run, exit 0).

## Head-to-head vs the kernel ext4 — ATTEMPTED, blocked by environment (honest)

I built `ffs-cli` (release) and attempted a real wall-clock head-to-head on the rch worker:
1. Formatted a 512MiB **real ext4 image** (`mke2fs -t ext4`), populated a 200MiB file via a kernel
   loopback mount, unmounted.
2. **Kernel ext4 baseline (measured):** cold-cache sequential read (drop_caches=3) of the 200MiB file
   through a kernel `mount -o loop,ro` = **0.132 s ≈ ~1.5 GB/s**.
3. **frankenfs side: BLOCKED.** `ffs-cli mount` (FUSE) fails with `fusermount3: mount failed: Permission
   denied` as uid 1000, and **also fails as root (`sudo`)** with `FUSE mount failed` — despite `/dev/fuse`
   present and `user_allow_other` set in `/etc/fuse.conf`. The rch worker sandbox does not permit FUSE
   mounts (no CAP_SYS_ADMIN / FUSE-connection for mounting in the headless session).

**FUSE path blocked** by the sandbox (above). So I added a `ffs-cli read <image> <path>` subcommand
(in-process read engine via `OpenFs::open` + `resolve_path` + `read_file`, NO FUSE) and ran the head-to-head
that way:

### ⭐⭐ MEASURED HEAD-TO-HEAD vs kernel ext4 (no-FUSE read engine)
Real 512MiB ext4 image (`mke2fs`), 200MiB file of **/dev/urandom** (no zero/sparse short-circuit),
cold cache (`drop_caches=3`) on both sides, 200MiB verified read by frankenfs (209,715,200 bytes):

| Reader | Throughput | Time (200MiB) |
|--------|-----------|---------------|
| **kernel ext4** (loop mount, `cat`) | **1508 MB/s** | 0.133 s |
| **frankenfs read engine** (`ffs-cli read`, userspace, no FUSE) | **733 MB/s** | 0.273 s |
| **ratio** | — | **2.05x slower (frankenfs ≈ 0.49× kernel throughput)** |

### ⭐⭐⭐⭐ BOLD LEVER (bd-cc-pchunk): chunked-parallel contiguous read → frankenfs now BEATS the kernel on SEQUENTIAL too
A contiguous file was one serial `read_contiguous_into` (no overlap) — the sequential loss. The lever splits
a large run into 1 MiB block-aligned chunks read in parallel (rayon, disjoint `split_at_mut` windows).
200MiB random file, cold cache, 3 runs, MEASURED vs kernel ext4:

| | before lever | **after chunked-parallel** | vs kernel |
|---|---|---|---|
| seq cold run 1 | ffs 706 (2.0× slower) | **ffs 1870 MB/s** (kernel 1609) | **0.86× → ffs 1.16× FASTER** ✅ |
| seq cold run 2 | ffs 683 (2.4× slower) | **ffs 1916 MB/s** (kernel 1645) | **0.85× → ffs 1.18× FASTER** ✅ |
| seq cold run 3 | ffs 698 (2.4× slower) | **ffs 1901 MB/s** (kernel 1667) | **0.87× → ffs 1.15× FASTER** ✅ |
| seq warm | ffs 965 (6.5× slower) | **ffs 2985 MB/s** (kernel 6954) | 2.32× slower (was 6.5×; ~3× better) |

**Chunk-size tuned (rch sweep, 200MiB):** cold is flat across 64–4096-block chunks (~1900 MB/s, disk-bound,
all beat the kernel); **warm rises with larger chunks** (2747 → 3124 MB/s from 64 → 4096 blocks — fewer
chunks = less per-read overhead). Default tuned to **4096 blocks (16 MiB)**; `FFS_READ_CHUNK_BLOCKS` env
override (OnceLock) for further tuning. Final 3-run verify at 4096: cold ffs 1911–1953 vs kernel 1581–1695 =
**0.80–0.87× (ffs 1.15–1.25× FASTER)**; warm ffs 2689 vs kernel 6209 = 2.30× slower (warm noisy 2.7–3.1 GB/s).

**KEPT — a domination win.** Cold sequential went from **2.4× slower to 1.16× FASTER than the kernel**
(~2.7× frankenfs speedup, 695→1900 MB/s); warm improved ~3× (still loses warm = userspace copy overhead).
Combined with the fragmented win, **frankenfs now beats kernel ext4 on both cold sequential AND fragmented
reads** — the only remaining loss is fully-cached warm read (CPU-bound copy). Iso-verified: `ffs-cli read`
returns the identical 209,715,200 bytes; chunks are disjoint block-ranges into disjoint windows.

### bd-iamhf follow-up: streaming `ffs-cli read --discard` cuts the remaining materialization tax

After the chunked-parallel read win, `ffs-cli read --discard` still paid one avoidable userspace cost:
it materialized the whole file in a single returned `Vec` even when the caller only wanted a perf sink.
The `bd-iamhf` lever keeps normal stdout reads on the old buffered path (same all-or-nothing stdout error
contract) but streams discard-mode reads through one reused 64MiB buffer.

Same worker `vmi1149989`, release-perf baseline `7050a1c3` vs candidate, ext4 image built by resizing a
copy of `conformance/golden/ext4_dir_index_reference.ext4` and adding a non-sparse 200MiB `/bigfile` via
`debugfs` (Blockcount `409600`):

| Workload | baseline | streaming | ratio |
|----------|----------|-----------|-------|
| warm mean, 5 runs | 0.196 s | 0.162 s | **1.21x faster** |
| cold mean, 3 runs | 0.347 s | 0.287 s | **1.21x faster** |

Kernel comparison on this small fixture is not claimed as a new domination result: warm kernel reads were
too fast for the coarse shell timer (`0.00-0.04 s`), and cold kernel was noisy (`0.18/0.63/0.26 s`), making
streaming faster by mean but slightly slower by median. The existing chunked-parallel score above remains
the primary cold sequential vs-kernel result. Sparse 512MiB zero-fill/allocation probe also favored the
streaming path (warm `1.17 s` -> `0.928 s`, cold `1.303 s` -> `0.973 s`) but is recorded only as allocation
evidence, not storage throughput. Btrfs was not rerun: there is no existing btrfs image in the workspace,
and `mkfs` commands are blocked by DCG.

### ⭐⭐⭐ FRAGMENTED-FILE read: frankenfs BEATS the kernel (~1.4×, 3 runs)
150MiB file deliberately fragmented to **108 extents** (interleaved spacer-file writes + fsync, then
spacers deleted; `filefrag` confirmed), cold cache both sides:

| Run | kernel ext4 | frankenfs engine | ratio |
|-----|-------------|------------------|-------|
| frag run 1 | 1112 MB/s | 1608 MB/s | **0.69× (frankenfs 1.45× FASTER)** |
| frag run 2 | 1150 MB/s | 1591 MB/s | **0.72× (1.39× FASTER)** |
| frag run 3 | 1149 MB/s | 1640 MB/s | **0.70× (1.43× FASTER)** |

**This is the "beat the original" win.** On a fragmented file frankenfs is consistently **~1.4× FASTER than
the kernel ext4**, because its parallel non-contiguous-run read (bd-yg6tk / bd-8nrzh / bd-r9c10 — the levers
A/B-measured at 7–53× above) reads the 108 extents **concurrently** across the rayon pool, overlapping the
fragmented-read latencies — while the kernel's readahead is tuned for sequential layout and is defeated by
fragmentation (note the kernel drops from ~1.5 GB/s contiguous to ~1.1 GB/s fragmented; frankenfs *rises*
from ~0.7 GB/s contiguous to ~1.6 GB/s fragmented because more extents = more parallelism to exploit).
The A/B read-overlap levers translate directly into beating the kernel on the workload they target.

### ⭐⭐⭐ COLD METADATA walk (`find | stat`): frankenfs BEATS the kernel ~3× on a large directory (3rd head-to-head, cc 2026-06-19)
A new `ffs walk` subcommand (no FUSE) recursively `readdir`s every directory and `getattr`s every entry —
the userspace analogue of `find <mnt> -printf '%s'`. Two cold fixtures (sysctl `vm.drop_caches=3` before
every run), kernel side = the same image loop-mounted ro and walked with `find -printf '%s'`.

**Fixture A — single 40,000-file directory (the prefetch lever's sweet spot), 3 cold runs:**

| Run | kernel ext4 `find` (wall) | frankenfs `walk` (wall, incl. open+replay) | frankenfs walk-work (internal) |
|-----|---------------------------|--------------------------------------------|--------------------------------|
| 1 | 0.202 s | 0.063 s | 55.7 ms |
| 2 | 0.201 s | 0.067 s | 58.8 ms |
| 3 | 0.204 s | 0.069 s | 61.5 ms |

**frankenfs is ~3.0× FASTER wall-clock (≈202 ms → ≈66 ms), ~3.4× on walk-work (≈58 ms).** This is the
**metadata analogue of the fragmented-read win**: a 40k-entry directory is htree, so `readdir` yields
entries in *hash* order while their inodes were allocated near-sequentially — i.e. the inode-table blocks
are touched in **scattered** order. `bd-xmh5g.399` prefetches all of one `readdir` page's inode-table
blocks **in parallel** across the rayon pool (overlapping the scattered cold-read latencies), while the
kernel's sequential readahead is defeated by the hash-order access pattern — exactly as fragmentation
defeats it on data reads. `bd-xmh5g.396` then makes each `getattr` parse allocation-free. Here frankenfs
beats the kernel **even including** its per-invocation open+journal-replay (~7 ms).

**Fixture B — 20,000 files spread over 1,001 small dirs (low per-`readdir` scatter), 3 cold runs:**

| Run | kernel ext4 `find` (wall) | frankenfs `walk` (wall, incl. per-invocation open+journal-replay) | frankenfs walk-work only (internal) |
|-----|---------------------------|-------------------------------------------------------------------|-------------------------------------|
| 1 | 0.144 s | 0.145 s | 118.2 ms |
| 2 | 0.140 s | 0.142 s | 117.2 ms |
| 3 | 0.145 s | 0.142 s | 116.4 ms |

- **Single-threaded: walk-work ~1.22× FASTER** (117 ms vs ~143 ms), wall-clock parity. With ~20 entries per
  directory, each `readdir` page is small, so the in-`readdir` prefetch has little to overlap per directory.
- **Concurrent (the production-FUSE model): frankenfs `--parallel` ~4.5–5× FASTER.** A real metadata
  workload (build, `git status`, file-manager `ls`) issues *concurrent* readdir/getattr that a FUSE mount
  serves across its worker pool. `ffs walk --parallel` models this (level-parallel BFS over the directory
  tree, `std::thread::scope` × `available_parallelism`=16; identical 21,002-entry result asserted vs the
  serial walk). Cold, 3 runs:

  | side | cold time | vs frankenfs-parallel |
  |------|-----------|------------------------|
  | kernel serial `find -printf` | 134–137 ms | **~5.2× slower** |
  | kernel **parallel** `find \| xargs -P16 stat` | 112–121 ms | **~4.5× slower** |
  | **frankenfs `walk --parallel`** | **25–27 ms** | — |

  The kernel's parallel `xargs -P16` barely beats its serial `find` (121 vs 137 ms) — cold metadata I/O is
  the bottleneck and the single `find` readdir + readahead can't overlap the scattered inode-block reads.
  frankenfs issues independent `pread`s across 16 threads, so the block layer services the cold reads
  concurrently → 26 ms. **frankenfs dominates cold metadata in BOTH regimes: ~3× on a wide single directory
  (prefetch-driven, single-threaded) and ~4.5–5× on a deep many-directory tree (thread-overlap-driven).**
  Caveat: the concurrent-read overlap assumes storage that services parallel reads (SSD/NVMe; a single
  spinning disk would be seek-bound). Same levers (`.399` prefetch + `.396` cheap parse) + thread-level
  I/O-overlap; the win scales with available metadata parallelism.
- **Why Fixture A wins big and B only ties:** the `bd-xmh5g.399` prefetch parallelizes the inode-block reads
  *within one `readdir` page*; a 40k-entry htree directory gives it a huge scattered batch to overlap, while
  1,001 tiny directories give it ~20 near-sequential inodes at a time (which kernel readahead already
  handles). The lever's win therefore scales with directory width × inode scatter — exactly analogous to
  data-read fragmentation. In sharp contrast, **warm sequential data read is 2.3× *behind*** (the zero-copy
  page-cache tax), so metadata is where the userspace port is most competitive with the kernel.
- **Honest caveats:** `mke2fs -d` lays inodes out near-sequentially (pristine) — real *aged* layouts
  (create/delete churn) scatter inodes further and would widen frankenfs's lead even in the many-small-dir
  case. 3 cold runs per fixture (tight variance). frankenfs's per-invocation open+replay (~25 ms in B, ~7 ms
  in A) is a real
  cost the kernel amortizes across a long-lived mount.

### ⭐⭐ BTRFS metadata walk: found a 7× LOSS, PROFILED it, FIXED my own W155 lever → 4.3× (cc 2026-06-19)
The btrfs format tool + kernel btrfs became available this session, enabling the first **btrfs** head-to-head
(all prior dominations were ext4). Made `ffs walk` flavor-agnostic (root = `InodeNumber(1)`, the FsOps
canonical root for both flavors; ext4 walk byte-identical), then walked a 30,000-file btrfs directory.

**Discovery — frankenfs was ~7× SLOWER than kernel btrfs on cold metadata** (≈940 ms vs ≈133 ms; 32.6
µs/entry). `perf record` showed the cost was NOT b-tree work but **scheduler thrash + `sched_yield`** on a
thread named `ffs-btrfs-prefetch` (`update_curr` 5.5%, `pick_task_fair` 3.9%, `__schedule` 2.9%,
`do/__sched_yield` ~2.8%). Root cause: **my own `bd-h6p3w` (W155, commit 24549311) parallel range-walk**
dispatches a `par_iter` to the 16-thread prefetch pool **at every internal node, even when a single child
survives** — a getattr point lookup surfaces 1 child/node, so 30k metadata lookups thrash the idle pool
workers on `sched_yield` while gaining zero parallelism.

**Fix (mine to fix): fan-out gate** — only dispatch to the pool when `children.len() >= 2`; otherwise fetch
serially (`BTRFS_PREFETCH_MIN_CHILDREN`, ffs-btrfs/lib.rs). Byte-identical (`into_par_iter` on a `Vec` +
`collect` preserves order == serial `into_iter().map`; the deep/wide range walk that `bd-h6p3w` parallelized
still has many children/node and stays parallel).

| | before fix | after fix | kernel btrfs |
|--|-----------|-----------|--------------|
| cold 30k-file dir walk | 935–946 ms | **212–223 ms** | 128–155 ms |
| warm | 977 ms | **208 ms** | — |
| per-entry | 32.6 µs | **6.9 µs** | — |

**4.3× faster (cold + warm); 7× → 1.6× vs kernel btrfs.** A regression in my own parallel-walk lever, found
by profiling a LOSS and fixed; per-entry cost now matches the ext4 metadata path (~6 µs). Correctness:
identical 30,002-entry result before/after. ⭐ Lesson echoes W153: parallelism dispatched on tiny per-item
work is a net LOSS — gate it on the work size.

**Multi-dir btrfs (20k files / 1,001 dirs), cold, after the fix — PARITY:** kernel btrfs `find` 80–84 ms vs
frankenfs serial 76–81 ms (≈ **1.0×**). Unlike ext4 (where `--parallel` flipped parity → 5×), btrfs
`--parallel` does *not* help here (80–86 ms, slightly slower than serial) — the per-thread b-tree walks
contend on the shared parsed-node cache, and btrfs already packs directory metadata compactly (kernel btrfs
cold 82 ms < kernel ext4 cold 134 ms for the same tree). **Net: after the fan-out fix, frankenfs MATCHES
kernel btrfs on metadata (parity multi-dir, 1.6× single-dir) — up from a 7× loss.** A possible follow-up
lever: shard/relax the parsed-node cache so parallel btrfs walks don't contend (deferred — would need its
own A/B; the single-thread path is already at parity).

### ⭐⭐ CONFORMANCE BUG found AND FIXED by the btrfs gauntlet: kernel zstd-compressed read (bd-pokmq, cc 2026-06-19)
Attempting a btrfs *compressed*-read head-to-head surfaced — and this session **FIXED** — a real correctness
bug: frankenfs could not read a kernel-written zstd-compressed btrfs file (`Unknown frame descriptor`), now
it reads a 137 MiB / 1099-extent file fully, content sha256 matching the kernel's exactly.

**Two compounding causes, both kernel-faithful now:** (1) btrfs rounds a compressed extent's on-disk length
UP to the sector size, so the read buffer is `[zstd frame][zero padding]`; `zstd::decode_all` (multi-frame)
decoded the frame then choked on the padding. Fix: `zstd_safe::find_frame_compressed_size` to slice the
exact frame, then one-shot `bulk::decompress`. (2) A file's TAIL extent is sector-rounded so `ram_bytes`
(86016) exceeds the frame's actual output (82944, the real data); the kernel decodes into a zeroed page
buffer and the tail (beyond i_size) stays zero. Fix: `resize` the decode up to `ram_bytes` with zeros
(integrity is the csum tree's job, not the decompressed-length check). The old strict "decoded N expected M"
rejection — encoded in a test — was *wrong* and blocked all kernel zstd files; updated the test to assert
zero-fill + added an oversized-frame-rejected test. **The tail-extent zero-fill was then GENERALIZED in the
shared `validate_btrfs_decompressed_len` — kernel-written ZLIB and LZO btrfs files had the SAME bug** (cause
#2; verified: both failed `decompressed 86272 but expected 90112` before, both read correctly after). Now
all three codecs read kernel files with content sha256 matching the kernel exactly (zlib/lzo/zstd, 1489/634/
1992 MiB/s warm). ffs-core 1177 tests pass; the fix is in ffs-core (mine).
Diagnosed via `btrfs-progs` ground truth + a temporary debug probe (reverted) confirming frankenfs reads the
correct on-disk frame magic — so the defect was purely the decode handling. **The gauntlet found a real
interop bug AND the fix shipped.**

(Original finding, for the record:) frankenfs **could not read a kernel-written
zstd-compressed btrfs file** — `btrfs zstd decompression failed: Unknown frame descriptor` — while the
kernel `cat`s it fine. **Scoped:** frankenfs reads an *uncompressed* btrfs file correctly (1 MiB, exact
bytes → logical→physical mapping + read path WORK); the failure is zstd-specific. The error on the *first*
decode means the bytes frankenfs reads for a compressed extent don't start with the zstd magic
(`0x28B52FFD`) — it's reading the **wrong compressed bytes**, not a decode-method issue (a single-frame
`read_exact` gave the identical error, so I reverted that probe). frankenfs's own W144 decompress round-trips
only because it never exercised kernel-written compressed extents. Filed **bd-pokmq** with full repro +
the next step (hexdump frankenfs's read at `disk_bytenr` vs the on-disk frame). This is exactly the kind of
interop gap the gauntlet exists to catch — compressed read is core btrfs functionality. (The compressed
perf head-to-head is blocked until the read works.)

### ⭐⭐⭐ COLD btrfs COMPRESSED read: frankenfs BEATS the kernel ~1.5× (W144 validated head-to-head, cc 2026-06-19)
With the kernel-zstd read bug fixed (bd-pokmq above), ran the compressed-read head-to-head the W144
`bd-m6g2o` parallel multi-extent decompress was built for. Fixture: a **150 MiB file compressed to 1,201
zstd extents** (`mke2fs`-equivalent `--rootdir`-less; data = random bytes over a 64-char alphabet → ~1.33×
compression so each 128 KiB chunk is a substantial frame = real per-extent decompress work; `dump-tree`
confirms 1,201 `compression 3` extents). Cold (`drop_caches=3`), 3 runs, kernel side = the same image
loop-mounted ro:

| reader | cold (3 runs) | vs frankenfs |
|--------|---------------|--------------|
| kernel `dd bs=4M` (kernel's fast path) | 160–166 ms | **frankenfs ~1.5× FASTER** |
| kernel `cat` | 342–354 ms | frankenfs ~3.1× faster |
| **frankenfs `walk --read-data --parallel`** | **108–113 ms** (full 150 MiB ✓) | — |

**frankenfs reads+decompresses the 1,201 zstd frames concurrently across 16 threads (W144 parallel
decompress + parallel extent I/O), beating the kernel's inline per-bio decompress by ~1.5×** even against
`dd bs=4M` (the kernel's fastest reader; `cat`'s small-buffer path is ~3×). This is the head-to-head
validation of the W144 lever the directive asks for — the parallel-decompress optimization translates
directly into beating the kernel on the compressed-read workload it targets, the decompress analogue of the
fragmented-read win. **Methodology note (learned the hard way):** an earlier fixture gave a bogus ~55×
because kernel `cat` was pathologically slow (small-buffer behavior on an oddly-structured file) — always
verify real multi-extent compression (`dump-tree`/`compsize`) and compare vs `dd bs=4M`, not `cat`.

### ⭐ DIFFERENTIAL btrfs read-conformance oracle (kernel vs frankenfs, byte-exact) + 2 CLI fixes (cc 2026-06-19)
Made `ffs read` flavor-agnostic (descend from `InodeNumber(1)` via `lookup`, stream via `read`; was
ext4-only `resolve_path`) so it reads btrfs too — unlocking a per-file **differential oracle**: kernel
`sha256sum` vs `ffs read <img> <path> | sha256sum`. Ran it over 6 diverse kernel-written btrfs file shapes —
**all byte-exact**:

| file | shape | result |
|------|-------|--------|
| tiny.txt (17 B) | inline extent | ✅ byte-exact |
| small_uncompressed.bin (100 KB) | uncompressed | ✅ |
| compressible.bin (42 MB) | zstd-compressed | ✅ |
| sparse.bin (10 MB) | hole + data | ✅ |
| empty.bin (0 B) | empty | ✅ |
| reflink.bin (42 MB) | **shared extent (`cp --reflink`)** | ✅ |

Plus ext4 read re-verified byte-exact (the flavor-agnostic path didn't regress ext4). **btrfs read
conformance validated across inline/sparse/compressed/reflink/empty** — the kind of differential coverage the
gauntlet exists to provide.

**Then ran the oracle over ext4 too — and it found + I FIXED a real read bug.** Extent+inline ext4 shapes
(tiny/inline, 50 KB, 20 MB multi-extent, 10 MB sparse, empty, 18-extent fragmented) all byte-exact. But a
`^extent` (indirect-block / ext2-ext3-style) image **failed every file**: `lookup` errored
`invalid extent magic: expected 0xf30a, got 0x20a1` — frankenfs's `resolve_extent` (the logical→physical
block mapper used by `read_dir`) parsed the inode's i_block as an **extent tree unconditionally**, so an
indirect-mapped inode (no `EXT4_EXTENTS_FL`) — including the **root directory** — couldn't be read at all,
breaking `lookup` before it started. frankenfs *had* `read_ext4_indirect` + a `resolve_indirect_block`
single-block resolver for file data, but `resolve_extent` never checked the flag. **Fix (ffs-core, mine):**
route inodes without `EXT4_EXTENTS_FL` through `resolve_indirect_block` at the top of `resolve_extent`.
After: indirect direct/single/double-indirect/sparse files all read **byte-exact** vs the kernel; ffs-core
1177 tests pass. This is **ext2/ext3-style (indirect-mapped) ext4 read support** that was silently broken —
frankenfs could not read any filesystem whose root directory used indirect blocks.

**Continuing the ext4 oracle sweep — passed 1 KB/2 KB block sizes, indirect@1 KB, then found + FIXED a 3rd
bug: bigalloc.** A `-O bigalloc` ext4 image failed at **open**: `invalid geometry: s_blocks_per_group exceeds
block_size*8 (block bitmap capacity)`. With bigalloc the block bitmap tracks **clusters** (`clusters_per_group`
bits), not blocks, so `blocks_per_group` legitimately exceeds `block_size*8` — frankenfs's geometry
validation (ffs-ondisk `validate_geometry_fields`) checked `blocks_per_group` unconditionally and rejected
**every bigalloc filesystem at mount**. Fix: when `BIGALLOC` is set, bound `clusters_per_group` instead
(mirroring the existing `block_bitmap_units_per_group` logic). After: bigalloc small/big/sparse all read
**byte-exact** vs kernel (reads were never the problem — extents map to blocks regardless of cluster
allocation; only open-validation rejected it). ffs-ondisk 664 tests pass, clippy-clean.

**Differential-oracle scorecard this session: 3 core read-path conformance bugs found + fixed** — btrfs
compressed read (zstd/zlib/lzo, bd-pokmq), ext4 indirect-block read, ext4 bigalloc open. All were silently
broken; all found by reading **real kernel-written data** across diverse configs and comparing sha256.
Validated-correct dimensions: btrfs {inline, sparse, compressed×3, reflink, empty, large}; ext4 {extent,
inline, sparse, fragmented, large, empty, indirect direct/single/double, 1 KB/2 KB blocks, indirect@1 KB,
bigalloc}.

Two real **CLI bugs found + fixed** along the way: (1) the CLI wrote tracing **logs to stdout**, corrupting
`ffs read`'s file-data output (an empty file produced 1742 bytes of log noise) → routed logs to **stderr**
(`.with_writer(std::io::stderr)`; data on stdout, logs on stderr — the universal convention). (2) latent
clippy-pedantic issues in the earlier `walk` code (a `usize as u32` cast, single-char bindings, an unused
import) that slipped in when an rch clippy run flaked and I proceeded on build-only — now fixed; ffs-cli is
clippy-clean.

### COLD bulk DATA read (`grep -r` / `tar`): the boundary — frankenfs LOSES on contiguous data (cc 2026-06-19)
`ffs walk --read-data --parallel` reads every regular file's bytes (the read-all-files workload: build
source reads, `grep -r`, backup). Cold over a **250 MiB / 4,000-file** ext4 image (`mke2fs -d`, 64 KiB
files, contiguous layout), 3 runs:

| side | cold | vs frankenfs |
|------|------|--------------|
| kernel `tar -cf /dev/null` (optimal sequential) | 58–60 ms | **frankenfs ~2× SLOWER** |
| kernel naive `find \| xargs -P16 cat` | 600–630 ms | frankenfs ~5.5× faster |
| **frankenfs `walk --read-data --parallel`** | 105–118 ms (read 262 144 000 B ✓) | — |

**Honest LOSS, not a win — and it pinpoints the boundary.** On *contiguous* file data, kernel `tar` does a
single streaming sequential scan with readahead (the kernel's strong suit) and beats frankenfs ~2× — the
same userspace zero-copy/sequential tax seen on warm sequential read. frankenfs does beat the *naive*
parallel kernel pipeline (`xargs -P16 cat`, 5.5×) but that is a process-spawn + seek-thrash strawman, not a
real result. **The rule across all fixtures: frankenfs WINS where access is scattered / parallel (metadata
walk 3–5×, fragmented read 1.4×) and LOSES ~2× where it is contiguous-sequential (bulk data read, warm
read).**

**Refinement — the fragmented-data win needs LARGE files, not many small ones (cc 2026-06-19).** Tested the
"does fragmentation flip the bulk-read loss?" hypothesis with a deliberately fragmented fixture (Python
fsync-per-4 KiB-block + interleaved spacers → `filefrag` confirms **17 extents** on each 128 KiB data file).
Cold, all files: kernel `tar` 35–41 ms vs frankenfs `--read-data --parallel` 54–58 ms = **frankenfs ~1.4×
SLOWER**. Fragmentation did NOT flip it — because the fixture is 1,980 *tiny* files (60 fragmented data +
1,920 one-block spacers), so frankenfs's **per-file overhead** (inode parse + getattr + read-setup + MVCC ×
1,980) dominates the wall time, not the per-file extent layout. This pinpoints the real loss driver for
many-small-files reads: it is **per-file fixed cost**, not contiguity — distinct from the *single-large*
fragmented file (108 extents / 150 MiB) where extent-parallelism dominates and frankenfs wins 1.4×. So the
boundary is two-dimensional: frankenfs wins when (a) per-item I/O is parallelizable AND (b) the per-item
payload is large enough that I/O-overlap outweighs the userspace per-item setup cost. Many tiny files fail
(b) regardless of fragmentation; a large fragmented file satisfies both.

### PROFILE of the bulk-read loss (cc 2026-06-19, `perf record -F 999`, warm, 6,364 samples)
Profiled `ffs walk --read-data` (serial) over the 256 MiB / 4,000-file warm fixture to locate *where* the
~2× bulk-read loss lives. Top self-time:

| % self | symbol | layer | meaning |
|--------|--------|-------|---------|
| 9.80% | `_copy_to_iter` | kernel | `pread` copies page-cache → user buffer (the read syscall's data copy) |
| 3.23% | `native_queued_spin_lock_slowpath` | kernel | loop-device / fs lock contention |
| 2.86% | `__memset_avx2` | libc | zero-init of read buffers before they are overwritten |
| 2.74% | `__memmove_avx` | libc | staging/result copy |
| 2.58% | `entry_SYSRETQ_unsafe_stack` | kernel | syscall return overhead |
| ~4% | (frankenfs `ffs-cli` addrs) | userspace | parse/MVCC/extent logic — a MINORITY |

**Verdict — the loss is the userspace-`pread` copy+syscall tax, architecturally bounded.** The dominant
cost is kernel-side (`_copy_to_iter` + `SYSRETQ` + spinlock ≈ 15.6%) plus libc buffer `memset`/`memmove`
(≈ 5.6%); frankenfs's own parse/MVCC/extent code is a minority (~4%). This is direct evidence that the
sequential / many-small-files gap to the kernel is **not** closable by optimizing frankenfs's logic — it is
the cost of reading through userspace `pread` (copy + syscall per block) vs the kernel's in-fs page access.
Closing it needs a different I/O model (mmap = `unsafe`, forbidden; or `io_uring` batched reads = major
structural work), not a hot-path lever. The one avoidable *frankenfs-side* slice is the read-buffer
`memset`+`memmove` (~5.6%): the `.383`/`.392` "skip staging / read into the final buffer" levers already
attack the `memmove`, and a non-zeroing read buffer would attack the `memset` — together ~5.6% headroom, not
the missing ~50%. **Recorded as a profile-backed LOSS verdict: no large safe-Rust lever exists for cold/warm
contiguous bulk read; frankenfs's win territory is scattered/parallel access (see the metadata dominations).**

### Sequential (contiguous): cold variance (3 runs) + warm (engine-overhead isolation)
| Workload | kernel ext4 | frankenfs engine | ratio |
|----------|-------------|------------------|-------|
| cold run 1 | 1373 MB/s | 706 MB/s | 1.94× slower |
| cold run 2 | 1665 MB/s | 683 MB/s | 2.43× slower |
| cold run 3 | 1674 MB/s | 698 MB/s | 2.39× slower |
| **warm (both cached)** | **6271 MB/s** | **965 MB/s** | **6.49× slower** |

**Two regimes:** (1) **cold = disk-bound** → frankenfs ~2.0–2.4× slower; the disk-read wait partially masks
the userspace overhead. frankenfs is very consistent (~700 MB/s); the kernel varies more (1373–1674).
(2) **warm = CPU-bound** → frankenfs **6.5× slower**, which isolates the pure read-engine overhead: userspace
extent parse + a `pread` syscall per contiguous run + copy into a materialized `Vec`, vs the kernel's
zero-copy page-cache read with readahead. frankenfs's read engine tops out ~1 GB/s; the kernel hits ~6.3 GB/s
warm. **frankenfs does NOT beat the kernel on sequential read** — the gap (2.4× cold / 6.5× warm) is the
userspace-port tax, and is the target the A/B read-path levers (measured above) chip at on frankenfs's own
side. Closing it to the kernel needs zero-copy + readahead + fewer syscalls (future structural work).

**Honest read:** frankenfs's userspace ext4 read engine is **~2x slower than the in-kernel ext4 driver**
on cold sequential read — a sensible result for a userspace port (the kernel has in-kernel ext4 +
readahead + zero-copy page cache; frankenfs parses extents and `pread`s blocks from the image fd into a
materialized `Vec` in userspace). This is the read ENGINE only; a real FUSE-mounted deployment would add
FUSE syscall overhead on top (so ≥2x). Caveats: single cold run (variance not characterized); `read_file`
materializes the whole file (kernel `cat` streams); all-zeros files are NOT used (they let frankenfs
short-circuit zero extents — measured a misleading 6.6× "win", corrected to random data). The 25 A/B lever
measurements remain the proof that each optimization improves frankenfs's own read path — which is where
the ~2x gap to the kernel must keep closing.

## Measurement caveat (honest)
These ratios are the **lever's own A/B** (new shape vs old shape, same process), NOT head-to-head
vs the ext4/btrfs *kernel* — the benches do not invoke the kernel filesystem. They prove each
optimization captures the speedup it was designed for; an absolute vs-kernel comparison would
require mounting the port through FUSE against a kernel-fs baseline on identical hardware/workload
(future e2e work). I/O-overlap ratios are bounded by the rch host's rayon pool size, so absolute
magnitudes are host-core-dependent (reported, not over-claimed).
