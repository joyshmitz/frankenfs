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
| 6 | bd-pkvrj | ffs-journal · journal_replay_apply_io_overlap | parallel staged reads | _pending_ | _pending_ |
| 7 | bd-wgv6x/2ql88 | ffs-inode · inode_free_runs | contiguous-run batch free | _pending_ | _pending_ |
| 8 | bd-r9c10 | ffs-core · ext4_indirect_read_overlap | parallel non-contig runs | _pending_ | _pending_ |
| 9 | bd-8nrzh | ffs-core · ext4_extent_tree_walk_overlap | parallel child reads | _pending_ | _pending_ |
| 10 | bd-giyxr | ffs-core · e2compr_cluster_read_overlap | parallel cluster reads | _pending_ | _pending_ |

(filled in as each rch bench completes; reverts and negative-ledger entries recorded for any
neutral/regressed lever.)
