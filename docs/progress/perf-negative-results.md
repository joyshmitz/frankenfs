# Performance Negative-Evidence Ledger

This ledger records every code-first optimization attempt in the no-gaps
campaign, including pending attempts that have not yet received a benchmark
verdict. Rejected rows are not to be retried unless their retry predicate is
met by new profile evidence.

## Rules

- One lever per row.
- Record the benchmark surface, result, and exact keep/reject/pending status.
- If benchmark execution is intentionally deferred, record the command that must
  produce the verdict.
- Rejected ideas require a concrete retry predicate, not a vague "try later."

## Current Campaign Rows

| Date | Bead | Surface | Lever | Status | Evidence | Retry predicate |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-06-18 | `bd-xmh5g.386` | `ffs_btree::search` / `search_with_leaf_window` validated ext4 extent leaf search | Private trusted `search_leaf_bounded_validated` path used only immediately after `parse_leaf_entries` has already rejected zero-length, unsorted, and overlapping leaves; checked helper retained for public pre-parsed roots | Pending batch benchmark | Runtime lever, public-preparsed zero-length guard, and Criterion A/B row `extent_leaf_search_validation_ab` added. This cod-b batch is explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-btree`; benchmarks/tests are not run in this commit. | Run `cargo bench -p ffs-btree --bench extent_leaf_search -- extent_leaf_search_validation_ab` plus the crate conformance/search gate. Keep only on a meaningful leaf-search win and no corrupt-leaf/public-preparsed regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-18 | `bd-xmh5g.388` | `ffs_btrfs::BtrfsExtentAllocator::resolve_containing_data_extent` logical-ino/backref lookup | Replace the materializing from-zero extent-tree range scan with a `floor_key` predecessor walk that skips interleaved non-`EXTENT_ITEM` keys and checks the single greatest data extent candidate | Pending batch benchmark | Runtime lever, interleaved non-extent regression guard, and Criterion A/B row `resolve_containing_extent_floor_ab` added. This cod-a batch is explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a cargo check -p ffs-btrfs`; benchmarks/tests are not run in this commit. | Run `cargo bench -p ffs-btrfs --bench extent_fetch -- resolve_containing_extent_floor_ab` plus the crate logical-ino/backref conformance gate. Keep only on `Score >= 2.0` and no boundary/interleaved-key regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-18 | `bd-xmh5g.384` | `ffs_ondisk::parse_leaf_items` dense btrfs leaf payload-overlap validation | Lazy descending-payload fast path that avoids eager coverage bitmap allocation on canonical leaves; exact bitset replay fallback for noncanonical layouts | Pending batch benchmark | Runtime lever, focused fallback fixture, and Criterion A/B row `btrfs_leaf_payload_coverage_ab` added. This cod-b batch is explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-b cargo check -p ffs-ondisk`; benchmarks/tests are not run in this commit. | Run `cargo bench -p ffs-ondisk --bench btrfs_leaf_parse -- btrfs_leaf_payload_coverage_ab` plus the crate conformance/parser gate. Keep only on a meaningful parser win and no overlap-validation regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-18 | `bd-xmh5g.381` | `ffs-alloc::succinct::SuccinctBitmap::find_contiguous` | Broadword zero-run detector for mixed 64-bit words plus exact earliest-run property guard | Pending batch benchmark | Criterion A/B row `succinct_find_contiguous_ab` added. This cod-a batch was explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a cargo check -p ffs-alloc`; benchmarks/tests were not run in this commit. | Run `cargo bench -p ffs-alloc --bench bitmap_ops -- succinct_find_contiguous_ab` and the crate conformance gate. Keep only on `Score >= 2.0` and no correctness regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-18 | `bd-xmh5g.382` | `ffs-extent::ExtentCache::lookup` same-namespace hot hits | Shared read-lock hit path with atomic hit/miss counters and atomic per-entry recency; insert-time eviction falls back to deterministic `min_by_key(last_access, key)` scan | Pending batch benchmark | Production code and min-scan victim conformance guard added. This cod-a batch was explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a cargo check -p ffs-extent`; benchmarks/tests were not run in this commit. | Run `cargo bench -p ffs-extent --bench extent_cache_same_ns -- extent_cache_same_ns_8t` and `cargo bench -p ffs-extent --bench extent_cache_real_contention -- extent_cache_real_same_ns`, then the crate conformance gate. Keep only on `Score >= 2.0` and no correctness regression; otherwise revert the lever and mark rejected with the measured ratio. |
| 2026-06-18 | `bd-xmh5g.385` | `ffs-xattr::parse_external_entries` zero-initialized external xattr block acceptance | Replace scalar `block.iter().all(|b| *b == 0)` with chunked `ffs_types::all_zero_bytes` for the allow-zero-initialized invalid-magic fallback | Pending batch benchmark | Production lever and Criterion A/B row `xattr_zero_initialized_external_block` added. This cod-a batch was explicitly limited to `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cod-a cargo check -p ffs-xattr`; benchmarks/tests were not run in this commit. | Run `cargo bench -p ffs-xattr --bench xattr_exists_probe -- xattr_zero_initialized_external_block` and the crate conformance gate. Keep only on `Score >= 2.0` and no zero-block accept/reject regression; otherwise revert the lever and mark rejected with the measured ratio. |

## Seeded Do-Not-Retry Rows From Prior No-Gaps Work

These rows summarize already-explored families from the existing `bd-xmh5g`
history so the new campaign does not loop on known dead ends. Update each row
with fresh benchmark artifacts if a new workload or primitive changes the
profile.

| Family | Prior rows | Status | Retry predicate |
| --- | --- | --- | --- |
| RaptorQ source-row memoization/cache variants | `bd-xmh5g.149`, `bd-xmh5g.150`, `bd-xmh5g.165` | Rejected or no-ship under prior same-worker evidence | Retry only if a new profile shows row generation, not memory traffic or solve/projection, dominates the current workload after the kept source-domain encode path. |
| LRC small-parity and fused pair/quad microkernels | `bd-xmh5g.152`, `bd-xmh5g.153`, `bd-xmh5g.156`, `bd-xmh5g.157`, `bd-xmh5g.166`, `bd-xmh5g.167`, `bd-xmh5g.169` | Mixed to rejected under prior focused benches | Retry only with a new benchmark family whose workload shape differs materially from the old 64-block/8-parity lanes and includes same-binary A/B evidence. |
| Raw allocation bitmap contiguous/largest-run broadword families | `bd-xmh5g.78`, `bd-xmh5g.85`, `bd-dlc4x`, plus rejected table/broadword variants `bd-xmh5g.30`, `bd-xmh5g.57`, `bd-xmh5g.60`, `bd-xmh5g.77` | Already covered; some kept, some rejected | Do not duplicate raw bitmap work. Only optimize distinct call surfaces, such as succinct-index queries, and add an oracle guard before changing tie-breaking. |
