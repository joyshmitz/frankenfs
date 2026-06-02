# bd-5wpg4 ffs-extent range mapping perf evidence

Profile target:

- Command: `RCH_FORCE_REMOTE=true TMPDIR=/data/tmp timeout 1800 rch exec -- cargo bench --profile release-perf -p ffs-extent --bench extent_resolve -- --noplot`
- Worker: `vmi1153651`
- Hot row: `extent_sequential_100blocks_uncached`
- Baseline: 440.57 us mean, confidence interval [396.29 us, 496.22 us]

Kept lever:

- `ffs_btree::walk_range` walks only extents overlapping a logical range and reads each relevant subtree/leaf once.
- `ffs_extent::map_logical_to_physical(count > 1)` uses the range walk to emit the same ordered mapping/hole segments.
- `count == 1` remains on the existing single-search path.

After measurements:

- Same-worker pre-checkpoint-cadence sanity run on `vmi1153651`: 298.38 us mean, [291.63 us, 305.33 us].
- Final post-checkpoint-cadence run on `vmi1227854`: 201.02 us mean, [186.18 us, 219.22 us].
- The final upper bound remains below the baseline lower bound by 177.07 us.

Behavior proof:

- Ordering preserved: yes. `walk_range` preserves the existing btree walk/index order, and `map_logical_range_by_walk` appends holes/extents in increasing logical position.
- Tie-breaking unchanged: yes. Extents are still sorted by logical block; overlapping/unsorted corrupt trees are rejected by existing parse invariants.
- Floating-point identical: N/A.
- RNG seeds unchanged: N/A.
- Golden outputs verified:
  - `(cd conformance/fixtures && sha256sum -c checksums.sha256)`
  - `(cd conformance/golden && sha256sum -c checksums.sha256)`
- Differential proof: `map_depth1_range_matches_repeated_search_and_reads_leaf_once` builds a 100-extent depth-1 tree, asserts new output equals the old repeated-search output, and verifies the new path reads the leaf once.

Closeout gates:

- `rch exec -- cargo test -p ffs-extent map_depth1_range_matches_repeated_search_and_reads_leaf_once -- --nocapture`
- `rch exec -- cargo test -p ffs-btree -p ffs-extent --lib -- --nocapture`
- `rch exec -- cargo check -p ffs-btree -p ffs-extent --all-targets`
- `rch exec -- cargo clippy -p ffs-btree -p ffs-extent --all-targets -- -D warnings`
- `cargo fmt --package ffs-btree --package ffs-extent --check`
- `git diff --check`

Score: Impact 4 x Confidence 4 / Effort 2 = 8.0.
