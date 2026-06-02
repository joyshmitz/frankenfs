# bd-dlc4x: bitmap_largest_free_run word aggregation

## Target

- Bead: `bd-dlc4x`
- Crate: `ffs-alloc`
- Function: `bitmap_largest_free_run`
- Profile source: `rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot`
- Baseline worker: `vmi1227854`

## Profile Baseline

Top residual bitmap row before the lever:

- `largest_free_run/fragmented_mixed_bytes`: mean `6.5948 us`, interval `[6.2932 us, 6.9274 us]`
- `succinct_build`: mean `1.2137 us`, interval `[1.1551 us, 1.2657 us]`
- `count_free/plain_O(n)`: mean `414.32 ns`, interval `[337.35 ns, 538.83 ns]`
- `find_contiguous/plain_32_O(n)`: mean `75.133 ns`, interval `[71.507 ns, 77.518 ns]`

## Lever

One lever: replace the byte-at-a-time full-byte scan in `bitmap_largest_free_run` with safe word-at-a-time zero-run aggregation over aligned 8-byte chunks, keeping the existing byte summary table for tails and exact partial-byte masking.

Alien-graveyard primitive: `alien_cs_graveyard.md` section 7.1 succinct data structures / bitvector broadword operations.

## Isomorphism Proof

- Ordering preserved: yes. Bits are still interpreted LSB-first from the same little-endian bitmap byte order.
- Tie-breaking unchanged: N/A. The function returns only a run length, not a position.
- Floating-point identical: N/A. The function is integer-only.
- RNG seeds unchanged: N/A. No RNG is used.
- Truncated bitmap behavior preserved: yes. Missing full bytes still break any in-flight run and contribute no free bits; missing remainder byte leaves `best` unchanged.
- Partial-byte behavior preserved: yes. The trailing byte is still masked with `byte | !mask` before applying the byte zero-run table.
- Golden output sha256: `b21427931653ed162ae8c8d84bf1ce171a8007ae5f34e144f001c4be2bdf303f` before and after.

Golden command:

```bash
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary TMPDIR=/data/tmp timeout 1200 rch exec -- cargo test -p ffs-alloc bitmap_largest_free_run_golden_report --lib -- --nocapture --test-threads=1
```

## Re-benchmark

Re-bench worker: `vmi1149989`

- `largest_free_run/fragmented_mixed_bytes`: mean `969.97 ns`, interval `[872.34 ns, 1.0913 us]`

Baseline-to-after comparison:

- `6.5948 us` to `969.97 ns`
- Ratio: about `6.80x` faster
- Mean reduction: about `85.3%`

Score: Impact `4` x Confidence `4` / Effort `2` = `8.0`, keep.

## Gates

- `rch exec -- cargo test -p ffs-alloc bitmap_largest_free_run --lib -- --test-threads=1`: pass, 6 tests.
- `rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_ops -- --warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot`: pass.
- `rch exec -- cargo fmt --package ffs-alloc --check`: pass.
- `rch exec -- cargo check -p ffs-alloc --all-targets`: pass.
- `rch exec -- cargo clippy -p ffs-alloc --all-targets -- -D warnings`: pass.
