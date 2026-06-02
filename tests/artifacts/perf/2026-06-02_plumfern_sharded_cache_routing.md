# bd-xmh5g.1 - ffs-block power-of-two sharded cache routing

## Target

- Bead: `bd-xmh5g.1`
- Crate: `ffs-block`
- Hot path: `ShardedArcCache::shard_index_for` in the 64-thread hot-read benchmark.
- One lever: cache `shard_mask = shard_count - 1` when `shard_count` is a power of two, route with `block.0 & mask`, and keep the existing modulo path for non-power-of-two shard counts.
- Safe Rust only; no unsafe code and no C linkage.

## Baseline

Command:

```text
RCH_FORCE_REMOTE=true rch exec -- cargo bench --profile release-perf -p ffs-block --bench arc_cache -- concurrent_hot_read_64threads --noplot
```

Worker: `vmi1167313`

Criterion means:

| row | mean | interval |
| --- | ---: | --- |
| `block_cache_arc_concurrent_hot_read_64threads` | 99.849 ms | [93.840, 106.43] ms |
| `block_cache_sharded_arc_concurrent_hot_read_64threads` | 51.459 ms | [48.754, 54.359] ms |

Baseline sharded/control ratio: `0.515`.

## After

Command:

```text
RCH_FORCE_REMOTE=true rch exec -- cargo bench --profile release-perf -p ffs-block --bench arc_cache -- concurrent_hot_read_64threads --noplot
```

Worker: `vmi1293453`

Criterion means:

| row | mean | interval |
| --- | ---: | --- |
| `block_cache_arc_concurrent_hot_read_64threads` | 74.277 ms | [69.890, 78.849] ms |
| `block_cache_sharded_arc_concurrent_hot_read_64threads` | 15.545 ms | [14.722, 16.430] ms |

After sharded/control ratio: `0.209`.

## Delta

- Raw sharded row: `51.459 ms -> 15.545 ms`, `-69.79%`.
- Control-normalized ratio: `0.515 -> 0.209`, `-59.4%`.
- Worker skew note: the unsharded control also improved on the after worker (`99.849 ms -> 74.277 ms`), so the normalized ratio is the conservative comparison.
- Score: `15.0 = Impact 5 x Confidence 3 / Effort 1`; keep threshold `>= 2.0` satisfied.

## Alien Recommendation Card

- Symptom: hot routing path pays integer modulo for every block under high-core sharded cache read bursts.
- Primitive: cache-conscious control-path reduction from the alien graveyard's layout/probe-path minimization family; precompute a cheap routing discriminator and avoid the higher-latency division/modulo operation where algebra permits it.
- Expected value: `5 x 3 / 1 = 15.0`.
- Fallback: retain the modulo path for non-power-of-two shard counts; revert the mask field if the sharded/control ratio regresses below baseline.

## Isomorphism Proof

- Ordering preserved: yes. For every unsigned block number `x` and power-of-two shard count `n`, `x & (n - 1) == x % n`; the new unit test checks this for all blocks `0..128` with `n = 8`.
- Non-power-of-two behavior preserved: yes. The cached mask is `None`, so `shard_index_for` executes the original modulo expression; the unit test checks `n = 5`.
- Tie-breaking unchanged: yes. No eviction, ARC recency, dirty-block, or victim-selection logic changed.
- Floating-point bits: N/A. No floating-point code is touched.
- RNG seeds: unchanged. The deterministic workload report still uses seeds `2711683073..2711683077`.
- Error classes unchanged: yes. Constructor validation for zero capacity and zero shard count is unchanged.

## Golden Output

Command:

```text
RCH_FORCE_REMOTE=true rch exec -- bash -lc 'set -euo pipefail; FFS_BLOCK_CACHE_WORKLOAD_REPORT=- cargo bench --profile release-perf -p ffs-block --bench arc_cache 2>/dev/null | tee >(sha256sum >&2)'
```

Stream sha256:

```text
3f8b444b755bbaf74b7287be6a70840d68bcb974b7483a1e948faf3f8294ac74  -
```

Report rows:

```text
policy	workload	accesses	hits	misses	hit_rate	resident	capacity	b1_len	b2_len	memory_overhead_per_cached_block	seed
arc	sequential_scan	16384	0	16384	0.000000	512	512	0	0	0.000000	2711683073
arc	zipf_distribution	24000	18574	5426	0.773917	512	512	500	12	1.000000	2711683074
arc	mixed_seq70_hot30	24000	7447	16553	0.310292	512	512	64	0	0.125000	2711683075
arc	compile_like	14848	2285	12563	0.153893	640	640	421	219	1.000000	2711683076
arc	database_like	38880	33132	5748	0.852160	768	768	715	53	1.000000	2711683077
```

Note: writing the report to remote `/tmp` failed with ENOSPC, so the accepted golden check hashes the report stream instead of a remote file. A later direct `rch exec -- cargo bench` env-forward attempt was rejected as evidence because the report env did not reach the remote command and it entered full Criterion sampling.

## Validation

- `RCH_FORCE_REMOTE=true timeout 700 rch exec -- cargo test -p ffs-block --lib sharded_arc_cache -- --nocapture`
  - Worker: `vmi1293453`
  - Result: `3 passed; 0 failed; 255 filtered out`
- `RCH_FORCE_REMOTE=true timeout 700 rch exec -- cargo check -p ffs-block --all-targets`
  - Worker: `vmi1293453`
  - Result: pass
- `RCH_FORCE_REMOTE=true timeout 900 rch exec -- cargo clippy -p ffs-block --all-targets -- -D warnings`
  - Worker: `vmi1227854`
  - Result: pass
- `RCH_FORCE_REMOTE=true timeout 300 rch exec -- cargo fmt --package ffs-block --check`
  - Result: pass
