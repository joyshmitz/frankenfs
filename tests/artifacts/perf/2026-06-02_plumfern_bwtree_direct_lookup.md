# bd-xmh5g.2 - direct Bw-tree lookup without page materialization

Agent: PlumFern
Date: 2026-06-02
Crate: ffs-btree

## Profile-backed target

`MappingTable::lookup` was the hot path in the `read_heavy/bwtree/1` Criterion row. The old path called `materialize_page`, cloned the base `BTreeMap`, replayed the full delta chain, and then performed one key probe.

Baseline command:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 700 rch exec -- cargo bench --profile release-perf -p ffs-btree --bench bwtree_vs_locked -- read_heavy/bwtree/1 --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
```

Baseline worker/result:

```text
vmi1227854
read_heavy/bwtree/1 time [1.1026 s 1.1969 s 1.2996 s]
Criterion warning: unable to complete 10 samples in 2.0s, target expanded to 10.691s.
```

## One lever

`MappingTable::lookup` now performs a newest-to-oldest delta-chain walk for one key. It short-circuits on the first matching `Insert` or `Delete`, preserves split-tail exclusion, skips `Merge` deltas as materialization already does, and falls back to `Base.entries.get(&key)` without cloning the full page.

The old materialization API remains unchanged for range reads, consolidation, and proof benchmarks.

## Alien primitive recommendation card

Symptom: point queries reconstructed whole page state even when the answer was determined by a shallow delta.

Primitive: delta-chain query specialization; avoid reconstructing full state for point queries and exploit newest-wins temporal order for early exit.

Expected value: high. The hot row is dominated by point lookup, the lever removes allocation and full-map clone work, and the fallback materialization path remains available for bulk/range behavior.

Fallback: revert `lookup_from_head` and restore `lookup -> materialize_page -> get` if any lookup/materialization isomorphism test, golden hash, or benchmark score fails.

## Re-benchmark

After command:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 700 rch exec -- cargo bench --profile release-perf -p ffs-btree --bench bwtree_vs_locked -- read_heavy/bwtree/1 --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
```

After worker/result:

```text
vmi1153651
read_heavy/bwtree/1 time [627.47 ms 635.43 ms 644.26 ms]
Criterion warning: unable to complete 10 samples in 2.0s, target expanded to 6.5185s.
```

Delta:

```text
1.1969 s mean -> 635.43 ms mean
-46.91%
Score 12.0 = Impact 4 x Confidence 3 / Effort 1
```

Same-binary A/B proof benchmark:

```text
RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary timeout 700 rch exec -- cargo bench --profile release-perf -p ffs-btree --bench bwtree_vs_locked -- point_lookup --warm-up-time 1 --measurement-time 2 --sample-size 10 --noplot
worker: vmi1149989
point_lookup/old_materialize_then_get time [4.2645 ms 4.4656 ms 4.6590 ms]
point_lookup/new_direct_lookup       time [2.7869 us 2.9354 us 3.1165 us]
same-binary ratio: 1521x faster by mean
```

## Isomorphism proof

Ordering preserved: yes. Direct lookup traverses newest to oldest, which is equivalent to materialization applying old operations into a map and letting newer operations overwrite or remove older state.

Tie-breaking/latest writer preserved: yes. The first matching `Insert` or `Delete` in the newest-to-oldest chain decides the result, exactly matching the final map state after materialization.

Split behavior preserved: yes. A `Split` delta removes keys greater than or equal to the separator from the main page unless a newer delta above the split shadows that decision first.

Merge behavior preserved: yes. Current materialization records merge as a no-op for lookup state; direct lookup also skips `Merge`.

Error class preserved: yes. Direct lookup uses the same `MAX_CHAIN_WALK` corruption guard and error detail as materialization when a chain does not terminate in a base page.

Floating-point identity: N/A.

RNG identity: N/A.

## Golden outputs

Broad golden trace rows:

```text
BWTREE_GOLDEN	0	-
BWTREE_GOLDEN	1	100
BWTREE_GOLDEN	2	-
BWTREE_GOLDEN	3	3333
BWTREE_GOLDEN	4	400
BWTREE_GOLDEN	5	500
BWTREE_GOLDEN	6	-
BWTREE_GOLDEN	7	7000
BWTREE_GOLDEN	8	-
BWTREE_GOLDEN	9	-
BWTREE_GOLDEN	10	-
BWTREE_GOLDEN	11	-
BWTREE_GOLDEN	12	-
BWTREE_GOLDEN	13	-
```

Broad trace sha256:

```text
93708fafce092d55629d110246e941c862fcea9f64c1c1bab95ab72cc1d1daed
```

Compact lookup report sha256:

```text
4d144811f1271f665c3464d25e8cd8350bc153b34bf59fb78284a7a349ef8761
```

## Validation

```text
RCH_FORCE_REMOTE=true timeout 700 rch exec -- cargo test -p ffs-btree split_delta_partitions_data_in_materialization -- --nocapture
PASS

RCH_FORCE_REMOTE=true timeout 700 rch exec -- cargo test -p ffs-btree proptest_materialize_matches_btreemap_model -- --nocapture
PASS

RCH_FORCE_REMOTE=true timeout 700 rch exec -- cargo test -p ffs-btree bwtree_lookup_golden_report -- --nocapture
PASS; compact lookup report sha256 4d144811f1271f665c3464d25e8cd8350bc153b34bf59fb78284a7a349ef8761

RCH_FORCE_REMOTE=true timeout 900 rch exec -- cargo check -p ffs-btree --all-targets
PASS

RCH_FORCE_REMOTE=true timeout 900 rch exec -- cargo clippy -p ffs-btree --all-targets -- -D warnings
PASS

cargo fmt --package ffs-btree --check
PASS
```
