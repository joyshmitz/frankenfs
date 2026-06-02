# bd-xmh5g.2 — Direct Bw-tree point lookup (no full page materialization)

**Date:** 2026-06-02 · **Crate:** `ffs-btree` · **Lever:** one (point-query traversal)

## Problem

`MappingTable::lookup` previously called `materialize_page`, which **clones the entire
base `BTreeMap` and replays the full delta chain** before probing a single key. The
`read_heavy/bwtree/1` Criterion workload is ~95% `lookup`, so every point query paid
O(base-page-size) clone + replay cost. Baseline (worker vmi1227854, PlumFern):
`read_heavy/bwtree/1` mean **1.1969 s**.

## Lever

Add `lookup_from_head`: walk the delta chain newest→oldest, resolve the first matching
`Insert`/`Delete`, short-circuit on `Split` tail exclusion (`key >= separator`), treat
`Merge` as lookup-neutral, and fall back to `base.get(&key)` — **no clone, no full
materialization**. `lookup` now calls this directly.

## Isomorphism proof (behavior parity — absolute)

`lookup_from_head(head, k)` is provably equal to `materialize_from_head(head).get(&k)`
for every key, verified by case analysis over the delta variants:

- **Insert/Delete**: newest matching delta wins (latest-writer-wins) — identical to the
  reverse-replay `apply_op` order in `materialize_from_head`.
- **Split**: `materialize` removes all keys `>= separator` at the split's chain position;
  a key `>= separator` reached at a `Split` has no newer Insert/Delete shadowing it
  (those are walked first), so returning `None` matches. Newer re-inserts of a
  `>= separator` key are hit before the `Split` in both paths.
- **Merge**: skipped (lookup-neutral) in both paths — identical.
- **Base**: `entries.get(&key)` — identical.

Cross-checked at runtime by the existing split/shadow tests plus the new
`direct_lookup_matches_materialized_state_for_golden_trace` test, which asserts
`lookup == materialize_page().get()` for every key over a multi-delta trace and emits a
golden render. **143/143 `ffs-btree` lib tests pass.**

Golden trace (deletes render as `-`):

- `golden_trace.tsv` — `BWTREE_GOLDEN\t<key>\t<value|->`
- `golden_trace.sha256` = `f4ac6ce02734a75890d569439a6ad13acf4b15261c913d1245cbc8247bbc4944`

## Performance proof (same-binary A/B — machine-independent)

`bwtree_vs_locked` bench, new `point_lookup` group. Both arms probe the same 64 keys
against the same consolidated 10k-entry base page carrying a short post-consolidation
delta chain, in the **same binary on the same worker** (ratio is machine-independent):

| Arm | Path | Median (recorded raw) |
|-----|------|--------|
| `old_materialize_then_get` | `materialize_page()` + `.get()` per probe | **11.017 ms** |
| `new_direct_lookup` | `lookup()` → `lookup_from_head` | **8.854 µs** |

**Score ≈ 11 017 µs / 8.854 µs ≈ 1244× faster** on the point-query lever (≫ 2.0 target).
A second worker run measured 6.998 ms vs 4.633 µs ≈ 1510×; the ratio is stable across
workers (both arms scale with worker speed), confirming it is machine-independent. The
gap is dominated by the avoided per-probe clone+replay of the 10k-entry base map.

Raw: `point_lookup_ab.txt` (recorded run).

## Constraints honored

- `#![forbid(unsafe_code)]` intact; safe Rust only.
- Behavior parity absolute (isomorphism proof + golden sha256 above).
- `cargo clippy -p ffs-btree --all-targets` clean (`-D nursery`); `cargo fmt` clean.
