# bd-xmh5g.10 — cache Bw-tree chain length for append/consolidation decisions

**Date:** 2026-06-02 · **Crate:** `ffs-btree` · **Lever:** one (cached per-page chain length)

## Problem (profile-backed, rank-1 ffs-btree gap)

`MappingTable::append_delta` (and `consolidate_page`, `scan_for_consolidation`) called
`chain_length(&snapshot.head)` on every operation, walking the entire growing delta chain.
For N sequential inserts before consolidation this is **O(N²)** pointer-chasing. The
`bwtree_vs_locked` bench showed the bw-tree **40×–800× slower than the locked baseline**:
`write_heavy/bwtree/8` ≈ **10.018 s** vs locked 26.96 ms; `read_heavy/bwtree/8` ≈ **717 ms**
vs locked 17.19 ms.

## Lever

Store the chain length next to the head pointer: `MappingEntry.head: RwLock<PageHead>`
where `PageHead { delta, chain_len }`. `chain_len` is updated **only on a successful
`cas_page`** — computed as `snapshot.chain_len + 1` for an appended delta, or `1` for a
fresh consolidated base. `append_delta`/`consolidate_page`/`scan_for_consolidation` read
`snapshot.chain_len` instead of walking the chain. No per-op walk → **O(N)**.

## Isomorphism — PROVEN (every CAS validated)

`cas_page` carries `debug_assert_eq!(chain_length(&new_head), new_chain_len)`, so in test/
debug builds **every successful CAS re-walks and verifies the cached length is exact**.
Because the cache is only updated under the epoch-CAS (which fails on any concurrent
mutation since the snapshot), `snapshot.chain_len + 1` is always the true new length.

- **143/143 `ffs-btree` lib tests pass** with that assert live, plus a new
  `assert_cached_chain_len_matches` helper asserting `cached == chain_length(head)` across
  insert-growth, consolidation, scan, split-shadow, and preconsolidation scenarios.
- Golden bw-tree lookup report unchanged (lookup/materialize semantics untouched):
  `bwtree_lookup_golden.sha256`.
- `cargo clippy -p ffs-btree --all-targets` clean.

## Performance proof (`bwtree_vs_locked`, 8 writers)

| Scenario | Baseline (bead) | After | Speedup |
|----------|-----------------|-------|---------|
| `write_heavy/bwtree/8` | 10.018 s | **81.75 ms** | **~122×** |
| `read_heavy/bwtree/8` | 717.36 ms | **29.00 ms** | **~24.7×** |
| `mixed/bwtree/8` | 11.47 s | **1.035 s** | **~11×** |

Same-run `locked_btree/8` references: write 26.24 ms, read 16.23 ms — the bw-tree is now
within ~3× of the locked baseline (was 380×/40× slower). Score ≫ 2.0. Raw: `bwtree_bench.txt`.

## Constraints

- `#![forbid(unsafe_code)]` intact; safe Rust (cached `usize` beside the head under the
  existing `RwLock`/epoch-CAS).
- Behavior parity absolute (per-CAS `debug_assert` + 143 tests + golden sha256).
