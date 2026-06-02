# bd-xmh5g.4 — word-at-a-time find_contiguous: REJECTED (1.63× < 2.0)

**Date:** 2026-06-02 · **Crate:** `ffs-alloc` · **Outcome:** lever reverted; tests retained.

## Lever attempted

Add a 64-bit word fast path to `bitmap_find_contiguous_linear`: on a 64-bit aligned
boundary with a full window remaining, read an LE `u64` (bytes past the slice end = `0xFF`
used, matching `bitmap_get`) and collapse all-used (`u64::MAX` → skip 64) / all-free
(`0` → extend run by 64, early-return if `>= n`) windows in one step; mixed words fall
through to the existing per-byte path. Alien primitive: broadword word-parallel scan.

## Isomorphism — PROVEN (parity held)

The lever was behavior-identical. Confirmed by:

- `proptest_find_contiguous_matches_naive` (512 cases, random bitmaps/`n`/`start`) — the
  scan equals a pure per-bit first-fit reference.
- `bitmap_find_contiguous_golden_report` — `select`-style golden across `n ∈ {1,8,11,12,
  32,64,65,128}` × `start ∈ {0,1,64,65,128,200,256}` over a 320-bit map crossing several
  64-bit word boundaries (all-used, all-free, mixed). Golden sha256
  `f8c518e21636bc6ac4da36cd0281c6ea4fce9a41c66174b089ff6c97e2df1e3f` (56 rows,
  `golden_trace.tsv`).

## Performance — BELOW BAR

Same-binary A/B (`bitmap_ops` `find_contiguous_scan`), representative ext4 workload
(`make_bitmap`: 4096 B mostly `0xFF`, 5% free clusters; search `n=32` from `start=16000`):

| Arm | Median |
|-----|--------|
| `old_byte_scan` | **66.332 ns** [63.870, 68.850] |
| `new_word_scan` | **40.614 ns** [38.907, 42.259] |

**Score ≈ 66.332 / 40.614 ≈ 1.63×** — a real, CI-separated win, but **below the
campaign's Score ≥ 2.0 bar.** The skip distance on this representative workload (~350
bits from `start` to the next free cluster) is too short for the 8×-fewer-iterations
word skip to dominate the fixed per-call + mixed-word-cluster cost. (The analogous
word-parallelize of `bitmap_largest_free_run` was likewise rejected — bd-knxlf.)

Raw: `find_contiguous_scan_ab.txt`.

## Decision

Per `/extreme-software-optimization` discipline ("Score ≥ 2.0 … otherwise revert"), the
production word-path lever and its `read_used_word_le` helper were **reverted**. The two
new tests (`proptest_find_contiguous_matches_naive`, `bitmap_find_contiguous_golden_report`)
are **retained** — they validate the existing byte-scan against a naive reference and add
durable regression coverage the function previously lacked. `#![forbid(unsafe_code)]`
intact; clippy/fmt clean.
