# bd-xmh5g.3 — Broadword select0 inside the succinct bitmap block

**Date:** 2026-06-02 · **Crate:** `ffs-alloc` · **Lever:** one (in-block select0 scan)

## Problem

`SuccinctBitmap::select0` locates the target superblock and 256-bit local block in
O(1)/O(log) via the rank index, then scanned the **final block bit-by-bit** with
`get_bit`, decrementing a counter until the k-th zero. Baseline (worker vmi1227854,
PlumFern): `succinct_select0` mean **197.58 ns** [182.14, 218.21]. The in-block bit loop
is the residual hot path once the index lands on the block.

## Lever

`select0_in_block`: walk the block in **64-bit words**. For each word read a zero-mask
(`!read_word` masked to the valid tail), use `count_ones()` to skip whole words whose
zero-count is `<= remaining`, and `select_nth_set_bit` (`trailing_zeros` + clear-lowest
loop) to pick the k-th zero in the landing word. Replaces the per-bit `get_bit` loop;
safe-Rust broadword (alien_cs_graveyard §7.1 rank/select bitvectors).

## Isomorphism proof (behavior parity — absolute)

`select0_in_block` returns the same position as the old ascending per-bit scan:

- **Bit order**: `read_word` is little-endian, so bit `i` of the word = position
  `word_base + i` = `get_bit(word_base + i)`; `trailing_zeros` picks the lowest set
  (= lowest position) zero first — identical ascending order.
- **k-th zero**: `select_nth_set_bit(mask, remaining)` returns the `remaining`-th
  (0-indexed) lowest set bit; the old loop returned when its zero counter hit 0 — same
  index. Words fully consumed (`remaining >= zeros_in_word`) decrement `remaining` by the
  exact `count_ones()`, matching the per-bit decrements.
- **Tail masking**: `block_end = min(word_base + 256, len)`; the final partial word is
  masked to `(1 << bits_in_word) - 1`, so bits `>= len` are never counted — identical to
  the old `bits_in_block = 256.min(len - bit_base)` bound.
- **None behavior**: falls through the `while word_base < block_end` loop and returns
  `None` when fewer than `k+1` zeros exist — same as the old loop.

Cross-checked at runtime by `select0_golden_report`, which asserts `select0(k)` equals
the naive `(0..len).filter(!get_bit)` enumeration for **every** `k` in `0..=count_zeros`
(including the `None` tail) over a 305-bit map crossing a 256-bit block boundary.
**199/199 `ffs-alloc` lib tests pass** (incl. existing `rank_select_consistency` and
`select0`/`rank0`/`find_free` proptests).

Golden trace: `golden_trace.tsv` — `SUCCINCT_SELECT0_GOLDEN\t<k>\t<pos|None>`
`golden_trace.sha256` = `bb12fd98905f1fdcb0bd0ca8751e6ff851e1d575f680ad332664b69dcb9529a5`

## Performance proof (same-binary A/B — machine-independent)

`bitmap_ops` bench, `select0_in_block` group. Both arms run the identical in-block scan
logic against the same block in the **same binary on the same worker**:

| Arm | Path | Median |
|-----|------|--------|
| `old_bit_scan` | per-bit `get_bit` loop | **60.925 ns** |
| `new_broadword` | 64-bit zero-mask + popcount skip + `select_nth_set_bit` | **25.820 ns** |

**Score ≈ 60.925 ns / 25.820 ns ≈ 2.36× faster** on the in-block select0 lever (≥ 2.0).

Raw: `select0_in_block_ab.txt`.

## Constraints honored

- `#![forbid(unsafe_code)]` intact; safe-Rust broadword only.
- Behavior parity absolute (isomorphism proof + golden sha256 above).
- `cargo clippy -p ffs-alloc --all-targets` clean; `cargo fmt` clean.
