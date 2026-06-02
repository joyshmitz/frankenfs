# bd-xmh5g.7 — eliminate redundant scrub buffer zeroing / per-batch allocation

**Date:** 2026-06-02 · **Crates:** `ffs-core`, `ffs-repair` · **Lever:** one (reuse + skip-zero)

## Problem (rank-2 residual, confirmed by fresh strace)

After bd-a384r (batched preadv) and bd-xmh5g.6 (fsck prefix read), a fresh `strace -c` of
`fsck -f` shows I/O is optimal (32 batched preadv, no whole-image read; see
`../2026-06-02_tealmarten_strace/`). The residual rank-2 (`__memset`/`__memmove`) cost is
buffer churn on the scrub read path:

- `BlockDevice::read_contiguous_blocks` (`ffs-core/src/lib.rs`) did
  `*buf = BlockBuf::zeroed(block_size)` for **every** buffer on **every** batch.
- `Scrubber::scrub_range` (`ffs-repair/src/scrub.rs`) re-allocated the `bufs` vec each batch.

`read_vectored_exact_at` (preadv) fills every byte or returns `UnexpectedEof`, so the
zeroing is pure waste: an 8 MiB scrub allocated + zeroed ~8 MiB of buffers (64 × 4 KiB ×
32 batches) that were immediately overwritten, plus ~2048 allocations.

## Lever

- `read_contiguous_blocks`: only `BlockBuf::zeroed` a buffer when it is **not already**
  `block_size`; already-sized buffers are reused as-is (preadv overwrites them).
- `scrub_range`: hoist the `bufs` pool out of the batch loop and `resize_with` it once;
  reuse across all batches.

## Behavior parity — PROVEN

Bytes are fully overwritten by preadv on success (Err leaves buffers unused), so output is
bit-identical. Verified on real images / data:

- `cargo test -p ffs-repair --lib scrub` — **55 passed**.
- `cargo test -p ffs-cli --test cli_e2e fsck` — **5 passed** (real `mkfs.ext4`/`mkfs.btrfs`
  images: json output, clean, corrupted, truncated, btrfs).
- `cargo clippy -p ffs-repair -p ffs-core --all-targets` — clean.

## Performance proof (same-binary A/B)

`scrub_codec` bench, `scrub_buffer_prep` group: 64 blocks × 32 batches (8 MiB), both arms
touching every buffer via `simulate_read_fill` (stands in for preadv):

| Arm | Path | Median |
|-----|------|--------|
| `old_zero_per_batch` | `BlockBuf::zeroed` × 64 fresh per batch | **353.67 µs** |
| `new_reuse_pool` | reuse pool + skip re-zero when sized | **25.80 µs** |

**Score ≈ 353.67 / 25.80 ≈ 13.7×** on the buffer-prep path (≫ 2.0). The gap is the
eliminated 8 MiB of allocation + `memset` that preadv would overwrite anyway.

Raw: `scrub_buffer_prep_ab.txt`.

## Constraints

- `#![forbid(unsafe_code)]` intact; safe Rust (reuse + conditional zero only).
- Parity absolute (55 scrub + 5 real-image fsck e2e tests).
