# Design: allocation-gated scrub (opt-in) — the one remaining measured gap vs the original

**Status:** scoped, not implemented. **Owner decision needed** on scope + semantics.
**Author:** BlackThrush, 2026-07-04. Filed after the solo per-crate dig frontier
was verified CLOSED across all crates (see `docs/NEGATIVE_EVIDENCE.md`
COVERAGE-MAP row) — this is the one substantive gap-vs-original that remains, and
it is a correctness-critical CLI-integration effort, NOT a solo single-turn
per-crate lever.

## The gap

`ffs-cli scrub` (via `Scrubber` + `CompositeValidator`) reads and validates
**every** block of the device. On a mostly-empty image the vast majority of
blocks are FREE space, which:

1. **Wastes I/O + CPU** — the dominant cost is reading ~2 GB of free space and
   running `ZeroCheckValidator` (word-wise all-zeros scan) over it. Measured
   share of scrub self-time in the free-space zero-scan alone: **~12.89% btrfs /
   ~7% ext4** (b6bbdd6f-era profiles); the free-block **reads** are a larger
   cost on top.
2. **Emits false positives** — `ZeroCheckValidator` flags free zeroed blocks as
   `UnexpectedZeroes` warnings (61365/102400 ext4, 131050/131072 btrfs blocks on
   the test images). The reference tools (`e2fsck -fn`, `btrfs scrub`) do **not**
   report free zeroed space as corruption.

The reference tools scrub only **allocated** blocks. Closing this gap is both a
perf win (skip free-space I/O + scan) and a fidelity fix (no free-block false
positives). Recoverable ratio ≈ `1 / allocated_fraction` on the scan/read of
free space (e.g. a 10%-full image → ~10x less block I/O + validation).

## Why it is not a solo single-turn per-crate lever

- The `Scrubber` (ffs-repair) is deliberately **block-level / fs-agnostic** — it
  only has a `BlockDevice`. It already supports `scrub_range(start, count)`, so
  the ffs-repair side needs **no new code**: a caller can already scrub arbitrary
  ranges and skip gaps.
- The missing piece is entirely **CLI integration**: `scrub_cmd`
  (`crates/ffs-cli/src/main.rs`) currently opens only a `ByteBlockDevice` +
  detects the flavor. It builds **no fs-state** (no `OpenFs`, no group-descriptor
  walk). So an allocated-block **enumerator** must be built there from scratch.
- The enumerator is **correctness-critical and geometry-complete**: missing an
  allocated block means scrub silently **skips real corruption** (a false
  negative — strictly worse than the current false positives). It must correctly
  handle every ext4 geometry variant:
  - **flex_bg** (bitmaps/inode-tables clustered per flex group),
  - **meta_bg** (group-descriptor placement),
  - **bigalloc** (the "block bitmap" is a **cluster** bitmap — bit → cluster, not
    block; must expand by `clusters_per_group` / `cluster_size`),
  - **64-bit** (`bg_block_bitmap_hi`),
  - **sparse_super** / **uninit_bg** (`BLOCK_UNINIT` → group's data blocks are
    all-unallocated without reading a bitmap; must synthesize the metadata blocks
    the group still owns: superblock backup, GDT, bitmaps, inode table),
  - block 0 / reserved GDT blocks / journal inode blocks.

This is exactly the class of change the campaign discipline says must **not** be
rushed (the bd-bhh0i FS-corruptions came from rushing correctness-sensitive
work).

## Proposed implementation (owner to approve)

1. Add an opt-in flag `scrub --allocated-only` (default OFF → existing
   all-block semantics unchanged; no regression, no maintainer semantics call
   for the default path).
2. For ext4: build `fn ext4_allocated_block_ranges(cx, sb, dev) ->
   Vec<(BlockNumber, u64)>` that walks all groups, reads each group's block
   bitmap (respecting `BLOCK_UNINIT`, flex_bg, meta_bg, bigalloc, 64-bit),
   and emits merged allocated ranges. Reuse `read_group_desc`
   (ffs-ondisk/ext4.rs:4677) + the block-bitmap helpers already present
   (`verify_block_bitmap_checksum`, `verify_block_bitmap_free_count`).
3. Scrub each allocated range via the existing `Scrubber::scrub_range`; free
   gaps are simply not scanned.
4. btrfs: harder (allocation lives in the extent tree, not a flat bitmap) —
   ship ext4 first; btrfs is a separate follow-up.

## Gating (mandatory before merge)

- **A/B correctness:** on an `e2fsck -fn`-clean image, `scrub --allocated-only`
  must report **zero real findings** (i.e. the full-scan findings **minus** the
  free-block `UnexpectedZeroes` warnings) — proves it does not lose coverage of
  in-use blocks.
- **Injected corruption:** corrupt a byte in an **allocated** block →
  `--allocated-only` MUST still flag it (no false negative). Corrupt a **free**
  block → `--allocated-only` correctly ignores it (that is the intended fidelity
  change).
- **Geometry matrix:** run the A/B on images built with flex_bg, meta_bg,
  bigalloc, 64-bit, and a mostly-uninit large image.
- **Measured ratio:** record scrub wall-time all-block vs `--allocated-only` on a
  10%-full and 50%-full image in `docs/NEGATIVE_EVIDENCE.md`.

## Non-goals

- Changing the **default** scrub semantics (stays all-block; opt-in only).
- btrfs allocation-gating (separate follow-up).
