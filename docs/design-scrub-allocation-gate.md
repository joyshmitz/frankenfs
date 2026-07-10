# Design: allocation-gated scrub (opt-in) — the one remaining measured gap vs the original

**Status:** scoped, not implemented. **Owner decision needed** on scope + semantics.
**Author:** BlackThrush, 2026-07-04. Filed after the solo per-crate dig frontier
was verified CLOSED across all crates (see `docs/NEGATIVE_EVIDENCE.md`
COVERAGE-MAP row) — this is the one substantive gap-vs-original that remains, and
it is a correctness-critical CLI-integration effort, NOT a solo single-turn
per-crate lever.

> **UPDATE 2026-07-09 (BlackThrush / cc_ffs): gap (2) below — the false
> positives — is FIXED and needs no allocation gate.** This doc assumed the
> enumerator was required for *both* halves. It is not. Three independent
> false-positive classes were root-caused and removed without any allocation map
> (commits `b2db6d0e`, `fdfba7b2`, `af469da7`):
>
> 1. the blind whole-image `ZeroCheckValidator` (removed from both validator
>    sets — free space is legitimately zero, and a zeroed *superblock* is still
>    caught by the superblock validator's magic/parse check),
> 2. `BtrfsTreeBlockValidator` comparing `header.bytenr` (a **logical**,
>    chunk-mapped address) against the **physical** offset `block * block_size`
>    (`bd-5vb36`),
> 3. btrfs backup superblocks at the 64 MiB / 256 GiB mirrors being
>    misclassified as tree blocks (they carry `fsid` at the same `0x20..0x30`).
>
> All 7 valid test images (5 btrfs + 2 ext4) now scrub **0 corrupt / 0 findings**,
> and an injected single-bit flip in a live tree block is still reported
> (`checksum_mismatch`/critical). **Only gap (1), the perf half, remains** — and
> that is what the allocated-block enumerator below is for. Note that with the
> zero-scan gone, the "~12.89% btrfs / ~7% ext4 zero-scan self-time" figure below
> no longer applies; the residual free-space cost is the block **reads**.

## The gap

`ffs-cli scrub` (via `Scrubber` + `CompositeValidator`) reads and validates
**every** block of the device. On a mostly-empty image the vast majority of
blocks are FREE space, which:

1. **Wastes I/O + CPU** — the dominant cost is reading ~2 GB of free space and
   running `ZeroCheckValidator` (word-wise all-zeros scan) over it. Measured
   share of scrub self-time in the free-space zero-scan alone: **~12.89% btrfs /
   ~7% ext4** (b6bbdd6f-era profiles); the free-block **reads** are a larger
   cost on top. *(2026-07-09: the zero-scan itself is gone — see the update
   above. The free-block reads remain.)*
2. ~~**Emits false positives**~~ — **FIXED 2026-07-09, no enumerator needed.**
   `ZeroCheckValidator` flagged free zeroed blocks as `UnexpectedZeroes`
   warnings (61365/102400 ext4, 131050/131072 btrfs blocks on the test images).
   The reference tools (`e2fsck -fn`, `btrfs scrub`) do **not** report free
   zeroed space as corruption — and now neither do we.

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

## The crux: `BLOCK_UNINIT` makes the common case the hard case (analysis 2026-07-04)

Do **not** attempt a "simple version that returns None (→ full-scan fallback)
for `BLOCK_UNINIT` groups" — it would be **useless**: `mkfs.ext4` sets
`uninit_bg` by default, so on any fresh image essentially **every** group is
`BLOCK_UNINIT` and the fast path would never activate.

Why uninit groups are the hard part: for a `BLOCK_UNINIT` group the on-disk
block bitmap is **not initialized on disk** (that is the whole point of the
flag), so you **cannot read it** to learn which blocks are allocated. The
allocated blocks of an uninit group must be **synthesized** from geometry —
they are exactly the group's owned metadata: its backup superblock + GDT (only
in groups selected by `sparse_super`), and its block-bitmap / inode-bitmap /
inode-table blocks — whose **physical locations under `flex_bg` are clustered
into the first group of the flex group**, not at the group's own start. So a
correct enumerator must compute the flex_bg metadata layout, not just read
bitmaps. This is the intricate, correctness-critical core; there is no safe
"common-case-only" shortcut. Budget it as a focused, e2fsck-gated task.

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
