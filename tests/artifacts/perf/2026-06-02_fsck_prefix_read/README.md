# bd-xmh5g.6 — fsck reads whole image into RAM but only needs the SB+GDT prefix

**Date:** 2026-06-02 · **Crate:** `ffs-cli` · **Lever:** one (scope the fsck image read)

## Problem (rank-2 symptom of the 2026-06-01 PlumFern hotspot table)

`build_fsck_output` opened every filesystem with:

```rust
let image = std::fs::read(path)?;   // entire device into a heap Vec
```

That allocates and copies the **whole device** (e.g. 8 MiB) on every `fsck`. But:

- **btrfs** never touches `image` (only `image_len`, taken from the byte device) — the
  entire whole-image read + 8 MiB allocation was pure waste.
- **ext4** feeds it to `Ext4ImageReader` + `validate_ext4_group_descriptors`, which call
  **only `read_group_desc`** — i.e. they read the superblock and the group-descriptor
  table (a small prefix immediately after the SB), never inodes or data blocks. The
  `Scrubber` already re-reads every data block via batched vectored I/O (bd-a384r), so the
  whole-image `std::fs::read` duplicated ~8 MiB of I/O it never used.

This 8 MiB alloc+zero+copy is exactly the rank-2 `__memmove_avx/__memset_avx2` cost in
`docs/perf/2026-06-01_plumfern/HOTSPOT_TABLE.md`.

## Lever

- **btrfs**: drop the whole-image read entirely (buffer was unused).
- **ext4**: read only `[0, gdt_end)` where
  `gdt_end = group_desc_offset(last_group) + group_desc_size`, clamped to the device
  length. Falls back to the full length only if the offset can't be computed (overflow).

```rust
let prefix_len = sb
    .group_desc_offset(GroupNumber(sb.groups_count().saturating_sub(1)))
    .and_then(|off| off.checked_add(u64::from(sb.group_desc_size())))
    .map_or(image_len, |gdt_end| gdt_end.min(image_len));
let mut image = vec![0u8; prefix_len as usize];
byte_dev.read_exact_at(&cx, ByteOffset(0), &mut image)?;
```

The GDT always sits *after* the superblock for every ext4 block size (1 KiB → GDT at
offset 2048; ≥2 KiB → GDT at `block_size` ≥ 2048), so the prefix always covers the SB
that `Ext4ImageReader::new` parses. Clamping to `image_len` preserves the **identical**
`ParseError` for a truncated/malformed GDT (`ensure_slice` fails for the same descriptors
as the previous full-image slice).

## Behavior parity — PROVEN

`cargo test -p ffs-cli --test cli_e2e fsck` (real `mkfs.ext4`/`mkfs.btrfs` images, no mocks)
— **5/5 pass**, directly covering every changed path:

| Test | Covers |
|------|--------|
| `cli_fsck_json_output` | ext4 `fsck -f --json` output unchanged (the prefix path) |
| `cli_fsck_ext4_clean_image` | ext4 clean-state scan |
| `cli_fsck_corrupted_superblock_reports_error` | error parity |
| `cli_fsck_truncated_image_returns_error` | the `gdt_end.min(image_len)` clamp path |
| `cli_fsck_btrfs_runs_without_crash` | btrfs whole-image-read elimination |

```
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 21 filtered out
```

## I/O reduction (deterministic)

Per `fsck`, the whole-device `std::fs::read` (and its `image_len`-byte heap allocation +
memcpy) is eliminated:

- **btrfs**: full `image_len`-byte read **+ allocation removed entirely** (was 100% unused).
- **ext4 8 MiB reference** (`conformance/golden/ext4_8mb_reference.ext4`, 4 KiB blocks,
  1 group, 64 B descriptor): reader path reads `gdt_end = 4096 + 64 = 4160 B` instead of
  `8 388 608 B` — a **~2017× reduction** on that path. Total `fsck` read I/O drops from
  ~16 MiB (8 MiB `std::fs::read` + 8 MiB scrubber) to ~8 MiB (4 KiB prefix + 8 MiB
  scrubber) = **~2× fewer bytes read**, plus an 8 MiB heap allocation + memcpy removed.

Reduction scales linearly with device size (an N-MiB image previously read N MiB into RAM
just to validate a few-KiB descriptor table).

## Constraints

- `#![forbid(unsafe_code)]` intact; clippy/fmt clean; `cargo check -p ffs-cli` green.
- Parity absolute (5/5 real-image e2e tests above).
