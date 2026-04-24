# Conformance Divergences - btrfs on-disk format

Every intentional deviation from the kernel btrfs format must be catalogued
here. Tests that trip an accepted divergence use XFAIL (or parse-only
round-trips), not SKIP.

## DISC-BTRFS-001: Kernel-untracked INODE_ITEM fields are zeroed

- **Reference:** Linux `btrfs_inode_item` (fs/btrfs/ctree.h) carries
  `transid`, `block_group`, `flags`, `sequence`, and `reserved[4]` u64
  fields that are meaningful to the kernel (`transid` tracks the last
  write's commit sequence, `flags` include `BTRFS_INODE_NODATACOW` etc.).
- **Our impl:** `BtrfsInodeItem::to_bytes` at
  `crates/ffs-btrfs/src/lib.rs:243-267` zeroes all of these fields because
  the VFS layer does not track them; FrankenFS's INODE_ITEM participates
  in the FUSE path, not the kernel's on-disk mount path.
- **Impact:** A FrankenFS-written INODE_ITEM has no `BTRFS_INODE_*` flags
  set and `transid=0`. Kernel-mount reads of such an inode see "immutable
  by default" with "never committed" generation-like semantics.
- **Resolution:** ACCEPTED for V1. The conformance fixtures therefore
  require these zones to be zero in the fixture bytes so the bit-exact
  round-trip passes. When V2 starts emitting real `transid`/`flags`,
  update these fixtures and split new cases for non-zero values.
- **Tests affected:** `golden_inode_item_regfile_roundtrip`,
  `golden_inode_item_dir_zero_times_roundtrip`,
  `inode_item_u64_bounds_roundtrip`,
  `bitexact_roundtrip_helper_exercises_inode_item`.
- **Review date:** 2026-04-24

## DISC-BTRFS-002: No in-tree encoder for ROOT_ITEM / ROOT_REF

- **Reference:** `btrfs_root_item` / `btrfs_root_ref` are written by the
  kernel on `btrfs subvolume create`, `btrfs subvolume snapshot`, and
  implicit operations like mount-time root-tree COW.
- **Our impl:** `crates/ffs-btrfs/src/lib.rs:490-611` ships `parse_root_item`
  and `parse_root_ref` but no `to_bytes` counterpart. The writable path in
  `ffs-core` seeds the alloc state from the disk's existing ROOT_ITEM and
  mutates `InMemoryCowBtrfsTree` in place; new subvolumes/snapshots are
  not yet supported.
- **Impact:** Cannot write a new subvolume to disk. Read-path conformance
  is fully covered (fixture parse + field-by-field assertions). Encoder
  side is XFAIL.
- **Resolution:** ACCEPTED for V1 read-only + V1.x single-subvolume
  writable. WILL-FIX when multi-subvolume write lands.
- **Tests affected:** `golden_root_item_256_bytes_parse_only`,
  `root_item_bytenr_zero_rejected`, `root_ref_minimal_payload_parses`.
- **Review date:** 2026-04-24

## DISC-BTRFS-003: DIR_ITEM `transid` emitted as zero

- **Reference:** Kernel DIR_ITEM / DIR_INDEX entries carry an 8-byte
  `transid` field at offset 17.
- **Our impl:** `BtrfsDirItem::to_bytes` at `crates/ffs-btrfs/src/lib.rs:287`
  zeroes the `transid` field (documented at the call site). The parser
  correctly ignores this field on read.
- **Impact:** Directory entries written by FrankenFS show "transid=0" in
  `btrfs inspect-internal dump-tree` output. No functional consequence for
  lookup/readdir/rename.
- **Resolution:** ACCEPTED. Fixture bytes use `transid=0`; bit-exact round-
  trip passes.
- **Tests affected:** `golden_dir_item_hello_txt_roundtrip`,
  `dir_item_multiple_entries_concatenate`,
  `dir_item_empty_name_length_2_roundtrips`.
- **Review date:** 2026-04-24

## DISC-BTRFS-004: Checksum types beyond CRC32C unsupported

- **Reference:** btrfs supports CRC32C (type 0), XXHASH64 (type 1), SHA256
  (type 2), and BLAKE2B (type 3) since Linux 5.5.
- **Our impl:** `crates/ffs-ondisk/src/btrfs.rs::verify_tree_block_checksum`
  and `verify_superblock_checksum` return
  `ParseError::InvalidField { field: "csum_type", reason: "only CRC32C (type
  0) is currently supported" }` for any non-CRC32C type.
- **Impact:** Any real btrfs image with a non-CRC32C csum (rare but
  valid) fails to mount.
- **Resolution:** ACCEPTED for V1. Out of scope for this conformance
  family: format-level, not on-disk-encoding.
- **Tests affected:** none in this suite; the behavior is covered by the
  `ffs-ondisk` unit tests for `verify_*_checksum`.
- **Review date:** 2026-04-24
