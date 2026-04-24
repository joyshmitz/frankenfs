# Conformance Divergences - ext4 inode on-disk format

Every intentional deviation from the kernel ext4 format is catalogued
here. Tests that trip an accepted divergence use XFAIL (or parse-only
round-trips), not SKIP.

## DISC-EXT4-001: Inode checksum field written as zero by `fuzz_serialize_inode`

- **Reference:** Linux `ext4_inode::i_checksum_lo` (offset 0x7C, 2 bytes)
  and `i_checksum_hi` (offset 0x82, 2 bytes) carry a CRC32C of the inode
  computed with a per-inode seed derived from the ext4 superblock's
  `s_uuid` and the inode number.
- **Our impl:** `crates/ffs-inode/src/lib.rs::serialize_inode` zeroes the
  checksum fields; the production path (`write_inode` at line 117) calls
  `compute_and_set_checksum` AFTER serialization to patch them in place.
  The doc-hidden `fuzz_serialize_inode` helper returns the pre-patch bytes.
- **Impact:** Conformance fixtures use `checksum=0` in both the fixture
  bytes and the expected `Ext4Inode.checksum` field so `parse -> encode`
  is bit-exact. An encoder that hits `compute_and_set_checksum` will not
  match these fixtures byte-for-byte.
- **Resolution:** ACCEPTED. The conformance harness tests the
  layout/encoding correctness of `serialize_inode`; the checksum-compute
  path is covered by `ext4_bitmap_csum.rs` integration tests and the
  `ffs-inode` unit tests for `compute_and_set_checksum`.
- **Tests affected:** all `golden_ext4_inode_*_bitexact` cases.
- **Review date:** 2026-04-24

## DISC-EXT4-002: 128-byte inodes have no extended area at all

- **Reference:** Linux ext4 supports inodes as small as 128 bytes (the
  original ext2/ext3 layout with no checksums, no nsec timestamps).
- **Our impl:** `parse_from_bytes` checks `bytes.len() >= 0x82` before
  reading `extra_isize`; for 128-byte inodes this branch is false and
  all extended fields (extra_isize, checksum_hi, ctime_extra, mtime_extra,
  atime_extra, crtime, crtime_extra, version_hi, projid) are zero. The
  serializer's `if inode_size > 128` guard matches.
- **Impact:** Round-trips for 128-byte fixtures require all extended
  fields = 0 in the expected struct; we cannot express nsec-precision
  timestamps or projids in this mode.
- **Resolution:** ACCEPTED: matches kernel semantics for legacy inodes.
- **Tests affected:** `golden_ext4_inode_128_regfile_*`.
- **Review date:** 2026-04-24

## DISC-EXT4-003: No in-tree encoder for `Ext4DirEntry`, `Ext4Superblock`, `Ext4GroupDesc`

- **Reference:** The kernel writes these structures as part of mkfs and
  mutations.
- **Our impl:** `ffs-ondisk` ships parsers only; the production write path
  uses offset-targeted `buf[N..M].copy_from_slice(...)` in-place updates
  against a fetched block (see `ffs-core` ext4 writable path).
- **Impact:** This conformance family covers inode layout only. Directory
  entry + superblock + group descriptor layouts are covered by the
  existing `ext4_journal_recovery.rs` integration tests and unit tests
  in `ffs-ondisk/src/ext4.rs` using the `write_dir_entry` test helper.
- **Resolution:** ACCEPTED. Out of scope for this conformance family;
  tracked for a future "ext4 on-disk write path" family once a public
  encoder API lands.
- **Review date:** 2026-04-24
