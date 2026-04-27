# Conformance Coverage Matrix

> Tracks what's tested vs what's not. Score < 0.95 for MUST clauses = NOT conformant.

## ext4 On-Disk Structures

| Structure | Fixture | Test | MUST Clauses | Passing | Score | Notes |
|-----------|:-------:|:----:|:------------:|:-------:|:-----:|-------|
| Ext4Superblock | ✅ | ✅ | 12 | 12 | 100% | sparse + mkfs variants |
| Ext4GroupDesc | ✅ | ✅ | 8 | 8 | 100% | 32-byte + 64-byte variants |
| Ext4Inode | ✅ | ✅ | 10 | 10 | 100% | regular file + directory + inline data |
| Ext4DirEntry | ✅ | ✅ | 6 | 6 | 100% | with tail, deleted, edge cases |
| Ext4DirEntryTail | ✅ | ✅ | 3 | 3 | 100% | checksum verification |
| Ext4Extent | ✅ | ✅ | 5 | 5 | 100% | leaf + unwritten extent |
| Ext4ExtentHeader | ✅ | ✅ | 4 | 4 | 100% | via leaf + index fixtures |
| Ext4ExtentIndex | ✅ | ✅ | 3 | 3 | 100% | via index fixture |
| Ext4Xattr (ibody) | ✅ | ✅ | 4 | 4 | 100% | via inline_data_with_continuation |
| Ext4Xattr (block) | ✅ | ✅ | 4 | 4 | 100% | user + security attrs |
| Ext4DxRoot | ✅ | ✅ | 3 | 3 | 100% | htree DX root with 3 entries |
| Ext4DxEntry | ✅ | ✅ | 2 | 2 | 100% | via dx_root fixture |
| Ext4MmpBlock | ✅ | ✅ | 2 | 2 | 100% | clean state, status decoding |
| Ext4InlineData read boundary | ✅ | ✅ | 2 | 2 | 100% | reads crossing, at, and past EOF return exact bytes/empty output for inode-body and xattr continuation storage |
| Ext4InlineData extreme read boundary | ✅ | ✅ | 2 | 2 | 100% | zero-size reads return empty and oversized/extreme-offset reads clamp safely for inode-body and xattr-continuation storage |
| Ext4InlineData VFS surface | ✅ | ✅ | 3 | 3 | 100% | mounted root `readdir`, `lookup`/`getattr`, path resolution, and readback through looked-up inode for inline and xattr-continuation storage |
| Ext4InlineData RW boundary | ✅ | ✅ | 2 | 2 | 100% | read-compatible; write/fallocate mutation rejects with `EOPNOTSUPP` and preserves data |

**ext4 Total: 75 MUST clauses, 75 passing = 100.0%**

## btrfs On-Disk Structures

| Structure | Fixture | Test | MUST Clauses | Passing | Score | Notes |
|-----------|:-------:|:----:|:------------:|:-------:|:-----:|-------|
| BtrfsSuperblock | ✅ | ✅ | 18 | 18 | 100% | sparse + with_chunks variants plus invalid accounting rejection |
| BtrfsChunkEntry | ✅ | ✅ | 6 | 6 | 100% | via superblock sys_chunk_array |
| BtrfsStripe | ✅ | ✅ | 3 | 3 | 100% | via chunk entries |
| BtrfsHeader | ✅ | ✅ | 5 | 5 | 100% | via leaf fixtures |
| BtrfsItem | ✅ | ✅ | 4 | 4 | 100% | via leaf fixtures |
| BtrfsKey | ✅ | ✅ | 3 | 3 | 100% | via leaf fixtures |
| BtrfsKeyPtr | ✅ | ✅ | 2 | 2 | 100% | internal node pointers |
| BtrfsDevItem | ✅ | ✅ | 6 | 6 | 100% | 1TB device with 512GB used plus invalid accounting rejection |
| BtrfsRootItem | ✅ | ✅ | 5 | 5 | 100% | via roottree_leaf fixture |
| BtrfsInodeItem | ✅ | ✅ | 6 | 6 | 100% | via fstree_leaf fixture |
| BtrfsDirItem | ✅ | ✅ | 4 | 4 | 100% | via fstree_leaf fixture |
| BtrfsExtentData | ✅ | ✅ | 5 | 5 | 100% | via fstree_leaf fixture |

**btrfs Total: 67 MUST clauses, 67 passing = 100.0%**

## Priority Gaps

None. All identified on-disk structures have conformance fixtures.

## Fuzz/Adversarial Parser Coverage

| Surface | Corpus/Test | Passing | Notes |
|---------|-------------|:-------:|-------|
| Ext4 superblocks | ✅ | ✅ | synthetic adversarial seeds cover valid region/image parsing, bad magic, unsupported block-size shifts, invalid cluster-size shifts, metadata checksum stamping/corruption, geometry validation failures, and short region/image rejection |
| Ext4 inline-data ibody xattrs | ✅ | ✅ | synthetic adversarial seeds cover inline-data flags with huge `i_size`, oversized `i_extra_isize`, ibody xattr magic-only, name overflow, value overflow, and a valid ibody xattr smoke path through the deterministic fuzz regression harness |
| Ext4 inode checksums | ✅ | ✅ | synthetic adversarial seeds cover 132-byte and 256-byte inode checksum layouts with low/high checksum halves, checksum-field corruption, covered-byte corruption, wrong inode-number checksum seed rejection, short inode buffers, and below-minimum inode-size rejection |
| Ext4 external xattr blocks | ✅ | ✅ | synthetic adversarial seeds cover bad magic, header-only empty block, name overflow, value overflow, and a valid user xattr smoke path through the deterministic fuzz regression harness |
| Ext4 directory blocks | ✅ | ✅ | synthetic adversarial seeds cover valid multi-entry checksum-tail iteration, checksum stamping/verification, checksum-field corruption, covered-entry-byte corruption, wrong inode/generation checksum seed rejection, malformed tails, too-small checksum blocks, short/unaligned/out-of-bounds `rec_len`, name overflow, and nonzero checksum-tail padding |
| Ext4 HTree dx roots | ✅ | ✅ | synthetic adversarial seeds cover valid root entries, unknown hash-version preservation for hash fallback, zero-count roots, nonzero reserved fields, bad root-info length, excessive indirect levels, nonzero unused flags, entry count greater than limit, and short-root rejection |
| Ext4 extent trees | ✅ | ✅ | synthetic adversarial seeds cover valid leaf and index nodes, bad magic, `eh_entries > eh_max`, truncated entries, overlapping leaf extents, unsorted index entries, and extent-block checksum stamping/corruption |
| Ext4 group descriptors | ✅ | ✅ | synthetic adversarial seeds cover 32-byte and 64-byte descriptor field composition, metadata checksum stamping/verification, checksum corruption rejection, invalid descriptor size, and short descriptor rejection |
| Ext4 MMP blocks | ✅ | ✅ | synthetic adversarial seeds cover clean/fsck/active/unknown sequence statuses, bad magic rejection, checksum corruption rejection, and short-block rejection |
| Btrfs tree blocks | ✅ | ✅ | synthetic adversarial seeds cover valid leaf and internal nodes, excessive tree level, leaf payload overlap with the item table, payload out-of-block bounds, overlapping leaf payload ranges, zero child block pointers, and tree-block checksum stamping/corruption |
| Btrfs sys_chunk_array | ✅ | ✅ | synthetic adversarial seeds cover valid single-device bootstrap mapping, bad chunk key type/objectid, zero chunk length, zero stripe length, zero stripes, multiple RAID profile bits, and truncated stripe data |
| Btrfs chunk-tree items | ✅ | ✅ | deterministic adversarial regression tests cover valid multi-stripe chunk-tree item parsing, fixed header truncation, declared stripe payload truncation, zero chunk length, zero stripe length, zero stripes, and multiple RAID profile bit rejection |
| Btrfs dev items | ✅ | ✅ | synthetic adversarial seeds cover full field-layout parsing, max numeric/classification values, trailing bytes after the fixed 98-byte item, zero-capacity device rejection, impossible `bytes_used > total_bytes` accounting, and truncated payload rejection |
| Btrfs superblocks | ✅ | ✅ | synthetic adversarial seeds cover valid superblock-region parsing, image-offset parsing, bad magic, zero and non-power-of-two sizing fields, oversized sector/node/stripe sizing fields, zero-capacity, zero-device, and `bytes_used > total_bytes` accounting rejection, unsupported checksum types, oversized sys_chunk_array declarations, invalid root/chunk/log tree levels, and short region/image rejection |
| Btrfs item payload parsers | ✅ | ✅ | deterministic adversarial regression tests cover root/root_ref/inode/dir/xattr/extent payload valid boundaries, multi-entry dir/xattr payloads, short headers, length overflows, unsupported extent types, compression values, and encoding fields, zero root bytenr rejection, and malformed ROOT_REF fallback behavior for subvolumes/snapshots |
| Btrfs send streams | ✅ | ✅ | deterministic adversarial regression tests cover command CRC32C validation, missing-END rejection, unknown command fallback, zero-length and unknown attributes, multi-attribute commands, trailing partial command headers, and END payload TLV validation |
| Btrfs delayed refs | ✅ | ✅ | deterministic adversarial regression tests cover zero-limit flush preservation, bounded partial flush accounting, delete-underflow queue preservation, and sequence-ordered drain across extent key order |
| Btrfs transactions | ✅ | ✅ | deterministic adversarial mutation tests cover same-tree root replacement, delayed-ref commit failure nonvisibility, and tree-root address overflow nonvisibility |
| Btrfs extent allocator | ✅ | ✅ | deterministic adversarial mutation tests cover overflowing block-group range rejection without accounting side effects and exact block-group tail-fit allocation |
| Btrfs COW tree mutations | ✅ | ✅ | deterministic COW tests cover positive internal split height growth, parent-rewrite update, and left/right delete-borrow success paths plus allocator-failure atomicity for duplicate/missing-key short-circuits, leaf split child allocation, internal split child allocation, internal-root allocation, root split, insert/update parent rewrite, update leaf, delete left/right borrow, and delete merge/root-shrink paths without publishing deferred frees for still-reachable nodes |

## Next Actions

- [x] Add ext4_mmp_block.json fixture - DONE
- [ ] Consider additional edge cases (malformed structures, boundary conditions)
- [x] Add ext4 superblock adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 inline-data adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 inode checksum adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 xattr block adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 directory block adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 directory checksum adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 HTree dx root adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 extent tree adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 group descriptor adversarial corpus entries for fuzzing - DONE
- [x] Add ext4 MMP block adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs tree block adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs sys_chunk_array adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs chunk-tree item adversarial parser regression coverage - DONE
- [x] Add btrfs dev item adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs superblock adversarial corpus entries for fuzzing - DONE
- [x] Add btrfs send stream adversarial parser regression coverage - DONE
- [x] Add btrfs item payload parser adversarial regression coverage - DONE
- [x] Add btrfs ROOT_REF adversarial parser regression coverage - DONE
- [x] Add btrfs delayed ref adversarial mutation coverage - DONE
- [x] Add btrfs transaction adversarial mutation coverage - DONE
- [x] Harden btrfs extent allocator overflow boundaries - DONE
- [x] Add btrfs COW tree allocator-failure mutation coverage - DONE
- [x] Add btrfs COW delete allocator-failure mutation coverage - DONE
- [x] Add btrfs COW update allocator-failure mutation coverage - DONE
- [x] Add btrfs COW leaf-split allocator-failure mutation coverage - DONE
- [x] Add btrfs COW key-error mutation short-circuit coverage - DONE
- [x] Add btrfs COW delete left-borrow allocator-failure mutation coverage - DONE
- [x] Add btrfs COW internal-split allocator-failure mutation coverage - DONE
- [x] Add btrfs COW internal-root allocator-failure mutation coverage - DONE
- [x] Add btrfs COW internal-split success coverage - DONE
- [x] Add btrfs COW left-borrow delete success coverage - DONE
- [x] Add btrfs COW parent-rewrite update success coverage - DONE
- [ ] Continue targeted adversarial corpus expansion for remaining mutation surfaces

---

*Last updated: 2026-04-18*
