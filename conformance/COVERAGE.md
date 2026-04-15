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
| Ext4MmpBlock | ❌ | ❌ | 2 | 0 | 0% | **MISSING** - multi-mount protection |

**ext4 Total: 66 MUST clauses, 64 passing = 97.0%**

## btrfs On-Disk Structures

| Structure | Fixture | Test | MUST Clauses | Passing | Score | Notes |
|-----------|:-------:|:----:|:------------:|:-------:|:-----:|-------|
| BtrfsSuperblock | ✅ | ✅ | 15 | 15 | 100% | sparse + with_chunks variants |
| BtrfsChunkEntry | ✅ | ✅ | 6 | 6 | 100% | via superblock sys_chunk_array |
| BtrfsStripe | ✅ | ✅ | 3 | 3 | 100% | via chunk entries |
| BtrfsHeader | ✅ | ✅ | 5 | 5 | 100% | via leaf fixtures |
| BtrfsItem | ✅ | ✅ | 4 | 4 | 100% | via leaf fixtures |
| BtrfsKey | ✅ | ✅ | 3 | 3 | 100% | via leaf fixtures |
| BtrfsKeyPtr | ✅ | ✅ | 2 | 2 | 100% | internal node pointers |
| BtrfsDevItem | ✅ | ✅ | 4 | 4 | 100% | 1TB device with 512GB used |
| BtrfsRootItem | ✅ | ✅ | 5 | 5 | 100% | via roottree_leaf fixture |
| BtrfsInodeItem | ✅ | ✅ | 6 | 6 | 100% | via fstree_leaf fixture |
| BtrfsDirItem | ✅ | ✅ | 4 | 4 | 100% | via fstree_leaf fixture |
| BtrfsExtentData | ✅ | ✅ | 5 | 5 | 100% | via fstree_leaf fixture |

**btrfs Total: 62 MUST clauses, 62 passing = 100.0%**

## Priority Gaps

1. **ext4 MMP Block** - Multi-mount protection (2 MUST clauses)

## Next Actions

- [ ] Add ext4_mmp_block.json fixture

---

*Last updated: 2026-04-15*
