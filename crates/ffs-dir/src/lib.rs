#![forbid(unsafe_code)]
//! Directory operations.
//!
//! Linear directory entry scan, htree (hashed B-tree) lookup with
//! dx_hash computation (half-MD4 and TEA), directory entry creation
//! and deletion, and `..`/`.` management.

use ffs_error::{FfsError, Result};
use ffs_ondisk::Ext4FileType;

/// ext4 directory entry header size (`ext4_dir_entry_2`).
const DIR_ENTRY_HEADER_LEN: usize = 8;
/// Fake file type for metadata checksum tail.
const EXT4_FT_DIR_CSUM: u8 = 0xDE;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn required_rec_len(name_len: usize) -> usize {
    align4(DIR_ENTRY_HEADER_LEN + name_len)
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let bytes = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u16_le(buf: &mut [u8], off: usize, value: u16) -> Result<()> {
    let dst = buf
        .get_mut(off..off + 2)
        .ok_or_else(|| FfsError::Corruption {
            block: 0,
            detail: "u16 write out of bounds".to_owned(),
        })?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32_le(buf: &mut [u8], off: usize, value: u32) -> Result<()> {
    let dst = buf
        .get_mut(off..off + 4)
        .ok_or_else(|| FfsError::Corruption {
            block: 0,
            detail: "u32 write out of bounds".to_owned(),
        })?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn validate_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(FfsError::Format(
            "directory entry name cannot be empty".to_owned(),
        ));
    }
    if name.len() > u8::MAX as usize {
        return Err(FfsError::Format(
            "directory entry name exceeds 255 bytes".to_owned(),
        ));
    }
    Ok(())
}

fn write_entry(
    block: &mut [u8],
    offset: usize,
    ino: u32,
    rec_len: usize,
    file_type: Ext4FileType,
    name: &[u8],
) -> Result<()> {
    let name_len_u8 = u8::try_from(name.len())
        .map_err(|_| FfsError::Format("directory entry name exceeds 255 bytes".to_owned()))?;
    let rec_len_u16 = u16::try_from(rec_len)
        .map_err(|_| FfsError::Format("directory entry rec_len exceeds u16".to_owned()))?;
    let end = offset
        .checked_add(rec_len)
        .ok_or_else(|| FfsError::Format("directory entry offset overflow".to_owned()))?;
    if end > block.len() {
        return Err(FfsError::Corruption {
            block: 0,
            detail: "directory entry exceeds block boundary".to_owned(),
        });
    }
    let min_size = required_rec_len(name.len());
    if rec_len < min_size {
        return Err(FfsError::Format(
            "directory entry rec_len smaller than minimum".to_owned(),
        ));
    }

    write_u32_le(block, offset, ino)?;
    write_u16_le(block, offset + 4, rec_len_u16)?;
    block[offset + 6] = name_len_u8;
    block[offset + 7] = file_type as u8;
    block[offset + DIR_ENTRY_HEADER_LEN..offset + DIR_ENTRY_HEADER_LEN + name.len()]
        .copy_from_slice(name);
    // Zero remaining bytes in slot for deterministic tests and clean replay.
    if rec_len > DIR_ENTRY_HEADER_LEN + name.len() {
        block[offset + DIR_ENTRY_HEADER_LEN + name.len()..end].fill(0);
    }
    Ok(())
}

/// Add a directory entry into a single directory block.
///
/// Uses ext4-style `rec_len` management:
/// - Reuses deleted slots (`inode == 0`) when large enough.
/// - Otherwise splits a live slot when it has enough slack.
/// - Returns the byte offset where the new entry was inserted.
///
/// `reserved_tail` is the number of bytes at the end of the block reserved
/// for metadata checksums (typically 12 for `METADATA_CSUM`).
pub fn add_entry(
    block: &mut [u8],
    ino: u32,
    name: &[u8],
    file_type: Ext4FileType,
    reserved_tail: usize,
) -> Result<usize> {
    if ino == 0 {
        return Err(FfsError::Format(
            "directory entry inode cannot be zero".to_owned(),
        ));
    }
    validate_name(name)?;

    let need = required_rec_len(name.len());
    let limit = block.len().saturating_sub(reserved_tail);
    if need > limit {
        return Err(FfsError::NoSpace);
    }

    let mut off = 0usize;
    while off + DIR_ENTRY_HEADER_LEN <= limit {
        let rec_len =
            usize::from(
                read_u16_le(block, off + 4).ok_or_else(|| FfsError::Corruption {
                    block: 0,
                    detail: "unable to read directory entry rec_len".to_owned(),
                })?,
            );
        if rec_len < DIR_ENTRY_HEADER_LEN || (rec_len % 4) != 0 {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "invalid directory entry rec_len".to_owned(),
            });
        }
        let end = off
            .checked_add(rec_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry offset overflow".to_owned(),
            })?;
        if end > limit {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry exceeds usable block area".to_owned(),
            });
        }

        let cur_ino = read_u32_le(block, off).ok_or_else(|| FfsError::Corruption {
            block: 0,
            detail: "unable to read directory entry inode".to_owned(),
        })?;
        let cur_name_len = usize::from(block[off + 6]);

        // Validate name_len against rec_len to prevent out-of-bounds access.
        if DIR_ENTRY_HEADER_LEN + cur_name_len > rec_len {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "directory entry name_len {cur_name_len} exceeds rec_len {rec_len} at offset {off}"
                ),
            });
        }

        if cur_ino == 0 {
            if rec_len >= need {
                write_entry(block, off, ino, rec_len, file_type, name)?;
                return Ok(off);
            }
            off = end;
            continue;
        }

        let actual = required_rec_len(cur_name_len);
        if actual > rec_len {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry name length exceeds rec_len".to_owned(),
            });
        }

        let slack = rec_len - actual;
        if slack >= need {
            let actual_u16 = u16::try_from(actual)
                .map_err(|_| FfsError::Format("actual rec_len exceeds u16".to_owned()))?;
            write_u16_le(block, off + 4, actual_u16)?;
            let new_off = off + actual;
            write_entry(block, new_off, ino, slack, file_type, name)?;
            return Ok(new_off);
        }

        off = end;
    }

    Err(FfsError::NoSpace)
}

/// Remove a directory entry by name from a single directory block.
///
/// On success:
/// - If there is a previous live entry, its `rec_len` is expanded to absorb
///   the removed slot (coalescing free space).
/// - Otherwise the target entry is marked deleted (`inode = 0`).
pub fn remove_entry(block: &mut [u8], name: &[u8], reserved_tail: usize) -> Result<bool> {
    validate_name(name)?;

    let mut off = 0usize;
    let mut prev_off_opt: Option<usize> = None;
    let limit = block.len().saturating_sub(reserved_tail);

    while off + DIR_ENTRY_HEADER_LEN <= limit {
        let rec_len =
            usize::from(
                read_u16_le(block, off + 4).ok_or_else(|| FfsError::Corruption {
                    block: 0,
                    detail: "unable to read directory entry rec_len".to_owned(),
                })?,
            );
        if rec_len < DIR_ENTRY_HEADER_LEN || (rec_len % 4) != 0 {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "invalid directory entry rec_len".to_owned(),
            });
        }
        let end = off
            .checked_add(rec_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry offset overflow".to_owned(),
            })?;
        if end > limit {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "directory entry exceeds usable block area".to_owned(),
            });
        }

        let cur_ino = read_u32_le(block, off).ok_or_else(|| FfsError::Corruption {
            block: 0,
            detail: "unable to read directory entry inode".to_owned(),
        })?;
        let cur_name_len = usize::from(block[off + 6]);
        let name_end = off
            .checked_add(DIR_ENTRY_HEADER_LEN + cur_name_len)
            .ok_or_else(|| FfsError::Corruption {
                block: 0,
                detail: "directory entry name offset overflow".to_owned(),
            })?;
        if name_end > end {
            return Err(FfsError::Corruption {
                block: 0,
                detail: format!(
                    "directory entry name_len {cur_name_len} exceeds rec_len {rec_len} at offset {off}"
                ),
            });
        }

        if cur_ino != 0 && &block[off + DIR_ENTRY_HEADER_LEN..name_end] == name {
            if let Some(prev_off) = prev_off_opt {
                let merged = (off + rec_len)
                    .checked_sub(prev_off)
                    .ok_or_else(|| FfsError::Format("merged rec_len underflow".to_owned()))?;
                let merged_u16 = u16::try_from(merged)
                    .map_err(|_| FfsError::Format("merged rec_len exceeds u16".to_owned()))?;
                write_u16_le(block, prev_off + 4, merged_u16)?;
            }

            write_u32_le(block, off, 0)?;
            // Clear metadata for cleanliness.
            block[off + 6] = 0;
            block[off + 7] = 0;
            return Ok(true);
        }

        if cur_ino != 0 {
            prev_off_opt = Some(off);
        }
        off = end;
    }

    Ok(false)
}

/// Initialize an empty directory block with `.` and `..` entries.
pub fn init_dir_block(
    block: &mut [u8],
    self_ino: u32,
    parent_ino: u32,
    reserved_tail: usize,
) -> Result<()> {
    if block.len() < required_rec_len(1) + required_rec_len(2) + reserved_tail {
        return Err(FfsError::Format(
            "directory block too small for . and .. entries".to_owned(),
        ));
    }
    block.fill(0);

    let dot_len = required_rec_len(1);
    let dotdot_len = block.len() - dot_len - reserved_tail;

    write_entry(block, 0, self_ino, dot_len, Ext4FileType::Dir, b".")?;
    write_entry(
        block,
        dot_len,
        parent_ino,
        dotdot_len,
        Ext4FileType::Dir,
        b"..",
    )?;

    if reserved_tail >= 12 {
        let off = block.len() - reserved_tail;
        // struct ext4_dir_entry_tail: { 0(4), rec_len=12(2), 0(1), 0xDE(1), checksum(4) }
        write_u32_le(block, off, 0)?;
        write_u16_le(block, off + 4, 12)?;
        block[off + 6] = 0;
        block[off + 7] = EXT4_FT_DIR_CSUM;
        write_u32_le(block, off + 8, 0)?; // checksum initially 0
    }

    Ok(())
}

/// Hash/index entry for ext4 htree directory indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtreeEntry {
    pub hash: u32,
    pub block: u32,
}

/// Compute ext4 DX hash major value for a directory name.
#[must_use]
pub fn compute_dx_hash(hash_version: u8, name: &[u8], seed: &[u32; 4]) -> u32 {
    ffs_ondisk::dx_hash(hash_version, name, seed).0
}

/// Insert an htree mapping entry while preserving hash ordering.
///
/// Returns the insertion index.
pub fn htree_insert(entries: &mut Vec<HtreeEntry>, hash: u32, block: u32) -> usize {
    let idx = entries.partition_point(|e| e.hash <= hash);
    entries.insert(idx, HtreeEntry { hash, block });
    idx
}

/// Remove one matching htree mapping entry (`hash`, `block`).
///
/// Returns `true` when an entry was removed.
pub fn htree_remove(entries: &mut Vec<HtreeEntry>, hash: u32, block: u32) -> bool {
    let Some(pos) = entries
        .iter()
        .position(|e| e.hash == hash && e.block == block)
    else {
        return false;
    };
    entries.remove(pos);
    true
}

/// Find the leaf block using the "rightmost hash <= target" rule.
#[must_use]
pub fn htree_find_leaf(entries: &[HtreeEntry], target_hash: u32) -> Option<u32> {
    if entries.is_empty() {
        return None;
    }
    let idx = entries.partition_point(|e| e.hash <= target_hash);
    let chosen = if idx == 0 { 0 } else { idx - 1 };
    entries.get(chosen).map(|e| e.block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::{Ext4FileType, parse_dir_block};

    #[test]
    fn init_dir_block_contains_dot_and_dotdot() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 11, 2, 0).unwrap();
        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
        assert!(tail.is_none());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b".".to_vec());
        assert_eq!(entries[0].inode, 11);
        assert_eq!(entries[1].name, b"..".to_vec());
        assert_eq!(entries[1].inode, 2);
    }

    #[test]
    fn init_dir_block_with_tail() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 11, 2, 12).unwrap();
        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries[1].rec_len, 1024 - 12 - 12);
        assert!(tail.is_some());
    }

    #[test]
    fn add_entry_splits_live_slot_slack() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 2, 1024, Ext4FileType::Dir, b".").unwrap();
        let off = add_entry(&mut block, 33, b"hello", Ext4FileType::RegFile, 0).unwrap();
        assert_eq!(off, 12);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b".".to_vec());
        assert_eq!(entries[1].name, b"hello".to_vec());
        assert_eq!(entries[1].inode, 33);
    }

    #[test]
    fn add_entry_reuses_deleted_slot() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 2, 12, Ext4FileType::Dir, b".").unwrap();
        write_entry(&mut block, 12, 0, 1012, Ext4FileType::Unknown, b"x").unwrap();
        let off = add_entry(&mut block, 44, b"new", Ext4FileType::RegFile, 0).unwrap();
        assert_eq!(off, 12);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].inode, 44);
        assert_eq!(entries[1].name, b"new".to_vec());
    }

    #[test]
    fn add_entry_no_space_returns_enospc() {
        let mut block = vec![0u8; 24];
        write_entry(&mut block, 0, 1, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 2, 12, Ext4FileType::RegFile, b"b").unwrap();
        let err = add_entry(&mut block, 3, b"c", Ext4FileType::RegFile, 0).unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOSPC);
    }

    #[test]
    fn remove_entry_coalesces_prev_rec_len() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 10, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 11, 12, Ext4FileType::RegFile, b"b").unwrap();
        write_entry(&mut block, 24, 12, 1000, Ext4FileType::RegFile, b"c").unwrap();

        let removed = remove_entry(&mut block, b"b", 0).unwrap();
        assert!(removed);
        let merged = read_u16_le(&block, 4).unwrap();
        assert_eq!(merged, 24);
    }

    #[test]
    fn remove_entry_coalesces_into_previous_live_entry_after_deleted_slot() {
        // Layout: [a(live)][x(deleted)][b(live)][c(live)]
        // Removing "b" should coalesce "a" through the deleted "x" and removed "b",
        // giving "a" a rec_len that spans from offset 0 to offset 36 (where "c" starts).
        let mut block = vec![0u8; 64];
        write_entry(&mut block, 0, 10, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 0, 12, Ext4FileType::Unknown, b"x").unwrap();
        write_entry(&mut block, 24, 11, 12, Ext4FileType::RegFile, b"b").unwrap();
        write_entry(&mut block, 36, 12, 28, Ext4FileType::RegFile, b"c").unwrap();

        let removed = remove_entry(&mut block, b"b", 0).unwrap();
        assert!(removed);
        // "a" at offset 0 absorbs deleted "x" (12 bytes) + removed "b" (12 bytes) = 36 total.
        assert_eq!(read_u16_le(&block, 4).unwrap(), 36);
        // "b" at offset 24 has inode zeroed.
        assert_eq!(read_u32_le(&block, 24).unwrap(), 0);
        // "c" at offset 36 is untouched.
        assert_eq!(read_u32_le(&block, 36).unwrap(), 12);
        assert_eq!(read_u16_le(&block, 40).unwrap(), 28);
    }

    #[test]
    fn remove_first_entry_marks_deleted() {
        let mut block = vec![0u8; 128];
        write_entry(&mut block, 0, 10, 128, Ext4FileType::RegFile, b"a").unwrap();
        let removed = remove_entry(&mut block, b"a", 0).unwrap();
        assert!(removed);
        assert_eq!(read_u32_le(&block, 0).unwrap(), 0);
    }

    #[test]
    fn htree_insert_preserves_sorted_hash_order() {
        let mut entries = Vec::new();
        htree_insert(&mut entries, 0x2000, 2);
        htree_insert(&mut entries, 0x1000, 1);
        htree_insert(&mut entries, 0x5000, 5);
        htree_insert(&mut entries, 0x3000, 3);
        let hashes: Vec<u32> = entries.iter().map(|e| e.hash).collect();
        assert_eq!(hashes, vec![0x1000, 0x2000, 0x3000, 0x5000]);
    }

    #[test]
    fn htree_find_leaf_uses_rightmost_lte() {
        let entries = vec![
            HtreeEntry {
                hash: 0x0000,
                block: 1,
            },
            HtreeEntry {
                hash: 0x1000,
                block: 2,
            },
            HtreeEntry {
                hash: 0x8000,
                block: 3,
            },
        ];
        assert_eq!(htree_find_leaf(&entries, 0x0500), Some(1));
        assert_eq!(htree_find_leaf(&entries, 0x1000), Some(2));
        assert_eq!(htree_find_leaf(&entries, 0xFFFF), Some(3));
        assert_eq!(htree_find_leaf(&[], 0xFFFF), None);
    }

    #[test]
    fn htree_remove_specific_entry() {
        let mut entries = vec![
            HtreeEntry {
                hash: 0x1000,
                block: 2,
            },
            HtreeEntry {
                hash: 0x1000,
                block: 8,
            },
        ];
        assert!(htree_remove(&mut entries, 0x1000, 8));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].block, 2);
        assert!(!htree_remove(&mut entries, 0x1000, 8));
    }

    #[test]
    fn compute_dx_hash_is_deterministic() {
        let seed = [1, 2, 3, 4];
        let h1 = compute_dx_hash(1, b"hello", &seed);
        let h2 = compute_dx_hash(1, b"hello", &seed);
        let h3 = compute_dx_hash(1, b"world", &seed);
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn add_entry_rejects_zero_inode() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 1, 1024, Ext4FileType::Dir, b".").unwrap();
        let err = add_entry(&mut block, 0, b"bad", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn add_entry_rejects_empty_name() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 1, 1024, Ext4FileType::Dir, b".").unwrap();
        let err = add_entry(&mut block, 10, b"", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn remove_nonexistent_entry_returns_false() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 10, 1024, Ext4FileType::RegFile, b"a").unwrap();
        let removed = remove_entry(&mut block, b"nonexistent", 0).unwrap();
        assert!(!removed);
    }

    #[test]
    fn init_dir_block_too_small_fails() {
        let mut block = vec![0u8; 16]; // Too small for . and ..
        let err = init_dir_block(&mut block, 1, 2, 0).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn add_entry_after_remove_reclaims_space() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        // Add, then remove, then add again to same slot.
        add_entry(&mut block, 100, b"temp", Ext4FileType::RegFile, 0).unwrap();
        remove_entry(&mut block, b"temp", 0).unwrap();
        add_entry(&mut block, 200, b"repl", Ext4FileType::RegFile, 0).unwrap();

        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert!(entries.iter().any(|e| e.inode == 200 && e.name == b"repl"));
        assert!(!entries.iter().any(|e| e.name == b"temp"));
    }

    #[test]
    fn add_entry_detects_corrupt_rec_len_zero() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap(); // inode
        write_u16_le(&mut block, 4, 0).unwrap(); // rec_len = 0 (invalid)
        block[6] = 1; // name_len
        block[7] = 1; // file_type
        block[8] = b'a'; // name

        let err = add_entry(&mut block, 20, b"new", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn add_entry_detects_name_len_exceeding_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 12).unwrap(); // rec_len = 12
        block[6] = 100; // name_len = 100 (exceeds rec_len - 8 = 4)
        block[7] = 1;
        block[8] = b'a';
        write_u32_le(&mut block, 12, 0).unwrap();
        write_u16_le(&mut block, 16, 116).unwrap();

        let err = add_entry(&mut block, 20, b"new", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn remove_entry_detects_name_exceeding_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 12).unwrap(); // rec_len = 12
        block[6] = 50; // name_len = 50 (exceeds rec_len - 8 = 4)
        block[7] = 1;
        block[8] = b'x';
        write_u32_le(&mut block, 12, 0).unwrap();
        write_u16_le(&mut block, 16, 116).unwrap();

        let err = remove_entry(&mut block, b"x", 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn test_remove_entry_overlap_bug() {
        let mut block = vec![0u8; 256];
        write_entry(&mut block, 0, 10, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 0, 12, Ext4FileType::Unknown, b"x").unwrap();
        write_entry(&mut block, 24, 11, 100, Ext4FileType::RegFile, b"b").unwrap();
        write_entry(&mut block, 124, 12, 132, Ext4FileType::RegFile, b"c").unwrap();

        let removed = remove_entry(&mut block, b"b", 0).unwrap();
        assert!(removed);

        let _rec_len_0 = read_u16_le(&block, 4).unwrap();

        let (entries, _) = ffs_ondisk::parse_dir_block(&block, 256).unwrap();
        assert_eq!(entries.len(), 2, "Expected 2 entries left (a and c)");
        assert_eq!(entries[0].name, b"a".to_vec());
        assert_eq!(entries[1].name, b"c".to_vec());
    }
}
