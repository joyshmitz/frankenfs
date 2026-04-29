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

fn validate_reserved_tail(block_len: usize, reserved_tail: usize) -> Result<usize> {
    if reserved_tail != 0 {
        if reserved_tail < 12 {
            return Err(FfsError::Format(
                "directory reserved tail must be 0 or at least 12 bytes".to_owned(),
            ));
        }
        if reserved_tail % 4 != 0 {
            return Err(FfsError::Format(
                "directory reserved tail must be 4-byte aligned".to_owned(),
            ));
        }
    }
    block_len
        .checked_sub(reserved_tail)
        .ok_or_else(|| FfsError::Format("directory reserved tail exceeds block length".to_owned()))
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
    let limit = validate_reserved_tail(block.len(), reserved_tail)?;
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
    let limit = validate_reserved_tail(block.len(), reserved_tail)?;

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

fn update_live_entry_header(
    block: &mut [u8],
    name: &[u8],
    new_ino: u32,
    new_file_type: Option<Ext4FileType>,
    reserved_tail: usize,
) -> Result<bool> {
    validate_name(name)?;
    if new_ino == 0 {
        return Err(FfsError::Format(
            "directory entry inode cannot be zero".to_owned(),
        ));
    }

    let mut off = 0usize;
    let limit = validate_reserved_tail(block.len(), reserved_tail)?;
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
            write_u32_le(block, off, new_ino)?;
            if let Some(file_type) = new_file_type {
                block[off + 7] = file_type as u8;
            }
            return Ok(true);
        }
        off = end;
    }
    Ok(false)
}

/// Swap the inode number on the live entry whose name matches `name`.
///
/// This intentionally leaves the ext4 `file_type` tag unchanged. Use
/// [`retarget_entry`] when the target inode's kind may differ.
///
/// Returns `Ok(true)` on swap, `Ok(false)` if `name` is not present
/// in this block. Tombstones (entries with `inode == 0`) are skipped
/// so a deleted entry that happens to share the name is never matched.
pub fn swap_inode_in_entry(
    block: &mut [u8],
    name: &[u8],
    new_ino: u32,
    reserved_tail: usize,
) -> Result<bool> {
    update_live_entry_header(block, name, new_ino, None, reserved_tail)
}

/// Retarget a live directory entry to a different inode and file type.
///
/// `renameat2(RENAME_EXCHANGE)` needs this for mixed-type exchanges:
/// swapping only inode numbers would leave stale d_type/file_type tags
/// attached to the old names.
pub fn retarget_entry(
    block: &mut [u8],
    name: &[u8],
    new_ino: u32,
    new_file_type: Ext4FileType,
    reserved_tail: usize,
) -> Result<bool> {
    update_live_entry_header(block, name, new_ino, Some(new_file_type), reserved_tail)
}

/// Initialize an empty directory block with `.` and `..` entries.
pub fn init_dir_block(
    block: &mut [u8],
    self_ino: u32,
    parent_ino: u32,
    reserved_tail: usize,
) -> Result<()> {
    if self_ino == 0 {
        return Err(FfsError::Format(
            "directory self inode cannot be zero".to_owned(),
        ));
    }
    if parent_ino == 0 {
        return Err(FfsError::Format(
            "directory parent inode cannot be zero".to_owned(),
        ));
    }

    let usable_len = validate_reserved_tail(block.len(), reserved_tail)?;
    let min_entries = required_rec_len(1)
        .checked_add(required_rec_len(2))
        .ok_or_else(|| FfsError::Format("directory minimum entry size overflow".to_owned()))?;
    if usable_len < min_entries {
        return Err(FfsError::Format(
            "directory block too small for . and .. entries".to_owned(),
        ));
    }
    block.fill(0);

    let dot_len = required_rec_len(1);
    let dotdot_len = usable_len - dot_len;

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

/// Find the rightmost entry index whose hash is <= target_hash.
#[must_use]
pub fn htree_find_leaf_idx(entries: &[HtreeEntry], target_hash: u32) -> usize {
    if entries.is_empty() {
        return 0;
    }
    let idx = entries.partition_point(|e| e.hash <= target_hash);
    if idx == 0 { 0 } else { idx - 1 }
}

/// Find the leaf block using the "rightmost hash <= target" rule.
#[must_use]
pub fn htree_find_leaf(entries: &[HtreeEntry], target_hash: u32) -> Option<u32> {
    if entries.is_empty() {
        return None;
    }
    let idx = htree_find_leaf_idx(entries, target_hash);
    entries.get(idx).map(|e| e.block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::{Ext4FileType, parse_dir_block};
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn valid_dir_name_strategy(max_len: usize) -> BoxedStrategy<Vec<u8>> {
        proptest::collection::vec(b'a'..=b'z', 1..=max_len).boxed()
    }

    fn dir_block_geometry_strategy() -> BoxedStrategy<(usize, usize)> {
        (6_usize..=1024)
            .prop_map(|units| units * 4)
            .prop_flat_map(|block_len| {
                let max_tail_units = (block_len - 24) / 4;
                if max_tail_units >= 3 {
                    prop_oneof![
                        Just((block_len, 0_usize)),
                        (3_usize..=max_tail_units)
                            .prop_map(move |tail_units| { (block_len, tail_units * 4) }),
                    ]
                    .boxed()
                } else {
                    Just((block_len, 0_usize)).boxed()
                }
            })
            .boxed()
    }

    fn unique_htree_entries_strategy() -> BoxedStrategy<Vec<(u32, u32)>> {
        proptest::collection::btree_map(any::<u32>(), 1_u32..=u32::MAX, 1..32)
            .prop_map(|entries| entries.into_iter().collect())
            .boxed()
    }

    const REPRESENTATIVE_DIR_BLOCK_GOLDEN: &str = concat!(
        "slot_headers\n",
        "  [0] inode=17 rec_len=12 name_len=1 file_type=Dir\n",
        "  [12] inode=2 rec_len=28 name_len=2 file_type=Dir\n",
        "  [24] inode=0 rec_len=16 name_len=0 file_type_raw=0\n",
        "  [40] inode=99 rec_len=12 name_len=3 file_type=Dir\n",
        "tail\n",
        "  checksum=0 raw=[00, 00, 00, 00, 0c, 00, 00, de, 00, 00, 00, 00]\n",
        "parsed\n",
        "  inode=17 rec_len=12 file_type=Dir name=\".\"\n",
        "  inode=2 rec_len=28 file_type=Dir name=\"..\"\n",
        "  inode=99 rec_len=12 file_type=Dir name=\"sub\"\n",
        "block=[11, 00, 00, 00, 0c, 00, 01, 02, 2e, 00, 00, 00, 02, 00, 00, 00, 1c, 00, 02, 02, 2e, 2e, 00, 00, 00, 00, 00, 00, 10, 00, 00, 00, 68, 69, 2e, 74, 78, 74, 00, 00, 63, 00, 00, 00, 0c, 00, 03, 02, 73, 75, 62, 00, 00, 00, 00, 00, 0c, 00, 00, de, 00, 00, 00, 00]"
    );

    fn representative_dir_block_golden_contract_actual() -> String {
        let mut block = vec![0_u8; 64];
        init_dir_block(&mut block, 17, 2, 12).expect("init representative dir block");
        add_entry(&mut block, 41, b"hi.txt", Ext4FileType::RegFile, 12)
            .expect("insert representative file");
        add_entry(&mut block, 99, b"sub", Ext4FileType::Dir, 12)
            .expect("insert representative subdir");
        assert!(
            remove_entry(&mut block, b"hi.txt", 12).expect("remove representative file"),
            "representative file entry should be removed"
        );

        let (entries, tail) = parse_dir_block(&block, 64).expect("parse representative dir block");
        let tail = tail.expect("representative dir block should preserve checksum tail");
        let parsed_lines = entries
            .iter()
            .map(|entry| {
                format!(
                    "  inode={} rec_len={} file_type={:?} name={:?}",
                    entry.inode,
                    entry.rec_len,
                    entry.file_type,
                    entry.name_str()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            concat!(
                "slot_headers\n",
                "  [0] inode={} rec_len={} name_len={} file_type={:?}\n",
                "  [12] inode={} rec_len={} name_len={} file_type={:?}\n",
                "  [24] inode={} rec_len={} name_len={} file_type_raw={}\n",
                "  [40] inode={} rec_len={} name_len={} file_type={:?}\n",
                "tail\n",
                "  checksum={} raw={:02x?}\n",
                "parsed\n",
                "{}\n",
                "block={:02x?}"
            ),
            read_u32_le(&block, 0).expect("read dot inode"),
            read_u16_le(&block, 4).expect("read dot rec_len"),
            block[6],
            Ext4FileType::from_raw(block[7]),
            read_u32_le(&block, 12).expect("read dotdot inode"),
            read_u16_le(&block, 16).expect("read dotdot rec_len"),
            block[18],
            Ext4FileType::from_raw(block[19]),
            read_u32_le(&block, 24).expect("read deleted inode"),
            read_u16_le(&block, 28).expect("read deleted rec_len"),
            block[30],
            block[31],
            read_u32_le(&block, 40).expect("read sub inode"),
            read_u16_le(&block, 44).expect("read sub rec_len"),
            block[46],
            Ext4FileType::from_raw(block[47]),
            tail.checksum,
            &block[52..64],
            parsed_lines,
            block,
        )
    }

    fn live_name_set(block: &[u8]) -> BTreeSet<Vec<u8>> {
        parse_dir_block(block, u32::try_from(block.len()).unwrap())
            .unwrap()
            .0
            .into_iter()
            .filter(|entry| entry.inode != 0)
            .map(|entry| entry.name)
            .collect()
    }

    fn assert_add_entry_alignment_boundary(name_len: usize) {
        let mut block = vec![0u8; 12 + required_rec_len(name_len)];
        let block_len = block.len();
        write_entry(&mut block, 0, 1, block_len, Ext4FileType::Dir, b".").unwrap();

        let name = vec![b'x'; name_len];
        let off = add_entry(&mut block, 99, &name, Ext4FileType::RegFile, 0).unwrap();

        assert_eq!(off, 12);
        assert_eq!(usize::from(read_u16_le(&block, 4).unwrap()), 12);
        assert_eq!(
            usize::from(read_u16_le(&block, off + 4).unwrap()),
            required_rec_len(name_len)
        );

        let (entries, _) = parse_dir_block(&block, u32::try_from(block.len()).unwrap()).unwrap();
        let entry = entries
            .iter()
            .find(|entry| entry.inode == 99)
            .expect("new entry must be parseable");
        assert_eq!(entry.name.len(), name_len);
    }

    macro_rules! add_entry_alignment_boundary_test {
        ($name:ident, $len:expr) => {
            #[test]
            fn $name() {
                assert_add_entry_alignment_boundary($len);
            }
        };
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn proptest_add_remove_roundtrip_preserves_parseability(
            ino in 3_u32..=u32::MAX,
            reserved_tail in prop_oneof![Just(0_usize), Just(12_usize), Just(24_usize)],
            name in valid_dir_name_strategy(255),
        ) {
            let mut block = vec![0u8; 4096];
            init_dir_block(&mut block, 2, 2, reserved_tail).unwrap();

            let off = add_entry(&mut block, ino, &name, Ext4FileType::RegFile, reserved_tail)
                .unwrap();
            prop_assert!(off + required_rec_len(name.len()) <= block.len() - reserved_tail);

            let (entries, tail) = parse_dir_block(&block, 4096).unwrap();
            prop_assert_eq!(tail.is_some(), reserved_tail >= 12);
            prop_assert!(entries.iter().any(|entry| entry.inode == ino && entry.name == name));

            let removed = remove_entry(&mut block, &name, reserved_tail).unwrap();
            prop_assert!(removed);

            let (entries_after, tail_after) = parse_dir_block(&block, 4096).unwrap();
            prop_assert_eq!(tail_after.is_some(), reserved_tail >= 12);
            prop_assert_eq!(
                entries_after.iter().filter(|entry| entry.inode != 0).count(),
                2
            );
            prop_assert!(!entries_after
                .iter()
                .any(|entry| entry.inode != 0 && entry.name == name));
        }

        #[test]
        fn proptest_add_sequence_remains_parseable_until_enospc(
            reserved_tail in prop_oneof![Just(0_usize), Just(12_usize), Just(24_usize)],
            operations in proptest::collection::vec(
                (3_u32..=u32::MAX, valid_dir_name_strategy(32)),
                0..40
            ),
        ) {
            let mut block = vec![0u8; 1024];
            init_dir_block(&mut block, 2, 2, reserved_tail).unwrap();

            let mut successes = 0usize;
            for (ino, name) in operations {
                let before = block.clone();
                match add_entry(&mut block, ino, &name, Ext4FileType::RegFile, reserved_tail) {
                    Ok(off) => {
                        successes += 1;
                        prop_assert!(off < block.len() - reserved_tail);
                        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
                        prop_assert_eq!(tail.is_some(), reserved_tail >= 12);
                        prop_assert_eq!(
                            entries.iter().filter(|entry| entry.inode != 0).count(),
                            2 + successes
                        );
                    }
                    Err(FfsError::NoSpace) => {
                        prop_assert_eq!(block.as_slice(), before.as_slice());
                        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
                        prop_assert_eq!(tail.is_some(), reserved_tail >= 12);
                        prop_assert_eq!(
                            entries.iter().filter(|entry| entry.inode != 0).count(),
                            2 + successes
                        );
                    }
                    Err(err) => prop_assert!(false, "unexpected add_entry error: {err:?}"),
                }
            }
        }

        #[test]
        fn proptest_init_dir_block_roundtrip_preserves_inode_numbers(
            geometry in dir_block_geometry_strategy(),
            self_ino in 1_u32..=u32::MAX,
            parent_ino in 1_u32..=u32::MAX,
        ) {
            let (block_len, reserved_tail) = geometry;
            let mut block = vec![0u8; block_len];

            init_dir_block(&mut block, self_ino, parent_ino, reserved_tail).unwrap();

            let (entries, tail) =
                parse_dir_block(&block, u32::try_from(block_len).unwrap()).unwrap();
            prop_assert_eq!(entries.len(), 2);
            prop_assert_eq!(&entries[0].name, b".");
            prop_assert_eq!(entries[0].inode, self_ino);
            prop_assert_eq!(&entries[1].name, b"..");
            prop_assert_eq!(entries[1].inode, parent_ino);
            prop_assert_eq!(
                usize::try_from(entries[1].rec_len).unwrap(),
                block_len - required_rec_len(1) - reserved_tail
            );
            prop_assert_eq!(tail.is_some(), reserved_tail >= 12);
        }

        #[test]
        fn proptest_htree_insert_and_lookup_matches_manual_model(
            operations in proptest::collection::vec((any::<u32>(), any::<u32>()), 0..128),
            target_hash in any::<u32>(),
        ) {
            let mut entries = Vec::new();
            for (hash, block) in operations {
                htree_insert(&mut entries, hash, block);
                prop_assert!(entries.windows(2).all(|pair| pair[0].hash <= pair[1].hash));
            }

            let expected = if entries.is_empty() {
                None
            } else {
                let mut chosen = entries[0].block;
                for entry in &entries {
                    if entry.hash <= target_hash {
                        chosen = entry.block;
                    } else {
                        break;
                    }
                }
                Some(chosen)
            };

            prop_assert_eq!(htree_find_leaf(&entries, target_hash), expected);
        }

        #[test]
        fn proptest_htree_insert_order_invariance_for_unique_hashes(
            canonical_entries in unique_htree_entries_strategy(),
            queries in proptest::collection::vec(any::<u32>(), 0..32),
        ) {
            let mut forward = Vec::new();
            for (hash, block) in &canonical_entries {
                htree_insert(&mut forward, *hash, *block);
            }

            let mut reversed = Vec::new();
            for (hash, block) in canonical_entries.iter().rev() {
                htree_insert(&mut reversed, *hash, *block);
            }

            let expected: Vec<HtreeEntry> = canonical_entries
                .iter()
                .map(|(hash, block)| HtreeEntry {
                    hash: *hash,
                    block: *block,
                })
                .collect();

            prop_assert_eq!(&forward, &expected);
            prop_assert_eq!(&reversed, &expected);

            for query in queries {
                prop_assert_eq!(htree_find_leaf_idx(&forward, query), htree_find_leaf_idx(&reversed, query));
                prop_assert_eq!(htree_find_leaf(&forward, query), htree_find_leaf(&reversed, query));
            }
        }
    }

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
    fn representative_dir_block_mutation_exact_golden_contract() {
        assert_eq!(
            representative_dir_block_golden_contract_actual(),
            REPRESENTATIVE_DIR_BLOCK_GOLDEN
        );
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
    fn retarget_entry_updates_inode_and_file_type_without_moving_slot() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 33, 1024, Ext4FileType::RegFile, b"node").unwrap();

        assert!(
            retarget_entry(&mut block, b"node", 44, Ext4FileType::Dir, 0).expect("retarget entry")
        );

        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].inode, 44);
        assert_eq!(entries[0].rec_len, 1024);
        assert_eq!(entries[0].name, b"node".to_vec());
        assert_eq!(entries[0].file_type, Ext4FileType::Dir);
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
    fn remove_entry_last_entry_extends_previous_to_block_end() {
        let mut block = vec![0u8; 64];
        write_entry(&mut block, 0, 10, 12, Ext4FileType::RegFile, b"a").unwrap();
        write_entry(&mut block, 12, 11, 52, Ext4FileType::RegFile, b"b").unwrap();

        assert!(remove_entry(&mut block, b"b", 0).unwrap());
        assert_eq!(read_u16_le(&block, 4).unwrap(), 64);
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
    fn init_dir_block_rejects_zero_dot_inodes_without_mutation() {
        for (self_ino, parent_ino) in [(0, 2), (2, 0)] {
            let mut block = vec![0xA5; 1024];
            let before = block.clone();

            let err = init_dir_block(&mut block, self_ino, parent_ino, 0).unwrap_err();

            assert!(matches!(err, FfsError::Format(_)));
            assert_eq!(block, before);
        }
    }

    #[test]
    fn init_dir_block_rejects_invalid_reserved_tail_geometry_without_mutation() {
        for reserved_tail in [1_usize, 8, 13, 128] {
            let mut block = vec![0xA5; 64];
            let before = block.clone();

            let err = init_dir_block(&mut block, 1, 2, reserved_tail).unwrap_err();

            assert!(matches!(err, FfsError::Format(_)));
            assert_eq!(block, before);
        }
    }

    #[test]
    fn mutation_paths_reject_invalid_reserved_tail_geometry_without_mutation() {
        let mut block = vec![0u8; 128];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        let before_add = block.clone();
        let err = add_entry(&mut block, 10, b"new", Ext4FileType::RegFile, 8).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(block, before_add);

        let before_remove = block.clone();
        let err = remove_entry(&mut block, b".", 13).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(block, before_remove);

        let before_retarget = block.clone();
        let err = retarget_entry(&mut block, b".", 3, Ext4FileType::Dir, 256).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
        assert_eq!(block, before_retarget);
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
    fn add_entry_all_zero_block_is_rejected_as_corruption() {
        let mut block = vec![0u8; 128];
        let err = add_entry(&mut block, 10, b"new", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn remove_entry_detects_zero_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 0).unwrap();
        block[6] = 1;
        block[7] = Ext4FileType::RegFile as u8;
        block[8] = b'a';

        let err = remove_entry(&mut block, b"a", 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn remove_entry_detects_misaligned_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 13).unwrap();
        block[6] = 1;
        block[7] = Ext4FileType::RegFile as u8;
        block[8] = b'a';

        let err = remove_entry(&mut block, b"a", 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn remove_entry_detects_rec_len_exceeds_block() {
        let mut block = vec![0u8; 32];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 64).unwrap();
        block[6] = 1;
        block[7] = Ext4FileType::RegFile as u8;
        block[8] = b'a';

        let err = remove_entry(&mut block, b"a", 0).unwrap_err();
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

    // ── reserved_tail tests ─────────────────────────────────────────────

    #[test]
    fn add_entry_with_reserved_tail_12() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 2, 2, 12).unwrap();
        add_entry(&mut block, 100, b"file.txt", Ext4FileType::RegFile, 12).unwrap();
        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
        assert!(tail.is_some());
        assert!(
            entries
                .iter()
                .any(|e| e.name == b"file.txt" && e.inode == 100)
        );
    }

    #[test]
    fn remove_entry_with_reserved_tail() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 2, 2, 12).unwrap();
        add_entry(&mut block, 100, b"temp", Ext4FileType::RegFile, 12).unwrap();
        let removed = remove_entry(&mut block, b"temp", 12).unwrap();
        assert!(removed);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert!(!entries.iter().any(|e| e.name == b"temp"));
    }

    #[test]
    fn add_entry_respects_reserved_tail_capacity() {
        // 1024-byte block, init with reserved_tail=12, then try to add when
        // reserved_tail leaves no room beyond existing entries
        let mut block = vec![0u8; 36];
        init_dir_block(&mut block, 2, 2, 12).unwrap();
        // Usable area is 36 - 12 = 24 bytes, entirely consumed by . and ..
        let err = add_entry(&mut block, 10, b"x", Ext4FileType::RegFile, 12).unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOSPC);
    }

    // ── name length edge cases ──────────────────────────────────────────

    #[test]
    fn add_entry_max_name_length_255() {
        let mut block = vec![0u8; 4096];
        write_entry(&mut block, 0, 1, 4096, Ext4FileType::Dir, b".").unwrap();
        let long_name = vec![b'a'; 255];
        let off = add_entry(&mut block, 99, &long_name, Ext4FileType::RegFile, 0).unwrap();
        assert!(off > 0);
        let (entries, _) = parse_dir_block(&block, 4096).unwrap();
        assert!(entries.iter().any(|e| e.name.len() == 255 && e.inode == 99));
    }

    #[test]
    fn add_entry_rejects_name_over_255() {
        let mut block = vec![0u8; 4096];
        write_entry(&mut block, 0, 1, 4096, Ext4FileType::Dir, b".").unwrap();
        let too_long = vec![b'a'; 256];
        let err = add_entry(&mut block, 10, &too_long, Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn add_entry_single_byte_name() {
        let mut block = vec![0u8; 1024];
        write_entry(&mut block, 0, 1, 1024, Ext4FileType::Dir, b".").unwrap();
        let off = add_entry(&mut block, 50, b"x", Ext4FileType::RegFile, 0).unwrap();
        assert!(off > 0);
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries[1].name, b"x".to_vec());
    }

    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_1, 1);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_2, 2);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_3, 3);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_4, 4);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_5, 5);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_8, 8);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_12, 12);
    add_entry_alignment_boundary_test!(add_entry_alignment_boundary_len_16, 16);

    #[test]
    fn add_entry_reuses_deleted_slot_exact_fit() {
        let mut block = vec![0u8; 36];
        write_entry(&mut block, 0, 1, 12, Ext4FileType::Dir, b".").unwrap();
        write_entry(&mut block, 12, 0, 12, Ext4FileType::Unknown, b"x").unwrap();
        write_entry(&mut block, 24, 2, 12, Ext4FileType::Dir, b"..").unwrap();

        let off = add_entry(&mut block, 77, b"z", Ext4FileType::RegFile, 0).unwrap();

        assert_eq!(off, 12);
        assert_eq!(usize::from(read_u16_le(&block, 16).unwrap()), 12);
        let (entries, _) = parse_dir_block(&block, 36).unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.inode == 77 && entry.name == b"z")
        );
    }

    #[test]
    fn add_entry_exact_capacity_with_reserved_tail_succeeds() {
        let mut block = vec![0u8; 48];
        init_dir_block(&mut block, 2, 2, 12).unwrap();

        let off = add_entry(&mut block, 55, b"x", Ext4FileType::RegFile, 12).unwrap();

        assert_eq!(off, 24);
        let (entries, tail) = parse_dir_block(&block, 48).unwrap();
        assert!(tail.is_some());
        assert!(
            entries
                .iter()
                .any(|entry| entry.inode == 55 && entry.name == b"x")
        );
    }

    // ── htree edge cases ────────────────────────────────────────────────

    #[test]
    fn htree_insert_duplicate_hashes() {
        let mut entries = Vec::new();
        htree_insert(&mut entries, 0x5000, 1);
        htree_insert(&mut entries, 0x5000, 2);
        htree_insert(&mut entries, 0x5000, 3);
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e.hash == 0x5000));
    }

    #[test]
    fn htree_find_leaf_single_entry() {
        let entries = vec![HtreeEntry {
            hash: 0x1000,
            block: 5,
        }];
        // With a single entry, partition_point fallback returns index 0 for any target
        assert_eq!(htree_find_leaf(&entries, 0x0), Some(5));
        assert_eq!(htree_find_leaf(&entries, 0x1000), Some(5));
        assert_eq!(htree_find_leaf(&entries, 0xFFFF_FFFF), Some(5));
    }

    #[test]
    fn htree_find_leaf_zero_hash() {
        let entries = vec![
            HtreeEntry { hash: 0, block: 1 },
            HtreeEntry {
                hash: 0x8000,
                block: 2,
            },
        ];
        assert_eq!(htree_find_leaf(&entries, 0), Some(1));
        assert_eq!(htree_find_leaf(&entries, 0x7FFF), Some(1));
        assert_eq!(htree_find_leaf(&entries, 0x8000), Some(2));
    }

    #[test]
    fn htree_find_leaf_u32_max_hash() {
        let entries = vec![
            HtreeEntry { hash: 0, block: 1 },
            HtreeEntry {
                hash: u32::MAX,
                block: 2,
            },
        ];
        assert_eq!(htree_find_leaf(&entries, u32::MAX), Some(2));
        assert_eq!(htree_find_leaf(&entries, u32::MAX - 1), Some(1));
    }

    #[test]
    fn htree_remove_from_empty() {
        let mut entries = Vec::new();
        assert!(!htree_remove(&mut entries, 0x1000, 1));
    }

    #[test]
    fn htree_remove_wrong_block_same_hash() {
        let mut entries = vec![HtreeEntry {
            hash: 0x1000,
            block: 5,
        }];
        assert!(!htree_remove(&mut entries, 0x1000, 99));
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn htree_insert_into_empty() {
        let mut entries = Vec::new();
        let idx = htree_insert(&mut entries, 42, 7);
        assert_eq!(idx, 0);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], HtreeEntry { hash: 42, block: 7 });
    }

    // ── compute_dx_hash edge cases ──────────────────────────────────────

    #[test]
    fn compute_dx_hash_different_seeds_differ() {
        let h1 = compute_dx_hash(1, b"test", &[0, 0, 0, 0]);
        let h2 = compute_dx_hash(1, b"test", &[1, 2, 3, 4]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_dx_hash_long_name() {
        let seed = [1, 2, 3, 4];
        let long_name = vec![b'z'; 255];
        let h1 = compute_dx_hash(1, &long_name, &seed);
        // Deterministic: same input produces same output
        let h2 = compute_dx_hash(1, &long_name, &seed);
        assert_eq!(h1, h2, "hash of max-length name must be deterministic");
        // Different from shorter name
        let short_name = vec![b'z'; 10];
        let h3 = compute_dx_hash(1, &short_name, &seed);
        assert_ne!(
            h1, h3,
            "hash should differ between 255-byte and 10-byte names"
        );
    }

    #[test]
    fn compute_dx_hash_single_byte_name() {
        let seed = [1, 2, 3, 4];
        let h = compute_dx_hash(1, b"a", &seed);
        let h2 = compute_dx_hash(1, b"b", &seed);
        assert_ne!(h, h2);
    }

    // ── block size variations ───────────────────────────────────────────

    #[test]
    fn init_dir_block_4096() {
        let mut block = vec![0u8; 4096];
        init_dir_block(&mut block, 2, 2, 0).unwrap();
        let (entries, _) = parse_dir_block(&block, 4096).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b".".to_vec());
        assert_eq!(entries[1].name, b"..".to_vec());
    }

    #[test]
    fn init_dir_block_minimum_viable_size() {
        // Minimum: . needs 12 bytes, .. needs 12 bytes = 24 total
        let mut block = vec![0u8; 24];
        init_dir_block(&mut block, 5, 3, 0).unwrap();
        let (entries, _) = parse_dir_block(&block, 24).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn init_dir_block_reserved_tail_equal_to_block_minus_minimum_entries() {
        let mut block = vec![0u8; 64];
        init_dir_block(&mut block, 7, 9, 40).unwrap();

        let (entries, tail) = parse_dir_block(&block, 64).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].rec_len, 12);
        assert!(tail.is_some());
    }

    // ── multiple operations ─────────────────────────────────────────────

    #[test]
    fn fill_block_then_enospc() {
        let mut block = vec![0u8; 128];
        init_dir_block(&mut block, 2, 2, 0).unwrap();
        // Fill up with entries
        let mut count = 0;
        for i in 3..100_u32 {
            let name = format!("f{i}");
            match add_entry(&mut block, i, name.as_bytes(), Ext4FileType::RegFile, 0) {
                Ok(_) => count += 1,
                Err(_) => break,
            }
        }
        assert!(count > 0, "should fit at least one entry");
        // Next add should fail
        let err = add_entry(&mut block, 999, b"overflow", Ext4FileType::RegFile, 0);
        assert!(err.is_err());
    }

    #[test]
    fn fill_4096_block_parses_every_inserted_entry() {
        let mut block = vec![0u8; 4096];
        let mut inserted = BTreeSet::new();
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        for ino in 3..512_u32 {
            let name = format!("bulk{ino:03}");
            match add_entry(&mut block, ino, name.as_bytes(), Ext4FileType::RegFile, 0) {
                Ok(_) => {
                    inserted.insert(name.into_bytes());
                }
                Err(err) => {
                    assert!(
                        matches!(err, FfsError::NoSpace),
                        "unexpected add_entry failure: {err:?}"
                    );
                    break;
                }
            }
        }

        let live_names = live_name_set(&block);
        assert!(live_names.contains(b".".as_slice()));
        assert!(live_names.contains(b"..".as_slice()));
        for name in inserted {
            assert!(
                live_names.contains(&name),
                "missing inserted entry {name:?}"
            );
        }
    }

    #[test]
    fn add_remove_add_cycle_multiple() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        for i in 0..5_u32 {
            let name = format!("cycle{i}");
            add_entry(
                &mut block,
                100 + i,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
            remove_entry(&mut block, name.as_bytes(), 0).unwrap();
        }

        // After all cycles, only . and .. should remain (as live entries)
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.iter().filter(|e| e.inode != 0).count(), 2);
    }

    #[test]
    fn remove_every_other_then_add() {
        let mut block = vec![0u8; 4096];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        // Add 10 entries
        for i in 0..10_u32 {
            let name = format!("entry{i:02}");
            add_entry(
                &mut block,
                100 + i,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
        }

        // Remove odd-indexed entries
        for i in (1..10_u32).step_by(2) {
            let name = format!("entry{i:02}");
            remove_entry(&mut block, name.as_bytes(), 0).unwrap();
        }

        // Re-add to reclaimed slots
        for i in 0..5_u32 {
            let name = format!("new{i:02}");
            add_entry(
                &mut block,
                200 + i,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
        }

        let (entries, _) = parse_dir_block(&block, 4096).unwrap();
        // . + .. + 5 even originals + 5 new = 12
        assert_eq!(entries.iter().filter(|e| e.inode != 0).count(), 12);
    }

    #[test]
    fn add_100_remove_50_add_50_preserves_expected_live_set() {
        let mut block = vec![0u8; 8192];
        init_dir_block(&mut block, 2, 2, 0).unwrap();

        for ino in 0..100_u32 {
            let name = format!("seed{ino:03}");
            add_entry(
                &mut block,
                1_000 + ino,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
        }

        for ino in 0..50_u32 {
            let name = format!("seed{ino:03}");
            assert!(remove_entry(&mut block, name.as_bytes(), 0).unwrap());
        }

        for ino in 0..50_u32 {
            let name = format!("fresh{ino:03}");
            add_entry(
                &mut block,
                2_000 + ino,
                name.as_bytes(),
                Ext4FileType::RegFile,
                0,
            )
            .unwrap();
        }

        let live_names = live_name_set(&block);
        assert_eq!(live_names.len(), 102);
        assert!(live_names.contains(b".".as_slice()));
        assert!(live_names.contains(b"..".as_slice()));
        for ino in 0..50_u32 {
            assert!(!live_names.contains(format!("seed{ino:03}").as_bytes()));
        }
        for ino in 50..100_u32 {
            assert!(live_names.contains(format!("seed{ino:03}").as_bytes()));
        }
        for ino in 0..50_u32 {
            assert!(live_names.contains(format!("fresh{ino:03}").as_bytes()));
        }
    }

    // ── corruption detection ────────────────────────────────────────────

    #[test]
    fn add_entry_detects_misaligned_rec_len() {
        let mut block = vec![0u8; 128];
        write_u32_le(&mut block, 0, 10).unwrap(); // inode
        write_u16_le(&mut block, 4, 13).unwrap(); // rec_len = 13 (not 4-aligned)
        block[6] = 1;
        block[7] = 1;
        block[8] = b'a';

        let err = add_entry(&mut block, 20, b"new", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    #[test]
    fn add_entry_detects_rec_len_exceeds_block() {
        let mut block = vec![0u8; 32];
        write_u32_le(&mut block, 0, 10).unwrap();
        write_u16_le(&mut block, 4, 64).unwrap(); // rec_len > block size
        block[6] = 1;
        block[7] = 1;
        block[8] = b'a';

        let err = add_entry(&mut block, 20, b"x", Ext4FileType::RegFile, 0).unwrap_err();
        assert!(matches!(err, FfsError::Corruption { .. }));
    }

    // ── init_dir_block edge cases ───────────────────────────────────────

    #[test]
    fn init_dir_block_reserved_tail_zero() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 5, 3, 0).unwrap();
        let (_, tail) = parse_dir_block(&block, 1024).unwrap();
        assert!(tail.is_none());
    }

    #[test]
    fn init_dir_block_large_reserved_tail() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 5, 3, 24).unwrap();
        let (entries, tail) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(tail.is_some());
    }

    #[test]
    fn init_dir_block_preserves_inode_numbers() {
        let mut block = vec![0u8; 1024];
        init_dir_block(&mut block, 0xFFFF_FFFE, 0xFFFF_FFFF, 0).unwrap();
        let (entries, _) = parse_dir_block(&block, 1024).unwrap();
        assert_eq!(entries[0].inode, 0xFFFF_FFFE);
        assert_eq!(entries[1].inode, 0xFFFF_FFFF);
    }

    // ── file type preservation ──────────────────────────────────────────

    #[test]
    fn add_entry_preserves_file_types() {
        let types = [
            (Ext4FileType::RegFile, b"file" as &[u8]),
            (Ext4FileType::Dir, b"dir"),
            (Ext4FileType::Symlink, b"link"),
            (Ext4FileType::Chrdev, b"cdev"),
            (Ext4FileType::Blkdev, b"bdev"),
            (Ext4FileType::Fifo, b"fifo"),
            (Ext4FileType::Sock, b"sock"),
        ];
        let mut block = vec![0u8; 4096];
        write_entry(&mut block, 0, 1, 4096, Ext4FileType::Dir, b".").unwrap();

        for (i, (ft, name)) in types.iter().enumerate() {
            add_entry(&mut block, u32::try_from(i + 10).unwrap(), name, *ft, 0).unwrap();
        }

        let (entries, _) = parse_dir_block(&block, 4096).unwrap();
        assert!(entries.len() >= 8);
        for (ft, name) in &types {
            let entry = entries.iter().find(|e| e.name == *name).unwrap();
            assert_eq!(entry.file_type, *ft);
        }
    }

    // ── HtreeEntry derive trait coverage ────────────────────────────────

    #[test]
    fn htree_find_leaf_handles_collisions_correctly() {
        let entries = vec![
            HtreeEntry { hash: 0, block: 1 },
            HtreeEntry {
                hash: 100,
                block: 2,
            },
            HtreeEntry {
                hash: 101,
                block: 3,
            }, // 101 means 100 | 1 (collision bit)
            HtreeEntry {
                hash: 200,
                block: 4,
            },
        ];
        // Looking for hash 100.
        let mut idx = htree_find_leaf_idx(&entries, 100);
        assert_eq!(idx, 1);
        assert_eq!(entries[idx].block, 2);

        // Simulate not found in block 2, check next
        idx += 1;
        assert!(idx < entries.len());
        // Hash 101 has bit 1 set, meaning it's a collision continuation of 100.
        assert_eq!(entries[idx].hash & 1, 1);
        assert_eq!(entries[idx].hash & !1, 100);
        assert_eq!(entries[idx].block, 3);
    }
}
