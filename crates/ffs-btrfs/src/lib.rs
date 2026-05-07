#![forbid(unsafe_code)]
//! Higher-level btrfs operations: tree traversal, item enumeration.
//!
//! Builds on `ffs_ondisk::btrfs` parsing primitives. I/O-agnostic —
//! callers provide a read callback for physical byte access.

use asupersync::Cx;
use ffs_mvcc::{CommitError, MvccStore, Transaction};
pub use ffs_ondisk::btrfs::*;
use ffs_types::{BlockNumber, CommitSeq, ParseError, Snapshot, TxnId};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

/// A single leaf item yielded by tree traversal: key + raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsLeafEntry {
    pub key: BtrfsKey,
    pub data: Vec<u8>,
}

/// btrfs objectid for the root tree.
pub const BTRFS_ROOT_TREE_OBJECTID: u64 = 1;
/// btrfs objectid for the default filesystem tree.
pub const BTRFS_FS_TREE_OBJECTID: u64 = 5;

/// btrfs item type constants used by the read-only VFS path.
pub const BTRFS_ITEM_INODE_ITEM: u8 = 1;
pub const BTRFS_ITEM_DIR_ITEM: u8 = 84;
pub const BTRFS_ITEM_DIR_INDEX: u8 = 96;
pub const BTRFS_ITEM_INODE_REF: u8 = 12;
pub const BTRFS_ITEM_XATTR_ITEM: u8 = 24;
pub const BTRFS_ITEM_EXTENT_DATA: u8 = 108;
pub const BTRFS_ITEM_ROOT_ITEM: u8 = 132;

/// btrfs item type constants for extent/block-group management (write path).
pub const BTRFS_ITEM_EXTENT_ITEM: u8 = 168;
pub const BTRFS_ITEM_METADATA_ITEM: u8 = 169;
pub const BTRFS_ITEM_BLOCK_GROUP_ITEM: u8 = 192;
pub const BTRFS_ITEM_DEV_ITEM: u8 = 216;
pub const BTRFS_ITEM_CHUNK: u8 = 228;
pub const BTRFS_ITEM_FREE_SPACE_INFO: u8 = 198;
pub const BTRFS_ITEM_FREE_SPACE_EXTENT: u8 = 199;
pub const BTRFS_ITEM_FREE_SPACE_BITMAP: u8 = 200;

/// Well-known tree objectids (kernel: fs/btrfs/btrfs_tree.h).
pub const BTRFS_EXTENT_TREE_OBJECTID: u64 = 2;
pub const BTRFS_CHUNK_TREE_OBJECTID: u64 = 3;
pub const BTRFS_DEV_TREE_OBJECTID: u64 = 4;
/// Root tree's dir entry inode (kernel: `BTRFS_ROOT_TREE_DIR_OBJECTID`).
pub const BTRFS_ROOT_TREE_DIR_OBJECTID: u64 = 6;
/// Data-checksum tree (kernel: `BTRFS_CSUM_TREE_OBJECTID`).
pub const BTRFS_CSUM_TREE_OBJECTID: u64 = 7;
/// Quota tree (kernel: `BTRFS_QUOTA_TREE_OBJECTID`).
pub const BTRFS_QUOTA_TREE_OBJECTID: u64 = 8;
/// Subvolume UUID lookup tree (kernel: `BTRFS_UUID_TREE_OBJECTID`).
pub const BTRFS_UUID_TREE_OBJECTID: u64 = 9;
/// Free-space tree v2 (kernel: `BTRFS_FREE_SPACE_TREE_OBJECTID`).
pub const BTRFS_FREE_SPACE_TREE_OBJECTID: u64 = 10;
/// Block-group tree v2 (kernel: `BTRFS_BLOCK_GROUP_TREE_OBJECTID`).
pub const BTRFS_BLOCK_GROUP_TREE_OBJECTID: u64 = 11;

/// Block group type flags.
pub const BTRFS_BLOCK_GROUP_DATA: u64 = 1;
pub const BTRFS_BLOCK_GROUP_SYSTEM: u64 = 2;
pub const BTRFS_BLOCK_GROUP_METADATA: u64 = 4;

/// Directory entry type values stored in btrfs dir items.
pub const BTRFS_FT_UNKNOWN: u8 = 0;
pub const BTRFS_FT_REG_FILE: u8 = 1;
pub const BTRFS_FT_DIR: u8 = 2;
pub const BTRFS_FT_CHRDEV: u8 = 3;
pub const BTRFS_FT_BLKDEV: u8 = 4;
pub const BTRFS_FT_FIFO: u8 = 5;
pub const BTRFS_FT_SOCK: u8 = 6;
pub const BTRFS_FT_SYMLINK: u8 = 7;

/// File extent type values in EXTENT_DATA payloads.
pub const BTRFS_FILE_EXTENT_INLINE: u8 = 0;
pub const BTRFS_FILE_EXTENT_REG: u8 = 1;
pub const BTRFS_FILE_EXTENT_PREALLOC: u8 = 2;

/// Compression type values in EXTENT_DATA payloads.
pub const BTRFS_COMPRESS_NONE: u8 = 0;
pub const BTRFS_COMPRESS_ZLIB: u8 = 1;
pub const BTRFS_COMPRESS_LZO: u8 = 2;
pub const BTRFS_COMPRESS_ZSTD: u8 = 3;

/// Highest valid btrfs tree level. The kernel's `BTRFS_MAX_LEVEL` is the
/// level count (8), so valid on-disk levels are `0..=7`.
pub const BTRFS_MAX_TREE_LEVEL: u8 = 7;

/// Internal MVCC metadata block base used for btrfs transaction manifests.
const BTRFS_TX_META_BASE_BLOCK: u64 = 0x4_0000_0000;
/// Internal MVCC metadata block base used for tree-root pointer updates.
const BTRFS_TX_TREE_ROOT_BASE_BLOCK: u64 = 0x4_1000_0000;
/// Internal MVCC metadata block base used for pending-free ledgers.
const BTRFS_TX_PENDING_FREE_BASE_BLOCK: u64 = 0x4_2000_0000;

const BTRFS_ROOT_ITEM_LEGACY_SIZE: usize = 239;
const BTRFS_ROOT_ITEM_GENERATION_OFFSET: usize = 160;
const BTRFS_ROOT_ITEM_ROOT_DIRID_OFFSET: usize = 168;
const BTRFS_ROOT_ITEM_BYTENR_OFFSET: usize = 176;
const BTRFS_ROOT_ITEM_FLAGS_OFFSET: usize = 208;
const BTRFS_ROOT_ITEM_REFS_OFFSET: usize = 216;
const BTRFS_ROOT_ITEM_LEVEL_OFFSET: usize = 238;
const BTRFS_ROOT_ITEM_GENERATION_V2_OFFSET: usize = 239;
const BTRFS_ROOT_ITEM_UUID_OFFSET: usize = 247;
const BTRFS_ROOT_ITEM_PARENT_UUID_OFFSET: usize = 263;
const BTRFS_ROOT_ITEM_UUID_END: usize = BTRFS_ROOT_ITEM_UUID_OFFSET + 16;
const BTRFS_ROOT_ITEM_PARENT_UUID_END: usize = BTRFS_ROOT_ITEM_PARENT_UUID_OFFSET + 16;

/// Parsed subset of `btrfs_root_item` needed for tree bootstrapping,
/// subvolume enumeration, and snapshot navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsRootItem {
    /// Logical address of the tree root block (`bytenr`).
    pub bytenr: u64,
    /// Root tree level (`0` for leaf roots).
    pub level: u8,
    /// Generation when this root was last modified.
    pub generation: u64,
    /// Directory inode for the root of this subvolume (typically 256).
    pub root_dirid: u64,
    /// Flags (bit 0 = read-only subvolume).
    pub flags: u64,
    /// Reference count.
    pub refs: u64,
    /// UUID of this subvolume/snapshot (zero if not set).
    pub uuid: [u8; 16],
    /// Parent UUID — set when this is a snapshot (identifies source subvolume).
    pub parent_uuid: [u8; 16],
}

/// A parsed btrfs ROOT_REF item linking parent subvolume to child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsRootRef {
    /// Directory inode in parent subvolume containing this entry.
    pub dirid: u64,
    /// Sequence number.
    pub sequence: u64,
    /// Name of the subvolume entry.
    pub name: Vec<u8>,
}

/// One decoded btrfs INODE_REF entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsInodeRef {
    /// Directory index for the name within the parent inode.
    pub index: u64,
    /// Directory entry name for this child in the parent directory.
    pub name: Vec<u8>,
}

impl BtrfsInodeRef {
    /// Fallibly serialize to the on-disk INODE_REF entry layout.
    ///
    /// Layout: index(8) + name_len(2) + name bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidField`] when the name cannot fit in the
    /// on-disk `u16` `name_len` field.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, ParseError> {
        let name_len = btrfs_name_len_u16(self.name.len(), "inode_ref.name_len")?;
        let mut buf = Vec::with_capacity(10 + usize::from(name_len));
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&self.name);
        Ok(buf)
    }

    /// Serialize to the on-disk INODE_REF entry layout.
    ///
    /// Layout: index(8) + name_len(2) + name bytes.
    ///
    /// # Panics
    ///
    /// Panics when the name cannot fit in the on-disk `u16` `name_len` field.
    /// Use [`Self::try_to_bytes`] when serializing untrusted or caller-owned names.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("BtrfsInodeRef name length exceeds u16::MAX")
    }
}

fn btrfs_name_len_u16(len: usize, field: &'static str) -> Result<u16, ParseError> {
    if len == 0 {
        return Err(ParseError::InvalidField {
            field,
            reason: "must be non-zero",
        });
    }
    u16::try_from(len).map_err(|_| ParseError::InvalidField {
        field,
        reason: "name length exceeds u16::MAX",
    })
}

/// Descriptor for an enumerated btrfs subvolume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsSubvolume {
    /// Subvolume object ID (also the tree ID).
    pub id: u64,
    /// Parent subvolume ID (0 if top-level).
    pub parent_id: u64,
    /// Name of the subvolume (from ROOT_REF).
    pub name: String,
    /// Generation when last modified.
    pub generation: u64,
    /// Whether this subvolume is read-only.
    pub read_only: bool,
    /// Logical address of the subvolume's root tree block.
    pub bytenr: u64,
    /// Root tree level.
    pub level: u8,
}

/// Descriptor for an enumerated btrfs snapshot.
///
/// A snapshot is a read-only subvolume whose `parent_uuid` is non-zero,
/// indicating which subvolume it was created from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsSnapshot {
    /// Snapshot subvolume ID.
    pub id: u64,
    /// Source subvolume ID (the subvolume this is a snapshot of).
    pub source_id: u64,
    /// Name of the snapshot.
    pub name: String,
    /// Generation when the snapshot was created.
    pub generation: u64,
    /// UUID of this snapshot.
    pub uuid: [u8; 16],
    /// UUID of the source subvolume.
    pub parent_uuid: [u8; 16],
    /// Logical address of the snapshot's root tree block.
    pub bytenr: u64,
    /// Root tree level.
    pub level: u8,
}

/// Type of change detected in a generation-based snapshot diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotChangeType {
    /// Item was added (present in newer, absent in older).
    Added,
    /// Item was modified (present in both, newer generation).
    Modified,
    /// Item was deleted (present in older, absent in newer).
    Deleted,
}

/// A single change entry from a generation-based snapshot diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDiffEntry {
    /// Inode objectid of the changed file.
    pub inode: u64,
    /// Type of change.
    pub change_type: SnapshotChangeType,
}

/// btrfs ROOT_REF item type (parent → child subvolume link).
pub const BTRFS_ITEM_ROOT_REF: u8 = 156;
/// btrfs ROOT_BACKREF item type (child → parent subvolume link).
pub const BTRFS_ITEM_ROOT_BACKREF: u8 = 144;
/// Flag bit in `BtrfsRootItem::flags` indicating a read-only subvolume.
const BTRFS_ROOT_SUBVOL_RDONLY: u64 = 1 << 0;
/// First free objectid for user subvolumes.
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

/// Parsed subset of `btrfs_inode_item` needed for read-only VFS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsInodeItem {
    /// Transaction generation when this inode was created.
    ///
    /// Used as the FUSE/NFS generation number for stale-handle detection.
    /// Since btrfs objectids are never reused, the creation-time transaction
    /// generation uniquely identifies this inode incarnation.
    pub generation: u64,
    pub size: u64,
    pub nbytes: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u64,
    pub atime_sec: u64,
    pub atime_nsec: u32,
    pub ctime_sec: u64,
    pub ctime_nsec: u32,
    pub mtime_sec: u64,
    pub mtime_nsec: u32,
    pub otime_sec: u64,
    pub otime_nsec: u32,
}

impl BtrfsInodeItem {
    /// Serialize to the 160-byte on-disk representation.
    ///
    /// Layout matches the kernel `btrfs_inode_item` struct. Fields we do not
    /// track (block_group, sequence, flags, reserved) are zeroed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 160];
        buf[0..8].copy_from_slice(&self.generation.to_le_bytes());
        // transid at 8..16 (zero)
        buf[16..24].copy_from_slice(&self.size.to_le_bytes());
        buf[24..32].copy_from_slice(&self.nbytes.to_le_bytes());
        // block_group at 32..40 (zero)
        buf[40..44].copy_from_slice(&self.nlink.to_le_bytes());
        buf[44..48].copy_from_slice(&self.uid.to_le_bytes());
        buf[48..52].copy_from_slice(&self.gid.to_le_bytes());
        buf[52..56].copy_from_slice(&self.mode.to_le_bytes());
        buf[56..64].copy_from_slice(&self.rdev.to_le_bytes());
        // flags at 64..72 (zero)
        // sequence at 72..80 (zero)
        // reserved[4] at 80..112 (zero)
        buf[112..120].copy_from_slice(&self.atime_sec.to_le_bytes());
        buf[120..124].copy_from_slice(&self.atime_nsec.to_le_bytes());
        buf[124..132].copy_from_slice(&self.ctime_sec.to_le_bytes());
        buf[132..136].copy_from_slice(&self.ctime_nsec.to_le_bytes());
        buf[136..144].copy_from_slice(&self.mtime_sec.to_le_bytes());
        buf[144..148].copy_from_slice(&self.mtime_nsec.to_le_bytes());
        buf[148..156].copy_from_slice(&self.otime_sec.to_le_bytes());
        buf[156..160].copy_from_slice(&self.otime_nsec.to_le_bytes());
        buf
    }
}

/// One decoded directory entry from DIR_ITEM / DIR_INDEX payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsDirItem {
    pub child_objectid: u64,
    pub child_key_type: u8,
    pub child_key_offset: u64,
    pub file_type: u8,
    pub name: Vec<u8>,
}

impl BtrfsDirItem {
    /// Fallibly serialize to the on-disk DIR_ITEM / DIR_INDEX layout.
    ///
    /// Layout: location key (objectid:8 + type:1 + offset:8) + transid(8) +
    /// data_len(2) + name_len(2) + file_type(1) + name bytes.
    /// `transid` is set to zero (not tracked in our VFS layer).
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidField`] when the name cannot fit in the
    /// on-disk `u16` `name_len` field.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, ParseError> {
        let name_len = btrfs_name_len_u16(self.name.len(), "dir_item.name_len")?;
        let mut buf = vec![0u8; 30 + usize::from(name_len)];
        buf[0..8].copy_from_slice(&self.child_objectid.to_le_bytes());
        buf[8] = self.child_key_type;
        buf[9..17].copy_from_slice(&self.child_key_offset.to_le_bytes());
        // transid at 17..25 (zero)
        // data_len at 25..27 (zero — no trailing payload)
        buf[27..29].copy_from_slice(&name_len.to_le_bytes());
        buf[29] = self.file_type;
        buf[30..].copy_from_slice(&self.name);
        Ok(buf)
    }

    /// Serialize to the on-disk DIR_ITEM / DIR_INDEX layout.
    ///
    /// Layout: location key (objectid:8 + type:1 + offset:8) + transid(8) +
    /// data_len(2) + name_len(2) + file_type(1) + name bytes.
    /// `transid` is set to zero (not tracked in our VFS layer).
    ///
    /// # Panics
    ///
    /// Panics when the name cannot fit in the on-disk `u16` `name_len` field.
    /// Use [`Self::try_to_bytes`] when serializing untrusted or caller-owned names.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.try_to_bytes()
            .expect("BtrfsDirItem name length exceeds u16::MAX")
    }
}

/// Parsed XATTR_ITEM payload.
///
/// Uses the same on-disk layout as `BtrfsDirItem` but with `data_len > 0`:
/// the value bytes follow the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsXattrItem {
    /// The extended attribute name (e.g. `user.foo`).
    pub name: Vec<u8>,
    /// The extended attribute value.
    pub value: Vec<u8>,
}

/// Parse one or more XATTR_ITEM entries from the concatenated payload bytes.
///
/// The format is the same DIR_ITEM header (30 bytes) followed by `name_len`
/// bytes of name and `data_len` bytes of value.
pub fn parse_xattr_items(data: &[u8]) -> Result<Vec<BtrfsXattrItem>, ParseError> {
    const HEADER: usize = 30;
    let mut out = Vec::new();
    let mut cur = 0_usize;
    while cur < data.len() {
        if cur + HEADER > data.len() {
            return Err(ParseError::InsufficientData {
                needed: HEADER,
                offset: cur,
                actual: data.len() - cur,
            });
        }
        let data_len = usize::from(read_u16(data, cur + 25, "xattr.data_len")?);
        let name_len = usize::from(read_u16(data, cur + 27, "xattr.name_len")?);
        if name_len == 0 {
            return Err(ParseError::InvalidField {
                field: "xattr.name_len",
                reason: "must be non-zero",
            });
        }

        let name_start = cur + HEADER;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ParseError::InvalidField {
                field: "xattr.name_len",
                reason: "overflow",
            })?;
        let value_end = name_end
            .checked_add(data_len)
            .ok_or(ParseError::InvalidField {
                field: "xattr.data_len",
                reason: "overflow",
            })?;

        if value_end > data.len() {
            return Err(ParseError::InsufficientData {
                needed: value_end,
                offset: cur,
                actual: data.len(),
            });
        }

        out.push(BtrfsXattrItem {
            name: data[name_start..name_end].to_vec(),
            value: data[name_end..value_end].to_vec(),
        });
        cur = value_end;
    }
    Ok(out)
}

/// Parsed EXTENT_DATA payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsExtentData {
    /// Inline extent payload bytes.
    Inline {
        generation: u64,
        ram_bytes: u64,
        compression: u8,
        data: Vec<u8>,
    },
    /// Regular or preallocated extent that references on-disk bytes.
    ///
    /// `disk_bytenr` is a logical bytenr in btrfs address space.
    Regular {
        generation: u64,
        ram_bytes: u64,
        extent_type: u8,
        compression: u8,
        disk_bytenr: u64,
        disk_num_bytes: u64,
        extent_offset: u64,
        num_bytes: u64,
    },
}

impl BtrfsExtentData {
    /// Serialize to the on-disk EXTENT_DATA layout.
    ///
    /// Fixed header (21 bytes): generation(8) + ram_bytes(8) + compression(1)
    /// + encryption(1) + other_encoding(2) + type(1).
    ///   Inline: header + data bytes.
    ///   Regular: header + disk_bytenr(8) + disk_num_bytes(8) + offset(8) + num_bytes(8).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Inline {
                generation,
                ram_bytes,
                compression,
                data,
            } => {
                let mut buf = vec![0u8; 21 + data.len()];
                buf[0..8].copy_from_slice(&generation.to_le_bytes());
                buf[8..16].copy_from_slice(&ram_bytes.to_le_bytes());
                buf[16] = *compression;
                // encryption at 17 (zero)
                // other_encoding at 18..20 (zero)
                buf[20] = BTRFS_FILE_EXTENT_INLINE;
                buf[21..21 + data.len()].copy_from_slice(data);
                buf
            }
            Self::Regular {
                generation,
                ram_bytes,
                extent_type,
                compression,
                disk_bytenr,
                disk_num_bytes,
                extent_offset,
                num_bytes,
            } => {
                let mut buf = vec![0u8; 53];
                buf[0..8].copy_from_slice(&generation.to_le_bytes());
                buf[8..16].copy_from_slice(&ram_bytes.to_le_bytes());
                buf[16] = *compression;
                // encryption at 17 (zero)
                // other_encoding at 18..20 (zero)
                buf[20] = *extent_type;
                buf[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
                buf[29..37].copy_from_slice(&disk_num_bytes.to_le_bytes());
                buf[37..45].copy_from_slice(&extent_offset.to_le_bytes());
                buf[45..53].copy_from_slice(&num_bytes.to_le_bytes());
                buf
            }
        }
    }
}

fn read_exact<const N: usize>(
    data: &[u8],
    off: usize,
    field: &'static str,
) -> Result<[u8; N], ParseError> {
    let end = off.checked_add(N).ok_or(ParseError::InvalidField {
        field,
        reason: "offset overflow",
    })?;
    let Some(slice) = data.get(off..end) else {
        return Err(ParseError::InsufficientData {
            needed: end,
            offset: off,
            actual: data.len(),
        });
    };
    let mut out = [0_u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_u16(data: &[u8], off: usize, field: &'static str) -> Result<u16, ParseError> {
    Ok(u16::from_le_bytes(read_exact::<2>(data, off, field)?))
}

fn read_u32(data: &[u8], off: usize, field: &'static str) -> Result<u32, ParseError> {
    Ok(u32::from_le_bytes(read_exact::<4>(data, off, field)?))
}

fn read_u64(data: &[u8], off: usize, field: &'static str) -> Result<u64, ParseError> {
    Ok(u64::from_le_bytes(read_exact::<8>(data, off, field)?))
}

/// Parse the subset of `btrfs_root_item` needed to find the FS tree root,
/// enumerate subvolumes, and identify snapshots.
///
/// Layout (stable for the supported on-disk variants):
/// - offset 160: `generation` (u64)
/// - offset 168: `root_dirid` (u64)
/// - offset 176: `bytenr` (u64)
/// - offset 208: `flags` (u64)
/// - offset 216: `refs` (u32)
/// - offset 238: `level` (u8)
/// - offset 239: `generation_v2` (u64) — validates newer optional fields
/// - offset 247: `uuid` (16 bytes) — zero if absent/stale, rejected if partial and valid
/// - offset 263: `parent_uuid` (16 bytes) — zero if absent/stale, rejected if partial and valid
pub fn parse_root_item(data: &[u8]) -> Result<BtrfsRootItem, ParseError> {
    if data.len() < BTRFS_ROOT_ITEM_LEGACY_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_ROOT_ITEM_LEGACY_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }
    if data.len() > BTRFS_ROOT_ITEM_LEGACY_SIZE && data.len() < BTRFS_ROOT_ITEM_UUID_OFFSET {
        return Err(ParseError::InvalidField {
            field: "root_item.generation_v2",
            reason: "partial extension field",
        });
    }

    let generation = read_u64(
        data,
        BTRFS_ROOT_ITEM_GENERATION_OFFSET,
        "root_item.generation",
    )?;
    let root_dirid = read_u64(
        data,
        BTRFS_ROOT_ITEM_ROOT_DIRID_OFFSET,
        "root_item.root_dirid",
    )?;
    let bytenr = read_u64(data, BTRFS_ROOT_ITEM_BYTENR_OFFSET, "root_item.bytenr")?;
    let flags = read_u64(data, BTRFS_ROOT_ITEM_FLAGS_OFFSET, "root_item.flags")?;
    let refs = u64::from(read_u32(
        data,
        BTRFS_ROOT_ITEM_REFS_OFFSET,
        "root_item.refs",
    )?);
    let level = read_exact::<1>(data, BTRFS_ROOT_ITEM_LEVEL_OFFSET, "root_item.level")?[0];

    // UUID-era fields are valid only when generation_v2 matches generation;
    // older kernels can leave stale values behind after modifying the root.
    let extended_fields_valid = if data.len() >= BTRFS_ROOT_ITEM_UUID_OFFSET {
        read_u64(
            data,
            BTRFS_ROOT_ITEM_GENERATION_V2_OFFSET,
            "root_item.generation_v2",
        )? == generation
    } else {
        false
    };
    if extended_fields_valid
        && data.len() > BTRFS_ROOT_ITEM_UUID_OFFSET
        && data.len() < BTRFS_ROOT_ITEM_UUID_END
    {
        return Err(ParseError::InvalidField {
            field: "root_item.uuid",
            reason: "partial extension field",
        });
    }
    if extended_fields_valid
        && data.len() > BTRFS_ROOT_ITEM_PARENT_UUID_OFFSET
        && data.len() < BTRFS_ROOT_ITEM_PARENT_UUID_END
    {
        return Err(ParseError::InvalidField {
            field: "root_item.parent_uuid",
            reason: "partial extension field",
        });
    }

    let uuid = if extended_fields_valid && data.len() >= BTRFS_ROOT_ITEM_UUID_END {
        read_exact::<16>(data, BTRFS_ROOT_ITEM_UUID_OFFSET, "root_item.uuid")?
    } else {
        [0u8; 16]
    };
    let parent_uuid = if extended_fields_valid && data.len() >= BTRFS_ROOT_ITEM_PARENT_UUID_END {
        read_exact::<16>(
            data,
            BTRFS_ROOT_ITEM_PARENT_UUID_OFFSET,
            "root_item.parent_uuid",
        )?
    } else {
        [0u8; 16]
    };

    if bytenr == 0 {
        return Err(ParseError::InvalidField {
            field: "root_item.bytenr",
            reason: "must be non-zero",
        });
    }
    if level > BTRFS_MAX_TREE_LEVEL {
        return Err(ParseError::InvalidField {
            field: "root_item.level",
            reason: "exceeds maximum btrfs tree level",
        });
    }

    Ok(BtrfsRootItem {
        bytenr,
        level,
        generation,
        root_dirid,
        flags,
        refs,
        uuid,
        parent_uuid,
    })
}

/// Parse a ROOT_REF item payload.
///
/// Layout:
/// - offset 0: `dirid` (u64) — directory inode in parent subvolume
/// - offset 8: `sequence` (u64)
/// - offset 16: `name_len` (u16)
/// - offset 18: name bytes (variable length)
pub fn parse_root_ref(data: &[u8]) -> Result<BtrfsRootRef, ParseError> {
    if data.len() < 18 {
        return Err(ParseError::InsufficientData {
            needed: 18,
            offset: 0,
            actual: data.len(),
        });
    }
    let dirid = read_u64(data, 0, "root_ref.dirid")?;
    let sequence = read_u64(data, 8, "root_ref.sequence")?;
    let name_len = u16::from_le_bytes([data[16], data[17]]);
    if name_len == 0 {
        return Err(ParseError::InvalidField {
            field: "root_ref.name_len",
            reason: "must be non-zero",
        });
    }
    let name_end = 18 + usize::from(name_len);
    if data.len() < name_end {
        return Err(ParseError::InsufficientData {
            needed: name_end,
            offset: 18,
            actual: data.len() - 18,
        });
    }
    if data.len() > name_end {
        return Err(ParseError::InvalidField {
            field: "root_ref.name_len",
            reason: "does not match payload length",
        });
    }
    Ok(BtrfsRootRef {
        dirid,
        sequence,
        name: data[18..name_end].to_vec(),
    })
}

/// Parse one or more INODE_REF entries from a raw btrfs payload.
pub fn parse_inode_refs(data: &[u8]) -> Result<Vec<BtrfsInodeRef>, ParseError> {
    const HEADER: usize = 10;
    let mut out = Vec::new();
    let mut cur = 0_usize;
    while cur < data.len() {
        if cur + HEADER > data.len() {
            return Err(ParseError::InsufficientData {
                needed: HEADER,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let index = read_u64(data, cur, "inode_ref.index")?;
        let name_len = usize::from(read_u16(data, cur + 8, "inode_ref.name_len")?);
        if name_len == 0 {
            return Err(ParseError::InvalidField {
                field: "inode_ref.name_len",
                reason: "must be non-zero",
            });
        }
        let name_start = cur + HEADER;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ParseError::InvalidField {
                field: "inode_ref.name_len",
                reason: "overflow",
            })?;
        if name_end > data.len() {
            return Err(ParseError::InsufficientData {
                needed: name_end,
                offset: cur,
                actual: data.len(),
            });
        }

        out.push(BtrfsInodeRef {
            index,
            name: data[name_start..name_end].to_vec(),
        });
        cur = name_end;
    }
    Ok(out)
}

/// Enumerate subvolumes from root tree leaf entries.
///
/// Takes all leaf entries from the root tree (obtained via `walk_tree`)
/// and extracts subvolume information by correlating ROOT_ITEM and ROOT_REF
/// entries for objectids >= 256 (user subvolumes).
#[must_use]
pub fn enumerate_subvolumes(entries: &[BtrfsLeafEntry]) -> Vec<BtrfsSubvolume> {
    let mut subvols = Vec::new();

    // Collect ROOT_ITEM entries for user subvolumes
    for entry in entries {
        if entry.key.item_type != BTRFS_ITEM_ROOT_ITEM {
            continue;
        }
        let id = entry.key.objectid;
        if id < BTRFS_FIRST_FREE_OBJECTID {
            continue;
        }
        let Ok(root) = parse_root_item(&entry.data) else {
            continue;
        };

        // Find matching ROOT_REF for this subvolume
        let (parent_id, name) = entries
            .iter()
            .find_map(|e| {
                if e.key.item_type == BTRFS_ITEM_ROOT_REF && e.key.offset == id {
                    let rref = parse_root_ref(&e.data).ok()?;
                    let name = String::from_utf8_lossy(&rref.name).into_owned();
                    Some((e.key.objectid, name))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| (0, format!("subvol-{id}")));

        subvols.push(BtrfsSubvolume {
            id,
            parent_id,
            name,
            generation: root.generation,
            read_only: root.flags & BTRFS_ROOT_SUBVOL_RDONLY != 0,
            bytenr: root.bytenr,
            level: root.level,
        });
    }

    subvols
}

/// Check if a UUID is non-zero (i.e., has been set).
fn uuid_is_set(uuid: &[u8; 16]) -> bool {
    uuid.iter().any(|&b| b != 0)
}

/// Enumerate snapshots from root tree leaf entries.
///
/// A snapshot is a subvolume whose `parent_uuid` is non-zero, indicating
/// it was created as a snapshot of another subvolume.
#[must_use]
pub fn enumerate_snapshots(entries: &[BtrfsLeafEntry]) -> Vec<BtrfsSnapshot> {
    let mut snapshots = Vec::new();

    // First pass: collect all ROOT_ITEM entries with parent_uuid set
    for entry in entries {
        if entry.key.item_type != BTRFS_ITEM_ROOT_ITEM {
            continue;
        }
        let id = entry.key.objectid;
        if id < BTRFS_FIRST_FREE_OBJECTID {
            continue;
        }
        let Ok(root) = parse_root_item(&entry.data) else {
            continue;
        };
        if !uuid_is_set(&root.parent_uuid) {
            continue;
        }

        // Find the source subvolume by matching parent_uuid to uuid
        let source_id = entries
            .iter()
            .find_map(|e| {
                if e.key.item_type != BTRFS_ITEM_ROOT_ITEM {
                    return None;
                }
                let src = parse_root_item(&e.data).ok()?;
                if src.uuid == root.parent_uuid {
                    Some(e.key.objectid)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // Find matching ROOT_REF for the snapshot name
        let name = entries
            .iter()
            .find_map(|e| {
                if e.key.item_type == BTRFS_ITEM_ROOT_REF && e.key.offset == id {
                    let rref = parse_root_ref(&e.data).ok()?;
                    Some(String::from_utf8_lossy(&rref.name).into_owned())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| format!("snap-{id}"));

        snapshots.push(BtrfsSnapshot {
            id,
            source_id,
            name,
            generation: root.generation,
            uuid: root.uuid,
            parent_uuid: root.parent_uuid,
            bytenr: root.bytenr,
            level: root.level,
        });
    }

    snapshots
}

/// Compute a generation-based diff between two sets of tree leaf entries.
///
/// Compares inode items by objectid. An inode is:
/// - **Added** if it exists in `newer` but not `older`.
/// - **Deleted** if it exists in `older` but not `newer`.
/// - **Modified** if it exists in both but the `newer` entry has a higher
///   generation in its inode item.
///
/// This is a simplified diff that does NOT produce full paths — it
/// operates on inode objectids only.
#[must_use]
pub fn snapshot_diff_by_generation(
    older_entries: &[BtrfsLeafEntry],
    newer_entries: &[BtrfsLeafEntry],
) -> Vec<SnapshotDiffEntry> {
    use std::collections::BTreeMap;

    // Collect inode items (type 1) by objectid with generation
    let collect_inodes = |entries: &[BtrfsLeafEntry]| -> BTreeMap<u64, u64> {
        entries
            .iter()
            .filter(|e| e.key.item_type == BTRFS_ITEM_INODE_ITEM)
            .filter_map(|e| {
                let inode = parse_inode_item(&e.data).ok()?;
                Some((e.key.objectid, inode.generation))
            })
            .collect()
    };

    let old_inodes = collect_inodes(older_entries);
    let new_inodes = collect_inodes(newer_entries);
    let mut diffs = Vec::new();

    // Deleted: in old but not in new
    for &oid in old_inodes.keys() {
        if !new_inodes.contains_key(&oid) {
            diffs.push(SnapshotDiffEntry {
                inode: oid,
                change_type: SnapshotChangeType::Deleted,
            });
        }
    }

    // Added or Modified
    for (&oid, &new_gen) in &new_inodes {
        match old_inodes.get(&oid) {
            None => {
                diffs.push(SnapshotDiffEntry {
                    inode: oid,
                    change_type: SnapshotChangeType::Added,
                });
            }
            Some(&old_gen) if new_gen > old_gen => {
                diffs.push(SnapshotDiffEntry {
                    inode: oid,
                    change_type: SnapshotChangeType::Modified,
                });
            }
            _ => {}
        }
    }

    diffs.sort_by_key(|d| d.inode);
    diffs
}

/// Parse the subset of `btrfs_inode_item` needed for read-only VFS operations.
pub fn parse_inode_item(data: &[u8]) -> Result<BtrfsInodeItem, ParseError> {
    const INODE_ITEM_SIZE: usize = 160;
    const NANOS_PER_SECOND: u32 = 1_000_000_000;

    if data.len() < INODE_ITEM_SIZE {
        return Err(ParseError::InsufficientData {
            needed: INODE_ITEM_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }
    if data.len() > INODE_ITEM_SIZE {
        return Err(ParseError::InvalidField {
            field: "inode_item.size",
            reason: "does not match fixed inode item size",
        });
    }

    let atime_nsec = read_u32(data, 120, "inode_item.atime_nsec")?;
    let ctime_nsec = read_u32(data, 132, "inode_item.ctime_nsec")?;
    let mtime_nsec = read_u32(data, 144, "inode_item.mtime_nsec")?;
    let otime_nsec = read_u32(data, 156, "inode_item.otime_nsec")?;
    for (field, nsec) in [
        ("inode_item.atime_nsec", atime_nsec),
        ("inode_item.ctime_nsec", ctime_nsec),
        ("inode_item.mtime_nsec", mtime_nsec),
        ("inode_item.otime_nsec", otime_nsec),
    ] {
        if nsec >= NANOS_PER_SECOND {
            return Err(ParseError::InvalidField {
                field,
                reason: "must be less than 1_000_000_000",
            });
        }
    }

    Ok(BtrfsInodeItem {
        generation: read_u64(data, 0, "inode_item.generation")?,
        size: read_u64(data, 16, "inode_item.size")?,
        nbytes: read_u64(data, 24, "inode_item.nbytes")?,
        nlink: read_u32(data, 40, "inode_item.nlink")?,
        uid: read_u32(data, 44, "inode_item.uid")?,
        gid: read_u32(data, 48, "inode_item.gid")?,
        mode: read_u32(data, 52, "inode_item.mode")?,
        rdev: read_u64(data, 56, "inode_item.rdev")?,
        atime_sec: read_u64(data, 112, "inode_item.atime_sec")?,
        atime_nsec,
        ctime_sec: read_u64(data, 124, "inode_item.ctime_sec")?,
        ctime_nsec,
        mtime_sec: read_u64(data, 136, "inode_item.mtime_sec")?,
        mtime_nsec,
        otime_sec: read_u64(data, 148, "inode_item.otime_sec")?,
        otime_nsec,
    })
}

/// Parse one or more directory entries from a DIR_ITEM or DIR_INDEX payload.
pub fn parse_dir_items(data: &[u8]) -> Result<Vec<BtrfsDirItem>, ParseError> {
    const HEADER: usize = 30; // disk_key(17) + transid(8) + data_len(2) + name_len(2) + type(1)

    let mut out = Vec::new();
    let mut cur = 0_usize;
    while cur < data.len() {
        if cur + HEADER > data.len() {
            return Err(ParseError::InsufficientData {
                needed: HEADER,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let child_objectid = read_u64(data, cur, "dir_item.location.objectid")?;
        let child_key_type = data[cur + 8];
        let child_key_offset = read_u64(data, cur + 9, "dir_item.location.offset")?;
        // transid at +17..+25 (currently unused in VFS path)
        let _transid = read_u64(data, cur + 17, "dir_item.transid")?;
        let data_len = usize::from(read_u16(data, cur + 25, "dir_item.data_len")?);
        let name_len = usize::from(read_u16(data, cur + 27, "dir_item.name_len")?);
        let file_type = data[cur + 29];
        if name_len == 0 {
            return Err(ParseError::InvalidField {
                field: "dir_item.name_len",
                reason: "must be non-zero",
            });
        }
        if data_len != 0 {
            return Err(ParseError::InvalidField {
                field: "dir_item.data_len",
                reason: "must be zero for directory entries",
            });
        }

        let name_start = cur + HEADER;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(ParseError::InvalidField {
                field: "dir_item.name_len",
                reason: "overflow",
            })?;

        if name_end > data.len() {
            return Err(ParseError::InsufficientData {
                needed: name_end,
                offset: cur,
                actual: data.len(),
            });
        }

        out.push(BtrfsDirItem {
            child_objectid,
            child_key_type,
            child_key_offset,
            file_type,
            name: data[name_start..name_end].to_vec(),
        });

        cur = name_end;
    }

    Ok(out)
}

/// Parse an EXTENT_DATA payload for regular or inline extents.
pub fn parse_extent_data(data: &[u8]) -> Result<BtrfsExtentData, ParseError> {
    const FIXED: usize = 21; // generation(8) + ram_bytes(8) + compression(1) + encryption(1) + other_encoding(2) + type(1)
    const REGULAR_SIZE: usize = FIXED + 32; // disk_bytenr + disk_num_bytes + extent_offset + num_bytes

    if data.len() < FIXED {
        return Err(ParseError::InsufficientData {
            needed: FIXED,
            offset: 0,
            actual: data.len(),
        });
    }

    let generation = read_u64(data, 0, "extent_data.generation")?;
    let ram_bytes = read_u64(data, 8, "extent_data.ram_bytes")?;
    let compression = data[16];
    let encryption = data[17];
    let other_encoding = read_u16(data, 18, "extent_data.other_encoding")?;
    let extent_type = data[20];
    if !matches!(
        compression,
        BTRFS_COMPRESS_NONE | BTRFS_COMPRESS_ZLIB | BTRFS_COMPRESS_LZO | BTRFS_COMPRESS_ZSTD
    ) {
        return Err(ParseError::InvalidField {
            field: "extent_data.compression",
            reason: "unsupported compression",
        });
    }
    if encryption != 0 {
        return Err(ParseError::InvalidField {
            field: "extent_data.encryption",
            reason: "unsupported encryption",
        });
    }
    if other_encoding != 0 {
        return Err(ParseError::InvalidField {
            field: "extent_data.other_encoding",
            reason: "unsupported other encoding",
        });
    }
    match extent_type {
        BTRFS_FILE_EXTENT_INLINE => {
            parse_inline_extent_data(generation, ram_bytes, compression, &data[FIXED..])
        }
        BTRFS_FILE_EXTENT_REG | BTRFS_FILE_EXTENT_PREALLOC => {
            // disk_bytenr + disk_num_bytes + extent_offset + num_bytes
            if data.len() < REGULAR_SIZE {
                return Err(ParseError::InsufficientData {
                    needed: REGULAR_SIZE,
                    offset: 0,
                    actual: data.len(),
                });
            }
            if data.len() > REGULAR_SIZE {
                return Err(ParseError::InvalidField {
                    field: "extent_data.length",
                    reason: "trailing bytes after fixed extent payload",
                });
            }
            let disk_bytenr = read_u64(data, 21, "extent_data.disk_bytenr")?;
            let disk_num_bytes = read_u64(data, 29, "extent_data.disk_num_bytes")?;
            let extent_offset = read_u64(data, 37, "extent_data.offset")?;
            let num_bytes = read_u64(data, 45, "extent_data.num_bytes")?;

            // Validate source-slice arithmetic for extents that read from
            // backing bytes. Compressed extents slice the decompressed
            // `ram_bytes` payload, while uncompressed extents address
            // `disk_num_bytes` bytes from `disk_bytenr`.
            if compression != BTRFS_COMPRESS_NONE || disk_bytenr != 0 {
                let extent_end =
                    extent_offset
                        .checked_add(num_bytes)
                        .ok_or(ParseError::InvalidField {
                            field: "extent_data.extent_offset+num_bytes",
                            reason: "source slice arithmetic overflow",
                        })?;
                if compression != BTRFS_COMPRESS_NONE && extent_end > ram_bytes {
                    return Err(ParseError::InvalidField {
                        field: "extent_data.extent_offset+num_bytes",
                        reason: "source slice exceeds ram_bytes",
                    });
                }
                if compression == BTRFS_COMPRESS_NONE && extent_end > disk_num_bytes {
                    return Err(ParseError::InvalidField {
                        field: "extent_data.extent_offset+num_bytes",
                        reason: "source slice exceeds disk_num_bytes",
                    });
                }
            }

            Ok(BtrfsExtentData::Regular {
                generation,
                ram_bytes,
                extent_type,
                compression,
                disk_bytenr,
                disk_num_bytes,
                extent_offset,
                num_bytes,
            })
        }
        _ => Err(ParseError::InvalidField {
            field: "extent_data.type",
            reason: "unsupported extent type",
        }),
    }
}

fn parse_inline_extent_data(
    generation: u64,
    ram_bytes: u64,
    compression: u8,
    inline_data: &[u8],
) -> Result<BtrfsExtentData, ParseError> {
    validate_inline_extent_ram_bytes(compression, inline_data.len(), ram_bytes)?;
    Ok(BtrfsExtentData::Inline {
        generation,
        ram_bytes,
        compression,
        data: inline_data.to_vec(),
    })
}

fn validate_inline_extent_ram_bytes(
    compression: u8,
    inline_len: usize,
    ram_bytes: u64,
) -> Result<(), ParseError> {
    if compression != BTRFS_COMPRESS_NONE {
        return Ok(());
    }
    let inline_len = u64::try_from(inline_len).map_err(|_| ParseError::InvalidField {
        field: "extent_data.inline_len",
        reason: "does not fit u64",
    })?;
    if inline_len != ram_bytes {
        return Err(ParseError::InvalidField {
            field: "extent_data.ram_bytes",
            reason: "uncompressed inline length mismatch",
        });
    }
    Ok(())
}

/// Walk a btrfs tree from `root_logical` down to all leaves, collecting items.
///
/// `read_physical` reads `nodesize` bytes at the given physical byte offset.
/// `chunks` provides the logical→physical address mapping.
///
/// Returns all leaf items in key order (left-to-right DFS).
/// The traversal is bounded: it rejects levels > 7 and validates nritems
/// against block capacity at each node.
pub fn walk_tree(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    chunks: &[BtrfsChunkEntry],
    root_logical: u64,
    nodesize: u32,
    csum_type: u16,
) -> Result<Vec<BtrfsLeafEntry>, ParseError> {
    let mut walker = BtrfsTreeWalker {
        read_physical,
        chunks,
        nodesize,
        csum_type,
        out: Vec::new(),
        active_path: HashSet::new(),
        visited_nodes: HashSet::new(),
    };
    walker.walk_node(root_logical)?;
    Ok(walker.out)
}

struct BtrfsTreeWalker<'a> {
    read_physical: &'a mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    chunks: &'a [BtrfsChunkEntry],
    nodesize: u32,
    csum_type: u16,
    out: Vec<BtrfsLeafEntry>,
    active_path: HashSet<u64>,
    visited_nodes: HashSet<u64>,
}

impl BtrfsTreeWalker<'_> {
    fn walk_node(&mut self, logical: u64) -> Result<(), ParseError> {
        let nodesize_u64 = u64::from(self.nodesize);
        if nodesize_u64 == 0 {
            return Err(ParseError::InvalidField {
                field: "nodesize",
                reason: "zero nodesize",
            });
        }
        if logical % nodesize_u64 != 0 {
            return Err(ParseError::InvalidField {
                field: "logical_address",
                reason: "not aligned to nodesize",
            });
        }
        if !self.active_path.insert(logical) {
            return Err(ParseError::InvalidField {
                field: "logical_address",
                reason: "cycle detected in btrfs tree pointers",
            });
        }
        if !self.visited_nodes.insert(logical) {
            return Err(ParseError::InvalidField {
                field: "logical_address",
                reason: "duplicate node reference in btrfs tree pointers",
            });
        }

        let mapping =
            map_logical_to_physical(self.chunks, logical)?.ok_or(ParseError::InvalidField {
                field: "logical_address",
                reason: "not covered by any chunk",
            })?;

        let block = (self.read_physical)(mapping.physical)?;
        let ns = usize::try_from(self.nodesize)
            .map_err(|_| ParseError::IntegerConversion { field: "nodesize" })?;
        if block.len() != ns {
            return Err(ParseError::InsufficientData {
                needed: ns,
                offset: 0,
                actual: block.len(),
            });
        }

        // Verify checksum before parsing.
        ffs_ondisk::verify_btrfs_tree_block_checksum(&block, self.csum_type)?;

        let header = BtrfsHeader::parse_from_block(&block)?;
        header.validate(block.len(), Some(logical))?;

        if header.level == 0 {
            collect_leaf_items(&block, &mut self.out)?;
        } else {
            let (_, ptrs) = parse_internal_items(&block)?;
            for kp in &ptrs {
                if kp.blockptr % nodesize_u64 != 0 {
                    return Err(ParseError::InvalidField {
                        field: "blockptr",
                        reason: "not aligned to nodesize",
                    });
                }
                self.walk_node(kp.blockptr)?;
            }
        }

        self.active_path.remove(&logical);
        Ok(())
    }
}

fn collect_leaf_items(block: &[u8], out: &mut Vec<BtrfsLeafEntry>) -> Result<(), ParseError> {
    let (_, items) = parse_leaf_items(block)?;
    for item in &items {
        let off = usize::try_from(item.data_offset).map_err(|_| ParseError::IntegerConversion {
            field: "data_offset",
        })?;
        let sz = usize::try_from(item.data_size)
            .map_err(|_| ParseError::IntegerConversion { field: "data_size" })?;
        let end = off.checked_add(sz).ok_or(ParseError::InvalidField {
            field: "data_offset",
            reason: "overflow",
        })?;
        if end > block.len() {
            return Err(ParseError::InvalidField {
                field: "data_offset",
                reason: "item data extends past block",
            });
        }
        out.push(BtrfsLeafEntry {
            key: item.key,
            data: block[off..end].to_vec(),
        });
    }
    Ok(())
}

fn key_cmp(lhs: &BtrfsKey, rhs: &BtrfsKey) -> Ordering {
    lhs.objectid
        .cmp(&rhs.objectid)
        .then_with(|| lhs.item_type.cmp(&rhs.item_type))
        .then_with(|| lhs.offset.cmp(&rhs.offset))
}

/// Errors returned by in-memory btrfs COW tree mutation APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsMutationError {
    InvalidConfig(&'static str),
    InvalidRange,
    KeyAlreadyExists,
    KeyNotFound,
    MissingNode(u64),
    BrokenInvariant(&'static str),
    AddressOverflow,
}

impl std::fmt::Display for BtrfsMutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Self::InvalidRange => write!(f, "invalid key range"),
            Self::KeyAlreadyExists => write!(f, "key already exists"),
            Self::KeyNotFound => write!(f, "key not found"),
            Self::MissingNode(block) => write!(f, "missing tree node {block}"),
            Self::BrokenInvariant(msg) => write!(f, "broken invariant: {msg}"),
            Self::AddressOverflow => write!(f, "address overflow"),
        }
    }
}

/// Key/value payload stored in leaf nodes for the in-memory COW model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsTreeItem {
    pub key: BtrfsKey,
    pub data: Vec<u8>,
}

/// In-memory btrfs B-tree node model used for mutation planning and testing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtrfsCowNode {
    Leaf {
        items: Vec<BtrfsTreeItem>,
    },
    Internal {
        keys: Vec<BtrfsKey>,
        children: Vec<u64>,
    },
}

/// Block lifecycle interface for btrfs COW mutation planning.
///
/// The in-memory tree uses this to allocate new node addresses and to
/// report nodes that became unreachable after a successful mutation.
pub trait BtrfsAllocator: std::fmt::Debug + Send + Sync {
    fn alloc_block(&mut self) -> Result<u64, BtrfsMutationError>;
    fn defer_free(&mut self, block: u64);
}

/// Default in-memory allocator used by `InMemoryCowBtrfsTree`.
#[derive(Debug, Clone, Default)]
pub struct InMemoryBtrfsAllocator {
    next_block: u64,
    deferred: Vec<u64>,
}

impl InMemoryBtrfsAllocator {
    #[must_use]
    pub fn with_start(next_block: u64) -> Self {
        Self {
            next_block,
            deferred: Vec::new(),
        }
    }
}

impl BtrfsAllocator for InMemoryBtrfsAllocator {
    fn alloc_block(&mut self) -> Result<u64, BtrfsMutationError> {
        let block = self.next_block;
        self.next_block = self
            .next_block
            .checked_add(1)
            .ok_or(BtrfsMutationError::AddressOverflow)?;
        Ok(block)
    }

    fn defer_free(&mut self, block: u64) {
        self.deferred.push(block);
    }
}

/// COW B-tree mutation interface used by write-path planning code.
pub trait BtrfsBTree {
    fn insert(&mut self, key: BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError>;
    fn delete(&mut self, key: &BtrfsKey) -> Result<u64, BtrfsMutationError>;
    fn update(&mut self, key: &BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError>;
    fn range(
        &self,
        start: &BtrfsKey,
        end: &BtrfsKey,
    ) -> Result<Vec<(BtrfsKey, Vec<u8>)>, BtrfsMutationError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InsertResult {
    node_id: u64,
    split: Option<(BtrfsKey, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeleteResult {
    node_id: u64,
    deleted: bool,
}

/// In-memory COW btrfs B-tree. Every mutation allocates new nodes and advances
/// the root pointer, keeping previously-addressed nodes immutable.
#[derive(Debug)]
pub struct InMemoryCowBtrfsTree {
    max_items: usize,
    min_items: usize,
    root: u64,
    allocator: Box<dyn BtrfsAllocator>,
    deferred_frees: Vec<u64>,
    staged_allocations: Vec<u64>,
    staged_deferred_frees: Vec<u64>,
    nodes: BTreeMap<u64, BtrfsCowNode>,
}

impl InMemoryCowBtrfsTree {
    /// Create a COW B-tree with the requested maximum keys/items per node.
    ///
    /// `max_items` must be >= 3 to allow split/merge behavior.
    pub fn new(max_items: usize) -> Result<Self, BtrfsMutationError> {
        Self::with_allocator(max_items, Box::new(InMemoryBtrfsAllocator::with_start(2)))
    }

    /// Create a COW B-tree with a custom block allocator.
    pub fn with_allocator(
        max_items: usize,
        allocator: Box<dyn BtrfsAllocator>,
    ) -> Result<Self, BtrfsMutationError> {
        if max_items < 3 {
            return Err(BtrfsMutationError::InvalidConfig("max_items must be >= 3"));
        }
        let root = 1_u64;
        let mut nodes = BTreeMap::new();
        nodes.insert(root, BtrfsCowNode::Leaf { items: Vec::new() });
        Ok(Self {
            max_items,
            min_items: max_items / 2,
            root,
            allocator,
            deferred_frees: Vec::new(),
            staged_allocations: Vec::new(),
            staged_deferred_frees: Vec::new(),
            nodes,
        })
    }

    /// Current root block identifier.
    #[must_use]
    pub fn root_block(&self) -> u64 {
        self.root
    }

    /// Snapshot a node by block number.
    pub fn node_snapshot(&self, block: u64) -> Result<BtrfsCowNode, BtrfsMutationError> {
        self.nodes
            .get(&block)
            .cloned()
            .ok_or(BtrfsMutationError::MissingNode(block))
    }

    /// List of blocks marked for deferred free during successful mutations.
    #[must_use]
    pub fn deferred_free_blocks(&self) -> &[u64] {
        &self.deferred_frees
    }

    /// Return tree height (`1` for a leaf root).
    pub fn height(&self) -> Result<usize, BtrfsMutationError> {
        self.height_of(self.root)
    }

    /// Validate structure invariants:
    /// - key ordering
    /// - child count relationships
    /// - balanced depth
    /// - node occupancy for non-root nodes
    pub fn validate_invariants(&self) -> Result<(), BtrfsMutationError> {
        let mut leaf_depth = None;
        self.validate_node(self.root, None, None, 1, &mut leaf_depth, true)?;
        Ok(())
    }

    fn node_ref(&self, block: u64) -> Result<&BtrfsCowNode, BtrfsMutationError> {
        self.nodes
            .get(&block)
            .ok_or(BtrfsMutationError::MissingNode(block))
    }

    fn alloc_node(&mut self, node: BtrfsCowNode) -> Result<u64, BtrfsMutationError> {
        let block = self.allocator.alloc_block()?;
        self.nodes.insert(block, node);
        self.staged_allocations.push(block);
        trace!(block, "btrfs_cow_alloc_node");
        Ok(block)
    }

    fn retire_node(&mut self, block: u64) {
        self.staged_deferred_frees.push(block);
        trace!(block, "btrfs_cow_defer_free");
    }

    fn commit_retired_nodes(&mut self) {
        for block in self.staged_deferred_frees.drain(..) {
            self.allocator.defer_free(block);
            self.deferred_frees.push(block);
        }
    }

    fn commit_allocated_nodes(&mut self) {
        self.staged_allocations.clear();
    }

    fn discard_retired_nodes(&mut self) {
        self.staged_deferred_frees.clear();
    }

    fn rollback_allocated_nodes(&mut self) {
        for block in self.staged_allocations.drain(..).rev() {
            self.nodes.remove(&block);
            self.allocator.defer_free(block);
            trace!(block, "btrfs_cow_rollback_alloc");
        }
    }

    fn rollback_mutation(&mut self) {
        self.discard_retired_nodes();
        self.rollback_allocated_nodes();
    }

    fn child_slot(keys: &[BtrfsKey], key: &BtrfsKey) -> usize {
        keys.iter()
            .position(|sep| key_cmp(key, sep) == Ordering::Less)
            .unwrap_or(keys.len())
    }

    fn insert_entry(
        &mut self,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<u64, BtrfsMutationError> {
        debug_assert!(self.staged_allocations.is_empty());
        debug_assert!(self.staged_deferred_frees.is_empty());
        let old_root = self.root;
        trace!(
            root = old_root,
            objectid = entry.key.objectid,
            item_type = entry.key.item_type,
            offset = entry.key.offset,
            allow_replace,
            "btrfs_cow_insert_start"
        );
        let result = match self.insert_into(self.root, entry, allow_replace) {
            Ok(result) => result,
            Err(err) => {
                self.rollback_mutation();
                return Err(err);
            }
        };
        let new_root = if let Some((separator, right_id)) = result.split {
            debug!(
                old_root,
                left_root = result.node_id,
                right_root = right_id,
                separator_objectid = separator.objectid,
                separator_type = separator.item_type,
                separator_offset = separator.offset,
                "btrfs_cow_root_split"
            );
            match self.alloc_node(BtrfsCowNode::Internal {
                keys: vec![separator],
                children: vec![result.node_id, right_id],
            }) {
                Ok(new_root) => new_root,
                Err(err) => {
                    self.rollback_mutation();
                    return Err(err);
                }
            }
        } else {
            result.node_id
        };
        self.root = new_root;
        self.commit_allocated_nodes();
        self.commit_retired_nodes();
        trace!(old_root, new_root = self.root, "btrfs_cow_insert_complete");
        Ok(self.root)
    }

    fn insert_into(
        &mut self,
        node_id: u64,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<InsertResult, BtrfsMutationError> {
        let node = self.node_ref(node_id)?.clone();
        let result = match node {
            BtrfsCowNode::Leaf { items } => self.insert_into_leaf(items, entry, allow_replace),
            BtrfsCowNode::Internal { keys, children } => {
                self.insert_into_internal(keys, children, entry, allow_replace)
            }
        };
        if result.is_ok() {
            self.retire_node(node_id);
        }
        result
    }

    fn insert_into_leaf(
        &mut self,
        mut items: Vec<BtrfsTreeItem>,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<InsertResult, BtrfsMutationError> {
        let idx = items.partition_point(|existing| key_cmp(&existing.key, &entry.key).is_lt());
        if let Some(existing) = items.get_mut(idx)
            && key_cmp(&existing.key, &entry.key) == Ordering::Equal
        {
            if allow_replace {
                trace!(
                    objectid = entry.key.objectid,
                    item_type = entry.key.item_type,
                    offset = entry.key.offset,
                    "btrfs_cow_update_leaf"
                );
                existing.data = entry.data;
                let new_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
                return Ok(InsertResult {
                    node_id: new_id,
                    split: None,
                });
            }
            return Err(BtrfsMutationError::KeyAlreadyExists);
        }

        items.insert(idx, entry);
        if items.len() <= self.max_items {
            let new_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
            return Ok(InsertResult {
                node_id: new_id,
                split: None,
            });
        }

        let mid = items.len() / 2;
        let right_items = items.split_off(mid);
        let separator =
            right_items
                .first()
                .map(|item| item.key)
                .ok_or(BtrfsMutationError::BrokenInvariant(
                    "right split leaf must not be empty",
                ))?;
        debug!(
            separator_objectid = separator.objectid,
            separator_type = separator.item_type,
            separator_offset = separator.offset,
            left_items = items.len(),
            right_items = right_items.len(),
            "btrfs_cow_leaf_split"
        );
        let left_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
        let right_id = self.alloc_node(BtrfsCowNode::Leaf { items: right_items })?;
        Ok(InsertResult {
            node_id: left_id,
            split: Some((separator, right_id)),
        })
    }

    fn insert_into_internal(
        &mut self,
        mut keys: Vec<BtrfsKey>,
        mut children: Vec<u64>,
        entry: BtrfsTreeItem,
        allow_replace: bool,
    ) -> Result<InsertResult, BtrfsMutationError> {
        if children.len() != keys.len().saturating_add(1) {
            return Err(BtrfsMutationError::BrokenInvariant(
                "internal node child count mismatch",
            ));
        }

        let idx = Self::child_slot(&keys, &entry.key);
        let child_result = self.insert_into(children[idx], entry, allow_replace)?;
        children[idx] = child_result.node_id;
        if let Some((separator, right_child)) = child_result.split {
            keys.insert(idx, separator);
            children.insert(idx + 1, right_child);
        }

        if keys.len() <= self.max_items {
            let new_id = self.alloc_node(BtrfsCowNode::Internal { keys, children })?;
            return Ok(InsertResult {
                node_id: new_id,
                split: None,
            });
        }

        let mid = keys.len() / 2;
        let separator = keys[mid];
        let right_keys = keys.split_off(mid + 1);
        let removed = keys.pop();
        if removed.is_none() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "internal split separator missing",
            ));
        }
        let right_children = children.split_off(mid + 1);
        debug!(
            separator_objectid = separator.objectid,
            separator_type = separator.item_type,
            separator_offset = separator.offset,
            left_keys = keys.len(),
            right_keys = right_keys.len(),
            "btrfs_cow_internal_split"
        );
        let left_id = self.alloc_node(BtrfsCowNode::Internal { keys, children })?;
        let right_id = self.alloc_node(BtrfsCowNode::Internal {
            keys: right_keys,
            children: right_children,
        })?;
        Ok(InsertResult {
            node_id: left_id,
            split: Some((separator, right_id)),
        })
    }

    fn first_key(&self, node_id: u64) -> Result<Option<BtrfsKey>, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => Ok(items.first().map(|item| item.key)),
            BtrfsCowNode::Internal { children, .. } => {
                let Some(first_child) = children.first() else {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node must have children",
                    ));
                };
                self.first_key(*first_child)
            }
        }
    }

    fn compute_internal_keys(&self, children: &[u64]) -> Result<Vec<BtrfsKey>, BtrfsMutationError> {
        if children.is_empty() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "internal node must have children",
            ));
        }
        let mut keys = Vec::with_capacity(children.len().saturating_sub(1));
        for child in children.iter().skip(1) {
            let Some(separator) = self.first_key(*child)? else {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "internal separator child must contain a key",
                ));
            };
            keys.push(separator);
        }
        Ok(keys)
    }

    fn alloc_internal_node(&mut self, children: Vec<u64>) -> Result<u64, BtrfsMutationError> {
        let keys = self.compute_internal_keys(&children)?;
        self.alloc_node(BtrfsCowNode::Internal { keys, children })
    }

    fn node_key_count(&self, node_id: u64) -> Result<usize, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => Ok(items.len()),
            BtrfsCowNode::Internal { keys, .. } => Ok(keys.len()),
        }
    }

    fn rotate_from_left(
        &mut self,
        left_id: u64,
        right_id: u64,
    ) -> Result<(u64, u64), BtrfsMutationError> {
        let left_node = self.node_ref(left_id)?.clone();
        let right_node = self.node_ref(right_id)?.clone();
        match (left_node, right_node) {
            (
                BtrfsCowNode::Leaf {
                    items: mut left_items,
                },
                BtrfsCowNode::Leaf {
                    items: mut right_items,
                },
            ) => {
                let moved = left_items.pop().ok_or(BtrfsMutationError::BrokenInvariant(
                    "cannot borrow from empty left leaf",
                ))?;
                right_items.insert(0, moved);
                let new_left = self.alloc_node(BtrfsCowNode::Leaf { items: left_items })?;
                let new_right = self.alloc_node(BtrfsCowNode::Leaf { items: right_items })?;
                Ok((new_left, new_right))
            }
            (
                BtrfsCowNode::Internal {
                    children: mut left_children,
                    ..
                },
                BtrfsCowNode::Internal {
                    children: mut right_children,
                    ..
                },
            ) => {
                let moved = left_children
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty left internal",
                    ))?;
                right_children.insert(0, moved);
                let new_left = self.alloc_internal_node(left_children)?;
                let new_right = self.alloc_internal_node(right_children)?;
                Ok((new_left, new_right))
            }
            _ => Err(BtrfsMutationError::BrokenInvariant(
                "sibling node type mismatch",
            )),
        }
    }

    fn rotate_from_right(
        &mut self,
        left_id: u64,
        right_id: u64,
    ) -> Result<(u64, u64), BtrfsMutationError> {
        let left_node = self.node_ref(left_id)?.clone();
        let right_node = self.node_ref(right_id)?.clone();
        match (left_node, right_node) {
            (
                BtrfsCowNode::Leaf {
                    items: mut left_items,
                },
                BtrfsCowNode::Leaf {
                    items: mut right_items,
                },
            ) => {
                if right_items.is_empty() {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right leaf",
                    ));
                }
                right_items.rotate_left(1);
                let moved = right_items
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right leaf",
                    ))?;
                left_items.push(moved);
                let new_left = self.alloc_node(BtrfsCowNode::Leaf { items: left_items })?;
                let new_right = self.alloc_node(BtrfsCowNode::Leaf { items: right_items })?;
                Ok((new_left, new_right))
            }
            (
                BtrfsCowNode::Internal {
                    children: mut left_children,
                    ..
                },
                BtrfsCowNode::Internal {
                    children: mut right_children,
                    ..
                },
            ) => {
                if right_children.is_empty() {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right internal",
                    ));
                }
                right_children.rotate_left(1);
                let moved = right_children
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "cannot borrow from empty right internal",
                    ))?;
                left_children.push(moved);
                let new_left = self.alloc_internal_node(left_children)?;
                let new_right = self.alloc_internal_node(right_children)?;
                Ok((new_left, new_right))
            }
            _ => Err(BtrfsMutationError::BrokenInvariant(
                "sibling node type mismatch",
            )),
        }
    }

    fn merge_adjacent_nodes(
        &mut self,
        left_id: u64,
        right_id: u64,
    ) -> Result<u64, BtrfsMutationError> {
        let left_node = self.node_ref(left_id)?.clone();
        let right_node = self.node_ref(right_id)?.clone();
        match (left_node, right_node) {
            (
                BtrfsCowNode::Leaf {
                    items: mut left_items,
                },
                BtrfsCowNode::Leaf { items: right_items },
            ) => {
                left_items.extend(right_items);
                self.alloc_node(BtrfsCowNode::Leaf { items: left_items })
            }
            (
                BtrfsCowNode::Internal {
                    children: mut left_children,
                    ..
                },
                BtrfsCowNode::Internal {
                    children: right_children,
                    ..
                },
            ) => {
                left_children.extend(right_children);
                self.alloc_internal_node(left_children)
            }
            _ => Err(BtrfsMutationError::BrokenInvariant(
                "cannot merge different node types",
            )),
        }
    }

    fn rebalance_child(
        &mut self,
        children: &mut Vec<u64>,
        child_idx: usize,
    ) -> Result<(), BtrfsMutationError> {
        if child_idx >= children.len() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "child index out of bounds",
            ));
        }
        if children.len() <= 1 {
            return Ok(());
        }

        let child_keys = self.node_key_count(children[child_idx])?;
        if child_keys >= self.min_items {
            return Ok(());
        }

        if child_idx > 0 {
            let left_keys = self.node_key_count(children[child_idx - 1])?;
            if left_keys > self.min_items {
                let old_left = children[child_idx - 1];
                let old_child = children[child_idx];
                let (new_left, new_child) =
                    self.rotate_from_left(children[child_idx - 1], children[child_idx])?;
                children[child_idx - 1] = new_left;
                children[child_idx] = new_child;
                self.retire_node(old_left);
                self.retire_node(old_child);
                debug!(
                    child_idx,
                    left_keys, child_keys, "btrfs_cow_delete_borrow_left"
                );
                return Ok(());
            }
        }

        if child_idx + 1 < children.len() {
            let right_keys = self.node_key_count(children[child_idx + 1])?;
            if right_keys > self.min_items {
                let old_child = children[child_idx];
                let old_right = children[child_idx + 1];
                let (new_child, new_right) =
                    self.rotate_from_right(children[child_idx], children[child_idx + 1])?;
                children[child_idx] = new_child;
                children[child_idx + 1] = new_right;
                self.retire_node(old_child);
                self.retire_node(old_right);
                debug!(
                    child_idx,
                    right_keys, child_keys, "btrfs_cow_delete_borrow_right"
                );
                return Ok(());
            }
        }

        if child_idx > 0 {
            let old_left = children[child_idx - 1];
            let old_child = children[child_idx];
            let merged = self.merge_adjacent_nodes(children[child_idx - 1], children[child_idx])?;
            children[child_idx - 1] = merged;
            children.remove(child_idx);
            self.retire_node(old_left);
            self.retire_node(old_child);
            debug!(merged_child = child_idx - 1, "btrfs_cow_delete_merge_left");
        } else {
            let old_child = children[child_idx];
            let old_right = children[child_idx + 1];
            let merged = self.merge_adjacent_nodes(children[child_idx], children[child_idx + 1])?;
            children[child_idx] = merged;
            children.remove(child_idx + 1);
            self.retire_node(old_child);
            self.retire_node(old_right);
            debug!(merged_child = child_idx, "btrfs_cow_delete_merge_right");
        }
        Ok(())
    }

    fn delete_from(
        &mut self,
        node_id: u64,
        key: &BtrfsKey,
    ) -> Result<DeleteResult, BtrfsMutationError> {
        let node = self.node_ref(node_id)?.clone();
        match node {
            BtrfsCowNode::Leaf { mut items } => {
                let idx = items.partition_point(|existing| key_cmp(&existing.key, key).is_lt());
                let Some(existing) = items.get(idx) else {
                    return Ok(DeleteResult {
                        node_id,
                        deleted: false,
                    });
                };
                if key_cmp(&existing.key, key) != Ordering::Equal {
                    return Ok(DeleteResult {
                        node_id,
                        deleted: false,
                    });
                }
                items.remove(idx);
                let new_id = self.alloc_node(BtrfsCowNode::Leaf { items })?;
                self.retire_node(node_id);
                Ok(DeleteResult {
                    node_id: new_id,
                    deleted: true,
                })
            }
            BtrfsCowNode::Internal { keys, mut children } => {
                if children.len() != keys.len().saturating_add(1) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node child count mismatch",
                    ));
                }
                let idx = Self::child_slot(&keys, key);
                let child_result = self.delete_from(children[idx], key)?;
                if !child_result.deleted {
                    return Ok(DeleteResult {
                        node_id,
                        deleted: false,
                    });
                }
                children[idx] = child_result.node_id;
                self.rebalance_child(&mut children, idx)?;
                let new_id = self.alloc_internal_node(children)?;
                self.retire_node(node_id);
                Ok(DeleteResult {
                    node_id: new_id,
                    deleted: true,
                })
            }
        }
    }

    fn normalized_root_after_delete(&mut self, mut root: u64) -> Result<u64, BtrfsMutationError> {
        loop {
            let root_node = self.node_ref(root)?.clone();
            let BtrfsCowNode::Internal { children, .. } = root_node else {
                break;
            };
            if children.len() != 1 {
                break;
            }
            let Some(child) = children.first() else {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "internal node must have children",
                ));
            };
            let old_root = root;
            root = *child;
            self.retire_node(old_root);
        }
        Ok(root)
    }

    fn find(&self, key: &BtrfsKey) -> Result<Option<Vec<u8>>, BtrfsMutationError> {
        self.find_in(self.root, key)
    }

    fn find_in(&self, node_id: u64, key: &BtrfsKey) -> Result<Option<Vec<u8>>, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => Ok(items
                .iter()
                .find(|item| key_cmp(&item.key, key) == Ordering::Equal)
                .map(|item| item.data.clone())),
            BtrfsCowNode::Internal { keys, children } => {
                if children.len() != keys.len().saturating_add(1) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node child count mismatch",
                    ));
                }
                let idx = Self::child_slot(keys, key);
                self.find_in(children[idx], key)
            }
        }
    }

    fn height_of(&self, node_id: u64) -> Result<usize, BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { .. } => Ok(1),
            BtrfsCowNode::Internal { children, .. } => {
                let mut child_heights = children
                    .iter()
                    .map(|child| self.height_of(*child))
                    .collect::<Result<Vec<_>, _>>()?;
                let first = child_heights
                    .pop()
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "internal node must have children",
                    ))?;
                if child_heights.iter().any(|height| *height != first) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "tree is not height-balanced",
                    ));
                }
                Ok(first + 1)
            }
        }
    }

    fn validate_node(
        &self,
        node_id: u64,
        lower: Option<BtrfsKey>,
        upper: Option<BtrfsKey>,
        depth: usize,
        leaf_depth: &mut Option<usize>,
        is_root: bool,
    ) -> Result<(), BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => {
                if !is_root && items.len() < self.min_items {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "non-root leaf underflow",
                    ));
                }
                for window in items.windows(2) {
                    if key_cmp(&window[0].key, &window[1].key) != Ordering::Less {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaf keys must be strictly increasing",
                        ));
                    }
                }
                for item in items {
                    if let Some(min_key) = lower
                        && key_cmp(&item.key, &min_key) == Ordering::Less
                    {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaf key below lower bound",
                        ));
                    }
                    if let Some(max_key) = upper
                        && key_cmp(&item.key, &max_key) != Ordering::Less
                    {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaf key above upper bound",
                        ));
                    }
                }
                if let Some(expected_depth) = *leaf_depth {
                    if expected_depth != depth {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "leaves must have uniform depth",
                        ));
                    }
                } else {
                    *leaf_depth = Some(depth);
                }
                Ok(())
            }
            BtrfsCowNode::Internal { keys, children } => {
                if children.len() != keys.len().saturating_add(1) {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "internal node child count mismatch",
                    ));
                }
                if !is_root && keys.len() < self.min_items {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "non-root internal underflow",
                    ));
                }
                for window in keys.windows(2) {
                    if key_cmp(&window[0], &window[1]) != Ordering::Less {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "internal separators must be strictly increasing",
                        ));
                    }
                }
                for (idx, separator) in keys.iter().enumerate() {
                    let Some(expected) = self.first_key(children[idx + 1])? else {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "separator child must contain a key",
                        ));
                    };
                    if key_cmp(separator, &expected) != Ordering::Equal {
                        return Err(BtrfsMutationError::BrokenInvariant(
                            "internal separator mismatch",
                        ));
                    }
                }
                for (idx, child) in children.iter().enumerate() {
                    let child_lower = if idx == 0 { lower } else { Some(keys[idx - 1]) };
                    let child_upper = if idx == keys.len() {
                        upper
                    } else {
                        Some(keys[idx])
                    };
                    self.validate_node(
                        *child,
                        child_lower,
                        child_upper,
                        depth + 1,
                        leaf_depth,
                        false,
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl BtrfsBTree for InMemoryCowBtrfsTree {
    fn insert(&mut self, key: BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError> {
        self.insert_entry(
            BtrfsTreeItem {
                key,
                data: item.to_vec(),
            },
            false,
        )
    }

    fn delete(&mut self, key: &BtrfsKey) -> Result<u64, BtrfsMutationError> {
        debug_assert!(self.staged_allocations.is_empty());
        debug_assert!(self.staged_deferred_frees.is_empty());
        let old_root = self.root;
        trace!(
            root = old_root,
            objectid = key.objectid,
            item_type = key.item_type,
            offset = key.offset,
            "btrfs_cow_delete_start"
        );
        let deleted = match self.delete_from(self.root, key) {
            Ok(deleted) => deleted,
            Err(err) => {
                self.rollback_mutation();
                return Err(err);
            }
        };
        if !deleted.deleted {
            self.rollback_mutation();
            return Err(BtrfsMutationError::KeyNotFound);
        }
        let new_root = match self.normalized_root_after_delete(deleted.node_id) {
            Ok(new_root) => new_root,
            Err(err) => {
                self.rollback_mutation();
                return Err(err);
            }
        };
        self.root = new_root;
        self.commit_allocated_nodes();
        self.commit_retired_nodes();
        trace!(old_root, new_root = self.root, "btrfs_cow_delete_complete");
        Ok(self.root)
    }

    fn update(&mut self, key: &BtrfsKey, item: &[u8]) -> Result<u64, BtrfsMutationError> {
        if self.find(key)?.is_none() {
            return Err(BtrfsMutationError::KeyNotFound);
        }
        self.insert_entry(
            BtrfsTreeItem {
                key: *key,
                data: item.to_vec(),
            },
            true,
        )
    }

    fn range(
        &self,
        start: &BtrfsKey,
        end: &BtrfsKey,
    ) -> Result<Vec<(BtrfsKey, Vec<u8>)>, BtrfsMutationError> {
        if key_cmp(start, end) == Ordering::Greater {
            return Err(BtrfsMutationError::InvalidRange);
        }
        let mut out = Vec::new();
        self.collect_range_from(self.root, start, end, &mut out)?;
        Ok(out)
    }
}

impl InMemoryCowBtrfsTree {
    /// B-tree-aware range descent. Only visits internal children whose
    /// `[keys[i-1], keys[i])` span intersects `[start, end]`, and uses
    /// `partition_point` on sorted leaves so the result is O(log N + k)
    /// per call instead of a full-tree materialisation followed by
    /// filter. bd-yt66z's `btrfs_resolve_inode_path_via_cow`
    /// fast path depends on this for its O(depth · log N) complexity.
    fn collect_range_from(
        &self,
        node_id: u64,
        start: &BtrfsKey,
        end: &BtrfsKey,
        out: &mut Vec<(BtrfsKey, Vec<u8>)>,
    ) -> Result<(), BtrfsMutationError> {
        match self.node_ref(node_id)? {
            BtrfsCowNode::Leaf { items } => {
                let lo = items.partition_point(|item| key_cmp(&item.key, start).is_lt());
                for item in &items[lo..] {
                    if key_cmp(&item.key, end).is_gt() {
                        break;
                    }
                    out.push((item.key, item.data.clone()));
                }
            }
            BtrfsCowNode::Internal { keys, children } => {
                // children[i] holds keys in [keys[i-1], keys[i]); edges are
                // sentinels (-inf, +inf). Skip children whose upper bound
                // `keys[i]` is <= start (all their keys are < start), and
                // stop once a child's lower bound `keys[i-1]` is > end
                // (all remaining children are strictly past the query).
                for (i, child) in children.iter().enumerate() {
                    if let Some(high) = keys.get(i)
                        && key_cmp(high, start) != Ordering::Greater
                    {
                        continue;
                    }
                    if i > 0 && key_cmp(&keys[i - 1], end).is_gt() {
                        break;
                    }
                    self.collect_range_from(*child, start, end, out)?;
                }
            }
        }
        Ok(())
    }
}

// ── Extent allocation ───────────────────────────────────────────────────────

/// On-disk block group item: describes a contiguous region of the address space
/// and how much of it is allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsBlockGroupItem {
    /// Total bytes in this block group.
    pub total_bytes: u64,
    /// Bytes currently allocated.
    pub used_bytes: u64,
    /// Type flags (DATA, METADATA, SYSTEM).
    pub flags: u64,
}

impl BtrfsBlockGroupItem {
    /// Serialize to on-disk format (24 bytes LE).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.used_bytes.to_le_bytes());
        buf.extend_from_slice(&self.total_bytes.to_le_bytes()); // Note: kernel stores chunk_objectid here; we reuse for total
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf
    }

    /// Free bytes remaining.
    #[must_use]
    pub fn free_bytes(&self) -> u64 {
        self.total_bytes.saturating_sub(self.used_bytes)
    }
}

/// On-disk extent item: records a single allocated extent and its reference count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsExtentItem {
    /// Reference count.
    pub refs: u64,
    /// Generation.
    pub generation: u64,
    /// Flags.
    pub flags: u64,
}

impl BtrfsExtentItem {
    /// Extent flag: this is a tree block (metadata).
    pub const FLAG_TREE_BLOCK: u64 = 2;

    /// Serialize to on-disk format (24 bytes LE).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.refs.to_le_bytes());
        buf.extend_from_slice(&self.generation.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf
    }
}

/// Logical key for a physical extent in delayed reference bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtentKey {
    /// Physical byte address of the extent.
    pub bytenr: u64,
    /// Extent length in bytes.
    pub num_bytes: u64,
}

/// Reference kinds tracked by delayed references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtrfsRef {
    /// Tree block back-reference.
    TreeBlock {
        root: u64,
        owner: u64,
        offset: u64,
        level: u8,
    },
    /// Data extent back-reference.
    DataExtent {
        root: u64,
        objectid: u64,
        offset: u64,
    },
    /// Shared tree block reference.
    SharedTreeBlock { parent: u64, level: u8 },
    /// Shared data extent reference.
    SharedDataExtent { parent: u64 },
}

/// Delayed reference action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefAction {
    /// Add a back-reference (increment refcount).
    Insert,
    /// Delete a back-reference (decrement refcount).
    Delete,
}

/// A delayed reference entry queued for batch processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelayedRef {
    /// Extent this reference applies to.
    pub extent: ExtentKey,
    /// Reference shape.
    pub ref_type: BtrfsRef,
    /// Insert/delete action.
    pub action: RefAction,
    /// Monotonic sequence number for deterministic replay.
    pub sequence: u64,
}

/// Delayed reference queue keyed by extent, with deterministic sequencing.
#[derive(Debug, Clone, Default)]
pub struct DelayedRefQueue {
    refs: BTreeMap<ExtentKey, Vec<DelayedRef>>,
    pending_count: usize,
    next_sequence: u64,
}

impl DelayedRefQueue {
    /// Create an empty delayed reference queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a delayed reference action for an extent.
    pub fn queue(&mut self, extent: ExtentKey, ref_type: BtrfsRef, action: RefAction) {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let entry = DelayedRef {
            extent,
            ref_type,
            action,
            sequence: seq,
        };
        self.refs.entry(extent).or_default().push(entry);
        self.pending_count = self.pending_count.saturating_add(1);
    }

    /// Number of queued delayed reference entries.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Borrow pending entries for one extent key.
    #[must_use]
    pub fn pending_for(&self, extent: &ExtentKey) -> &[DelayedRef] {
        self.refs.get(extent).map_or(&[], Vec::as_slice)
    }

    /// Flush up to `limit` delayed refs into persistent refcounts.
    ///
    /// Returns number of flushed entries.
    pub fn flush(
        &mut self,
        limit: usize,
        refcounts: &mut BTreeMap<ExtentKey, u64>,
    ) -> Result<usize, BtrfsMutationError> {
        if limit == 0 || self.pending_count == 0 {
            return Ok(0);
        }

        let started = std::time::Instant::now();
        let mut flushed = 0usize;
        let mut selected = Vec::new();
        let extent_keys: Vec<ExtentKey> = self.refs.keys().copied().collect();
        let mut candidate_refcounts = refcounts.clone();

        for extent in extent_keys {
            if flushed >= limit {
                break;
            }

            let Some(entries) = self.refs.get(&extent) else {
                continue;
            };

            let remaining_budget = limit - flushed;
            let take_n = remaining_budget.min(entries.len());

            for entry in entries.iter().copied().take(take_n) {
                match entry.action {
                    RefAction::Insert => {
                        let counter = candidate_refcounts.entry(entry.extent).or_insert(0);
                        let next =
                            counter
                                .checked_add(1)
                                .ok_or(BtrfsMutationError::BrokenInvariant(
                                    "delayed ref insert overflow",
                                ))?;
                        *counter = next;
                    }
                    RefAction::Delete => match candidate_refcounts.entry(entry.extent) {
                        std::collections::btree_map::Entry::Occupied(mut occ) => {
                            let current = *occ.get();
                            if current == 0 {
                                return Err(BtrfsMutationError::BrokenInvariant(
                                    "delayed ref delete underflow",
                                ));
                            }
                            let next = current - 1;
                            if next == 0 {
                                occ.remove_entry();
                            } else {
                                *occ.get_mut() = next;
                            }
                        }
                        std::collections::btree_map::Entry::Vacant(_) => {
                            return Err(BtrfsMutationError::BrokenInvariant(
                                "delayed ref delete without prior refcount",
                            ));
                        }
                    },
                }
            }

            selected.push((extent, take_n));
            flushed = flushed.saturating_add(take_n);
        }

        let mut to_prune = Vec::new();
        for (extent, take_n) in selected {
            let Some(entries) = self.refs.get_mut(&extent) else {
                continue;
            };
            entries.drain(..take_n);
            self.pending_count = self.pending_count.saturating_sub(take_n);

            if entries.is_empty() {
                to_prune.push(extent);
            }
        }

        for extent in to_prune {
            self.refs.remove(&extent);
        }
        *refcounts = candidate_refcounts;

        debug!(
            target: "ffs::btrfs::alloc",
            flushed,
            remaining = self.pending_count,
            duration_us = started.elapsed().as_micros(),
            "delayed_ref_flush_batch"
        );

        Ok(flushed)
    }

    /// Drain all queued delayed refs in sequence order.
    pub fn drain_all(&mut self) -> Vec<DelayedRef> {
        let mut drained: Vec<DelayedRef> = self
            .refs
            .values_mut()
            .flat_map(|entries| entries.drain(..))
            .collect();
        self.refs.clear();
        self.pending_count = 0;
        drained.sort_by_key(|entry| entry.sequence);
        drained
    }
}

/// Logical tree identifier for btrfs roots.
pub type TreeId = u64;

/// Root pointer update staged by a btrfs transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeRoot {
    /// Logical bytenr of the new root node.
    pub bytenr: u64,
    /// Tree level of the root node.
    pub level: u8,
}

/// Summary returned when a transaction is aborted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsAbortSummary {
    pub txn_id: TxnId,
    pub discarded_tree_updates: usize,
    pub released_allocations: Vec<BlockNumber>,
    pub deferred_frees: Vec<BlockNumber>,
}

/// Errors from btrfs transaction orchestration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BtrfsTransactionError {
    #[error("request checkpoint failed before transaction begin")]
    CancelledBegin,
    #[error("request checkpoint failed before transaction commit")]
    CancelledCommit,
    #[error("request checkpoint failed after transaction commit")]
    CancelledPostCommit,
    #[error("btrfs transaction already finished")]
    AlreadyFinished,
    #[error("tree root set is empty; stage at least one root update before commit")]
    EmptyRootSet,
    #[error("tree root block address overflow for tree_id={tree_id}")]
    TreeRootAddressOverflow { tree_id: TreeId },
    #[error("transaction metadata block address overflow for txn_id={txn_id:?}")]
    MetadataAddressOverflow { txn_id: TxnId },
    #[error("pending-free metadata block address overflow for txn_id={txn_id:?}")]
    PendingFreeAddressOverflow { txn_id: TxnId },
    #[error("delayed reference flush failed: {0:?}")]
    DelayedRefs(BtrfsMutationError),
    #[error("mvcc commit failed: {0}")]
    Commit(#[from] CommitError),
}

/// In-memory btrfs transaction handle bridged onto MVCC commit boundaries.
///
/// This models core btrfs transaction semantics:
/// - snapshot-at-begin reads
/// - staged tree-root updates
/// - delayed-ref accumulation + flush on commit
/// - explicit abort path with allocation cleanup bookkeeping
#[derive(Debug)]
pub struct BtrfsTransaction {
    txn_id: TxnId,
    snapshot: Snapshot,
    generation: u64,
    mvcc_txn: Option<Transaction>,
    pending_trees: BTreeMap<TreeId, TreeRoot>,
    delayed_refs: DelayedRefQueue,
    allocated: Vec<BlockNumber>,
    to_free: Vec<BlockNumber>,
}

impl BtrfsTransaction {
    /// Begin a btrfs transaction backed by an MVCC transaction.
    pub fn begin(
        store: &mut MvccStore,
        generation: u64,
        cx: &Cx,
    ) -> Result<Self, BtrfsTransactionError> {
        cx.checkpoint()
            .map_err(|_| BtrfsTransactionError::CancelledBegin)?;
        let mvcc_txn = store.begin();
        debug!(
            target: "ffs::btrfs::txn",
            txn_id = mvcc_txn.id.0,
            snapshot = mvcc_txn.snapshot.high.0,
            generation,
            "btrfs_tx_begin"
        );
        Ok(Self {
            txn_id: mvcc_txn.id,
            snapshot: mvcc_txn.snapshot,
            generation,
            mvcc_txn: Some(mvcc_txn),
            pending_trees: BTreeMap::new(),
            delayed_refs: DelayedRefQueue::new(),
            allocated: Vec::new(),
            to_free: Vec::new(),
        })
    }

    /// Transaction identifier.
    #[must_use]
    pub const fn txn_id(&self) -> TxnId {
        self.txn_id
    }

    /// Snapshot captured at begin.
    #[must_use]
    pub const fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// Transaction generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Staged tree-root updates.
    #[must_use]
    pub fn pending_trees(&self) -> &BTreeMap<TreeId, TreeRoot> {
        &self.pending_trees
    }

    /// Number of queued delayed references.
    #[must_use]
    pub fn delayed_ref_count(&self) -> usize {
        self.delayed_refs.pending_count()
    }

    /// Queue or replace a tree-root update.
    pub fn stage_tree_root(&mut self, tree_id: TreeId, root: TreeRoot) {
        self.pending_trees.insert(tree_id, root);
    }

    /// Stage a logical block write in the underlying MVCC transaction.
    pub fn stage_block_write(
        &mut self,
        block: BlockNumber,
        data: Vec<u8>,
    ) -> Result<(), BtrfsTransactionError> {
        let txn = self
            .mvcc_txn
            .as_mut()
            .ok_or(BtrfsTransactionError::AlreadyFinished)?;
        txn.stage_write(block, data);
        Ok(())
    }

    /// Record a newly allocated block so abort can return it for cleanup.
    pub fn track_allocation(&mut self, block: BlockNumber) {
        self.allocated.push(block);
    }

    /// Record a block to be freed after a successful commit.
    pub fn defer_free_on_commit(&mut self, block: BlockNumber) {
        self.to_free.push(block);
    }

    /// Queue a delayed reference to flush during commit.
    pub fn queue_delayed_ref(&mut self, extent: ExtentKey, ref_type: BtrfsRef, action: RefAction) {
        self.delayed_refs.queue(extent, ref_type, action);
    }

    /// Commit this transaction through MVCC.
    ///
    /// Commit steps:
    /// 1. Flush delayed refs deterministically.
    /// 2. Stage tree-root updates and metadata records.
    /// 3. Commit the MVCC transaction (FCW conflict detection).
    pub fn commit(
        mut self,
        store: &mut MvccStore,
        cx: &Cx,
    ) -> Result<CommitSeq, BtrfsTransactionError> {
        cx.checkpoint()
            .map_err(|_| BtrfsTransactionError::CancelledCommit)?;
        if self.pending_trees.is_empty() {
            return Err(BtrfsTransactionError::EmptyRootSet);
        }

        let commit_started = std::time::Instant::now();
        let delayed_ref_total = self.delayed_refs.pending_count();
        let mut materialized_refcounts = BTreeMap::new();
        if delayed_ref_total > 0 {
            self.delayed_refs
                .flush(usize::MAX, &mut materialized_refcounts)
                .map_err(BtrfsTransactionError::DelayedRefs)?;
        }

        self.stage_metadata_records()?;

        let txn = self
            .mvcc_txn
            .take()
            .ok_or(BtrfsTransactionError::AlreadyFinished)?;
        let commit_seq = store.commit(txn)?;
        let duration_us = u64::try_from(commit_started.elapsed().as_micros()).unwrap_or(u64::MAX);
        info!(
            target: "ffs::btrfs::txn",
            txn_id = self.txn_id.0,
            generation = self.generation,
            commit_seq = commit_seq.0,
            trees_modified = self.pending_trees.len(),
            delayed_refs_flushed = delayed_ref_total,
            staged_allocations = self.allocated.len(),
            pending_frees = self.to_free.len(),
            duration_us,
            "btrfs_tx_commit"
        );
        cx.checkpoint()
            .map_err(|_| BtrfsTransactionError::CancelledPostCommit)?;
        Ok(commit_seq)
    }

    /// Abort this transaction and return cleanup bookkeeping.
    #[must_use]
    pub fn abort(mut self) -> BtrfsAbortSummary {
        let _ = self.mvcc_txn.take();
        warn!(
            target: "ffs::btrfs::txn",
            txn_id = self.txn_id.0,
            generation = self.generation,
            discarded_tree_updates = self.pending_trees.len(),
            allocated = self.allocated.len(),
            deferred_frees = self.to_free.len(),
            "btrfs_tx_abort"
        );
        BtrfsAbortSummary {
            txn_id: self.txn_id,
            discarded_tree_updates: self.pending_trees.len(),
            released_allocations: self.allocated,
            deferred_frees: self.to_free,
        }
    }

    fn stage_metadata_records(&mut self) -> Result<(), BtrfsTransactionError> {
        let tx_meta_block = Self::metadata_block_for_txn(self.txn_id)?;
        self.stage_block_write(tx_meta_block, self.encode_tx_metadata())?;

        let tree_updates: Vec<(TreeId, TreeRoot)> = self
            .pending_trees
            .iter()
            .map(|(tree_id, root)| (*tree_id, *root))
            .collect();
        for (tree_id, root) in tree_updates {
            let block = Self::tree_root_block(tree_id)?;
            let payload = Self::encode_tree_root_record(self.generation, tree_id, root);
            self.stage_block_write(block, payload)?;
        }

        if !self.to_free.is_empty() {
            let free_block = Self::pending_free_block_for_txn(self.txn_id)?;
            self.stage_block_write(free_block, self.encode_pending_frees())?;
        }

        Ok(())
    }

    fn metadata_block_for_txn(txn_id: TxnId) -> Result<BlockNumber, BtrfsTransactionError> {
        BTRFS_TX_META_BASE_BLOCK
            .checked_add(txn_id.0)
            .map(BlockNumber)
            .ok_or(BtrfsTransactionError::MetadataAddressOverflow { txn_id })
    }

    fn tree_root_block(tree_id: TreeId) -> Result<BlockNumber, BtrfsTransactionError> {
        BTRFS_TX_TREE_ROOT_BASE_BLOCK
            .checked_add(tree_id)
            .map(BlockNumber)
            .ok_or(BtrfsTransactionError::TreeRootAddressOverflow { tree_id })
    }

    fn pending_free_block_for_txn(txn_id: TxnId) -> Result<BlockNumber, BtrfsTransactionError> {
        BTRFS_TX_PENDING_FREE_BASE_BLOCK
            .checked_add(txn_id.0)
            .map(BlockNumber)
            .ok_or(BtrfsTransactionError::PendingFreeAddressOverflow { txn_id })
    }

    fn encode_tx_metadata(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.extend_from_slice(&self.snapshot.high.0.to_le_bytes());
        bytes.extend_from_slice(&self.txn_id.0.to_le_bytes());
        bytes.extend_from_slice(&(self.pending_trees.len() as u64).to_le_bytes());
        bytes
    }

    fn encode_pending_frees(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.to_free.len().saturating_mul(8));
        bytes.extend_from_slice(&(self.to_free.len() as u64).to_le_bytes());
        for block in &self.to_free {
            bytes.extend_from_slice(&block.0.to_le_bytes());
        }
        bytes
    }

    fn encode_tree_root_record(generation: u64, tree_id: TreeId, root: TreeRoot) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&generation.to_le_bytes());
        bytes.extend_from_slice(&tree_id.to_le_bytes());
        bytes.extend_from_slice(&root.bytenr.to_le_bytes());
        bytes.push(root.level);
        bytes
    }
}

/// Result of an extent allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentAllocation {
    /// Physical byte address of the allocated extent.
    pub bytenr: u64,
    /// Size of the allocated extent.
    pub num_bytes: u64,
    /// Block group the allocation came from.
    pub block_group_start: u64,
}

/// In-memory block group state tracked by the extent allocator.
#[derive(Debug, Clone)]
struct BlockGroupState {
    /// Starting byte address of this block group.
    start: u64,
    /// On-disk item.
    item: BtrfsBlockGroupItem,
    /// Hint for next allocation search offset within this group.
    alloc_offset: u64,
}

/// Extent allocator for btrfs write path.
///
/// Manages block groups and finds free space by scanning for gaps between
/// allocated extents in the extent tree. For V1 single-device, free space
/// is determined by gap analysis (no free-space-tree optimization yet).
#[derive(Debug)]
pub struct BtrfsExtentAllocator {
    /// Block groups, keyed by start address.
    block_groups: BTreeMap<u64, BlockGroupState>,
    /// The extent tree (COW B-tree tracking allocated extents).
    extent_tree: InMemoryCowBtrfsTree,
    /// Queued delayed references for batch commit.
    delayed_ref_queue: DelayedRefQueue,
    /// Refcounts materialized by delayed-ref flush.
    extent_refcounts: BTreeMap<ExtentKey, u64>,
    /// Current transaction generation.
    generation: u64,
}

impl BtrfsExtentAllocator {
    /// Create a new extent allocator with an empty extent tree.
    pub fn new(generation: u64) -> Result<Self, BtrfsMutationError> {
        let extent_tree = InMemoryCowBtrfsTree::new(5)?;
        Ok(Self {
            block_groups: BTreeMap::new(),
            extent_tree,
            delayed_ref_queue: DelayedRefQueue::new(),
            extent_refcounts: BTreeMap::new(),
            generation,
        })
    }

    /// Register a block group.
    pub fn add_block_group(&mut self, start: u64, item: BtrfsBlockGroupItem) {
        debug!(
            target: "ffs::btrfs::alloc",
            start, total = item.total_bytes, used = item.used_bytes,
            flags = item.flags, "block_group_register"
        );
        self.block_groups.insert(
            start,
            BlockGroupState {
                start,
                item,
                alloc_offset: item.used_bytes,
            },
        );
    }

    /// Allocate a data extent of the given size.
    ///
    /// Scans block groups with `BTRFS_BLOCK_GROUP_DATA` flag for a gap
    /// large enough to hold `num_bytes`.
    pub fn alloc_data(&mut self, num_bytes: u64) -> Result<ExtentAllocation, BtrfsMutationError> {
        self.alloc_extent(num_bytes, BTRFS_BLOCK_GROUP_DATA, false)
    }

    /// Allocate a metadata extent (tree block).
    pub fn alloc_metadata(
        &mut self,
        num_bytes: u64,
    ) -> Result<ExtentAllocation, BtrfsMutationError> {
        self.alloc_extent(num_bytes, BTRFS_BLOCK_GROUP_METADATA, true)
    }

    /// Core allocation logic.
    #[allow(clippy::too_many_lines)]
    fn alloc_extent(
        &mut self,
        num_bytes: u64,
        required_flags: u64,
        is_metadata: bool,
    ) -> Result<ExtentAllocation, BtrfsMutationError> {
        if num_bytes == 0 {
            return Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero",
            ));
        }

        // Find a block group with enough free space.
        let bg_start = self
            .block_groups
            .values()
            .find(|bg| (bg.item.flags & required_flags) != 0 && bg.item.free_bytes() >= num_bytes)
            .map(|bg| bg.start);

        let bg_start = bg_start.ok_or(BtrfsMutationError::BrokenInvariant(
            "no block group with enough free space",
        ))?;

        debug!(
            target: "ffs::btrfs::alloc",
            block_group = bg_start,
            size_needed = num_bytes,
            "alloc_search_start"
        );

        // Find a gap in this block group by scanning allocation items in range.
        // We must include both EXTENT_ITEM (168) and METADATA_ITEM (169)
        // as both represent physical space allocations.
        let bg = &self.block_groups[&bg_start];
        let bg_end = bg
            .start
            .checked_add(bg.item.total_bytes)
            .ok_or(BtrfsMutationError::AddressOverflow)?;

        let range_start = BtrfsKey {
            objectid: bg.start,
            item_type: BTRFS_ITEM_EXTENT_ITEM, // 168
            offset: 0,
        };
        let range_end = BtrfsKey {
            objectid: bg_end,
            item_type: BTRFS_ITEM_METADATA_ITEM, // 169
            offset: u64::MAX,
        };

        let extents = self.extent_tree.range(&range_start, &range_end)?;

        // Scan for gaps between existing extents.
        let alloc_offset = self.block_groups[&bg_start].alloc_offset;
        let mut cursor = bg_start
            .checked_add(alloc_offset)
            .ok_or(BtrfsMutationError::AddressOverflow)?;

        let allocated_ranges: Vec<(u64, u64)> = extents
            .iter()
            .map(|(key, _)| (key.objectid, key.offset))
            .collect();

        let mut found = None;
        // Try from alloc_offset first, then wrap around.
        for &(ext_start, ext_size) in &allocated_ranges {
            let ext_end = ext_start
                .checked_add(ext_size)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            if cursor < ext_start {
                let gap = ext_start - cursor;
                if gap >= num_bytes {
                    found = Some(cursor);
                    break;
                }
            }
            if ext_end > cursor {
                cursor = ext_end;
            }
        }
        // Check gap after last extent.
        if found.is_none() {
            if let Some(end) = cursor.checked_add(num_bytes) {
                if end <= bg_end {
                    found = Some(cursor);
                }
            }
        }
        // Wrap around: try from block group start if we started mid-group.
        if found.is_none() && alloc_offset > 0 {
            cursor = bg_start;
            for &(ext_start, ext_size) in &allocated_ranges {
                let ext_end = ext_start
                    .checked_add(ext_size)
                    .ok_or(BtrfsMutationError::AddressOverflow)?;
                if cursor < ext_start {
                    let gap = ext_start - cursor;
                    if gap >= num_bytes {
                        found = Some(cursor);
                        break;
                    }
                }
                if ext_end > cursor {
                    cursor = ext_end;
                }
            }
            if found.is_none() {
                if let Some(end) = cursor.checked_add(num_bytes) {
                    if end <= bg_end {
                        found = Some(cursor);
                    }
                }
            }
        }

        let bytenr = found.ok_or(BtrfsMutationError::BrokenInvariant(
            "block group has no gap",
        ))?;
        let extent = ExtentKey { bytenr, num_bytes };

        debug!(
            target: "ffs::btrfs::alloc",
            block_group = bg_start,
            extent_start = bytenr,
            extent_size = num_bytes,
            "alloc_found"
        );

        // Insert EXTENT_ITEM into extent tree.
        let extent_item = BtrfsExtentItem {
            refs: 1,
            generation: self.generation,
            flags: if is_metadata {
                BtrfsExtentItem::FLAG_TREE_BLOCK
            } else {
                0
            },
        };
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: if is_metadata {
                BTRFS_ITEM_METADATA_ITEM
            } else {
                BTRFS_ITEM_EXTENT_ITEM
            },
            offset: num_bytes,
        };
        self.extent_tree.insert(key, &extent_item.to_bytes())?;

        trace!(
            target: "ffs::btrfs::alloc",
            bytenr,
            size = num_bytes,
            refs = 1,
            "extent_item_insert"
        );

        // Update block group accounting.
        if let Some(bg) = self.block_groups.get_mut(&bg_start) {
            let used_before = bg.item.used_bytes;
            bg.item.used_bytes += num_bytes;
            let alloc_end = bytenr
                .checked_add(num_bytes)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            bg.alloc_offset = alloc_end
                .checked_sub(bg_start)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            trace!(
                target: "ffs::btrfs::alloc",
                block_group = bg_start,
                used_before,
                used_after = bg.item.used_bytes,
                delta = num_bytes,
                "bg_accounting"
            );
        }

        // Queue delayed ref.
        let ref_type = if is_metadata {
            BtrfsRef::TreeBlock {
                root: bg_start,
                owner: bytenr,
                offset: num_bytes,
                level: 0,
            }
        } else {
            BtrfsRef::DataExtent {
                root: bg_start,
                objectid: bytenr,
                offset: num_bytes,
            }
        };
        self.delayed_ref_queue
            .queue(extent, ref_type, RefAction::Insert);
        debug!(
            target: "ffs::btrfs::alloc",
            bytenr,
            ref_type = if is_metadata { "metadata" } else { "data" },
            action = "insert",
            "delayed_ref_queue"
        );

        Ok(ExtentAllocation {
            bytenr,
            num_bytes,
            block_group_start: bg_start,
        })
    }

    /// Free an extent (decrement refcount, remove if zero).
    pub fn free_extent(
        &mut self,
        bytenr: u64,
        num_bytes: u64,
        is_metadata: bool,
    ) -> Result<(), BtrfsMutationError> {
        if num_bytes == 0 {
            return Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero",
            ));
        }

        debug!(
            target: "ffs::btrfs::alloc",
            bytenr, size = num_bytes, "free_search"
        );

        let item_type = if is_metadata {
            BTRFS_ITEM_METADATA_ITEM
        } else {
            BTRFS_ITEM_EXTENT_ITEM
        };
        let key = BtrfsKey {
            objectid: bytenr,
            item_type,
            offset: num_bytes,
        };
        if self.extent_tree.range(&key, &key)?.is_empty() {
            return Err(BtrfsMutationError::KeyNotFound);
        }

        let extent_end = bytenr
            .checked_add(num_bytes)
            .ok_or(BtrfsMutationError::AddressOverflow)?;
        let mut owning_bg = None;
        for bg in self.block_groups.values() {
            let bg_end = bg
                .start
                .checked_add(bg.item.total_bytes)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            if bytenr >= bg.start && extent_end <= bg_end {
                let used_after = bg.item.used_bytes.checked_sub(num_bytes).ok_or(
                    BtrfsMutationError::BrokenInvariant("block group used bytes underflow"),
                )?;
                owning_bg = Some((bg.start, used_after));
                break;
            }
        }

        let (root, used_after) = owning_bg.ok_or(BtrfsMutationError::BrokenInvariant(
            "extent has no owning block group",
        ))?;

        // Remove from extent tree only after ownership and accounting checks pass.
        self.extent_tree.delete(&key)?;
        trace!(
            target: "ffs::btrfs::alloc",
            bytenr, size = num_bytes, "extent_item_remove"
        );

        // Update block group accounting.
        let bg = self
            .block_groups
            .get_mut(&root)
            .ok_or(BtrfsMutationError::BrokenInvariant(
                "extent owner block group disappeared",
            ))?;
        let used_before = bg.item.used_bytes;
        bg.item.used_bytes = used_after;
        trace!(
            target: "ffs::btrfs::alloc",
            block_group = bg.start,
            used_before,
            used_after = bg.item.used_bytes,
            delta = num_bytes,
            "bg_accounting_free"
        );

        // Queue delayed ref for delete.
        let extent = ExtentKey { bytenr, num_bytes };
        let ref_type = if is_metadata {
            BtrfsRef::TreeBlock {
                root,
                owner: bytenr,
                offset: num_bytes,
                level: 0,
            }
        } else {
            BtrfsRef::DataExtent {
                root,
                objectid: bytenr,
                offset: num_bytes,
            }
        };
        self.delayed_ref_queue
            .queue(extent, ref_type, RefAction::Delete);
        debug!(
            target: "ffs::btrfs::alloc",
            bytenr,
            ref_type = if is_metadata { "metadata" } else { "data" },
            action = "delete",
            "delayed_ref_queue"
        );

        Ok(())
    }

    /// Drain all queued delayed references (for transaction commit).
    pub fn drain_delayed_refs(&mut self) -> Vec<DelayedRef> {
        self.delayed_ref_queue.drain_all()
    }

    /// Number of queued delayed references.
    #[must_use]
    pub fn delayed_ref_count(&self) -> usize {
        self.delayed_ref_queue.pending_count()
    }

    /// Borrow queued delayed references for an extent.
    #[must_use]
    pub fn pending_for(&self, extent: &ExtentKey) -> &[DelayedRef] {
        self.delayed_ref_queue.pending_for(extent)
    }

    /// Flush up to `limit` delayed refs into materialized refcounts.
    pub fn flush_delayed_refs(&mut self, limit: usize) -> Result<usize, BtrfsMutationError> {
        self.delayed_ref_queue
            .flush(limit, &mut self.extent_refcounts)
    }

    /// Materialized refcount for an extent.
    #[must_use]
    pub fn extent_refcount(&self, extent: ExtentKey) -> u64 {
        self.extent_refcounts.get(&extent).copied().unwrap_or(0)
    }

    /// Get block group state for inspection.
    #[must_use]
    pub fn block_group(&self, start: u64) -> Option<&BtrfsBlockGroupItem> {
        self.block_groups.get(&start).map(|bg| &bg.item)
    }

    /// Total free space across all block groups with the given type flags.
    #[must_use]
    pub fn total_free(&self, type_flags: u64) -> u64 {
        self.block_groups
            .values()
            .filter(|bg| (bg.item.flags & type_flags) != 0)
            .fold(0_u64, |total, bg| {
                total.saturating_add(bg.item.free_bytes())
            })
    }

    /// Largest currently allocatable free extent across matching block groups.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsMutationError::AddressOverflow`] if a tracked block-group
    /// or extent range cannot be represented as a half-open byte interval.
    pub fn largest_free_extent(&self, type_flags: u64) -> Result<u64, BtrfsMutationError> {
        let mut best = 0_u64;

        for bg in self
            .block_groups
            .values()
            .filter(|bg| (bg.item.flags & type_flags) != 0)
        {
            let bg_end = bg
                .start
                .checked_add(bg.item.total_bytes)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            let range_start = BtrfsKey {
                objectid: bg.start,
                item_type: BTRFS_ITEM_EXTENT_ITEM,
                offset: 0,
            };
            let range_end = BtrfsKey {
                objectid: bg_end,
                item_type: BTRFS_ITEM_METADATA_ITEM,
                offset: u64::MAX,
            };
            let mut allocated_ranges = Vec::new();
            let mut materialized_used = 0_u64;

            for (key, _) in self.extent_tree.range(&range_start, &range_end)? {
                if key.objectid >= bg_end {
                    break;
                }
                let extent_start = key.objectid.max(bg.start);
                let extent_end = key
                    .objectid
                    .checked_add(key.offset)
                    .ok_or(BtrfsMutationError::AddressOverflow)?
                    .min(bg_end);
                if extent_start < extent_end {
                    let extent_len = extent_end - extent_start;
                    materialized_used = materialized_used
                        .checked_add(extent_len)
                        .ok_or(BtrfsMutationError::AddressOverflow)?;
                    allocated_ranges.push((extent_start, extent_end));
                }
            }

            let untracked_used = bg
                .item
                .used_bytes
                .saturating_sub(materialized_used)
                .min(bg.item.total_bytes);
            if untracked_used > 0 {
                allocated_ranges.push((
                    bg.start,
                    bg.start
                        .checked_add(untracked_used)
                        .ok_or(BtrfsMutationError::AddressOverflow)?,
                ));
            }
            allocated_ranges.sort_unstable_by_key(|&(start, end)| (start, end));

            let mut cursor = bg.start;
            let mut group_best = 0_u64;
            for (extent_start, extent_end) in allocated_ranges {
                if extent_end <= cursor {
                    continue;
                }
                if cursor < extent_start {
                    group_best = group_best.max(extent_start - cursor);
                }
                cursor = extent_end;
            }

            if cursor < bg_end {
                group_best = group_best.max(bg_end - cursor);
            }
            best = best.max(group_best.min(bg.item.free_bytes()));
        }

        Ok(best)
    }

    /// Total used bytes across all block groups.
    #[must_use]
    pub fn total_used(&self) -> u64 {
        self.block_groups
            .values()
            .fold(0_u64, |total, bg| total.saturating_add(bg.item.used_bytes))
    }

    /// Total capacity across all block groups.
    #[must_use]
    pub fn total_capacity(&self) -> u64 {
        self.block_groups
            .values()
            .fold(0_u64, |total, bg| total.saturating_add(bg.item.total_bytes))
    }
}

// ── btrfs multi-device support ─────────────────────────────────────────────

const BTRFS_CHUNK_ITEM_FIXED_SIZE: usize = 48;
const BTRFS_CHUNK_ITEM_STRIPE_SIZE: usize = 32;

/// Parse a single chunk item from its raw on-disk data.
///
/// The `logical_offset` is the chunk's key.offset (logical start address).
/// The data contains the fixed chunk header (48 bytes) + stripe entries.
fn parse_chunk_item(data: &[u8], logical_offset: u64) -> Result<BtrfsChunkEntry, ParseError> {
    use ffs_types::{read_le_u16, read_le_u32, read_le_u64};

    if data.len() < BTRFS_CHUNK_ITEM_FIXED_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_CHUNK_ITEM_FIXED_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }

    let length = read_le_u64(data, 0)?;
    let owner = read_le_u64(data, 8)?;
    let stripe_len = read_le_u64(data, 16)?;
    let chunk_type = read_le_u64(data, 24)?;
    let io_align = read_le_u32(data, 32)?;
    let io_width = read_le_u32(data, 36)?;
    let sector_size = read_le_u32(data, 40)?;
    let num_stripes = read_le_u16(data, 44)?;
    let sub_stripes = read_le_u16(data, 46)?;

    let raid_bits = chunk_type & chunk_type_flags::RAID_MASK;
    if raid_bits.count_ones() > 1 {
        return Err(ParseError::InvalidField {
            field: "chunk_type",
            reason: "multiple RAID profiles set",
        });
    }
    if length == 0 {
        return Err(ParseError::InvalidField {
            field: "chunk_length",
            reason: "chunk has zero length",
        });
    }
    if stripe_len == 0 {
        return Err(ParseError::InvalidField {
            field: "stripe_len",
            reason: "chunk has zero stripe length",
        });
    }
    if io_align == 0 {
        return Err(ParseError::InvalidField {
            field: "io_align",
            reason: "must be non-zero",
        });
    }
    if io_width == 0 {
        return Err(ParseError::InvalidField {
            field: "io_width",
            reason: "must be non-zero",
        });
    }
    if sector_size == 0 {
        return Err(ParseError::InvalidField {
            field: "sector_size",
            reason: "must be non-zero",
        });
    }
    if num_stripes == 0 {
        return Err(ParseError::InvalidField {
            field: "stripes",
            reason: "chunk has no stripes",
        });
    }

    let stripe_count = usize::from(num_stripes);
    let stripes = parse_chunk_item_stripes(data, stripe_count)?;

    Ok(BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: BTRFS_CHUNK_TREE_OBJECTID,
            item_type: BTRFS_ITEM_CHUNK,
            offset: logical_offset,
        },
        length,
        owner,
        stripe_len,
        chunk_type,
        io_align,
        io_width,
        sector_size,
        num_stripes,
        sub_stripes,
        stripes,
    })
}

fn parse_chunk_item_stripes(
    data: &[u8],
    stripe_count: usize,
) -> Result<Vec<ffs_ondisk::BtrfsStripe>, ParseError> {
    use ffs_types::read_le_u64;

    let stripe_bytes = stripe_count
        .checked_mul(BTRFS_CHUNK_ITEM_STRIPE_SIZE)
        .ok_or(ParseError::InvalidField {
            field: "stripes",
            reason: "chunk stripe payload overflows usize",
        })?;
    let required = BTRFS_CHUNK_ITEM_FIXED_SIZE
        .checked_add(stripe_bytes)
        .ok_or(ParseError::InvalidField {
            field: "stripes",
            reason: "chunk stripe payload overflows usize",
        })?;
    if data.len() < required {
        return Err(ParseError::InsufficientData {
            needed: required,
            offset: BTRFS_CHUNK_ITEM_FIXED_SIZE,
            actual: data.len(),
        });
    }
    if data.len() > required {
        return Err(ParseError::InvalidField {
            field: "stripes",
            reason: "does not match declared stripe count",
        });
    }

    let mut stripes = Vec::with_capacity(stripe_count);
    let mut off = BTRFS_CHUNK_ITEM_FIXED_SIZE;
    for _ in 0..stripe_count {
        let devid = read_le_u64(data, off)?;
        if devid == 0 {
            return Err(ParseError::InvalidField {
                field: "stripe_devid",
                reason: "must be non-zero",
            });
        }
        stripes.push(ffs_ondisk::BtrfsStripe {
            devid,
            offset: read_le_u64(data, off + 8)?,
            dev_uuid: {
                let uuid_off = off + 16;
                if uuid_off + 16 > data.len() {
                    [0u8; 16]
                } else {
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(&data[uuid_off..uuid_off + 16]);
                    uuid
                }
            },
        });
        off += BTRFS_CHUNK_ITEM_STRIPE_SIZE;
    }

    Ok(stripes)
}

/// Walk the chunk tree to build a complete chunk map.
///
/// The `sys_chunk_array` in the superblock provides bootstrap chunks needed to
/// locate the chunk tree itself. This function walks the chunk tree (rooted at
/// `sb.chunk_root`) using the bootstrap chunks, and returns ALL chunk entries
/// including those not in `sys_chunk_array`.
///
/// For single-device filesystems, the `sys_chunk_array` usually contains all
/// chunks. Multi-device or large filesystems may have additional chunks only
/// in the chunk tree.
pub fn walk_chunk_tree(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    sb: &BtrfsSuperblock,
    bootstrap_chunks: &[BtrfsChunkEntry],
) -> Result<Vec<BtrfsChunkEntry>, ParseError> {
    let items = walk_tree(
        read_physical,
        bootstrap_chunks,
        sb.chunk_root,
        sb.nodesize,
        sb.csum_type,
    )?;

    let mut chunks = bootstrap_chunks.to_vec();
    for item in &items {
        if item.key.item_type == BTRFS_ITEM_CHUNK {
            let chunk = parse_chunk_item(&item.data, item.key.offset)?;
            // Only add if not already in bootstrap set (avoid duplicates).
            if !chunks.iter().any(|c| c.key.offset == chunk.key.offset) {
                chunks.push(chunk);
            }
        }
    }

    // Sort by logical offset for efficient lookup.
    chunks.sort_by_key(|c| c.key.offset);
    Ok(chunks)
}

/// Walk the device tree to discover all physical devices.
///
/// The `dev_root_bytenr` is the logical address of the DEV_TREE root node,
/// obtained by looking up objectid 4 (`BTRFS_DEV_TREE_OBJECTID`) in the
/// ROOT_TREE. Returns all leaf items in the device tree.
pub fn walk_device_tree(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    dev_root_bytenr: u64,
    chunks: &[BtrfsChunkEntry],
    nodesize: u32,
    csum_type: u16,
) -> Result<Vec<BtrfsLeafEntry>, ParseError> {
    walk_tree(read_physical, chunks, dev_root_bytenr, nodesize, csum_type)
}

/// Each device is identified by its `devid` (from `DEV_ITEM` in the device tree).
/// The `read_physical` method dispatches reads to the correct device based on the
/// stripe mapping returned by `map_logical_to_stripes`.
/// Device reader: reads `len` bytes from physical offset, returns data or error.
type DeviceReader = Box<dyn Fn(u64, usize) -> Result<Vec<u8>, ffs_types::ParseError> + Send + Sync>;

/// A set of physical devices backing a btrfs filesystem.
pub struct BtrfsDeviceSet {
    /// Map from devid → device read closure.
    devices: std::collections::BTreeMap<u64, DeviceReader>,
}

impl BtrfsDeviceSet {
    /// Create an empty device set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: std::collections::BTreeMap::new(),
        }
    }

    /// Register a device with the given devid.
    pub fn add_device(
        &mut self,
        devid: u64,
        reader: Box<dyn Fn(u64, usize) -> Result<Vec<u8>, ffs_types::ParseError> + Send + Sync>,
    ) {
        self.devices.insert(devid, reader);
    }

    /// Number of registered devices.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Read `len` bytes from the device identified by `devid` at `physical_offset`.
    pub fn read_physical(
        &self,
        devid: u64,
        physical_offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, ffs_types::ParseError> {
        let reader = self
            .devices
            .get(&devid)
            .ok_or(ffs_types::ParseError::InvalidField {
                field: "devid",
                reason: "device not found in device set",
            })?;
        reader(physical_offset, len)
    }

    /// Read a logical block using the chunk map and stripe resolution.
    ///
    /// Resolves the logical address to physical stripes via `map_logical_to_stripes`,
    /// then reads from the first available stripe's device. For mirrored profiles
    /// (RAID1/10), this reads from the first mirror; fallback to other mirrors on
    /// error could be added in the future.
    pub fn read_logical(
        &self,
        chunks: &[ffs_ondisk::BtrfsChunkEntry],
        logical: u64,
        len: usize,
    ) -> Result<Vec<u8>, ffs_types::ParseError> {
        let mapping = ffs_ondisk::map_logical_to_stripes(chunks, logical)?.ok_or(
            ffs_types::ParseError::InvalidField {
                field: "logical_address",
                reason: "address not mapped in chunk table",
            },
        )?;

        // Try each stripe until one succeeds (redundancy for mirrored profiles).
        for stripe in &mapping.stripes {
            match self.read_physical(stripe.devid, stripe.physical, len) {
                Ok(data) => return Ok(data),
                Err(_) if mapping.stripes.len() > 1 => {} // Try next mirror.
                Err(e) => return Err(e),
            }
        }

        Err(ffs_types::ParseError::InvalidField {
            field: "stripe",
            reason: "all mirrors failed to read",
        })
    }
}

impl std::fmt::Debug for BtrfsDeviceSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtrfsDeviceSet")
            .field("device_count", &self.devices.len())
            .field("devids", &self.devices.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Default for BtrfsDeviceSet {
    fn default() -> Self {
        Self::new()
    }
}

// ── btrfs send/receive stream ──────────────────────────────────────────────

/// btrfs send stream magic ("btrfs-stream\0").
pub const BTRFS_SEND_STREAM_MAGIC: &[u8; 13] = b"btrfs-stream\0";

/// btrfs send stream version.
pub const BTRFS_SEND_STREAM_VERSION: u32 = 1;

/// Send stream command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SendCommand {
    Unspec = 0,
    Subvol = 1,
    Snapshot = 2,
    Mkfile = 3,
    Mkdir = 4,
    Mknod = 5,
    Mkfifo = 6,
    Mksock = 7,
    Symlink = 8,
    Rename = 9,
    Link = 10,
    Unlink = 11,
    Rmdir = 12,
    SetXattr = 13,
    RemoveXattr = 14,
    Write = 15,
    Clone = 16,
    Truncate = 17,
    Chmod = 18,
    Chown = 19,
    Utimes = 20,
    End = 21,
    UpdateExtent = 22,
}

impl SendCommand {
    fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Unspec),
            1 => Some(Self::Subvol),
            2 => Some(Self::Snapshot),
            3 => Some(Self::Mkfile),
            4 => Some(Self::Mkdir),
            5 => Some(Self::Mknod),
            6 => Some(Self::Mkfifo),
            7 => Some(Self::Mksock),
            8 => Some(Self::Symlink),
            9 => Some(Self::Rename),
            10 => Some(Self::Link),
            11 => Some(Self::Unlink),
            12 => Some(Self::Rmdir),
            13 => Some(Self::SetXattr),
            14 => Some(Self::RemoveXattr),
            15 => Some(Self::Write),
            16 => Some(Self::Clone),
            17 => Some(Self::Truncate),
            18 => Some(Self::Chmod),
            19 => Some(Self::Chown),
            20 => Some(Self::Utimes),
            21 => Some(Self::End),
            22 => Some(Self::UpdateExtent),
            _ => None,
        }
    }
}

/// Send stream attribute types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SendAttr {
    Unspec = 0,
    Uuid = 1,
    Ctransid = 2,
    Ino = 3,
    Size = 4,
    Mode = 5,
    Uid = 6,
    Gid = 7,
    Rdev = 8,
    Ctime = 9,
    Mtime = 10,
    Atime = 11,
    Otime = 12,
    XattrName = 13,
    XattrData = 14,
    Path = 15,
    PathTo = 16,
    PathLink = 17,
    FileOffset = 18,
    Data = 19,
    CloneUuid = 20,
    CloneCtransid = 21,
    ClonePath = 22,
    CloneOffset = 23,
    CloneLen = 24,
}

/// A parsed command from a btrfs send stream.
#[derive(Debug, Clone)]
pub struct SendStreamCommand {
    pub cmd: SendCommand,
    pub attrs: Vec<(u16, Vec<u8>)>,
}

/// Result of parsing a btrfs send stream.
#[derive(Debug, Clone, Default)]
pub struct SendStreamParseResult {
    pub version: u32,
    pub commands: Vec<SendStreamCommand>,
}

const BTRFS_SEND_CRC32C_POLY: u32 = 0x82F6_3B78;

fn btrfs_send_crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ BTRFS_SEND_CRC32C_POLY
            };
        }
    }
    crc
}

fn send_stream_command_crc32c(command: &[u8]) -> u32 {
    let mut crc = btrfs_send_crc32c(0, &command[..6]);
    crc = btrfs_send_crc32c(crc, &[0_u8; 4]);
    btrfs_send_crc32c(crc, &command[10..])
}

fn parse_send_stream_attrs(
    cmd_data: &[u8],
    cmd_data_start: usize,
) -> Result<Vec<(u16, Vec<u8>)>, ffs_types::ParseError> {
    let mut attrs = Vec::new();
    let mut attr_pos = 0;
    while attr_pos + 4 <= cmd_data.len() {
        let attr_type = u16::from_le_bytes([cmd_data[attr_pos], cmd_data[attr_pos + 1]]);
        let attr_len =
            u16::from_le_bytes([cmd_data[attr_pos + 2], cmd_data[attr_pos + 3]]) as usize;
        attr_pos += 4;
        let Some(attr_end) = attr_pos.checked_add(attr_len) else {
            return Err(ffs_types::ParseError::InvalidField {
                field: "send_stream_attr_len",
                reason: "overflow",
            });
        };
        if attr_end > cmd_data.len() {
            return Err(ffs_types::ParseError::InsufficientData {
                needed: attr_len,
                offset: cmd_data_start + attr_pos,
                actual: cmd_data.len().saturating_sub(attr_pos),
            });
        }
        attrs.push((attr_type, cmd_data[attr_pos..attr_end].to_vec()));
        attr_pos = attr_end;
    }
    if attr_pos != cmd_data.len() {
        return Err(ffs_types::ParseError::InsufficientData {
            needed: 4,
            offset: cmd_data_start + attr_pos,
            actual: cmd_data.len().saturating_sub(attr_pos),
        });
    }
    Ok(attrs)
}

/// Parse a btrfs send stream from raw bytes.
///
/// The send stream format is:
/// - 13-byte magic ("btrfs-stream\0")
/// - 4-byte version (u32 LE)
/// - Commands: each is [len(u32 LE), cmd(u16 LE), crc32(u32 LE), attrs...]
/// - Attributes: each is [type(u16 LE), len(u16 LE), data(len bytes)]
pub fn parse_send_stream(data: &[u8]) -> Result<SendStreamParseResult, ffs_types::ParseError> {
    if data.len() < 17 {
        return Err(ffs_types::ParseError::InsufficientData {
            needed: 17,
            offset: 0,
            actual: data.len(),
        });
    }

    if &data[..13] != BTRFS_SEND_STREAM_MAGIC {
        return Err(ffs_types::ParseError::InvalidField {
            field: "send_stream_magic",
            reason: "not a btrfs send stream (magic mismatch)",
        });
    }

    let version = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
    if version != BTRFS_SEND_STREAM_VERSION {
        return Err(ffs_types::ParseError::InvalidField {
            field: "send_stream_version",
            reason: "unsupported btrfs send stream version",
        });
    }
    let mut pos = 17;
    let mut commands = Vec::new();
    let mut saw_end = false;

    while pos + 10 <= data.len() {
        let command_start = pos;
        // Command header: len(u32), cmd(u16), crc32(u32)
        let cmd_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let cmd_type = u16::from_le_bytes([data[pos + 4], data[pos + 5]]);
        let expected_crc =
            u32::from_le_bytes([data[pos + 6], data[pos + 7], data[pos + 8], data[pos + 9]]);
        pos += 10;

        let cmd_data_start = pos;
        let Some(cmd_end) = pos.checked_add(cmd_len) else {
            return Err(ffs_types::ParseError::InvalidField {
                field: "send_stream_cmd_len",
                reason: "overflow",
            });
        };
        if cmd_end > data.len() {
            return Err(ffs_types::ParseError::InsufficientData {
                needed: cmd_len,
                offset: cmd_data_start,
                actual: data.len().saturating_sub(cmd_data_start),
            });
        }

        let computed_crc = send_stream_command_crc32c(&data[command_start..cmd_end]);
        if computed_crc != expected_crc {
            return Err(ffs_types::ParseError::InvalidField {
                field: "send_stream_crc32c",
                reason: "command crc32c mismatch",
            });
        }

        let cmd_data = &data[pos..cmd_end];
        pos = cmd_end;

        let cmd = SendCommand::from_u16(cmd_type).unwrap_or(SendCommand::Unspec);
        let attrs = parse_send_stream_attrs(cmd_data, cmd_data_start)?;
        commands.push(SendStreamCommand { cmd, attrs });
        if cmd == SendCommand::End {
            saw_end = true;
            break;
        }
    }

    if pos < data.len() {
        if saw_end {
            return Err(ffs_types::ParseError::InvalidField {
                field: "send_stream",
                reason: "trailing bytes after end command",
            });
        }
        return Err(ffs_types::ParseError::InsufficientData {
            needed: 10,
            offset: pos,
            actual: data.len().saturating_sub(pos),
        });
    }

    if !saw_end {
        return Err(ffs_types::ParseError::InvalidField {
            field: "send_stream",
            reason: "missing end command",
        });
    }

    Ok(SendStreamParseResult { version, commands })
}

// ── btrfs tree-log replay ─────────────────────────────────────────────────

/// Result of scanning the btrfs tree-log.
///
/// The tree-log is a per-subvolume journal used for efficient fsync. When
/// present (superblock `log_root != 0`), it contains items that were fsynced
/// but not yet committed in a full transaction. On mount, the tree-log must
/// be replayed to bring the FS tree to the state of the last fsync.
#[derive(Debug, Clone, Default)]
pub struct TreeLogReplayResult {
    /// Items extracted from the tree-log, in key order.
    pub items: Vec<BtrfsLeafEntry>,
    /// Number of items replayed.
    pub items_count: usize,
    /// Whether a valid tree-log was found and replayed.
    pub replayed: bool,
}

/// Replay the btrfs tree-log if present.
///
/// Checks the superblock for a non-zero `log_root`. If present, walks the
/// tree-log tree and returns all items found. The caller is responsible for
/// merging these items into the FS tree (applying inode updates, directory
/// entries, and extent mappings).
///
/// The `read_physical` closure reads a physical byte range from the device.
/// If `log_root` is 0, returns an empty result (no tree-log to replay).
pub fn replay_tree_log(
    read_physical: &mut dyn FnMut(u64) -> Result<Vec<u8>, ParseError>,
    sb: &BtrfsSuperblock,
    chunks: &[BtrfsChunkEntry],
) -> Result<TreeLogReplayResult, ParseError> {
    if sb.log_root == 0 {
        return Ok(TreeLogReplayResult::default());
    }

    tracing::info!(
        log_root = sb.log_root,
        log_root_level = sb.log_root_level,
        "btrfs tree-log replay start"
    );

    let items = walk_tree(
        read_physical,
        chunks,
        sb.log_root,
        sb.nodesize,
        sb.csum_type,
    )?;

    tracing::info!(
        items_replayed = items.len(),
        "btrfs tree-log replay complete"
    );

    Ok(TreeLogReplayResult {
        items_count: items.len(),
        items,
        replayed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::{BtrfsStripe, BtrfsSuperblock};
    use proptest::prelude::*;
    use std::collections::{BTreeMap, HashMap};
    use std::fmt::Write as _;
    use std::sync::{Arc, Mutex};

    const NODESIZE: u32 = 4096;
    const HEADER_SIZE: usize = 101;
    const ITEM_SIZE: usize = 25;
    const KEY_PTR_SIZE: usize = 33;

    fn test_key(objectid: u64) -> BtrfsKey {
        BtrfsKey {
            objectid,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: 0,
        }
    }

    fn test_payload(objectid: u64) -> [u8; 1] {
        [u8::try_from(objectid).expect("test objectid should fit in u8")]
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut out, "{byte:02x}").expect("write to String");
        }
        out
    }

    /// Build a btrfs header in a block buffer.
    fn write_header(
        block: &mut [u8],
        bytenr: u64,
        nritems: u32,
        level: u8,
        owner: u64,
        generation: u64,
    ) {
        block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
        block[0x50..0x58].copy_from_slice(&generation.to_le_bytes());
        block[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;
    }

    fn stamp_tree_block_crc32c(block: &mut [u8]) {
        let csum = ffs_types::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
    }

    /// Write a leaf item entry at the given index.
    fn write_leaf_item(
        block: &mut [u8],
        idx: usize,
        objectid: u64,
        item_type: u8,
        data_off: u32,
        data_sz: u32,
    ) {
        let base = HEADER_SIZE + idx * ITEM_SIZE;
        let header_size = u32::try_from(HEADER_SIZE).expect("header size should fit in u32");
        let encoded_data_off = data_off
            .checked_sub(header_size)
            .expect("test leaf item data offset should be after header");
        block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
        block[base + 8] = item_type;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[base + 17..base + 21].copy_from_slice(&encoded_data_off.to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&data_sz.to_le_bytes());
    }

    fn write_leaf_item_payload(
        block: &mut [u8],
        idx: usize,
        objectid: u64,
        item_type: u8,
        data_off: u32,
        payload: &[u8],
    ) {
        let data_sz = u32::try_from(payload.len()).expect("test item payload length fits u32");
        write_leaf_item(block, idx, objectid, item_type, data_off, data_sz);
        let data_start = usize::try_from(data_off).expect("test data offset fits usize");
        let data_end = data_start
            .checked_add(payload.len())
            .expect("test item payload end fits usize");
        block[data_start..data_end].copy_from_slice(payload);
    }

    /// Write an internal key-pointer entry at the given index.
    fn write_key_ptr(
        block: &mut [u8],
        idx: usize,
        objectid: u64,
        item_type: u8,
        blockptr: u64,
        generation: u64,
    ) {
        let base = HEADER_SIZE + idx * KEY_PTR_SIZE;
        block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
        block[base + 8] = item_type;
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
        block[base + 25..base + 33].copy_from_slice(&generation.to_le_bytes());
    }

    /// Identity chunk: logical == physical for the range [0, 1GiB).
    fn identity_chunks() -> Vec<BtrfsChunkEntry> {
        vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0,
            },
            length: 0x4000_0000, // 1 GiB
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: 2,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0, // identity mapping
                dev_uuid: [0; 16],
            }],
        }]
    }

    #[test]
    fn walk_chunk_tree_rejects_invalid_chunk_item() {
        let root_logical = 0x4000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, root_logical, 1, 0, BTRFS_CHUNK_TREE_OBJECTID, 1);
        let data_off = NODESIZE.saturating_sub(16);
        write_leaf_item(&mut leaf, 0, 256, BTRFS_ITEM_CHUNK, data_off, 16);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let sb = BtrfsSuperblock {
            csum: [0; 32],
            fsid: [0; 16],
            bytenr: root_logical,
            flags: 0,
            magic: 0,
            generation: 1,
            root: 0,
            chunk_root: root_logical,
            log_root: 0,
            total_bytes: 0,
            bytes_used: 0,
            root_dir_objectid: 0,
            num_devices: 1,
            sectorsize: 4096,
            nodesize: NODESIZE,
            stripesize: 0,
            compat_flags: 0,
            compat_ro_flags: 0,
            incompat_flags: 0,
            csum_type: 0,
            root_level: 0,
            chunk_root_level: 0,
            log_root_level: 0,
            label: String::new(),
            sys_chunk_array_size: 0,
            sys_chunk_array: Vec::new(),
        };

        let err = walk_chunk_tree(&mut read, &sb, &chunks).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn walk_single_leaf() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 2, 0, 5, 10);
        // Item 0: key=(256,1,0), data at [3000..3010]
        write_leaf_item(&mut leaf, 0, 256, 1, 3000, 10);
        leaf[3000..3010].copy_from_slice(&[0xAA; 10]);
        // Item 1: key=(257,1,0), data at [3010..3025]
        write_leaf_item(&mut leaf, 1, 257, 1, 3010, 15);
        leaf[3010..3025].copy_from_slice(&[0xBB; 15]);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key.objectid, 256);
        assert_eq!(entries[0].data, vec![0xAA; 10]);
        assert_eq!(entries[1].key.objectid, 257);
        assert_eq!(entries[1].data, vec![0xBB; 15]);
    }

    #[test]
    fn walk_internal_plus_leaves() {
        let root_logical = 0x1_0000_u64;
        let left_logical = 0x2_0000_u64;
        let right_logical = 0x3_0000_u64;
        let chunks = identity_chunks();

        // Root: internal node (level=1) with 2 children
        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 2, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, left_logical, 10);
        write_key_ptr(&mut root, 1, 512, 1, right_logical, 10);

        // Leaf A: 1 item
        let mut left_leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut left_leaf, left_logical, 1, 0, 5, 10);
        write_leaf_item(&mut left_leaf, 0, 256, 1, 2000, 4);
        left_leaf[2000..2004].copy_from_slice(&[1, 2, 3, 4]);

        // Leaf B: 1 item
        let mut right_leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut right_leaf, right_logical, 1, 0, 5, 10);
        write_leaf_item(&mut right_leaf, 0, 512, 1, 2000, 4);
        right_leaf[2000..2004].copy_from_slice(&[5, 6, 7, 8]);

        stamp_tree_block_crc32c(&mut root);
        stamp_tree_block_crc32c(&mut left_leaf);
        stamp_tree_block_crc32c(&mut right_leaf);

        let blocks: HashMap<u64, Vec<u8>> = [
            (root_logical, root),
            (left_logical, left_leaf),
            (right_logical, right_leaf),
        ]
        .into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, root_logical, NODESIZE, 0).expect("walk");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key.objectid, 256);
        assert_eq!(entries[0].data, vec![1, 2, 3, 4]);
        assert_eq!(entries[1].key.objectid, 512);
        assert_eq!(entries[1].data, vec![5, 6, 7, 8]);
    }

    #[test]
    fn walk_unmapped_address_fails() {
        let chunks = identity_chunks();
        // Address beyond the 1GiB chunk range
        let far_logical = 0x8000_0000_u64;
        let mut read = |_phys: u64| -> Result<Vec<u8>, ParseError> {
            Err(ParseError::InvalidField {
                field: "unexpected_read",
                reason: "should not be called",
            })
        };
        let err = walk_tree(&mut read, &chunks, far_logical, NODESIZE, 0).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "logical_address",
                    ..
                }
            ),
            "expected unmapped error, got: {err:?}"
        );
    }

    #[test]
    fn walk_unaligned_root_fails() {
        let chunks = identity_chunks();
        let unaligned = 0x4_001_u64;
        let mut read = |_phys: u64| -> Result<Vec<u8>, ParseError> {
            Err(ParseError::InvalidField {
                field: "unexpected_read",
                reason: "should not be called",
            })
        };
        let err = walk_tree(&mut read, &chunks, unaligned, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "not aligned to nodesize",
            }
        ));
    }

    #[test]
    fn walk_unaligned_child_pointer_fails() {
        let root_logical = 0x1_0000_u64;
        let chunks = identity_chunks();
        let unaligned_child = 0x2_0001_u64;

        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 1, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, unaligned_child, 10);
        stamp_tree_block_crc32c(&mut root);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, root)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, root_logical, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "blockptr",
                reason: "not aligned to nodesize",
            }
        ));
    }

    #[test]
    fn walk_empty_leaf() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 0, 0, 5, 10);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk");
        assert!(entries.is_empty());
    }

    #[test]
    fn walk_self_cycle_fails_fast() {
        let root_logical = 0x1_0000_u64;
        let chunks = identity_chunks();

        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 1, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, root_logical, 10);
        stamp_tree_block_crc32c(&mut root);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, root)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, root_logical, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "cycle detected in btrfs tree pointers",
            }
        ));
    }

    #[test]
    fn walk_two_node_cycle_fails_fast() {
        let a_logical = 0x1_0000_u64;
        let b_logical = 0x2_0000_u64;
        let chunks = identity_chunks();

        let mut a = vec![0_u8; NODESIZE as usize];
        write_header(&mut a, a_logical, 1, 1, 1, 10);
        write_key_ptr(&mut a, 0, 256, 1, b_logical, 10);

        let mut b = vec![0_u8; NODESIZE as usize];
        write_header(&mut b, b_logical, 1, 1, 1, 10);
        write_key_ptr(&mut b, 0, 256, 1, a_logical, 10);

        stamp_tree_block_crc32c(&mut a);
        stamp_tree_block_crc32c(&mut b);

        let blocks: HashMap<u64, Vec<u8>> = [(a_logical, a), (b_logical, b)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, a_logical, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "cycle detected in btrfs tree pointers",
            }
        ));
    }

    #[test]
    fn walk_duplicate_child_reference_fails_fast() {
        let root_logical = 0x1_0000_u64;
        let leaf_logical = 0x2_0000_u64;
        let chunks = identity_chunks();

        let mut root = vec![0_u8; NODESIZE as usize];
        write_header(&mut root, root_logical, 2, 1, 1, 10);
        write_key_ptr(&mut root, 0, 256, 1, leaf_logical, 10);
        write_key_ptr(&mut root, 1, 512, 1, leaf_logical, 10);

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, leaf_logical, 0, 0, 5, 10);

        stamp_tree_block_crc32c(&mut root);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(root_logical, root), (leaf_logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let err = walk_tree(&mut read, &chunks, root_logical, NODESIZE, 0).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "logical_address",
                reason: "duplicate node reference in btrfs tree pointers",
            }
        ));
    }

    #[test]
    fn cow_insert_preserves_previous_root_node() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        tree.insert(test_key(10), b"a").expect("insert first");
        let root_before = tree.root_block();
        let snapshot = tree.node_snapshot(root_before).expect("snapshot");

        tree.insert(test_key(20), b"b").expect("insert second");
        let root_after = tree.root_block();
        assert_ne!(root_before, root_after);
        assert_eq!(
            tree.node_snapshot(root_before).expect("snapshot old root"),
            snapshot
        );
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_mutations_record_deferred_node_frees() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        tree.insert(test_key(1), b"a").expect("insert 1");
        assert!(
            !tree.deferred_free_blocks().is_empty(),
            "initial mutation should retire prior root"
        );
        let deferred_before_delete = tree.deferred_free_blocks().len();
        tree.insert(test_key(2), b"b").expect("insert 2");
        tree.delete(&test_key(2)).expect("delete 2");
        assert!(
            tree.deferred_free_blocks().len() > deferred_before_delete,
            "delete path should retire replaced COW nodes"
        );
    }

    #[test]
    fn insert_split_creates_internal_root() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Internal { .. }
        ));
        let entries = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![10, 20, 30, 40]);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_shrinks_to_leaf_root() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in 1_u64..=8 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }
        let height_before = tree.height().expect("height before");

        for objectid in 2_u64..=8 {
            tree.delete(&test_key(objectid)).expect("delete");
        }

        let height_after = tree.height().expect("height after");
        assert!(height_after <= height_before);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Leaf { .. }
        ));
        let entries = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.objectid, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_underflow_borrows_from_right_sibling() {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("tree");
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        tree.delete(&test_key(1)).expect("delete");
        let keys = tree
            .range(&test_key(0), &test_key(10))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![2, 3, 4, 5]);
        assert_eq!(tree.height().expect("height"), 2);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_underflow_borrows_from_left_sibling() {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("tree");
        for objectid in [10_u64, 20, 30, 40, 50, 5] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }
        tree.delete(&test_key(50)).expect("seed delete");

        tree.delete(&test_key(40)).expect("left borrow delete");
        let keys = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![5, 10, 20, 30]);
        assert_eq!(tree.height().expect("height"), 2);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Internal { .. }
        ));
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_underflow_merges_and_shrinks_root() {
        let mut tree = InMemoryCowBtrfsTree::new(4).expect("tree");
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        tree.delete(&test_key(5)).expect("delete first");
        tree.delete(&test_key(4)).expect("delete second");
        let keys = tree
            .range(&test_key(0), &test_key(10))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![1, 2, 3]);
        assert_eq!(tree.height().expect("height"), 1);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Leaf { .. }
        ));
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn delete_missing_key_returns_error() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        tree.insert(test_key(1), b"a").expect("insert");
        let err = tree.delete(&test_key(999)).expect_err("delete should fail");
        assert_eq!(err, BtrfsMutationError::KeyNotFound);
    }

    #[test]
    fn update_replaces_existing_value() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let key = test_key(9);
        tree.insert(key, b"old").expect("insert");
        tree.update(&key, b"new").expect("update");
        let entries = tree.range(&key, &key).expect("point range");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"new");
    }

    #[test]
    fn update_internal_child_rewrites_parent_and_preserves_order() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }
        assert_eq!(tree.height().expect("height before"), 2);
        let root_before = tree.root_block();
        let root_snapshot = tree.node_snapshot(root_before).expect("root snapshot");

        tree.update(&test_key(20), b"updated")
            .expect("update internal child");

        assert_ne!(tree.root_block(), root_before);
        assert_eq!(
            tree.node_snapshot(root_before).expect("old root snapshot"),
            root_snapshot
        );
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("new root snapshot"),
            BtrfsCowNode::Internal { .. }
        ));
        let entries = tree
            .range(&test_key(0), &test_key(100))
            .expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![10, 20, 30, 40]);
        assert_eq!(entries[0].1, test_payload(10));
        assert_eq!(entries[1].1, b"updated");
        assert_eq!(entries[2].1, test_payload(30));
        assert_eq!(entries[3].1, test_payload(40));
        assert_eq!(tree.height().expect("height after"), 2);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn range_returns_inclusive_sorted_window() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        for objectid in 1_u64..=6 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        let entries = tree.range(&test_key(2), &test_key(4)).expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![2, 3, 4]);
    }

    #[test]
    fn range_descends_multi_level_tree_without_full_materialisation() {
        // With max_items=3, inserting 40 keys forces several internal levels.
        // The range scan must descend B-tree-aware (skipping children whose
        // separator span is outside [start, end]) instead of materialising
        // the entire tree. The semantic check is that range() returns
        // exactly the keys in the window; the complexity improvement is
        // validated separately by the bd-yt66z resolve-path tests.
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        for objectid in 0_u64..40 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("insert");
        }

        // Window in the middle of the tree — must span multiple leaves and
        // skip both left and right subtrees.
        let entries = tree
            .range(&test_key(12), &test_key(27))
            .expect("range query");
        let keys = entries
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, (12_u64..=27).collect::<Vec<_>>());

        // Window below the smallest key — must return empty without error.
        let empty = tree
            .range(
                &BtrfsKey {
                    objectid: 0,
                    item_type: 0,
                    offset: 0,
                },
                &BtrfsKey {
                    objectid: 0,
                    item_type: 0,
                    offset: u64::MAX,
                },
            )
            .expect("range below tree");
        assert!(
            empty.is_empty(),
            "range below tree span must be empty, got {empty:?}"
        );

        // Window above the largest key — also empty.
        let empty = tree
            .range(&test_key(100), &test_key(200))
            .expect("range above tree");
        assert!(empty.is_empty());

        // Exact-single-key range returns just that key.
        let one = tree.range(&test_key(17), &test_key(17)).expect("point");
        let one_keys = one.iter().map(|(key, _)| key.objectid).collect::<Vec<_>>();
        assert_eq!(one_keys, vec![17_u64]);
    }

    #[test]
    fn random_mutations_preserve_invariants_and_ordering() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let mut model = BTreeMap::<u64, u8>::new();
        let mut state = 0xD1CE_D00D_CAFE_BABEu64;

        for _ in 0..1000 {
            // LCG for deterministic pseudo-random operations without extra deps.
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let objectid = (state % 128) + 1;
            let op = state % 3;
            let payload = [u8::try_from(objectid).expect("objectid should fit u8")];
            let key = test_key(objectid);

            match op {
                0 => {
                    if tree.insert(key, &payload).is_ok() {
                        model.insert(objectid, payload[0]);
                    }
                }
                1 => {
                    if tree.update(&key, &payload).is_ok() {
                        model.insert(objectid, payload[0]);
                    }
                }
                _ => {
                    if tree.delete(&key).is_ok() {
                        model.remove(&objectid);
                    }
                }
            }

            tree.validate_invariants().expect("invariants after op");
            let observed = tree
                .range(&test_key(0), &test_key(u64::MAX))
                .expect("full range");
            let observed_keys = observed
                .iter()
                .map(|(entry_key, _)| entry_key.objectid)
                .collect::<Vec<_>>();
            let model_keys = model.keys().copied().collect::<Vec<_>>();
            assert_eq!(observed_keys, model_keys);
        }
    }

    #[test]
    fn cow_adversarial_duplicate_insert_short_circuits_without_mutation() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        tree.insert(test_key(10), b"old").expect("seed insert");

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .insert(test_key(10), b"duplicate")
            .expect_err("duplicate insert should short-circuit before allocation");
        assert_eq!(err, BtrfsMutationError::KeyAlreadyExists);
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after duplicate insert"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_missing_update_short_circuits_without_mutation() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .update(&test_key(40), b"missing")
            .expect_err("missing update should short-circuit before allocation");
        assert_eq!(err, BtrfsMutationError::KeyNotFound);
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after missing update"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_missing_delete_short_circuits_without_mutation() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        assert_eq!(tree.height().expect("height"), 2);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .delete(&test_key(25))
            .expect_err("missing delete should short-circuit before allocation");
        assert_eq!(err, BtrfsMutationError::KeyNotFound);
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after missing delete"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_leaf_split_left_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .insert(test_key(40), b"d")
            .expect_err("left split allocation should fail before publishing a root");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed left split allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_leaf_split_right_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .insert(test_key(40), b"d")
            .expect_err("right split allocation should fail before publishing a root");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed right split allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_root_split_allocator_failure_is_not_visible() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(2));
        let err = tree
            .insert(test_key(40), b"d")
            .expect_err("new root allocation should fail after split children allocate");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed split"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 2);
        tree.validate_invariants().expect("invariants");
    }

    fn seed_cow_tree_for_internal_split(tree: &mut InMemoryCowBtrfsTree) {
        for objectid in [10_u64, 20, 30, 40, 50, 60, 70, 80, 90] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        assert_eq!(tree.height().expect("height"), 2);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Internal { keys, .. } if keys.len() == 3
        ));
    }

    #[test]
    fn cow_insert_internal_split_creates_higher_root_and_preserves_order() {
        let mut tree = InMemoryCowBtrfsTree::new(3).expect("tree");
        seed_cow_tree_for_internal_split(&mut tree);

        tree.insert(test_key(100), &test_payload(100))
            .expect("insert triggering internal split");

        assert_eq!(tree.height().expect("height"), 3);
        assert!(matches!(
            tree.node_snapshot(tree.root_block())
                .expect("root snapshot"),
            BtrfsCowNode::Internal { keys, children } if keys.len() == 1 && children.len() == 2
        ));
        let keys = tree
            .range(&test_key(0), &test_key(200))
            .expect("range query")
            .iter()
            .map(|(key, _)| key.objectid)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_internal_split_left_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        seed_cow_tree_for_internal_split(&mut tree);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(200))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(2));
        let err = tree
            .insert(test_key(100), &test_payload(100))
            .expect_err("left internal split allocation should fail after leaf split allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(200))
                .expect("range after failed internal split left allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 2);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_internal_split_right_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        seed_cow_tree_for_internal_split(&mut tree);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(200))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(3));
        let err = tree.insert(test_key(100), &test_payload(100)).expect_err(
            "right internal split allocation should fail after left internal allocates",
        );
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(200))
                .expect("range after failed internal split right allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 3);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_internal_root_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        seed_cow_tree_for_internal_split(&mut tree);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(200))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(4));
        let err = tree
            .insert(test_key(100), &test_payload(100))
            .expect_err("new root allocation should fail after internal split allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(200))
                .expect("range after failed internal root allocation"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 4);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_parent_rewrite_allocator_failure_does_not_retire_live_child() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        assert_eq!(tree.height().expect("height"), 2);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .insert(test_key(25), b"new")
            .expect_err("parent rewrite allocation should fail after child rewrite allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed parent rewrite"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_delete_borrow_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator_max(4);
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(10))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .delete(&test_key(1))
            .expect_err("right-borrow allocation should fail after child rewrite allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(10))
                .expect("range after failed delete borrow"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_delete_left_borrow_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator_max(4);
        for objectid in [10_u64, 20, 30, 40, 50, 5] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        tree.delete(&test_key(50)).expect("seed delete");

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .delete(&test_key(40))
            .expect_err("left-borrow allocation should fail after child rewrite allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed delete left borrow"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_delete_merge_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator_max(4);
        for objectid in 1_u64..=5 {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        tree.delete(&test_key(5)).expect("seed delete");

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(10))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(2));
        let err = tree
            .delete(&test_key(4))
            .expect_err("parent allocation should fail after merge allocation");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(10))
                .expect("range after failed delete merge"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 2);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_update_leaf_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        tree.insert(test_key(10), b"old").expect("seed insert");

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(0));
        let err = tree
            .update(&test_key(10), b"new")
            .expect_err("leaf update allocation should fail");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed leaf update"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 0);
        tree.validate_invariants().expect("invariants");
    }

    #[test]
    fn cow_adversarial_update_parent_rewrite_allocator_failure_preserves_visible_tree() {
        let (mut tree, allocator_state) = cow_tree_with_shared_allocator();
        for objectid in [10_u64, 20, 30, 40] {
            tree.insert(test_key(objectid), &test_payload(objectid))
                .expect("seed insert");
        }
        assert_eq!(tree.height().expect("height"), 2);

        let root_before = tree.root_block();
        let entries_before = tree
            .range(&test_key(0), &test_key(100))
            .expect("range before");
        let deferred_before = tree.deferred_free_blocks().len();
        let allocator_deferred_before = allocator_deferred_len(&allocator_state);

        set_allocator_remaining_successes(&allocator_state, Some(1));
        let err = tree
            .update(&test_key(20), b"updated")
            .expect_err("parent rewrite allocation should fail after update child allocates");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("injected allocation failure")
        );
        set_allocator_remaining_successes(&allocator_state, None);

        assert_eq!(tree.root_block(), root_before);
        assert_eq!(
            tree.range(&test_key(0), &test_key(100))
                .expect("range after failed parent update"),
            entries_before
        );
        assert_eq!(tree.deferred_free_blocks().len(), deferred_before);
        assert_allocator_deferred_delta(&allocator_state, allocator_deferred_before, 1);
        tree.validate_invariants().expect("invariants");
    }

    fn lcg_next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *state
    }

    fn payload_from_rng(rand: u64, case: usize) -> Vec<u8> {
        let case_u64 = u64::try_from(case).expect("case should fit u64");
        (rand ^ case_u64).to_le_bytes().to_vec()
    }

    #[derive(Debug)]
    struct FailAllocatorState {
        next_block: u64,
        remaining_successful_allocs: Option<usize>,
        deferred: Vec<u64>,
    }

    #[derive(Debug)]
    struct SharedFailAllocator {
        state: Arc<Mutex<FailAllocatorState>>,
    }

    impl SharedFailAllocator {
        fn new(state: Arc<Mutex<FailAllocatorState>>) -> Self {
            Self { state }
        }
    }

    impl BtrfsAllocator for SharedFailAllocator {
        fn alloc_block(&mut self) -> Result<u64, BtrfsMutationError> {
            let mut state = lock_fail_allocator_state(&self.state);
            if let Some(remaining) = &mut state.remaining_successful_allocs {
                if *remaining == 0 {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "injected allocation failure",
                    ));
                }
                *remaining -= 1;
            }
            let block = state.next_block;
            state.next_block = state
                .next_block
                .checked_add(1)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            drop(state);
            Ok(block)
        }

        fn defer_free(&mut self, block: u64) {
            lock_fail_allocator_state(&self.state).deferred.push(block);
        }
    }

    fn cow_tree_with_shared_allocator() -> (InMemoryCowBtrfsTree, Arc<Mutex<FailAllocatorState>>) {
        cow_tree_with_shared_allocator_max(3)
    }

    fn cow_tree_with_shared_allocator_max(
        max_items: usize,
    ) -> (InMemoryCowBtrfsTree, Arc<Mutex<FailAllocatorState>>) {
        let state = Arc::new(Mutex::new(FailAllocatorState {
            next_block: 2,
            remaining_successful_allocs: None,
            deferred: Vec::new(),
        }));
        let tree = InMemoryCowBtrfsTree::with_allocator(
            max_items,
            Box::new(SharedFailAllocator::new(Arc::clone(&state))),
        )
        .expect("tree");
        (tree, state)
    }

    fn set_allocator_remaining_successes(
        state: &Arc<Mutex<FailAllocatorState>>,
        remaining: Option<usize>,
    ) {
        lock_fail_allocator_state(state).remaining_successful_allocs = remaining;
    }

    fn allocator_deferred_len(state: &Arc<Mutex<FailAllocatorState>>) -> usize {
        lock_fail_allocator_state(state).deferred.len()
    }

    fn assert_allocator_deferred_delta(
        state: &Arc<Mutex<FailAllocatorState>>,
        before: usize,
        expected_delta: usize,
    ) {
        assert_eq!(allocator_deferred_len(state), before + expected_delta);
    }

    fn lock_fail_allocator_state(
        state: &Arc<Mutex<FailAllocatorState>>,
    ) -> std::sync::MutexGuard<'_, FailAllocatorState> {
        match state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn assert_extent_non_overlap(
        allocations: &BTreeMap<u64, ExtentAllocation>,
        candidate: ExtentAllocation,
        seed: u64,
        case: usize,
    ) {
        for existing in allocations.values() {
            let candidate_end = candidate
                .bytenr
                .checked_add(candidate.num_bytes)
                .expect("candidate extent end overflow");
            let existing_end = existing
                .bytenr
                .checked_add(existing.num_bytes)
                .expect("existing extent end overflow");
            let disjoint = candidate_end <= existing.bytenr || existing_end <= candidate.bytenr;
            assert!(
                disjoint,
                "overlapping extents detected seed={seed:#x} case={case}: candidate={candidate:?} existing={existing:?}"
            );
        }
    }

    fn run_cow_property(seed: u64, cases: usize) {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let mut model = BTreeMap::<u64, Vec<u8>>::new();
        let mut state = seed;

        for case in 0..cases {
            let rand = lcg_next(&mut state);
            let objectid = (rand % 256) + 1;
            let key = test_key(objectid);
            let payload = payload_from_rng(rand, case);

            match rand % 3 {
                0 => {
                    let result = tree.insert(key, &payload);
                    if result.is_ok() {
                        model.insert(objectid, payload.clone());
                    } else {
                        assert_eq!(
                            result.expect_err("duplicate insert should fail"),
                            BtrfsMutationError::KeyAlreadyExists
                        );
                    }
                }
                1 => {
                    let result = tree.update(&key, &payload);
                    if let std::collections::btree_map::Entry::Occupied(mut entry) =
                        model.entry(objectid)
                    {
                        result.expect("update existing key");
                        entry.insert(payload.clone());
                    } else {
                        assert_eq!(
                            result.expect_err("update on missing key should fail"),
                            BtrfsMutationError::KeyNotFound
                        );
                    }
                }
                _ => {
                    let result = tree.delete(&key);
                    if model.remove(&objectid).is_some() {
                        result.expect("delete existing key");
                    } else {
                        assert_eq!(
                            result.expect_err("delete on missing key should fail"),
                            BtrfsMutationError::KeyNotFound
                        );
                    }
                }
            }

            tree.validate_invariants()
                .expect("tree invariants after random operation");
            let observed = tree
                .range(&test_key(0), &test_key(u64::MAX))
                .expect("full tree range");
            let observed_pairs = observed
                .into_iter()
                .map(|(entry_key, data)| (entry_key.objectid, data))
                .collect::<Vec<_>>();
            let model_pairs = model
                .iter()
                .map(|(objectid, data)| (*objectid, data.clone()))
                .collect::<Vec<_>>();
            assert_eq!(
                observed_pairs, model_pairs,
                "cow model mismatch seed={seed:#x} case={case}"
            );
        }
    }

    fn run_allocator_property(seed: u64, cases: usize) {
        let mut alloc = BtrfsExtentAllocator::new(99).expect("allocator");
        let bg_a = 0x1_0000_u64;
        let bg_b = 0x5_0000_u64;
        alloc.add_block_group(bg_a, make_data_bg(bg_a, 0x40_000));
        alloc.add_block_group(bg_b, make_data_bg(bg_b, 0x40_000));

        let mut expected_used = BTreeMap::from([(bg_a, 0_u64), (bg_b, 0_u64)]);
        let mut live = BTreeMap::<u64, ExtentAllocation>::new();
        let mut state = seed;
        let sizes = [4096_u64, 8192, 12_288, 16_384];

        for case in 0..cases {
            let rand = lcg_next(&mut state);
            let should_free = (rand & 1) == 1 && !live.is_empty();

            if should_free {
                let idx = usize::try_from(rand).expect("rand should fit usize") % live.len();
                let extent = *live
                    .values()
                    .nth(idx)
                    .expect("index into live allocation set");
                alloc
                    .free_extent(extent.bytenr, extent.num_bytes, false)
                    .expect("free extent");
                live.remove(&extent.bytenr);
                let used = expected_used
                    .get_mut(&extent.block_group_start)
                    .expect("expected block group key");
                *used = used.saturating_sub(extent.num_bytes);
            } else {
                let size_idx = usize::try_from(rand).expect("rand should fit usize") % sizes.len();
                let size = sizes[size_idx];
                if let Ok(extent) = alloc.alloc_data(size) {
                    assert_extent_non_overlap(&live, extent, seed, case);
                    live.insert(extent.bytenr, extent);
                    let used = expected_used
                        .get_mut(&extent.block_group_start)
                        .expect("expected block group key");
                    *used = used.saturating_add(extent.num_bytes);
                }
            }

            for (bg, used) in &expected_used {
                let observed = alloc.block_group(*bg).expect("block group").used_bytes;
                assert_eq!(
                    observed, *used,
                    "allocator accounting mismatch seed={seed:#x} case={case} block_group={bg:#x}"
                );
            }
        }

        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush delayed refs");
        for extent in live.values() {
            let key = ExtentKey {
                bytenr: extent.bytenr,
                num_bytes: extent.num_bytes,
            };
            assert_eq!(
                alloc.extent_refcount(key),
                1,
                "live extent must have refcount=1 seed={seed:#x}"
            );
        }
    }

    fn run_delayed_ref_property(seed: u64, cases: usize) {
        let mut queue = DelayedRefQueue::new();
        let mut model = BTreeMap::<ExtentKey, u64>::new();
        let extents = (0_u64..64)
            .map(|idx| ExtentKey {
                bytenr: 0x10_0000 + idx * 4096,
                num_bytes: 4096,
            })
            .collect::<Vec<_>>();

        let mut state = seed;
        for case in 0..cases {
            let rand = lcg_next(&mut state);
            let extent_idx = usize::try_from(rand).expect("rand should fit usize") % extents.len();
            let extent = extents[extent_idx];
            let current = model.get(&extent).copied().unwrap_or(0);
            let delete = (rand & 1) == 1 && current > 0;
            let ref_type = match rand % 4 {
                0 => BtrfsRef::DataExtent {
                    root: BTRFS_FS_TREE_OBJECTID,
                    objectid: extent.bytenr,
                    offset: extent.num_bytes,
                },
                1 => BtrfsRef::SharedDataExtent {
                    parent: extent.bytenr,
                },
                2 => BtrfsRef::TreeBlock {
                    root: BTRFS_EXTENT_TREE_OBJECTID,
                    owner: extent.bytenr,
                    offset: extent.num_bytes,
                    level: 0,
                },
                _ => BtrfsRef::SharedTreeBlock {
                    parent: extent.bytenr,
                    level: 0,
                },
            };
            let action = if delete {
                RefAction::Delete
            } else {
                RefAction::Insert
            };
            queue.queue(extent, ref_type, action);

            if delete {
                let updated = current - 1;
                if updated == 0 {
                    model.remove(&extent);
                } else {
                    model.insert(extent, updated);
                }
            } else {
                model.insert(extent, current + 1);
            }

            if case % 250 == 0 {
                assert_eq!(
                    queue.pending_count(),
                    case + 1,
                    "queue size mismatch seed={seed:#x} case={case}"
                );
            }
        }

        let mut observed = BTreeMap::new();
        let flushed = queue
            .flush(usize::MAX, &mut observed)
            .expect("flush delayed refs");
        assert_eq!(flushed, cases);
        assert_eq!(observed, model);
    }

    fn run_transaction_property(seed: u64, cases: usize) {
        let cx = Cx::for_request();
        let mut harness = TxPropertyHarness::new();
        let mut state = seed;

        for case in 0..cases {
            let rand = lcg_next(&mut state);
            match rand % 4 {
                0 => harness.commit_single(rand, case, &cx),
                1 => harness.abort_single(rand, case, &cx),
                2 => harness.commit_disjoint_pair(rand, case, &cx),
                _ => harness.conflict_pair(rand, case, &cx),
            }
            harness.assert_sample_visible(rand, seed, case);
        }

        harness.assert_all_visible();
    }

    #[derive(Debug, Default)]
    struct TxPropertyHarness {
        store: MvccStore,
        expected: BTreeMap<u64, Vec<u8>>,
        expected_commit_seq: u64,
    }

    impl TxPropertyHarness {
        fn new() -> Self {
            Self::default()
        }

        fn commit_single(&mut self, rand: u64, case: usize, cx: &Cx) {
            let tree_id = if (rand & 1) == 0 {
                BTRFS_FS_TREE_OBJECTID
            } else {
                BTRFS_EXTENT_TREE_OBJECTID
            };
            let block = BlockNumber(0x20_000 + (rand % 128));
            let payload = payload_from_rng(rand.rotate_left(7), case);
            let mut txn = BtrfsTransaction::begin(&mut self.store, 100 + rand, cx)
                .expect("begin transaction");
            txn.stage_tree_root(
                tree_id,
                TreeRoot {
                    bytenr: 0x1000_0000 + rand,
                    level: u8::try_from(rand % 3).expect("level should fit u8"),
                },
            );
            txn.stage_block_write(block, payload.clone())
                .expect("stage write");
            let seq = txn.commit(&mut self.store, cx).expect("commit transaction");
            self.expected_commit_seq = self.expected_commit_seq.saturating_add(1);
            assert_eq!(seq.0, self.expected_commit_seq);
            self.expected.insert(block.0, payload);
        }

        fn abort_single(&mut self, rand: u64, case: usize, cx: &Cx) {
            let block = BlockNumber(0x21_000 + (rand % 128));
            let mut txn = BtrfsTransaction::begin(&mut self.store, 200 + rand, cx)
                .expect("begin transaction");
            txn.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x2000_0000 + rand,
                    level: 1,
                },
            );
            txn.stage_block_write(block, payload_from_rng(rand, case))
                .expect("stage write");
            let _ = txn.abort();
        }

        fn commit_disjoint_pair(&mut self, rand: u64, case: usize, cx: &Cx) {
            let mut tx1 =
                BtrfsTransaction::begin(&mut self.store, 300 + rand, cx).expect("begin tx1");
            let mut tx2 =
                BtrfsTransaction::begin(&mut self.store, 300 + rand, cx).expect("begin tx2");
            let block1 = BlockNumber(0x22_000 + (rand % 64));
            let block2 = BlockNumber(0x23_000 + (rand % 64));
            let payload1 = payload_from_rng(rand, case);
            let payload2 = payload_from_rng(rand.rotate_left(13), case);

            tx1.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x3000_0000 + rand,
                    level: 0,
                },
            );
            tx1.stage_block_write(block1, payload1.clone())
                .expect("stage tx1 write");

            tx2.stage_tree_root(
                BTRFS_EXTENT_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x3100_0000 + rand,
                    level: 0,
                },
            );
            tx2.stage_block_write(block2, payload2.clone())
                .expect("stage tx2 write");

            let s1 = tx1.commit(&mut self.store, cx).expect("commit tx1");
            let s2 = tx2.commit(&mut self.store, cx).expect("commit tx2");
            self.expected_commit_seq = self.expected_commit_seq.saturating_add(2);
            assert_eq!(s2.0, self.expected_commit_seq);
            assert_eq!(s1.0 + 1, s2.0);
            self.expected.insert(block1.0, payload1);
            self.expected.insert(block2.0, payload2);
        }

        fn conflict_pair(&mut self, rand: u64, case: usize, cx: &Cx) {
            let mut tx1 =
                BtrfsTransaction::begin(&mut self.store, 400 + rand, cx).expect("begin tx1");
            let mut tx2 =
                BtrfsTransaction::begin(&mut self.store, 400 + rand, cx).expect("begin tx2");
            let block = BlockNumber(0x24_000 + (rand % 64));
            let payload1 = payload_from_rng(rand, case);
            let payload2 = payload_from_rng(rand.rotate_right(11), case);

            tx1.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x3200_0000 + rand,
                    level: 1,
                },
            );
            tx2.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x3210_0000 + rand,
                    level: 1,
                },
            );
            tx1.stage_block_write(block, payload1.clone())
                .expect("stage tx1 write");
            tx2.stage_block_write(block, payload2)
                .expect("stage tx2 write");

            let s1 = tx1.commit(&mut self.store, cx).expect("commit tx1");
            self.expected_commit_seq = self.expected_commit_seq.saturating_add(1);
            assert_eq!(s1.0, self.expected_commit_seq);
            self.expected.insert(block.0, payload1);

            let err = tx2.commit(&mut self.store, cx).expect_err("tx2 conflict");
            assert!(
                matches!(
                    err,
                    BtrfsTransactionError::Commit(CommitError::Conflict { .. })
                ),
                "expected FCW conflict, got {err:?}"
            );
        }

        fn assert_sample_visible(&self, rand: u64, seed: u64, case: usize) {
            if self.expected.is_empty() {
                return;
            }
            let sample_idx =
                usize::try_from(rand).expect("rand should fit usize") % self.expected.len();
            let (block, payload) = self
                .expected
                .iter()
                .nth(sample_idx)
                .expect("sample expected payload");
            let snapshot = self.store.current_snapshot();
            let observed = self
                .store
                .read_visible(BlockNumber(*block), snapshot)
                .expect("sample payload should be visible");
            assert_eq!(
                observed, *payload,
                "transaction sample mismatch seed={seed:#x} case={case} block={block}"
            );
        }

        fn assert_all_visible(&self) {
            let snapshot = self.store.current_snapshot();
            for (block, payload) in &self.expected {
                let observed = self
                    .store
                    .read_visible(BlockNumber(*block), snapshot)
                    .expect("payload should be visible");
                assert_eq!(observed, *payload);
            }
        }
    }

    #[test]
    fn property_cow_seed_01_1000_cases() {
        run_cow_property(0x000A_11CE_0001, 1000);
    }

    #[test]
    fn property_cow_seed_02_1000_cases() {
        run_cow_property(0x000A_11CE_0002, 1000);
    }

    #[test]
    fn property_cow_seed_03_1000_cases() {
        run_cow_property(0x000A_11CE_0003, 1000);
    }

    #[test]
    fn property_cow_seed_04_1000_cases() {
        run_cow_property(0x000A_11CE_0004, 1000);
    }

    #[test]
    fn property_cow_seed_05_1000_cases() {
        run_cow_property(0x000A_11CE_0005, 1000);
    }

    #[test]
    fn property_allocator_seed_01_1000_cases() {
        run_allocator_property(0xB00C_A001, 1000);
    }

    #[test]
    fn property_allocator_seed_02_1000_cases() {
        run_allocator_property(0xB00C_A002, 1000);
    }

    #[test]
    fn property_delayed_refs_seed_01_1000_cases() {
        run_delayed_ref_property(0xC001_D001, 1000);
    }

    #[test]
    fn property_delayed_refs_seed_02_1000_cases() {
        run_delayed_ref_property(0xC001_D002, 1000);
    }

    #[test]
    fn property_transactions_seed_01_1000_cases() {
        run_transaction_property(0xD00D_1001, 1000);
    }

    #[test]
    fn integration_create_path_commits_inode_dir_and_extent_data() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut alloc = BtrfsExtentAllocator::new(1).expect("allocator");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x20_000));
        let extent = alloc.alloc_data(4096).expect("allocate data extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush delayed refs");
        assert_eq!(
            alloc.extent_refcount(ExtentKey {
                bytenr: extent.bytenr,
                num_bytes: extent.num_bytes
            }),
            1
        );

        let mut txn = BtrfsTransaction::begin(&mut store, 1, &cx).expect("begin transaction");
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5000_0000,
                level: 1,
            },
        );
        txn.stage_block_write(BlockNumber(30_001), b"inode:256:size=11".to_vec())
            .expect("stage inode");
        txn.stage_block_write(BlockNumber(30_002), b"dir:/file.txt->256".to_vec())
            .expect("stage directory entry");
        txn.stage_block_write(BlockNumber(30_003), b"hello world".to_vec())
            .expect("stage file payload");
        txn.queue_delayed_ref(
            ExtentKey {
                bytenr: extent.bytenr,
                num_bytes: extent.num_bytes,
            },
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );

        let seq = txn.commit(&mut store, &cx).expect("commit");
        assert_eq!(seq, CommitSeq(1));
        let snapshot = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(BlockNumber(30_001), snapshot)
                .expect("inode visible"),
            b"inode:256:size=11".to_vec()
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(30_002), snapshot)
                .expect("dir entry visible"),
            b"dir:/file.txt->256".to_vec()
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(30_003), snapshot)
                .expect("payload visible"),
            b"hello world".to_vec()
        );
    }

    #[test]
    fn integration_delete_path_frees_extent_and_updates_directory() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut alloc = BtrfsExtentAllocator::new(2).expect("allocator");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x20_000));
        let extent = alloc.alloc_data(4096).expect("allocate data extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush delayed refs");

        let mut create_tx = BtrfsTransaction::begin(&mut store, 2, &cx).expect("begin create");
        create_tx.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5100_0000,
                level: 1,
            },
        );
        create_tx
            .stage_block_write(BlockNumber(31_001), b"dir:/tmp.bin->512".to_vec())
            .expect("stage dir entry");
        create_tx
            .stage_block_write(BlockNumber(31_002), b"inode:512:size=4096".to_vec())
            .expect("stage inode");
        create_tx.commit(&mut store, &cx).expect("commit create");

        alloc
            .free_extent(extent.bytenr, extent.num_bytes, false)
            .expect("free data extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush delayed refs");
        assert_eq!(
            alloc.extent_refcount(ExtentKey {
                bytenr: extent.bytenr,
                num_bytes: extent.num_bytes
            }),
            0
        );

        let mut delete_tx = BtrfsTransaction::begin(&mut store, 3, &cx).expect("begin delete");
        delete_tx.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5200_0000,
                level: 1,
            },
        );
        delete_tx
            .stage_block_write(BlockNumber(31_001), b"dir:/tmp.bin-><deleted>".to_vec())
            .expect("stage dir tombstone");
        delete_tx
            .stage_block_write(BlockNumber(31_002), b"inode:512:<deleted>".to_vec())
            .expect("stage inode tombstone");
        delete_tx.commit(&mut store, &cx).expect("commit delete");

        let snapshot = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(BlockNumber(31_001), snapshot)
                .expect("dir tombstone visible")
                .as_ref(),
            b"dir:/tmp.bin-><deleted>"
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(31_002), snapshot)
                .expect("inode tombstone visible")
                .as_ref(),
            b"inode:512:<deleted>"
        );
    }

    #[test]
    fn integration_overwrite_path_replaces_extent_and_payload_atomically() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut alloc = BtrfsExtentAllocator::new(4).expect("allocator");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x40_000));

        let old_extent = alloc.alloc_data(4096).expect("allocate old extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush old extent delayed refs");

        let mut tx1 = BtrfsTransaction::begin(&mut store, 4, &cx).expect("begin tx1");
        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5300_0000,
                level: 1,
            },
        );
        tx1.stage_block_write(BlockNumber(32_001), b"payload:old".to_vec())
            .expect("stage old payload");
        tx1.commit(&mut store, &cx).expect("commit tx1");

        let new_extent = alloc.alloc_data(4096).expect("allocate new extent");
        alloc
            .free_extent(old_extent.bytenr, old_extent.num_bytes, false)
            .expect("free old extent");
        alloc
            .flush_delayed_refs(usize::MAX)
            .expect("flush overwrite delayed refs");
        assert_eq!(
            alloc.extent_refcount(ExtentKey {
                bytenr: old_extent.bytenr,
                num_bytes: old_extent.num_bytes
            }),
            0
        );
        assert_eq!(
            alloc.extent_refcount(ExtentKey {
                bytenr: new_extent.bytenr,
                num_bytes: new_extent.num_bytes
            }),
            1
        );

        let mut tx2 = BtrfsTransaction::begin(&mut store, 5, &cx).expect("begin tx2");
        tx2.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5400_0000,
                level: 1,
            },
        );
        tx2.stage_block_write(BlockNumber(32_001), b"payload:new".to_vec())
            .expect("stage new payload");
        tx2.commit(&mut store, &cx).expect("commit tx2");

        let snapshot = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(BlockNumber(32_001), snapshot)
                .expect("new payload visible")
                .as_ref(),
            b"payload:new"
        );
    }

    #[test]
    fn integration_rename_path_moves_directory_entry_without_inode_rewrite() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();

        let mut tx1 = BtrfsTransaction::begin(&mut store, 6, &cx).expect("begin tx1");
        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5500_0000,
                level: 1,
            },
        );
        tx1.stage_block_write(BlockNumber(33_001), b"dir:/old-name->900".to_vec())
            .expect("stage old dir entry");
        tx1.stage_block_write(BlockNumber(33_002), b"inode:900:size=128".to_vec())
            .expect("stage inode");
        tx1.commit(&mut store, &cx).expect("commit tx1");

        let mut tx2 = BtrfsTransaction::begin(&mut store, 7, &cx).expect("begin tx2");
        tx2.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x5600_0000,
                level: 1,
            },
        );
        tx2.stage_block_write(BlockNumber(33_001), b"dir:/old-name-><deleted>".to_vec())
            .expect("stage old dir tombstone");
        tx2.stage_block_write(BlockNumber(33_003), b"dir:/new-name->900".to_vec())
            .expect("stage new dir entry");
        tx2.commit(&mut store, &cx).expect("commit tx2");

        let snapshot = store.current_snapshot();
        assert_eq!(
            store
                .read_visible(BlockNumber(33_001), snapshot)
                .expect("old entry tombstone visible")
                .as_ref(),
            b"dir:/old-name-><deleted>"
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(33_003), snapshot)
                .expect("new entry visible")
                .as_ref(),
            b"dir:/new-name->900"
        );
        assert_eq!(
            store
                .read_visible(BlockNumber(33_002), snapshot)
                .expect("inode still visible")
                .as_ref(),
            b"inode:900:size=128"
        );
    }

    #[test]
    fn parse_root_item_smoke() {
        let mut root = vec![0_u8; 239];
        root[176..184].copy_from_slice(&0x1234_0000_u64.to_le_bytes());
        root[238] = 0;
        let parsed = parse_root_item(&root).expect("parse root item");
        assert_eq!(parsed.bytenr, 0x1234_0000);
        assert_eq!(parsed.level, 0);
    }

    /// bd-xbqdw — Kernel-conformance pin for the btrfs_root_item field
    /// offsets per fs/btrfs/btrfs_tree.h. Each field is stamped with a
    /// UNIQUE magic value at its canonical kernel offset, then a single
    /// parse_root_item call must round-trip every field. A regression
    /// that drifted any single offset by ±1 byte would produce a
    /// distinct cross-field collision and fail this test, even though
    /// parse_root_item_smoke (which only checks bytenr+level) would
    /// still pass. The valid non-zero `level` exercises the u8 path;
    /// the all-distinct UUID byte patterns guard against UUID vs
    /// parent_uuid swap regressions.
    ///
    /// Pairs with bd-yb4r0 (ext4 dx_hash invariant pin), bd-bevt2
    /// (ext4 feature flags), bd-xt5ru (ext4 dx_hash version
    /// constants).
    #[test]
    fn parse_root_item_kernel_offsets_match_btrfs_tree_h() {
        // 279 bytes covers the full UUID-era root_item per kernel header.
        let mut root = vec![0_u8; 279];

        // Each field gets a distinct non-zero magic so an offset
        // drift produces a cross-field collision.
        let generation = 0x1111_1111_1111_1111_u64;
        let root_dirid = 0x2222_2222_2222_2222_u64;
        let bytenr = 0x3333_3333_3333_3333_u64;
        let flags = 0x4444_4444_4444_4444_u64;
        let refs: u32 = 0x5555_5555;
        let level: u8 = 4; // valid: <= BTRFS_MAX_TREE_LEVEL (8)
        let generation_v2 = generation; // extended fields valid only when matches
        let uuid = [0x77_u8; 16];
        let parent_uuid = [0x88_u8; 16];

        // Stamp at kernel offsets.
        root[160..168].copy_from_slice(&generation.to_le_bytes());
        root[168..176].copy_from_slice(&root_dirid.to_le_bytes());
        root[176..184].copy_from_slice(&bytenr.to_le_bytes());
        root[208..216].copy_from_slice(&flags.to_le_bytes());
        root[216..220].copy_from_slice(&refs.to_le_bytes());
        root[238] = level;
        root[239..247].copy_from_slice(&generation_v2.to_le_bytes());
        root[247..263].copy_from_slice(&uuid);
        root[263..279].copy_from_slice(&parent_uuid);

        let parsed = parse_root_item(&root).expect("kernel-stamped root_item must parse");

        assert_eq!(
            parsed.generation, generation,
            "generation must come from offset 160 per kernel layout"
        );
        assert_eq!(
            parsed.root_dirid, root_dirid,
            "root_dirid must come from offset 168 per kernel layout"
        );
        assert_eq!(
            parsed.bytenr, bytenr,
            "bytenr must come from offset 176 per kernel layout"
        );
        assert_eq!(
            parsed.flags, flags,
            "flags must come from offset 208 per kernel layout"
        );
        assert_eq!(
            parsed.refs,
            u64::from(refs),
            "refs must come from offset 216 (u32 zero-extended) per kernel layout"
        );
        assert_eq!(
            parsed.level, level,
            "level must come from offset 238 per kernel layout"
        );
        assert_eq!(
            parsed.uuid, uuid,
            "uuid must come from offset 247 per kernel layout (16 bytes)"
        );
        assert_eq!(
            parsed.parent_uuid, parent_uuid,
            "parent_uuid must come from offset 263 per kernel layout (16 bytes)"
        );

        // Negative MR: if generation_v2 disagrees with generation,
        // extended fields (uuid, parent_uuid) must be cleared per
        // the kernel's "stale-extension" rule.
        let mut stale = root.clone();
        stale[239..247].copy_from_slice(&(generation ^ 1).to_le_bytes());
        let parsed_stale = parse_root_item(&stale).expect("stale generation_v2 must still parse");
        assert_eq!(
            parsed_stale.uuid, [0_u8; 16],
            "stale generation_v2 must clear uuid"
        );
        assert_eq!(
            parsed_stale.parent_uuid, [0_u8; 16],
            "stale generation_v2 must clear parent_uuid"
        );
    }

    #[test]
    fn parse_inode_item_smoke() {
        let mut inode = [0_u8; 160];
        inode[16..24].copy_from_slice(&4096_u64.to_le_bytes());
        inode[24..32].copy_from_slice(&4096_u64.to_le_bytes());
        inode[40..44].copy_from_slice(&2_u32.to_le_bytes());
        inode[44..48].copy_from_slice(&1000_u32.to_le_bytes());
        inode[48..52].copy_from_slice(&1000_u32.to_le_bytes());
        inode[52..56].copy_from_slice(&0o040_755_u32.to_le_bytes());
        inode[112..120].copy_from_slice(&10_u64.to_le_bytes());
        inode[124..132].copy_from_slice(&11_u64.to_le_bytes());
        inode[136..144].copy_from_slice(&12_u64.to_le_bytes());
        inode[148..156].copy_from_slice(&13_u64.to_le_bytes());
        let parsed = parse_inode_item(&inode).expect("parse inode item");
        assert_eq!(parsed.size, 4096);
        assert_eq!(parsed.mode, 0o040_755);
        assert_eq!(parsed.nlink, 2);
        assert_eq!(parsed.mtime_sec, 12);
    }

    #[test]
    fn parse_dir_items_smoke() {
        let name = b"hello.txt";
        let mut data = vec![0_u8; 30 + name.len()];
        data[0..8].copy_from_slice(&257_u64.to_le_bytes());
        data[8] = BTRFS_ITEM_INODE_ITEM;
        data[17..25].copy_from_slice(&1_u64.to_le_bytes()); // transid
        data[25..27].copy_from_slice(&0_u16.to_le_bytes()); // data_len
        let name_len = u16::try_from(name.len()).expect("test name length should fit u16");
        data[27..29].copy_from_slice(&name_len.to_le_bytes());
        data[29] = BTRFS_FT_REG_FILE;
        data[30..30 + name.len()].copy_from_slice(name);

        let parsed = parse_dir_items(&data).expect("parse dir items");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].child_objectid, 257);
        assert_eq!(parsed[0].file_type, BTRFS_FT_REG_FILE);
        assert_eq!(parsed[0].name, name);
    }

    #[test]
    fn parse_extent_data_regular_smoke() {
        let mut data = [0_u8; 53];
        data[20] = BTRFS_FILE_EXTENT_REG;
        data[21..29].copy_from_slice(&0x8_000_u64.to_le_bytes());
        data[29..37].copy_from_slice(&4096_u64.to_le_bytes());
        data[45..53].copy_from_slice(&128_u64.to_le_bytes());

        let parsed = parse_extent_data(&data).expect("parse extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Regular { .. }),
            "expected regular extent"
        );
        if let BtrfsExtentData::Regular {
            generation,
            extent_type,
            compression,
            disk_bytenr,
            num_bytes,
            ..
        } = parsed
        {
            assert_eq!(generation, 0);
            assert_eq!(extent_type, BTRFS_FILE_EXTENT_REG);
            assert_eq!(compression, 0);
            assert_eq!(disk_bytenr, 0x8_000);
            assert_eq!(num_bytes, 128);
        }
    }

    fn make_root_item_payload(len: usize, bytenr: u64) -> Vec<u8> {
        assert!(
            len >= 239,
            "root item test payload must include fixed fields"
        );

        let mut payload = vec![0_u8; len];
        payload[160..168].copy_from_slice(&7_u64.to_le_bytes());
        payload[168..176].copy_from_slice(&256_u64.to_le_bytes());
        payload[176..184].copy_from_slice(&bytenr.to_le_bytes());
        payload[208..216].copy_from_slice(&1_u64.to_le_bytes());
        payload[216..220].copy_from_slice(&3_u32.to_le_bytes());
        payload[238] = 2;
        if len >= 247 {
            payload[239..247].copy_from_slice(&7_u64.to_le_bytes());
        }
        if len >= 263 {
            payload[247..263].copy_from_slice(&[0x11; 16]);
        }
        if len >= 279 {
            payload[263..279].copy_from_slice(&[0x22; 16]);
        }
        payload
    }

    fn make_xattr_payload(name: &[u8], value: &[u8]) -> Vec<u8> {
        let name_len = u16::try_from(name.len()).expect("test xattr name length fits u16");
        let value_len = u16::try_from(value.len()).expect("test xattr value length fits u16");

        let mut payload = Vec::with_capacity(30 + name.len() + value.len());
        payload.extend_from_slice(&[0_u8; 17]);
        payload.extend_from_slice(&[0_u8; 8]);
        payload.extend_from_slice(&value_len.to_le_bytes());
        payload.extend_from_slice(&name_len.to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(name);
        payload.extend_from_slice(value);
        payload
    }

    fn assert_insufficient_data<T: std::fmt::Debug>(
        result: Result<T, ParseError>,
        needed: usize,
        offset: usize,
        actual: usize,
    ) {
        let err = result.expect_err("expected insufficient data error");
        if let ParseError::InsufficientData {
            needed: got_needed,
            offset: got_offset,
            actual: got_actual,
        } = err
        {
            assert_eq!(got_needed, needed);
            assert_eq!(got_offset, offset);
            assert_eq!(got_actual, actual);
        } else {
            assert!(
                matches!(err, ParseError::InsufficientData { .. }),
                "expected insufficient data error, got {err:?}"
            );
        }
    }

    fn assert_invalid_field<T: std::fmt::Debug>(
        result: Result<T, ParseError>,
        field: &'static str,
        reason: &'static str,
    ) {
        let err = result.expect_err("expected invalid field error");
        if let ParseError::InvalidField {
            field: got_field,
            reason: got_reason,
        } = err
        {
            assert_eq!(got_field, field);
            assert_eq!(got_reason, reason);
        } else {
            assert!(
                matches!(err, ParseError::InvalidField { .. }),
                "expected invalid field error, got {err:?}"
            );
        }
    }

    fn assert_root_item_adversarial_boundaries() {
        let valid_min = make_root_item_payload(239, 0x1234_0000);
        let parsed = parse_root_item(&valid_min).expect("parse minimal root item");
        assert_eq!(parsed.bytenr, 0x1234_0000);
        assert_eq!(parsed.generation, 7);
        assert_eq!(parsed.root_dirid, 256);
        assert_eq!(parsed.level, 2);

        let valid_generation_v2_only = make_root_item_payload(247, 0x2345_0000);
        let parsed =
            parse_root_item(&valid_generation_v2_only).expect("parse generation_v2-only root item");
        assert_eq!(parsed.bytenr, 0x2345_0000);
        assert_eq!(parsed.uuid, [0; 16]);
        assert_eq!(parsed.parent_uuid, [0; 16]);

        let valid_uuid_only = make_root_item_payload(263, 0x3456_0000);
        let parsed = parse_root_item(&valid_uuid_only).expect("parse uuid-only root item");
        assert_eq!(parsed.bytenr, 0x3456_0000);
        assert_eq!(parsed.uuid[0], 0x11);
        assert_eq!(parsed.parent_uuid, [0; 16]);

        let valid_uuid = make_root_item_payload(279, 0x5678_0000);
        let parsed = parse_root_item(&valid_uuid).expect("parse root item with uuids");
        assert_eq!(parsed.bytenr, 0x5678_0000);
        assert_eq!(parsed.uuid[0], 0x11);
        assert_eq!(parsed.parent_uuid[0], 0x22);
        assert_eq!(parsed.level, 2);

        let mut stale_uuid = valid_uuid;
        stale_uuid[239..247].copy_from_slice(&6_u64.to_le_bytes());
        let parsed = parse_root_item(&stale_uuid).expect("parse stale-uuid root item");
        assert_eq!(parsed.uuid, [0; 16]);
        assert_eq!(parsed.parent_uuid, [0; 16]);

        assert_insufficient_data(parse_root_item(&[0_u8; 238]), 239, 0, 238);
        let partial_generation_v2 = make_root_item_payload(240, 0x1234_0000);
        assert_invalid_field(
            parse_root_item(&partial_generation_v2),
            "root_item.generation_v2",
            "partial extension field",
        );
        let partial_uuid = make_root_item_payload(248, 0x1234_0000);
        assert_invalid_field(
            parse_root_item(&partial_uuid),
            "root_item.uuid",
            "partial extension field",
        );
        let partial_parent_uuid = make_root_item_payload(264, 0x1234_0000);
        assert_invalid_field(
            parse_root_item(&partial_parent_uuid),
            "root_item.parent_uuid",
            "partial extension field",
        );

        let zero_bytenr = make_root_item_payload(239, 0);
        assert_invalid_field(
            parse_root_item(&zero_bytenr),
            "root_item.bytenr",
            "must be non-zero",
        );

        let mut bad_level = make_root_item_payload(239, 0x1234_0000);
        bad_level[238] = BTRFS_MAX_TREE_LEVEL + 1;
        assert_invalid_field(
            parse_root_item(&bad_level),
            "root_item.level",
            "exceeds maximum btrfs tree level",
        );
    }

    fn assert_inode_item_adversarial_boundaries() {
        let original = BtrfsInodeItem {
            generation: u64::MAX,
            size: u64::MAX,
            nbytes: u64::MAX,
            nlink: u32::MAX,
            uid: u32::MAX,
            gid: u32::MAX,
            mode: u32::MAX,
            rdev: u64::MAX,
            atime_sec: u64::MAX,
            atime_nsec: 999_999_999,
            ctime_sec: u64::MAX,
            ctime_nsec: 999_999_999,
            mtime_sec: u64::MAX,
            mtime_nsec: 999_999_999,
            otime_sec: u64::MAX,
            otime_nsec: 999_999_999,
        };
        let bytes = original.to_bytes();
        assert_eq!(
            parse_inode_item(&bytes).expect("parse max inode item"),
            original
        );
        assert_insufficient_data(parse_inode_item(&bytes[..159]), 160, 0, 159);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_invalid_field(
            parse_inode_item(&trailing),
            "inode_item.size",
            "does not match fixed inode item size",
        );

        for (offset, field) in [
            (120, "inode_item.atime_nsec"),
            (132, "inode_item.ctime_nsec"),
            (144, "inode_item.mtime_nsec"),
            (156, "inode_item.otime_nsec"),
        ] {
            let mut invalid_nsec = bytes.clone();
            invalid_nsec[offset..offset + 4].copy_from_slice(&1_000_000_000_u32.to_le_bytes());
            assert_invalid_field(
                parse_inode_item(&invalid_nsec),
                field,
                "must be less than 1_000_000_000",
            );
        }
    }

    fn assert_dir_item_adversarial_boundaries() {
        let first = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: b"file-a".to_vec(),
        };
        let mut second = BtrfsDirItem {
            child_objectid: 259,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: 0xff,
            name: b"unknown-type".to_vec(),
        };
        let mut payload = first.to_bytes();
        payload.extend_from_slice(&second.to_bytes());

        let parsed = parse_dir_items(&payload).expect("parse multi-entry dir payload");
        assert_eq!(parsed, [first, second.clone()]);
        assert!(
            parse_dir_items(&[])
                .expect("parse empty dir payload")
                .is_empty()
        );

        assert_insufficient_data(parse_dir_items(&[0_u8; 29]), 30, 0, 29);

        let empty_name = vec![0_u8; 30];
        assert_invalid_field(
            parse_dir_items(&empty_name),
            "dir_item.name_len",
            "must be non-zero",
        );

        let mut name_overflow = vec![0_u8; 30];
        name_overflow[27..29].copy_from_slice(&5_u16.to_le_bytes());
        assert_insufficient_data(parse_dir_items(&name_overflow), 35, 0, 30);

        second.name = b"n".to_vec();
        let mut nonzero_data_len = second.to_bytes();
        nonzero_data_len[25..27].copy_from_slice(&4_u16.to_le_bytes());
        nonzero_data_len.extend_from_slice(b"data");
        assert_invalid_field(
            parse_dir_items(&nonzero_data_len),
            "dir_item.data_len",
            "must be zero for directory entries",
        );
    }

    fn assert_xattr_item_adversarial_boundaries() {
        let mut payload = make_xattr_payload(b"user.a", b"alpha");
        payload.extend_from_slice(&make_xattr_payload(b"user.b", b""));
        let parsed = parse_xattr_items(&payload).expect("parse multi-entry xattr payload");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, b"user.a");
        assert_eq!(parsed[0].value, b"alpha");
        assert_eq!(parsed[1].name, b"user.b");
        assert!(parsed[1].value.is_empty());
        assert!(
            parse_xattr_items(&[])
                .expect("parse empty xattr payload")
                .is_empty()
        );

        assert_insufficient_data(parse_xattr_items(&[0_u8; 29]), 30, 0, 29);

        let empty_name = vec![0_u8; 30];
        assert_invalid_field(
            parse_xattr_items(&empty_name),
            "xattr.name_len",
            "must be non-zero",
        );

        let mut name_overflow = vec![0_u8; 30];
        name_overflow[27..29].copy_from_slice(&5_u16.to_le_bytes());
        assert_insufficient_data(parse_xattr_items(&name_overflow), 35, 0, 30);

        let mut value_overflow = make_xattr_payload(b"n", b"");
        value_overflow[25..27].copy_from_slice(&4_u16.to_le_bytes());
        assert_insufficient_data(parse_xattr_items(&value_overflow), 35, 0, 31);
    }

    #[allow(clippy::too_many_lines)]
    fn assert_extent_data_adversarial_boundaries() {
        let inline = BtrfsExtentData::Inline {
            generation: 9,
            ram_bytes: 3,
            compression: 0,
            data: b"abc".to_vec(),
        };
        assert_eq!(
            parse_extent_data(&inline.to_bytes()).expect("parse inline extent"),
            inline
        );

        let prealloc = BtrfsExtentData::Regular {
            generation: 10,
            ram_bytes: 8192,
            extent_type: BTRFS_FILE_EXTENT_PREALLOC,
            compression: 0,
            disk_bytenr: 0x80_000,
            disk_num_bytes: 8192,
            extent_offset: 0,
            num_bytes: 4096,
        };
        assert_eq!(
            parse_extent_data(&prealloc.to_bytes()).expect("parse prealloc extent"),
            prealloc
        );

        assert_insufficient_data(parse_extent_data(&[0_u8; 20]), 21, 0, 20);

        let mut truncated_regular = vec![0_u8; 52];
        truncated_regular[20] = BTRFS_FILE_EXTENT_REG;
        assert_insufficient_data(parse_extent_data(&truncated_regular), 53, 0, 52);

        let mut trailing_regular = prealloc.to_bytes();
        trailing_regular.push(0);
        assert_invalid_field(
            parse_extent_data(&trailing_regular),
            "extent_data.length",
            "trailing bytes after fixed extent payload",
        );

        let mut unsupported_compression = inline.to_bytes();
        unsupported_compression[16] = 0xff;
        assert_invalid_field(
            parse_extent_data(&unsupported_compression),
            "extent_data.compression",
            "unsupported compression",
        );

        let mut encrypted_inline = inline.to_bytes();
        encrypted_inline[17] = 1;
        assert_invalid_field(
            parse_extent_data(&encrypted_inline),
            "extent_data.encryption",
            "unsupported encryption",
        );

        let mut other_encoded_regular = prealloc.to_bytes();
        other_encoded_regular[18..20].copy_from_slice(&1_u16.to_le_bytes());
        assert_invalid_field(
            parse_extent_data(&other_encoded_regular),
            "extent_data.other_encoding",
            "unsupported other encoding",
        );

        let mut unknown_type = vec![0_u8; 21];
        unknown_type[20] = 0xff;
        assert_invalid_field(
            parse_extent_data(&unknown_type),
            "extent_data.type",
            "unsupported extent type",
        );

        // Compressed extent source slice arithmetic: extent_offset + num_bytes overflow.
        let overflow_extent = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_ZSTD,
            disk_bytenr: 0x100_000,
            disk_num_bytes: 2048,
            extent_offset: u64::MAX - 100,
            num_bytes: 200,
        };
        assert_invalid_field(
            parse_extent_data(&overflow_extent.to_bytes()),
            "extent_data.extent_offset+num_bytes",
            "source slice arithmetic overflow",
        );

        // Compressed extent source slice: extent_offset + num_bytes > ram_bytes.
        let exceeds_ram_bytes = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_ZLIB,
            disk_bytenr: 0x100_000,
            disk_num_bytes: 2048,
            extent_offset: 4000,
            num_bytes: 200,
        };
        assert_invalid_field(
            parse_extent_data(&exceeds_ram_bytes.to_bytes()),
            "extent_data.extent_offset+num_bytes",
            "source slice exceeds ram_bytes",
        );

        // Valid compressed extent: extent_offset + num_bytes == ram_bytes.
        let valid_compressed = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_LZO,
            disk_bytenr: 0x100_000,
            disk_num_bytes: 2048,
            extent_offset: 1024,
            num_bytes: 3072,
        };
        assert_eq!(
            parse_extent_data(&valid_compressed.to_bytes()).expect("parse valid compressed"),
            valid_compressed
        );

        // Uncompressed extents must stay within their declared on-disk extent.
        let out_of_range_disk_extent = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 8192,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_NONE,
            disk_bytenr: 0x100_000,
            disk_num_bytes: 4096,
            extent_offset: 4096,
            num_bytes: 4096,
        };
        assert_invalid_field(
            parse_extent_data(&out_of_range_disk_extent.to_bytes()),
            "extent_data.extent_offset+num_bytes",
            "source slice exceeds disk_num_bytes",
        );

        // Uncompressed extent with disk_bytenr=0 (hole): validation is skipped.
        let hole_extent = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 0,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_NONE,
            disk_bytenr: 0,
            disk_num_bytes: 0,
            extent_offset: 0,
            num_bytes: 0,
        };
        assert_eq!(
            parse_extent_data(&hole_extent.to_bytes()).expect("parse hole extent"),
            hole_extent
        );
    }

    #[test]
    fn btrfs_item_payload_adversarial_samples_exercise_boundaries() {
        assert_root_item_adversarial_boundaries();
        assert_inode_item_adversarial_boundaries();
        assert_dir_item_adversarial_boundaries();
        assert_xattr_item_adversarial_boundaries();
        assert_extent_data_adversarial_boundaries();
    }

    // ── Serialization round-trip tests ────────────────────────────────────

    const REPRESENTATIVE_BTRFS_ITEM_GOLDEN: &str =
        include_str!("../../../conformance/golden/btrfs_item_payloads.txt");

    fn representative_btrfs_item_golden_actual() -> String {
        let inode_ref_key = BtrfsKey {
            objectid: 258,
            item_type: BTRFS_ITEM_INODE_REF,
            offset: 256,
        };
        let inode_ref = BtrfsInodeRef {
            index: 7,
            name: b"alpha.txt".to_vec(),
        };
        let inode_ref_payload = inode_ref.to_bytes();
        let parsed_inode_refs = parse_inode_refs(&inode_ref_payload).expect("parse inode_ref");
        assert_eq!(parsed_inode_refs, vec![inode_ref.clone()]);

        let extent_key = BtrfsKey {
            objectid: 258,
            item_type: BTRFS_ITEM_EXTENT_DATA,
            offset: 0,
        };
        let extent = BtrfsExtentData::Regular {
            generation: 3,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: 0,
            disk_bytenr: 0x10_0000,
            disk_num_bytes: 4096,
            extent_offset: 512,
            num_bytes: 3584,
        };
        let extent_payload = extent.to_bytes();
        let parsed_extent = parse_extent_data(&extent_payload).expect("parse extent_data");
        assert_eq!(parsed_extent, extent);

        let dir_item_key = BtrfsKey {
            objectid: 256,
            item_type: BTRFS_ITEM_DIR_ITEM,
            offset: 2_214_237_132,
        };
        let dir_item = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: b"file.txt".to_vec(),
        };
        let dir_item_payload = dir_item.to_bytes();
        let parsed_dir_items = parse_dir_items(&dir_item_payload).expect("parse dir_item");
        assert_eq!(parsed_dir_items, vec![dir_item.clone()]);

        format!(
            concat!(
                "INODE_REF\n",
                "  key=objectid:{},type:{},offset:{}\n",
                "  decoded=index:{},name:{}\n",
                "  payload_hex={}\n",
                "EXTENT_DATA\n",
                "  key=objectid:{},type:{},offset:{}\n",
                "  decoded=regular,generation:{},ram_bytes:{},disk_bytenr:{},disk_num_bytes:{},extent_offset:{},num_bytes:{}\n",
                "  payload_hex={}\n",
                "DIR_ITEM\n",
                "  key=objectid:{},type:{},offset:{}\n",
                "  decoded=child_objectid:{},child_key_type:{},child_key_offset:{},file_type:{},name:{}\n",
                "  payload_hex={}\n",
            ),
            inode_ref_key.objectid,
            inode_ref_key.item_type,
            inode_ref_key.offset,
            inode_ref.index,
            String::from_utf8_lossy(&inode_ref.name),
            hex_lower(&inode_ref_payload),
            extent_key.objectid,
            extent_key.item_type,
            extent_key.offset,
            3,
            4096,
            0x10_0000_u64,
            4096,
            512,
            3584,
            hex_lower(&extent_payload),
            dir_item_key.objectid,
            dir_item_key.item_type,
            dir_item_key.offset,
            dir_item.child_objectid,
            dir_item.child_key_type,
            dir_item.child_key_offset,
            dir_item.file_type,
            String::from_utf8_lossy(&dir_item.name),
            hex_lower(&dir_item_payload)
        )
    }

    #[test]
    fn representative_btrfs_item_payloads_exact_golden_contract() {
        assert_eq!(
            representative_btrfs_item_golden_actual(),
            REPRESENTATIVE_BTRFS_ITEM_GOLDEN
        );
    }

    #[test]
    fn inode_ref_round_trip() {
        let original = BtrfsInodeRef {
            index: 42,
            name: b"hardlink-target".to_vec(),
        };
        let bytes = original.to_bytes();
        let parsed = parse_inode_refs(&bytes).expect("round-trip parse");
        assert_eq!(parsed, vec![original]);
    }

    #[test]
    fn inode_ref_try_to_bytes_rejects_name_len_overflow() {
        let original = BtrfsInodeRef {
            index: 42,
            name: vec![b'x'; usize::from(u16::MAX) + 1],
        };

        let err = original
            .try_to_bytes()
            .expect_err("oversized inode_ref name should fail before encoding");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "inode_ref.name_len",
                reason: "name length exceeds u16::MAX",
            }
        ));
    }

    #[test]
    fn inode_ref_try_to_bytes_rejects_empty_name() {
        let original = BtrfsInodeRef {
            index: 42,
            name: Vec::new(),
        };

        let err = original
            .try_to_bytes()
            .expect_err("empty inode_ref name should fail before encoding");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "inode_ref.name_len",
                reason: "must be non-zero",
            }
        ));
    }

    // bd-pt9pk: metamorphic proptests for parse_inode_refs.
    // The existing inode_ref_round_trip test covers ONE fixed input;
    // these proptests sweep arbitrary (index, name) pairs plus
    // multi-entry concatenations to catch any regression in the
    // cursor-advance or variable-length boundary handling.
    proptest::proptest! {
        // MR-1 single-entry round-trip: for any (index, name length 1..=64),
        // try_to_bytes(entry) ↦ parse_inode_refs ↦ [entry].
        #[test]
        fn inode_ref_proptest_single_round_trip(
            index in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
        ) {
            let entry = BtrfsInodeRef { index, name };
            let bytes = entry.try_to_bytes().expect("non-empty name encodes");
            let parsed = parse_inode_refs(&bytes).expect("round-trip parse");
            proptest::prop_assert_eq!(parsed, vec![entry]);
        }

        // MR-2 multi-entry concatenation: stamp(a)++stamp(b)++... ↦
        // parse_inode_refs ↦ [a, b, ...]. Catches cursor-advance
        // regressions (e.g., reading past name_end into the next
        // entry's index field).
        #[test]
        fn inode_ref_proptest_multi_entry_concat(
            entries in proptest::collection::vec(
                (
                    proptest::prelude::any::<u64>(),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
                ),
                2..=8,
            ),
        ) {
            let originals: Vec<BtrfsInodeRef> = entries
                .into_iter()
                .map(|(index, name)| BtrfsInodeRef { index, name })
                .collect();

            let mut bytes = Vec::new();
            for entry in &originals {
                let entry_bytes = entry.try_to_bytes().expect("non-empty name encodes");
                bytes.extend_from_slice(&entry_bytes);
            }

            let parsed = parse_inode_refs(&bytes).expect("multi-entry parse");
            proptest::prop_assert_eq!(parsed, originals);
        }

        // MR-3 inner-truncation rejection: removing any non-zero
        // suffix from a valid encoding must produce an error rather
        // than a panic or buffer over-read. (k=full length means
        // empty input which parse_inode_refs treats as Ok([]) — that
        // is an intentional contract, so we sweep 1..len, not 1..=len.)
        #[test]
        fn inode_ref_proptest_truncation_rejection(
            index in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
            k in 1_usize..50,
        ) {
            let entry = BtrfsInodeRef { index, name };
            let bytes = entry.try_to_bytes().expect("non-empty name encodes");
            let trunc = k.min(bytes.len() - 1);
            let truncated = &bytes[..bytes.len() - trunc];
            let err = parse_inode_refs(truncated).expect_err("truncated payload must reject");
            // Specific variant intentionally not asserted to avoid
            // over-coupling to the ParseError shape; rendering must
            // succeed (covers no-panic).
            let _ = format!("{err:?}");
        }
    }

    /// bd-nzs5f — Kernel-conformance pin for the btrfs_inode_item
    /// field offsets per fs/btrfs/btrfs_tree.h. Each field is stamped
    /// with a UNIQUE non-zero magic at its canonical kernel offset,
    /// then a single parse_inode_item call must round-trip every
    /// field. A regression that drifted any single offset by ±4 bytes
    /// (one field-width) would mis-route mode↔rdev or uid↔gid
    /// silently. parse_inode_item_smoke / inode_item_round_trip
    /// (which round-trip via to_bytes) cannot detect such drift if
    /// to_bytes drifts the same way.
    ///
    /// Pairs with bd-xbqdw (parse_root_item kernel pin), bd-m6chz
    /// (BTRFS_ITEM_* discriminants), bd-qyfph (BTRFS_FT_* values).
    #[test]
    fn parse_inode_item_kernel_offsets_match_btrfs_tree_h() {
        let mut item = vec![0_u8; 160];

        // Distinct non-zero magics so an offset drift produces a
        // cross-field collision.
        let generation = 0x1111_1111_1111_1111_u64;
        let size = 0x2222_2222_2222_2222_u64;
        let nbytes = 0x3333_3333_3333_3333_u64;
        let nlink: u32 = 0x4444_4444;
        let uid: u32 = 0x5555_5555;
        let gid: u32 = 0x6666_6666;
        let mode: u32 = 0o100_644; // valid regular-file mode
        let rdev = 0x7777_7777_7777_7777_u64;
        // nsec must be < 1_000_000_000 per parser invariant. Pick four
        // distinct values inside [0, 1B) so a swap regression is caught.
        let access_time = (0x8888_8888_8888_8888_u64, 100_000_001_u32);
        let change_time = (0xAAAA_AAAA_AAAA_AAAA_u64, 200_000_002_u32);
        let modification_time = (0xCCCC_CCCC_CCCC_CCCC_u64, 300_000_003_u32);
        let creation_time = (0xEEEE_EEEE_EEEE_EEEE_u64, 400_000_004_u32);

        // Stamp at kernel offsets. Skip transid (8..16), block_group
        // (32..40), flags (64..72), sequence (72..80), reserved
        // (80..112) — these are zeroed by to_bytes and not exposed
        // on BtrfsInodeItem.
        item[0..8].copy_from_slice(&generation.to_le_bytes());
        item[16..24].copy_from_slice(&size.to_le_bytes());
        item[24..32].copy_from_slice(&nbytes.to_le_bytes());
        item[40..44].copy_from_slice(&nlink.to_le_bytes());
        item[44..48].copy_from_slice(&uid.to_le_bytes());
        item[48..52].copy_from_slice(&gid.to_le_bytes());
        item[52..56].copy_from_slice(&mode.to_le_bytes());
        item[56..64].copy_from_slice(&rdev.to_le_bytes());
        item[112..120].copy_from_slice(&access_time.0.to_le_bytes());
        item[120..124].copy_from_slice(&access_time.1.to_le_bytes());
        item[124..132].copy_from_slice(&change_time.0.to_le_bytes());
        item[132..136].copy_from_slice(&change_time.1.to_le_bytes());
        item[136..144].copy_from_slice(&modification_time.0.to_le_bytes());
        item[144..148].copy_from_slice(&modification_time.1.to_le_bytes());
        item[148..156].copy_from_slice(&creation_time.0.to_le_bytes());
        item[156..160].copy_from_slice(&creation_time.1.to_le_bytes());

        let parsed = parse_inode_item(&item).expect("kernel-stamped inode_item must parse");

        assert_eq!(parsed.generation, generation, "generation @ offset 0");
        assert_eq!(parsed.size, size, "size @ offset 16");
        assert_eq!(parsed.nbytes, nbytes, "nbytes @ offset 24");
        assert_eq!(parsed.nlink, nlink, "nlink @ offset 40");
        assert_eq!(parsed.uid, uid, "uid @ offset 44");
        assert_eq!(parsed.gid, gid, "gid @ offset 48");
        assert_eq!(parsed.mode, mode, "mode @ offset 52");
        assert_eq!(parsed.rdev, rdev, "rdev @ offset 56");
        assert_eq!(parsed.atime_sec, access_time.0, "atime_sec @ offset 112");
        assert_eq!(parsed.atime_nsec, access_time.1, "atime_nsec @ offset 120");
        assert_eq!(parsed.ctime_sec, change_time.0, "ctime_sec @ offset 124");
        assert_eq!(parsed.ctime_nsec, change_time.1, "ctime_nsec @ offset 132");
        assert_eq!(
            parsed.mtime_sec, modification_time.0,
            "mtime_sec @ offset 136"
        );
        assert_eq!(
            parsed.mtime_nsec, modification_time.1,
            "mtime_nsec @ offset 144"
        );
        assert_eq!(parsed.otime_sec, creation_time.0, "otime_sec @ offset 148");
        assert_eq!(
            parsed.otime_nsec, creation_time.1,
            "otime_nsec @ offset 156"
        );
    }

    #[test]
    fn inode_item_round_trip() {
        let original = BtrfsInodeItem {
            generation: 42,
            size: 65536,
            nbytes: 65536,
            nlink: 3,
            uid: 1000,
            gid: 1000,
            mode: 0o100_644,
            rdev: 0,
            atime_sec: 1_700_000_000,
            atime_nsec: 123_456_789,
            ctime_sec: 1_700_000_001,
            ctime_nsec: 987_654_321,
            mtime_sec: 1_700_000_002,
            mtime_nsec: 111_111_111,
            otime_sec: 1_700_000_003,
            otime_nsec: 222_222_222,
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 160);
        let parsed = parse_inode_item(&bytes).expect("round-trip parse");
        assert_eq!(parsed.size, original.size);
        assert_eq!(parsed.nbytes, original.nbytes);
        assert_eq!(parsed.nlink, original.nlink);
        assert_eq!(parsed.uid, original.uid);
        assert_eq!(parsed.gid, original.gid);
        assert_eq!(parsed.mode, original.mode);
        assert_eq!(parsed.rdev, original.rdev);
        assert_eq!(parsed.atime_sec, original.atime_sec);
        assert_eq!(parsed.atime_nsec, original.atime_nsec);
        assert_eq!(parsed.ctime_sec, original.ctime_sec);
        assert_eq!(parsed.ctime_nsec, original.ctime_nsec);
        assert_eq!(parsed.mtime_sec, original.mtime_sec);
        assert_eq!(parsed.mtime_nsec, original.mtime_nsec);
        assert_eq!(parsed.otime_sec, original.otime_sec);
        assert_eq!(parsed.otime_nsec, original.otime_nsec);
    }

    #[test]
    fn dir_item_round_trip() {
        let original = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: b"my_test_file.txt".to_vec(),
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 30 + original.name.len());
        let parsed = parse_dir_items(&bytes).expect("round-trip parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], original);
    }

    #[test]
    fn dir_item_try_to_bytes_rejects_name_len_overflow() {
        let original = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: vec![b'x'; usize::from(u16::MAX) + 1],
        };

        let err = original
            .try_to_bytes()
            .expect_err("oversized dir_item name should fail before encoding");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_item.name_len",
                reason: "name length exceeds u16::MAX",
            }
        ));
    }

    #[test]
    fn dir_item_try_to_bytes_rejects_empty_name() {
        let original = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: Vec::new(),
        };

        let err = original
            .try_to_bytes()
            .expect_err("empty dir_item name should fail before encoding");
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "dir_item.name_len",
                reason: "must be non-zero",
            }
        ));
    }

    #[test]
    fn dir_item_round_trip_directory() {
        let original = BtrfsDirItem {
            child_objectid: 300,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_DIR,
            name: b"subdir".to_vec(),
        };
        let bytes = original.to_bytes();
        let parsed = parse_dir_items(&bytes).expect("round-trip parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], original);
    }

    #[test]
    fn dir_item_multiple_entries_concatenated() {
        // btrfs stores multiple dir entries with the same hash in one payload.
        let entry_a = BtrfsDirItem {
            child_objectid: 258,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_REG_FILE,
            name: b"file_a".to_vec(),
        };
        let entry_b = BtrfsDirItem {
            child_objectid: 259,
            child_key_type: BTRFS_ITEM_INODE_ITEM,
            child_key_offset: 0,
            file_type: BTRFS_FT_SYMLINK,
            name: b"link_b".to_vec(),
        };
        let mut payload = entry_a.to_bytes();
        payload.extend_from_slice(&entry_b.to_bytes());
        let parsed = parse_dir_items(&payload).expect("parse concatenated entries");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], entry_a);
        assert_eq!(parsed[1], entry_b);
    }

    // bd-78fbx: metamorphic proptests for parse_dir_items.
    // Existing tests cover three fixed-input dir_items. These
    // proptests sweep arbitrary (objectid, key_type, key_offset,
    // file_type, name) tuples plus N-entry concatenations to catch
    // regressions in cursor-advance and variable-length boundary
    // handling. Mirrors bd-pt9pk for parse_inode_refs.
    proptest::proptest! {
        // MR-1 single-entry round-trip.
        #[test]
        fn dir_item_proptest_single_round_trip(
            child_objectid in proptest::prelude::any::<u64>(),
            child_key_type in proptest::prelude::any::<u8>(),
            child_key_offset in proptest::prelude::any::<u64>(),
            file_type in proptest::prelude::any::<u8>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
        ) {
            let entry = BtrfsDirItem {
                child_objectid,
                child_key_type,
                child_key_offset,
                file_type,
                name,
            };
            let bytes = entry.try_to_bytes().expect("non-empty name encodes");
            let parsed = parse_dir_items(&bytes).expect("round-trip parse");
            proptest::prop_assert_eq!(parsed, vec![entry]);
        }

        // MR-2 multi-entry concatenation: stamp(a)++stamp(b)++... ↦
        // parse_dir_items ↦ [a, b, ...]. Catches cursor-advance bugs
        // (e.g., reading past name_end into the next entry's location
        // key fields).
        #[test]
        fn dir_item_proptest_multi_entry_concat(
            entries in proptest::collection::vec(
                (
                    proptest::prelude::any::<u64>(),
                    proptest::prelude::any::<u8>(),
                    proptest::prelude::any::<u64>(),
                    proptest::prelude::any::<u8>(),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
                ),
                2..=8,
            ),
        ) {
            let originals: Vec<BtrfsDirItem> = entries
                .into_iter()
                .map(|(objid, ktype, koffset, ftype, name)| BtrfsDirItem {
                    child_objectid: objid,
                    child_key_type: ktype,
                    child_key_offset: koffset,
                    file_type: ftype,
                    name,
                })
                .collect();

            let mut bytes = Vec::new();
            for entry in &originals {
                let entry_bytes = entry.try_to_bytes().expect("non-empty name encodes");
                bytes.extend_from_slice(&entry_bytes);
            }

            let parsed = parse_dir_items(&bytes).expect("multi-entry parse");
            proptest::prop_assert_eq!(parsed, originals);
        }

        // MR-3 inner-truncation rejection: removing any non-zero
        // suffix from a valid encoding must produce an error rather
        // than a panic or buffer over-read.
        #[test]
        fn dir_item_proptest_truncation_rejection(
            child_objectid in proptest::prelude::any::<u64>(),
            child_key_type in proptest::prelude::any::<u8>(),
            child_key_offset in proptest::prelude::any::<u64>(),
            file_type in proptest::prelude::any::<u8>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
            k in 1_usize..50,
        ) {
            let entry = BtrfsDirItem {
                child_objectid,
                child_key_type,
                child_key_offset,
                file_type,
                name,
            };
            let bytes = entry.try_to_bytes().expect("non-empty name encodes");
            let trunc = k.min(bytes.len() - 1);
            let truncated = &bytes[..bytes.len() - trunc];
            let err = parse_dir_items(truncated).expect_err("truncated payload must reject");
            let _ = format!("{err:?}");
        }
    }

    #[test]
    fn extent_data_inline_round_trip() {
        let data = b"Hello, btrfs inline extent!".to_vec();
        let original = BtrfsExtentData::Inline {
            generation: 0,
            ram_bytes: data.len() as u64,
            compression: 0,
            data: data.clone(),
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 21 + data.len());
        let parsed = parse_extent_data(&bytes).expect("round-trip parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn extent_data_inline_uncompressed_rejects_ram_bytes_mismatch() {
        let mut bytes = BtrfsExtentData::Inline {
            generation: 0,
            ram_bytes: 3,
            compression: BTRFS_COMPRESS_NONE,
            data: b"abcd".to_vec(),
        }
        .to_bytes();

        let err = parse_extent_data(&bytes).expect_err("oversized inline payload rejects");
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "extent_data.ram_bytes",
                reason: "uncompressed inline length mismatch",
            }
        );

        bytes[8..16].copy_from_slice(&5_u64.to_le_bytes());
        let err = parse_extent_data(&bytes).expect_err("undersized inline payload rejects");
        assert_eq!(
            err,
            ParseError::InvalidField {
                field: "extent_data.ram_bytes",
                reason: "uncompressed inline length mismatch",
            }
        );
    }

    #[test]
    fn extent_data_inline_compressed_allows_payload_len_different_from_ram_bytes() {
        let compressed_inline = BtrfsExtentData::Inline {
            generation: 1,
            ram_bytes: 4096,
            compression: BTRFS_COMPRESS_ZLIB,
            data: b"compressed payload".to_vec(),
        };

        let parsed =
            parse_extent_data(&compressed_inline.to_bytes()).expect("parse compressed inline");
        assert_eq!(parsed, compressed_inline);
    }

    #[test]
    fn extent_data_regular_round_trip() {
        let original = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 3500,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: 0,
            disk_bytenr: 0x10_0000,
            disk_num_bytes: 4096,
            extent_offset: 0,
            num_bytes: 3500,
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 53);
        let parsed = parse_extent_data(&bytes).expect("round-trip parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn extent_data_prealloc_round_trip() {
        let original = BtrfsExtentData::Regular {
            generation: 1,
            ram_bytes: 7680,
            extent_type: BTRFS_FILE_EXTENT_PREALLOC,
            compression: 0,
            disk_bytenr: 0x20_0000,
            disk_num_bytes: 8192,
            extent_offset: 512,
            num_bytes: 7680,
        };
        let bytes = original.to_bytes();
        let parsed = parse_extent_data(&bytes).expect("round-trip parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn inode_item_zero_fields_round_trip() {
        let original = BtrfsInodeItem {
            generation: 0,
            size: 0,
            nbytes: 0,
            nlink: 1,
            uid: 0,
            gid: 0,
            mode: 0o100_000,
            rdev: 0,
            atime_sec: 0,
            atime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            otime_sec: 0,
            otime_nsec: 0,
        };
        let bytes = original.to_bytes();
        let parsed = parse_inode_item(&bytes).expect("round-trip parse");
        assert_eq!(parsed.size, 0);
        assert_eq!(parsed.nlink, 1);
        assert_eq!(parsed.mode, 0o100_000);
    }

    #[test]
    fn inode_item_max_values_round_trip() {
        let original = BtrfsInodeItem {
            generation: u64::MAX,
            size: u64::MAX,
            nbytes: u64::MAX,
            nlink: u32::MAX,
            uid: u32::MAX,
            gid: u32::MAX,
            mode: u32::MAX,
            rdev: u64::MAX,
            atime_sec: u64::MAX,
            atime_nsec: 999_999_999,
            ctime_sec: u64::MAX,
            ctime_nsec: 999_999_999,
            mtime_sec: u64::MAX,
            mtime_nsec: 999_999_999,
            otime_sec: u64::MAX,
            otime_nsec: 999_999_999,
        };
        let bytes = original.to_bytes();
        let parsed = parse_inode_item(&bytes).expect("round-trip parse");
        assert_eq!(parsed.size, u64::MAX);
        assert_eq!(parsed.nlink, u32::MAX);
        assert_eq!(parsed.rdev, u64::MAX);
        assert_eq!(parsed.atime_sec, u64::MAX);
        assert_eq!(parsed.otime_nsec, 999_999_999);
    }

    // bd-0rsx6: metamorphic relation — every field of BtrfsInodeItem
    // must survive the to_bytes ↦ parse_inode_item round trip. The
    // existing fixed-input tests would miss any regression where
    // both writer and reader drifted the same way (e.g., off-by-4
    // in both); a proptest sweep over arbitrary field values catches
    // such symmetric drift because it would surface as a swap or
    // truncation between distinctly-valued fields. nsec values are
    // constrained to [0, 1_000_000_000) per the parser invariant.
    proptest::proptest! {
        #[test]
        fn inode_item_proptest_round_trip(
            generation in proptest::prelude::any::<u64>(),
            size in proptest::prelude::any::<u64>(),
            nbytes in proptest::prelude::any::<u64>(),
            nlink in proptest::prelude::any::<u32>(),
            uid in proptest::prelude::any::<u32>(),
            gid in proptest::prelude::any::<u32>(),
            mode in proptest::prelude::any::<u32>(),
            rdev in proptest::prelude::any::<u64>(),
            atime_sec in proptest::prelude::any::<u64>(),
            atime_nsec in 0_u32..1_000_000_000,
            ctime_sec in proptest::prelude::any::<u64>(),
            ctime_nsec in 0_u32..1_000_000_000,
            mtime_sec in proptest::prelude::any::<u64>(),
            mtime_nsec in 0_u32..1_000_000_000,
            otime_sec in proptest::prelude::any::<u64>(),
            otime_nsec in 0_u32..1_000_000_000,
        ) {
            let original = BtrfsInodeItem {
                generation,
                size,
                nbytes,
                nlink,
                uid,
                gid,
                mode,
                rdev,
                atime_sec,
                atime_nsec,
                ctime_sec,
                ctime_nsec,
                mtime_sec,
                mtime_nsec,
                otime_sec,
                otime_nsec,
            };
            let bytes = original.to_bytes();
            proptest::prop_assert_eq!(bytes.len(), 160, "kernel-aligned 160-byte item");
            let parsed = parse_inode_item(&bytes).expect("round-trip parse");
            proptest::prop_assert_eq!(parsed, original);
        }
    }

    #[test]
    fn extent_data_inline_empty() {
        let original = BtrfsExtentData::Inline {
            generation: 1,
            ram_bytes: 0,
            compression: 0,
            data: vec![],
        };
        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), 21);
        let parsed = parse_extent_data(&bytes).expect("round-trip parse");
        assert_eq!(parsed, original);
    }

    // ── Xattr item parse tests ───────────────────────────────────────────

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn xattr_item_round_trip() {
        // Build xattr payload in the same format btrfs_setxattr uses.
        let name = b"user.myattr";
        let value = b"some-value";
        let mut payload = Vec::with_capacity(30 + name.len() + value.len());
        payload.extend_from_slice(&[0u8; 17]); // location key
        payload.extend_from_slice(&[0u8; 8]); // transid
        payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
        payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
        payload.push(0); // type
        payload.extend_from_slice(name);
        payload.extend_from_slice(value);

        let parsed = parse_xattr_items(&payload).expect("parse xattr");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, name);
        assert_eq!(parsed[0].value, value);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn xattr_item_empty_value() {
        let name = b"user.empty";
        let mut payload = Vec::with_capacity(30 + name.len());
        payload.extend_from_slice(&[0u8; 17]);
        payload.extend_from_slice(&[0u8; 8]);
        payload.extend_from_slice(&0_u16.to_le_bytes()); // data_len=0
        payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
        payload.push(0);
        payload.extend_from_slice(name);

        let parsed = parse_xattr_items(&payload).expect("parse xattr empty value");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, name);
        assert!(parsed[0].value.is_empty());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn xattr_item_multiple_concatenated() {
        // Two xattr items concatenated (would happen with hash collisions).
        let mut payload = Vec::new();
        for (name, value) in [("user.a", b"val1" as &[u8]), ("user.b", b"val2")] {
            payload.extend_from_slice(&[0u8; 17]);
            payload.extend_from_slice(&[0u8; 8]);
            payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
            payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
            payload.push(0);
            payload.extend_from_slice(name.as_bytes());
            payload.extend_from_slice(value);
        }

        let parsed = parse_xattr_items(&payload).expect("parse multiple xattrs");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, b"user.a");
        assert_eq!(parsed[0].value, b"val1");
        assert_eq!(parsed[1].name, b"user.b");
        assert_eq!(parsed[1].value, b"val2");
    }

    // bd-fhznm — Property-based round-trip MR for parse_xattr_items.
    //
    // Existing fixture tests cover hand-crafted single-entry and
    // two-entry payloads. They would not catch an off-by-one in the
    // data_len@+25 / name_len@+27 offset arithmetic that mis-aligned
    // the second-and-later entries: entry[0] would still parse
    // because cur=0 is a fixed point. These proptests sweep
    // 1..=12-entry payloads with random names (1..=128 bytes) and
    // values (0..=256 bytes), encode in the on-disk format, and
    // assert structural agreement with the parser. Determinism MR
    // is included as a cheap check against any future use of
    // hashing/iteration-order primitives in the parser path.
    fn xattr_encode_one(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
        // Mirror parse_xattr_items's 30-byte header: location key (17)
        // + transid (8) + data_len u16 LE @25 + name_len u16 LE @27.
        out.extend_from_slice(&[0_u8; 17]);
        out.extend_from_slice(&[0_u8; 8]);
        out.extend_from_slice(
            &u16::try_from(value.len())
                .expect("xattr value < u16::MAX in test")
                .to_le_bytes(),
        );
        out.extend_from_slice(
            &u16::try_from(name.len())
                .expect("xattr name < u16::MAX in test")
                .to_le_bytes(),
        );
        out.push(0); // type byte (unused by parser)
        out.extend_from_slice(name);
        out.extend_from_slice(value);
    }

    proptest::proptest! {
        // MR-1 multi-entry round-trip: encode N random (name, value)
        // pairs in the on-disk format → parse → assert vec length and
        // per-entry equality.
        #[test]
        fn proptest_xattr_items_payload_round_trip(
            entries in proptest::collection::vec(
                (
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=128),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=256),
                ),
                1..=12,
            ),
        ) {
            let mut payload = Vec::new();
            for (name, value) in &entries {
                xattr_encode_one(&mut payload, name, value);
            }
            let parsed = parse_xattr_items(&payload).expect("encode → parse round-trip");
            proptest::prop_assert_eq!(parsed.len(), entries.len());
            for (i, parsed_item) in parsed.iter().enumerate() {
                proptest::prop_assert_eq!(&parsed_item.name, &entries[i].0);
                proptest::prop_assert_eq!(&parsed_item.value, &entries[i].1);
            }
        }

        // MR-2 determinism: parse(payload) == parse(payload). Cheap
        // check that the parser does not depend on any hidden state
        // (allocator addresses, hash iteration order, time).
        #[test]
        fn proptest_xattr_items_determinism(
            entries in proptest::collection::vec(
                (
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
                    proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=128),
                ),
                1..=8,
            ),
        ) {
            let mut payload = Vec::new();
            for (name, value) in &entries {
                xattr_encode_one(&mut payload, name, value);
            }
            let a = parse_xattr_items(&payload).expect("first parse");
            let b = parse_xattr_items(&payload).expect("second parse");
            proptest::prop_assert_eq!(a, b);
        }

        // MR-3 inner-truncation rejection: cutting any non-zero suffix
        // from a valid multi-entry encoding must reject (Err) rather
        // than panic or silently succeed with a short result. Sweeps
        // 1..bytes.len() so the empty-input contract (Ok([])) is
        // intentionally excluded.
        #[test]
        fn proptest_xattr_items_truncation_rejection(
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
            value in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=128),
            k in 1_usize..50,
        ) {
            let mut payload = Vec::new();
            xattr_encode_one(&mut payload, &name, &value);
            let trunc = k.min(payload.len() - 1);
            let truncated = &payload[..payload.len() - trunc];
            // Specific error variant intentionally not asserted -- the
            // parser legitimately produces InsufficientData or
            // InvalidField depending on which field is truncated.
            proptest::prop_assert!(
                parse_xattr_items(truncated).is_err(),
                "truncated payload must reject (cut last {} of {} bytes)",
                trunc,
                payload.len()
            );
        }
    }

    // ── Extent allocator tests ──────────────────────────────────────────

    fn make_data_bg(_start: u64, size: u64) -> BtrfsBlockGroupItem {
        BtrfsBlockGroupItem {
            total_bytes: size,
            used_bytes: 0,
            flags: BTRFS_BLOCK_GROUP_DATA,
        }
    }

    fn make_meta_bg(_start: u64, size: u64) -> BtrfsBlockGroupItem {
        BtrfsBlockGroupItem {
            total_bytes: size,
            used_bytes: 0,
            flags: BTRFS_BLOCK_GROUP_METADATA,
        }
    }

    #[test]
    fn alloc_single_extent_in_empty_group() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let result = alloc.alloc_data(4096).expect("alloc");
        assert_eq!(result.bytenr, 0x1_0000);
        assert_eq!(result.num_bytes, 4096);
        assert_eq!(result.block_group_start, 0x1_0000);

        // Block group accounting should be updated.
        let bg = alloc.block_group(0x1_0000).expect("bg");
        assert_eq!(bg.used_bytes, 4096);
        assert_eq!(bg.free_bytes(), 0x10_0000 - 4096);
    }

    #[test]
    fn extent_allocator_rejects_zero_byte_allocations_without_side_effects() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));
        alloc.add_block_group(0x20_0000, make_meta_bg(0x20_0000, 0x10_0000));

        assert_eq!(
            alloc.alloc_data(0),
            Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero"
            ))
        );
        assert_eq!(
            alloc.alloc_metadata(0),
            Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero"
            ))
        );

        let data_bg = alloc.block_group(0x1_0000).expect("data bg");
        let meta_bg = alloc.block_group(0x20_0000).expect("meta bg");
        assert_eq!(data_bg.used_bytes, 0);
        assert_eq!(meta_bg.used_bytes, 0);
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn extent_allocator_rejects_zero_byte_free_without_side_effects() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let existing = alloc.alloc_data(4096).expect("seed alloc");
        let refs_before = alloc.delayed_ref_count();
        let used_before = alloc.block_group(0x1_0000).expect("bg").used_bytes;

        assert_eq!(
            alloc.free_extent(existing.bytenr, 0, false),
            Err(BtrfsMutationError::InvalidConfig(
                "extent size must be non-zero"
            ))
        );

        let bg = alloc.block_group(0x1_0000).expect("bg");
        assert_eq!(bg.used_bytes, used_before);
        assert_eq!(alloc.delayed_ref_count(), refs_before);
    }

    #[test]
    fn alloc_fills_group_sequentially() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("first");
        let a2 = alloc.alloc_data(8192).expect("second");
        let a3 = alloc.alloc_data(4096).expect("third");

        // Allocations should be sequential.
        assert_eq!(a1.bytenr, 0x1_0000);
        assert_eq!(a2.bytenr, 0x1_0000 + 4096);
        assert_eq!(a3.bytenr, 0x1_0000 + 4096 + 8192);

        let bg = alloc.block_group(0x1_0000).expect("bg");
        assert_eq!(bg.used_bytes, 4096 + 8192 + 4096);
    }

    #[test]
    fn free_extent_creates_reclaimable_space() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("first");
        let _a2 = alloc.alloc_data(4096).expect("second");

        // Free first extent.
        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("free");

        let bg = alloc.block_group(0x1_0000).expect("bg");
        assert_eq!(bg.used_bytes, 4096); // only second extent remains
    }

    #[test]
    fn alloc_respects_block_group_type() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));
        alloc.add_block_group(0x20_0000, make_meta_bg(0x20_0000, 0x10_0000));

        // Data allocation should go to the data block group.
        let data = alloc.alloc_data(4096).expect("data alloc");
        assert_eq!(data.block_group_start, 0x1_0000);

        // Metadata allocation should go to the metadata block group.
        let meta = alloc.alloc_metadata(4096).expect("meta alloc");
        assert_eq!(meta.block_group_start, 0x20_0000);
    }

    #[test]
    fn delayed_refs_tracked() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("alloc");
        let extent = ExtentKey {
            bytenr: a1.bytenr,
            num_bytes: a1.num_bytes,
        };
        assert_eq!(alloc.delayed_ref_count(), 1);
        assert_eq!(alloc.pending_for(&extent).len(), 1);

        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("free");
        assert_eq!(alloc.delayed_ref_count(), 2);
        assert_eq!(alloc.pending_for(&extent).len(), 2);

        let refs = alloc.drain_delayed_refs();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].action, RefAction::Insert);
        assert_eq!(refs[0].extent.bytenr, a1.bytenr);
        assert_eq!(refs[1].action, RefAction::Delete);
        assert_eq!(refs[1].extent.bytenr, a1.bytenr);

        // After drain, count is zero.
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn flush_delayed_refs_applies_refcounts() {
        let mut alloc = BtrfsExtentAllocator::new(7).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("alloc");
        let extent = ExtentKey {
            bytenr: a1.bytenr,
            num_bytes: a1.num_bytes,
        };

        let flushed = alloc.flush_delayed_refs(1).expect("flush insert");
        assert_eq!(flushed, 1);
        assert_eq!(alloc.delayed_ref_count(), 0);
        assert_eq!(alloc.extent_refcount(extent), 1);

        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("free");
        let flushed = alloc.flush_delayed_refs(1).expect("flush delete");
        assert_eq!(flushed, 1);
        assert_eq!(alloc.extent_refcount(extent), 0);
    }

    #[test]
    fn flush_delayed_refs_respects_limit() {
        let mut alloc = BtrfsExtentAllocator::new(9).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 0x10_0000));

        let a1 = alloc.alloc_data(4096).expect("a1");
        let a2 = alloc.alloc_data(4096).expect("a2");
        let e1 = ExtentKey {
            bytenr: a1.bytenr,
            num_bytes: a1.num_bytes,
        };
        let e2 = ExtentKey {
            bytenr: a2.bytenr,
            num_bytes: a2.num_bytes,
        };

        let flushed = alloc.flush_delayed_refs(1).expect("first flush");
        assert_eq!(flushed, 1);
        assert_eq!(alloc.delayed_ref_count(), 1);
        assert_eq!(alloc.extent_refcount(e1) + alloc.extent_refcount(e2), 1);

        let flushed = alloc.flush_delayed_refs(1).expect("second flush");
        assert_eq!(flushed, 1);
        assert_eq!(alloc.delayed_ref_count(), 0);
        assert_eq!(alloc.extent_refcount(e1), 1);
        assert_eq!(alloc.extent_refcount(e2), 1);
    }

    #[test]
    fn delayed_ref_queue_shared_extent_refcount() {
        let mut queue = DelayedRefQueue::new();
        let extent = ExtentKey {
            bytenr: 0x80_0000,
            num_bytes: 4096,
        };
        queue.queue(
            extent,
            BtrfsRef::DataExtent {
                root: 5,
                objectid: 0x200,
                offset: 0,
            },
            RefAction::Insert,
        );
        queue.queue(
            extent,
            BtrfsRef::SharedDataExtent { parent: 0x1000 },
            RefAction::Insert,
        );

        let mut refcounts = BTreeMap::new();
        let flushed = queue.flush(1024, &mut refcounts).expect("flush");
        assert_eq!(flushed, 2);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(refcounts.get(&extent), Some(&2));
    }

    #[test]
    fn delayed_ref_queue_stress_10000_refs_flushes_all() {
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::new();

        for i in 0..10_000_u64 {
            let extent = ExtentKey {
                bytenr: 0x10_0000 + (i * 4096),
                num_bytes: 4096,
            };
            queue.queue(
                extent,
                BtrfsRef::DataExtent {
                    root: 5,
                    objectid: i,
                    offset: 0,
                },
                RefAction::Insert,
            );
        }

        assert_eq!(queue.pending_count(), 10_000);
        let flushed = queue.flush(10_000, &mut refcounts).expect("flush");
        assert_eq!(flushed, 10_000);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(refcounts.len(), 10_000);
    }

    #[test]
    fn btrfs_tx_begin_abort_discards_staged_updates() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 7, &cx).expect("begin");

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x2000,
                level: 1,
            },
        );
        txn.stage_block_write(BlockNumber(777), b"transient".to_vec())
            .expect("stage write");
        txn.track_allocation(BlockNumber(900));
        txn.defer_free_on_commit(BlockNumber(901));

        let summary = txn.abort();
        assert_eq!(summary.discarded_tree_updates, 1);
        assert_eq!(summary.released_allocations, vec![BlockNumber(900)]);
        assert_eq!(summary.deferred_frees, vec![BlockNumber(901)]);

        let snapshot = store.current_snapshot();
        assert!(store.read_visible(BlockNumber(777), snapshot).is_none());
    }

    #[test]
    fn btrfs_tx_commit_persists_tree_root_and_payload() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 11, &cx).expect("begin");
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x55_0000,
                level: 2,
            },
        );
        txn.stage_block_write(BlockNumber(1234), b"hello-btrfs".to_vec())
            .expect("stage payload");
        txn.queue_delayed_ref(
            ExtentKey {
                bytenr: 0x8000,
                num_bytes: 4096,
            },
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );

        let commit_seq = txn.commit(&mut store, &cx).expect("commit");
        assert_eq!(commit_seq, CommitSeq(1));

        let snapshot = store.current_snapshot();
        let payload = store
            .read_visible(BlockNumber(1234), snapshot)
            .expect("payload visible");
        assert_eq!(payload.as_ref(), b"hello-btrfs");

        let tree_block =
            BtrfsTransaction::tree_root_block(BTRFS_FS_TREE_OBJECTID).expect("tree block");
        let tree_record = store
            .read_visible(tree_block, snapshot)
            .expect("tree root record");
        assert_eq!(tree_record.len(), 25);
        assert_eq!(
            u64::from_le_bytes(tree_record[0..8].try_into().unwrap()),
            11_u64
        );
        assert_eq!(
            u64::from_le_bytes(tree_record[8..16].try_into().unwrap()),
            BTRFS_FS_TREE_OBJECTID
        );
        assert_eq!(
            u64::from_le_bytes(tree_record[16..24].try_into().unwrap()),
            0x55_0000_u64
        );
        assert_eq!(tree_record[24], 2_u8);
    }

    #[test]
    fn btrfs_tx_disjoint_trees_commit_without_fcw_conflict() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();

        let mut tx1 = BtrfsTransaction::begin(&mut store, 20, &cx).expect("begin tx1");
        let mut tx2 = BtrfsTransaction::begin(&mut store, 20, &cx).expect("begin tx2");

        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x60_0000,
                level: 1,
            },
        );
        tx2.stage_tree_root(
            BTRFS_EXTENT_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x61_0000,
                level: 0,
            },
        );

        let c1 = tx1.commit(&mut store, &cx).expect("commit tx1");
        let c2 = tx2.commit(&mut store, &cx).expect("commit tx2");
        assert_eq!(c1, CommitSeq(1));
        assert_eq!(c2, CommitSeq(2));
    }

    #[test]
    fn btrfs_tx_same_tree_conflicts_via_fcw() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();

        let mut tx1 = BtrfsTransaction::begin(&mut store, 30, &cx).expect("begin tx1");
        let mut tx2 = BtrfsTransaction::begin(&mut store, 30, &cx).expect("begin tx2");

        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x70_0000,
                level: 1,
            },
        );
        tx2.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x71_0000,
                level: 1,
            },
        );

        let _ = tx1.commit(&mut store, &cx).expect("tx1 commit");
        let err = tx2.commit(&mut store, &cx).expect_err("tx2 must conflict");
        assert!(
            matches!(
                err,
                BtrfsTransactionError::Commit(CommitError::Conflict { .. })
            ),
            "unexpected error: {err:?}"
        );
        if let BtrfsTransactionError::Commit(CommitError::Conflict { block, .. }) = err {
            let expected =
                BtrfsTransaction::tree_root_block(BTRFS_FS_TREE_OBJECTID).expect("block");
            assert_eq!(block, expected);
        }
    }

    #[test]
    fn btrfs_tx_drop_without_commit_has_no_visible_effect() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        {
            let mut txn = BtrfsTransaction::begin(&mut store, 44, &cx).expect("begin");
            txn.stage_tree_root(
                BTRFS_FS_TREE_OBJECTID,
                TreeRoot {
                    bytenr: 0x80_0000,
                    level: 1,
                },
            );
            txn.stage_block_write(BlockNumber(3210), b"uncommitted".to_vec())
                .expect("stage");
        }

        let snapshot = store.current_snapshot();
        assert!(store.read_visible(BlockNumber(3210), snapshot).is_none());
    }

    #[test]
    fn alloc_fails_when_no_space() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        // Small block group: only 100 bytes.
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 100));

        let result = alloc.alloc_data(200);
        assert!(result.is_err());
    }

    #[test]
    fn total_free_computation() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x1_0000, make_data_bg(0x1_0000, 1000));
        alloc.add_block_group(0x2_0000, make_data_bg(0x2_0000, 2000));
        alloc.add_block_group(0x3_0000, make_meta_bg(0x3_0000, 500));

        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), 3000);
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_METADATA), 500);

        alloc.alloc_data(100).expect("alloc");
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), 2900);
    }

    #[test]
    fn block_group_aggregate_counters_saturate_on_overflow() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(
            0x10_0000,
            BtrfsBlockGroupItem {
                total_bytes: u64::MAX,
                used_bytes: u64::MAX,
                flags: BTRFS_BLOCK_GROUP_DATA,
            },
        );
        alloc.add_block_group(
            0x20_0000,
            BtrfsBlockGroupItem {
                total_bytes: 1,
                used_bytes: 1,
                flags: BTRFS_BLOCK_GROUP_DATA,
            },
        );
        alloc.add_block_group(
            0x30_0000,
            BtrfsBlockGroupItem {
                total_bytes: u64::MAX,
                used_bytes: 0,
                flags: BTRFS_BLOCK_GROUP_METADATA,
            },
        );
        alloc.add_block_group(
            0x40_0000,
            BtrfsBlockGroupItem {
                total_bytes: 1,
                used_bytes: 0,
                flags: BTRFS_BLOCK_GROUP_METADATA,
            },
        );

        assert_eq!(alloc.total_used(), u64::MAX);
        assert_eq!(alloc.total_capacity(), u64::MAX);
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_METADATA), u64::MAX);
        assert_eq!(
            alloc.total_free(BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA),
            u64::MAX
        );
    }

    #[test]
    fn extent_item_serialization() {
        let item = BtrfsExtentItem {
            refs: 1,
            generation: 42,
            flags: 0,
        };
        let bytes = item.to_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 42);
        assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 0);
    }

    #[test]
    fn block_group_item_free_bytes() {
        let bg = BtrfsBlockGroupItem {
            total_bytes: 1000,
            used_bytes: 300,
            flags: BTRFS_BLOCK_GROUP_DATA,
        };
        assert_eq!(bg.free_bytes(), 700);
    }

    // ── bd-375.6: btrfs read path unit tests ────────────────────────────

    // Tree Walk Test 1: Walk root tree — all items iterated in key order
    #[test]
    fn readpath_walk_root_tree_key_order() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        // Build a leaf containing 3 ROOT_ITEM entries for different tree objectids.
        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 3, 0, BTRFS_ROOT_TREE_OBJECTID, 10);

        // ROOT_ITEM for FS tree (objectid=5)
        let root_payload_a = {
            let mut p = vec![0_u8; 239];
            p[176..184].copy_from_slice(&0xAAAA_0000_u64.to_le_bytes());
            p[238] = 0; // level
            p
        };
        // ROOT_ITEM for extent tree (objectid=2)
        let root_payload_b = {
            let mut p = vec![0_u8; 239];
            p[176..184].copy_from_slice(&0xBBBB_0000_u64.to_le_bytes());
            p[238] = 1;
            p
        };
        // ROOT_ITEM for chunk tree (objectid=3)
        let root_payload_c = {
            let mut p = vec![0_u8; 239];
            p[176..184].copy_from_slice(&0xCCCC_0000_u64.to_le_bytes());
            p[238] = 0;
            p
        };

        // Items placed in key order: objectid 2, 3, 5 (all type ROOT_ITEM=132)
        let data_region = NODESIZE as usize - 239 * 3;
        write_leaf_item(
            &mut leaf,
            0,
            BTRFS_EXTENT_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            u32::try_from(data_region).unwrap(),
            239,
        );
        leaf[data_region..data_region + 239].copy_from_slice(&root_payload_b);

        write_leaf_item(
            &mut leaf,
            1,
            BTRFS_CHUNK_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            u32::try_from(data_region + 239).unwrap(),
            239,
        );
        leaf[data_region + 239..data_region + 478].copy_from_slice(&root_payload_c);

        write_leaf_item(
            &mut leaf,
            2,
            BTRFS_FS_TREE_OBJECTID,
            BTRFS_ITEM_ROOT_ITEM,
            u32::try_from(data_region + 478).unwrap(),
            239,
        );
        leaf[data_region + 478..data_region + 717].copy_from_slice(&root_payload_a);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk root tree");
        assert_eq!(entries.len(), 3, "expected 3 root tree items");

        // Verify strict key ordering: objectid 2 < 3 < 5
        assert_eq!(entries[0].key.objectid, BTRFS_EXTENT_TREE_OBJECTID);
        assert_eq!(entries[1].key.objectid, BTRFS_CHUNK_TREE_OBJECTID);
        assert_eq!(entries[2].key.objectid, BTRFS_FS_TREE_OBJECTID);

        for entry in &entries {
            assert_eq!(entry.key.item_type, BTRFS_ITEM_ROOT_ITEM);
            let parsed = parse_root_item(&entry.data).expect("parse root item payload");
            assert_ne!(parsed.bytenr, 0, "root item bytenr should be non-zero");
        }

        // Verify specific root items were parsed correctly
        let fs_root = parse_root_item(&entries[2].data).expect("parse FS root");
        assert_eq!(fs_root.bytenr, 0xAAAA_0000);
        assert_eq!(fs_root.level, 0);
    }

    // Tree Walk Test 2: Walk extent tree — all extents found for given inode
    #[test]
    fn readpath_walk_extent_tree_finds_extents_for_inode() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        // Build a leaf with an INODE_ITEM and two EXTENT_DATA items for inode 256,
        // plus an unrelated item for inode 257.
        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 4, 0, BTRFS_FS_TREE_OBJECTID, 10);

        // Inode 256 INODE_ITEM (160 bytes)
        let inode_payload = vec![0_u8; 160];
        let inode_off = 3200_u32;
        write_leaf_item(&mut leaf, 0, 256, BTRFS_ITEM_INODE_ITEM, inode_off, 160);
        leaf[inode_off as usize..(inode_off + 160) as usize].copy_from_slice(&inode_payload);

        // Inode 256 EXTENT_DATA at offset 0 (inline, 21 + 11 = 32 bytes)
        let inline_payload = BtrfsExtentData::Inline {
            generation: 0,
            ram_bytes: 11,
            compression: BTRFS_COMPRESS_NONE,
            data: b"hello world".to_vec(),
        }
        .to_bytes();
        let ext0_off = 3000_u32;
        write_leaf_item_payload(
            &mut leaf,
            1,
            256,
            BTRFS_ITEM_EXTENT_DATA,
            ext0_off,
            &inline_payload,
        );
        // Set key offset to 0 (file offset)
        let base1 = HEADER_SIZE + ITEM_SIZE;
        leaf[base1 + 9..base1 + 17].copy_from_slice(&0_u64.to_le_bytes());

        // Inode 256 EXTENT_DATA at offset 4096 (regular, 53 bytes)
        let reg_payload = BtrfsExtentData::Regular {
            generation: 0,
            ram_bytes: 4096,
            extent_type: BTRFS_FILE_EXTENT_REG,
            compression: BTRFS_COMPRESS_NONE,
            disk_bytenr: 0x10_000,
            disk_num_bytes: 4096,
            extent_offset: 0,
            num_bytes: 4096,
        }
        .to_bytes();
        let ext1_off = 3040_u32;
        write_leaf_item_payload(
            &mut leaf,
            2,
            256,
            BTRFS_ITEM_EXTENT_DATA,
            ext1_off,
            &reg_payload,
        );
        let base2 = HEADER_SIZE + 2 * ITEM_SIZE;
        leaf[base2 + 9..base2 + 17].copy_from_slice(&4096_u64.to_le_bytes());

        // Inode 257 INODE_ITEM (unrelated)
        let ext2_off = 3400_u32;
        write_leaf_item(&mut leaf, 3, 257, BTRFS_ITEM_INODE_ITEM, ext2_off, 160);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let all_entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk");

        // Filter for inode 256 EXTENT_DATA items
        let extents: Vec<_> = all_entries
            .iter()
            .filter(|e| e.key.objectid == 256 && e.key.item_type == BTRFS_ITEM_EXTENT_DATA)
            .collect();

        assert_eq!(
            extents.len(),
            2,
            "expected 2 extent_data items for inode 256"
        );
        assert_eq!(extents[0].key.offset, 0, "first extent at file offset 0");
        assert_eq!(
            extents[1].key.offset, 4096,
            "second extent at file offset 4096"
        );

        // Verify inline extent
        let inline = parse_extent_data(&extents[0].data).expect("parse inline");
        assert!(
            matches!(inline, BtrfsExtentData::Inline { .. }),
            "expected inline extent, got regular"
        );
        if let BtrfsExtentData::Inline { data, .. } = inline {
            assert_eq!(data, b"hello world", "inline extent data mismatch");
        }

        // Verify regular extent
        let regular = parse_extent_data(&extents[1].data).expect("parse regular");
        assert!(
            matches!(regular, BtrfsExtentData::Regular { .. }),
            "expected regular extent, got inline"
        );
        if let BtrfsExtentData::Regular {
            disk_bytenr,
            num_bytes,
            ..
        } = regular
        {
            assert_eq!(disk_bytenr, 0x10_000);
            assert_eq!(num_bytes, 4096);
        }
    }

    // Tree Walk Test 3: Walk directory tree — all dir entries found
    #[test]
    fn readpath_walk_directory_tree_finds_dir_entries() {
        let logical = 0x4000_u64;
        let chunks = identity_chunks();

        // Build a leaf with DIR_ITEM entries for a parent directory (objectid=256).
        let mut leaf = vec![0_u8; NODESIZE as usize];

        // Build two DIR_ITEM payloads
        let name_a = b"file.txt";
        let dir_entry_a = {
            let mut d = vec![0_u8; 30 + name_a.len()];
            d[0..8].copy_from_slice(&257_u64.to_le_bytes()); // child objectid
            d[8] = BTRFS_ITEM_INODE_ITEM; // child key type
            d[17..25].copy_from_slice(&1_u64.to_le_bytes()); // transid
            d[25..27].copy_from_slice(&0_u16.to_le_bytes()); // data_len
            let nl = u16::try_from(name_a.len()).unwrap();
            d[27..29].copy_from_slice(&nl.to_le_bytes()); // name_len
            d[29] = BTRFS_FT_REG_FILE; // file type
            d[30..30 + name_a.len()].copy_from_slice(name_a);
            d
        };

        let name_b = b"subdir";
        let dir_entry_b = {
            let mut d = vec![0_u8; 30 + name_b.len()];
            d[0..8].copy_from_slice(&258_u64.to_le_bytes());
            d[8] = BTRFS_ITEM_INODE_ITEM;
            d[17..25].copy_from_slice(&1_u64.to_le_bytes());
            d[25..27].copy_from_slice(&0_u16.to_le_bytes());
            let nl = u16::try_from(name_b.len()).unwrap();
            d[27..29].copy_from_slice(&nl.to_le_bytes());
            d[29] = BTRFS_FT_DIR;
            d[30..30 + name_b.len()].copy_from_slice(name_b);
            d
        };

        // Place two leaf items
        let file_entry_len = u32::try_from(dir_entry_a.len()).unwrap();
        let subdir_entry_len = u32::try_from(dir_entry_b.len()).unwrap();
        let off_a = 3500_u32;
        let off_b = off_a + file_entry_len;

        write_header(&mut leaf, logical, 2, 0, BTRFS_FS_TREE_OBJECTID, 10);
        write_leaf_item(
            &mut leaf,
            0,
            256,
            BTRFS_ITEM_DIR_ITEM,
            off_a,
            file_entry_len,
        );
        write_leaf_item(
            &mut leaf,
            1,
            256,
            BTRFS_ITEM_DIR_ITEM,
            off_b,
            subdir_entry_len,
        );
        // Set different key offsets (hash of name) so they are distinct items
        let base0 = HEADER_SIZE;
        leaf[base0 + 9..base0 + 17].copy_from_slice(&100_u64.to_le_bytes());
        let base1 = HEADER_SIZE + ITEM_SIZE;
        leaf[base1 + 9..base1 + 17].copy_from_slice(&200_u64.to_le_bytes());

        leaf[off_a as usize..(off_a + file_entry_len) as usize].copy_from_slice(&dir_entry_a);
        leaf[off_b as usize..(off_b + subdir_entry_len) as usize].copy_from_slice(&dir_entry_b);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk");

        // Filter DIR_ITEM entries
        let dir_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.key.item_type == BTRFS_ITEM_DIR_ITEM)
            .collect();
        assert_eq!(dir_entries.len(), 2);

        let parsed_a = parse_dir_items(&dir_entries[0].data).expect("parse dir_item a");
        assert_eq!(parsed_a.len(), 1);
        assert_eq!(parsed_a[0].child_objectid, 257);
        assert_eq!(parsed_a[0].file_type, BTRFS_FT_REG_FILE);
        assert_eq!(parsed_a[0].name, b"file.txt");

        let parsed_b = parse_dir_items(&dir_entries[1].data).expect("parse dir_item b");
        assert_eq!(parsed_b.len(), 1);
        assert_eq!(parsed_b[0].child_objectid, 258);
        assert_eq!(parsed_b[0].file_type, BTRFS_FT_DIR);
        assert_eq!(parsed_b[0].name, b"subdir");
    }

    // Tree Walk Test 4: Walk with corrupt node — CRC mismatch detected
    #[test]
    fn readpath_walk_corrupt_node_crc_mismatch() {
        // Build a valid tree block with correct CRC, then corrupt it.
        let mut block = vec![0_u8; NODESIZE as usize];
        write_header(&mut block, 0x4000, 0, 0, BTRFS_FS_TREE_OBJECTID, 10);

        // Compute valid CRC32C and store it
        let csum = ffs_types::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());

        // Verify the block passes CRC check before corruption
        verify_tree_block_checksum(&block, ffs_types::BTRFS_CSUM_TYPE_CRC32C)
            .expect("CRC should be valid before corruption");

        // Corrupt a byte in the payload area
        block[0x50] ^= 0xFF;

        // Now CRC check should fail
        let err =
            verify_tree_block_checksum(&block, ffs_types::BTRFS_CSUM_TYPE_CRC32C).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "tree_block_csum",
                    reason: "CRC32C checksum mismatch",
                }
            ),
            "expected CRC mismatch error, got: {err:?}"
        );
    }

    // Tree Walk Test 5: Walk empty tree — no items, no error
    #[test]
    fn readpath_walk_empty_tree_no_items() {
        let logical = 0x8000_u64;
        let chunks = identity_chunks();

        let mut leaf = vec![0_u8; NODESIZE as usize];
        write_header(&mut leaf, logical, 0, 0, BTRFS_FS_TREE_OBJECTID, 1);
        stamp_tree_block_crc32c(&mut leaf);

        let blocks: HashMap<u64, Vec<u8>> = [(logical, leaf)].into();
        let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
            blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
                field: "physical",
                reason: "block not in test image",
            })
        };

        let entries = walk_tree(&mut read, &chunks, logical, NODESIZE, 0).expect("walk empty tree");
        assert!(entries.is_empty(), "empty tree should yield no items");
    }

    // Extent Read Test 6: Read inline extent — small file data correct
    #[test]
    fn readpath_parse_inline_extent_small_file() {
        let file_data = b"tiny inline file";
        let mut payload = vec![0_u8; 21 + file_data.len()];
        // generation(8) + ram_bytes(8) + compression(1) + encryption(1) + other_encoding(2) + type(1)
        payload[0..8].copy_from_slice(&1_u64.to_le_bytes()); // generation
        payload[8..16].copy_from_slice(&(file_data.len() as u64).to_le_bytes()); // ram_bytes
        payload[16] = 0; // compression = none
        payload[17] = 0; // encryption
        payload[18..20].copy_from_slice(&0_u16.to_le_bytes()); // other_encoding
        payload[20] = BTRFS_FILE_EXTENT_INLINE; // type
        payload[21..].copy_from_slice(file_data);

        let parsed = parse_extent_data(&payload).expect("parse inline extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Inline { .. }),
            "expected inline extent, got regular"
        );
        if let BtrfsExtentData::Inline {
            compression, data, ..
        } = parsed
        {
            assert_eq!(compression, 0, "should be uncompressed");
            assert_eq!(data, file_data, "inline data mismatch");
        }
    }

    // Extent Read Test 7: Read regular extent — block data correct
    #[test]
    fn readpath_parse_regular_extent_block_data() {
        let mut payload = [0_u8; 53];
        payload[0..8].copy_from_slice(&5_u64.to_le_bytes()); // generation
        payload[8..16].copy_from_slice(&8192_u64.to_le_bytes()); // ram_bytes
        payload[16] = 0; // compression
        payload[20] = BTRFS_FILE_EXTENT_REG;
        payload[21..29].copy_from_slice(&0x20_0000_u64.to_le_bytes()); // disk_bytenr
        payload[29..37].copy_from_slice(&8192_u64.to_le_bytes()); // disk_num_bytes
        payload[37..45].copy_from_slice(&0_u64.to_le_bytes()); // extent_offset
        payload[45..53].copy_from_slice(&8192_u64.to_le_bytes()); // num_bytes

        let parsed = parse_extent_data(&payload).expect("parse regular extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Regular { .. }),
            "expected regular extent, got inline"
        );
        if let BtrfsExtentData::Regular {
            extent_type,
            compression,
            disk_bytenr,
            disk_num_bytes,
            extent_offset,
            num_bytes,
            ..
        } = parsed
        {
            assert_eq!(extent_type, BTRFS_FILE_EXTENT_REG);
            assert_eq!(compression, 0);
            assert_eq!(disk_bytenr, 0x20_0000);
            assert_eq!(disk_num_bytes, 8192);
            assert_eq!(extent_offset, 0);
            assert_eq!(num_bytes, 8192);
        }
    }

    // Extent Read Test 8: Read compressed extent — compression field correct
    #[test]
    fn readpath_parse_compressed_extent_fields() {
        let mut payload = [0_u8; 53];
        payload[0..8].copy_from_slice(&3_u64.to_le_bytes()); // generation
        payload[8..16].copy_from_slice(&16384_u64.to_le_bytes()); // ram_bytes (uncompressed)
        payload[16] = 1; // compression = zlib
        payload[20] = BTRFS_FILE_EXTENT_REG;
        payload[21..29].copy_from_slice(&0x30_0000_u64.to_le_bytes()); // disk_bytenr
        payload[29..37].copy_from_slice(&4096_u64.to_le_bytes()); // disk_num_bytes (compressed)
        payload[37..45].copy_from_slice(&0_u64.to_le_bytes()); // extent_offset
        payload[45..53].copy_from_slice(&16384_u64.to_le_bytes()); // num_bytes

        let parsed = parse_extent_data(&payload).expect("parse compressed extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Regular { .. }),
            "expected regular extent, got inline"
        );
        if let BtrfsExtentData::Regular {
            extent_type,
            compression,
            disk_bytenr,
            disk_num_bytes,
            num_bytes,
            ..
        } = parsed
        {
            assert_eq!(extent_type, BTRFS_FILE_EXTENT_REG);
            assert_eq!(compression, 1, "compression should be zlib (1)");
            assert_eq!(disk_bytenr, 0x30_0000);
            assert_eq!(
                disk_num_bytes, 4096,
                "compressed on-disk size should be smaller"
            );
            assert_eq!(num_bytes, 16384, "logical extent size");
        }
    }

    // Extent Read Test 9: Read prealloc extent — zeros returned
    #[test]
    fn readpath_parse_prealloc_extent_zeros() {
        let mut payload = [0_u8; 53];
        payload[0..8].copy_from_slice(&2_u64.to_le_bytes()); // generation
        payload[8..16].copy_from_slice(&65536_u64.to_le_bytes()); // ram_bytes
        payload[16] = 0; // no compression
        payload[20] = BTRFS_FILE_EXTENT_PREALLOC;
        // Prealloc extents have a disk_bytenr pointing to allocated but unwritten space.
        payload[21..29].copy_from_slice(&0x40_0000_u64.to_le_bytes()); // disk_bytenr
        payload[29..37].copy_from_slice(&65536_u64.to_le_bytes()); // disk_num_bytes
        payload[37..45].copy_from_slice(&0_u64.to_le_bytes()); // extent_offset
        payload[45..53].copy_from_slice(&65536_u64.to_le_bytes()); // num_bytes

        let parsed = parse_extent_data(&payload).expect("parse prealloc extent");
        assert!(
            matches!(parsed, BtrfsExtentData::Regular { .. }),
            "expected prealloc extent, got inline"
        );
        if let BtrfsExtentData::Regular {
            extent_type,
            compression,
            disk_bytenr,
            num_bytes,
            ..
        } = parsed
        {
            assert_eq!(
                extent_type, BTRFS_FILE_EXTENT_PREALLOC,
                "should be PREALLOC type"
            );
            assert_eq!(compression, 0, "prealloc extents are uncompressed");
            assert_eq!(disk_bytenr, 0x40_0000);
            assert_eq!(num_bytes, 65536);
        }
    }

    // Directory Listing Test 10: List root directory — all entries present
    #[test]
    fn readpath_list_root_directory_all_entries() {
        // Build a DIR_ITEM payload with 3 entries packed together
        let names: &[(&[u8], u64, u8)] = &[
            (b"bin", 257, BTRFS_FT_DIR),
            (b"etc", 258, BTRFS_FT_DIR),
            (b"init", 259, BTRFS_FT_REG_FILE),
        ];

        // Build separate DIR_ITEM payloads for each name (each is a separate leaf item)
        let mut payloads = Vec::new();
        for &(name, child_oid, ftype) in names {
            let mut d = vec![0_u8; 30 + name.len()];
            d[0..8].copy_from_slice(&child_oid.to_le_bytes());
            d[8] = BTRFS_ITEM_INODE_ITEM;
            d[17..25].copy_from_slice(&1_u64.to_le_bytes()); // transid
            d[25..27].copy_from_slice(&0_u16.to_le_bytes()); // data_len
            let nl = u16::try_from(name.len()).unwrap();
            d[27..29].copy_from_slice(&nl.to_le_bytes());
            d[29] = ftype;
            d[30..30 + name.len()].copy_from_slice(name);
            payloads.push(d);
        }

        // Parse each payload independently
        for (i, &(name, child_oid, ftype)) in names.iter().enumerate() {
            let parsed = parse_dir_items(&payloads[i]).expect("parse dir entry");
            assert_eq!(parsed.len(), 1);
            assert_eq!(parsed[0].child_objectid, child_oid);
            assert_eq!(parsed[0].file_type, ftype);
            assert_eq!(parsed[0].name, name);
        }

        // Also test parsing two entries concatenated in a single DIR_ITEM payload
        let mut combined = payloads[0].clone();
        combined.extend_from_slice(&payloads[1]);
        let parsed_combined = parse_dir_items(&combined).expect("parse combined dir entries");
        assert_eq!(parsed_combined.len(), 2);
        assert_eq!(parsed_combined[0].name, b"bin");
        assert_eq!(parsed_combined[1].name, b"etc");
    }

    // Directory Listing Test 11: List subdirectory — correct entries, correct types
    #[test]
    fn readpath_list_subdirectory_correct_types() {
        // Build DIR_ITEM payloads for a subdirectory with various file types
        let entries: &[(&[u8], u64, u8)] = &[
            (b"regular.dat", 300, BTRFS_FT_REG_FILE),
            (b"nested", 301, BTRFS_FT_DIR),
            (b"link", 302, BTRFS_FT_SYMLINK),
            (b"socket", 303, BTRFS_FT_SOCK),
        ];

        for &(name, child_oid, ftype) in entries {
            let mut d = vec![0_u8; 30 + name.len()];
            d[0..8].copy_from_slice(&child_oid.to_le_bytes());
            d[8] = BTRFS_ITEM_INODE_ITEM;
            d[17..25].copy_from_slice(&1_u64.to_le_bytes());
            d[25..27].copy_from_slice(&0_u16.to_le_bytes());
            let nl = u16::try_from(name.len()).unwrap();
            d[27..29].copy_from_slice(&nl.to_le_bytes());
            d[29] = ftype;
            d[30..30 + name.len()].copy_from_slice(name);

            let parsed = parse_dir_items(&d).expect("parse dir entry");
            assert_eq!(parsed.len(), 1, "each payload has one entry");
            assert_eq!(
                parsed[0].child_objectid, child_oid,
                "child objectid mismatch for {name:?}"
            );
            assert_eq!(
                parsed[0].file_type, ftype,
                "file type mismatch for {name:?}"
            );
            assert_eq!(parsed[0].name, name, "name mismatch");
        }
    }

    // Directory Listing Test 12: List empty directory — no entries (beyond . and ..)
    #[test]
    fn readpath_list_empty_directory_no_entries() {
        // An empty directory has no DIR_ITEM payloads (. and .. are implicit in btrfs).
        // parse_dir_items with empty input should return an empty vec.
        let parsed = parse_dir_items(&[]).expect("parse empty dir items");
        assert!(
            parsed.is_empty(),
            "empty directory should have no dir item entries"
        );
    }

    // Logical-Physical Mapping Test 13: Single-device mapping — logical → physical correct
    #[test]
    fn readpath_single_device_mapping_correct() {
        // Single chunk: logical range [1MiB, 9MiB) maps to physical [2MiB, 10MiB)
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x10_0000, // logical start = 1 MiB
            },
            length: 0x80_0000, // 8 MiB
            owner: 2,
            stripe_len: 0x1_0000,
            chunk_type: 1, // DATA
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 1,
            sub_stripes: 0,
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 0x20_0000, // physical start = 2 MiB
                dev_uuid: [0; 16],
            }],
        }];

        // Test exact start of chunk
        let m0 = map_logical_to_physical(&chunks, 0x10_0000)
            .expect("no error")
            .expect("should map");
        assert_eq!(m0.devid, 1);
        assert_eq!(
            m0.physical, 0x20_0000,
            "start of chunk maps to start of stripe"
        );

        // Test middle of chunk
        let m1 = map_logical_to_physical(&chunks, 0x10_0000 + 0x4_0000)
            .expect("no error")
            .expect("should map");
        assert_eq!(m1.physical, 0x20_0000 + 0x4_0000);

        // Test end-1 of chunk
        let m2 = map_logical_to_physical(&chunks, 0x10_0000 + 0x80_0000 - 1)
            .expect("no error")
            .expect("should map");
        assert_eq!(m2.physical, 0x20_0000 + 0x80_0000 - 1);

        // Test just past end — should be None
        let m3 = map_logical_to_physical(&chunks, 0x10_0000 + 0x80_0000).expect("no error");
        assert!(m3.is_none(), "address past chunk end should not map");

        // Test before start — should be None
        let m4 = map_logical_to_physical(&chunks, 0x0F_FFFF).expect("no error");
        assert!(m4.is_none(), "address before chunk start should not map");
    }

    // Logical-Physical Mapping Test 14: sys_chunk mapping — bootstrap chunks resolve
    #[test]
    fn readpath_sys_chunk_mapping_bootstrap_resolves() {
        // Build a sys_chunk_array entry manually, parse it, then use for mapping.
        // disk_key (17) + chunk_fixed (48) + 1 stripe (32) = 97 bytes
        let mut sys_array = vec![0_u8; 97];

        // disk_key: objectid=256, type=228 (CHUNK_ITEM), offset=0x100_0000 (logical start 16 MiB)
        sys_array[0..8].copy_from_slice(&256_u64.to_le_bytes());
        sys_array[8] = 228;
        sys_array[9..17].copy_from_slice(&0x100_0000_u64.to_le_bytes());

        // chunk header: length=8MiB, owner=2, stripe_len=64K, type=SYSTEM(2)
        let c = 17;
        sys_array[c..c + 8].copy_from_slice(&(8 * 1024 * 1024_u64).to_le_bytes()); // length
        sys_array[c + 8..c + 16].copy_from_slice(&2_u64.to_le_bytes()); // owner
        sys_array[c + 16..c + 24].copy_from_slice(&(64 * 1024_u64).to_le_bytes()); // stripe_len
        sys_array[c + 24..c + 32].copy_from_slice(&2_u64.to_le_bytes()); // chunk_type
        sys_array[c + 32..c + 36].copy_from_slice(&4096_u32.to_le_bytes()); // io_align
        sys_array[c + 36..c + 40].copy_from_slice(&4096_u32.to_le_bytes()); // io_width
        sys_array[c + 40..c + 44].copy_from_slice(&4096_u32.to_le_bytes()); // sector_size
        sys_array[c + 44..c + 46].copy_from_slice(&1_u16.to_le_bytes()); // num_stripes
        sys_array[c + 46..c + 48].copy_from_slice(&0_u16.to_le_bytes()); // sub_stripes

        // stripe: devid=1, offset=0x80_0000 (physical start 8 MiB)
        let s = c + 48;
        sys_array[s..s + 8].copy_from_slice(&1_u64.to_le_bytes()); // devid
        sys_array[s + 8..s + 16].copy_from_slice(&0x80_0000_u64.to_le_bytes()); // offset

        // Parse the sys_chunk_array
        let chunks = parse_sys_chunk_array(&sys_array).expect("parse sys_chunk_array");
        assert_eq!(chunks.len(), 1, "should parse one chunk");
        assert_eq!(chunks[0].key.offset, 0x100_0000);
        assert_eq!(chunks[0].length, 8 * 1024 * 1024);
        assert_eq!(chunks[0].stripes[0].offset, 0x80_0000);

        // Use the parsed chunks for logical → physical mapping
        let mapping = map_logical_to_physical(&chunks, 0x100_0000 + 0x1000)
            .expect("no error")
            .expect("should resolve via bootstrap chunks");
        assert_eq!(mapping.devid, 1);
        assert_eq!(
            mapping.physical,
            0x80_0000 + 0x1000,
            "bootstrap chunk should resolve logical to physical"
        );

        // Verify unmapped address outside the sys_chunk range
        let miss = map_logical_to_physical(&chunks, 0x200_0000).expect("no error");
        assert!(miss.is_none(), "address outside sys_chunk should not map");
    }

    fn make_chunk_item_payload(
        length: u64,
        stripe_len: u64,
        chunk_type: u64,
        num_stripes: u16,
    ) -> Vec<u8> {
        const CHUNK_FIXED: usize = 48;
        const STRIPE_SIZE: usize = 32;

        let stripe_count = usize::from(num_stripes);
        let mut data = vec![0_u8; CHUNK_FIXED + stripe_count * STRIPE_SIZE];
        data[0..8].copy_from_slice(&length.to_le_bytes());
        data[8..16].copy_from_slice(&2_u64.to_le_bytes());
        data[16..24].copy_from_slice(&stripe_len.to_le_bytes());
        data[24..32].copy_from_slice(&chunk_type.to_le_bytes());
        data[32..36].copy_from_slice(&4096_u32.to_le_bytes());
        data[36..40].copy_from_slice(&4096_u32.to_le_bytes());
        data[40..44].copy_from_slice(&4096_u32.to_le_bytes());
        data[44..46].copy_from_slice(&num_stripes.to_le_bytes());
        data[46..48].copy_from_slice(&0_u16.to_le_bytes());

        for stripe_idx in 0..stripe_count {
            let stripe_off = CHUNK_FIXED + stripe_idx * STRIPE_SIZE;
            let devid = u64::try_from(stripe_idx + 1).expect("test stripe index fits u64");
            let physical = 0x80_0000_u64
                + u64::try_from(stripe_idx).expect("test stripe index fits u64") * 0x10_0000;
            let uuid_byte = 0xa0_u8
                .checked_add(u8::try_from(stripe_idx).expect("test stripe index fits u8"))
                .expect("test stripe uuid byte fits u8");
            data[stripe_off..stripe_off + 8].copy_from_slice(&devid.to_le_bytes());
            data[stripe_off + 8..stripe_off + 16].copy_from_slice(&physical.to_le_bytes());
            data[stripe_off + 16..stripe_off + 32].fill(uuid_byte);
        }

        data
    }

    #[test]
    fn parse_chunk_item_adversarial_samples_exercise_boundaries() {
        let chunk_type =
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0;
        let data = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 2);
        let parsed = parse_chunk_item(&data, 0x100_0000).expect("parse multi-stripe chunk");
        assert_eq!(parsed.key.objectid, BTRFS_CHUNK_TREE_OBJECTID);
        assert_eq!(parsed.key.item_type, BTRFS_ITEM_CHUNK);
        assert_eq!(parsed.key.offset, 0x100_0000);
        assert_eq!(parsed.length, 8 * 1024 * 1024);
        assert_eq!(parsed.stripe_len, 64 * 1024);
        assert_eq!(parsed.chunk_type, chunk_type);
        assert_eq!(parsed.io_align, 4096);
        assert_eq!(parsed.io_width, 4096);
        assert_eq!(parsed.sector_size, 4096);
        assert_eq!(parsed.num_stripes, 2);
        assert_eq!(parsed.stripes.len(), 2);
        assert_eq!(parsed.stripes[0].devid, 1);
        assert_eq!(parsed.stripes[0].offset, 0x80_0000);
        assert_eq!(parsed.stripes[0].dev_uuid, [0xa0; 16]);
        assert_eq!(parsed.stripes[1].devid, 2);
        assert_eq!(parsed.stripes[1].offset, 0x90_0000);
        assert_eq!(parsed.stripes[1].dev_uuid, [0xa1; 16]);

        assert_insufficient_data(parse_chunk_item(&data[..47], 0x100_0000), 48, 0, 47);

        let mut truncated_stripe = data;
        truncated_stripe.truncate(48 + 31);
        assert_insufficient_data(parse_chunk_item(&truncated_stripe, 0x100_0000), 112, 48, 79);

        let mut trailing_stripe_payload =
            make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        trailing_stripe_payload.extend_from_slice(b"extra");
        assert_invalid_field(
            parse_chunk_item(&trailing_stripe_payload, 0x100_0000),
            "stripes",
            "does not match declared stripe count",
        );

        let zero_stripes = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 0);
        assert_invalid_field(
            parse_chunk_item(&zero_stripes, 0x100_0000),
            "stripes",
            "chunk has no stripes",
        );

        let zero_length = make_chunk_item_payload(0, 64 * 1024, chunk_type, 1);
        assert_invalid_field(
            parse_chunk_item(&zero_length, 0x100_0000),
            "chunk_length",
            "chunk has zero length",
        );

        let zero_stripe_len = make_chunk_item_payload(8 * 1024 * 1024, 0, chunk_type, 1);
        assert_invalid_field(
            parse_chunk_item(&zero_stripe_len, 0x100_0000),
            "stripe_len",
            "chunk has zero stripe length",
        );

        let mut zero_io_align = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        zero_io_align[32..36].copy_from_slice(&0_u32.to_le_bytes());
        assert_invalid_field(
            parse_chunk_item(&zero_io_align, 0x100_0000),
            "io_align",
            "must be non-zero",
        );

        let mut zero_io_width = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        zero_io_width[36..40].copy_from_slice(&0_u32.to_le_bytes());
        assert_invalid_field(
            parse_chunk_item(&zero_io_width, 0x100_0000),
            "io_width",
            "must be non-zero",
        );

        let mut zero_sector_size =
            make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        zero_sector_size[40..44].copy_from_slice(&0_u32.to_le_bytes());
        assert_invalid_field(
            parse_chunk_item(&zero_sector_size, 0x100_0000),
            "sector_size",
            "must be non-zero",
        );

        let mut zero_stripe_devid =
            make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, chunk_type, 1);
        zero_stripe_devid[48..56].copy_from_slice(&0_u64.to_le_bytes());
        assert_invalid_field(
            parse_chunk_item(&zero_stripe_devid, 0x100_0000),
            "stripe_devid",
            "must be non-zero",
        );

        let multi_raid_type = chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1;
        let multi_raid = make_chunk_item_payload(8 * 1024 * 1024, 64 * 1024, multi_raid_type, 1);
        assert_invalid_field(
            parse_chunk_item(&multi_raid, 0x100_0000),
            "chunk_type",
            "multiple RAID profiles set",
        );
    }

    #[test]
    fn parse_chunk_item_rejects_zero_stripe_len() {
        const CHUNK_FIXED: usize = 48;
        const STRIPE_SIZE: usize = 32;
        let mut data = vec![0_u8; CHUNK_FIXED + STRIPE_SIZE];

        data[0..8].copy_from_slice(&(8 * 1024 * 1024_u64).to_le_bytes()); // length
        data[8..16].copy_from_slice(&2_u64.to_le_bytes()); // owner
        data[16..24].copy_from_slice(&0_u64.to_le_bytes()); // stripe_len (invalid)
        data[24..32].copy_from_slice(&2_u64.to_le_bytes()); // chunk_type
        data[32..36].copy_from_slice(&4096_u32.to_le_bytes()); // io_align
        data[36..40].copy_from_slice(&4096_u32.to_le_bytes()); // io_width
        data[40..44].copy_from_slice(&4096_u32.to_le_bytes()); // sector_size
        data[44..46].copy_from_slice(&1_u16.to_le_bytes()); // num_stripes
        data[46..48].copy_from_slice(&0_u16.to_le_bytes()); // sub_stripes

        let s = CHUNK_FIXED;
        data[s..s + 8].copy_from_slice(&1_u64.to_le_bytes()); // devid
        data[s + 8..s + 16].copy_from_slice(&0x80_0000_u64.to_le_bytes()); // offset

        let err = parse_chunk_item(&data, 0x100_0000).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "stripe_len",
                ..
            }
        ));
    }

    #[test]
    fn parse_chunk_item_rejects_zero_length() {
        const CHUNK_FIXED: usize = 48;
        const STRIPE_SIZE: usize = 32;
        let mut data = vec![0_u8; CHUNK_FIXED + STRIPE_SIZE];

        data[0..8].copy_from_slice(&0_u64.to_le_bytes()); // length (invalid)
        data[8..16].copy_from_slice(&2_u64.to_le_bytes()); // owner
        data[16..24].copy_from_slice(&4096_u64.to_le_bytes()); // stripe_len
        data[24..32].copy_from_slice(&2_u64.to_le_bytes()); // chunk_type
        data[32..36].copy_from_slice(&4096_u32.to_le_bytes()); // io_align
        data[36..40].copy_from_slice(&4096_u32.to_le_bytes()); // io_width
        data[40..44].copy_from_slice(&4096_u32.to_le_bytes()); // sector_size
        data[44..46].copy_from_slice(&1_u16.to_le_bytes()); // num_stripes
        data[46..48].copy_from_slice(&0_u16.to_le_bytes()); // sub_stripes

        let s = CHUNK_FIXED;
        data[s..s + 8].copy_from_slice(&1_u64.to_le_bytes()); // devid
        data[s + 8..s + 16].copy_from_slice(&0x80_0000_u64.to_le_bytes()); // offset

        let err = parse_chunk_item(&data, 0x100_0000).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "chunk_length",
                ..
            }
        ));
    }

    // ── bd-29z.2: btrfs write path unit tests ───────────────────────────

    // Extent Allocation Test 1: Allocate extent returns valid block range
    #[test]
    fn writepath_alloc_extent_returns_valid_block_range() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000_u64;
        let bg_size = 0x100_000_u64; // 1 MiB
        alloc.add_block_group(bg_start, make_data_bg(bg_start, bg_size));

        let extent = alloc.alloc_data(4096).expect("alloc data");

        // Returned bytenr must lie within the block group
        assert!(
            extent.bytenr >= bg_start,
            "bytenr {:#x} should be >= block group start {bg_start:#x}",
            extent.bytenr
        );
        assert!(
            extent.bytenr + extent.num_bytes <= bg_start + bg_size,
            "extent end {:#x} should not exceed block group end {:#x}",
            extent.bytenr + extent.num_bytes,
            bg_start + bg_size
        );
        assert_eq!(
            extent.num_bytes, 4096,
            "allocated size should match request"
        );
        assert_eq!(extent.block_group_start, bg_start);
    }

    // Extent Allocation Test 2: Free extent returns blocks to free space
    #[test]
    fn writepath_free_extent_returns_blocks_to_free_space() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000_u64;
        let bg_size = 0x100_000_u64;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, bg_size));

        let a1 = alloc.alloc_data(8192).expect("alloc");
        let bg_after_alloc = *alloc.block_group(bg_start).expect("bg");
        assert_eq!(bg_after_alloc.used_bytes, 8192);
        assert_eq!(bg_after_alloc.free_bytes(), bg_size - 8192);

        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("free");
        let bg_after_free = alloc.block_group(bg_start).expect("bg");
        assert_eq!(
            bg_after_free.used_bytes, 0,
            "used should be zero after free"
        );
        assert_eq!(
            bg_after_free.free_bytes(),
            bg_size,
            "all space should be free"
        );
    }

    // Extent Allocation Test 3: Double-free detected — error returned
    #[test]
    fn writepath_double_free_detected() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let a1 = alloc.alloc_data(4096).expect("alloc");
        alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect("first free should succeed");

        // Second free of the same extent should fail (key already deleted from extent tree).
        let err = alloc
            .free_extent(a1.bytenr, a1.num_bytes, false)
            .expect_err("double free should be detected");
        assert_eq!(
            err,
            BtrfsMutationError::KeyNotFound,
            "double free should return KeyNotFound, got: {err:?}"
        );
    }

    // Extent Allocation Test 4: Allocate when full — ENOSPC returned
    #[test]
    fn writepath_alloc_when_full_enospc() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        // Block group with only 256 bytes of space.
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 256));

        // First allocation fits.
        alloc.alloc_data(128).expect("first alloc should fit");

        // Second allocation exceeds remaining space.
        let result = alloc.alloc_data(256);
        assert!(
            result.is_err(),
            "allocating beyond capacity should fail (ENOSPC)"
        );
    }

    // Extent Allocation Test 5: Allocation respects block group boundaries
    #[test]
    fn writepath_alloc_respects_block_group_boundaries() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let data_bg = 0x10_0000_u64;
        let meta_bg = 0x20_0000_u64;
        alloc.add_block_group(data_bg, make_data_bg(data_bg, 0x100_000));
        alloc.add_block_group(meta_bg, make_meta_bg(meta_bg, 0x100_000));

        // Data allocation lands in data block group.
        let data_ext = alloc.alloc_data(4096).expect("data alloc");
        assert_eq!(
            data_ext.block_group_start, data_bg,
            "data extent should come from data block group"
        );
        assert!(data_ext.bytenr >= data_bg && data_ext.bytenr < data_bg + 0x100_000);

        // Metadata allocation lands in metadata block group.
        let meta_ext = alloc.alloc_metadata(4096).expect("meta alloc");
        assert_eq!(
            meta_ext.block_group_start, meta_bg,
            "metadata extent should come from metadata block group"
        );
        assert!(meta_ext.bytenr >= meta_bg && meta_ext.bytenr < meta_bg + 0x100_000);

        // Verify no cross-contamination: data BG only has data usage, meta BG only meta.
        let data_used = alloc.block_group(data_bg).expect("data bg").used_bytes;
        let meta_used = alloc.block_group(meta_bg).expect("meta bg").used_bytes;
        assert_eq!(data_used, 4096, "data bg should only have data allocation");
        assert_eq!(
            meta_used, 4096,
            "meta bg should only have metadata allocation"
        );
    }

    // COW Test 6: COW write preserves original block, allocates new
    #[test]
    fn writepath_cow_write_preserves_original() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let key = test_key(42);

        tree.insert(key, b"original").expect("insert");
        let root_v1 = tree.root_block();
        let snapshot_v1 = tree.node_snapshot(root_v1).expect("snapshot v1");

        // Update (COW write) should allocate a new root, old root preserved.
        tree.update(&key, b"modified").expect("update");
        let root_v2 = tree.root_block();

        assert_ne!(root_v1, root_v2, "COW update should allocate new root");
        assert_eq!(
            tree.node_snapshot(root_v1).expect("old snapshot"),
            snapshot_v1,
            "original root node must be preserved after COW"
        );

        // New root should contain modified data.
        let entries = tree.range(&key, &key).expect("point query");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"modified");
        tree.validate_invariants().expect("invariants");
    }

    // COW Test 7: COW chain produces version chain (multiple updates tracked)
    #[test]
    fn writepath_cow_chain_produces_version_chain() {
        let mut tree = InMemoryCowBtrfsTree::new(5).expect("tree");
        let key = test_key(100);
        let mut root_versions = Vec::new();

        // Insert initial value.
        tree.insert(key, b"v1").expect("insert");
        root_versions.push(tree.root_block());

        // Perform 4 updates, capturing root at each step.
        for version in 2..=5 {
            let payload = format!("v{version}");
            tree.update(&key, payload.as_bytes()).expect("update");
            root_versions.push(tree.root_block());
        }

        // All root versions should be distinct (COW semantics).
        let unique_roots: HashSet<u64> = root_versions.iter().copied().collect();
        assert_eq!(
            unique_roots.len(),
            root_versions.len(),
            "each COW write should produce a distinct root: {root_versions:?}"
        );

        // Deferred free list should have entries from retired nodes.
        assert!(
            !tree.deferred_free_blocks().is_empty(),
            "COW chain should record deferred frees for retired nodes"
        );

        // Current value should be the latest.
        let entries = tree.range(&key, &key).expect("point query");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, b"v5");
        tree.validate_invariants().expect("invariants");
    }

    // COW Test 8: COW with MVCC — different transactions see different versions
    #[test]
    fn writepath_cow_with_mvcc_different_txns_see_versions() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let block = BlockNumber(0x5000);

        // Transaction 1: write "version-A".
        let mut tx1 = BtrfsTransaction::begin(&mut store, 1, &cx).expect("begin tx1");
        tx1.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x100_0000,
                level: 0,
            },
        );
        tx1.stage_block_write(block, b"version-A".to_vec())
            .expect("stage A");
        let seq1 = tx1.commit(&mut store, &cx).expect("commit tx1");
        let snap_after_a = store.current_snapshot();

        // Transaction 2: overwrite with "version-B".
        let mut tx2 = BtrfsTransaction::begin(&mut store, 2, &cx).expect("begin tx2");
        tx2.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x200_0000,
                level: 0,
            },
        );
        tx2.stage_block_write(block, b"version-B".to_vec())
            .expect("stage B");
        let seq2 = tx2.commit(&mut store, &cx).expect("commit tx2");
        let snap_after_b = store.current_snapshot();

        // Verify monotonic commit sequence.
        assert!(seq2.0 > seq1.0, "commit sequence should be monotonic");

        // Snapshot after tx1 should see "version-A".
        let data_a = store
            .read_visible(block, snap_after_a)
            .expect("version-A should be visible at snap_after_a");
        assert_eq!(
            data_a.as_ref(),
            b"version-A",
            "snap_after_a should see version-A"
        );

        // Snapshot after tx2 should see "version-B".
        let data_b = store
            .read_visible(block, snap_after_b)
            .expect("version-B should be visible at snap_after_b");
        assert_eq!(
            data_b.as_ref(),
            b"version-B",
            "snap_after_b should see version-B"
        );
    }

    // ── Transaction edge-case tests ───────────────────────────────────

    #[test]
    fn btrfs_tx_commit_empty_root_set_errors() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let txn = BtrfsTransaction::begin(&mut store, 1, &cx).expect("begin");
        // Commit without staging any tree roots should fail.
        let err = txn.commit(&mut store, &cx).expect_err("empty root set");
        assert!(
            matches!(err, BtrfsTransactionError::EmptyRootSet),
            "expected EmptyRootSet, got: {err:?}"
        );
    }

    #[test]
    fn btrfs_tx_stage_block_write_after_abort_errors() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 2, &cx).expect("begin");
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x1000,
                level: 0,
            },
        );
        let _summary = txn.abort();
        // Can't stage after abort — txn is consumed by abort().
        // (This is enforced by Rust's ownership system.)
    }

    #[test]
    fn btrfs_tx_accessors_return_correct_values() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 42, &cx).expect("begin");
        assert_eq!(txn.generation(), 42);
        assert!(txn.pending_trees().is_empty());
        assert_eq!(txn.delayed_ref_count(), 0);

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x3000,
                level: 1,
            },
        );
        assert_eq!(txn.pending_trees().len(), 1);
        assert!(txn.pending_trees().contains_key(&BTRFS_FS_TREE_OBJECTID));

        txn.queue_delayed_ref(
            ExtentKey {
                bytenr: 0x5000,
                num_bytes: 4096,
            },
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );
        assert_eq!(txn.delayed_ref_count(), 1);
    }

    #[test]
    fn btrfs_tx_multiple_tree_roots_in_single_txn() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 5, &cx).expect("begin");

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x10_0000,
                level: 1,
            },
        );
        txn.stage_tree_root(
            BTRFS_EXTENT_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x20_0000,
                level: 0,
            },
        );
        txn.stage_tree_root(
            BTRFS_CHUNK_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x30_0000,
                level: 0,
            },
        );

        assert_eq!(txn.pending_trees().len(), 3);
        let commit_seq = txn.commit(&mut store, &cx).expect("commit");
        assert_eq!(commit_seq, CommitSeq(1));

        // Verify all tree roots are persisted.
        let snap = store.current_snapshot();
        for tree_id in [
            BTRFS_FS_TREE_OBJECTID,
            BTRFS_EXTENT_TREE_OBJECTID,
            BTRFS_CHUNK_TREE_OBJECTID,
        ] {
            let block = BtrfsTransaction::tree_root_block(tree_id).expect("block");
            assert!(
                store.read_visible(block, snap).is_some(),
                "tree {tree_id} root should be visible after commit"
            );
        }
    }

    #[test]
    fn btrfs_tx_adversarial_same_tree_root_replacement_persists_last_root() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 55, &cx).expect("begin");
        let txn_id = txn.txn_id();
        let meta_block = BtrfsTransaction::metadata_block_for_txn(txn_id).expect("metadata block");

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x10_0000,
                level: 0,
            },
        );
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x20_0000,
                level: 2,
            },
        );
        assert_eq!(txn.pending_trees().len(), 1);

        let commit_seq = txn.commit(&mut store, &cx).expect("commit");
        assert_eq!(commit_seq, CommitSeq(1));

        let snap = store.current_snapshot();
        let metadata = store
            .read_visible(meta_block, snap)
            .expect("transaction metadata should be visible");
        assert_eq!(
            u64::from_le_bytes(metadata[24..32].try_into().unwrap()),
            1_u64,
            "same-tree replacement should count as one root update"
        );

        let tree_block =
            BtrfsTransaction::tree_root_block(BTRFS_FS_TREE_OBJECTID).expect("tree block");
        let tree_record = store
            .read_visible(tree_block, snap)
            .expect("tree root record should be visible");
        assert_eq!(
            u64::from_le_bytes(tree_record[16..24].try_into().unwrap()),
            0x20_0000_u64
        );
        assert_eq!(tree_record[24], 2_u8);
    }

    #[test]
    fn btrfs_tx_adversarial_delayed_ref_failure_leaves_no_visible_records() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 56, &cx).expect("begin");
        let txn_id = txn.txn_id();
        let meta_block = BtrfsTransaction::metadata_block_for_txn(txn_id).expect("metadata block");
        let tree_block =
            BtrfsTransaction::tree_root_block(BTRFS_FS_TREE_OBJECTID).expect("tree block");
        let payload_block = BlockNumber(0xCAFE);

        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x30_0000,
                level: 1,
            },
        );
        txn.stage_block_write(payload_block, b"must-not-commit".to_vec())
            .expect("stage payload");
        txn.queue_delayed_ref(
            ExtentKey {
                bytenr: 0x40_0000,
                num_bytes: 4096,
            },
            delayed_data_ref(700),
            RefAction::Delete,
        );

        let err = txn
            .commit(&mut store, &cx)
            .expect_err("delete without materialized refcount should fail");
        assert!(
            matches!(
                err,
                BtrfsTransactionError::DelayedRefs(BtrfsMutationError::BrokenInvariant(
                    "delayed ref delete without prior refcount"
                ))
            ),
            "unexpected error: {err:?}"
        );

        let snap = store.current_snapshot();
        assert!(store.read_visible(meta_block, snap).is_none());
        assert!(store.read_visible(tree_block, snap).is_none());
        assert!(store.read_visible(payload_block, snap).is_none());
    }

    #[test]
    fn btrfs_tx_adversarial_tree_root_overflow_leaves_no_visible_records() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 57, &cx).expect("begin");
        let txn_id = txn.txn_id();
        let meta_block = BtrfsTransaction::metadata_block_for_txn(txn_id).expect("metadata block");
        let payload_block = BlockNumber(0xD00D);

        txn.stage_tree_root(
            u64::MAX,
            TreeRoot {
                bytenr: 0x50_0000,
                level: 0,
            },
        );
        txn.stage_block_write(payload_block, b"must-not-commit".to_vec())
            .expect("stage payload");

        let err = txn
            .commit(&mut store, &cx)
            .expect_err("overflowing tree id should fail");
        assert!(
            matches!(
                err,
                BtrfsTransactionError::TreeRootAddressOverflow { tree_id } if tree_id == u64::MAX
            ),
            "unexpected error: {err:?}"
        );

        let snap = store.current_snapshot();
        assert!(
            store.read_visible(meta_block, snap).is_none(),
            "metadata staged before the overflow must not become visible"
        );
        assert!(store.read_visible(payload_block, snap).is_none());
    }

    #[test]
    fn btrfs_tx_track_allocation_and_defer_free() {
        let cx = Cx::for_request();
        let mut store = MvccStore::new();
        let mut txn = BtrfsTransaction::begin(&mut store, 10, &cx).expect("begin");

        txn.track_allocation(BlockNumber(100));
        txn.track_allocation(BlockNumber(101));
        txn.defer_free_on_commit(BlockNumber(200));
        txn.defer_free_on_commit(BlockNumber(201));
        txn.stage_tree_root(
            BTRFS_FS_TREE_OBJECTID,
            TreeRoot {
                bytenr: 0x1000,
                level: 0,
            },
        );

        let summary = txn.abort();
        assert_eq!(summary.released_allocations.len(), 2);
        assert!(summary.released_allocations.contains(&BlockNumber(100)));
        assert!(summary.released_allocations.contains(&BlockNumber(101)));
        assert_eq!(summary.deferred_frees.len(), 2);
        assert!(summary.deferred_frees.contains(&BlockNumber(200)));
        assert!(summary.deferred_frees.contains(&BlockNumber(201)));
    }

    // ── Extent allocator edge-case tests ──────────────────────────────

    #[test]
    fn alloc_metadata_no_metadata_bg_fails() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        // Only add a data block group, no metadata.
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let result = alloc.alloc_metadata(4096);
        assert!(
            result.is_err(),
            "metadata alloc without metadata bg should fail"
        );
    }

    #[test]
    fn extent_allocator_adversarial_rejects_overflowing_block_group_range() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = u64::MAX - 1024;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 4096));

        let err = alloc
            .alloc_data(512)
            .expect_err("overflowing block group end should be rejected");
        assert_eq!(err, BtrfsMutationError::AddressOverflow);

        let bg = alloc.block_group(bg_start).expect("bg");
        assert_eq!(
            bg.used_bytes, 0,
            "failed allocation should not change accounting"
        );
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn extent_allocator_adversarial_propagates_range_scan_errors() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 8192));
        alloc.extent_tree.root = u64::MAX;

        let err = alloc
            .alloc_data(4096)
            .expect_err("broken allocation tree should fail closed");
        assert_eq!(err, BtrfsMutationError::MissingNode(u64::MAX));

        let bg = alloc.block_group(bg_start).expect("bg");
        assert_eq!(
            bg.used_bytes, 0,
            "failed allocation should not change accounting"
        );
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn extent_allocator_adversarial_allows_exact_tail_fit() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 8192));

        let first = alloc.alloc_data(4096).expect("first half");
        let second = alloc.alloc_data(4096).expect("exact tail fit");
        assert_eq!(first.bytenr, bg_start);
        assert_eq!(second.bytenr, bg_start + 4096);

        let bg = alloc.block_group(bg_start).expect("bg");
        assert_eq!(bg.used_bytes, 8192);
        assert_eq!(bg.free_bytes(), 0);

        let err = alloc
            .alloc_data(1)
            .expect_err("full block group should reject one more byte");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("no block group with enough free space")
        );
    }

    #[test]
    fn extent_refcount_after_alloc_and_flush_is_one() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let ext = alloc.alloc_data(4096).expect("alloc");
        // Allocation queues a delayed ref; flush it to materialize the refcount.
        alloc.flush_delayed_refs(usize::MAX).expect("flush refs");
        let key = ExtentKey {
            bytenr: ext.bytenr,
            num_bytes: ext.num_bytes,
        };
        assert_eq!(alloc.extent_refcount(key), 1);
    }

    #[test]
    fn extent_refcount_after_free_is_zero() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let ext = alloc.alloc_data(4096).expect("alloc");
        alloc
            .free_extent(ext.bytenr, ext.num_bytes, false)
            .expect("free");
        // Flush delayed refs to apply both the insert and remove.
        alloc.flush_delayed_refs(usize::MAX).expect("flush refs");
        let key = ExtentKey {
            bytenr: ext.bytenr,
            num_bytes: ext.num_bytes,
        };
        assert_eq!(alloc.extent_refcount(key), 0);
    }

    #[test]
    fn extent_allocator_adversarial_rejects_free_without_owning_block_group() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 8192));
        let bytenr = 0x20_0000;
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: 4096,
        };
        let extent_item = BtrfsExtentItem {
            refs: 1,
            generation: 1,
            flags: 0,
        };
        alloc
            .extent_tree
            .insert(key, &extent_item.to_bytes())
            .expect("insert orphan extent");

        let err = alloc
            .free_extent(bytenr, 4096, false)
            .expect_err("orphan extent should fail closed");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("extent has no owning block group")
        );

        assert_eq!(
            alloc
                .extent_tree
                .range(&key, &key)
                .expect("extent lookup should still work")
                .len(),
            1,
            "failed free should not delete the extent item"
        );
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn extent_allocator_adversarial_rejects_free_accounting_underflow() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 8192));
        let key = BtrfsKey {
            objectid: bg_start,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: 4096,
        };
        let extent_item = BtrfsExtentItem {
            refs: 1,
            generation: 1,
            flags: 0,
        };
        alloc
            .extent_tree
            .insert(key, &extent_item.to_bytes())
            .expect("insert inconsistent extent");

        let err = alloc
            .free_extent(bg_start, 4096, false)
            .expect_err("accounting underflow should fail closed");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("block group used bytes underflow")
        );

        let bg = alloc.block_group(bg_start).expect("bg");
        assert_eq!(bg.used_bytes, 0);
        assert_eq!(
            alloc
                .extent_tree
                .range(&key, &key)
                .expect("extent lookup should still work")
                .len(),
            1,
            "failed free should not delete the extent item"
        );
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn total_used_and_capacity_computations() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_size = 0x100_000_u64;
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, bg_size));
        alloc.add_block_group(0x20_0000, make_meta_bg(0x20_0000, bg_size));

        assert_eq!(alloc.total_capacity(), bg_size * 2);
        assert_eq!(alloc.total_used(), 0);

        alloc.alloc_data(4096).expect("data alloc");
        alloc.alloc_metadata(8192).expect("meta alloc");

        assert_eq!(alloc.total_used(), 4096 + 8192);
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), bg_size - 4096);
        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_METADATA), bg_size - 8192);
    }

    #[test]
    fn largest_free_extent_reports_fragmented_data_gap() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        alloc.add_block_group(bg_start, make_data_bg(bg_start, 16 * 4096));

        let _first = alloc.alloc_data(4 * 4096).expect("first");
        let middle = alloc.alloc_data(4 * 4096).expect("middle");
        let _last = alloc.alloc_data(4 * 4096).expect("last");
        alloc
            .free_extent(middle.bytenr, middle.num_bytes, false)
            .expect("free middle");

        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), 8 * 4096);
        assert_eq!(
            alloc
                .largest_free_extent(BTRFS_BLOCK_GROUP_DATA)
                .expect("largest gap"),
            4 * 4096
        );
    }

    #[test]
    fn largest_free_extent_respects_untracked_used_prefix() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let bg_start = 0x10_0000;
        let mut bg = make_data_bg(bg_start, 64 * 4096);
        bg.used_bytes = 16 * 4096;
        alloc.add_block_group(bg_start, bg);

        let first = alloc.alloc_data(16 * 4096).expect("first");
        let _second = alloc.alloc_data(8 * 4096).expect("second");
        alloc
            .free_extent(first.bytenr, first.num_bytes, false)
            .expect("free first");

        assert_eq!(alloc.total_free(BTRFS_BLOCK_GROUP_DATA), 40 * 4096);
        assert_eq!(
            alloc
                .largest_free_extent(BTRFS_BLOCK_GROUP_DATA)
                .expect("largest gap"),
            24 * 4096
        );
    }

    #[test]
    fn largest_free_extent_is_scoped_by_block_group_type() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        let data_start = 0x10_0000;
        let meta_start = 0x20_0000;
        alloc.add_block_group(data_start, make_data_bg(data_start, 16 * 4096));
        alloc.add_block_group(meta_start, make_meta_bg(meta_start, 32 * 4096));

        let _data = alloc.alloc_data(12 * 4096).expect("data");
        let _meta = alloc.alloc_metadata(4 * 4096).expect("metadata");

        assert_eq!(
            alloc
                .largest_free_extent(BTRFS_BLOCK_GROUP_DATA)
                .expect("data largest"),
            4 * 4096
        );
        assert_eq!(
            alloc
                .largest_free_extent(BTRFS_BLOCK_GROUP_METADATA)
                .expect("metadata largest"),
            28 * 4096
        );
    }

    #[test]
    fn drain_delayed_refs_returns_all_queued() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let _ext = alloc.alloc_data(4096).expect("alloc");
        // alloc_data queues a delayed ref; verify drain works.
        assert_eq!(alloc.delayed_ref_count(), 1);
        let drained = alloc.drain_delayed_refs();
        assert_eq!(drained.len(), 1);
        assert_eq!(alloc.delayed_ref_count(), 0);
    }

    #[test]
    fn multiple_allocs_sequential_in_same_bg() {
        let mut alloc = BtrfsExtentAllocator::new(1).expect("alloc");
        alloc.add_block_group(0x10_0000, make_data_bg(0x10_0000, 0x100_000));

        let a1 = alloc.alloc_data(4096).expect("alloc 1");
        let a2 = alloc.alloc_data(4096).expect("alloc 2");
        let a3 = alloc.alloc_data(4096).expect("alloc 3");

        // All should come from the same block group.
        assert_eq!(a1.block_group_start, 0x10_0000);
        assert_eq!(a2.block_group_start, 0x10_0000);
        assert_eq!(a3.block_group_start, 0x10_0000);

        // None should overlap.
        let extents = [
            (a1.bytenr, a1.bytenr + a1.num_bytes),
            (a2.bytenr, a2.bytenr + a2.num_bytes),
            (a3.bytenr, a3.bytenr + a3.num_bytes),
        ];
        for i in 0..extents.len() {
            for j in (i + 1)..extents.len() {
                assert!(
                    extents[i].1 <= extents[j].0 || extents[j].1 <= extents[i].0,
                    "extents {i} and {j} overlap: {:?} vs {:?}",
                    extents[i],
                    extents[j]
                );
            }
        }

        assert_eq!(alloc.total_used(), 4096 * 3);
    }

    #[test]
    fn block_group_item_serialization_round_trip() {
        let bg = BtrfsBlockGroupItem {
            total_bytes: 0x100_000,
            used_bytes: 0x50_000,
            flags: BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA,
        };
        let bytes = bg.to_bytes();
        assert_eq!(bytes.len(), 24);
        // Serialization order: used_bytes, total_bytes, flags
        assert_eq!(
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            0x50_000
        );
        assert_eq!(
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            0x100_000
        );
        assert_eq!(
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            BTRFS_BLOCK_GROUP_DATA | BTRFS_BLOCK_GROUP_METADATA
        );
        assert_eq!(bg.free_bytes(), 0x100_000 - 0x50_000);
    }

    #[test]
    fn extent_item_to_bytes_round_trip() {
        let ext = BtrfsExtentItem {
            refs: 3,
            generation: 42,
            flags: 1,
        };
        let bytes = ext.to_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 42);
        assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 1);
    }

    #[test]
    fn delayed_ref_queue_drain_all_empties_queue() {
        let mut queue = DelayedRefQueue::new();
        let key = ExtentKey {
            bytenr: 0x1000,
            num_bytes: 4096,
        };
        queue.queue(
            key,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );
        queue.queue(
            key,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 4096,
            },
            RefAction::Insert,
        );
        assert_eq!(queue.pending_count(), 2);

        let drained = queue.drain_all();
        assert_eq!(drained.len(), 2);
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn delayed_ref_queue_pending_for_filters_by_extent() {
        let mut queue = DelayedRefQueue::new();
        let key_a = ExtentKey {
            bytenr: 0x1000,
            num_bytes: 4096,
        };
        let key_b = ExtentKey {
            bytenr: 0x2000,
            num_bytes: 8192,
        };
        queue.queue(
            key_a,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 256,
                offset: 0,
            },
            RefAction::Insert,
        );
        queue.queue(
            key_b,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 257,
                offset: 0,
            },
            RefAction::Insert,
        );
        queue.queue(
            key_a,
            BtrfsRef::DataExtent {
                root: BTRFS_FS_TREE_OBJECTID,
                objectid: 258,
                offset: 0,
            },
            RefAction::Insert,
        );

        assert_eq!(queue.pending_for(&key_a).len(), 2);
        assert_eq!(queue.pending_for(&key_b).len(), 1);
    }

    fn delayed_data_ref(objectid: u64) -> BtrfsRef {
        BtrfsRef::DataExtent {
            root: BTRFS_FS_TREE_OBJECTID,
            objectid,
            offset: 0,
        }
    }

    #[test]
    fn delayed_ref_queue_adversarial_flush_boundaries() {
        let key_a = ExtentKey {
            bytenr: 0x1000,
            num_bytes: 4096,
        };
        let key_b = ExtentKey {
            bytenr: 0x2000,
            num_bytes: 8192,
        };
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::new();

        queue.queue(key_a, delayed_data_ref(1), RefAction::Insert);
        assert_eq!(queue.flush(0, &mut refcounts).expect("zero-limit flush"), 0);
        assert_eq!(queue.pending_count(), 1);
        assert!(refcounts.is_empty());
        assert_eq!(queue.pending_for(&key_a).len(), 1);

        queue.queue(key_a, delayed_data_ref(2), RefAction::Insert);
        queue.queue(key_b, delayed_data_ref(3), RefAction::Insert);
        assert_eq!(queue.pending_count(), 3);

        let flushed = queue.flush(2, &mut refcounts).expect("bounded flush");
        assert_eq!(flushed, 2);
        assert_eq!(queue.pending_count(), 1);
        assert_eq!(refcounts.get(&key_a), Some(&2));
        assert_eq!(queue.pending_for(&key_a).len(), 0);
        assert_eq!(queue.pending_for(&key_b).len(), 1);
    }

    #[test]
    fn delayed_ref_queue_adversarial_delete_underflow_preserves_queue() {
        let key = ExtentKey {
            bytenr: 0x3000,
            num_bytes: 4096,
        };
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::new();

        queue.queue(key, delayed_data_ref(4), RefAction::Delete);
        let err = queue
            .flush(1, &mut refcounts)
            .expect_err("delete without refcount");
        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("delayed ref delete without prior refcount")
        );
        assert_eq!(queue.pending_count(), 1);
        assert_eq!(queue.pending_for(&key).len(), 1);
        assert!(refcounts.is_empty());
    }

    #[test]
    fn delayed_ref_queue_failed_flush_is_atomic_for_refcounts() {
        let inserted = ExtentKey {
            bytenr: 0x3000,
            num_bytes: 4096,
        };
        let missing_delete = ExtentKey {
            bytenr: 0x7000,
            num_bytes: 4096,
        };
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::new();

        queue.queue(inserted, delayed_data_ref(4), RefAction::Insert);
        queue.queue(missing_delete, delayed_data_ref(5), RefAction::Delete);
        let err = queue
            .flush(2, &mut refcounts)
            .expect_err("delete without refcount");

        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("delayed ref delete without prior refcount")
        );
        assert!(
            refcounts.is_empty(),
            "failed batch must not materialize earlier successful refs"
        );
        assert_eq!(queue.pending_count(), 2);
        assert_eq!(queue.pending_for(&inserted).len(), 1);
        assert_eq!(queue.pending_for(&missing_delete).len(), 1);

        refcounts.insert(missing_delete, 1);
        let flushed = queue.flush(2, &mut refcounts).expect("retry flush");
        assert_eq!(flushed, 2);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(refcounts.get(&inserted), Some(&1));
        assert!(!refcounts.contains_key(&missing_delete));
    }

    #[test]
    fn delayed_ref_queue_insert_overflow_is_atomic() {
        let key = ExtentKey {
            bytenr: 0x3000,
            num_bytes: 4096,
        };
        let mut queue = DelayedRefQueue::new();
        let mut refcounts = BTreeMap::from([(key, u64::MAX)]);

        queue.queue(key, delayed_data_ref(4), RefAction::Insert);
        let err = queue
            .flush(1, &mut refcounts)
            .expect_err("refcount overflow");

        assert_eq!(
            err,
            BtrfsMutationError::BrokenInvariant("delayed ref insert overflow")
        );
        assert_eq!(refcounts.get(&key), Some(&u64::MAX));
        assert_eq!(queue.pending_count(), 1);
        assert_eq!(queue.pending_for(&key).len(), 1);
    }

    #[test]
    fn delayed_ref_queue_drain_all_preserves_sequence_across_key_order() {
        let key_low = ExtentKey {
            bytenr: 0x1000,
            num_bytes: 4096,
        };
        let key_high = ExtentKey {
            bytenr: 0x9000,
            num_bytes: 4096,
        };
        let mut queue = DelayedRefQueue::new();

        queue.queue(key_high, delayed_data_ref(10), RefAction::Insert);
        queue.queue(key_low, delayed_data_ref(11), RefAction::Insert);
        queue.queue(key_high, delayed_data_ref(12), RefAction::Delete);

        let drained = queue.drain_all();
        assert_eq!(drained.len(), 3);
        assert_eq!(
            drained
                .iter()
                .map(|entry| entry.sequence)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(drained[0].extent, key_high);
        assert_eq!(drained[1].extent, key_low);
        assert_eq!(drained[2].extent, key_high);
        assert_eq!(drained[2].action, RefAction::Delete);
        assert_eq!(queue.pending_count(), 0);
        assert!(queue.pending_for(&key_low).is_empty());
        assert!(queue.pending_for(&key_high).is_empty());
    }

    // ── Subvolume enumeration tests ────────────────────────────────

    fn make_root_item_data(bytenr: u64, generation: u64, flags: u64) -> Vec<u8> {
        let mut data = vec![0_u8; 279];
        data[160..168].copy_from_slice(&generation.to_le_bytes()); // generation
        data[168..176].copy_from_slice(&256_u64.to_le_bytes()); // root_dirid
        data[176..184].copy_from_slice(&bytenr.to_le_bytes()); // bytenr
        data[208..216].copy_from_slice(&flags.to_le_bytes()); // flags
        data[216..220].copy_from_slice(&1_u32.to_le_bytes()); // refs
        // uuid at 247, parent_uuid at 263 — left as zeros
        data[238] = 0; // level
        data[239..247].copy_from_slice(&generation.to_le_bytes()); // generation_v2
        data
    }

    fn make_root_item_with_uuids(
        bytenr: u64,
        generation: u64,
        flags: u64,
        uuid: [u8; 16],
        parent_uuid: [u8; 16],
    ) -> Vec<u8> {
        let mut data = make_root_item_data(bytenr, generation, flags);
        data[247..263].copy_from_slice(&uuid);
        data[263..279].copy_from_slice(&parent_uuid);
        data
    }

    fn make_root_ref_data(dirid: u64, name: &[u8]) -> Vec<u8> {
        let mut data = vec![0_u8; 18 + name.len()];
        let name_len = u16::try_from(name.len()).expect("root ref name length must fit u16");
        data[0..8].copy_from_slice(&dirid.to_le_bytes());
        data[8..16].copy_from_slice(&0_u64.to_le_bytes()); // sequence
        data[16..18].copy_from_slice(&name_len.to_le_bytes());
        data[18..18 + name.len()].copy_from_slice(name);
        data
    }

    #[test]
    fn enumerate_subvolumes_finds_user_subvols() {
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x1000, 10, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 256,
                },
                data: make_root_ref_data(256, b"mysubvol"),
            },
        ];
        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert_eq!(subvols[0].id, 256);
        assert_eq!(subvols[0].name, "mysubvol");
        assert_eq!(subvols[0].generation, 10);
        assert!(!subvols[0].read_only);
    }

    #[test]
    fn enumerate_subvolumes_skips_system_trees() {
        let entries = vec![
            // System tree (objectid < 256) — should be skipped
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x2000, 5, 0),
            },
        ];
        let subvols = enumerate_subvolumes(&entries);
        assert!(subvols.is_empty());
    }

    #[test]
    fn enumerate_subvolumes_read_only_flag() {
        let entries = vec![BtrfsLeafEntry {
            key: BtrfsKey {
                objectid: 300,
                item_type: BTRFS_ITEM_ROOT_ITEM,
                offset: 0,
            },
            data: make_root_item_data(0x3000, 20, 1), // flags=1 = RDONLY
        }];
        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert!(subvols[0].read_only);
    }

    #[test]
    fn enumerate_subvolumes_no_root_ref_uses_fallback_name() {
        let entries = vec![BtrfsLeafEntry {
            key: BtrfsKey {
                objectid: 500,
                item_type: BTRFS_ITEM_ROOT_ITEM,
                offset: 0,
            },
            data: make_root_item_data(0x5000, 15, 0),
        }];
        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert_eq!(subvols[0].name, "subvol-500");
    }

    #[test]
    fn enumerate_subvolumes_malformed_root_ref_uses_fallback_name() {
        let mut malformed_ref = make_root_ref_data(256, b"broken");
        malformed_ref.truncate(20);
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 600,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x6000, 22, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 600,
                },
                data: malformed_ref,
            },
        ];

        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert_eq!(subvols[0].name, "subvol-600");
    }

    #[test]
    fn enumerate_subvolumes_trailing_root_ref_uses_fallback_name() {
        let mut malformed_ref = make_root_ref_data(256, b"broken");
        malformed_ref.extend_from_slice(b"trailing");
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 601,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x6000, 22, 0),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 601,
                },
                data: malformed_ref,
            },
        ];

        let subvols = enumerate_subvolumes(&entries);
        assert_eq!(subvols.len(), 1);
        assert_eq!(subvols[0].name, "subvol-601");
    }

    // ── Snapshot enumeration tests ─────────────────────────────────

    #[test]
    fn enumerate_snapshots_finds_snapshots() {
        let src_uuid = [1_u8; 16];
        let snap_uuid = [2_u8; 16];
        let entries = vec![
            // Source subvolume
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x1000, 10, 0, src_uuid, [0; 16]),
            },
            // Snapshot (parent_uuid = src_uuid)
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x2000, 15, 1, snap_uuid, src_uuid),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 257,
                },
                data: make_root_ref_data(256, b"my_snapshot"),
            },
        ];
        let snapshots = enumerate_snapshots(&entries);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].id, 257);
        assert_eq!(snapshots[0].source_id, 256);
        assert_eq!(snapshots[0].name, "my_snapshot");
        assert_eq!(snapshots[0].generation, 15);
    }

    #[test]
    fn enumerate_snapshots_ignores_regular_subvolumes() {
        let entries = vec![BtrfsLeafEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: BTRFS_ITEM_ROOT_ITEM,
                offset: 0,
            },
            data: make_root_item_with_uuids(0x1000, 10, 0, [1; 16], [0; 16]),
        }];
        let snapshots = enumerate_snapshots(&entries);
        assert!(
            snapshots.is_empty(),
            "regular subvolume should not be listed as snapshot"
        );
    }

    #[test]
    fn enumerate_snapshots_malformed_root_ref_uses_fallback_name() {
        let src_uuid = [1_u8; 16];
        let snap_uuid = [2_u8; 16];
        let mut malformed_ref = make_root_ref_data(256, b"broken_snapshot");
        malformed_ref.truncate(21);
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x1000, 10, 0, src_uuid, [0; 16]),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 257,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x2000, 15, 1, snap_uuid, src_uuid),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 257,
                },
                data: malformed_ref,
            },
        ];

        let snapshots = enumerate_snapshots(&entries);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "snap-257");
    }

    // ── Snapshot diff tests ────────────────────────────────────────

    fn make_inode_entry(objectid: u64, generation: u64) -> BtrfsLeafEntry {
        let mut data = vec![0_u8; 160];
        data[0..8].copy_from_slice(&generation.to_le_bytes()); // generation
        data[8..16].copy_from_slice(&100_u64.to_le_bytes()); // size
        data[24..28].copy_from_slice(&1_u32.to_le_bytes()); // nlink
        data[32..36].copy_from_slice(&0o100_644_u32.to_le_bytes()); // mode
        BtrfsLeafEntry {
            key: BtrfsKey {
                objectid,
                item_type: BTRFS_ITEM_INODE_ITEM,
                offset: 0,
            },
            data,
        }
    }

    fn inode_entries_from_generations(generations: &BTreeMap<u64, u64>) -> Vec<BtrfsLeafEntry> {
        generations
            .iter()
            .map(|(&objectid, &generation)| make_inode_entry(objectid, generation))
            .collect()
    }

    const REPRESENTATIVE_SUBVOLUME_SNAPSHOT_ENUMERATION_GOLDEN: &str = concat!(
        "subvolumes\n",
        "  id=256 parent=5 name=src gen=10 ro=false bytenr=0x1000 level=0\n",
        "  id=300 parent=0 name=subvol-300 gen=22 ro=true bytenr=0x3000 level=0\n",
        "  id=400 parent=5 name=snap-a gen=15 ro=true bytenr=0x2000 level=0\n",
        "snapshots\n",
        "  id=400 source=256 name=snap-a gen=15 uuid=02020202020202020202020202020202 parent_uuid=01010101010101010101010101010101 bytenr=0x2000 level=0\n",
        "diff\n",
        "  inode=100 change=deleted\n",
        "  inode=200 change=modified\n",
        "  inode=300 change=deleted\n",
        "  inode=400 change=added"
    );

    fn format_uuid_hex(uuid: [u8; 16]) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(32);
        for byte in uuid {
            write!(&mut out, "{byte:02x}").expect("write to String");
        }
        out
    }

    fn representative_subvolume_snapshot_enumeration_actual() -> String {
        use std::fmt::Write as _;

        let src_uuid = [1_u8; 16];
        let snap_uuid = [2_u8; 16];
        let entries = vec![
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x1000, 10, 0, src_uuid, [0; 16]),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 300,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_data(0x3000, 22, 1),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 400,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                },
                data: make_root_item_with_uuids(0x2000, 15, 1, snap_uuid, src_uuid),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 256,
                },
                data: make_root_ref_data(256, b"src"),
            },
            BtrfsLeafEntry {
                key: BtrfsKey {
                    objectid: 5,
                    item_type: BTRFS_ITEM_ROOT_REF,
                    offset: 400,
                },
                data: make_root_ref_data(256, b"snap-a"),
            },
        ];
        let older = vec![
            make_inode_entry(100, 5),
            make_inode_entry(200, 5),
            make_inode_entry(300, 5),
        ];
        let newer = vec![make_inode_entry(200, 10), make_inode_entry(400, 8)];
        let subvols = enumerate_subvolumes(&entries);
        let snapshots = enumerate_snapshots(&entries);
        let diffs = snapshot_diff_by_generation(&older, &newer);

        let mut out = String::new();
        out.push_str("subvolumes\n");
        for subvol in &subvols {
            writeln!(
                &mut out,
                "  id={} parent={} name={} gen={} ro={} bytenr=0x{:x} level={}",
                subvol.id,
                subvol.parent_id,
                subvol.name,
                subvol.generation,
                subvol.read_only,
                subvol.bytenr,
                subvol.level
            )
            .expect("write subvolume");
        }
        out.push_str("snapshots\n");
        for snapshot in &snapshots {
            writeln!(
                &mut out,
                "  id={} source={} name={} gen={} uuid={} parent_uuid={} bytenr=0x{:x} level={}",
                snapshot.id,
                snapshot.source_id,
                snapshot.name,
                snapshot.generation,
                format_uuid_hex(snapshot.uuid),
                format_uuid_hex(snapshot.parent_uuid),
                snapshot.bytenr,
                snapshot.level
            )
            .expect("write snapshot");
        }
        out.push_str("diff\n");
        for diff in &diffs {
            let change = match diff.change_type {
                SnapshotChangeType::Added => "added",
                SnapshotChangeType::Modified => "modified",
                SnapshotChangeType::Deleted => "deleted",
            };
            writeln!(&mut out, "  inode={} change={change}", diff.inode).expect("write diff");
        }
        out.pop();
        out
    }

    #[test]
    fn snapshot_diff_detects_added() {
        let older = vec![make_inode_entry(256, 10)];
        let newer = vec![make_inode_entry(256, 10), make_inode_entry(257, 15)];
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].inode, 257);
        assert_eq!(diffs[0].change_type, SnapshotChangeType::Added);
    }

    #[test]
    fn snapshot_diff_detects_deleted() {
        let older = vec![make_inode_entry(256, 10), make_inode_entry(257, 10)];
        let newer = vec![make_inode_entry(256, 10)];
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].inode, 257);
        assert_eq!(diffs[0].change_type, SnapshotChangeType::Deleted);
    }

    #[test]
    fn snapshot_diff_detects_modified() {
        let older = vec![make_inode_entry(256, 10)];
        let newer = vec![make_inode_entry(256, 20)]; // higher generation
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].inode, 256);
        assert_eq!(diffs[0].change_type, SnapshotChangeType::Modified);
    }

    #[test]
    fn snapshot_diff_identical_no_changes() {
        let older = vec![make_inode_entry(256, 10), make_inode_entry(257, 10)];
        let newer = vec![make_inode_entry(256, 10), make_inode_entry(257, 10)];
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert!(diffs.is_empty());
    }

    #[test]
    fn snapshot_diff_multiple_changes() {
        let older = vec![
            make_inode_entry(100, 5),
            make_inode_entry(200, 5),
            make_inode_entry(300, 5),
        ];
        let newer = vec![
            make_inode_entry(200, 10), // modified
            make_inode_entry(400, 8),  // added (100 and 300 deleted)
        ];
        let diffs = snapshot_diff_by_generation(&older, &newer);
        assert_eq!(diffs.len(), 4);
        // Sorted by inode
        assert_eq!(diffs[0].inode, 100);
        assert_eq!(diffs[0].change_type, SnapshotChangeType::Deleted);
        assert_eq!(diffs[1].inode, 200);
        assert_eq!(diffs[1].change_type, SnapshotChangeType::Modified);
        assert_eq!(diffs[2].inode, 300);
        assert_eq!(diffs[2].change_type, SnapshotChangeType::Deleted);
        assert_eq!(diffs[3].inode, 400);
        assert_eq!(diffs[3].change_type, SnapshotChangeType::Added);
    }

    /// Property: diff(snapshot, snapshot) is always empty for any snapshot
    /// shape. Keep this fixed-seed regression sweep alongside the proptest
    /// coverage below so a regression that flagged identical inode sets as
    /// Added or Modified surfaces immediately with a deterministic case.
    ///
    /// Implementation: deterministic LCG-driven sweep over (inode_count,
    /// generation_distribution) shapes.
    #[test]
    fn snapshot_diff_self_diff_is_always_empty() {
        // Linear congruential generator (Numerical Recipes constants) for
        // reproducible per-iteration entropy.
        let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let mut next = || -> u64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };

        for _ in 0..256 {
            let entry_count =
                usize::try_from(next() % 16).expect("value reduced modulo 16 fits in usize");
            let entries: Vec<BtrfsLeafEntry> = (0..entry_count)
                .map(|i| {
                    // Mix unique objectid (256 + i) so every entry collides
                    // exactly once with itself, with varied generations.
                    let objectid = 256 + i as u64;
                    let generation = next() % 1000;
                    make_inode_entry(objectid, generation)
                })
                .collect();
            let diffs = snapshot_diff_by_generation(&entries, &entries);
            assert!(
                diffs.is_empty(),
                "self-diff over {entry_count} entries must be empty, got {diffs:?}"
            );
        }
    }

    /// Property: diff(empty, snapshot) reports every inode in snapshot as
    /// Added. Pins the symmetry of the Added/Deleted classification.
    #[test]
    fn snapshot_diff_empty_to_snapshot_reports_all_added() {
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = || -> u64 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };

        for _ in 0..64 {
            let entry_count =
                1 + usize::try_from(next() % 12).expect("value reduced modulo 12 fits in usize");
            let entries: Vec<BtrfsLeafEntry> = (0..entry_count)
                .map(|i| make_inode_entry(256 + i as u64, next() % 1000))
                .collect();
            let added = snapshot_diff_by_generation(&[], &entries);
            assert_eq!(added.len(), entry_count);
            assert!(
                added
                    .iter()
                    .all(|d| d.change_type == SnapshotChangeType::Added),
                "every diff entry must be Added when older is empty"
            );
            // Sorted by inode (snapshot_diff_by_generation contract).
            for window in added.windows(2) {
                assert!(window[0].inode < window[1].inode);
            }

            let deleted = snapshot_diff_by_generation(&entries, &[]);
            assert_eq!(deleted.len(), entry_count);
            assert!(
                deleted
                    .iter()
                    .all(|d| d.change_type == SnapshotChangeType::Deleted),
                "every diff entry must be Deleted when newer is empty"
            );
        }
    }

    proptest! {
        #[test]
        fn snapshot_diff_self_diff_proptest_is_empty(
            generations in proptest::collection::btree_map(256_u64..4096, any::<u64>(), 0..32),
        ) {
            let entries = inode_entries_from_generations(&generations);
            prop_assert!(snapshot_diff_by_generation(&entries, &entries).is_empty());
        }

        #[test]
        fn snapshot_diff_empty_snapshot_proptest_reports_added_and_deleted(
            generations in proptest::collection::btree_map(256_u64..4096, any::<u64>(), 0..32),
        ) {
            let entries = inode_entries_from_generations(&generations);
            let expected_inodes: Vec<u64> = generations.keys().copied().collect();

            let added = snapshot_diff_by_generation(&[], &entries);
            let added_inodes: Vec<u64> = added.iter().map(|diff| diff.inode).collect();
            prop_assert_eq!(added_inodes.as_slice(), expected_inodes.as_slice());
            prop_assert!(
                added
                    .iter()
                    .all(|diff| diff.change_type == SnapshotChangeType::Added)
            );

            let deleted = snapshot_diff_by_generation(&entries, &[]);
            let deleted_inodes: Vec<u64> = deleted.iter().map(|diff| diff.inode).collect();
            prop_assert_eq!(deleted_inodes.as_slice(), expected_inodes.as_slice());
            prop_assert!(
                deleted
                    .iter()
                    .all(|diff| diff.change_type == SnapshotChangeType::Deleted)
            );
        }

        #[test]
        fn snapshot_diff_same_inode_set_only_reports_generation_increases(
            generations in proptest::collection::btree_map(
                256_u64..4096,
                (0_u64..10_000, 0_u64..3),
                0..32,
            ),
        ) {
            let older: Vec<BtrfsLeafEntry> = generations
                .iter()
                .map(|(&objectid, &(old_generation, _delta))| {
                    make_inode_entry(objectid, old_generation)
                })
                .collect();
            let newer: Vec<BtrfsLeafEntry> = generations
                .iter()
                .map(|(&objectid, &(old_generation, delta))| {
                    make_inode_entry(objectid, old_generation + delta)
                })
                .collect();
            let expected: Vec<SnapshotDiffEntry> = generations
                .iter()
                .filter_map(|(&objectid, &(_old_generation, delta))| {
                    (delta > 0).then_some(SnapshotDiffEntry {
                        inode: objectid,
                        change_type: SnapshotChangeType::Modified,
                    })
                })
                .collect();

            prop_assert_eq!(snapshot_diff_by_generation(&older, &newer), expected);
        }
    }

    #[test]
    fn representative_subvolume_snapshot_enumeration_exact_golden_contract() {
        assert_eq!(
            representative_subvolume_snapshot_enumeration_actual(),
            REPRESENTATIVE_SUBVOLUME_SNAPSHOT_ENUMERATION_GOLDEN
        );
    }

    // ── ROOT_REF parsing tests ─────────────────────────────────────

    #[test]
    fn parse_root_ref_valid() {
        let data = make_root_ref_data(256, b"test_subvol");
        let rref = parse_root_ref(&data).unwrap();
        assert_eq!(rref.dirid, 256);
        assert_eq!(rref.name, b"test_subvol");
    }

    #[test]
    fn parse_root_ref_too_short() {
        let data = vec![0_u8; 10];
        let err = parse_root_ref(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    // bd-ay4aw: metamorphic proptests for parse_root_ref.
    // Existing tests cover 3 fixed-input cases. parse_root_ref has
    // STRICT length semantics: it rejects both data.len() < name_end
    // AND data.len() > name_end (exact match required, unlike
    // parse_inode_refs which allows multiple concatenated entries).
    // These proptests sweep arbitrary (dirid, sequence, name) tuples
    // plus append/truncate variants to lock the contract.
    proptest::proptest! {
        // MR-1 round-trip: stamp a valid root_ref payload and parse
        // it back, asserting every field round-trips.
        #[test]
        fn parse_root_ref_proptest_round_trip(
            dirid in proptest::prelude::any::<u64>(),
            sequence in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=64),
        ) {
            // Stamp payload: 8 dirid + 8 sequence + 2 name_len + name.
            let mut bytes = Vec::with_capacity(18 + name.len());
            bytes.extend_from_slice(&dirid.to_le_bytes());
            bytes.extend_from_slice(&sequence.to_le_bytes());
            let name_len = u16::try_from(name.len()).expect("name fits u16");
            bytes.extend_from_slice(&name_len.to_le_bytes());
            bytes.extend_from_slice(&name);

            let parsed = parse_root_ref(&bytes).expect("valid stamp must parse");
            proptest::prop_assert_eq!(parsed.dirid, dirid);
            proptest::prop_assert_eq!(parsed.sequence, sequence);
            proptest::prop_assert_eq!(parsed.name, name);
        }

        // MR-2 append-rejection: parse_root_ref requires exact
        // length match. Appending arbitrary non-empty suffix must
        // produce InvalidField "does not match payload length".
        #[test]
        fn parse_root_ref_proptest_append_rejection(
            dirid in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
            suffix in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
        ) {
            let mut bytes = make_root_ref_data(dirid, &name);
            bytes.extend_from_slice(&suffix);
            let err = parse_root_ref(&bytes).err().expect("append must reject");
            // Specific variant intentionally not asserted to avoid
            // over-coupling; rendering must succeed (no-panic).
            let _ = format!("{err:?}");
        }

        // MR-3 truncation-rejection: removing any non-zero suffix
        // from a valid encoding must produce an error rather than
        // a panic or buffer over-read.
        #[test]
        fn parse_root_ref_proptest_truncation_rejection(
            dirid in proptest::prelude::any::<u64>(),
            name in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..=32),
            k in 1_usize..50,
        ) {
            let bytes = make_root_ref_data(dirid, &name);
            let trunc = k.min(bytes.len() - 1);
            let truncated = &bytes[..bytes.len() - trunc];
            let err = parse_root_ref(truncated)
                .err()
                .expect("truncated must reject");
            let _ = format!("{err:?}");
        }
    }

    #[test]
    fn parse_root_ref_adversarial_samples_exercise_boundaries() {
        let empty_name = make_root_ref_data(256, b"");
        assert_invalid_field(
            parse_root_ref(&empty_name),
            "root_ref.name_len",
            "must be non-zero",
        );

        let long_name = vec![b'a'; 255];
        let parsed = parse_root_ref(&make_root_ref_data(4096, &long_name))
            .expect("parse long root ref name");
        assert_eq!(parsed.dirid, 4096);
        assert_eq!(parsed.name, long_name);

        let mut trailing = make_root_ref_data(512, b"subvol");
        trailing.extend_from_slice(b"trailing");
        assert_invalid_field(
            parse_root_ref(&trailing),
            "root_ref.name_len",
            "does not match payload length",
        );

        assert_insufficient_data(parse_root_ref(&[0_u8; 17]), 18, 0, 17);

        let mut truncated_name = vec![0_u8; 20];
        truncated_name[16..18].copy_from_slice(&5_u16.to_le_bytes());
        assert_insufficient_data(parse_root_ref(&truncated_name), 23, 18, 2);
    }

    // ── RAID6 parity wraparound regression test ────────────────────

    #[test]
    fn raid6_parity_wraparound_selects_correct_data_device() {
        use ffs_ondisk::{
            BtrfsChunkEntry, BtrfsKey, BtrfsRaidProfile, BtrfsStripe, chunk_type_flags,
            map_logical_to_stripes,
        };

        // 4 devices, RAID6 (2 parity), stripe_len=65536, data_stripes=2
        let chunk = BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 0x100,
                item_type: 228,
                offset: 0,
            },
            length: 65536 * 2 * 8,
            owner: 2,
            stripe_len: 65536,
            chunk_type: chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
                | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes: 4,
            sub_stripes: 0,
            stripes: vec![
                BtrfsStripe {
                    devid: 1,
                    offset: 0x10_0000,
                    dev_uuid: [0; 16],
                },
                BtrfsStripe {
                    devid: 2,
                    offset: 0x20_0000,
                    dev_uuid: [0; 16],
                },
                BtrfsStripe {
                    devid: 3,
                    offset: 0x30_0000,
                    dev_uuid: [0; 16],
                },
                BtrfsStripe {
                    devid: 4,
                    offset: 0x40_0000,
                    dev_uuid: [0; 16],
                },
            ],
        };
        let chunks = vec![chunk];

        // Row 3: P at pos 3 (dev 4), Q at pos 0 (dev 1).
        // Data should be at pos 1 (dev 2) and pos 2 (dev 3).
        // Row 3 offset = 3 * 65536 * 2 = 393216
        let r = map_logical_to_stripes(&chunks, 393_216).unwrap().unwrap();
        assert_eq!(r.profile, BtrfsRaidProfile::Raid6);
        assert_ne!(
            r.stripes[0].devid, 1,
            "dev 1 is Q parity in row 3, must not be data target"
        );
        assert_ne!(
            r.stripes[0].devid, 4,
            "dev 4 is P parity in row 3, must not be data target"
        );
        assert_eq!(r.stripes[0].devid, 2, "data stripe 0 should be dev 2");

        // Row 3, data stripe 1
        let r2 = map_logical_to_stripes(&chunks, 393_216 + 65_536)
            .unwrap()
            .unwrap();
        assert_eq!(r2.stripes[0].devid, 3, "data stripe 1 should be dev 3");
    }

    // ── Send stream tests ───────────────────────────────────────────────

    fn make_send_stream_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        data.extend_from_slice(&BTRFS_SEND_STREAM_VERSION.to_le_bytes());
        data
    }

    fn append_send_command(data: &mut Vec<u8>, cmd: u16, payload: &[u8]) {
        let payload_len =
            u32::try_from(payload.len()).expect("test send command payload length fits u32");
        let command_start = data.len();
        data.extend_from_slice(&payload_len.to_le_bytes());
        data.extend_from_slice(&cmd.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(payload);
        let crc = send_stream_command_crc32c(&data[command_start..]);
        data[command_start + 6..command_start + 10].copy_from_slice(&crc.to_le_bytes());
    }

    fn append_send_attr(payload: &mut Vec<u8>, attr_type: u16, attr_data: &[u8]) {
        let attr_len =
            u16::try_from(attr_data.len()).expect("test send attr payload length fits u16");
        payload.extend_from_slice(&attr_type.to_le_bytes());
        payload.extend_from_slice(&attr_len.to_le_bytes());
        payload.extend_from_slice(attr_data);
    }

    #[test]
    fn parse_send_stream_minimal() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::End as u16, &[]);

        let result = parse_send_stream(&data).unwrap();
        assert_eq!(result.version, 1);
        assert_eq!(result.commands.len(), 1);
        assert_eq!(result.commands[0].cmd, SendCommand::End);
    }

    #[test]
    fn parse_send_stream_adversarial_samples_exercise_boundaries() {
        let mut no_end = make_send_stream_data();
        append_send_command(&mut no_end, 0xffff, &[]);
        let err = parse_send_stream(&no_end).unwrap_err();
        assert!(matches!(err, ffs_types::ParseError::InvalidField { .. }));

        let mut attrs = Vec::new();
        append_send_attr(&mut attrs, 15, b"");
        append_send_attr(&mut attrs, 0xfffe, b"payload");
        let mut multi_attr = make_send_stream_data();
        append_send_command(&mut multi_attr, 4, &attrs);
        append_send_command(&mut multi_attr, 21, &[]);
        let parsed = parse_send_stream(&multi_attr).expect("parse multi-attribute command");
        assert_eq!(parsed.commands.len(), 2);
        assert_eq!(parsed.commands[0].cmd, SendCommand::Mkdir);
        assert_eq!(parsed.commands[0].attrs.len(), 2);
        assert_eq!(parsed.commands[0].attrs[0], (15, Vec::new()));
        assert_eq!(parsed.commands[0].attrs[1], (0xfffe, b"payload".to_vec()));
        assert_eq!(parsed.commands[1].cmd, SendCommand::End);

        let mut partial_header = make_send_stream_data();
        append_send_command(&mut partial_header, 4, &[]);
        partial_header.extend_from_slice(&[0xaa; 9]);
        assert_insufficient_data(parse_send_stream(&partial_header), 10, 27, 9);

        let mut end_payload = Vec::new();
        append_send_attr(&mut end_payload, 15, b"x");
        let mut end_with_payload = make_send_stream_data();
        append_send_command(&mut end_with_payload, 21, &end_payload);
        let parsed = parse_send_stream(&end_with_payload).expect("parse end command TLV payload");
        assert_eq!(parsed.commands.len(), 1);
        assert_eq!(parsed.commands[0].cmd, SendCommand::End);
        assert_eq!(parsed.commands[0].attrs, vec![(15, b"x".to_vec())]);
    }

    #[test]
    fn parse_send_stream_rejects_crc_mismatch() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::End as u16, &[]);
        data[23] ^= 0x01;

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(err, ffs_types::ParseError::InvalidField { .. }));
    }

    #[test]
    fn parse_send_stream_rejects_malformed_end_payload() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::End as u16, b"bad");

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn parse_send_stream_with_mkdir() {
        // MKDIR command with path attribute
        let path = b"/testdir";
        let mut payload = Vec::new();
        append_send_attr(&mut payload, 15, path);
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::Mkdir as u16, &payload);
        append_send_command(&mut data, SendCommand::End as u16, &[]);

        let result = parse_send_stream(&data).unwrap();
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0].cmd, SendCommand::Mkdir);
        assert_eq!(result.commands[0].attrs.len(), 1);
        assert_eq!(result.commands[0].attrs[0].0, 15); // Path attr
        assert_eq!(result.commands[0].attrs[0].1, path);
        assert_eq!(result.commands[1].cmd, SendCommand::End);
    }

    #[test]
    fn parse_send_stream_rejects_bad_magic() {
        let data = b"not-btrfs-magic\x01\x00\x00\x00";
        assert!(parse_send_stream(data).is_err());
    }

    #[test]
    fn parse_send_stream_rejects_unsupported_version() {
        let mut data = Vec::new();
        data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        data.extend_from_slice(&BTRFS_SEND_STREAM_VERSION.saturating_add(1).to_le_bytes());
        append_send_command(&mut data, SendCommand::End as u16, &[]);

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InvalidField {
                field: "send_stream_version",
                ..
            }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_truncated_command() {
        let mut data = Vec::new();
        data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        data.extend_from_slice(&1_u32.to_le_bytes());
        data.extend_from_slice(&4_u32.to_le_bytes()); // cmd_len
        data.extend_from_slice(&4_u16.to_le_bytes()); // cmd = Mkdir
        data.extend_from_slice(&0_u32.to_le_bytes()); // crc

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_truncated_command_header() {
        let mut data = Vec::new();
        data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
        data.extend_from_slice(&1_u32.to_le_bytes());
        data.extend_from_slice(&[0xAA, 0xBB]); // partial command header

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_truncated_attribute() {
        // Command with attribute header but missing attribute payload.
        let mut payload = Vec::new();
        payload.extend_from_slice(&15_u16.to_le_bytes()); // attr type = Path
        payload.extend_from_slice(&8_u16.to_le_bytes()); // attr len (missing payload)
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::Mkdir as u16, &payload);

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_truncated_attribute_header() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::Mkdir as u16, &[0x11, 0x22]);

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(
            err,
            ffs_types::ParseError::InsufficientData { .. }
        ));
    }

    #[test]
    fn parse_send_stream_rejects_trailing_bytes_after_end() {
        let mut data = make_send_stream_data();
        append_send_command(&mut data, SendCommand::End as u16, &[]);
        data.extend_from_slice(&[0xEE, 0xFF]); // trailing bytes

        let err = parse_send_stream(&data).unwrap_err();
        assert!(matches!(err, ffs_types::ParseError::InvalidField { .. }));
    }

    /// bd-f0q7n — Kernel-conformance pin for the on-disk item-key
    /// type field constants declared as `BTRFS_ITEM_*` in this crate.
    /// Each value mirrors a kernel macro from `fs/btrfs/btrfs_tree.h`.
    /// A regression that swapped, e.g., BTRFS_ITEM_DIR_ITEM (84) and
    /// BTRFS_ITEM_DIR_INDEX (96) would silently mis-route every btrfs
    /// directory iteration — dir_index entries would be parsed as
    /// dir_item entries (different key.offset semantics: hash vs
    /// sequence-counter). This test pins each value plus the
    /// monotonic ordering across the reserved range.
    #[test]
    fn btrfs_item_key_constants_match_kernel_header() {
        // Values per fs/btrfs/btrfs_tree.h:
        //   #define BTRFS_INODE_ITEM_KEY        1
        //   #define BTRFS_INODE_REF_KEY        12
        //   #define BTRFS_XATTR_ITEM_KEY       24
        //   #define BTRFS_DIR_ITEM_KEY         84
        //   #define BTRFS_DIR_INDEX_KEY        96
        //   #define BTRFS_EXTENT_DATA_KEY     108
        //   #define BTRFS_ROOT_ITEM_KEY       132
        //   #define BTRFS_EXTENT_ITEM_KEY     168
        //   #define BTRFS_METADATA_ITEM_KEY   169
        //   #define BTRFS_BLOCK_GROUP_ITEM_KEY 192
        //   #define BTRFS_FREE_SPACE_INFO_KEY  198
        //   #define BTRFS_FREE_SPACE_EXTENT_KEY 199
        //   #define BTRFS_FREE_SPACE_BITMAP_KEY 200
        //   #define BTRFS_DEV_ITEM_KEY        216
        //   #define BTRFS_CHUNK_ITEM_KEY      228
        assert_eq!(BTRFS_ITEM_INODE_ITEM, 1);
        assert_eq!(BTRFS_ITEM_INODE_REF, 12);
        assert_eq!(BTRFS_ITEM_XATTR_ITEM, 24);
        assert_eq!(BTRFS_ITEM_DIR_ITEM, 84);
        assert_eq!(BTRFS_ITEM_DIR_INDEX, 96);
        assert_eq!(BTRFS_ITEM_EXTENT_DATA, 108);
        assert_eq!(BTRFS_ITEM_ROOT_ITEM, 132);
        assert_eq!(BTRFS_ITEM_EXTENT_ITEM, 168);
        assert_eq!(BTRFS_ITEM_METADATA_ITEM, 169);
        assert_eq!(BTRFS_ITEM_BLOCK_GROUP_ITEM, 192);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_INFO, 198);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_EXTENT, 199);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_BITMAP, 200);
        assert_eq!(BTRFS_ITEM_DEV_ITEM, 216);
        assert_eq!(BTRFS_ITEM_CHUNK, 228);

        // Strict-monotonic ascending across the 15-element set; pins
        // that no two constants collide and that the implicit
        // dispatch order (small inode/ref/xattr keys before large
        // extent/chunk keys) is preserved.
        const {
            assert!(
                BTRFS_ITEM_INODE_ITEM < BTRFS_ITEM_INODE_REF
                    && BTRFS_ITEM_INODE_REF < BTRFS_ITEM_XATTR_ITEM
                    && BTRFS_ITEM_XATTR_ITEM < BTRFS_ITEM_DIR_ITEM
                    && BTRFS_ITEM_DIR_ITEM < BTRFS_ITEM_DIR_INDEX
                    && BTRFS_ITEM_DIR_INDEX < BTRFS_ITEM_EXTENT_DATA
                    && BTRFS_ITEM_EXTENT_DATA < BTRFS_ITEM_ROOT_ITEM
                    && BTRFS_ITEM_ROOT_ITEM < BTRFS_ITEM_EXTENT_ITEM
                    && BTRFS_ITEM_EXTENT_ITEM < BTRFS_ITEM_METADATA_ITEM
                    && BTRFS_ITEM_METADATA_ITEM < BTRFS_ITEM_BLOCK_GROUP_ITEM
                    && BTRFS_ITEM_BLOCK_GROUP_ITEM < BTRFS_ITEM_FREE_SPACE_INFO
                    && BTRFS_ITEM_FREE_SPACE_INFO < BTRFS_ITEM_FREE_SPACE_EXTENT
                    && BTRFS_ITEM_FREE_SPACE_EXTENT < BTRFS_ITEM_FREE_SPACE_BITMAP
                    && BTRFS_ITEM_FREE_SPACE_BITMAP < BTRFS_ITEM_DEV_ITEM
                    && BTRFS_ITEM_DEV_ITEM < BTRFS_ITEM_CHUNK,
                "btrfs item-key constants must be strict-monotonic ascending"
            );
        }

        // Boundary checks — pin specific kernel-published gaps so a
        // future contributor adding a constant in the middle (e.g.,
        // BTRFS_ROOT_BACKREF_KEY=144) doesn't accidentally collide
        // with an existing value.
        const {
            assert!(
                BTRFS_ITEM_ROOT_ITEM == 132 && BTRFS_ITEM_EXTENT_ITEM == 168,
                "kernel reserves 133..168 for {{ROOT_BACKREF=144, ROOT_REF=156}} \
                 — these slots must remain free"
            );
            assert!(
                BTRFS_ITEM_METADATA_ITEM == 169 && BTRFS_ITEM_BLOCK_GROUP_ITEM == 192,
                "kernel reserves 170..192 for {{TREE_BLOCK_REF=176, EXTENT_DATA_REF=178, \
                 SHARED_BLOCK_REF=182, SHARED_DATA_REF=184}} — these slots must remain free"
            );
        }
    }

    /// bd-cwfuf — Kernel-conformance pin for directory entry file-type
    /// values stored in `struct btrfs_dir_item.type`.
    #[test]
    fn btrfs_dir_file_type_constants_match_kernel_header() {
        // Values per include/uapi/linux/btrfs_tree.h, and the kernel
        // requires 0..7 to match the common Linux file type values.
        assert_eq!(BTRFS_FT_UNKNOWN, 0);
        assert_eq!(BTRFS_FT_REG_FILE, 1);
        assert_eq!(BTRFS_FT_DIR, 2);
        assert_eq!(BTRFS_FT_CHRDEV, 3);
        assert_eq!(BTRFS_FT_BLKDEV, 4);
        assert_eq!(BTRFS_FT_FIFO, 5);
        assert_eq!(BTRFS_FT_SOCK, 6);
        assert_eq!(BTRFS_FT_SYMLINK, 7);

        const {
            assert!(
                BTRFS_FT_UNKNOWN < BTRFS_FT_REG_FILE
                    && BTRFS_FT_REG_FILE < BTRFS_FT_DIR
                    && BTRFS_FT_DIR < BTRFS_FT_CHRDEV
                    && BTRFS_FT_CHRDEV < BTRFS_FT_BLKDEV
                    && BTRFS_FT_BLKDEV < BTRFS_FT_FIFO
                    && BTRFS_FT_FIFO < BTRFS_FT_SOCK
                    && BTRFS_FT_SOCK < BTRFS_FT_SYMLINK,
                "btrfs dir file-type constants must be strict-monotonic ascending"
            );
        }
        assert_eq!(
            BTRFS_FT_SYMLINK - BTRFS_FT_UNKNOWN,
            7,
            "the supported btrfs dir file-type range must be contiguous 0..=7"
        );
    }

    /// bd-cwfuf — Kernel-conformance pin for EXTENT_DATA payload type
    /// discriminants stored in `struct btrfs_file_extent_item.type`.
    #[test]
    fn btrfs_file_extent_type_constants_match_kernel_header() {
        // Values per include/uapi/linux/btrfs_tree.h.
        assert_eq!(BTRFS_FILE_EXTENT_INLINE, 0);
        assert_eq!(BTRFS_FILE_EXTENT_REG, 1);
        assert_eq!(BTRFS_FILE_EXTENT_PREALLOC, 2);

        const {
            assert!(
                BTRFS_FILE_EXTENT_INLINE < BTRFS_FILE_EXTENT_REG
                    && BTRFS_FILE_EXTENT_REG < BTRFS_FILE_EXTENT_PREALLOC,
                "btrfs file extent type constants must be strict-monotonic ascending"
            );
        }
        assert_eq!(
            BTRFS_FILE_EXTENT_PREALLOC - BTRFS_FILE_EXTENT_INLINE,
            2,
            "the btrfs file extent type range must be contiguous 0..=2"
        );
    }

    /// bd-cwfuf — Kernel-conformance pin for btrfs compression encoding
    /// values accepted by the EXTENT_DATA parser.
    #[test]
    fn btrfs_compression_type_constants_match_kernel_header() {
        // Values per fs/btrfs/fs.h `enum btrfs_compression_type`.
        assert_eq!(BTRFS_COMPRESS_NONE, 0);
        assert_eq!(BTRFS_COMPRESS_ZLIB, 1);
        assert_eq!(BTRFS_COMPRESS_LZO, 2);
        assert_eq!(BTRFS_COMPRESS_ZSTD, 3);

        const {
            assert!(
                BTRFS_COMPRESS_NONE < BTRFS_COMPRESS_ZLIB
                    && BTRFS_COMPRESS_ZLIB < BTRFS_COMPRESS_LZO
                    && BTRFS_COMPRESS_LZO < BTRFS_COMPRESS_ZSTD,
                "btrfs compression constants must be strict-monotonic ascending"
            );
        }
        assert_eq!(
            BTRFS_COMPRESS_ZSTD - BTRFS_COMPRESS_NONE,
            3,
            "the btrfs compression type range must be contiguous 0..=3"
        );
    }

    /// bd-m6chz — Kernel-conformance pin for the 17 BTRFS_ITEM_*
    /// leaf-key type constants per `include/uapi/linux/btrfs_tree.h`.
    ///
    /// Every leaf walk in the btrfs read path dispatches to the
    /// right payload parser (parse_inode_item, parse_dir_items,
    /// parse_inode_refs, parse_xattr_items, parse_extent_data,
    /// parse_root_item, parse_root_ref, …) by matching the leaf
    /// item's `key.type` against these constants. A regression that
    /// swapped any two values (e.g., DIR_ITEM=84 ↔ DIR_INDEX=96)
    /// would silently route the wrong parser for every leaf walk
    /// but pass functional tests that only exercise INODE_ITEM.
    ///
    /// Pairs with bd-qyfph (BTRFS_FT_*), bd-cwfuf (FILE_EXTENT +
    /// COMPRESS), bd-6uu7j (chunk_type_flags), bd-khzn4 (tree
    /// objectids).
    #[test]
    fn btrfs_leaf_item_type_constants_match_kernel_header() {
        // Values per include/uapi/linux/btrfs_tree.h.
        // Read-path types.
        assert_eq!(BTRFS_ITEM_INODE_ITEM, 1);
        assert_eq!(BTRFS_ITEM_INODE_REF, 12);
        assert_eq!(BTRFS_ITEM_XATTR_ITEM, 24);
        assert_eq!(BTRFS_ITEM_DIR_ITEM, 84);
        assert_eq!(BTRFS_ITEM_DIR_INDEX, 96);
        assert_eq!(BTRFS_ITEM_EXTENT_DATA, 108);
        assert_eq!(BTRFS_ITEM_ROOT_ITEM, 132);
        // Subvolume nav.
        assert_eq!(BTRFS_ITEM_ROOT_BACKREF, 144);
        assert_eq!(BTRFS_ITEM_ROOT_REF, 156);
        // Extent / block-group / chunk management.
        assert_eq!(BTRFS_ITEM_EXTENT_ITEM, 168);
        assert_eq!(BTRFS_ITEM_METADATA_ITEM, 169);
        assert_eq!(BTRFS_ITEM_BLOCK_GROUP_ITEM, 192);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_INFO, 198);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_EXTENT, 199);
        assert_eq!(BTRFS_ITEM_FREE_SPACE_BITMAP, 200);
        assert_eq!(BTRFS_ITEM_DEV_ITEM, 216);
        assert_eq!(BTRFS_ITEM_CHUNK, 228);

        // Uniqueness invariant: every constant must have a distinct
        // value so the leaf-walk dispatch is unambiguous.
        let constants: [(&str, u8); 17] = [
            ("INODE_ITEM", BTRFS_ITEM_INODE_ITEM),
            ("INODE_REF", BTRFS_ITEM_INODE_REF),
            ("XATTR_ITEM", BTRFS_ITEM_XATTR_ITEM),
            ("DIR_ITEM", BTRFS_ITEM_DIR_ITEM),
            ("DIR_INDEX", BTRFS_ITEM_DIR_INDEX),
            ("EXTENT_DATA", BTRFS_ITEM_EXTENT_DATA),
            ("ROOT_ITEM", BTRFS_ITEM_ROOT_ITEM),
            ("ROOT_BACKREF", BTRFS_ITEM_ROOT_BACKREF),
            ("ROOT_REF", BTRFS_ITEM_ROOT_REF),
            ("EXTENT_ITEM", BTRFS_ITEM_EXTENT_ITEM),
            ("METADATA_ITEM", BTRFS_ITEM_METADATA_ITEM),
            ("BLOCK_GROUP_ITEM", BTRFS_ITEM_BLOCK_GROUP_ITEM),
            ("FREE_SPACE_INFO", BTRFS_ITEM_FREE_SPACE_INFO),
            ("FREE_SPACE_EXTENT", BTRFS_ITEM_FREE_SPACE_EXTENT),
            ("FREE_SPACE_BITMAP", BTRFS_ITEM_FREE_SPACE_BITMAP),
            ("DEV_ITEM", BTRFS_ITEM_DEV_ITEM),
            ("CHUNK", BTRFS_ITEM_CHUNK),
        ];
        for (i, &(name_a, value_a)) in constants.iter().enumerate() {
            for &(name_b, value_b) in &constants[i + 1..] {
                assert_ne!(
                    value_a, value_b,
                    "BTRFS_ITEM_{name_a} and BTRFS_ITEM_{name_b} must have distinct values"
                );
            }
        }
    }

    /// bd-qyfph — Kernel-conformance pin for the BTRFS_FT_* directory
    /// file-type constants stored in `struct btrfs_dir_item.type` per
    /// `include/uapi/linux/btrfs_tree.h`. These values mirror the kernel
    /// `DT_*` constants from `include/uapi/linux/fs.h` (UNKNOWN=0,
    /// REG=1, DIR=2, CHR=3, BLK=4, FIFO=5, SOCK=6, LNK=7).
    ///
    /// A regression that swapped any two values would silently
    /// mis-classify every directory entry by file type but pass
    /// functional tests that only round-trip through a single
    /// `BtrfsDirItem` round-trip (e.g., dir_item_round_trip uses
    /// REG_FILE only).
    ///
    /// Pairs with bd-343v3 (ext4 EXT4_FT_*), bd-cwfuf (btrfs file-extent
    /// + compression types), bd-6uu7j (btrfs chunk_type_flags),
    ///   bd-khzn4 (btrfs tree objectids).
    #[test]
    fn btrfs_ft_constants_match_kernel_header() {
        // Values per include/uapi/linux/fs.h DT_* (mirrored by
        // include/uapi/linux/btrfs_tree.h BTRFS_FT_*).
        assert_eq!(
            BTRFS_FT_UNKNOWN, 0,
            "BTRFS_FT_UNKNOWN must equal kernel DT_UNKNOWN"
        );
        assert_eq!(
            BTRFS_FT_REG_FILE, 1,
            "BTRFS_FT_REG_FILE must equal kernel DT_REG"
        );
        assert_eq!(BTRFS_FT_DIR, 2, "BTRFS_FT_DIR must equal kernel DT_DIR");
        assert_eq!(
            BTRFS_FT_CHRDEV, 3,
            "BTRFS_FT_CHRDEV must equal kernel DT_CHR"
        );
        assert_eq!(
            BTRFS_FT_BLKDEV, 4,
            "BTRFS_FT_BLKDEV must equal kernel DT_BLK"
        );
        assert_eq!(BTRFS_FT_FIFO, 5, "BTRFS_FT_FIFO must equal kernel DT_FIFO");
        assert_eq!(BTRFS_FT_SOCK, 6, "BTRFS_FT_SOCK must equal kernel DT_SOCK");
        assert_eq!(
            BTRFS_FT_SYMLINK, 7,
            "BTRFS_FT_SYMLINK must equal kernel DT_LNK"
        );

        // Strict-monotonic ascending across the contiguous 0..=7 range.
        let values: [u8; 8] = [
            BTRFS_FT_UNKNOWN,
            BTRFS_FT_REG_FILE,
            BTRFS_FT_DIR,
            BTRFS_FT_CHRDEV,
            BTRFS_FT_BLKDEV,
            BTRFS_FT_FIFO,
            BTRFS_FT_SOCK,
            BTRFS_FT_SYMLINK,
        ];
        for window in values.windows(2) {
            assert!(
                window[0] < window[1],
                "BTRFS_FT_* constants must be strict-monotonic ascending"
            );
        }
        assert_eq!(
            BTRFS_FT_SYMLINK - BTRFS_FT_UNKNOWN,
            7,
            "the BTRFS_FT_* range must be contiguous 0..=7"
        );

        // Cross-check with ext4 parity: each BTRFS_FT_* equals the
        // corresponding ext4 EXT4_FT_* (verified separately at
        // bd-343v3) — this strict equality is what lets the FUSE
        // layer use a single `u8` discriminant across both backends.
        // Asserting the integer values here is sufficient.
    }

    /// bd-cwfuf — Kernel-conformance pin for `BTRFS_MAX_LEVEL`.
    #[test]
    fn btrfs_max_tree_level_matches_kernel_level_count() {
        // The kernel macro is a count (`BTRFS_MAX_LEVEL == 8`), while
        // this crate stores the highest valid on-disk level (`0..=7`).
        assert_eq!(BTRFS_MAX_TREE_LEVEL, 7);
        assert_eq!(BTRFS_MAX_TREE_LEVEL + 1, 8);
    }

    /// bd-khzn4 — Kernel-conformance pin for the well-known btrfs
    /// tree objectids declared in `fs/btrfs/btrfs_tree.h`. A regression
    /// that swapped, say, BTRFS_FREE_SPACE_TREE (10) and
    /// BTRFS_BLOCK_GROUP_TREE (11) would silently mis-route v2 metadata
    /// reads. This test pins each value AND the strict-monotonic
    /// ordering across the contiguous reserved range 1..=11 plus the
    /// FIRST_FREE = 256 boundary.
    #[test]
    fn btrfs_tree_objectid_constants_match_kernel_header() {
        // Values per fs/btrfs/btrfs_tree.h.
        assert_eq!(BTRFS_ROOT_TREE_OBJECTID, 1);
        assert_eq!(BTRFS_EXTENT_TREE_OBJECTID, 2);
        assert_eq!(BTRFS_CHUNK_TREE_OBJECTID, 3);
        assert_eq!(BTRFS_DEV_TREE_OBJECTID, 4);
        assert_eq!(BTRFS_FS_TREE_OBJECTID, 5);
        assert_eq!(BTRFS_ROOT_TREE_DIR_OBJECTID, 6);
        assert_eq!(BTRFS_CSUM_TREE_OBJECTID, 7);
        assert_eq!(BTRFS_QUOTA_TREE_OBJECTID, 8);
        assert_eq!(BTRFS_UUID_TREE_OBJECTID, 9);
        assert_eq!(BTRFS_FREE_SPACE_TREE_OBJECTID, 10);
        assert_eq!(BTRFS_BLOCK_GROUP_TREE_OBJECTID, 11);
        assert_eq!(BTRFS_FIRST_FREE_OBJECTID, 256);

        // Strict-monotonic ascending across the reserved range, with
        // a jump to FIRST_FREE that leaves room for non-upstream
        // tree objectids in [12, 256).
        const {
            assert!(
                BTRFS_ROOT_TREE_OBJECTID < BTRFS_EXTENT_TREE_OBJECTID
                    && BTRFS_EXTENT_TREE_OBJECTID < BTRFS_CHUNK_TREE_OBJECTID
                    && BTRFS_CHUNK_TREE_OBJECTID < BTRFS_DEV_TREE_OBJECTID
                    && BTRFS_DEV_TREE_OBJECTID < BTRFS_FS_TREE_OBJECTID
                    && BTRFS_FS_TREE_OBJECTID < BTRFS_ROOT_TREE_DIR_OBJECTID
                    && BTRFS_ROOT_TREE_DIR_OBJECTID < BTRFS_CSUM_TREE_OBJECTID
                    && BTRFS_CSUM_TREE_OBJECTID < BTRFS_QUOTA_TREE_OBJECTID
                    && BTRFS_QUOTA_TREE_OBJECTID < BTRFS_UUID_TREE_OBJECTID
                    && BTRFS_UUID_TREE_OBJECTID < BTRFS_FREE_SPACE_TREE_OBJECTID
                    && BTRFS_FREE_SPACE_TREE_OBJECTID < BTRFS_BLOCK_GROUP_TREE_OBJECTID
                    && BTRFS_BLOCK_GROUP_TREE_OBJECTID < BTRFS_FIRST_FREE_OBJECTID,
                "btrfs tree objectids must be strict-monotonic ascending"
            );
        }

        // The reserved range is contiguous 1..=11 (no gaps).
        assert_eq!(
            BTRFS_BLOCK_GROUP_TREE_OBJECTID - BTRFS_ROOT_TREE_OBJECTID,
            10,
            "the reserved tree objectid range must be contiguous 1..=11"
        );
    }
}
