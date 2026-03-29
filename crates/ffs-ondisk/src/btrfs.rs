#![forbid(unsafe_code)]

use ffs_types as crc32c;
use ffs_types::{
    BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, ParseError, read_fixed,
    read_le_u16, read_le_u32, read_le_u64, trim_nul_padded,
};
use serde::{Deserialize, Serialize};

const BTRFS_HEADER_SIZE: usize = 101;
const BTRFS_ITEM_SIZE: usize = 25;
/// Size of a btrfs_key_ptr on disk (key:17 + blockptr:u64 + generation:u64).
const BTRFS_KEY_PTR_SIZE: usize = 33;
/// Maximum tree depth in btrfs (kernel enforces 8 levels, 0-7).
const BTRFS_MAX_LEVEL: u8 = 7;
const BTRFS_SUPER_LABEL_OFFSET: usize = 0x12B;
const BTRFS_SUPER_LABEL_LEN: usize = 256;
const BTRFS_SYS_CHUNK_ARRAY_OFFSET: usize = 0x32B;
const BTRFS_SYS_CHUNK_ARRAY_MAX: usize = 2048;
/// Size of a btrfs_disk_key on disk (objectid:u64 + type:u8 + offset:u64).
const BTRFS_DISK_KEY_SIZE: usize = 17;
/// Minimum chunk size: header fields before the stripe array (48 bytes).
const BTRFS_CHUNK_FIXED_SIZE: usize = 48;
/// Size of one btrfs_stripe on disk (devid:u64 + offset:u64 + dev_uuid:16).
const BTRFS_STRIPE_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsSuperblock {
    pub csum: [u8; 32],
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub magic: u64,
    pub generation: u64,
    pub root: u64,
    pub chunk_root: u64,
    pub log_root: u64,
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub stripesize: u32,
    pub compat_flags: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub csum_type: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub log_root_level: u8,
    pub label: String,
    pub sys_chunk_array_size: u32,
    pub sys_chunk_array: Vec<u8>,
}

impl BtrfsSuperblock {
    #[allow(clippy::too_many_lines)]
    pub fn parse_superblock_region(region: &[u8]) -> Result<Self, ParseError> {
        if region.len() < BTRFS_SUPER_INFO_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_SUPER_INFO_SIZE,
                offset: 0,
                actual: region.len(),
            });
        }

        let magic = read_le_u64(region, 0x40)?;
        if magic != BTRFS_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: BTRFS_MAGIC,
                actual: magic,
            });
        }

        let sectorsize = read_le_u32(region, 0x90)?;
        let nodesize = read_le_u32(region, 0x94)?;
        let stripesize = read_le_u32(region, 0x9C)?;

        // Validate sectorsize: must be non-zero and power-of-two, 4K typical
        if sectorsize == 0 || !sectorsize.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "sectorsize",
                reason: "must be non-zero power of two",
            });
        }
        // Validate nodesize: must be non-zero and power-of-two, typically 4K-64K
        if nodesize == 0 || !nodesize.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "nodesize",
                reason: "must be non-zero power of two",
            });
        }
        // Validate stripesize: must be non-zero and power-of-two when set
        if stripesize != 0 && !stripesize.is_power_of_two() {
            return Err(ParseError::InvalidField {
                field: "stripesize",
                reason: "must be zero or power of two",
            });
        }
        // Sane upper bounds (256K for sector/stripe, 256K for node)
        if sectorsize > 256 * 1024 {
            return Err(ParseError::InvalidField {
                field: "sectorsize",
                reason: "exceeds 256K upper bound",
            });
        }
        if nodesize > 256 * 1024 {
            return Err(ParseError::InvalidField {
                field: "nodesize",
                reason: "exceeds 256K upper bound",
            });
        }

        // Parse sys_chunk_array_size and validate
        let sys_chunk_array_size = read_le_u32(region, 0xA0)?;
        let sys_array_len =
            usize::try_from(sys_chunk_array_size).map_err(|_| ParseError::IntegerConversion {
                field: "sys_chunk_array_size",
            })?;
        if sys_array_len > BTRFS_SYS_CHUNK_ARRAY_MAX {
            return Err(ParseError::InvalidField {
                field: "sys_chunk_array_size",
                reason: "exceeds 2048 byte limit",
            });
        }

        // Extract sys_chunk_array bytes
        let array_end = BTRFS_SYS_CHUNK_ARRAY_OFFSET
            .checked_add(sys_array_len)
            .ok_or(ParseError::InvalidField {
                field: "sys_chunk_array",
                reason: "offset overflow",
            })?;
        if array_end > region.len() {
            return Err(ParseError::InsufficientData {
                needed: array_end,
                offset: BTRFS_SYS_CHUNK_ARRAY_OFFSET,
                actual: region.len(),
            });
        }
        let sys_chunk_array = region[BTRFS_SYS_CHUNK_ARRAY_OFFSET..array_end].to_vec();

        Ok(Self {
            csum: read_fixed::<32>(region, 0x00)?,
            fsid: read_fixed::<16>(region, 0x20)?,
            bytenr: read_le_u64(region, 0x30)?,
            flags: read_le_u64(region, 0x38)?,
            magic,
            generation: read_le_u64(region, 0x48)?,
            root: read_le_u64(region, 0x50)?,
            chunk_root: read_le_u64(region, 0x58)?,
            log_root: read_le_u64(region, 0x60)?,
            total_bytes: read_le_u64(region, 0x70)?,
            bytes_used: read_le_u64(region, 0x78)?,
            root_dir_objectid: read_le_u64(region, 0x80)?,
            num_devices: read_le_u64(region, 0x88)?,
            sectorsize,
            nodesize,
            stripesize,
            compat_flags: read_le_u64(region, 0xAC)?,
            compat_ro_flags: read_le_u64(region, 0xB4)?,
            incompat_flags: read_le_u64(region, 0xBC)?,
            csum_type: read_le_u16(region, 0xC4)?,
            root_level: region[0xC6],
            chunk_root_level: region[0xC7],
            log_root_level: region[0xC8],
            label: trim_nul_padded(&read_fixed::<BTRFS_SUPER_LABEL_LEN>(
                region,
                BTRFS_SUPER_LABEL_OFFSET,
            )?),
            sys_chunk_array_size,
            sys_chunk_array,
        })
    }

    pub fn parse_from_image(image: &[u8]) -> Result<Self, ParseError> {
        let end = BTRFS_SUPER_INFO_OFFSET
            .checked_add(BTRFS_SUPER_INFO_SIZE)
            .ok_or(ParseError::InvalidField {
                field: "superblock_offset",
                reason: "overflow",
            })?;

        if image.len() < end {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_SUPER_INFO_SIZE,
                offset: BTRFS_SUPER_INFO_OFFSET,
                actual: image.len().saturating_sub(BTRFS_SUPER_INFO_OFFSET),
            });
        }

        Self::parse_superblock_region(&image[BTRFS_SUPER_INFO_OFFSET..end])
    }
}

// ── sys_chunk_array entry types ──────────────────────────────────────────────

/// A single stripe within a btrfs chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsStripe {
    pub devid: u64,
    pub offset: u64,
    pub dev_uuid: [u8; 16],
}

/// A parsed entry from the superblock's sys_chunk_array.
///
/// Each entry consists of a `btrfs_disk_key` followed by a `btrfs_chunk`
/// (which embeds one or more `btrfs_stripe` entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsChunkEntry {
    pub key: BtrfsKey,
    pub length: u64,
    pub owner: u64,
    pub stripe_len: u64,
    pub chunk_type: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub num_stripes: u16,
    pub sub_stripes: u16,
    pub stripes: Vec<BtrfsStripe>,
}

/// Parse all entries from a sys_chunk_array byte slice.
///
/// The array contains alternating `btrfs_disk_key` + `btrfs_chunk` entries.
/// Each chunk embeds `num_stripes` stripe descriptors.
pub fn parse_sys_chunk_array(data: &[u8]) -> Result<Vec<BtrfsChunkEntry>, ParseError> {
    let mut entries = Vec::new();
    let mut cur = 0_usize;

    while cur < data.len() {
        // Need at least a disk key (17 bytes)
        if cur + BTRFS_DISK_KEY_SIZE > data.len() {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_DISK_KEY_SIZE,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let key = BtrfsKey {
            objectid: read_le_u64(data, cur)?,
            item_type: data[cur + 8],
            offset: read_le_u64(data, cur + 9)?,
        };
        cur += BTRFS_DISK_KEY_SIZE;

        // Need at least the fixed chunk header (48 bytes) to read num_stripes
        if cur + BTRFS_CHUNK_FIXED_SIZE > data.len() {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_CHUNK_FIXED_SIZE,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let length = read_le_u64(data, cur)?;
        let owner = read_le_u64(data, cur + 8)?;
        let stripe_len = read_le_u64(data, cur + 16)?;
        let chunk_type = read_le_u64(data, cur + 24)?;
        let io_align = read_le_u32(data, cur + 32)?;
        let io_width = read_le_u32(data, cur + 36)?;
        let sector_size = read_le_u32(data, cur + 40)?;
        let num_stripes = read_le_u16(data, cur + 44)?;
        let sub_stripes = read_le_u16(data, cur + 46)?;
        cur += BTRFS_CHUNK_FIXED_SIZE;

        if num_stripes == 0 {
            return Err(ParseError::InvalidField {
                field: "num_stripes",
                reason: "chunk must have at least one stripe",
            });
        }

        let stripes_count = usize::from(num_stripes);
        let stripes_bytes =
            stripes_count
                .checked_mul(BTRFS_STRIPE_SIZE)
                .ok_or(ParseError::InvalidField {
                    field: "num_stripes",
                    reason: "stripe count overflow",
                })?;

        if cur + stripes_bytes > data.len() {
            return Err(ParseError::InsufficientData {
                needed: stripes_bytes,
                offset: cur,
                actual: data.len() - cur,
            });
        }

        let mut stripes = Vec::with_capacity(stripes_count);
        for _ in 0..stripes_count {
            stripes.push(BtrfsStripe {
                devid: read_le_u64(data, cur)?,
                offset: read_le_u64(data, cur + 8)?,
                dev_uuid: read_fixed::<16>(data, cur + 16)?,
            });
            cur += BTRFS_STRIPE_SIZE;
        }

        entries.push(BtrfsChunkEntry {
            key,
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
        });
    }

    Ok(entries)
}

// ── Logical → physical mapping ──────────────────────────────────────────────

/// Result of a logical-to-physical bytenr mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsPhysicalMapping {
    pub devid: u64,
    pub physical: u64,
}

/// Map a logical byte address to a physical (device, offset) pair using
/// only the sys_chunk_array entries.
///
/// This is the bootstrap mapping needed to read the chunk tree and root
/// tree from a single-device btrfs image. For multi-device or RAID
/// layouts, the full chunk tree is required.
///
/// Returns `Ok(Some(mapping))` if the logical address is covered,
/// `Ok(None)` if no chunk covers it, or `Err` on malformed data.
pub fn map_logical_to_physical(
    chunks: &[BtrfsChunkEntry],
    logical: u64,
) -> Result<Option<BtrfsPhysicalMapping>, ParseError> {
    for chunk in chunks {
        let chunk_start = chunk.key.offset;
        let chunk_end = chunk_start
            .checked_add(chunk.length)
            .ok_or(ParseError::InvalidField {
                field: "chunk_length",
                reason: "logical range overflow",
            })?;

        if logical >= chunk_start && logical < chunk_end {
            let offset_within = logical - chunk_start;
            // Use the first stripe (single-device assumption).
            let stripe = chunk.stripes.first().ok_or(ParseError::InvalidField {
                field: "stripes",
                reason: "chunk has no stripes",
            })?;
            let physical =
                stripe
                    .offset
                    .checked_add(offset_within)
                    .ok_or(ParseError::InvalidField {
                        field: "stripe_offset",
                        reason: "physical address overflow",
                    })?;
            return Ok(Some(BtrfsPhysicalMapping {
                devid: stripe.devid,
                physical,
            }));
        }
    }
    Ok(None)
}

// ── RAID profiles ───────────────────────────────────────────────────────────

/// Btrfs chunk type flags for RAID profiles (from `include/uapi/linux/btrfs.h`).
pub mod chunk_type_flags {
    /// Data chunk.
    pub const BTRFS_BLOCK_GROUP_DATA: u64 = 1 << 0;
    /// System chunk (bootstrap).
    pub const BTRFS_BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
    /// Metadata chunk.
    pub const BTRFS_BLOCK_GROUP_METADATA: u64 = 1 << 2;

    // RAID profile bits (bit 3+)
    /// RAID0: striped across N devices (no redundancy).
    pub const BTRFS_BLOCK_GROUP_RAID0: u64 = 1 << 3;
    /// RAID1: mirrored on 2 devices.
    pub const BTRFS_BLOCK_GROUP_RAID1: u64 = 1 << 4;
    /// DUP: duplicate on same device (not multi-device).
    pub const BTRFS_BLOCK_GROUP_DUP: u64 = 1 << 5;
    /// RAID10: striped mirrors (N/2 stripes, each mirrored).
    pub const BTRFS_BLOCK_GROUP_RAID10: u64 = 1 << 6;
    /// RAID5: striped with single parity.
    pub const BTRFS_BLOCK_GROUP_RAID5: u64 = 1 << 7;
    /// RAID6: striped with double parity.
    pub const BTRFS_BLOCK_GROUP_RAID6: u64 = 1 << 8;
    /// RAID1C3: mirrored on 3 devices.
    pub const BTRFS_BLOCK_GROUP_RAID1C3: u64 = 1 << 9;
    /// RAID1C4: mirrored on 4 devices.
    pub const BTRFS_BLOCK_GROUP_RAID1C4: u64 = 1 << 10;

    /// Mask for RAID profile bits.
    pub const RAID_MASK: u64 = BTRFS_BLOCK_GROUP_RAID0
        | BTRFS_BLOCK_GROUP_RAID1
        | BTRFS_BLOCK_GROUP_DUP
        | BTRFS_BLOCK_GROUP_RAID10
        | BTRFS_BLOCK_GROUP_RAID5
        | BTRFS_BLOCK_GROUP_RAID6
        | BTRFS_BLOCK_GROUP_RAID1C3
        | BTRFS_BLOCK_GROUP_RAID1C4;
}

/// Identified RAID profile for a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BtrfsRaidProfile {
    /// Single device / no RAID (linear mapping).
    Single,
    /// Duplicate on same device.
    Dup,
    /// RAID0: striped, no redundancy.
    Raid0,
    /// RAID1: mirrored on 2 devices.
    Raid1,
    /// RAID1C3: mirrored on 3 devices.
    Raid1C3,
    /// RAID1C4: mirrored on 4 devices.
    Raid1C4,
    /// RAID10: striped mirrors.
    Raid10,
    /// RAID5: single parity.
    Raid5,
    /// RAID6: double parity.
    Raid6,
}

impl BtrfsRaidProfile {
    /// Identify the RAID profile from chunk_type flags.
    #[must_use]
    pub fn from_chunk_type(chunk_type: u64) -> Self {
        use chunk_type_flags::{
            BTRFS_BLOCK_GROUP_DUP, BTRFS_BLOCK_GROUP_RAID0, BTRFS_BLOCK_GROUP_RAID1,
            BTRFS_BLOCK_GROUP_RAID1C3, BTRFS_BLOCK_GROUP_RAID1C4, BTRFS_BLOCK_GROUP_RAID5,
            BTRFS_BLOCK_GROUP_RAID6, BTRFS_BLOCK_GROUP_RAID10, RAID_MASK,
        };
        let raid_bits = chunk_type & RAID_MASK;
        if raid_bits & BTRFS_BLOCK_GROUP_RAID0 != 0 {
            Self::Raid0
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID1 != 0 {
            Self::Raid1
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID1C3 != 0 {
            Self::Raid1C3
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID1C4 != 0 {
            Self::Raid1C4
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID10 != 0 {
            Self::Raid10
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID5 != 0 {
            Self::Raid5
        } else if raid_bits & BTRFS_BLOCK_GROUP_RAID6 != 0 {
            Self::Raid6
        } else if raid_bits & BTRFS_BLOCK_GROUP_DUP != 0 {
            Self::Dup
        } else {
            Self::Single
        }
    }

    /// Number of data copies available for reads (mirrors).
    #[must_use]
    pub const fn data_copies(self) -> u16 {
        match self {
            Self::Single | Self::Raid0 | Self::Raid5 | Self::Raid6 => 1,
            Self::Dup | Self::Raid1 | Self::Raid10 => 2,
            Self::Raid1C3 => 3,
            Self::Raid1C4 => 4,
        }
    }

    /// Whether this profile provides redundancy (can tolerate device loss).
    #[must_use]
    pub const fn is_redundant(self) -> bool {
        self.data_copies() > 1 || matches!(self, Self::Raid5 | Self::Raid6)
    }
}

/// Result of multi-device logical-to-physical stripe resolution.
///
/// Returns all readable stripes for a given logical address, enabling
/// the caller to select a device (round-robin, failover, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsStripeMapping {
    /// RAID profile of the chunk.
    pub profile: BtrfsRaidProfile,
    /// All readable stripes (device, physical offset) for this logical address.
    /// For RAID1: 2 entries (either can serve the read).
    /// For RAID0: 1 entry (the stripe owning this offset).
    /// For Single: 1 entry.
    pub stripes: Vec<BtrfsPhysicalMapping>,
}

/// Map a logical byte address to all readable stripe locations.
///
/// Unlike [`map_logical_to_physical`] which assumes single-device, this
/// function resolves the full stripe layout for the matching chunk,
/// enabling multi-device reads and failover.
pub fn map_logical_to_stripes(
    chunks: &[BtrfsChunkEntry],
    logical: u64,
) -> Result<Option<BtrfsStripeMapping>, ParseError> {
    for chunk in chunks {
        let chunk_start = chunk.key.offset;
        let chunk_end = chunk_start
            .checked_add(chunk.length)
            .ok_or(ParseError::InvalidField {
                field: "chunk_length",
                reason: "logical range overflow",
            })?;

        if logical < chunk_start || logical >= chunk_end {
            continue;
        }

        let offset_within = logical - chunk_start;
        let profile = BtrfsRaidProfile::from_chunk_type(chunk.chunk_type);
        let stripes = resolve_chunk_stripes(chunk, offset_within, profile)?;
        return Ok(Some(BtrfsStripeMapping { profile, stripes }));
    }
    Ok(None)
}

/// Resolve stripe mappings for a single chunk at the given offset.
fn resolve_chunk_stripes(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
    profile: BtrfsRaidProfile,
) -> Result<Vec<BtrfsPhysicalMapping>, ParseError> {
    match profile {
        BtrfsRaidProfile::Single
        | BtrfsRaidProfile::Dup
        | BtrfsRaidProfile::Raid1
        | BtrfsRaidProfile::Raid1C3
        | BtrfsRaidProfile::Raid1C4 => resolve_mirror_stripes(chunk, offset_within),
        BtrfsRaidProfile::Raid0 => resolve_raid0_stripe(chunk, offset_within),
        BtrfsRaidProfile::Raid10 => resolve_raid10_stripes(chunk, offset_within),
        BtrfsRaidProfile::Raid5 | BtrfsRaidProfile::Raid6 => {
            resolve_raid56_stripe(chunk, offset_within, profile)
        }
    }
}

/// Mirror profiles (Single/DUP/RAID1/RAID1C3/RAID1C4): all stripes are copies.
fn resolve_mirror_stripes(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
) -> Result<Vec<BtrfsPhysicalMapping>, ParseError> {
    chunk
        .stripes
        .iter()
        .map(|s| stripe_physical(s, offset_within))
        .collect()
}

/// RAID0: data is striped across devices.
fn resolve_raid0_stripe(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
) -> Result<Vec<BtrfsPhysicalMapping>, ParseError> {
    let stripe_len = require_nonzero_stripe_len(chunk, "RAID0")?;
    let num = u64::from(chunk.num_stripes);
    let stripe_idx = (offset_within / stripe_len) % num;
    let offset_in_stripe = offset_within % stripe_len;
    let stripe_nr = offset_within
        / stripe_len
            .checked_mul(num)
            .ok_or(ParseError::InvalidField {
                field: "stripe_len",
                reason: "RAID0 stripe_len * num_stripes overflow",
            })?;
    let idx = usize::try_from(stripe_idx).unwrap_or(usize::MAX);
    let s = chunk.stripes.get(idx).ok_or(ParseError::InvalidField {
        field: "stripe_index",
        reason: "stripe index out of range",
    })?;
    Ok(vec![stripe_physical_at(
        s,
        stripe_nr,
        stripe_len,
        offset_in_stripe,
    )?])
}

/// RAID10: striped mirrors (sub_stripes mirrors per data stripe).
fn resolve_raid10_stripes(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
) -> Result<Vec<BtrfsPhysicalMapping>, ParseError> {
    let stripe_len = require_nonzero_stripe_len(chunk, "RAID10")?;
    let sub = u64::from(chunk.sub_stripes.max(1));
    let data_stripes = u64::from(chunk.num_stripes) / sub;
    if data_stripes == 0 {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "RAID10 has zero data stripes",
        });
    }
    let stripe_idx = (offset_within / stripe_len) % data_stripes;
    let offset_in_stripe = offset_within % stripe_len;
    let stripe_nr = offset_within
        / stripe_len
            .checked_mul(data_stripes)
            .ok_or(ParseError::InvalidField {
                field: "stripe_len",
                reason: "RAID10 stripe_len * data_stripes overflow",
            })?;
    let base = usize::try_from(stripe_idx.saturating_mul(sub)).unwrap_or(usize::MAX);
    let sub_usize = usize::try_from(sub).unwrap_or(0);
    Ok((0..sub_usize)
        .filter_map(|m| {
            let s = chunk.stripes.get(base.checked_add(m)?)?;
            let stripe_off = stripe_nr
                .checked_mul(stripe_len)?
                .checked_add(offset_in_stripe)?;
            let physical = s.offset.checked_add(stripe_off)?;
            Some(BtrfsPhysicalMapping {
                devid: s.devid,
                physical,
            })
        })
        .collect())
}

/// RAID5/6: return the data stripe (parity stripes excluded).
///
/// Parity rotation: for each "row" (stripe_nr), the parity position(s) rotate
/// across devices. RAID5 has 1 parity (P), RAID6 has 2 (P + Q at adjacent
/// positions modulo num_stripes). Data stripe indices are mapped to actual
/// device positions by explicitly skipping all parity positions — this
/// correctly handles the wrap-around case where P is at the last position
/// and Q wraps to position 0.
fn resolve_raid56_stripe(
    chunk: &BtrfsChunkEntry,
    offset_within: u64,
    profile: BtrfsRaidProfile,
) -> Result<Vec<BtrfsPhysicalMapping>, ParseError> {
    let stripe_len = require_nonzero_stripe_len(chunk, "RAID5/6")?;
    let num = u64::from(chunk.num_stripes);
    let parity_count: u64 = if profile == BtrfsRaidProfile::Raid6 {
        2
    } else {
        1
    };
    let data_stripes = num.saturating_sub(parity_count);
    if data_stripes == 0 {
        return Err(ParseError::InvalidField {
            field: "num_stripes",
            reason: "RAID5/6 has no data stripes",
        });
    }
    let stripe_idx = (offset_within / stripe_len) % data_stripes;
    let offset_in_stripe = offset_within % stripe_len;
    let stripe_nr = offset_within
        / stripe_len
            .checked_mul(data_stripes)
            .ok_or(ParseError::InvalidField {
                field: "stripe_len",
                reason: "RAID5/6 stripe_len * data_stripes overflow",
            })?;

    // Build set of parity positions for this row.
    // RAID5: P at (stripe_nr % num)
    // RAID6: P at (stripe_nr % num), Q at ((stripe_nr + 1) % num)
    let p_pos = stripe_nr % num;
    let is_parity = |pos: u64| -> bool {
        if pos == p_pos {
            return true;
        }
        if parity_count >= 2 && pos == (p_pos + 1) % num {
            return true;
        }
        false
    };

    // Map data stripe_idx to actual device position by walking positions
    // and skipping parity ones.
    let mut data_seen = 0_u64;
    let mut actual_idx = 0_u64;
    for pos in 0..num {
        if is_parity(pos) {
            continue;
        }
        if data_seen == stripe_idx {
            actual_idx = pos;
            break;
        }
        data_seen += 1;
    }

    let idx = usize::try_from(actual_idx).unwrap_or(usize::MAX);
    let s = chunk.stripes.get(idx).ok_or(ParseError::InvalidField {
        field: "stripe_index",
        reason: "stripe index out of range",
    })?;
    Ok(vec![stripe_physical_at(
        s,
        stripe_nr,
        stripe_len,
        offset_in_stripe,
    )?])
}

fn require_nonzero_stripe_len(chunk: &BtrfsChunkEntry, _label: &str) -> Result<u64, ParseError> {
    if chunk.stripe_len == 0 {
        return Err(ParseError::InvalidField {
            field: "stripe_len",
            reason: "chunk has zero stripe length",
        });
    }
    Ok(chunk.stripe_len)
}

fn stripe_physical(
    s: &BtrfsStripe,
    offset_within: u64,
) -> Result<BtrfsPhysicalMapping, ParseError> {
    Ok(BtrfsPhysicalMapping {
        devid: s.devid,
        physical: s
            .offset
            .checked_add(offset_within)
            .ok_or(ParseError::InvalidField {
                field: "stripe_offset",
                reason: "physical address overflow",
            })?,
    })
}

fn stripe_physical_at(
    s: &BtrfsStripe,
    stripe_nr: u64,
    stripe_len: u64,
    offset_in_stripe: u64,
) -> Result<BtrfsPhysicalMapping, ParseError> {
    let stripe_offset = stripe_nr
        .checked_mul(stripe_len)
        .and_then(|v| v.checked_add(offset_in_stripe))
        .ok_or(ParseError::InvalidField {
            field: "stripe_offset",
            reason: "stripe offset overflow",
        })?;
    let physical = s
        .offset
        .checked_add(stripe_offset)
        .ok_or(ParseError::InvalidField {
            field: "stripe_offset",
            reason: "physical address overflow",
        })?;
    Ok(BtrfsPhysicalMapping {
        devid: s.devid,
        physical,
    })
}

// ── DEV_ITEM parsing ────────────────────────────────────────────────────────

/// Parsed btrfs device item (from the device tree or superblock).
///
/// Contains device identification and capacity information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsDevItem {
    /// Device ID (matches BtrfsStripe::devid).
    pub devid: u64,
    /// Total bytes on this device.
    pub total_bytes: u64,
    /// Bytes used on this device.
    pub bytes_used: u64,
    /// I/O alignment for this device.
    pub io_align: u32,
    /// I/O width for this device.
    pub io_width: u32,
    /// Sector size of this device.
    pub sector_size: u32,
    /// Device type (0 = regular).
    pub dev_type: u64,
    /// Generation when this item was last updated.
    pub generation: u64,
    /// Byte offset of the start of data on device.
    pub start_offset: u64,
    /// Device group (for RAID assignment).
    pub dev_group: u32,
    /// Seek speed classification.
    pub seek_speed: u8,
    /// Bandwidth classification.
    pub bandwidth: u8,
    /// Device UUID.
    pub uuid: [u8; 16],
    /// Filesystem UUID.
    pub fsid: [u8; 16],
}

/// Size of a btrfs_dev_item on disk (98 bytes).
const BTRFS_DEV_ITEM_SIZE: usize = 98;

/// Parse a DEV_ITEM from raw leaf data.
pub fn parse_dev_item(data: &[u8]) -> Result<BtrfsDevItem, ParseError> {
    if data.len() < BTRFS_DEV_ITEM_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_DEV_ITEM_SIZE,
            offset: 0,
            actual: data.len(),
        });
    }

    Ok(BtrfsDevItem {
        devid: read_le_u64(data, 0)?,
        total_bytes: read_le_u64(data, 8)?,
        bytes_used: read_le_u64(data, 16)?,
        io_align: read_le_u32(data, 24)?,
        io_width: read_le_u32(data, 28)?,
        sector_size: read_le_u32(data, 32)?,
        dev_type: read_le_u64(data, 36)?,
        generation: read_le_u64(data, 44)?,
        start_offset: read_le_u64(data, 52)?,
        dev_group: read_le_u32(data, 60)?,
        seek_speed: data[64],
        bandwidth: data[65],
        uuid: read_fixed::<16>(data, 66)?,
        fsid: read_fixed::<16>(data, 82)?,
    })
}

// ── Tree node types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsKey {
    pub objectid: u64,
    pub item_type: u8,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsHeader {
    pub csum: [u8; 32],
    pub fsid: [u8; 16],
    pub bytenr: u64,
    pub flags: u64,
    pub chunk_tree_uuid: [u8; 16],
    pub generation: u64,
    pub owner: u64,
    pub nritems: u32,
    pub level: u8,
}

impl BtrfsHeader {
    pub fn parse_from_block(block: &[u8]) -> Result<Self, ParseError> {
        if block.len() < BTRFS_HEADER_SIZE {
            return Err(ParseError::InsufficientData {
                needed: BTRFS_HEADER_SIZE,
                offset: 0,
                actual: block.len(),
            });
        }

        Ok(Self {
            csum: read_fixed::<32>(block, 0x00)?,
            fsid: read_fixed::<16>(block, 0x20)?,
            bytenr: read_le_u64(block, 0x30)?,
            flags: read_le_u64(block, 0x38)?,
            chunk_tree_uuid: read_fixed::<16>(block, 0x40)?,
            generation: read_le_u64(block, 0x50)?,
            owner: read_le_u64(block, 0x58)?,
            nritems: read_le_u32(block, 0x60)?,
            level: block[0x64],
        })
    }

    /// Validate the header against the block it was parsed from.
    ///
    /// Checks:
    /// - `bytenr` matches `expected_bytenr` (if provided).
    /// - `nritems` fits within the block, considering item size (leaf vs internal).
    /// - `level` does not exceed `BTRFS_MAX_LEVEL`.
    pub fn validate(
        &self,
        block_size: usize,
        expected_bytenr: Option<u64>,
    ) -> Result<(), ParseError> {
        if let Some(expected) = expected_bytenr {
            if self.bytenr != expected {
                return Err(ParseError::InvalidField {
                    field: "bytenr",
                    reason: "header bytenr does not match expected",
                });
            }
        }

        if self.level > BTRFS_MAX_LEVEL {
            return Err(ParseError::InvalidField {
                field: "level",
                reason: "exceeds maximum tree depth",
            });
        }

        let payload_space = block_size.saturating_sub(BTRFS_HEADER_SIZE);
        let item_size = if self.level == 0 {
            BTRFS_ITEM_SIZE
        } else {
            BTRFS_KEY_PTR_SIZE
        };
        let max_items = payload_space / item_size;
        let nritems = usize::try_from(self.nritems)
            .map_err(|_| ParseError::IntegerConversion { field: "nritems" })?;

        if nritems > max_items {
            return Err(ParseError::InvalidField {
                field: "nritems",
                reason: "item count exceeds block capacity",
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsItem {
    pub key: BtrfsKey,
    pub data_offset: u32,
    pub data_size: u32,
}

/// An internal (non-leaf) node item: a key paired with a child block pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtrfsKeyPtr {
    pub key: BtrfsKey,
    pub blockptr: u64,
    pub generation: u64,
}

pub fn parse_leaf_items(block: &[u8]) -> Result<(BtrfsHeader, Vec<BtrfsItem>), ParseError> {
    let header = BtrfsHeader::parse_from_block(block)?;
    if header.level != 0 {
        return Err(ParseError::InvalidField {
            field: "level",
            reason: "expected leaf level 0",
        });
    }

    let nritems = usize::try_from(header.nritems)
        .map_err(|_| ParseError::IntegerConversion { field: "nritems" })?;

    let item_table_bytes =
        nritems
            .checked_mul(BTRFS_ITEM_SIZE)
            .ok_or(ParseError::InvalidField {
                field: "items",
                reason: "overflow",
            })?;
    let items_end =
        BTRFS_HEADER_SIZE
            .checked_add(item_table_bytes)
            .ok_or(ParseError::InvalidField {
                field: "items",
                reason: "overflow",
            })?;

    if block.len() < items_end {
        return Err(ParseError::InsufficientData {
            needed: items_end,
            offset: BTRFS_HEADER_SIZE,
            actual: block.len().saturating_sub(BTRFS_HEADER_SIZE),
        });
    }

    let mut items = Vec::with_capacity(nritems);
    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_ITEM_SIZE;
        let key = BtrfsKey {
            objectid: read_le_u64(block, base)?,
            item_type: block[base + 8],
            offset: read_le_u64(block, base + 9)?,
        };
        // btrfs leaf item offsets are relative to the end of the header (BTRFS_HEADER_SIZE).
        let raw_data_offset = read_le_u32(block, base + 17)?;
        let data_offset = raw_data_offset.checked_add(BTRFS_HEADER_SIZE as u32).ok_or(
            ParseError::InvalidField {
                field: "item_offset",
                reason: "overflow when adding header size",
            },
        )?;
        let data_size = read_le_u32(block, base + 21)?;

        let data_end = usize::try_from(data_offset)
            .ok()
            .and_then(|off| off.checked_add(usize::try_from(data_size).ok()?))
            .ok_or(ParseError::InvalidField {
                field: "item_offset",
                reason: "overflow",
            })?;

        if data_end > block.len() {
            return Err(ParseError::InvalidField {
                field: "item_offset",
                reason: "item points outside block",
            });
        }

        items.push(BtrfsItem {
            key,
            data_offset,
            data_size,
        });
    }

    Ok((header, items))
}

/// Parse a btrfs internal (non-leaf) node, returning the header and key-pointer items.
///
/// Internal nodes (level > 0) contain `btrfs_key_ptr` entries that point
/// to child blocks. Each entry is 33 bytes: key (17) + blockptr (8) + generation (8).
pub fn parse_internal_items(block: &[u8]) -> Result<(BtrfsHeader, Vec<BtrfsKeyPtr>), ParseError> {
    let header = BtrfsHeader::parse_from_block(block)?;
    if header.level == 0 {
        return Err(ParseError::InvalidField {
            field: "level",
            reason: "expected internal node (level > 0)",
        });
    }

    header.validate(block.len(), None)?;

    let nritems = usize::try_from(header.nritems)
        .map_err(|_| ParseError::IntegerConversion { field: "nritems" })?;

    let table_bytes = nritems
        .checked_mul(BTRFS_KEY_PTR_SIZE)
        .ok_or(ParseError::InvalidField {
            field: "key_ptrs",
            reason: "overflow",
        })?;
    let table_end = BTRFS_HEADER_SIZE
        .checked_add(table_bytes)
        .ok_or(ParseError::InvalidField {
            field: "key_ptrs",
            reason: "overflow",
        })?;

    if block.len() < table_end {
        return Err(ParseError::InsufficientData {
            needed: table_end,
            offset: BTRFS_HEADER_SIZE,
            actual: block.len().saturating_sub(BTRFS_HEADER_SIZE),
        });
    }

    let mut ptrs = Vec::with_capacity(nritems);
    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_KEY_PTR_SIZE;
        let key = BtrfsKey {
            objectid: read_le_u64(block, base)?,
            item_type: block[base + 8],
            offset: read_le_u64(block, base + 9)?,
        };
        let blockptr = read_le_u64(block, base + 17)?;
        let generation = read_le_u64(block, base + 25)?;

        if blockptr == 0 {
            return Err(ParseError::InvalidField {
                field: "blockptr",
                reason: "child block pointer is zero",
            });
        }

        ptrs.push(BtrfsKeyPtr {
            key,
            blockptr,
            generation,
        });
    }

    Ok((header, ptrs))
}

// ── Checksum verification ───────────────────────────────────────────────────

/// Verify the CRC32C checksum of a btrfs superblock.
///
/// The checksum covers `region[0x20..]` (everything after the 32-byte `csum`
/// field). The expected checksum is stored as a little-endian u32 in
/// `region[0..4]`.
///
/// Only CRC32C (`csum_type == 0`) is currently supported. Other algorithms
/// return an error.
pub fn verify_superblock_checksum(region: &[u8]) -> Result<(), ParseError> {
    if region.len() < BTRFS_SUPER_INFO_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_SUPER_INFO_SIZE,
            offset: 0,
            actual: region.len(),
        });
    }

    let csum_type = read_le_u16(region, 0xC4)?;
    if csum_type != ffs_types::BTRFS_CSUM_TYPE_CRC32C {
        return Err(ParseError::InvalidField {
            field: "csum_type",
            reason: "only CRC32C (type 0) is currently supported",
        });
    }

    let stored = read_le_u32(region, 0)?;
    let computed = crc32c::crc32c(&region[0x20..BTRFS_SUPER_INFO_SIZE]);

    if stored != computed {
        return Err(ParseError::InvalidField {
            field: "superblock_csum",
            reason: "CRC32C checksum mismatch",
        });
    }

    Ok(())
}

/// Verify the CRC32C checksum of a btrfs tree block (leaf or internal node).
///
/// The checksum covers `block[0x20..block.len()]` (everything after the
/// 32-byte `csum` field in the header). The expected checksum is stored as a
/// little-endian u32 in `block[0..4]`.
///
/// Only CRC32C (`csum_type == 0`) is currently supported.
pub fn verify_tree_block_checksum(block: &[u8], csum_type: u16) -> Result<(), ParseError> {
    if block.len() < BTRFS_HEADER_SIZE {
        return Err(ParseError::InsufficientData {
            needed: BTRFS_HEADER_SIZE,
            offset: 0,
            actual: block.len(),
        });
    }

    if csum_type != ffs_types::BTRFS_CSUM_TYPE_CRC32C {
        return Err(ParseError::InvalidField {
            field: "csum_type",
            reason: "only CRC32C (type 0) is currently supported",
        });
    }

    let stored = read_le_u32(block, 0)?;
    let computed = crc32c::crc32c(&block[0x20..]);

    if stored != computed {
        return Err(ParseError::InvalidField {
            field: "tree_block_csum",
            reason: "CRC32C checksum mismatch",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parse_superblock_smoke() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x30..0x38].copy_from_slice(&(BTRFS_SUPER_INFO_OFFSET as u64).to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&9_u64.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&4096_u64.to_le_bytes());
        sb[0x58..0x60].copy_from_slice(&8192_u64.to_le_bytes());
        sb[0x60..0x68].copy_from_slice(&12288_u64.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&1_000_000_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&123_456_u64.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&6_u64.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&65536_u32.to_le_bytes());
        sb[0xC4..0xC6].copy_from_slice(&1_u16.to_le_bytes());
        sb[0xC6] = 0;
        sb[0xC7] = 1;
        sb[0xC8] = 2;
        sb[BTRFS_SUPER_LABEL_OFFSET..BTRFS_SUPER_LABEL_OFFSET + 3].copy_from_slice(b"ffs");

        let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("superblock parse");
        assert_eq!(parsed.magic, BTRFS_MAGIC);
        assert_eq!(parsed.sectorsize, 4096);
        assert_eq!(parsed.nodesize, 16384);
        assert_eq!(parsed.label, "ffs");
    }

    #[test]
    fn superblock_sys_chunk_array_parsed() {
        // Build a superblock with a single sys_chunk_array entry
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&65536_u32.to_le_bytes());

        // Build a sys_chunk_array entry: disk_key (17) + chunk_fixed (48) + 1 stripe (32) = 97
        let entry_size: u32 = 97;
        sb[0xA0..0xA4].copy_from_slice(&entry_size.to_le_bytes());

        let base = BTRFS_SYS_CHUNK_ARRAY_OFFSET;
        // disk_key: objectid=256, type=228 (CHUNK_ITEM_KEY), offset=0
        sb[base..base + 8].copy_from_slice(&256_u64.to_le_bytes());
        sb[base + 8] = 228;
        sb[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
        // chunk: length=8MiB, owner=2, stripe_len=64K, type=2 (SYSTEM)
        let c = base + 17;
        sb[c..c + 8].copy_from_slice(&(8 * 1024 * 1024_u64).to_le_bytes());
        sb[c + 8..c + 16].copy_from_slice(&2_u64.to_le_bytes());
        sb[c + 16..c + 24].copy_from_slice(&(64 * 1024_u64).to_le_bytes());
        sb[c + 24..c + 32].copy_from_slice(&2_u64.to_le_bytes()); // type=SYSTEM
        sb[c + 32..c + 36].copy_from_slice(&4096_u32.to_le_bytes());
        sb[c + 36..c + 40].copy_from_slice(&4096_u32.to_le_bytes());
        sb[c + 40..c + 44].copy_from_slice(&4096_u32.to_le_bytes());
        sb[c + 44..c + 46].copy_from_slice(&1_u16.to_le_bytes()); // num_stripes=1
        sb[c + 46..c + 48].copy_from_slice(&0_u16.to_le_bytes()); // sub_stripes=0
        // stripe: devid=1, offset=0, uuid=zeros
        let s = c + 48;
        sb[s..s + 8].copy_from_slice(&1_u64.to_le_bytes());
        sb[s + 8..s + 16].copy_from_slice(&0_u64.to_le_bytes());

        let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("sb parse");
        assert_eq!(parsed.sys_chunk_array_size, entry_size);
        assert_eq!(parsed.sys_chunk_array.len(), 97);

        let entries = parse_sys_chunk_array(&parsed.sys_chunk_array).expect("chunk parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key.objectid, 256);
        assert_eq!(entries[0].key.item_type, 228);
        assert_eq!(entries[0].length, 8 * 1024 * 1024);
        assert_eq!(entries[0].num_stripes, 1);
        assert_eq!(entries[0].stripes[0].devid, 1);
    }

    #[test]
    fn superblock_rejects_non_power_of_two_sectorsize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&3000_u32.to_le_bytes()); // not power of 2
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "sectorsize",
                    ..
                }
            ),
            "expected sectorsize error, got: {err:?}"
        );
    }

    #[test]
    fn superblock_rejects_non_power_of_two_nodesize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&5000_u32.to_le_bytes()); // not power of 2
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nodesize",
                    ..
                }
            ),
            "expected nodesize error, got: {err:?}"
        );
    }

    #[test]
    fn map_logical_to_physical_hit() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000, // logical start = 16 MiB
            },
            length: 0x80_0000, // 8 MiB
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
                offset: 0x20_0000, // physical start = 2 MiB
                dev_uuid: [0; 16],
            }],
        }];

        // Hit: logical 16.5 MiB → physical 2.5 MiB
        let result = map_logical_to_physical(&chunks, 0x108_0000).expect("mapping should succeed");
        let mapping = result.expect("should find a mapping");
        assert_eq!(mapping.devid, 1);
        assert_eq!(mapping.physical, 0x28_0000);
    }

    #[test]
    fn map_logical_to_physical_miss() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
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
                offset: 0x20_0000,
                dev_uuid: [0; 16],
            }],
        }];

        // Miss: logical address outside the chunk range
        let result = map_logical_to_physical(&chunks, 0x200_0000).expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn map_logical_to_physical_empty_chunks() {
        let result = map_logical_to_physical(&[], 0x1000).expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn parse_sys_chunk_array_empty() {
        let entries = parse_sys_chunk_array(&[]).expect("empty array is valid");
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_sys_chunk_array_truncated_key() {
        let data = [0_u8; 10]; // too short for a disk_key
        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_leaf_items_smoke() {
        let mut block = vec![0_u8; 512];

        block[0x60..0x64].copy_from_slice(&1_u32.to_le_bytes());
        block[0x64] = 0;

        // first item at header+0
        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&123_u64.to_le_bytes());
        block[base + 8] = 42;
        block[base + 9..base + 17].copy_from_slice(&999_u64.to_le_bytes());
        block[base + 17..base + 21].copy_from_slice(&400_u32.to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&8_u32.to_le_bytes());

        let (_, items) = parse_leaf_items(&block).expect("leaf parse");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key.objectid, 123);
        assert_eq!(items[0].key.item_type, 42);
        assert_eq!(items[0].key.offset, 999);
    }

    /// Helper: build a minimal valid block with a header (zeros except nritems + level).
    fn make_block(size: usize, nritems: u32, level: u8) -> Vec<u8> {
        let mut block = vec![0_u8; size];
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;
        block
    }

    #[test]
    fn parse_internal_items_smoke() {
        let mut block = make_block(4096, 2, 1);

        // Item 0: key(256, 132, 0) → blockptr=0x4000, gen=10
        let b0 = BTRFS_HEADER_SIZE;
        block[b0..b0 + 8].copy_from_slice(&256_u64.to_le_bytes());
        block[b0 + 8] = 132;
        block[b0 + 9..b0 + 17].copy_from_slice(&0_u64.to_le_bytes());
        block[b0 + 17..b0 + 25].copy_from_slice(&0x4000_u64.to_le_bytes());
        block[b0 + 25..b0 + 33].copy_from_slice(&10_u64.to_le_bytes());

        // Item 1: key(512, 132, 100) → blockptr=0x8000, gen=10
        let b1 = BTRFS_HEADER_SIZE + BTRFS_KEY_PTR_SIZE;
        block[b1..b1 + 8].copy_from_slice(&512_u64.to_le_bytes());
        block[b1 + 8] = 132;
        block[b1 + 9..b1 + 17].copy_from_slice(&100_u64.to_le_bytes());
        block[b1 + 17..b1 + 25].copy_from_slice(&0x8000_u64.to_le_bytes());
        block[b1 + 25..b1 + 33].copy_from_slice(&10_u64.to_le_bytes());

        let (header, ptrs) = parse_internal_items(&block).expect("internal parse");
        assert_eq!(header.level, 1);
        assert_eq!(ptrs.len(), 2);
        assert_eq!(ptrs[0].key.objectid, 256);
        assert_eq!(ptrs[0].blockptr, 0x4000);
        assert_eq!(ptrs[0].generation, 10);
        assert_eq!(ptrs[1].key.objectid, 512);
        assert_eq!(ptrs[1].blockptr, 0x8000);
    }

    #[test]
    fn parse_internal_items_rejects_leaf() {
        let block = make_block(4096, 0, 0);
        let err = parse_internal_items(&block).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "level", .. }),
            "expected level error, got: {err:?}"
        );
    }

    #[test]
    fn parse_internal_items_rejects_zero_blockptr() {
        let mut block = make_block(4096, 1, 1);
        // key is valid but blockptr is zero
        let b0 = BTRFS_HEADER_SIZE;
        block[b0..b0 + 8].copy_from_slice(&256_u64.to_le_bytes());
        block[b0 + 8] = 132;
        // blockptr stays zero (from make_block)

        let err = parse_internal_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "blockptr",
                    ..
                }
            ),
            "expected blockptr error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_bytenr_mismatch() {
        let block = make_block(4096, 0, 0);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        // header.bytenr is 0, expected 0x1000
        let err = header.validate(4096, Some(0x1000)).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "bytenr",
                    ..
                }
            ),
            "expected bytenr error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_bytenr_match() {
        let mut block = make_block(4096, 0, 0);
        block[0x30..0x38].copy_from_slice(&0x1_0000_u64.to_le_bytes());
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        header.validate(4096, Some(0x1_0000)).expect("should match");
    }

    #[test]
    fn header_validate_nritems_overflow_leaf() {
        // A 4096-byte block can hold (4096-101)/25 = 159 leaf items max.
        let block = make_block(4096, 200, 0);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        let err = header.validate(4096, None).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nritems",
                    ..
                }
            ),
            "expected nritems error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_nritems_overflow_internal() {
        // A 4096-byte block can hold (4096-101)/33 = 121 internal items max.
        let block = make_block(4096, 130, 1);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        let err = header.validate(4096, None).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nritems",
                    ..
                }
            ),
            "expected nritems error, got: {err:?}"
        );
    }

    #[test]
    fn header_validate_level_too_high() {
        let block = make_block(4096, 0, 8); // max is 7
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        let err = header.validate(4096, None).unwrap_err();
        assert!(
            matches!(err, ParseError::InvalidField { field: "level", .. }),
            "expected level error, got: {err:?}"
        );
    }

    #[test]
    fn parse_leaf_items_rejects_out_of_bounds_data() {
        let mut block = make_block(512, 1, 0);
        let base = BTRFS_HEADER_SIZE;
        block[base..base + 8].copy_from_slice(&1_u64.to_le_bytes());
        block[base + 8] = 1;
        // data_offset = 600, data_size = 10 — well beyond the 512-byte block
        block[base + 17..base + 21].copy_from_slice(&600_u32.to_le_bytes());
        block[base + 21..base + 25].copy_from_slice(&10_u32.to_le_bytes());

        let err = parse_leaf_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "item_offset",
                    ..
                }
            ),
            "expected item_offset error, got: {err:?}"
        );
    }

    #[test]
    fn parse_internal_items_block_too_small() {
        // Block is too small to hold the declared items
        let mut block = make_block(140, 2, 1);
        // Need 101 + 2*33 = 167 bytes, but only have 140
        // Put a valid blockptr for item 0 so we fail on size not on blockptr
        let b0 = BTRFS_HEADER_SIZE;
        block[b0 + 17..b0 + 25].copy_from_slice(&0x4000_u64.to_le_bytes());

        let err = parse_internal_items(&block).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "nritems",
                    ..
                }
            ),
            "expected nritems error, got: {err:?}"
        );
    }

    // ── Checksum verification tests ──────────────────────────────────

    /// Build a valid superblock with correct CRC32C checksum.
    fn make_checksummed_sb() -> Vec<u8> {
        let mut sb = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes()); // sectorsize
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes()); // nodesize
        sb[0xC4..0xC6].copy_from_slice(&0_u16.to_le_bytes()); // csum_type=CRC32C
        // Compute CRC32C over bytes[0x20..4096] and store in bytes[0..4]
        let csum = crc32c::crc32c(&sb[0x20..BTRFS_SUPER_INFO_SIZE]);
        sb[0..4].copy_from_slice(&csum.to_le_bytes());
        sb
    }

    #[test]
    fn verify_superblock_checksum_valid() {
        let sb = make_checksummed_sb();
        verify_superblock_checksum(&sb).expect("valid checksum");
    }

    #[test]
    fn verify_superblock_checksum_corrupt() {
        let mut sb = make_checksummed_sb();
        // Flip a bit in the payload
        sb[0x50] ^= 0x01;
        let err = verify_superblock_checksum(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "superblock_csum",
                    ..
                }
            ),
            "expected checksum mismatch, got: {err:?}"
        );
    }

    #[test]
    fn verify_superblock_checksum_unsupported_type() {
        let mut sb = make_checksummed_sb();
        // Change csum_type to XXHASH64
        sb[0xC4..0xC6].copy_from_slice(&1_u16.to_le_bytes());
        let err = verify_superblock_checksum(&sb).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "csum_type",
                    ..
                }
            ),
            "expected unsupported csum_type error, got: {err:?}"
        );
    }

    #[test]
    fn verify_tree_block_checksum_valid() {
        let mut block = vec![0_u8; 16384]; // nodesize=16K
        // Set up a minimal header
        block[0x64] = 0; // level=0 (leaf)
        block[0x60..0x64].copy_from_slice(&0_u32.to_le_bytes()); // nritems=0
        // Compute CRC32C over bytes[0x20..] and store in [0..4]
        let csum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
        verify_tree_block_checksum(&block, 0).expect("valid tree block checksum");
    }

    #[test]
    fn verify_tree_block_checksum_corrupt() {
        let mut block = vec![0_u8; 16384];
        let csum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
        // Corrupt a byte
        block[0x30] ^= 0xFF;
        let err = verify_tree_block_checksum(&block, 0).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::InvalidField {
                    field: "tree_block_csum",
                    ..
                }
            ),
            "expected tree block checksum mismatch, got: {err:?}"
        );
    }

    // ── Edge-case tests (SilverWaterfall) ─────────────────────────────

    #[test]
    fn parse_from_image_too_small() {
        // Image is smaller than BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE
        let image = vec![0_u8; BTRFS_SUPER_INFO_OFFSET + 100];
        let err = BtrfsSuperblock::parse_from_image(&image).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_from_image_happy_path() {
        // Build a valid superblock at the correct offset
        let mut image = vec![0_u8; BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE];
        let sb_region = &mut image[BTRFS_SUPER_INFO_OFFSET..];
        sb_region[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb_region[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb_region[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb_region[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes());
        sb_region[0x48..0x50].copy_from_slice(&42_u64.to_le_bytes());

        let parsed = BtrfsSuperblock::parse_from_image(&image).expect("parse from image");
        assert_eq!(parsed.magic, BTRFS_MAGIC);
        assert_eq!(parsed.generation, 42);
    }

    #[test]
    fn btrfs_key_equality_and_copy() {
        let k1 = BtrfsKey {
            objectid: 256,
            item_type: 132,
            offset: 0,
        };
        let k2 = k1; // Copy
        assert_eq!(k1, k2);

        let k3 = BtrfsKey {
            objectid: 256,
            item_type: 133,
            offset: 0,
        };
        assert_ne!(k1, k3);
    }

    #[test]
    fn btrfs_physical_mapping_equality_and_copy() {
        let m1 = BtrfsPhysicalMapping {
            devid: 1,
            physical: 0x4000,
        };
        let m2 = m1; // Copy
        assert_eq!(m1, m2);

        let m3 = BtrfsPhysicalMapping {
            devid: 2,
            physical: 0x4000,
        };
        assert_ne!(m1, m3);
    }

    #[test]
    fn header_parse_exactly_minimum_size() {
        let block = vec![0_u8; BTRFS_HEADER_SIZE];
        let header = BtrfsHeader::parse_from_block(&block).expect("parse at exact size");
        assert_eq!(header.level, 0);
        assert_eq!(header.nritems, 0);
    }

    #[test]
    fn header_parse_too_small() {
        let block = vec![0_u8; BTRFS_HEADER_SIZE - 1];
        let err = BtrfsHeader::parse_from_block(&block).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn superblock_rejects_oversized_sys_chunk_array() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes());
        // Set sys_chunk_array_size to max+1
        let bad_size = u32::try_from(BTRFS_SYS_CHUNK_ARRAY_MAX).expect("fits u32") + 1;
        sb[0xA0..0xA4].copy_from_slice(&bad_size.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "sys_chunk_array_size",
                ..
            }
        ));
    }

    #[test]
    fn map_logical_at_exact_chunk_start() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
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
                offset: 0x20_0000,
                dev_uuid: [0; 16],
            }],
        }];

        // Exact start should hit
        let result = map_logical_to_physical(&chunks, 0x100_0000).expect("no error");
        let mapping = result.expect("should hit at start");
        assert_eq!(mapping.physical, 0x20_0000);
    }

    #[test]
    fn map_logical_at_last_byte_of_chunk() {
        let chunks = vec![BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 256,
                item_type: 228,
                offset: 0x100_0000,
            },
            length: 0x80_0000,
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
                offset: 0x20_0000,
                dev_uuid: [0; 16],
            }],
        }];

        // Last valid address = start + length - 1
        let last_valid = 0x100_0000 + 0x80_0000 - 1;
        let result = map_logical_to_physical(&chunks, last_valid).expect("no error");
        let mapping = result.expect("should hit at last byte");
        assert_eq!(mapping.physical, 0x20_0000 + 0x80_0000 - 1);

        // One past end should miss
        let past_end = 0x100_0000 + 0x80_0000;
        let result = map_logical_to_physical(&chunks, past_end).expect("no error");
        assert!(result.is_none());
    }

    #[test]
    fn map_logical_multiple_chunks_selects_correct() {
        let chunks = vec![
            BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228,
                    offset: 0x100_0000,
                },
                length: 0x80_0000,
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
                    offset: 0x20_0000,
                    dev_uuid: [0; 16],
                }],
            },
            BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228,
                    offset: 0x200_0000,
                },
                length: 0x40_0000,
                owner: 2,
                stripe_len: 0x1_0000,
                chunk_type: 1,
                io_align: 4096,
                io_width: 4096,
                sector_size: 4096,
                num_stripes: 1,
                sub_stripes: 0,
                stripes: vec![BtrfsStripe {
                    devid: 2,
                    offset: 0xA0_0000,
                    dev_uuid: [0xFF; 16],
                }],
            },
        ];

        // Address in second chunk
        let result = map_logical_to_physical(&chunks, 0x210_0000).expect("no error");
        let mapping = result.expect("should hit second chunk");
        assert_eq!(mapping.devid, 2);
        assert_eq!(mapping.physical, 0xB0_0000);
    }

    #[test]
    fn verify_tree_block_checksum_at_minimum_size() {
        let mut block = vec![0_u8; BTRFS_HEADER_SIZE];
        let csum = crc32c::crc32c(&block[0x20..]);
        block[0..4].copy_from_slice(&csum.to_le_bytes());
        verify_tree_block_checksum(&block, 0).expect("valid at min size");
    }

    #[test]
    fn verify_tree_block_checksum_too_small() {
        let block = vec![0_u8; BTRFS_HEADER_SIZE - 1];
        let err = verify_tree_block_checksum(&block, 0).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_sys_chunk_array_truncated_chunk_header() {
        // Just enough for a key but not enough for the chunk header
        let mut data = vec![0_u8; BTRFS_DISK_KEY_SIZE + 10];
        data[0..8].copy_from_slice(&256_u64.to_le_bytes());
        data[8] = 228;
        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn parse_sys_chunk_array_truncated_stripes() {
        // Key + chunk fixed header, but not enough for the stripes
        let mut data = vec![0_u8; BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE];
        data[0..8].copy_from_slice(&256_u64.to_le_bytes());
        data[8] = 228;
        let c = BTRFS_DISK_KEY_SIZE;
        data[c..c + 8].copy_from_slice(&1_u64.to_le_bytes()); // length
        data[c + 44..c + 46].copy_from_slice(&2_u16.to_le_bytes()); // num_stripes=2
        let err = parse_sys_chunk_array(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }

    #[test]
    fn header_validate_with_no_expected_bytenr() {
        let block = make_block(4096, 0, 0);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        // Should succeed with None for expected_bytenr
        header.validate(4096, None).expect("should pass");
    }

    #[test]
    fn superblock_rejects_zero_sectorsize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&0_u32.to_le_bytes()); // zero sectorsize
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "sectorsize",
                ..
            }
        ));
    }

    #[test]
    fn superblock_rejects_zero_nodesize() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&0_u32.to_le_bytes()); // zero nodesize
        let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
        assert!(matches!(
            err,
            ParseError::InvalidField {
                field: "nodesize",
                ..
            }
        ));
    }

    #[test]
    fn superblock_allows_zero_stripesize() {
        // Zero stripesize is explicitly allowed (not power-of-two check)
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&0_u32.to_le_bytes()); // zero stripesize
        let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("zero stripesize ok");
        assert_eq!(parsed.stripesize, 0);
    }

    #[test]
    fn leaf_items_zero_nritems() {
        let block = make_block(512, 0, 0);
        let (header, items) = parse_leaf_items(&block).expect("empty leaf");
        assert_eq!(header.nritems, 0);
        assert!(items.is_empty());
    }

    #[test]
    fn superblock_debug_and_clone() {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes());
        let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("parse");
        let cloned = parsed.clone();
        assert_eq!(parsed, cloned);
        let dbg = format!("{parsed:?}");
        assert!(dbg.contains("BtrfsSuperblock"));
    }

    #[test]
    fn header_max_valid_level() {
        let block = make_block(4096, 0, BTRFS_MAX_LEVEL);
        let header = BtrfsHeader::parse_from_block(&block).expect("parse");
        header.validate(4096, None).expect("max level ok");
        assert_eq!(header.level, 7);
    }

    #[test]
    fn key_ptr_debug_and_copy() {
        let kp = BtrfsKeyPtr {
            key: BtrfsKey {
                objectid: 1,
                item_type: 2,
                offset: 3,
            },
            blockptr: 0x4000,
            generation: 10,
        };
        let kp2 = kp; // Copy
        assert_eq!(kp, kp2);
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("BtrfsKeyPtr"));
    }

    fn make_proptest_valid_btrfs_superblock(
        sectorsize: u32,
        nodesize: u32,
        sys_chunk_array: &[u8],
    ) -> [u8; BTRFS_SUPER_INFO_SIZE] {
        let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
        let sys_chunk_len_u32 =
            u32::try_from(sys_chunk_array.len()).expect("sys_chunk_array length fits in u32");

        sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
        sb[0x30..0x38].copy_from_slice(&(BTRFS_SUPER_INFO_OFFSET as u64).to_le_bytes());
        sb[0x48..0x50].copy_from_slice(&1_u64.to_le_bytes());
        sb[0x50..0x58].copy_from_slice(&0x1000_u64.to_le_bytes());
        sb[0x58..0x60].copy_from_slice(&0x2000_u64.to_le_bytes());
        sb[0x60..0x68].copy_from_slice(&0_u64.to_le_bytes());
        sb[0x70..0x78].copy_from_slice(&1_000_000_u64.to_le_bytes());
        sb[0x78..0x80].copy_from_slice(&123_456_u64.to_le_bytes());
        sb[0x80..0x88].copy_from_slice(&6_u64.to_le_bytes());
        sb[0x88..0x90].copy_from_slice(&1_u64.to_le_bytes());
        sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
        sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
        sb[0x9C..0xA0].copy_from_slice(&sectorsize.to_le_bytes());
        sb[0xA0..0xA4].copy_from_slice(&sys_chunk_len_u32.to_le_bytes());

        let array_end = BTRFS_SYS_CHUNK_ARRAY_OFFSET + sys_chunk_array.len();
        sb[BTRFS_SYS_CHUNK_ARRAY_OFFSET..array_end].copy_from_slice(sys_chunk_array);
        sb
    }

    fn make_proptest_header_block(block_size: usize, nritems: u32, level: u8) -> Vec<u8> {
        let mut block = vec![0_u8; block_size.max(BTRFS_HEADER_SIZE)];
        block[0x30..0x38].copy_from_slice(&0x1000_u64.to_le_bytes());
        block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
        block[0x64] = level;
        block
    }

    fn write_disk_key(buf: &mut [u8], base: usize, key: BtrfsKey) {
        buf[base..base + 8].copy_from_slice(&key.objectid.to_le_bytes());
        buf[base + 8] = key.item_type;
        buf[base + 9..base + 17].copy_from_slice(&key.offset.to_le_bytes());
    }

    // Reproduce any failing case with:
    // PROPTEST_CASES=1 PROPTEST_SEED=<seed> cargo test -p ffs-ondisk <test_name> -- --nocapture
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn btrfs_proptest_parse_superblock_region_no_panic(
            region in proptest::collection::vec(any::<u8>(), 0..=(BTRFS_SUPER_INFO_SIZE * 2)),
        ) {
            let _ = BtrfsSuperblock::parse_superblock_region(&region);
        }

        #[test]
        fn btrfs_proptest_parse_from_image_no_panic(
            image in proptest::collection::vec(
                any::<u8>(),
                0..=(BTRFS_SUPER_INFO_OFFSET + BTRFS_SUPER_INFO_SIZE + 256),
            ),
        ) {
            let _ = BtrfsSuperblock::parse_from_image(&image);
        }

        #[test]
        fn btrfs_proptest_parse_sys_chunk_array_no_panic(
            data in proptest::collection::vec(any::<u8>(), 0..=BTRFS_SYS_CHUNK_ARRAY_MAX),
        ) {
            let _ = parse_sys_chunk_array(&data);
        }

        #[test]
        fn btrfs_proptest_parse_leaf_items_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let _ = parse_leaf_items(&block);
        }

        #[test]
        fn btrfs_proptest_parse_internal_items_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let _ = parse_internal_items(&block);
        }

        #[test]
        fn btrfs_proptest_header_parse_validate_no_panic(
            block in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            if let Ok(header) = BtrfsHeader::parse_from_block(&block) {
                let _ = header.validate(block.len(), None);
            }
        }

        #[test]
        fn btrfs_proptest_structured_superblock_size_invariants(
            sector_shift in 12_u32..=18,
            node_shift in 12_u32..=18,
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let sb = make_proptest_valid_btrfs_superblock(sectorsize, nodesize, &[]);
            let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("parse structured btrfs superblock");
            prop_assert!(parsed.sectorsize.is_power_of_two());
            prop_assert!(parsed.nodesize.is_power_of_two());
            prop_assert!(parsed.sectorsize <= 256 * 1024);
            prop_assert!(parsed.nodesize <= 256 * 1024);
        }

        #[test]
        fn btrfs_proptest_structured_sys_chunk_array_round_trip(
            sys_chunk_array in proptest::collection::vec(any::<u8>(), 0..=128),
        ) {
            let sb = make_proptest_valid_btrfs_superblock(4096, 16384, &sys_chunk_array);
            let parsed = BtrfsSuperblock::parse_superblock_region(&sb).expect("parse structured btrfs superblock");
            prop_assert_eq!(usize::try_from(parsed.sys_chunk_array_size).ok(), Some(sys_chunk_array.len()));
            prop_assert_eq!(parsed.sys_chunk_array, sys_chunk_array);
        }

        #[test]
        fn btrfs_proptest_header_validate_leaf_capacity(nritems in 0_u32..=159) {
            let block_size = 4096_usize;
            let block = make_proptest_header_block(block_size, nritems, 0);
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");
            prop_assert!(header.validate(block_size, Some(0x1000)).is_ok());
        }

        #[test]
        fn btrfs_proptest_header_validate_internal_capacity(
            nritems in 0_u32..=121,
            level in 1_u8..=BTRFS_MAX_LEVEL,
        ) {
            let block_size = 4096_usize;
            let block = make_proptest_header_block(block_size, nritems, level);
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");
            prop_assert!(header.validate(block_size, Some(0x1000)).is_ok());
        }

        #[test]
        fn btrfs_proptest_parse_from_image_matches_region_parser(
            sector_shift in 12_u32..=16,
            node_shift in 12_u32..=16,
            sys_chunk_array in proptest::collection::vec(any::<u8>(), 0..=128),
            prefix in proptest::collection::vec(any::<u8>(), BTRFS_SUPER_INFO_OFFSET..=BTRFS_SUPER_INFO_OFFSET),
            suffix in proptest::collection::vec(any::<u8>(), 0..=1024),
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let sb = make_proptest_valid_btrfs_superblock(sectorsize, nodesize, &sys_chunk_array);
            let from_region = BtrfsSuperblock::parse_superblock_region(&sb).expect("structured region parse");

            let mut image = prefix;
            image.extend_from_slice(&sb);
            image.extend_from_slice(&suffix);

            let from_image = BtrfsSuperblock::parse_from_image(&image).expect("structured image parse");
            prop_assert_eq!(from_image, from_region);
        }

        #[test]
        fn btrfs_proptest_leaf_items_structured_key_roundtrip(
            n_items in 1_usize..=8,
            bytenr in any::<u64>(),
            objectids in proptest::collection::vec(any::<u64>(), 8),
            item_types in proptest::collection::vec(any::<u8>(), 8),
            key_offsets in proptest::collection::vec(any::<u64>(), 8),
        ) {
            let mut block = vec![0_u8; 4096];
            block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
            let n_items_u32 = u32::try_from(n_items).expect("bounded n_items fits in u32");
            block[0x60..0x64].copy_from_slice(&n_items_u32.to_le_bytes());
            block[0x64] = 0;

            let data_offset_abs = u32::try_from(BTRFS_HEADER_SIZE + n_items * BTRFS_ITEM_SIZE)
                .expect("leaf item table endpoint fits in u32");
            let data_offset_rel = data_offset_abs - (BTRFS_HEADER_SIZE as u32);

            for i in 0..n_items {
                let base = BTRFS_HEADER_SIZE + i * BTRFS_ITEM_SIZE;
                let key = BtrfsKey {
                    objectid: objectids[i],
                    item_type: item_types[i],
                    offset: key_offsets[i],
                };
                write_disk_key(&mut block, base, key);
                block[base + 17..base + 21].copy_from_slice(&data_offset_rel.to_le_bytes());
                block[base + 21..base + 25].copy_from_slice(&0_u32.to_le_bytes());
            }

            let (header, items) = parse_leaf_items(&block).expect("structured leaf parse");
            prop_assert_eq!(usize::try_from(header.nritems).ok(), Some(n_items));
            prop_assert_eq!(items.len(), n_items);

            for i in 0..n_items {
                prop_assert_eq!(items[i].key.objectid, objectids[i]);
                prop_assert_eq!(items[i].key.item_type, item_types[i]);
                prop_assert_eq!(items[i].key.offset, key_offsets[i]);
                prop_assert_eq!(items[i].data_offset, data_offset_abs);
                prop_assert_eq!(items[i].data_size, 0);
            }
        }

        #[test]
        fn btrfs_proptest_internal_items_structured_roundtrip(
            n_items in 1_usize..=8,
            level in 1_u8..=BTRFS_MAX_LEVEL,
            bytenr in any::<u64>(),
            objectids in proptest::collection::vec(any::<u64>(), 8),
            item_types in proptest::collection::vec(any::<u8>(), 8),
            key_offsets in proptest::collection::vec(any::<u64>(), 8),
            blockptrs in proptest::collection::vec(1_u64..=u64::MAX, 8),
            generations in proptest::collection::vec(any::<u64>(), 8),
        ) {
            let mut block = vec![0_u8; 4096];
            block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
            let n_items_u32 = u32::try_from(n_items).expect("bounded n_items fits in u32");
            block[0x60..0x64].copy_from_slice(&n_items_u32.to_le_bytes());
            block[0x64] = level;

            for i in 0..n_items {
                let base = BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE;
                let key = BtrfsKey {
                    objectid: objectids[i],
                    item_type: item_types[i],
                    offset: key_offsets[i],
                };
                write_disk_key(&mut block, base, key);
                block[base + 17..base + 25].copy_from_slice(&blockptrs[i].to_le_bytes());
                block[base + 25..base + 33].copy_from_slice(&generations[i].to_le_bytes());
            }

            let (header, ptrs) = parse_internal_items(&block).expect("structured internal parse");
            prop_assert_eq!(header.level, level);
            prop_assert_eq!(usize::try_from(header.nritems).ok(), Some(n_items));
            prop_assert_eq!(ptrs.len(), n_items);

            for i in 0..n_items {
                prop_assert_eq!(ptrs[i].key.objectid, objectids[i]);
                prop_assert_eq!(ptrs[i].key.item_type, item_types[i]);
                prop_assert_eq!(ptrs[i].key.offset, key_offsets[i]);
                prop_assert_eq!(ptrs[i].blockptr, blockptrs[i]);
                prop_assert_eq!(ptrs[i].generation, generations[i]);
            }
        }

        #[test]
        fn btrfs_proptest_sys_chunk_array_structured_single_entry_roundtrip(
            key_objectid in any::<u64>(),
            key_type in any::<u8>(),
            key_offset in any::<u64>(),
            length in 1_u64..=1_000_000_u64,
            owner in any::<u64>(),
            stripe_len in 1_u64..=1_000_000_u64,
            chunk_type in any::<u64>(),
            io_align in any::<u32>(),
            io_width in any::<u32>(),
            sector_size in 1_u32..=65536_u32,
            num_stripes in 1_u16..=4_u16,
            sub_stripes in any::<u16>(),
            devids in proptest::collection::vec(any::<u64>(), 4),
            offsets in proptest::collection::vec(any::<u64>(), 4),
        ) {
            let stripes_count = usize::from(num_stripes);
            let entry_len = BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE + stripes_count * BTRFS_STRIPE_SIZE;
            let mut data = vec![0_u8; entry_len];

            let key = BtrfsKey {
                objectid: key_objectid,
                item_type: key_type,
                offset: key_offset,
            };
            write_disk_key(&mut data, 0, key);

            let chunk_base = BTRFS_DISK_KEY_SIZE;
            data[chunk_base..chunk_base + 8].copy_from_slice(&length.to_le_bytes());
            data[chunk_base + 8..chunk_base + 16].copy_from_slice(&owner.to_le_bytes());
            data[chunk_base + 16..chunk_base + 24].copy_from_slice(&stripe_len.to_le_bytes());
            data[chunk_base + 24..chunk_base + 32].copy_from_slice(&chunk_type.to_le_bytes());
            data[chunk_base + 32..chunk_base + 36].copy_from_slice(&io_align.to_le_bytes());
            data[chunk_base + 36..chunk_base + 40].copy_from_slice(&io_width.to_le_bytes());
            data[chunk_base + 40..chunk_base + 44].copy_from_slice(&sector_size.to_le_bytes());
            data[chunk_base + 44..chunk_base + 46].copy_from_slice(&num_stripes.to_le_bytes());
            data[chunk_base + 46..chunk_base + 48].copy_from_slice(&sub_stripes.to_le_bytes());

            let mut stripe_base = chunk_base + BTRFS_CHUNK_FIXED_SIZE;
            for i in 0..stripes_count {
                data[stripe_base..stripe_base + 8].copy_from_slice(&devids[i].to_le_bytes());
                data[stripe_base + 8..stripe_base + 16].copy_from_slice(&offsets[i].to_le_bytes());
                stripe_base += BTRFS_STRIPE_SIZE;
            }

            let parsed = parse_sys_chunk_array(&data).expect("structured sys_chunk parse");
            prop_assert_eq!(parsed.len(), 1);
            let entry = &parsed[0];
            prop_assert_eq!(entry.key, key);
            prop_assert_eq!(entry.length, length);
            prop_assert_eq!(entry.owner, owner);
            prop_assert_eq!(entry.stripe_len, stripe_len);
            prop_assert_eq!(entry.chunk_type, chunk_type);
            prop_assert_eq!(entry.io_align, io_align);
            prop_assert_eq!(entry.io_width, io_width);
            prop_assert_eq!(entry.sector_size, sector_size);
            prop_assert_eq!(entry.num_stripes, num_stripes);
            prop_assert_eq!(entry.sub_stripes, sub_stripes);
            prop_assert_eq!(entry.stripes.len(), stripes_count);
            for i in 0..stripes_count {
                prop_assert_eq!(entry.stripes[i].devid, devids[i]);
                prop_assert_eq!(entry.stripes[i].offset, offsets[i]);
            }
        }

        #[test]
        fn btrfs_proptest_map_logical_to_physical_single_chunk(
            chunk_start in 0_u64..=1_000_000_u64,
            length in 1_u64..=1_000_000_u64,
            stripe_devid in any::<u64>(),
            stripe_offset in 0_u64..=1_000_000_u64,
            delta in 0_u64..=1_000_000_u64,
        ) {
            prop_assume!(delta < length);
            let logical = chunk_start.checked_add(delta).expect("bounded logical address");
            let physical = stripe_offset.checked_add(delta).expect("bounded physical address");
            let chunk = BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228,
                    offset: chunk_start,
                },
                length,
                owner: 2,
                stripe_len: 64 * 1024,
                chunk_type: 1,
                io_align: 4096,
                io_width: 4096,
                sector_size: 4096,
                num_stripes: 1,
                sub_stripes: 1,
                stripes: vec![BtrfsStripe {
                    devid: stripe_devid,
                    offset: stripe_offset,
                    dev_uuid: [0_u8; 16],
                }],
            };

            let mapped = map_logical_to_physical(&[chunk], logical).expect("map should succeed");
            prop_assert_eq!(
                mapped,
                Some(BtrfsPhysicalMapping {
                    devid: stripe_devid,
                    physical,
                })
            );
        }

        #[test]
        fn btrfs_proptest_superblock_checksum_roundtrip_with_tamper_detection(
            sector_shift in 12_u32..=16,
            node_shift in 12_u32..=16,
            sys_chunk_array in proptest::collection::vec(any::<u8>(), 0..=64),
            flip_index in 0x20_usize..BTRFS_SUPER_INFO_SIZE,
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let mut sb = make_proptest_valid_btrfs_superblock(sectorsize, nodesize, &sys_chunk_array);
            sb[0xC4..0xC6].copy_from_slice(&ffs_types::BTRFS_CSUM_TYPE_CRC32C.to_le_bytes());
            let csum = crc32c::crc32c(&sb[0x20..]);
            sb[0..4].copy_from_slice(&csum.to_le_bytes());

            verify_superblock_checksum(&sb).expect("checksum should verify before tamper");
            sb[flip_index] ^= 0x01;
            prop_assert!(verify_superblock_checksum(&sb).is_err());
        }

        #[test]
        fn btrfs_proptest_tree_block_checksum_roundtrip_with_tamper_detection(
            block_len in 256_usize..=4096_usize,
            seed in any::<u8>(),
            flip_index in 0x20_usize..4096_usize,
        ) {
            prop_assume!(flip_index < block_len);
            let mut block = vec![seed; block_len];
            let csum = crc32c::crc32c(&block[0x20..]);
            block[0..4].copy_from_slice(&csum.to_le_bytes());
            verify_tree_block_checksum(&block, ffs_types::BTRFS_CSUM_TYPE_CRC32C)
                .expect("tree block checksum should verify before tamper");

            block[flip_index] ^= 0x80;
            prop_assert!(
                verify_tree_block_checksum(&block, ffs_types::BTRFS_CSUM_TYPE_CRC32C).is_err()
            );
        }

        #[test]
        fn btrfs_proptest_header_validate_bytenr_match_contract(
            bytenr in any::<u64>(),
            expected in any::<u64>(),
        ) {
            let mut block = make_proptest_header_block(4096, 0, 0);
            block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");

            let result = header.validate(block.len(), Some(expected));
            if bytenr == expected {
                prop_assert!(result.is_ok());
            } else {
                assert!(matches!(
                    result,
                    Err(ParseError::InvalidField {
                        field: "bytenr",
                        ..
                    })
                ));
            }
        }

        #[test]
        fn btrfs_proptest_header_validate_rejects_levels_above_max(level in (BTRFS_MAX_LEVEL + 1)..=u8::MAX) {
            let block = make_proptest_header_block(4096, 0, level);
            let header = BtrfsHeader::parse_from_block(&block).expect("parse header");
            assert!(matches!(
                header.validate(block.len(), None),
                Err(ParseError::InvalidField {
                    field: "level",
                    ..
                })
            ));
        }

        #[test]
        fn btrfs_proptest_superblock_rejects_invalid_non_power_of_two_stripesize(
            stripesize in 1_u32..=200_000_u32,
        ) {
            prop_assume!(!stripesize.is_power_of_two());
            let mut sb = make_proptest_valid_btrfs_superblock(4096, 16384, &[]);
            sb[0x9C..0xA0].copy_from_slice(&stripesize.to_le_bytes());
            assert!(matches!(
                BtrfsSuperblock::parse_superblock_region(&sb),
                Err(ParseError::InvalidField {
                    field: "stripesize",
                    ..
                })
            ));
        }

        // ── Additional semantic / roundtrip proptest tests (GreenSnow) ──

        /// Superblock field preservation: construct a valid SB with random
        /// field values, parse it, verify all scalar fields are preserved.
        #[test]
        fn btrfs_proptest_superblock_fields_preserved(
            sector_shift in 12_u32..=17,
            node_shift in 12_u32..=17,
            generation in any::<u64>(),
            root in any::<u64>(),
            chunk_root in any::<u64>(),
            log_root in any::<u64>(),
            total_bytes in any::<u64>(),
            bytes_used in any::<u64>(),
            root_dir_objectid in any::<u64>(),
            num_devices in any::<u64>(),
            compat_flags in any::<u64>(),
            compat_ro_flags in any::<u64>(),
            incompat_flags in any::<u64>(),
            csum_type in any::<u16>(),
            root_level in 0_u8..=BTRFS_MAX_LEVEL,
            chunk_root_level in 0_u8..=BTRFS_MAX_LEVEL,
            log_root_level in 0_u8..=BTRFS_MAX_LEVEL,
        ) {
            let sectorsize = 1_u32 << sector_shift;
            let nodesize = 1_u32 << node_shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x48..0x50].copy_from_slice(&generation.to_le_bytes());
            sb[0x50..0x58].copy_from_slice(&root.to_le_bytes());
            sb[0x58..0x60].copy_from_slice(&chunk_root.to_le_bytes());
            sb[0x60..0x68].copy_from_slice(&log_root.to_le_bytes());
            sb[0x70..0x78].copy_from_slice(&total_bytes.to_le_bytes());
            sb[0x78..0x80].copy_from_slice(&bytes_used.to_le_bytes());
            sb[0x80..0x88].copy_from_slice(&root_dir_objectid.to_le_bytes());
            sb[0x88..0x90].copy_from_slice(&num_devices.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
            sb[0x9C..0xA0].copy_from_slice(&sectorsize.to_le_bytes()); // stripesize
            sb[0xAC..0xB4].copy_from_slice(&compat_flags.to_le_bytes());
            sb[0xB4..0xBC].copy_from_slice(&compat_ro_flags.to_le_bytes());
            sb[0xBC..0xC4].copy_from_slice(&incompat_flags.to_le_bytes());
            sb[0xC4..0xC6].copy_from_slice(&csum_type.to_le_bytes());
            sb[0xC6] = root_level;
            sb[0xC7] = chunk_root_level;
            sb[0xC8] = log_root_level;

            let parsed = BtrfsSuperblock::parse_superblock_region(&sb)
                .expect("parse structured sb");
            prop_assert_eq!(parsed.magic, BTRFS_MAGIC);
            prop_assert_eq!(parsed.generation, generation);
            prop_assert_eq!(parsed.root, root);
            prop_assert_eq!(parsed.chunk_root, chunk_root);
            prop_assert_eq!(parsed.log_root, log_root);
            prop_assert_eq!(parsed.total_bytes, total_bytes);
            prop_assert_eq!(parsed.bytes_used, bytes_used);
            prop_assert_eq!(parsed.root_dir_objectid, root_dir_objectid);
            prop_assert_eq!(parsed.num_devices, num_devices);
            prop_assert_eq!(parsed.sectorsize, sectorsize);
            prop_assert_eq!(parsed.nodesize, nodesize);
            prop_assert_eq!(parsed.stripesize, sectorsize);
            prop_assert_eq!(parsed.compat_flags, compat_flags);
            prop_assert_eq!(parsed.compat_ro_flags, compat_ro_flags);
            prop_assert_eq!(parsed.incompat_flags, incompat_flags);
            prop_assert_eq!(parsed.csum_type, csum_type);
            prop_assert_eq!(parsed.root_level, root_level);
            prop_assert_eq!(parsed.chunk_root_level, chunk_root_level);
            prop_assert_eq!(parsed.log_root_level, log_root_level);
        }

        /// Superblock label preservation: random ASCII labels survive roundtrip.
        #[test]
        fn btrfs_proptest_superblock_label_preserved(
            label_bytes in proptest::collection::vec(0x21_u8..=0x7E, 0..=64),
        ) {
            let expected_label = String::from_utf8(label_bytes.clone())
                .unwrap_or_default();
            let mut sb = make_proptest_valid_btrfs_superblock(4096, 16384, &[]);
            for (i, &b) in label_bytes.iter().enumerate() {
                if i < BTRFS_SUPER_LABEL_LEN {
                    sb[BTRFS_SUPER_LABEL_OFFSET + i] = b;
                }
            }
            if label_bytes.len() < BTRFS_SUPER_LABEL_LEN {
                sb[BTRFS_SUPER_LABEL_OFFSET + label_bytes.len()] = 0;
            }

            let parsed = BtrfsSuperblock::parse_superblock_region(&sb)
                .expect("parse sb with label");
            prop_assert_eq!(parsed.label, expected_label);
        }

        /// BtrfsKey roundtrip via leaf item: write key bytes, parse, verify.
        #[test]
        fn btrfs_proptest_key_roundtrip_via_leaf(
            objectid in any::<u64>(),
            item_type in any::<u8>(),
            offset in any::<u64>(),
        ) {
            let mut block = vec![0_u8; 512];
            block[0x60..0x64].copy_from_slice(&1_u32.to_le_bytes());
            block[0x64] = 0; // leaf
            let base = BTRFS_HEADER_SIZE;
            let key = BtrfsKey { objectid, item_type, offset };
            write_disk_key(&mut block, base, key);
            block[base + 17..base + 21].copy_from_slice(&200_u32.to_le_bytes());
            block[base + 21..base + 25].copy_from_slice(&8_u32.to_le_bytes());

            let (_, items) = parse_leaf_items(&block).expect("parse leaf");
            prop_assert_eq!(items[0].key.objectid, objectid);
            prop_assert_eq!(items[0].key.item_type, item_type);
            prop_assert_eq!(items[0].key.offset, offset);
        }

        /// BtrfsHeader field preservation: random fields, parse, verify all.
        #[test]
        fn btrfs_proptest_header_fields_preserved(
            csum in proptest::collection::vec(any::<u8>(), 32..=32),
            fsid in proptest::collection::vec(any::<u8>(), 16..=16),
            bytenr in any::<u64>(),
            flags in any::<u64>(),
            chunk_tree_uuid in proptest::collection::vec(any::<u8>(), 16..=16),
            generation in any::<u64>(),
            owner in any::<u64>(),
            nritems in 0_u32..=10,
            level in 0_u8..=BTRFS_MAX_LEVEL,
        ) {
            let mut block = vec![0_u8; 4096];
            block[0x00..0x20].copy_from_slice(&csum);
            block[0x20..0x30].copy_from_slice(&fsid);
            block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
            block[0x38..0x40].copy_from_slice(&flags.to_le_bytes());
            block[0x40..0x50].copy_from_slice(&chunk_tree_uuid);
            block[0x50..0x58].copy_from_slice(&generation.to_le_bytes());
            block[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
            block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
            block[0x64] = level;

            let header = BtrfsHeader::parse_from_block(&block)
                .expect("parse header");
            prop_assert_eq!(&header.csum, csum.as_slice());
            prop_assert_eq!(&header.fsid, fsid.as_slice());
            prop_assert_eq!(header.bytenr, bytenr);
            prop_assert_eq!(header.flags, flags);
            prop_assert_eq!(&header.chunk_tree_uuid, chunk_tree_uuid.as_slice());
            prop_assert_eq!(header.generation, generation);
            prop_assert_eq!(header.owner, owner);
            prop_assert_eq!(header.nritems, nritems);
            prop_assert_eq!(header.level, level);
        }

        /// map_logical_to_physical miss: address outside any chunk returns None.
        #[test]
        fn btrfs_proptest_logical_to_physical_miss(
            chunk_start in 0x1000_u64..=0xFFFF_FFFF,
            chunk_length in 1_u64..=0x100_0000,
        ) {
            let chunks = vec![BtrfsChunkEntry {
                key: BtrfsKey {
                    objectid: 256,
                    item_type: 228,
                    offset: chunk_start,
                },
                length: chunk_length,
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
                    offset: 0,
                    dev_uuid: [0; 16],
                }],
            }];

            // Address before chunk start
            if chunk_start > 0 {
                let result = map_logical_to_physical(&chunks, chunk_start - 1)
                    .expect("no error");
                prop_assert!(result.is_none(), "Address before chunk should miss");
            }

            // Address at chunk_start + length (one past end)
            if let Some(end) = chunk_start.checked_add(chunk_length) {
                let result = map_logical_to_physical(&chunks, end)
                    .expect("no error");
                prop_assert!(result.is_none(), "Address at chunk end should miss");
            }
        }

        /// Superblock rejects zero sectorsize.
        #[test]
        fn btrfs_proptest_superblock_rejects_zero_sectorsize(
            nodesize_shift in 12_u32..=17,
        ) {
            let nodesize = 1_u32 << nodesize_shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&0_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "sectorsize", .. }
            ));
        }

        /// Superblock rejects zero nodesize.
        #[test]
        fn btrfs_proptest_superblock_rejects_zero_nodesize(
            sectorsize_shift in 12_u32..=17,
        ) {
            let sectorsize = 1_u32 << sectorsize_shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&0_u32.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "nodesize", .. }
            ));
        }

        /// Superblock rejects sectorsize > 256K.
        #[test]
        fn btrfs_proptest_superblock_rejects_oversized_sectorsize(
            shift in 19_u32..=30,
        ) {
            let sectorsize = 1_u32 << shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&sectorsize.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "sectorsize", .. }
            ));
        }

        /// Superblock rejects nodesize > 256K.
        #[test]
        fn btrfs_proptest_superblock_rejects_oversized_nodesize(
            shift in 19_u32..=30,
        ) {
            let nodesize = 1_u32 << shift;
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&nodesize.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "nodesize", .. }
            ));
        }

        /// Header validate rejects nritems above leaf capacity.
        #[test]
        fn btrfs_proptest_header_validate_rejects_overflow_leaf(
            nritems in 160_u32..=500,
        ) {
            let block = make_proptest_header_block(4096, nritems, 0);
            let header = BtrfsHeader::parse_from_block(&block)
                .expect("parse");
            let result = header.validate(4096, None);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "nritems", .. }
            ));
        }

        /// Header validate rejects nritems above internal capacity.
        #[test]
        fn btrfs_proptest_header_validate_rejects_overflow_internal(
            nritems in 122_u32..=500,
            level in 1_u8..=BTRFS_MAX_LEVEL,
        ) {
            let block = make_proptest_header_block(4096, nritems, level);
            let header = BtrfsHeader::parse_from_block(&block)
                .expect("parse");
            let result = header.validate(4096, None);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "nritems", .. }
            ));
        }

        /// parse_leaf_items rejects blocks with level > 0.
        #[test]
        fn btrfs_proptest_parse_leaf_rejects_nonzero_level(
            level in 1_u8..=BTRFS_MAX_LEVEL,
        ) {
            let block = make_proptest_header_block(4096, 0, level);
            let result = parse_leaf_items(&block);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "level", .. }
            ));
        }

        /// parse_internal_items rejects blocks with level == 0.
        #[test]
        fn btrfs_proptest_parse_internal_rejects_level_zero(
            nritems in 0_u32..=10,
        ) {
            let block = make_proptest_header_block(4096, nritems, 0);
            let result = parse_internal_items(&block);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "level", .. }
            ));
        }

        /// verify_tree_block_checksum rejects unsupported csum_type.
        #[test]
        fn btrfs_proptest_tree_block_checksum_rejects_unsupported_type(
            csum_type in 1_u16..=u16::MAX,
        ) {
            let block = vec![0_u8; 4096];
            let result = verify_tree_block_checksum(&block, csum_type);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "csum_type", .. }
            ));
        }

        /// verify_superblock_checksum rejects too-short regions.
        #[test]
        fn btrfs_proptest_superblock_checksum_rejects_short_region(
            len in 0_usize..BTRFS_SUPER_INFO_SIZE,
        ) {
            let region = vec![0_u8; len];
            let result = verify_superblock_checksum(&region);
            prop_assert!(result.is_err());
        }

        /// Superblock rejects wrong magic.
        #[test]
        fn btrfs_proptest_superblock_rejects_wrong_magic(
            magic in any::<u64>().prop_filter("not btrfs magic", |m| *m != BTRFS_MAGIC),
        ) {
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&magic.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(err, ParseError::InvalidMagic { .. }));
        }

        /// parse_sys_chunk_array rejects zero num_stripes.
        #[test]
        fn btrfs_proptest_sys_chunk_array_rejects_zero_stripes(
            key_objectid in any::<u64>(),
            key_offset in any::<u64>(),
        ) {
            let mut data = vec![0_u8; BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE];
            data[0..8].copy_from_slice(&key_objectid.to_le_bytes());
            data[8] = 228;
            data[9..17].copy_from_slice(&key_offset.to_le_bytes());
            let c = BTRFS_DISK_KEY_SIZE;
            data[c..c + 8].copy_from_slice(&1_u64.to_le_bytes());
            // num_stripes at c+44..c+46 stays 0
            let result = parse_sys_chunk_array(&data);
            prop_assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ParseError::InvalidField { field: "num_stripes", .. }
            ));
        }

        /// Superblock rejects sys_chunk_array_size > 2048.
        #[test]
        fn btrfs_proptest_superblock_rejects_oversized_sys_chunk_array(
            excess in 1_u32..=1000,
        ) {
            let mut sb = [0_u8; BTRFS_SUPER_INFO_SIZE];
            sb[0x40..0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
            sb[0x90..0x94].copy_from_slice(&4096_u32.to_le_bytes());
            sb[0x94..0x98].copy_from_slice(&16384_u32.to_le_bytes());
            sb[0x9C..0xA0].copy_from_slice(&4096_u32.to_le_bytes());
            let max_sys_chunk_array_size =
                u32::try_from(BTRFS_SYS_CHUNK_ARRAY_MAX).expect("constant fits in u32");
            let bad_size = max_sys_chunk_array_size + excess;
            sb[0xA0..0xA4].copy_from_slice(&bad_size.to_le_bytes());
            let err = BtrfsSuperblock::parse_superblock_region(&sb).unwrap_err();
            assert!(matches!(
                err,
                ParseError::InvalidField { field: "sys_chunk_array_size", .. }
            ));
        }
    }

    // ── RAID profile identification ────────────────────────────────

    #[test]
    fn raid_profile_single() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_DATA),
            BtrfsRaidProfile::Single
        );
    }

    #[test]
    fn raid_profile_dup() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(
                chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP
            ),
            BtrfsRaidProfile::Dup
        );
    }

    #[test]
    fn raid_profile_raid0() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0),
            BtrfsRaidProfile::Raid0
        );
    }

    #[test]
    fn raid_profile_raid1() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1),
            BtrfsRaidProfile::Raid1
        );
    }

    #[test]
    fn raid_profile_raid10() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10),
            BtrfsRaidProfile::Raid10
        );
    }

    #[test]
    fn raid_profile_raid5() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5),
            BtrfsRaidProfile::Raid5
        );
    }

    #[test]
    fn raid_profile_raid6() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6),
            BtrfsRaidProfile::Raid6
        );
    }

    #[test]
    fn raid_profile_raid1c3() {
        assert_eq!(
            BtrfsRaidProfile::from_chunk_type(chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C3),
            BtrfsRaidProfile::Raid1C3
        );
    }

    #[test]
    fn raid_profile_data_copies() {
        assert_eq!(BtrfsRaidProfile::Single.data_copies(), 1);
        assert_eq!(BtrfsRaidProfile::Dup.data_copies(), 2);
        assert_eq!(BtrfsRaidProfile::Raid0.data_copies(), 1);
        assert_eq!(BtrfsRaidProfile::Raid1.data_copies(), 2);
        assert_eq!(BtrfsRaidProfile::Raid1C3.data_copies(), 3);
        assert_eq!(BtrfsRaidProfile::Raid1C4.data_copies(), 4);
        assert_eq!(BtrfsRaidProfile::Raid10.data_copies(), 2);
        assert_eq!(BtrfsRaidProfile::Raid5.data_copies(), 1);
        assert_eq!(BtrfsRaidProfile::Raid6.data_copies(), 1);
    }

    #[test]
    fn raid_profile_redundancy() {
        assert!(!BtrfsRaidProfile::Single.is_redundant());
        assert!(!BtrfsRaidProfile::Raid0.is_redundant());
        assert!(BtrfsRaidProfile::Dup.is_redundant());
        assert!(BtrfsRaidProfile::Raid1.is_redundant());
        assert!(BtrfsRaidProfile::Raid5.is_redundant());
        assert!(BtrfsRaidProfile::Raid6.is_redundant());
        assert!(BtrfsRaidProfile::Raid10.is_redundant());
    }

    // ── Stripe resolution ──────────────────────────────────────────

    fn make_chunk(
        offset: u64,
        length: u64,
        stripe_len: u64,
        chunk_type: u64,
        stripes: Vec<BtrfsStripe>,
        sub_stripes: u16,
    ) -> BtrfsChunkEntry {
        let num_stripes = u16::try_from(stripes.len()).expect("test stripes length fits in u16");
        BtrfsChunkEntry {
            key: BtrfsKey {
                objectid: 0x100,
                item_type: 228,
                offset,
            },
            length,
            owner: 2,
            stripe_len,
            chunk_type,
            io_align: 4096,
            io_width: 4096,
            sector_size: 4096,
            num_stripes,
            sub_stripes,
            stripes,
        }
    }

    fn stripe(devid: u64, offset: u64) -> BtrfsStripe {
        BtrfsStripe {
            devid,
            offset,
            dev_uuid: [0; 16],
        }
    }

    #[test]
    fn stripe_resolve_single() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            vec![stripe(1, 0x10_0000)],
            0,
        )];
        let result = map_logical_to_stripes(&chunks, 4096).unwrap().unwrap();
        assert_eq!(result.profile, BtrfsRaidProfile::Single);
        assert_eq!(result.stripes.len(), 1);
        assert_eq!(result.stripes[0].devid, 1);
        assert_eq!(result.stripes[0].physical, 0x10_0000 + 4096);
    }

    #[test]
    fn stripe_resolve_raid1_returns_both_mirrors() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        )];
        let result = map_logical_to_stripes(&chunks, 4096).unwrap().unwrap();
        assert_eq!(result.profile, BtrfsRaidProfile::Raid1);
        assert_eq!(result.stripes.len(), 2);
        assert_eq!(result.stripes[0].devid, 1);
        assert_eq!(result.stripes[1].devid, 2);
        assert_eq!(result.stripes[0].physical, 0x10_0000 + 4096);
        assert_eq!(result.stripes[1].physical, 0x20_0000 + 4096);
    }

    #[test]
    fn stripe_resolve_raid0_selects_correct_stripe() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
            vec![stripe(1, 0x10_0000), stripe(2, 0x20_0000)],
            0,
        )];
        // offset 0 -> stripe 0 (dev 1)
        let r0 = map_logical_to_stripes(&chunks, 0).unwrap().unwrap();
        assert_eq!(r0.stripes.len(), 1);
        assert_eq!(r0.stripes[0].devid, 1);

        // offset 65536 -> stripe 1 (dev 2)
        let r1 = map_logical_to_stripes(&chunks, 65536).unwrap().unwrap();
        assert_eq!(r1.stripes.len(), 1);
        assert_eq!(r1.stripes[0].devid, 2);
    }

    #[test]
    fn stripe_resolve_raid6_parity_wraparound() {
        // 4 devices, RAID6 (2 parity), stripe_len=65536
        // This tests the case where P is at the last device and Q wraps to device 0.
        let chunks = vec![make_chunk(
            0,
            // Large enough to cover multiple stripe rows
            65536 * 2 * 8, // data_stripes=2, 8 rows
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
            vec![
                stripe(1, 0x10_0000),
                stripe(2, 0x20_0000),
                stripe(3, 0x30_0000),
                stripe(4, 0x40_0000),
            ],
            0,
        )];

        // Row 3 (stripe_nr=3): P at pos 3 (dev 4), Q at pos 0 (dev 1).
        // Data should be at pos 1 (dev 2) and pos 2 (dev 3).
        // offset for row 3, data stripe 0 = 3 * 65536 * 2 + 0 = 393216
        let r = map_logical_to_stripes(&chunks, 393_216).unwrap().unwrap();
        assert_eq!(r.profile, BtrfsRaidProfile::Raid6);
        assert_eq!(r.stripes.len(), 1);
        // Should NOT be dev 1 (which is Q in this row)
        assert_ne!(
            r.stripes[0].devid, 1,
            "stripe_nr=3: position 0 is Q parity, data should not map there"
        );
        assert_eq!(
            r.stripes[0].devid, 2,
            "stripe_nr=3, data_idx=0: should map to device 2 (position 1)"
        );

        // Row 3, data stripe 1 = 393216 + 65536 = 458752
        let r2 = map_logical_to_stripes(&chunks, 458_752).unwrap().unwrap();
        assert_eq!(
            r2.stripes[0].devid, 3,
            "stripe_nr=3, data_idx=1: should map to device 3 (position 2)"
        );
    }

    #[test]
    fn stripe_resolve_no_match_returns_none() {
        let chunks = vec![make_chunk(
            0,
            1_048_576,
            65536,
            chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
            vec![stripe(1, 0)],
            0,
        )];
        let result = map_logical_to_stripes(&chunks, 2_000_000).unwrap();
        assert!(result.is_none());
    }

    // ── DEV_ITEM parsing ───────────────────────────────────────────

    #[test]
    fn parse_dev_item_valid() {
        let mut data = vec![0u8; 98];
        // devid = 1
        data[0..8].copy_from_slice(&1_u64.to_le_bytes());
        // total_bytes = 1GB
        data[8..16].copy_from_slice(&(1024 * 1024 * 1024_u64).to_le_bytes());
        // bytes_used = 500MB
        data[16..24].copy_from_slice(&(500 * 1024 * 1024_u64).to_le_bytes());
        // sector_size = 4096
        data[32..36].copy_from_slice(&4096_u32.to_le_bytes());

        let item = parse_dev_item(&data).unwrap();
        assert_eq!(item.devid, 1);
        assert_eq!(item.total_bytes, 1024 * 1024 * 1024);
        assert_eq!(item.bytes_used, 500 * 1024 * 1024);
        assert_eq!(item.sector_size, 4096);
    }

    #[test]
    fn parse_dev_item_too_short() {
        let data = vec![0u8; 50];
        let err = parse_dev_item(&data).unwrap_err();
        assert!(matches!(err, ParseError::InsufficientData { .. }));
    }
}
