#![no_main]

use ffs_ondisk::{
    chunk_type_flags, map_logical_to_physical, map_logical_to_stripes, parse_dev_item,
    parse_internal_items, parse_leaf_items, parse_sys_chunk_array,
    verify_btrfs_superblock_checksum, verify_btrfs_tree_block_checksum, BtrfsChunkEntry,
    BtrfsHeader, BtrfsPhysicalMapping, BtrfsRaidProfile, BtrfsStripeMapping,
};
use libfuzzer_sys::fuzz_target;

const BTRFS_FIRST_CHUNK_TREE_OBJECTID: u64 = 256;
const BTRFS_CHUNK_ITEM_KEY: u8 = 228;
const BTRFS_DISK_KEY_SIZE: usize = 17;
const BTRFS_CHUNK_FIXED_SIZE: usize = 48;
const BTRFS_STRIPE_SIZE: usize = 32;
const SINGLE_CHUNK_SIZE: usize = BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE + BTRFS_STRIPE_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChunkOutcome {
    Chunks(Vec<ChunkSig>),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChunkSig {
    logical_start: u64,
    length: u64,
    stripe_len: u64,
    chunk_type: u64,
    num_stripes: u16,
    sub_stripes: u16,
    stripes: Vec<StripeSig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StripeSig {
    devid: u64,
    offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PhysicalOutcome {
    Hit(StripeSig),
    Miss,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StripeOutcome {
    Hit {
        profile: BtrfsRaidProfile,
        stripes: Vec<StripeSig>,
    },
    Miss,
    Error,
}

fn normalize_chunks(result: Result<Vec<BtrfsChunkEntry>, impl ToString>) -> ChunkOutcome {
    match result {
        Ok(chunks) => ChunkOutcome::Chunks(chunks.iter().map(chunk_sig).collect()),
        Err(err) => ChunkOutcome::Error(err.to_string()),
    }
}

fn chunk_sig(chunk: &BtrfsChunkEntry) -> ChunkSig {
    ChunkSig {
        logical_start: chunk.key.offset,
        length: chunk.length,
        stripe_len: chunk.stripe_len,
        chunk_type: chunk.chunk_type,
        num_stripes: chunk.num_stripes,
        sub_stripes: chunk.sub_stripes,
        stripes: chunk
            .stripes
            .iter()
            .map(|stripe| StripeSig {
                devid: stripe.devid,
                offset: stripe.offset,
            })
            .collect(),
    }
}

fn normalize_physical(
    result: Result<Option<BtrfsPhysicalMapping>, impl ToString>,
) -> PhysicalOutcome {
    match result {
        Ok(Some(mapping)) => PhysicalOutcome::Hit(StripeSig {
            devid: mapping.devid,
            offset: mapping.physical,
        }),
        Ok(None) => PhysicalOutcome::Miss,
        Err(_) => PhysicalOutcome::Error,
    }
}

fn normalize_stripes(result: Result<Option<BtrfsStripeMapping>, impl ToString>) -> StripeOutcome {
    match result {
        Ok(Some(mapping)) => StripeOutcome::Hit {
            profile: mapping.profile,
            stripes: mapping
                .stripes
                .iter()
                .map(|stripe| StripeSig {
                    devid: stripe.devid,
                    offset: stripe.physical,
                })
                .collect(),
        },
        Ok(None) => StripeOutcome::Miss,
        Err(_) => StripeOutcome::Error,
    }
}

fn read_seed_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(offset.saturating_add(idx)).copied().unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

fn bounded_bytes(data: &[u8], offset: usize, len: usize, fallback_seed: u8) -> Vec<u8> {
    (0..len)
        .map(|idx| {
            data.get(offset.saturating_add(idx))
                .copied()
                .unwrap_or(fallback_seed.wrapping_add(u8::try_from(idx).unwrap_or(0)))
        })
        .collect()
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn synthetic_single_chunk(data: &[u8]) -> (Vec<u8>, u64, u64, u64, u64) {
    let logical_start = read_seed_u64(data, 0) & 0x000f_ffff;
    let length = 4096 * (1 + u64::from(data.get(8).copied().unwrap_or(3) % 16));
    let stripe_len = 4096;
    let stripe_offset = read_seed_u64(data, 9) & 0x000f_ffff;
    let devid = u64::from(data.get(17).copied().unwrap_or(1) % 63) + 1;

    let mut bytes = vec![0_u8; SINGLE_CHUNK_SIZE];
    write_u64(&mut bytes, 0, BTRFS_FIRST_CHUNK_TREE_OBJECTID);
    bytes[8] = BTRFS_CHUNK_ITEM_KEY;
    write_u64(&mut bytes, 9, logical_start);

    let header = BTRFS_DISK_KEY_SIZE;
    write_u64(&mut bytes, header, length);
    write_u64(&mut bytes, header + 8, BTRFS_FIRST_CHUNK_TREE_OBJECTID);
    write_u64(&mut bytes, header + 16, stripe_len);
    write_u64(
        &mut bytes,
        header + 24,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
    );
    write_u32(&mut bytes, header + 32, 4096);
    write_u32(&mut bytes, header + 36, 4096);
    write_u32(&mut bytes, header + 40, 4096);
    write_u16(&mut bytes, header + 44, 1);
    write_u16(&mut bytes, header + 46, 0);

    let stripe = BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE;
    write_u64(&mut bytes, stripe, devid);
    write_u64(&mut bytes, stripe + 8, stripe_offset);
    bytes[stripe + 16..stripe + 32].copy_from_slice(&bounded_bytes(data, 18, 16, b'u'));

    (bytes, logical_start, length, stripe_offset, devid)
}

fn assert_chunk_shape(chunks: &[BtrfsChunkEntry]) {
    for chunk in chunks {
        assert!(chunk.length > 0, "parsed chunks must reject zero length");
        assert!(
            chunk.stripe_len > 0,
            "parsed chunks must reject zero stripe_len"
        );
        assert_eq!(
            usize::from(chunk.num_stripes),
            chunk.stripes.len(),
            "num_stripes must match the decoded stripe list"
        );
        assert!(
            chunk.stripes.iter().all(|stripe| stripe.devid != 0),
            "parsed stripes must reject zero devid"
        );
        assert!(
            (chunk.chunk_type & chunk_type_flags::RAID_MASK).count_ones() <= 1,
            "parsed chunks must reject multiple RAID profile bits"
        );
    }
}

fn assert_mapping_consistency(chunks: &[BtrfsChunkEntry], logical: u64) {
    let physical = normalize_physical(map_logical_to_physical(chunks, logical));
    assert_eq!(
        physical,
        normalize_physical(map_logical_to_physical(chunks, logical)),
        "logical-to-physical mapping must be deterministic"
    );

    let stripes = normalize_stripes(map_logical_to_stripes(chunks, logical));
    assert_eq!(
        stripes,
        normalize_stripes(map_logical_to_stripes(chunks, logical)),
        "logical-to-stripes mapping must be deterministic"
    );

    match (physical, stripes) {
        (PhysicalOutcome::Hit(physical), StripeOutcome::Hit { stripes, .. }) => {
            assert!(
                stripes.contains(&physical),
                "single physical mapping must appear in the readable stripe set"
            );
        }
        (PhysicalOutcome::Hit(_), StripeOutcome::Error) | (PhysicalOutcome::Error, _) => {}
        (PhysicalOutcome::Miss, StripeOutcome::Miss) => {}
        (PhysicalOutcome::Miss, other) => {
            assert!(
                matches!(other, StripeOutcome::Miss),
                "physical miss should agree with stripe miss"
            );
        }
        (PhysicalOutcome::Hit(_), other) => {
            assert!(
                matches!(other, StripeOutcome::Hit { .. }),
                "physical hit should agree with stripe hit"
            );
        }
    }
}

fn assert_arbitrary_chunk_mapping(data: &[u8]) {
    let first_sig = normalize_chunks(parse_sys_chunk_array(data));
    assert_eq!(
        first_sig,
        normalize_chunks(parse_sys_chunk_array(data)),
        "sys_chunk_array parsing must be deterministic"
    );

    let Ok(chunks) = parse_sys_chunk_array(data) else {
        return;
    };
    assert_chunk_shape(&chunks);

    for logical in [
        0_u64,
        4096,
        65_536,
        1 << 20,
        1 << 30,
        read_seed_u64(data, 0),
        u64::MAX,
    ] {
        assert_mapping_consistency(&chunks, logical);
    }
}

fn assert_synthetic_single_chunk(data: &[u8]) {
    let (bytes, logical_start, length, stripe_offset, devid) = synthetic_single_chunk(data);
    let parsed = parse_sys_chunk_array(&bytes);
    assert!(parsed.is_ok(), "synthetic single chunk must parse");
    let Ok(chunks) = parsed else {
        return;
    };
    assert_eq!(chunks.len(), 1);
    assert_chunk_shape(&chunks);

    for delta in [0_u64, length / 2, length - 1] {
        let logical = logical_start + delta;
        let physical = normalize_physical(map_logical_to_physical(&chunks, logical));
        assert_eq!(
            physical,
            PhysicalOutcome::Hit(StripeSig {
                devid,
                offset: stripe_offset + delta,
            }),
            "single chunk logical mapping should preserve offset within chunk"
        );
        let stripes = normalize_stripes(map_logical_to_stripes(&chunks, logical));
        assert_eq!(
            stripes,
            StripeOutcome::Hit {
                profile: BtrfsRaidProfile::Single,
                stripes: vec![StripeSig {
                    devid,
                    offset: stripe_offset + delta,
                }],
            },
            "single chunk stripe mapping should match physical mapping"
        );
    }

    assert_eq!(
        normalize_physical(map_logical_to_physical(&chunks, logical_start + length)),
        PhysicalOutcome::Miss,
        "logical address at chunk_end must miss"
    );
    assert_eq!(
        normalize_stripes(map_logical_to_stripes(&chunks, logical_start + length)),
        StripeOutcome::Miss,
        "stripe mapping at chunk_end must miss"
    );
}

fn assert_synthetic_rejections(data: &[u8]) {
    let (valid, _, _, _, _) = synthetic_single_chunk(data);

    let mut bad_key_type = valid.clone();
    bad_key_type[8] = bad_key_type[8].wrapping_add(1);
    assert!(
        matches!(
            normalize_chunks(parse_sys_chunk_array(&bad_key_type)),
            ChunkOutcome::Error(_)
        ),
        "sys_chunk_array must reject non-CHUNK_ITEM keys"
    );

    let mut zero_length = valid.clone();
    write_u64(&mut zero_length, BTRFS_DISK_KEY_SIZE, 0);
    assert!(
        matches!(
            normalize_chunks(parse_sys_chunk_array(&zero_length)),
            ChunkOutcome::Error(_)
        ),
        "sys_chunk_array must reject zero-length chunks"
    );

    let mut zero_stripe_len = valid.clone();
    write_u64(&mut zero_stripe_len, BTRFS_DISK_KEY_SIZE + 16, 0);
    assert!(
        matches!(
            normalize_chunks(parse_sys_chunk_array(&zero_stripe_len)),
            ChunkOutcome::Error(_)
        ),
        "sys_chunk_array must reject zero stripe_len"
    );

    let mut zero_stripes = valid.clone();
    write_u16(&mut zero_stripes, BTRFS_DISK_KEY_SIZE + 44, 0);
    assert!(
        matches!(
            normalize_chunks(parse_sys_chunk_array(&zero_stripes)),
            ChunkOutcome::Error(_)
        ),
        "sys_chunk_array must reject zero num_stripes"
    );

    let mut zero_devid = valid.clone();
    write_u64(
        &mut zero_devid,
        BTRFS_DISK_KEY_SIZE + BTRFS_CHUNK_FIXED_SIZE,
        0,
    );
    assert!(
        matches!(
            normalize_chunks(parse_sys_chunk_array(&zero_devid)),
            ChunkOutcome::Error(_)
        ),
        "sys_chunk_array must reject zero stripe devid"
    );

    let mut multiple_raid_bits = valid;
    write_u64(
        &mut multiple_raid_bits,
        BTRFS_DISK_KEY_SIZE + 24,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0
            | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
    );
    assert!(
        matches!(
            normalize_chunks(parse_sys_chunk_array(&multiple_raid_bits)),
            ChunkOutcome::Error(_)
        ),
        "sys_chunk_array must reject multiple RAID profile bits"
    );
}

fn assert_misc_btrfs_parsers_are_deterministic(data: &[u8]) {
    assert_eq!(
        format!("{:?}", verify_btrfs_superblock_checksum(data)),
        format!("{:?}", verify_btrfs_superblock_checksum(data)),
        "superblock checksum verification must be deterministic"
    );
    for csum_type in [0_u16, 1, 2, 3, 255] {
        assert_eq!(
            format!("{:?}", verify_btrfs_tree_block_checksum(data, csum_type)),
            format!("{:?}", verify_btrfs_tree_block_checksum(data, csum_type)),
            "tree block checksum verification must be deterministic"
        );
    }
    assert_eq!(
        format!("{:?}", parse_leaf_items(data)),
        format!("{:?}", parse_leaf_items(data)),
        "leaf item parsing must be deterministic"
    );
    assert_eq!(
        format!("{:?}", parse_internal_items(data)),
        format!("{:?}", parse_internal_items(data)),
        "internal item parsing must be deterministic"
    );
    assert_eq!(
        format!("{:?}", parse_dev_item(data)),
        format!("{:?}", parse_dev_item(data)),
        "dev item parsing must be deterministic"
    );
    assert_eq!(
        format!("{:?}", BtrfsHeader::parse_from_block(data)),
        format!("{:?}", BtrfsHeader::parse_from_block(data)),
        "header parsing must be deterministic"
    );
}

fuzz_target!(|data: &[u8]| {
    assert_arbitrary_chunk_mapping(data);
    assert_synthetic_single_chunk(data);
    assert_synthetic_rejections(data);
    assert_misc_btrfs_parsers_are_deterministic(data);
});
