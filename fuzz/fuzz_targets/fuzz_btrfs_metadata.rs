#![no_main]
use ffs_ondisk::{
    chunk_type_flags, parse_dev_item, parse_internal_items, parse_leaf_items,
    parse_sys_chunk_array, verify_btrfs_superblock_checksum, verify_btrfs_tree_block_checksum,
    BtrfsHeader, BtrfsKey, BtrfsSuperblock,
};
use ffs_types::{BTRFS_CSUM_TYPE_CRC32C, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET};
use libfuzzer_sys::fuzz_target;

const BTRFS_HEADER_SIZE: usize = 101;
const BTRFS_ITEM_SIZE: usize = 25;
const BTRFS_KEY_PTR_SIZE: usize = 33;
const BTRFS_MAX_LEVEL: u8 = 7;
const BTRFS_CHUNK_TREE_OBJECTID: u64 = 256;
const BTRFS_CHUNK_ITEM_KEY: u8 = 228;
const MAX_METADATA_FIELD_SIZE: u32 = 256 * 1024;

fn key_tuple(key: BtrfsKey) -> (u64, u8, u64) {
    (key.objectid, key.item_type, key.offset)
}

fn assert_superblock_invariants(data: &[u8]) {
    let parsed = BtrfsSuperblock::parse_superblock_region(data);
    assert_eq!(
        parsed,
        BtrfsSuperblock::parse_superblock_region(data),
        "superblock region parsing must be deterministic"
    );
    assert_eq!(
        verify_btrfs_superblock_checksum(data),
        verify_btrfs_superblock_checksum(data),
        "superblock checksum verification must be deterministic"
    );

    if data.len() >= BTRFS_SUPER_INFO_OFFSET + ffs_types::BTRFS_SUPER_INFO_SIZE {
        assert_eq!(
            BtrfsSuperblock::parse_from_image(data),
            BtrfsSuperblock::parse_from_image(data),
            "full-image superblock parsing must be deterministic"
        );
    }

    let Ok(superblock) = parsed else {
        return;
    };

    assert_eq!(superblock.magic, BTRFS_MAGIC);
    assert!(superblock.total_bytes > 0);
    assert!(superblock.bytes_used <= superblock.total_bytes);
    assert!(superblock.num_devices > 0);
    assert!(superblock.sectorsize.is_power_of_two());
    assert!(superblock.nodesize.is_power_of_two());
    assert!(superblock.sectorsize <= MAX_METADATA_FIELD_SIZE);
    assert!(superblock.nodesize <= MAX_METADATA_FIELD_SIZE);
    assert!(
        superblock.stripesize == 0 || superblock.stripesize.is_power_of_two(),
        "stripesize must be zero or a power of two"
    );
    assert!(superblock.stripesize <= MAX_METADATA_FIELD_SIZE);
    assert!(superblock.root_level <= BTRFS_MAX_LEVEL);
    assert!(superblock.chunk_root_level <= BTRFS_MAX_LEVEL);
    assert!(superblock.log_root_level <= BTRFS_MAX_LEVEL);
    assert_eq!(
        superblock.sys_chunk_array.len(),
        superblock.sys_chunk_array_size as usize
    );
}

fn assert_sys_chunk_array_invariants(data: &[u8]) {
    let parsed = parse_sys_chunk_array(data);
    assert_eq!(
        parsed,
        parse_sys_chunk_array(data),
        "sys_chunk_array parsing must be deterministic"
    );

    let Ok(entries) = parsed else {
        return;
    };

    for entry in entries {
        assert_eq!(entry.key.objectid, BTRFS_CHUNK_TREE_OBJECTID);
        assert_eq!(entry.key.item_type, BTRFS_CHUNK_ITEM_KEY);
        assert!(entry.length > 0);
        assert!(entry.stripe_len > 0);
        assert_eq!(usize::from(entry.num_stripes), entry.stripes.len());
        assert!(entry.num_stripes > 0);
        assert!(
            (entry.chunk_type & chunk_type_flags::RAID_MASK).count_ones() <= 1,
            "a parsed chunk must not advertise multiple RAID profiles"
        );
        for stripe in entry.stripes {
            assert!(stripe.devid > 0);
        }
    }
}

fn assert_header_matches_block(block: &[u8], header: &BtrfsHeader) {
    assert_eq!(
        header.nritems,
        u32::from_le_bytes([block[0x60], block[0x61], block[0x62], block[0x63]])
    );
    assert_eq!(header.level, block[0x64]);
}

fn assert_tree_item_invariants(data: &[u8]) {
    let header = BtrfsHeader::parse_from_block(data);
    assert_eq!(
        header,
        BtrfsHeader::parse_from_block(data),
        "tree block header parsing must be deterministic"
    );
    assert_eq!(
        verify_btrfs_tree_block_checksum(data, BTRFS_CSUM_TYPE_CRC32C),
        verify_btrfs_tree_block_checksum(data, BTRFS_CSUM_TYPE_CRC32C),
        "tree block checksum verification must be deterministic"
    );

    if let Ok(header) = &header {
        assert_header_matches_block(data, header);
    }

    let leaf = parse_leaf_items(data);
    assert_eq!(
        leaf,
        parse_leaf_items(data),
        "leaf item parsing must be deterministic"
    );
    if let Ok((header, items)) = &leaf {
        assert_eq!(header.level, 0);
        assert_eq!(header.nritems as usize, items.len());
        let item_table_end = BTRFS_HEADER_SIZE + items.len() * BTRFS_ITEM_SIZE;
        let mut previous = None;
        let mut ranges = Vec::new();
        for item in items {
            if let Some(previous) = previous {
                assert!(
                    previous < key_tuple(item.key),
                    "leaf item keys must be strictly increasing"
                );
            }
            previous = Some(key_tuple(item.key));
            let start = item.data_offset as usize;
            let end = start + item.data_size as usize;
            assert!(start >= item_table_end);
            assert!(end <= data.len());
            assert!(
                ranges
                    .iter()
                    .all(|(range_start, range_end)| start >= *range_end || end <= *range_start),
                "leaf item payloads must not overlap"
            );
            if start != end {
                ranges.push((start, end));
            }
        }
    }

    let internal = parse_internal_items(data);
    assert_eq!(
        internal,
        parse_internal_items(data),
        "internal item parsing must be deterministic"
    );
    if let Ok((header, ptrs)) = &internal {
        assert!(header.level > 0);
        assert!(header.level <= BTRFS_MAX_LEVEL);
        assert_eq!(header.nritems as usize, ptrs.len());
        assert!(BTRFS_HEADER_SIZE + ptrs.len() * BTRFS_KEY_PTR_SIZE <= data.len());
        let mut previous = None;
        for ptr in ptrs {
            if let Some(previous) = previous {
                assert!(
                    previous < key_tuple(ptr.key),
                    "internal item keys must be strictly increasing"
                );
            }
            previous = Some(key_tuple(ptr.key));
            assert!(ptr.blockptr > 0);
        }
    }
}

fn assert_dev_item_invariants(data: &[u8]) {
    let parsed = parse_dev_item(data);
    assert_eq!(
        parsed,
        parse_dev_item(data),
        "DEV_ITEM parsing must be deterministic"
    );

    let Ok(dev_item) = parsed else {
        return;
    };
    assert!(dev_item.devid > 0);
    assert!(dev_item.total_bytes > 0);
    assert!(dev_item.bytes_used <= dev_item.total_bytes);
}

fuzz_target!(|data: &[u8]| {
    assert_superblock_invariants(data);
    assert_sys_chunk_array_invariants(data);
    assert_tree_item_invariants(data);
    assert_dev_item_invariants(data);
});
