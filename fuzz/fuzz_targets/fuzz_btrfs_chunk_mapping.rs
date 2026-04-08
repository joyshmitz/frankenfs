#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz btrfs chunk mapping: parse sys_chunk_array then use it for
    // logical-to-physical address translation with arbitrary logical addresses.
    if let Ok(chunks) = ffs_ondisk::parse_sys_chunk_array(data) {
        // Try mapping various logical addresses through the parsed chunks.
        for offset in [0u64, 4096, 65536, 1 << 20, 1 << 30, u64::MAX] {
            let _ = ffs_ondisk::map_logical_to_physical(&chunks, offset);
            let _ = ffs_ondisk::map_logical_to_stripes(&chunks, offset);
        }
        // Also derive a logical address from the fuzzer input for better coverage.
        if data.len() >= 8 {
            let fuzz_logical = u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            let _ = ffs_ondisk::map_logical_to_physical(&chunks, fuzz_logical);
            let _ = ffs_ondisk::map_logical_to_stripes(&chunks, fuzz_logical);
        }
    }

    // Fuzz superblock checksum verification on arbitrary data.
    let _ = ffs_ondisk::verify_btrfs_superblock_checksum(data);

    // Fuzz tree block checksum verification with various checksum types.
    for csum_type in [0u16, 1, 2, 3, 255] {
        let _ = ffs_ondisk::verify_btrfs_tree_block_checksum(data, csum_type);
    }

    // Fuzz leaf item parsing then exercise parsed items to ensure no panic
    // on valid-header-but-truncated-payload scenarios.
    if let Ok((_header, items)) = ffs_ondisk::parse_leaf_items(data) {
        for item in &items {
            let _ = format!("{item:?}");
        }
    }

    // Fuzz internal (non-leaf) node parsing.
    if let Ok((_header, key_ptrs)) = ffs_ondisk::parse_internal_items(data) {
        for kp in &key_ptrs {
            let _ = format!("{kp:?}");
        }
    }

    // Dev item parsing.
    let _ = ffs_ondisk::parse_dev_item(data);

    // Header parsing.
    let _ = ffs_ondisk::BtrfsHeader::parse_from_block(data);
});
