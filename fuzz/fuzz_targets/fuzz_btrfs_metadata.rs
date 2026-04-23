#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz btrfs superblock parsing.
    let _ = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(data);
    let _ = ffs_ondisk::verify_btrfs_superblock_checksum(data);

    // Full image parse.
    if data.len() >= 69632 {
        let _ = ffs_ondisk::BtrfsSuperblock::parse_from_image(data);
    }

    // Sys chunk array parsing.
    let _ = ffs_ondisk::parse_sys_chunk_array(data);

    // Leaf and internal node parsing.
    let _ = ffs_ondisk::parse_leaf_items(data);
    let _ = ffs_ondisk::parse_internal_items(data);

    // Dev item parsing.
    let _ = ffs_ondisk::parse_dev_item(data);

    // Header parsing.
    let _ = ffs_ondisk::BtrfsHeader::parse_from_block(data);
    let _ = ffs_ondisk::verify_btrfs_tree_block_checksum(data, ffs_types::BTRFS_CSUM_TYPE_CRC32C);
});
