#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz ext4 superblock parsing from raw bytes.
    let _ = ffs_ondisk::Ext4Superblock::parse_superblock_region(data);

    // If we have enough data, also try parsing as a full image.
    if data.len() >= 2048 {
        let _ = ffs_ondisk::Ext4Superblock::parse_from_image(data);
    }

    // Try parsing as a group descriptor (both 32-byte and 64-byte variants).
    let _ = ffs_ondisk::Ext4GroupDesc::parse_from_bytes(data, 32);
    let _ = ffs_ondisk::Ext4GroupDesc::parse_from_bytes(data, 64);

    // Try parsing as an inode.
    let _ = ffs_ondisk::Ext4Inode::parse_from_bytes(data);
});
