#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz all ext4 checksum verification routines with arbitrary data.
    // These are critical for rejecting corrupted on-disk structures without
    // panicking.

    // Group descriptor parsing at both descriptor sizes.
    for desc_size in [32u16, 64] {
        let _ = ffs_ondisk::Ext4GroupDesc::parse_from_bytes(data, desc_size);
    }

    // Superblock-dependent checks.
    if let Ok(sb) = ffs_ondisk::Ext4Superblock::parse_superblock_region(data) {
        let desc_size = sb.group_desc_size();
        let checksum_kind = sb.group_desc_checksum_kind();

        // Inode checksum verification.
        let _ = ffs_ondisk::verify_inode_checksum(data, sb.checksum_seed, 2, 256);

        // Dir block checksum verification.
        let _ = ffs_ondisk::verify_dir_block_checksum(data, sb.checksum_seed, 2, 1);

        // Extent block checksum verification.
        let _ = ffs_ondisk::verify_extent_block_checksum(data, sb.checksum_seed, 11, 1);

        // Group descriptor checksum verification.
        let _ = ffs_ondisk::verify_group_desc_checksum(
            data,
            &sb.uuid,
            sb.checksum_seed,
            0,
            desc_size,
            checksum_kind,
        );
    }

    // Inode parsing then derived operations.
    if let Ok(inode) = ffs_ondisk::Ext4Inode::parse_from_bytes(data) {
        let _ = ffs_ondisk::parse_inode_extent_tree(&inode);
        let _ = ffs_ondisk::parse_ibody_xattrs(&inode);
    }

    // Bitmap checksum value computation (via ext4 module path).
    let _ = ffs_ondisk::ext4::block_bitmap_checksum_value(data, 0, 8192, 64);
    let _ = ffs_ondisk::ext4::inode_bitmap_checksum_value(data, 0, 256, 64);

    // Bitmap free-count verification.
    let _ = ffs_ondisk::ext4::verify_inode_bitmap_free_count(data, 256, 128);
    let _ = ffs_ondisk::ext4::verify_block_bitmap_free_count(data, 8192, 1024);

    // DX hash computation with arbitrary names and seeds.
    if data.len() >= 20 {
        let seed = [0u32; 4];
        for hash_version in [0u8, 1, 2, 3, 4, 5, 255] {
            let _ = ffs_ondisk::dx_hash(hash_version, &data[..16], &seed);
        }
    }

    // Case-insensitive directory lookup.
    for block_size in [1024u32, 4096] {
        let _ = ffs_ondisk::lookup_in_dir_block(data, block_size, b"test_file");
        let _ = ffs_ondisk::lookup_in_dir_block_casefold(data, block_size, b"Test_File");
    }

    // Dir block iteration.
    for block_size in [1024u32, 2048, 4096] {
        for entry in ffs_ondisk::iter_dir_block(data, block_size) {
            let _ = format!("{entry:?}");
        }
    }
});
