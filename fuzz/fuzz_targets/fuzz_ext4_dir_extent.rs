#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz directory block parsing with various block sizes.
    for block_size in [1024, 2048, 4096] {
        let _ = ffs_ondisk::parse_dir_block(data, block_size);
    }

    // Fuzz extent tree parsing from raw inode extent bytes.
    let _ = ffs_ondisk::parse_extent_tree(data);

    // Fuzz dx_root (htree root) parsing.
    let _ = ffs_ondisk::parse_dx_root(data);
});
