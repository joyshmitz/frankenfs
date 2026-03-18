#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz extent tree parsing with malformed nodes.
    let _ = ffs_ondisk::parse_extent_tree(data);

    // Fuzz inode extent tree parsing — requires a parsed inode first.
    if let Ok(inode) = ffs_ondisk::Ext4Inode::parse_from_bytes(data) {
        let _ = ffs_ondisk::parse_inode_extent_tree(&inode);
    }

    // Fuzz dx_root (htree directory root) parsing.
    if data.len() >= 32 {
        let _ = ffs_ondisk::parse_dx_root(data);
    }
});
