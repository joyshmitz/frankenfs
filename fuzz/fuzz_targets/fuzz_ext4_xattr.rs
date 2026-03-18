#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz xattr block parsing.
    let _ = ffs_ondisk::parse_xattr_block(data);

    // Fuzz inode xattr parsing (requires a valid-enough inode).
    if let Ok(inode) = ffs_ondisk::Ext4Inode::parse_from_bytes(data) {
        let _ = ffs_ondisk::parse_ibody_xattrs(&inode);
    }
});
