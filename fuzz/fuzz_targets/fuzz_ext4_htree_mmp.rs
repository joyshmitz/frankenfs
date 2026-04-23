#![no_main]
use ffs_ondisk::ext4::parse_dx_root_with_large_dir;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz htree DX root parsing in both normal and large_dir modes.
    let normal = ffs_ondisk::parse_dx_root(data);
    let large_dir = parse_dx_root_with_large_dir(data, true);

    if normal.is_ok() && large_dir.is_err() {
        std::process::abort();
    }

    if let Ok(root) = &large_dir {
        if root.indirect_levels <= 2 && normal.is_err() {
            std::process::abort();
        }
    }

    // Fuzz MMP block parsing.
    let _ = ffs_ondisk::Ext4MmpBlock::parse_from_bytes(data);
});
