#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz htree DX root parsing.
    let _ = ffs_ondisk::parse_dx_root(data);

    // Fuzz MMP block parsing.
    let _ = ffs_ondisk::Ext4MmpBlock::parse_from_bytes(data);
});
