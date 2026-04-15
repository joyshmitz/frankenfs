#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz btrfs device item parsing.
    let _ = ffs_ondisk::parse_dev_item(data);
});
