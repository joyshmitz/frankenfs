#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz WAL header decoding.
    let _ = ffs_mvcc::wal::decode_header(data);

    // Fuzz WAL commit decoding.
    let _ = ffs_mvcc::wal::decode_commit(data);

    // Fuzz commit byte size detection (used for framing).
    let _ = ffs_mvcc::wal::commit_byte_size(data);
});
