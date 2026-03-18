#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz MVCC store operations with arbitrary sequences of reads and writes.
// Drives begin/write/read/commit/abort against an in-memory MvccStore.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let mut store = ffs_mvcc::MvccStore::new();
    let mut active_txns: Vec<ffs_mvcc::Transaction> = Vec::new();

    for &byte in data {
        match byte % 6 {
            // Begin a new transaction.
            0 => {
                if active_txns.len() < 16 {
                    let txn = store.begin();
                    active_txns.push(txn);
                }
            }
            // Write to a block in the most recent transaction.
            1 => {
                if let Some(txn) = active_txns.last_mut() {
                    let block_id = ffs_types::BlockNumber(u64::from(byte.wrapping_mul(17)));
                    let value = vec![byte; 64];
                    txn.stage_write(block_id, value);
                }
            }
            // Read from a block via the store.
            2 => {
                let snap = store.current_snapshot();
                let block_id = ffs_types::BlockNumber(u64::from(byte.wrapping_mul(13)));
                let _ = store.read_visible(block_id, snap);
            }
            // Commit the oldest transaction.
            3 => {
                if !active_txns.is_empty() {
                    let txn = active_txns.remove(0);
                    let _ = store.commit(txn);
                }
            }
            // Abort (drop) the most recent transaction.
            4 => {
                active_txns.pop();
            }
            // Prune old versions.
            5 => {
                store.prune_safe();
            }
            _ => {}
        }
    }

    // Drop remaining transactions.
    drop(active_txns);
});
