use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_types::{BlockNumber, Snapshot};
use std::sync::Arc;
use std::thread;

#[test]
fn test_sharded_visibility_race() {
    let store = Arc::new(ShardedMvccStore::new(4)); // multiple shards

    let store_writer = Arc::clone(&store);

    // Writer thread
    let writer = thread::spawn(move || {
        for i in 0..5000 {
            let mut txn = store_writer.begin();
            for b in 0..100 {
                txn.stage_write(BlockNumber(b), vec![i as u8; 4096]);
            }
            store_writer.commit(txn).unwrap();
        }
    });

    // Reader thread
    let store_reader = Arc::clone(&store);
    let reader = thread::spawn(move || {
        for _ in 0..1000000 {
            let snap = store_reader.current_snapshot();
            if snap.high.0 > 0 {
                // If we have a snapshot, check a random block from the write set
                let b = snap.high.0 % 100;
                let data = store_reader.read_visible(BlockNumber(b), snap);
                if data.is_none() {
                    panic!(
                        "Visibility race detected! Snapshot {:?} but no data for block {:?}",
                        snap, b
                    );
                }
            }
        }
    });

    writer.join().unwrap();
    reader.join().unwrap();
}
