#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Criterion benchmark for `ShardedMvccStore::read_visible` over a deep version
//! chain read at an old snapshot.
//!
//! When a long-running reader holds the GC watermark down, a hot block's version
//! chain cannot be trimmed and grows large. Reading at an old snapshot whose
//! visible version sits near the front of the (ascending `commit_seq`) chain is
//! the pathological case: the prior reverse linear scan walked past every newer
//! version on each read. This bench builds that scenario directly.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_types::{BlockNumber, CommitSeq, Snapshot};
use std::hint::black_box;

const CHAIN: u64 = 512;
const BLOCK: BlockNumber = BlockNumber(7);

fn build_store() -> ShardedMvccStore {
    let store = ShardedMvccStore::new(8);
    for i in 0..CHAIN {
        let mut txn = store.begin();
        txn.stage_write(BLOCK, vec![(i & 0xff) as u8; 8]);
        store.commit(txn).expect("commit");
    }
    store
}

fn bench_read_visible_deep_chain(c: &mut Criterion) {
    let store = build_store();
    // Old snapshot: the visible version sits near the front of the 512-deep
    // chain, so the prior reverse linear scan walked past ~507 newer versions.
    let old_snap = Snapshot { high: CommitSeq(5) };
    assert!(store.read_visible(BLOCK, old_snap).is_some());

    c.bench_function("mvcc_read_visible_oldsnapshot_chain512", |b| {
        b.iter(|| black_box(store.read_visible(black_box(BLOCK), Snapshot { high: CommitSeq(5) })));
    });
}

criterion_group!(read_visible, bench_read_visible_deep_chain);
criterion_main!(read_visible);
