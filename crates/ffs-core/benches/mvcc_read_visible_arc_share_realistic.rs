#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Realistic-workload A/B for the bd-xmh5g.394 Arc-backed uncompressed-read lever.
//!
//! `.394` made `VersionData::Full` hold `Arc<AlignedVec>` and added
//! `read_visible_block_buf`, which SHARES that buffer (`Arc::clone`) instead of
//! the materializing `read_visible` (which copies the Full bytes into a fresh
//! `Vec` on every read). The block-level headroom bench isolates one block; this
//! drives the REAL store methods across a 2000-block sequential scan — the common
//! `cat`/large-read pattern — so the batch run can report the lever's aggregate
//! realistic-workload win (N eliminated block copies) vs the reference.
//!
//! `read_visible_vec` is the pre-lever path (materialize+copy per block);
//! `read_visible_block_buf_share` is the lever (refcount bump per block). Both
//! expose identical bytes (asserted before timing).

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ffs_mvcc::MvccStore;
use ffs_types::{BlockNumber, Snapshot};
use std::hint::black_box;

const BLOCKS: u64 = 2_000;
const BLOCK_SIZE: usize = 4096;

fn build_store() -> (MvccStore, Snapshot) {
    let mut store = MvccStore::new(); // defaults to algo: None => uncompressed Full
    for b in 0..BLOCKS {
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(b), vec![(b & 0xff) as u8; BLOCK_SIZE]);
        store.commit(txn).expect("commit");
    }
    let snap = store.current_snapshot();
    (store, snap)
}

fn bench_arc_share(c: &mut Criterion) {
    let (store, snap) = build_store();

    // Behavior guard: the shared read returns the exact seeded bytes (block 0 was
    // written as (0 & 0xff) = 0, i.e. an all-zero block).
    let expected = vec![0_u8; BLOCK_SIZE];
    assert_eq!(
        store
            .read_visible_block_buf(BlockNumber(0), snap)
            .unwrap()
            .as_slice(),
        expected.as_slice(),
        "read_visible_block_buf returned wrong bytes"
    );

    let mut group = c.benchmark_group("mvcc_read_visible_arc_share_2000");
    group.throughput(Throughput::Bytes(BLOCKS * BLOCK_SIZE as u64));

    // Pre-lever: materialize + copy the Full bytes into an owned Vec per block.
    group.bench_function("read_visible_vec", |b| {
        b.iter(|| {
            for blk in 0..BLOCKS {
                black_box(store.read_visible(black_box(BlockNumber(blk)), snap));
            }
        });
    });

    // Lever: share the stored Arc<AlignedVec> per block — no allocation/copy.
    group.bench_function("read_visible_block_buf_share", |b| {
        b.iter(|| {
            for blk in 0..BLOCKS {
                black_box(store.read_visible_block_buf(black_box(BlockNumber(blk)), snap));
            }
        });
    });

    group.finish();
}

criterion_group!(mvcc_read_visible_arc_share_realistic, bench_arc_share);
criterion_main!(mvcc_read_visible_arc_share_realistic);
