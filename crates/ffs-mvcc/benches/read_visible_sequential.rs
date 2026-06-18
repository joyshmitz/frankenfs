#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Realistic-workload read bench: a SEQUENTIAL scan over many distinct blocks,
//! each with a shallow version chain, read at the latest snapshot.
//!
//! The existing `read_visible` bench is the PATHOLOGICAL case (one block, a
//! 512-deep chain, read at an old snapshot). This is the COMMON case: a large
//! sequential read touches thousands of distinct blocks once each, at HEAD. It
//! exercises the integrated per-block read cost — the version-store lookup
//! (`newest_visible_index`) PLUS `into_owned()` on the resolved `Cow` (the
//! uncompressed clone that the Arc-backed-read lever bd-xmh5g.394 targets) — so
//! the batch run can quantify realistic read throughput vs the reference, the
//! top-line "beat the original on realistic workloads" metric, and see the
//! aggregate weight of the clone the lever would remove.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_types::{BlockNumber, CommitSeq, Snapshot};
use std::hint::black_box;

const BLOCKS: u64 = 2_000;
const BLOCK_SIZE: usize = 4096;

fn build_store() -> (ShardedMvccStore, CommitSeq) {
    let store = ShardedMvccStore::new(8);
    let mut last = CommitSeq(0);
    for b in 0..BLOCKS {
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(b), vec![(b & 0xff) as u8; BLOCK_SIZE]);
        last = store.commit(txn).expect("commit");
    }
    (store, last)
}

fn bench_sequential_scan(c: &mut Criterion) {
    let (store, latest) = build_store();
    let snap = Snapshot { high: latest };
    assert!(store.read_visible(BlockNumber(0), snap).is_some());
    assert!(store.read_visible(BlockNumber(BLOCKS - 1), snap).is_some());

    let mut group = c.benchmark_group("mvcc_read_visible_sequential");
    group.throughput(Throughput::Bytes(BLOCKS * BLOCK_SIZE as u64));
    group.bench_function("scan_2000_blocks", |b| {
        b.iter(|| {
            for blk in 0..BLOCKS {
                // The sharded read_visible resolves the visible version AND
                // materializes it into an owned Vec — the per-block lookup +
                // block-sized copy that the Arc-backed-read lever bd-xmh5g.394
                // would replace with a shared Arc on the uncompressed path.
                let data = store.read_visible(black_box(BlockNumber(blk)), snap);
                black_box(data);
            }
        });
    });
    group.finish();
}

criterion_group!(read_visible_sequential, bench_sequential_scan);
criterion_main!(read_visible_sequential);
