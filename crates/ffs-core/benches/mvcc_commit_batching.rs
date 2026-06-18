#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Bench target for write-back commit batching (bd-xmh5g.401).
//!
//! The FUSE write path commits per write request (one `commit_request_scope` per
//! ~128 KiB write), so a large file write pays a full MVCC commit — SSI
//! validation + WAL append + snapshot bump — thousands of times. Write-back
//! batching accumulates a file handle's writes in one long-lived txn and commits
//! once on fsync/flush. This isolates the headroom: `per_write_commit` does one
//! commit per block; `batched_commit` stages all N blocks in one txn and commits
//! once. The delta is the per-commit overhead the lever amortizes.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ffs_mvcc::MvccStore;
use ffs_types::BlockNumber;
use std::hint::black_box;

const BLOCKS: u64 = 2_000;
const BLOCK_SIZE: usize = 4096;

fn block_data() -> Vec<u8> {
    vec![0xA5_u8; BLOCK_SIZE]
}

/// Current model: a fresh txn + commit for every block (per write request).
fn per_write_commit(data: &[u8]) {
    let mut store = MvccStore::new();
    for b in 0..BLOCKS {
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(b), data.to_vec());
        store.commit(txn).expect("commit");
    }
    black_box(&store);
}

/// Write-back model: stage every block in one txn, commit once.
fn batched_commit(data: &[u8]) {
    let mut store = MvccStore::new();
    let mut txn = store.begin();
    for b in 0..BLOCKS {
        txn.stage_write(BlockNumber(b), data.to_vec());
    }
    store.commit(txn).expect("commit");
    black_box(&store);
}

fn bench_commit_batching(c: &mut Criterion) {
    let data = block_data();

    let mut group = c.benchmark_group("mvcc_commit_batching_2000");
    group.throughput(Throughput::Bytes(BLOCKS * BLOCK_SIZE as u64));

    group.bench_function("per_write_commit", |b| {
        b.iter(|| per_write_commit(black_box(&data)));
    });

    group.bench_function("batched_commit", |b| {
        b.iter(|| batched_commit(black_box(&data)));
    });

    group.finish();
}

criterion_group!(mvcc_commit_batching, bench_commit_batching);
criterion_main!(mvcc_commit_batching);
