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

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ffs_core::RequestScope;
use ffs_mvcc::{MvccStore, Transaction};
use ffs_types::BlockNumber;
use parking_lot::RwLock;
use std::hint::black_box;

const BLOCKS: u64 = 2_000;
const BLOCK_SIZE: usize = 4096;
const WRITE_SET_COLLECT_BLOCKS: [u64; 3] = [64, 256, 1024];

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

/// Core writeback-batch primitive: caller holds one `RequestScope` transaction.
fn request_scope_batched_commit(data: &[u8]) {
    let store = RwLock::new(MvccStore::new());
    let txn = store.write().begin();
    let mut scope = RequestScope::with_transaction(txn);
    scope.defer_commit_until_flush();
    for b in 0..BLOCKS {
        scope
            .tx
            .as_mut()
            .expect("scope carries transaction")
            .stage_write(BlockNumber(b), data.to_vec());
    }
    black_box(scope.pending_write_count());
    scope.commit_if_write(&store).expect("commit");
    black_box(&store);
}

fn staged_transaction(blocks: u64, data: &[u8]) -> Transaction {
    let mut store = MvccStore::new();
    let mut txn = store.begin();
    for b in 0..blocks {
        txn.stage_write(BlockNumber(b), data.to_vec());
    }
    txn
}

fn always_collect_write_set(txn: &Transaction) -> Vec<BlockNumber> {
    txn.write_set().keys().copied().collect()
}

fn gated_collect_write_set(txn: &Transaction, lifecycle_present: bool) -> Vec<BlockNumber> {
    if lifecycle_present {
        txn.write_set().keys().copied().collect()
    } else {
        Vec::new()
    }
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

    group.bench_function("request_scope_batched_commit", |b| {
        b.iter(|| request_scope_batched_commit(black_box(&data)));
    });

    group.finish();
}

fn bench_writeset_collect(c: &mut Criterion) {
    let data = block_data();
    let mut group = c.benchmark_group("commit_scope_writeset_collect");
    for blocks in WRITE_SET_COLLECT_BLOCKS {
        group.throughput(Throughput::Elements(blocks));

        group.bench_with_input(
            BenchmarkId::new("old_always_collect", blocks),
            &blocks,
            |b, &blocks| {
                b.iter_batched(
                    || staged_transaction(blocks, &data),
                    |txn| black_box(always_collect_write_set(&txn)),
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("new_gated_lifecycle_none", blocks),
            &blocks,
            |b, &blocks| {
                b.iter_batched(
                    || staged_transaction(blocks, &data),
                    |txn| {
                        black_box(gated_collect_write_set(&txn, black_box(false)));
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("new_gated_lifecycle_some", blocks),
            &blocks,
            |b, &blocks| {
                b.iter_batched(
                    || staged_transaction(blocks, &data),
                    |txn| black_box(gated_collect_write_set(&txn, black_box(true))),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    mvcc_commit_batching,
    bench_commit_batching,
    bench_writeset_collect
);
criterion_main!(mvcc_commit_batching);
