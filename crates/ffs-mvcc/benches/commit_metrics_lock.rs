#![forbid(unsafe_code)]

//! Parallel-commit A/B for the per-commit contention-metrics global lock.
//!
//! Under a fixed conflict policy (production default = `SafeMerge`; ffs-core
//! never switches to `Adaptive`) nothing reads the contention metrics, yet the
//! commit success path used to take `contention_metrics.write()` — a single
//! GLOBAL lock — on EVERY commit. That serializes otherwise-disjoint parallel
//! commits (different blocks, different shards) on one lock. The gate skips it
//! unless the policy is `Adaptive`.
//!
//! This benches N threads each committing `PER_THREAD` single-block txns to its
//! own disjoint block range (no shard-lock and no MVCC conflicts, so the metrics
//! lock is the only cross-thread serialization that differs between arms). Arm A
//! (`force_metrics_on`) reproduces the pre-gate behavior via the bench hook; arm
//! B (`gated_off`) is production. Same binary, same commit path — only the
//! metrics lock differs.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_types::BlockNumber;
use std::hint::black_box;
use std::sync::Arc;

const PER_THREAD: u64 = 2000;

fn parallel_commit_batch(threads: usize, force_metrics: bool) {
    let store = Arc::new(ShardedMvccStore::for_host_parallelism());
    store.set_force_metrics_record(force_metrics);
    std::thread::scope(|scope| {
        for t in 0..threads {
            let store = Arc::clone(&store);
            scope.spawn(move || {
                // Disjoint block range per thread => no same-block conflicts.
                let base = (t as u64) * PER_THREAD * 2;
                for i in 0..PER_THREAD {
                    let mut txn = store.begin();
                    txn.stage_write(BlockNumber(base + i), vec![0_u8; 64]);
                    let _ = store.commit(txn);
                }
            });
        }
    });
    black_box(&store);
}

fn bench_commit_metrics_lock(c: &mut Criterion) {
    let mut group = c.benchmark_group("mvcc_commit_metrics_lock");
    group.sample_size(20);
    for threads in [2_usize, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("force_metrics_on", threads),
            &threads,
            |b, &threads| b.iter(|| parallel_commit_batch(threads, true)),
        );
        group.bench_with_input(
            BenchmarkId::new("gated_off", threads),
            &threads,
            |b, &threads| b.iter(|| parallel_commit_batch(threads, false)),
        );
    }
    group.finish();
}

criterion_group!(commit_metrics_lock, bench_commit_metrics_lock);
criterion_main!(commit_metrics_lock);
