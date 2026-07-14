#![forbid(unsafe_code)]

//! Per-commit cost of `MvccStore::preflight_fcw`'s contention-metrics update that
//! only `ConflictPolicy::Adaptive` consumes.
//!
//! On the single-store (journaled / MVCC-WAL) commit path, preflight ran
//! `contention_metrics.record_commit(..)` + `select_policy(..)` on EVERY commit —
//! but under the default fixed policy (SafeMerge) nothing reads the result
//! (`effective_policy` only consults them under Adaptive). The gate skips this
//! when the configured policy is not Adaptive. This benches the exact eliminated
//! work (record_commit + select_policy) vs the gated skip.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_mvcc::{AdaptivePolicyConfig, ContentionMetrics};
use std::hint::black_box;

const N: u64 = 2_000_000;

fn bench_preflight_metrics(c: &mut Criterion) {
    let config = AdaptivePolicyConfig::default();
    let mut group = c.benchmark_group("mvcc_preflight_metrics_per_commit");
    group.sample_size(30);

    // OLD (un-gated): record_commit + select_policy every commit.
    group.bench_function("record_and_select", |b| {
        b.iter(|| {
            let mut m = ContentionMetrics::default();
            for _ in 0..N {
                m.record_commit(black_box(0.1_f64), false, false, false);
                black_box(m.select_policy(&config));
            }
            black_box(&m);
        });
    });

    // NEW (fixed policy): the gate skips it entirely.
    group.bench_function("gated_skip", |b| {
        b.iter(|| {
            let m = ContentionMetrics::default();
            for _ in 0..N {
                black_box(&m);
            }
            black_box(&m);
        });
    });

    group.finish();
}

criterion_group!(preflight_metrics, bench_preflight_metrics);
criterion_main!(preflight_metrics);
