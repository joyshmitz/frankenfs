#![forbid(unsafe_code)]

//! False-sharing cost of the redundant `any_version_installed` store on the
//! sharded commit path.
//!
//! `any_version_installed` is a MONOTONIC flag (false→true once, never clears)
//! that EVERY read loads to decide whether to probe the MVCC overlay. The commit
//! install loop used to `store(true, Release)` it per committed block — redundant
//! after the first-ever install, and each store dirties the flag's cache line,
//! invalidating the copy every concurrent reader caches. The fix guards the store
//! with a relaxed load so it fires only on the false→true transition.
//!
//! This models the effect: N committer threads either STORE the (already-true)
//! flag (old) or GUARDED-LOAD it (new, a no-op after warmup), while R reader
//! threads load it — all doing the same fixed iteration count. It isolates the
//! committer↔reader false sharing, not the full commit cost (production stores at
//! most once per commit, so this overstates the tight-loop magnitude while showing
//! the direction).

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const ITERS: u64 = 2_000_000;
const READERS: usize = 4;

fn run(committers: usize, guarded: bool) {
    let flag = Arc::new(AtomicBool::new(true)); // warmed-up: already installed
    std::thread::scope(|scope| {
        // Committer threads: mirror the commit hot path's flag handling.
        for _ in 0..committers {
            let flag = Arc::clone(&flag);
            scope.spawn(move || {
                for _ in 0..ITERS {
                    if guarded {
                        // New: relaxed load guards the store → no store after warmup.
                        if !flag.load(Ordering::Relaxed) {
                            flag.store(true, Ordering::Release);
                        }
                    } else {
                        // Old: unconditional Release store (dirties the line).
                        flag.store(true, Ordering::Release);
                    }
                }
            });
        }
        // Reader threads: every read loads the flag (read fast-path gate).
        for _ in 0..READERS {
            let flag = Arc::clone(&flag);
            scope.spawn(move || {
                for _ in 0..ITERS {
                    black_box(flag.load(Ordering::Acquire));
                }
            });
        }
    });
    black_box(&flag);
}

fn bench_false_sharing(c: &mut Criterion) {
    let mut group = c.benchmark_group("mvcc_any_version_flag_false_sharing");
    group.sample_size(20);
    for committers in [1_usize, 2, 4] {
        group.bench_with_input(
            BenchmarkId::new("unguarded_store", committers),
            &committers,
            |b, &n| b.iter(|| run(n, false)),
        );
        group.bench_with_input(
            BenchmarkId::new("guarded_load", committers),
            &committers,
            |b, &n| b.iter(|| run(n, true)),
        );
    }
    group.finish();
}

criterion_group!(any_version_flag_false_sharing, bench_false_sharing);
criterion_main!(any_version_flag_false_sharing);
