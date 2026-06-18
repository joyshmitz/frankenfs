#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Concurrent A/B for lock-striping [`ffs_extent::ExtentCache`] by namespace
//! (bd-e8us8).
//!
//! `ExtentCache::lookup` mutates per-entry LRU state (`last_access`) and the
//! hit/miss counters on EVERY call, so it takes the EXCLUSIVE write lock even
//! for a pure cache hit. The cache is hit on every logical→physical extent
//! mapping — the busiest ext4/btrfs read step — across up to 8 FUSE worker
//! threads, so a single lock serialized every mapping. Routing each namespace
//! (inode) to its own shard lets concurrent reads of different inodes proceed
//! in parallel.
//!
//! This models the exact lookup work (BTreeMap range probe + counter bump +
//! `last_access` touch under the write lock) for the old single-lock design vs
//! the 16-shard design, with 8 threads each reading its own namespace, and
//! asserts identical aggregate hit folds.

use criterion::{Criterion, criterion_group, criterion_main};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const THREADS: usize = 8;
const SHARDS: usize = 16;
const ENTRIES_PER_NS: u32 = 64; // working set per inode
const OPS_PER_THREAD: usize = 30_000;

/// Deterministic seeded mapping value for `(ns, lb)`, independent of access
/// order — so the folded aggregate is identical for the single-lock and
/// sharded designs regardless of thread interleaving.
fn mapping_for(ns: u64, lb: u32) -> u64 {
    ns.wrapping_mul(1_000).wrapping_add(u64::from(lb))
}

/// Minimal stand-in for `ExtentCacheInner`: each entry holds its (immutable)
/// mapping plus a mutable `last_access`. `lookup` bumps the hit counter and
/// refreshes `last_access` — the per-call mutation that forces the production
/// cache to take the WRITE lock even on a pure hit.
#[derive(Default)]
struct Inner {
    entries: BTreeMap<(u64, u32), (u64, u64)>, // (mapping, last_access)
    hits: u64,
}

impl Inner {
    fn seed(ns_count: u64) -> Self {
        let mut inner = Self::default();
        for ns in 0..ns_count {
            for lb in 0..ENTRIES_PER_NS {
                inner.entries.insert((ns, lb), (mapping_for(ns, lb), 0));
            }
        }
        inner
    }

    fn lookup(&mut self, ns: u64, lb: u32) -> Option<u64> {
        self.hits = self.hits.wrapping_add(1);
        let clock = self.hits;
        let entry = self.entries.get_mut(&(ns, lb))?;
        entry.1 = clock; // refresh LRU recency
        Some(entry.0.wrapping_add(u64::from(lb)))
    }
}

fn key(op: usize) -> u32 {
    ((op.wrapping_mul(2_654_435_761)) as u32) % ENTRIES_PER_NS
}

fn run_single(cache: &Arc<RwLock<Inner>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let cache = Arc::clone(cache);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let value = cache.write().lookup(t as u64, key(op));
                    if let Some(v) = value {
                        acc = acc.wrapping_add(v);
                    }
                }
                total.fetch_add(acc, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn run_sharded(shards: &Arc<Vec<RwLock<Inner>>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let shards = Arc::clone(shards);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let ns = t as u64;
                let shard = (ns % SHARDS as u64) as usize;
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let value = shards[shard].write().lookup(ns, key(op));
                    if let Some(v) = value {
                        acc = acc.wrapping_add(v);
                    }
                }
                total.fetch_add(acc, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn build_sharded() -> Vec<RwLock<Inner>> {
    let mut shards: Vec<RwLock<Inner>> =
        (0..SHARDS).map(|_| RwLock::new(Inner::default())).collect();
    for ns in 0..THREADS as u64 {
        let s = (ns % SHARDS as u64) as usize;
        let inner = shards[s].get_mut();
        for lb in 0..ENTRIES_PER_NS {
            inner.entries.insert((ns, lb), (mapping_for(ns, lb), 0));
        }
    }
    shards
}

fn bench_cache(c: &mut Criterion) {
    let single = Arc::new(RwLock::new(Inner::seed(THREADS as u64)));
    let sharded = Arc::new(build_sharded());

    assert_eq!(
        run_single(&single),
        run_sharded(&sharded),
        "sharded extent-cache lookups diverged from single-lock"
    );

    let mut group = c.benchmark_group("extent_cache_concurrent_lookup_8t");
    group.bench_function("single_rwlock", |b| {
        b.iter(|| black_box(run_single(black_box(&single))));
    });
    group.bench_function("sharded_16", |b| {
        b.iter(|| black_box(run_sharded(black_box(&sharded))));
    });
    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
