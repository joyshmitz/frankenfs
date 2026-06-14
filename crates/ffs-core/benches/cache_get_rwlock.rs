#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Concurrent A/B for the ext4 read-only file-data block cache (bd-tag2s).
//!
//! `OpenFs::ext4_file_data_block_cache` is hit on cached ext4 file and
//! directory block reads. FUSE dispatches concurrent requests from multiple
//! worker threads, so the old exclusive `Mutex` serialized cache hits even
//! though a hit only reads the map and clones an `Arc`. This benchmark runs
//! eight threads through the real hit work (`BTreeMap::get` + `Arc::clone`)
//! and asserts identical aggregates for the old `Mutex` and candidate
//! `RwLock` implementations.

use criterion::{Criterion, criterion_group, criterion_main};
use parking_lot::{Mutex, RwLock};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;

const ENTRIES: usize = 8_192;
const THREADS: usize = 8;
const OPS_PER_THREAD: usize = 12_000;
const BLOCK: usize = 4096;

type CacheMap = BTreeMap<u64, Arc<[u8]>>;
type MutexCache = Arc<Mutex<CacheMap>>;
type RwLockCache = Arc<RwLock<CacheMap>>;

fn build() -> CacheMap {
    (0..ENTRIES as u64)
        .map(|i| {
            let mut v = vec![0_u8; BLOCK];
            v[0] = i as u8;
            v[BLOCK - 1] = (i >> 8) as u8;
            (i, Arc::<[u8]>::from(v))
        })
        .collect()
}

fn key_for(thread: usize, op: usize) -> u64 {
    let base = (thread * (ENTRIES / THREADS)) as u64;
    base.wrapping_add((op as u64).wrapping_mul(7)) % (ENTRIES as u64)
}

fn fold(b: &Arc<[u8]>) -> u64 {
    u64::from(b[0]) + u64::from(b[BLOCK - 1])
}

fn run_mutex(cache: &MutexCache) -> u64 {
    let total = Arc::new(std::sync::atomic::AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let cache = Arc::clone(cache);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let hit = cache.lock().get(&key_for(t, op)).cloned();
                    if let Some(b) = hit {
                        acc = acc.wrapping_add(fold(&b));
                    }
                }
                total.fetch_add(acc, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    total.load(std::sync::atomic::Ordering::Relaxed)
}

fn run_rwlock(cache: &RwLockCache) -> u64 {
    let total = Arc::new(std::sync::atomic::AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let cache = Arc::clone(cache);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let hit = cache.read().get(&key_for(t, op)).cloned();
                    if let Some(b) = hit {
                        acc = acc.wrapping_add(fold(&b));
                    }
                }
                total.fetch_add(acc, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
    total.load(std::sync::atomic::Ordering::Relaxed)
}

fn bench_cache(c: &mut Criterion) {
    let mutex_cache = Arc::new(Mutex::new(build()));
    let rwlock_cache = Arc::new(RwLock::new(build()));

    let baseline = run_mutex(&mutex_cache);
    assert_eq!(baseline, run_rwlock(&rwlock_cache), "rwlock diverged");

    let mut group = c.benchmark_group("cache_concurrent_get_8t");
    group.bench_function("mutex_exclusive", |b| {
        b.iter(|| black_box(run_mutex(black_box(&mutex_cache))));
    });
    group.bench_function("rwlock_shared", |b| {
        b.iter(|| black_box(run_rwlock(black_box(&rwlock_cache))));
    });
    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
