#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::type_complexity)]

//! Concurrent A/B for lock-striping the read-only btrfs parsed-node cache
//! (bd-tag2s): `Mutex<BTreeMap<u64, Arc<_>>>` vs a 16-shard `[Mutex<BTreeMap>]`.
//!
//! `OpenFs::btrfs_parsed_node_cache` is hit on every btrfs tree-node read on a
//! read-only mount (`btrfs_read_parsed_node`): a hit clones the cached
//! `Arc<BtrfsParsedNode>` and skips the device read + checksum verify + parse.
//! FUSE dispatches concurrent requests from up to 8 worker threads, so the
//! single exclusive `Mutex` serializes every concurrent hit even though a hit
//! only reads the map and clones an `Arc`. Lock striping maps each key to one
//! of 16 independent shards, so concurrent gets on distinct keys never contend.
//!
//! This bench runs 8 threads doing `get(&key)` lookups (BTreeMap descent + Arc
//! clone — the real hit work) over a populated cache under the old single
//! `Mutex` vs the new 16-shard striping, and asserts identical aggregates.
//! Threads spread their keys so the benefit reflects independent lookups.

use criterion::{Criterion, criterion_group, criterion_main};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;

const ENTRIES: usize = 8_192; // cached nodes
const THREADS: usize = 8; // FUSE worker threads
const OPS_PER_THREAD: usize = 12_000;
const NODE: usize = 4096; // parsed-node payload proxy
const SHARDS: usize = 16;

fn build_one() -> BTreeMap<u64, Arc<[u8]>> {
    (0..ENTRIES as u64)
        .map(|i| {
            let mut v = vec![0_u8; NODE];
            v[0] = i as u8;
            v[NODE - 1] = (i >> 8) as u8;
            (i, Arc::<[u8]>::from(v))
        })
        .collect()
}

fn key_for(thread: usize, op: usize) -> u64 {
    let base = (thread * (ENTRIES / THREADS)) as u64;
    base.wrapping_add((op as u64).wrapping_mul(7)) % (ENTRIES as u64)
}

fn fold(b: &Arc<[u8]>) -> u64 {
    u64::from(b[0]) + u64::from(b[NODE - 1])
}

fn run_mutex(cache: &Arc<Mutex<BTreeMap<u64, Arc<[u8]>>>>) -> u64 {
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

fn run_sharded(shards: &Arc<Vec<Mutex<BTreeMap<u64, Arc<[u8]>>>>>) -> u64 {
    let total = Arc::new(std::sync::atomic::AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let shards = Arc::clone(shards);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let k = key_for(t, op);
                    let hit = shards[(k as usize) % SHARDS].lock().get(&k).cloned();
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

fn build_sharded() -> Vec<Mutex<BTreeMap<u64, Arc<[u8]>>>> {
    let shards: Vec<Mutex<BTreeMap<u64, Arc<[u8]>>>> =
        (0..SHARDS).map(|_| Mutex::new(BTreeMap::new())).collect();
    for (k, v) in build_one() {
        shards[(k as usize) % SHARDS].lock().insert(k, v);
    }
    shards
}

fn bench_cache(c: &mut Criterion) {
    let mutex_cache = Arc::new(Mutex::new(build_one()));
    let sharded_cache = Arc::new(build_sharded());

    assert_eq!(
        run_mutex(&mutex_cache),
        run_sharded(&sharded_cache),
        "sharded cache readers diverged from mutex readers"
    );

    let mut group = c.benchmark_group("parsed_node_cache_concurrent_get_8t");
    group.bench_function("mutex_exclusive", |b| {
        b.iter(|| black_box(run_mutex(black_box(&mutex_cache))));
    });
    group.bench_function("sharded_mutex_16", |b| {
        b.iter(|| black_box(run_sharded(black_box(&sharded_cache))));
    });
    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
