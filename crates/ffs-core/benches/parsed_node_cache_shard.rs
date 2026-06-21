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
//! `Mutex`, the old low-bit sharder, and the mixed sharder. Keys are btrfs-like
//! aligned logical node addresses, so the low-bit sharder collapses to shard 0;
//! the mixed sharder is the production bd-xmh5g.422 fix.

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
const BTRFS_NODE_ALIGN: u64 = 16_384;

fn build_one() -> BTreeMap<u64, Arc<[u8]>> {
    (0..ENTRIES)
        .map(|i| {
            let mut v = vec![0_u8; NODE];
            v[0] = i as u8;
            v[NODE - 1] = (i >> 8) as u8;
            (logical_key(i), Arc::<[u8]>::from(v))
        })
        .collect()
}

fn logical_key(idx: usize) -> u64 {
    (idx as u64) * BTRFS_NODE_ALIGN
}

fn key_for(thread: usize, op: usize) -> u64 {
    let base = thread * (ENTRIES / THREADS);
    let idx = base.wrapping_add(op.wrapping_mul(7)) % ENTRIES;
    logical_key(idx)
}

fn low_bits_shard(key: u64) -> usize {
    (key as usize & 0xFFF) % SHARDS
}

fn mixed_shard(key: u64) -> usize {
    const FIBONACCI_MIX: u64 = 0x9E37_79B9_7F4A_7C15;
    usize::try_from(key.wrapping_mul(FIBONACCI_MIX) >> 32).unwrap_or(0) % SHARDS
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

fn run_sharded(
    shards: &Arc<Vec<Mutex<BTreeMap<u64, Arc<[u8]>>>>>,
    shard_for: fn(u64) -> usize,
) -> u64 {
    let total = Arc::new(std::sync::atomic::AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let shards = Arc::clone(shards);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let k = key_for(t, op);
                    let hit = shards[shard_for(k)].lock().get(&k).cloned();
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

fn build_sharded(shard_for: fn(u64) -> usize) -> Vec<Mutex<BTreeMap<u64, Arc<[u8]>>>> {
    let shards: Vec<Mutex<BTreeMap<u64, Arc<[u8]>>>> =
        (0..SHARDS).map(|_| Mutex::new(BTreeMap::new())).collect();
    for (k, v) in build_one() {
        shards[shard_for(k)].lock().insert(k, v);
    }
    shards
}

fn bench_cache(c: &mut Criterion) {
    let mutex_cache = Arc::new(Mutex::new(build_one()));
    let low_bits_cache = Arc::new(build_sharded(low_bits_shard));
    let mixed_cache = Arc::new(build_sharded(mixed_shard));

    let mutex_total = run_mutex(&mutex_cache);
    assert_eq!(
        mutex_total,
        run_sharded(&low_bits_cache, low_bits_shard),
        "low-bit sharded cache readers diverged from mutex readers"
    );
    assert_eq!(
        mutex_total,
        run_sharded(&mixed_cache, mixed_shard),
        "mixed sharded cache readers diverged from mutex readers"
    );

    let mut group = c.benchmark_group("parsed_node_cache_concurrent_get_8t");
    group.bench_function("mutex_exclusive", |b| {
        b.iter(|| black_box(run_mutex(black_box(&mutex_cache))));
    });
    group.bench_function("sharded_low_bits_16_aligned", |b| {
        b.iter(|| black_box(run_sharded(black_box(&low_bits_cache), low_bits_shard)));
    });
    group.bench_function("sharded_mixed_16_aligned", |b| {
        b.iter(|| black_box(run_sharded(black_box(&mixed_cache), mixed_shard)));
    });
    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
