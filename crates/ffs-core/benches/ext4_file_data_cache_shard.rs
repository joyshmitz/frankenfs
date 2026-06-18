#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::type_complexity)]

//! Concurrent A/B for lock-striping the ext4 read-only file-data block cache
//! (bd-tag2s sibling): the production cache was a single
//! `RwLock<BTreeMap<BlockNumber, Arc<[u8]>>>`; this models converting it to the
//! 16-shard `ShardedCache` (a `[Mutex<BTreeMap>]` + atomic length).
//!
//! `OpenFs::read_ext4_file_data_block_with_scope` is the hot ext4 read path for
//! BOTH file-data blocks and directory blocks: it `get`s the block from this
//! cache and, on a miss, reads the device and inserts — but only while the
//! cache is below its `EXT4_FILE_DATA_BLOCK_CACHE_LIMIT` (256 blocks ~= 1 MiB).
//!
//! The single-`RwLock` design has a sharp cost the pure-read sharding benches
//! miss: the old miss path takes the EXCLUSIVE write lock UNCONDITIONALLY and
//! only then checks `len < cap`, so once the small cache is full (the steady
//! state for any working set > 1 MiB) EVERY cold read exclusively locks the
//! whole cache just to refuse the insert — serializing all 8 FUSE worker
//! threads' reads behind it. `ShardedCache::insert_within` instead does a
//! lock-free atomic length load first and returns without locking when full,
//! and otherwise locks only 1/16 of the cache.
//!
//! This runs 8 threads through the real get-then-insert-on-miss flow over a
//! FULL cache with a mix of warm hits and cold misses, and asserts identical
//! hit aggregates between the two designs.

use criterion::{Criterion, criterion_group, criterion_main};
use parking_lot::{Mutex, RwLock};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const CAP: usize = 256; // EXT4_FILE_DATA_BLOCK_CACHE_LIMIT
const THREADS: usize = 8; // FUSE worker threads
const OPS_PER_THREAD: usize = 20_000;
const BLOCK: usize = 4096; // ext4 block payload proxy
const SHARDS: usize = 16;
/// Distinct keys touched per thread; half land in the warm [0,CAP) hit set,
/// half are cold misses beyond the cache that exercise the (refused) insert.
const KEY_SPAN: u64 = (CAP as u64) * 2;

fn make_block(k: u64) -> Arc<[u8]> {
    let mut v = vec![0_u8; BLOCK];
    v[0] = k as u8;
    v[BLOCK - 1] = (k >> 8) as u8;
    Arc::<[u8]>::from(v)
}

fn fold(b: &Arc<[u8]>) -> u64 {
    u64::from(b[0]) + u64::from(b[BLOCK - 1])
}

fn key_for(thread: usize, op: usize) -> u64 {
    let base = (thread as u64).wrapping_mul(37);
    base.wrapping_add((op as u64).wrapping_mul(7)) % KEY_SPAN
}

// ── Old design: single RwLock<BTreeMap> ─────────────────────────────────────

fn build_rwlock() -> Arc<RwLock<BTreeMap<u64, Arc<[u8]>>>> {
    let mut map = BTreeMap::new();
    for k in 0..CAP as u64 {
        map.insert(k, make_block(k));
    }
    Arc::new(RwLock::new(map))
}

fn run_rwlock(cache: &Arc<RwLock<BTreeMap<u64, Arc<[u8]>>>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let cache = Arc::clone(cache);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let k = key_for(t, op);
                    let hit = cache.read().get(&k).cloned();
                    if let Some(b) = hit {
                        acc = acc.wrapping_add(fold(&b));
                    } else {
                        let v = make_block(k);
                        let mut map = cache.write();
                        if map.len() < CAP {
                            map.insert(k, v);
                        }
                    }
                }
                total.fetch_add(acc, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

// ── New design: 16-shard ShardedCache (Mutex shards + atomic len) ────────────

struct Sharded {
    shards: Vec<Mutex<BTreeMap<u64, Arc<[u8]>>>>,
    len: AtomicUsize,
}

impl Sharded {
    fn build() -> Arc<Self> {
        let shards: Vec<_> = (0..SHARDS).map(|_| Mutex::new(BTreeMap::new())).collect();
        let len = AtomicUsize::new(0);
        for k in 0..CAP as u64 {
            if shards[(k as usize) % SHARDS]
                .lock()
                .insert(k, make_block(k))
                .is_none()
            {
                len.fetch_add(1, Ordering::Relaxed);
            }
        }
        Arc::new(Self { shards, len })
    }

    fn get(&self, k: u64) -> Option<Arc<[u8]>> {
        self.shards[(k as usize) % SHARDS].lock().get(&k).cloned()
    }

    fn insert_within(&self, k: u64, v: Arc<[u8]>, limit: usize) {
        if self.len.load(Ordering::Relaxed) >= limit {
            return;
        }
        if self.shards[(k as usize) % SHARDS]
            .lock()
            .insert(k, v)
            .is_none()
        {
            self.len.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn run_sharded(cache: &Arc<Sharded>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|s| {
        for t in 0..THREADS {
            let cache = Arc::clone(cache);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let k = key_for(t, op);
                    if let Some(b) = cache.get(k) {
                        acc = acc.wrapping_add(fold(&b));
                    } else {
                        cache.insert_within(k, make_block(k), CAP);
                    }
                }
                total.fetch_add(acc, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn bench_cache(c: &mut Criterion) {
    let rwlock_cache = build_rwlock();
    let sharded_cache = Sharded::build();

    assert_eq!(
        run_rwlock(&rwlock_cache),
        run_sharded(&sharded_cache),
        "sharded cache readers diverged from rwlock readers"
    );

    let mut group = c.benchmark_group("ext4_file_data_cache_concurrent_8t");
    group.bench_function("rwlock_single", |b| {
        b.iter(|| black_box(run_rwlock(black_box(&rwlock_cache))));
    });
    group.bench_function("sharded_mutex_16", |b| {
        b.iter(|| black_box(run_sharded(black_box(&sharded_cache))));
    });
    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
