#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Faithful real-code baseline for the within-shard lock-free-hit lever
//! (bd-xmh5g.382).
//!
//! The A/B model in `extent_cache_same_ns.rs` isolates the lock-acquisition
//! cost with a simplified `Inner`. This bench drives the REAL
//! [`ffs_extent::ExtentCache`] — full `ExtentCacheInner` with the `eviction_index`
//! BTreeSet touch, generation check, and counter bumps — so the measured
//! baseline reflects the production hot path exactly.
//!
//! All threads read ONE namespace, so every lookup lands on one shard and takes
//! that shard's EXCLUSIVE write lock (the hit path touches `last_access` + the
//! eviction index). The 1→8-thread throughput curve quantifies the within-shard
//! contention tax — the headroom the lock-free-hit lever can reclaim. (After
//! ns-sharding (bd-e8us8) this is the residual serialization the sharding cannot
//! reach: N FUSE workers reading one large file.)

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_extent::{ExtentCache, ExtentMapping};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

const ENTRIES: u32 = 256; // resident extents of one inode (all in one shard)
const OPS_PER_THREAD: usize = 20_000;

fn seed() -> ExtentCache {
    let cache = ExtentCache::with_capacity(ENTRIES as usize);
    for i in 0..ENTRIES {
        cache.insert(
            0,
            ExtentMapping {
                logical_start: i,
                physical_start: u64::from(i) * 4096,
                count: 1,
                unwritten: false,
            },
        );
    }
    cache
}

fn run(cache: &ExtentCache, threads: usize) -> u64 {
    let total = AtomicU64::new(0);
    std::thread::scope(|s| {
        for _ in 0..threads {
            let total = &total;
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let lb = (op as u32) % ENTRIES;
                    if let Some(m) = cache.lookup(0, lb) {
                        acc = acc.wrapping_add(m.physical_start);
                    }
                }
                total.fetch_add(acc, Ordering::Relaxed);
            });
        }
    });
    total.load(Ordering::Relaxed)
}

fn bench_cache(c: &mut Criterion) {
    let cache = seed();
    let mut group = c.benchmark_group("extent_cache_real_same_ns");
    for threads in [1_usize, 2, 4, 8] {
        group.bench_function(format!("{threads}t"), |b| {
            b.iter(|| black_box(run(black_box(&cache), threads)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
