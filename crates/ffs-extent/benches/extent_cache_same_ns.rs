#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Within-shard A/B for the [`ffs_extent::ExtentCache`] hot-hit path
//! (bd-xmh5g.382).
//!
//! ns-sharding (bd-e8us8) routes each inode to its own shard, so readers of
//! DIFFERENT inodes run in parallel. But `lookup` still takes the EXCLUSIVE
//! per-shard write lock on every call — even a pure cache hit — because it
//! bumps the hit/miss counters and refreshes the entry's `last_access` LRU
//! clock. So N FUSE worker threads reading the SAME inode (the realistic
//! parallel read of one large file) all land on one shard and serialize on
//! that shard's write lock; the sharding cannot help this case.
//!
//! This models the exact same-namespace hot-hit work for two designs:
//!   * `write_lock_hit`  — the current design: hit path takes `.write()` and
//!     mutates `last_access` + `hits` in place.
//!   * `read_lock_atomic_hit` — the first proposed lever: per-entry
//!     `last_access` and the counters are atomics, so the hit path takes a
//!     SHARED `.read()` and touches them lock-free.
//!   * `read_lock_striped_atomic_hit` — the repaired lever after the first RCH
//!     run showed the single `hits` atomic became the new cache-line bottleneck.
//!
//! Both produce the identical aggregate fold (the returned mapping is a pure
//! function of the key, independent of access order), asserted before timing —
//! the conformance guard that the lock-free hit is behavior-preserving.

use criterion::{Criterion, criterion_group, criterion_main};
use parking_lot::RwLock;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const THREADS: usize = 8;
const ENTRIES: u32 = 64; // working set of one inode (all in one shard)
const OPS_PER_THREAD: usize = 30_000;
const COUNTER_STRIPES: usize = 64;
const UNASSIGNED_STRIPE: usize = usize::MAX;

static NEXT_COUNTER_STRIPE: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static COUNTER_STRIPE: Cell<usize> = const { Cell::new(UNASSIGNED_STRIPE) };
}

/// Deterministic mapping value for a logical block, independent of access
/// order so the folded aggregate is identical for both designs.
fn mapping_for(lb: u32) -> u64 {
    u64::from(lb).wrapping_mul(1_000)
}

fn key(op: usize) -> u32 {
    ((op.wrapping_mul(2_654_435_761)) as u32) % ENTRIES
}

fn counter_stripe() -> usize {
    COUNTER_STRIPE.with(|slot| {
        let existing = slot.get();
        if existing != UNASSIGNED_STRIPE {
            return existing;
        }
        let assigned = NEXT_COUNTER_STRIPE.fetch_add(1, Ordering::Relaxed) % COUNTER_STRIPES;
        slot.set(assigned);
        assigned
    })
}

/// Current design: the hit path mutates `last_access` + `hits`, so it must be
/// reached under the EXCLUSIVE write lock.
struct WriteInner {
    entries: BTreeMap<u32, (u64, u64)>, // (mapping, last_access)
    hits: u64,
}

impl WriteInner {
    fn seed() -> Self {
        let mut entries = BTreeMap::new();
        for lb in 0..ENTRIES {
            entries.insert(lb, (mapping_for(lb), 0));
        }
        Self { entries, hits: 0 }
    }

    fn lookup(&mut self, lb: u32) -> Option<u64> {
        self.hits = self.hits.wrapping_add(1);
        let clock = self.hits;
        let entry = self.entries.get_mut(&lb)?;
        entry.1 = clock; // refresh LRU recency
        Some(entry.0.wrapping_add(u64::from(lb)))
    }
}

/// Lever: `last_access` + `hits` are atomics, so a pure hit only needs a
/// SHARED read lock; same-inode hits proceed concurrently.
struct ReadInner {
    entries: BTreeMap<u32, (u64, AtomicU64)>, // (mapping, last_access)
    hits: AtomicU64,
}

#[repr(align(128))]
struct Stripe {
    value: AtomicU64,
}

impl Stripe {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }
}

/// Repaired lever: same shared read lock and atomic per-entry recency, but the
/// hot hit counter is striped so 8 readers do not fight over one cache line.
struct StripedReadInner {
    entries: BTreeMap<u32, (u64, AtomicU64)>, // (mapping, last_access)
    hits: Box<[Stripe]>,
}

impl StripedReadInner {
    fn seed() -> Self {
        let mut entries = BTreeMap::new();
        for lb in 0..ENTRIES {
            entries.insert(lb, (mapping_for(lb), AtomicU64::new(0)));
        }
        Self {
            entries,
            hits: (0..COUNTER_STRIPES).map(|_| Stripe::new()).collect(),
        }
    }

    fn lookup(&self, lb: u32) -> Option<u64> {
        let stripe = counter_stripe();
        let clock = self.hits[stripe]
            .value
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .saturating_mul(u64::try_from(COUNTER_STRIPES).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(stripe).unwrap_or(u64::MAX));
        let entry = self.entries.get(&lb)?;
        entry.1.store(clock, Ordering::Relaxed); // lock-free LRU touch
        Some(entry.0.wrapping_add(u64::from(lb)))
    }
}

impl ReadInner {
    fn seed() -> Self {
        let mut entries = BTreeMap::new();
        for lb in 0..ENTRIES {
            entries.insert(lb, (mapping_for(lb), AtomicU64::new(0)));
        }
        Self {
            entries,
            hits: AtomicU64::new(0),
        }
    }

    fn lookup(&self, lb: u32) -> Option<u64> {
        let clock = self.hits.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let entry = self.entries.get(&lb)?;
        entry.1.store(clock, Ordering::Relaxed); // lock-free LRU touch
        Some(entry.0.wrapping_add(u64::from(lb)))
    }
}

fn run_write(cache: &Arc<RwLock<WriteInner>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|s| {
        for _ in 0..THREADS {
            let cache = Arc::clone(cache);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let value = cache.write().lookup(key(op));
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

fn run_read(cache: &Arc<RwLock<ReadInner>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|s| {
        for _ in 0..THREADS {
            let cache = Arc::clone(cache);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let value = cache.read().lookup(key(op));
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

fn run_striped_read(cache: &Arc<RwLock<StripedReadInner>>) -> u64 {
    let total = Arc::new(AtomicU64::new(0));
    std::thread::scope(|s| {
        for _ in 0..THREADS {
            let cache = Arc::clone(cache);
            let total = Arc::clone(&total);
            s.spawn(move || {
                let mut acc = 0_u64;
                for op in 0..OPS_PER_THREAD {
                    let value = cache.read().lookup(key(op));
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

fn bench_cache(c: &mut Criterion) {
    let write_cache = Arc::new(RwLock::new(WriteInner::seed()));
    let read_cache = Arc::new(RwLock::new(ReadInner::seed()));
    let striped_read_cache = Arc::new(RwLock::new(StripedReadInner::seed()));

    assert_eq!(
        run_write(&write_cache),
        run_read(&read_cache),
        "lock-free read-hit fold diverged from the write-lock hit path"
    );
    assert_eq!(
        run_write(&write_cache),
        run_striped_read(&striped_read_cache),
        "striped lock-free read-hit fold diverged from the write-lock hit path"
    );

    let mut group = c.benchmark_group("extent_cache_same_ns_8t");
    group.bench_function("write_lock_hit", |b| {
        b.iter(|| black_box(run_write(black_box(&write_cache))));
    });
    group.bench_function("read_lock_atomic_hit", |b| {
        b.iter(|| black_box(run_read(black_box(&read_cache))));
    });
    group.bench_function("read_lock_striped_atomic_hit", |b| {
        b.iter(|| black_box(run_striped_read(black_box(&striped_read_cache))));
    });
    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
