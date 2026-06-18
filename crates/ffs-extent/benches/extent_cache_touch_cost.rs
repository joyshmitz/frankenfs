#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Single-threaded per-hit touch-cost isolation for the within-shard lever
//! (bd-xmh5g.382).
//!
//! The contention benches (`extent_cache_same_ns`, `extent_cache_real_contention`)
//! measure the multi-threaded lock cost. This one isolates the SINGLE-THREADED
//! per-hit work so the lever's tradeoff can be quantified without thread noise:
//!
//!   * `indexed_touch` — the production design: every hit refreshes
//!     `last_access` AND moves the entry's row in the `eviction_index` BTreeSet
//!     (one remove + one insert), so eviction is `O(log n)`.
//!   * `field_touch` — the lever's hot path: a hit only writes `last_access`
//!     (no index), so eviction must fall back to an `O(n) min_by_key` scan.
//!
//! Read-heavy workloads pay the `indexed_touch` cost on every hit but the
//! `field_touch` cost only on eviction, so the per-hit delta here times the
//! hit:eviction ratio is the lever's single-threaded headroom — the input to
//! the keep/reject decision (the multi-threaded lock-free-hit win is on top of
//! this). The aggregate fold is asserted identical first.

use criterion::{Criterion, criterion_group, criterion_main};
use std::collections::{BTreeMap, BTreeSet};
use std::hint::black_box;

const ENTRIES: u32 = 256;
const OPS: usize = 2_000_000;

fn mapping_for(lb: u32) -> u64 {
    u64::from(lb).wrapping_mul(1_000)
}

fn key(op: usize) -> u32 {
    ((op.wrapping_mul(2_654_435_761)) as u32) % ENTRIES
}

/// Production-shaped: hit refreshes `last_access` and moves the eviction-index
/// row (remove + insert).
struct Indexed {
    entries: BTreeMap<u32, (u64, u64)>, // (mapping, last_access)
    index: BTreeSet<(u64, u32)>,        // (last_access, key)
    hits: u64,
}

impl Indexed {
    fn seed() -> Self {
        let mut entries = BTreeMap::new();
        let mut index = BTreeSet::new();
        for lb in 0..ENTRIES {
            entries.insert(lb, (mapping_for(lb), 0));
            index.insert((0, lb));
        }
        Self {
            entries,
            index,
            hits: 0,
        }
    }

    fn lookup(&mut self, lb: u32) -> Option<u64> {
        self.hits = self.hits.wrapping_add(1);
        let clock = self.hits;
        let entry = self.entries.get_mut(&lb)?;
        self.index.remove(&(entry.1, lb));
        entry.1 = clock;
        self.index.insert((clock, lb));
        Some(entry.0.wrapping_add(u64::from(lb)))
    }
}

/// Lever hot path: hit only writes `last_access`; no index maintenance.
struct Field {
    entries: BTreeMap<u32, (u64, u64)>,
    hits: u64,
}

impl Field {
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
        entry.1 = clock;
        Some(entry.0.wrapping_add(u64::from(lb)))
    }
}

fn run_indexed(cache: &mut Indexed) -> u64 {
    let mut acc = 0_u64;
    for op in 0..OPS {
        if let Some(v) = cache.lookup(key(op)) {
            acc = acc.wrapping_add(v);
        }
    }
    acc
}

fn run_field(cache: &mut Field) -> u64 {
    let mut acc = 0_u64;
    for op in 0..OPS {
        if let Some(v) = cache.lookup(key(op)) {
            acc = acc.wrapping_add(v);
        }
    }
    acc
}

fn bench_cache(c: &mut Criterion) {
    assert_eq!(
        run_indexed(&mut Indexed::seed()),
        run_field(&mut Field::seed()),
        "field-touch fold diverged from indexed-touch"
    );

    let mut group = c.benchmark_group("extent_cache_hit_touch");
    group.bench_function("indexed_touch", |b| {
        b.iter_batched(
            Indexed::seed,
            |mut cache| black_box(run_indexed(black_box(&mut cache))),
            criterion::BatchSize::SmallInput,
        );
    });
    group.bench_function("field_touch", |b| {
        b.iter_batched(
            Field::seed,
            |mut cache| black_box(run_field(black_box(&mut cache))),
            criterion::BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_cache);
criterion_main!(benches);
