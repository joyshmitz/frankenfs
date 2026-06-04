#![forbid(unsafe_code)]
//! Benchmark: Bw-Tree vs Mutex-protected BTreeMap for concurrent extent index ops.
//!
//! Scenarios:
//! 1. Read-heavy (95% lookup, 5% insert)
//! 2. Write-heavy (30% lookup, 70% insert/delete)
//! 3. Mixed workload (50% lookup, 30% insert, 10% delete, 10% range scan)
//! 4. Single-threaded baseline
//! 5. Consolidation overhead

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_btree::bw_tree::{
    BwKey, BwValue, ConsolidationConfig, DeltaMutation, MappingTable, PageDelta, PageId,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Barrier, Mutex};

const PAGE_CAPACITY: usize = 16;
const PREPOPULATE: u64 = 10_000;
const OPS_PER_THREAD: u64 = 5_000;

// ── Locked BTreeMap baseline ────────────────────────────────────────────

struct LockedBTree {
    inner: Mutex<BTreeMap<u64, u64>>,
}

impl LockedBTree {
    fn new() -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    fn insert(&self, key: u64, value: u64) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, value);
    }

    fn lookup(&self, key: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .copied()
    }

    fn delete(&self, key: u64) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key);
    }

    fn range_scan(&self, start: u64, count: usize) -> Vec<(u64, u64)> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .range(start..)
            .take(count)
            .map(|(&k, &v)| (k, v))
            .collect()
    }
}

// ── Deterministic RNG for workload generation ───────────────────────────

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ── Scenario 1: Read-Heavy (95% lookup, 5% insert) ─────────────────────

fn bench_read_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_heavy");
    group.sample_size(10);

    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("bwtree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..PREPOPULATE {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    // Consolidate before benchmark
                    let cfg = ConsolidationConfig::default();
                    let _ = table.consolidate_page(page, &cfg);

                    run_bwtree_workload(&table, page, thread_count, 95, 5, 0, 0);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("locked_btree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let tree = Arc::new(LockedBTree::new());
                    for i in 0..PREPOPULATE {
                        tree.insert(i, i);
                    }
                    run_locked_workload(&tree, thread_count, 95, 5, 0, 0);
                });
            },
        );
    }
    group.finish();
}

// ── Scenario 2: Write-Heavy (30% lookup, 70% insert/delete) ────────────

fn bench_write_heavy(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_heavy");
    group.sample_size(10);

    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("bwtree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..PREPOPULATE {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    let cfg = ConsolidationConfig::default();
                    let _ = table.consolidate_page(page, &cfg);

                    run_bwtree_workload(&table, page, thread_count, 30, 40, 30, 0);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("locked_btree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let tree = Arc::new(LockedBTree::new());
                    for i in 0..PREPOPULATE {
                        tree.insert(i, i);
                    }
                    run_locked_workload(&tree, thread_count, 30, 40, 30, 0);
                });
            },
        );
    }
    group.finish();
}

// ── Scenario 3: Mixed workload ──────────────────────────────────────────

fn bench_mixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed");
    group.sample_size(10);

    for threads in [1_usize, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("bwtree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..PREPOPULATE {
                        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
                    }
                    let cfg = ConsolidationConfig::default();
                    let _ = table.consolidate_page(page, &cfg);

                    run_bwtree_workload(&table, page, thread_count, 50, 30, 10, 10);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("locked_btree", threads),
            &threads,
            |b, &thread_count| {
                b.iter(|| {
                    let tree = Arc::new(LockedBTree::new());
                    for i in 0..PREPOPULATE {
                        tree.insert(i, i);
                    }
                    run_locked_workload(&tree, thread_count, 50, 30, 10, 10);
                });
            },
        );
    }
    group.finish();
}

fn bench_mixed_auto_consolidation_ab(c: &mut Criterion) {
    let mut group = c.benchmark_group("mixed_auto_consolidation_ab");
    group.sample_size(10);

    group.bench_function("old_deferred_consolidation_8", |b| {
        b.iter(|| {
            let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
            let page = table.allocate_page().expect("alloc");
            for i in 0..PREPOPULATE {
                legacy_insert_without_preconsolidation(&table, page, BwKey(i), BwValue(i));
            }
            let cfg = ConsolidationConfig::default();
            let _ = table.consolidate_page(page, &cfg);

            run_bwtree_workload_without_preconsolidation(&table, page, 8, 50, 30, 10, 10);
        });
    });

    group.bench_function("new_default_preconsolidation_8", |b| {
        b.iter(|| {
            let table = Arc::new(MappingTable::with_capacity(PAGE_CAPACITY));
            let page = table.allocate_page().expect("alloc");
            for i in 0..PREPOPULATE {
                table.insert(page, BwKey(i), BwValue(i)).expect("insert");
            }
            let cfg = ConsolidationConfig::default();
            let _ = table.consolidate_page(page, &cfg);

            run_bwtree_workload(&table, page, 8, 50, 30, 10, 10);
        });
    });

    group.finish();
}

// ── Scenario 5: Consolidation overhead ──────────────────────────────────

fn bench_consolidation_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("consolidation");
    group.sample_size(10);

    // Measure consolidation cost for varying chain lengths
    for chain_len in [10_u64, 50, 200] {
        group.bench_with_input(
            BenchmarkId::new("consolidate", chain_len),
            &chain_len,
            |b, &len| {
                b.iter(|| {
                    let table = MappingTable::with_capacity(1);
                    let page = table.allocate_page().expect("alloc");
                    for i in 0..len {
                        legacy_insert_without_preconsolidation(&table, page, BwKey(i), BwValue(i));
                    }
                    let cfg = ConsolidationConfig {
                        chain_threshold: 1,
                        max_retries: 64,
                    };
                    table.consolidate_page(page, &cfg).expect("consolidate");
                });
            },
        );
    }
    group.finish();
}

// ── Workload runners ────────────────────────────────────────────────────

fn run_bwtree_workload(
    table: &Arc<MappingTable>,
    page: PageId,
    thread_count: usize,
    lookup_pct: u64,
    insert_pct: u64,
    delete_pct: u64,
    scan_pct: u64,
) {
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    let total = lookup_pct + insert_pct + delete_pct + scan_pct;

    for tid in 0..thread_count {
        let table = Arc::clone(table);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut rng = (tid as u64 + 1).wrapping_mul(6_364_136_223_846_793_005);
            for _ in 0..OPS_PER_THREAD {
                let op = xorshift64(&mut rng) % total;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < lookup_pct {
                    let _ = table.lookup(page, BwKey(key));
                } else if op < lookup_pct + insert_pct {
                    let _ = table.insert(page, BwKey(key), BwValue(key + 1));
                } else if op < lookup_pct + insert_pct + delete_pct {
                    let _ = table.delete(page, BwKey(key));
                } else {
                    let _ = table.range_scan(page, BwKey(key), 10);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("no panic");
    }
}

fn append_delta_without_preconsolidation(
    table: &MappingTable,
    page: PageId,
    mutation: DeltaMutation,
) {
    for _ in 0..1_024 {
        let snapshot = table.get_page(page).expect("snapshot");
        let new_head = Arc::new(match mutation {
            DeltaMutation::Insert { key, value } => PageDelta::Insert {
                key,
                value,
                next: snapshot.head,
            },
            DeltaMutation::Delete { key } => PageDelta::Delete {
                key,
                next: snapshot.head,
            },
            DeltaMutation::Split {
                separator,
                new_sibling,
            } => PageDelta::Split {
                separator,
                new_sibling,
                next: snapshot.head,
            },
            DeltaMutation::Merge { removed_sibling } => PageDelta::Merge {
                removed_sibling,
                next: snapshot.head,
            },
        });
        if table
            .cas_page(page, snapshot.epoch, new_head, snapshot.chain_len + 1)
            .expect("legacy cas")
        {
            return;
        }
    }
    panic!("legacy no-preconsolidation append exhausted CAS retries");
}

fn legacy_insert_without_preconsolidation(
    table: &MappingTable,
    page: PageId,
    key: BwKey,
    value: BwValue,
) {
    append_delta_without_preconsolidation(table, page, DeltaMutation::Insert { key, value });
}

fn legacy_delete_without_preconsolidation(table: &MappingTable, page: PageId, key: BwKey) {
    append_delta_without_preconsolidation(table, page, DeltaMutation::Delete { key });
}

fn run_bwtree_workload_without_preconsolidation(
    table: &Arc<MappingTable>,
    page: PageId,
    thread_count: usize,
    lookup_pct: u64,
    insert_pct: u64,
    delete_pct: u64,
    scan_pct: u64,
) {
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    let total = lookup_pct + insert_pct + delete_pct + scan_pct;

    for tid in 0..thread_count {
        let table = Arc::clone(table);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut rng = (tid as u64 + 1).wrapping_mul(6_364_136_223_846_793_005);
            for _ in 0..OPS_PER_THREAD {
                let op = xorshift64(&mut rng) % total;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < lookup_pct {
                    let _ = table.lookup(page, BwKey(key));
                } else if op < lookup_pct + insert_pct {
                    legacy_insert_without_preconsolidation(
                        &table,
                        page,
                        BwKey(key),
                        BwValue(key + 1),
                    );
                } else if op < lookup_pct + insert_pct + delete_pct {
                    legacy_delete_without_preconsolidation(&table, page, BwKey(key));
                } else {
                    let _ = table.range_scan(page, BwKey(key), 10);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("no panic");
    }
}

fn run_locked_workload(
    tree: &Arc<LockedBTree>,
    thread_count: usize,
    lookup_pct: u64,
    insert_pct: u64,
    delete_pct: u64,
    scan_pct: u64,
) {
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();
    let total = lookup_pct + insert_pct + delete_pct + scan_pct;

    for tid in 0..thread_count {
        let tree = Arc::clone(tree);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let mut rng = (tid as u64 + 1).wrapping_mul(6_364_136_223_846_793_005);
            for _ in 0..OPS_PER_THREAD {
                let op = xorshift64(&mut rng) % total;
                let key = xorshift64(&mut rng) % (PREPOPULATE * 2);
                if op < lookup_pct {
                    let _ = tree.lookup(key);
                } else if op < lookup_pct + insert_pct {
                    tree.insert(key, key + 1);
                } else if op < lookup_pct + insert_pct + delete_pct {
                    tree.delete(key);
                } else {
                    let _ = tree.range_scan(key, 10);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("no panic");
    }
}

// ── Scenario 6: Point-lookup A/B (materialize vs direct chain walk) ─────
//
// Same-binary, same-worker A/B isolating the bd-xmh5g.2 lever: a single
// point query against a consolidated base page carrying a short post-
// consolidation delta chain. The OLD path clones the whole base BTreeMap
// and replays the chain before probing one key (`materialize_page` + get);
// the NEW path (`lookup`) walks newest→oldest deltas and short-circuits.
// Both arms run in the same binary so the ratio is machine-independent.

fn build_chained_page() -> (MappingTable, PageId) {
    let table = MappingTable::with_capacity(PAGE_CAPACITY);
    let page = table.allocate_page().expect("alloc");
    for i in 0..PREPOPULATE {
        table.insert(page, BwKey(i), BwValue(i)).expect("insert");
    }
    // Collapse the prepopulate chain into a single Base delta.
    let cfg = ConsolidationConfig::default();
    let _ = table.consolidate_page(page, &cfg);
    // Short realistic post-consolidation delta chain on top of the base.
    for i in 0..8u64 {
        table
            .insert(page, BwKey(i * 1000), BwValue(i * 1000 + 7))
            .expect("post insert");
        table
            .delete(page, BwKey(i * 1000 + 1))
            .expect("post delete");
    }
    (table, page)
}

fn bench_point_lookup_ab(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_lookup");
    group.sample_size(50);

    let (table, page) = build_chained_page();
    // Spread of probe keys: base hits, deleted keys, and chain-shadowed keys.
    let probes: Vec<BwKey> = (0..64u64).map(|i| BwKey(i * 157 % PREPOPULATE)).collect();

    group.bench_function("old_materialize_then_get", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            for &key in &probes {
                let state = table.materialize_page(page).expect("materialize");
                if let Some(v) = state.get(&key) {
                    sum = sum.wrapping_add(v.0);
                }
            }
            std::hint::black_box(sum)
        });
    });

    group.bench_function("new_direct_lookup", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            for &key in &probes {
                if let Some(v) = table.lookup(page, key).expect("lookup") {
                    sum = sum.wrapping_add(v.0);
                }
            }
            std::hint::black_box(sum)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_read_heavy,
    bench_write_heavy,
    bench_mixed,
    bench_mixed_auto_consolidation_ab,
    bench_consolidation_overhead,
    bench_point_lookup_ab,
);
criterion_main!(benches);
