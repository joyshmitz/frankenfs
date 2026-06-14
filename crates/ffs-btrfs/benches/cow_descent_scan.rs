#![forbid(unsafe_code)]

//! Same-process A/B for binary-searching the in-memory COW B-tree descent
//! (bd-4p0ie).
//!
//! `InMemoryCowBtrfsTree` (the production btrfs COW write tree) descends each
//! internal node with `child_slot`, which linear-scanned the separator keys
//! (`.iter().position`), and `find_in`'s leaf arm linear-scanned items
//! (`.iter().find`). Internal nodes hold up to `max_items = (nodesize-101)/25`
//! ~= 651 keys for a 16 KiB nodesize, and `child_slot` runs per descent level on
//! every find/insert/delete. Keys/items are sorted ascending (insert maintains
//! it via partition_point) with unique btrfs keys, so both scans become binary
//! searches.
//!
//! Benches a full-fanout node (N=651): OLD linear `child_slot` / leaf find vs
//! NEW `partition_point` / `binary_search_by`, asserted to agree across probes.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::BtrfsKey;
use std::cmp::Ordering;
use std::hint::black_box;

const N: u64 = 651; // max_items for a 16 KiB nodesize

fn key_cmp(lhs: &BtrfsKey, rhs: &BtrfsKey) -> Ordering {
    lhs.objectid
        .cmp(&rhs.objectid)
        .then_with(|| lhs.item_type.cmp(&rhs.item_type))
        .then_with(|| lhs.offset.cmp(&rhs.offset))
}

/// Sorted, unique separator/leaf keys (objectid 0,2,4,... so odd probes miss).
fn build_keys() -> Vec<BtrfsKey> {
    (0..N)
        .map(|i| BtrfsKey {
            objectid: i * 2,
            item_type: 1,
            offset: 0,
        })
        .collect()
}

/// OLD child_slot: linear first index where `key < sep`.
fn child_slot_linear(keys: &[BtrfsKey], key: &BtrfsKey) -> usize {
    keys.iter()
        .position(|sep| key_cmp(key, sep) == Ordering::Less)
        .unwrap_or(keys.len())
}

/// NEW child_slot: partition_point over `key >= sep`.
fn child_slot_binary(keys: &[BtrfsKey], key: &BtrfsKey) -> usize {
    keys.partition_point(|sep| key_cmp(key, sep) != Ordering::Less)
}

/// OLD leaf find: linear exact-match.
fn leaf_find_linear(keys: &[BtrfsKey], key: &BtrfsKey) -> Option<usize> {
    keys.iter().position(|k| key_cmp(k, key) == Ordering::Equal)
}

/// NEW leaf find: binary_search.
fn leaf_find_binary(keys: &[BtrfsKey], key: &BtrfsKey) -> Option<usize> {
    keys.binary_search_by(|k| key_cmp(k, key)).ok()
}

fn probes() -> Vec<BtrfsKey> {
    // Spread across the node, plus a present and an absent key.
    (0..N)
        .step_by((N / 8) as usize)
        .map(|i| BtrfsKey {
            objectid: i, // even = present, odd = absent (gap)
            item_type: 1,
            offset: 0,
        })
        .collect()
}

fn bench_descent(c: &mut Criterion) {
    let keys = build_keys();
    let probes = probes();

    // Isomorphism: identical slot / find result for every probe.
    for p in &probes {
        assert_eq!(
            child_slot_linear(&keys, p),
            child_slot_binary(&keys, p),
            "child_slot diverged at {}",
            p.objectid
        );
        assert_eq!(
            leaf_find_linear(&keys, p),
            leaf_find_binary(&keys, p),
            "leaf_find diverged at {}",
            p.objectid
        );
    }

    let mut group = c.benchmark_group("cow_descent_scan_651");
    group.bench_function("child_slot_linear", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for p in black_box(&probes) {
                acc ^= child_slot_linear(black_box(&keys), p);
            }
            black_box(acc)
        });
    });
    group.bench_function("child_slot_partition_point", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for p in black_box(&probes) {
                acc ^= child_slot_binary(black_box(&keys), p);
            }
            black_box(acc)
        });
    });
    group.bench_function("leaf_find_linear", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for p in black_box(&probes) {
                acc ^= leaf_find_linear(black_box(&keys), p).unwrap_or(0);
            }
            black_box(acc)
        });
    });
    group.bench_function("leaf_find_binary_search", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for p in black_box(&probes) {
                acc ^= leaf_find_binary(black_box(&keys), p).unwrap_or(0);
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_descent);
criterion_main!(benches);
