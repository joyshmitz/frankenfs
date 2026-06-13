#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the within-node floor scan in `floor_descend` (bd-hv6ww).
//!
//! An on-disk btrfs floor descent visits one node per tree level on every
//! `read_file` extent fetch (and getattr/xattr point seeks). Within each node it
//! finds the floor — the last item (leaf) or key-ptr (internal) whose key is
//! `<= target`. Items are sorted ascending by `BtrfsKey`, so the old `for ...
//! break` scan was O(items); a 16 KiB leaf packs hundreds of items. The new code
//! binary-searches with `partition_point` (O(log items)). Both return the same
//! floor index.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::BtrfsKey;
use std::cmp::Ordering;
use std::hint::black_box;

const N: usize = 493; // ~items in a 16 KiB leaf at ~33 bytes/item entry

/// Mirror of the crate-private `key_cmp`: order by (objectid, item_type, offset).
fn key_cmp(lhs: &BtrfsKey, rhs: &BtrfsKey) -> Ordering {
    lhs.objectid
        .cmp(&rhs.objectid)
        .then_with(|| lhs.item_type.cmp(&rhs.item_type))
        .then_with(|| lhs.offset.cmp(&rhs.offset))
}

/// Sorted-ascending key list: one objectid, EXTENT_DATA type, strided offsets.
fn build_keys() -> Vec<BtrfsKey> {
    (0..N as u64)
        .map(|i| BtrfsKey {
            objectid: 256,
            item_type: 108, // EXTENT_DATA
            offset: i * 4096,
        })
        .collect()
}

/// Linear scan (pre-bd-hv6ww): last item with key <= target.
fn linear(keys: &[BtrfsKey], target: &BtrfsKey) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (i, k) in keys.iter().enumerate() {
        if key_cmp(k, target) == Ordering::Greater {
            break;
        }
        best = Some(i);
    }
    best
}

/// Binary search (new): partition_point to the floor index.
fn binary(keys: &[BtrfsKey], target: &BtrfsKey) -> Option<usize> {
    let pp = keys.partition_point(|k| key_cmp(k, target) != Ordering::Greater);
    if pp == 0 { None } else { Some(pp - 1) }
}

fn bench_floor_node_scan(c: &mut Criterion) {
    let keys = build_keys();
    let max_off = N as u64 * 4096;

    // Deterministic spread of probe targets across (and just outside) the range.
    let probes: Vec<BtrfsKey> = {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..1024)
            .map(|_| {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                BtrfsKey {
                    objectid: 256,
                    item_type: 108,
                    offset: (x >> 11) % (max_off + 8192),
                }
            })
            .collect()
    };

    // Isomorphism: binary returns the same floor index as linear for every probe.
    for t in &probes {
        assert_eq!(linear(&keys, t), binary(&keys, t), "target {t:?} diverged");
    }

    let mut group = c.benchmark_group("btrfs_floor_node_scan_493");
    group.bench_function("linear_scan", |b| {
        b.iter(|| {
            let mut acc = 0_usize;
            for t in &probes {
                acc = acc.wrapping_add(linear(black_box(&keys), t).unwrap_or(0));
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_search", |b| {
        b.iter(|| {
            let mut acc = 0_usize;
            for t in &probes {
                acc = acc.wrapping_add(binary(black_box(&keys), t).unwrap_or(0));
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(floor_node_scan, bench_floor_node_scan);
criterion_main!(floor_node_scan);
