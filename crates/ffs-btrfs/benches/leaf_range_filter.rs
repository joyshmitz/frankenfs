#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the leaf range-filter in `collect_leaf_items` /
//! `collect_leaf_item_batch` (bd-cp077).
//!
//! A btrfs range walk (readdir over DIR_INDEX, fiemap over EXTENT_DATA,
//! listxattr over XATTR_ITEM) visits each leaf and keeps the items whose key is
//! in the half-open range `[lo, hi)`. Leaf items are sorted ascending by
//! `BtrfsKey`, so the kept items form a contiguous run: the old code scanned the
//! whole leaf and filtered each item (O(items)); the new code brackets the run
//! with two `partition_point` probes (O(log items + matches)). A 16 KiB leaf
//! packs hundreds of items and a narrow range (e.g. one inode's extents inside a
//! shared leaf) keeps only a few.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::BtrfsKey;
use std::cmp::Ordering;
use std::hint::black_box;

const N: usize = 493; // ~items in a 16 KiB leaf at ~33 bytes/item entry
const WINDOW: u64 = 8; // narrow range: keep ~8 items out of 493

/// Mirror of the crate-private `key_cmp`: order by (objectid, item_type, offset).
fn key_cmp(lhs: &BtrfsKey, rhs: &BtrfsKey) -> Ordering {
    lhs.objectid
        .cmp(&rhs.objectid)
        .then_with(|| lhs.item_type.cmp(&rhs.item_type))
        .then_with(|| lhs.offset.cmp(&rhs.offset))
}

fn build_keys() -> Vec<BtrfsKey> {
    (0..N as u64)
        .map(|i| BtrfsKey {
            objectid: 256,
            item_type: 108, // EXTENT_DATA
            offset: i * 4096,
        })
        .collect()
}

/// Linear filter (pre-bd-cp077): collect indices of items in [lo, hi).
fn linear(keys: &[BtrfsKey], lo: &BtrfsKey, hi: &BtrfsKey, out: &mut Vec<usize>) {
    out.clear();
    for (i, k) in keys.iter().enumerate() {
        if key_cmp(k, lo) == Ordering::Less || key_cmp(k, hi) != Ordering::Less {
            continue;
        }
        out.push(i);
    }
}

/// Binary window (new): bracket the contiguous run with two partition_points.
fn binary(keys: &[BtrfsKey], lo: &BtrfsKey, hi: &BtrfsKey, out: &mut Vec<usize>) {
    out.clear();
    let start = keys.partition_point(|k| key_cmp(k, lo) == Ordering::Less);
    let end = keys.partition_point(|k| key_cmp(k, hi) == Ordering::Less);
    out.extend(start..end.max(start));
}

fn bench_leaf_range_filter(c: &mut Criterion) {
    let keys = build_keys();
    let max_off = N as u64 * 4096;

    // Deterministic spread of narrow [lo, hi) windows across the leaf.
    let ranges: Vec<(BtrfsKey, BtrfsKey)> = {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..1024)
            .map(|_| {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let lo_off = (x >> 11) % max_off;
                let mk = |off: u64| BtrfsKey {
                    objectid: 256,
                    item_type: 108,
                    offset: off,
                };
                (mk(lo_off), mk(lo_off + WINDOW * 4096))
            })
            .collect()
    };

    // Isomorphism: binary keeps the same item indices as the linear filter.
    let mut a = Vec::new();
    let mut b = Vec::new();
    for (lo, hi) in &ranges {
        linear(&keys, lo, hi, &mut a);
        binary(&keys, lo, hi, &mut b);
        assert_eq!(a, b, "range [{lo:?}, {hi:?}) diverged");
    }

    let mut group = c.benchmark_group("btrfs_leaf_range_filter_493");
    group.bench_function("linear_scan", |b| {
        let mut out = Vec::new();
        b.iter(|| {
            let mut acc = 0_usize;
            for (lo, hi) in black_box(&ranges) {
                linear(black_box(&keys), lo, hi, &mut out);
                acc = acc.wrapping_add(out.len());
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_search", |b| {
        let mut out = Vec::new();
        b.iter(|| {
            let mut acc = 0_usize;
            for (lo, hi) in black_box(&ranges) {
                binary(black_box(&keys), lo, hi, &mut out);
                acc = acc.wrapping_add(out.len());
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(leaf_range_filter, bench_leaf_range_filter);
criterion_main!(leaf_range_filter);
