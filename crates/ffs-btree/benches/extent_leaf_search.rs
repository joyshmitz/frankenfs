#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for the trusted extent-leaf search helper (bd-xmh5g.386).
//!
//! `parse_leaf_entries` already validates each leaf once: every extent has
//! nonzero length and entries are sorted/non-overlapping. The old production
//! search immediately rescanned the whole validated leaf for zero-length
//! extents before doing its `partition_point` lookup. The new production path
//! uses a private trusted helper only after that parser has succeeded, while
//! keeping the checked helper for caller-supplied parsed roots.
//!
//! This bench isolates the removed work over a full 4K ext4 extent leaf
//! (340 entries): `old_checked_zero_scan` models the old extra validation pass,
//! and `trusted_validated_no_rescan` models the new private helper.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btree::SearchResult;
use ffs_ondisk::Ext4Extent;
use std::hint::black_box;

const LEAF_ENTRIES_4K: u32 = 340;
const PROBE_COUNT: usize = 2048;

fn actual_len(raw_len: u16) -> u16 {
    const EXT_INIT_MAX_LEN: u16 = 1_u16 << 15;
    if raw_len <= EXT_INIT_MAX_LEN {
        raw_len
    } else {
        raw_len - EXT_INIT_MAX_LEN
    }
}

fn build_full_leaf() -> Vec<Ext4Extent> {
    (0..LEAF_ENTRIES_4K)
        .map(|i| Ext4Extent {
            logical_block: i * 2,
            raw_len: 1,
            physical_start: 1_000_000 + u64::from(i),
        })
        .collect()
}

fn build_probes() -> Vec<u32> {
    let max_logical = LEAF_ENTRIES_4K * 2 + 32;
    let mut x = 0x9e37_79b9_7f4a_7c15_u64;
    (0..PROBE_COUNT)
        .map(|_| {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            ((x >> 11) % u64::from(max_logical)) as u32
        })
        .collect()
}

fn trusted_validated_search(
    extents: &[Ext4Extent],
    target: u32,
    upper_bound: u64,
) -> SearchResult {
    if extents.is_empty() {
        return SearchResult::Hole {
            hole_len: upper_bound.saturating_sub(u64::from(target)),
        };
    }

    let pos = extents.partition_point(|e| e.logical_block <= target);

    if pos > 0 {
        let ext = &extents[pos - 1];
        let len = actual_len(ext.raw_len);
        let end = u64::from(ext.logical_block) + u64::from(len);
        if u64::from(target) < end {
            return SearchResult::Found {
                extent: *ext,
                offset_in_extent: target - ext.logical_block,
            };
        }
    }

    let next_start = if pos < extents.len() {
        u64::from(extents[pos].logical_block)
    } else {
        upper_bound
    };
    SearchResult::Hole {
        hole_len: next_start.saturating_sub(u64::from(target)),
    }
}

fn old_checked_search(
    extents: &[Ext4Extent],
    target: u32,
    upper_bound: u64,
) -> Option<SearchResult> {
    for ext in extents {
        if actual_len(ext.raw_len) == 0 {
            return None;
        }
    }
    Some(trusted_validated_search(extents, target, upper_bound))
}

fn bench_leaf_search_validation(c: &mut Criterion) {
    let extents = build_full_leaf();
    let probes = build_probes();
    let upper_bound = 1_u64 << 32;

    for &target in &probes {
        let checked = old_checked_search(&extents, target, upper_bound)
            .expect("benchmark leaf is parser-validated");
        let trusted = trusted_validated_search(&extents, target, upper_bound);
        assert_eq!(checked, trusted, "leaf search model diverged at {target}");
    }

    let mut group = c.benchmark_group("extent_leaf_search_validation_ab");
    group.bench_function("old_checked_zero_scan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &target in &probes {
                let result = old_checked_search(black_box(&extents), target, upper_bound)
                    .expect("benchmark leaf is parser-validated");
                match result {
                    SearchResult::Found { extent, .. } => {
                        acc = acc.wrapping_add(extent.physical_start);
                    }
                    SearchResult::Hole { hole_len } => acc = acc.wrapping_add(hole_len),
                }
            }
            black_box(acc)
        });
    });
    group.bench_function("trusted_validated_no_rescan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &target in &probes {
                let result = trusted_validated_search(black_box(&extents), target, upper_bound);
                match result {
                    SearchResult::Found { extent, .. } => {
                        acc = acc.wrapping_add(extent.physical_start);
                    }
                    SearchResult::Hole { hole_len } => acc = acc.wrapping_add(hole_len),
                }
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(extent_leaf_search, bench_leaf_search_validation);
criterion_main!(extent_leaf_search);
