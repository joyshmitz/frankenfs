#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the ext4 extent-leaf lookup (bd-vzmis).
//!
//! `walk_extent_tree`'s Leaf arm finds the extent covering a logical block.
//! Extents are sorted ascending by `logical_block` and non-overlapping, so the
//! covering extent is the last one whose start is `<= target`. The old code
//! scanned every extent (O(N), up to ~340 per 4 KiB leaf); the new code
//! binary-searches with `partition_point` (O(log N)). Both return the same
//! single covering extent.
//!
//! This benches resolving a spread of random logical blocks against a 340-extent
//! leaf — the cache-miss read path for a fragmented file.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const N: u32 = 340; // max extents in a 4 KiB extent leaf

/// One extent: (logical_block, len, physical_start). Sorted, non-overlapping.
fn build_extents() -> Vec<(u32, u32, u64)> {
    // Fragmented: each extent is `len` long; leave a 1-block hole between them
    // so lookups also exercise the hole (no-cover) path.
    let mut v = Vec::with_capacity(N as usize);
    let mut logical = 0_u32;
    let mut phys = 1_000_u64;
    for _ in 0..N {
        let len = 4; // small fragments
        v.push((logical, len, phys));
        logical += len + 1; // +1 hole
        phys += u64::from(len) + 7;
    }
    v
}

/// Linear scan (old): first extent covering `target`.
fn linear(extents: &[(u32, u32, u64)], target: u32) -> Option<u64> {
    for &(start, len, phys) in extents {
        if target >= start && target < start.saturating_add(len) {
            return Some(phys + u64::from(target - start));
        }
    }
    None
}

/// Binary search (new): the last extent with start <= target, then verify cover.
fn binary(extents: &[(u32, u32, u64)], target: u32) -> Option<u64> {
    let pp = extents.partition_point(|&(start, _, _)| start <= target);
    if pp == 0 {
        return None;
    }
    let (start, len, phys) = extents[pp - 1];
    if target < start.saturating_add(len) {
        Some(phys + u64::from(target - start))
    } else {
        None
    }
}

fn bench_extent_resolve(c: &mut Criterion) {
    let extents = build_extents();
    let max_logical = extents.last().map_or(0, |&(s, l, _)| s + l);

    // Deterministic spread of probe targets across the whole logical range.
    let probes: Vec<u32> = {
        let mut x: u32 = 0x9e37_79b9;
        (0..1024)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 8) % max_logical
            })
            .collect()
    };

    // Isomorphism: binary returns the same physical block as linear for every
    // probe (cover and hole alike).
    for &t in &probes {
        assert_eq!(linear(&extents, t), binary(&extents, t), "target {t} diverged");
    }

    let mut group = c.benchmark_group("ext4_extent_leaf_lookup_340");
    group.bench_function("linear_scan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(linear(black_box(&extents), t).unwrap_or(0));
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_search", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in &probes {
                acc = acc.wrapping_add(binary(black_box(&extents), t).unwrap_or(0));
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(extent_resolve, bench_extent_resolve);
criterion_main!(extent_resolve);
