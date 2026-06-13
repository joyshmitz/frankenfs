#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for binary-searching the ext4_write per-block extent resolve
//! (bd-uthzg).
//!
//! After caching the extent tree across the write loop (bd-yqq5l), the dominant
//! remaining per-block cost is the resolve: `extents.iter().find_map(..)` scans
//! all E extents linearly to find the one covering the block. Extents are sorted
//! ascending by logical_block and non-overlapping, so the covering one is the
//! last with start <= the block — a `partition_point` binary search. An N-block
//! write over an E-extent file drops from O(N*E) to O(N log E).
//!
//! This benches K resolves over a sorted E-extent map: OLD linear find_map vs
//! NEW partition_point. Same answer for every block (asserted).

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const E: u32 = 5440; // extents in a fragmented file (16 leaves * 340)
const K: u32 = 256; // blocks touched by the write (e.g. a 1 MiB write)

/// (logical_start, len, physical_start) — length-1 extents at 0,1,2,...,E-1.
fn build_extents() -> Vec<(u32, u32, u64)> {
    (0..E).map(|i| (i, 1, 100_000_u64 + u64::from(i))).collect()
}

fn targets() -> Vec<u32> {
    (0..K).map(|i| (i * (E / K)) % E).collect()
}

/// OLD: linear find_map over all extents.
fn resolve_linear(extents: &[(u32, u32, u64)], logical: u32) -> Option<(u64, bool)> {
    extents.iter().find_map(|&(start, len, phys)| {
        (logical >= start && logical < start + len)
            .then_some((phys + u64::from(logical - start), false))
    })
}

/// NEW: binary-search the covering extent.
fn resolve_binary(extents: &[(u32, u32, u64)], logical: u32) -> Option<(u64, bool)> {
    let pos = extents.partition_point(|&(start, _, _)| start <= logical);
    pos.checked_sub(1).and_then(|i| {
        let (start, len, phys) = extents[i];
        (logical < start + len).then_some((phys + u64::from(logical - start), false))
    })
}

fn bench_resolve(c: &mut Criterion) {
    let extents = build_extents();
    let targets = targets();

    // Isomorphism: both resolve every target identically.
    for &t in &targets {
        assert_eq!(
            resolve_linear(&extents, t),
            resolve_binary(&extents, t),
            "binary resolve diverged at logical {t}"
        );
    }

    let mut group = c.benchmark_group("ext4_write_resolve_256blk_over_5440ext");
    group.bench_function("linear_find_map", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in black_box(&targets) {
                acc ^= resolve_linear(black_box(&extents), t).map_or(0, |r| r.0);
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_partition_point", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in black_box(&targets) {
                acc ^= resolve_binary(black_box(&extents), t).map_or(0, |r| r.0);
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_resolve);
criterion_main!(benches);
