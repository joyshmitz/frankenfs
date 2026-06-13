#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for binary-searching ext4_add_dir_entry's resolve_logical
//! (bd-urrco).
//!
//! When inserting into an htree directory, `ext4_add_dir_entry` maps each htree
//! node's logical block to physical via a `resolve_logical` closure that linearly
//! scanned all E of the directory's extents. The htree descent calls it once per
//! node read, so a fragmented large directory pays O(E) per resolve, several
//! times per create/mkdir/link/unlink. Directory extents are sorted ascending by
//! logical_block and non-overlapping, so the covering one is the last with start
//! <= the block — a partition_point binary search (O(log E)).
//!
//! Benches R resolves (one htree descent worth, repeated) over a sorted E-extent
//! directory map: OLD linear scan vs NEW partition_point. Same answer (asserted).

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const E: u32 = 512; // extents in a fragmented large directory
const R: u32 = 4; // resolve_logical calls per insert (htree descent + target)

/// (logical_start, len, physical_start) — length-1 extents 0..E.
fn build_extents() -> Vec<(u32, u32, u64)> {
    (0..E).map(|i| (i, 1, 900_000_u64 + u64::from(i))).collect()
}

/// OLD: linear scan, skipping unwritten (none here), first covering extent.
fn linear(extents: &[(u32, u32, u64)], logical: u32) -> Option<u64> {
    for &(start, len, phys) in extents {
        if logical >= start && logical < start.saturating_add(len) {
            return Some(phys + u64::from(logical - start));
        }
    }
    None
}

/// NEW: binary-search the covering extent.
fn binary(extents: &[(u32, u32, u64)], logical: u32) -> Option<u64> {
    let pos = extents.partition_point(|&(start, _, _)| start <= logical);
    let (start, len, phys) = *extents.get(pos.checked_sub(1)?)?;
    (logical >= start && logical < start.saturating_add(len))
        .then_some(phys + u64::from(logical - start))
}

fn bench_resolve_logical(c: &mut Criterion) {
    let extents = build_extents();
    // Htree descent touches blocks spread across the directory.
    let probes: Vec<u32> = (0..R).map(|i| (i * (E / R)) % E).collect();

    for &p in &probes {
        assert_eq!(linear(&extents, p), binary(&extents, p), "diverged at {p}");
    }

    let mut group = c.benchmark_group("htree_resolve_logical_4probes_over_512ext");
    group.bench_function("linear_scan", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &p in black_box(&probes) {
                acc ^= linear(black_box(&extents), p).unwrap_or(0);
            }
            black_box(acc)
        });
    });
    group.bench_function("binary_partition_point", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &p in black_box(&probes) {
                acc ^= binary(black_box(&extents), p).unwrap_or(0);
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_resolve_logical);
criterion_main!(benches);
