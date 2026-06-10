#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B benchmark for the btrfs readdir name-dedup lever (ffs-core
//! `btrfs_dedup_dir_rows`).
//!
//! A btrfs directory presents ~2 rows per file (a DIR_ITEM and a DIR_INDEX with
//! the same name), and readdir deduplicates by name keeping the first in sort
//! order. The prior implementation scanned every already-kept row per row —
//! O(rows^2), i.e. O(files^2) per `ls`. This benches that all-pairs scan against
//! the O(N) seen-name HashSet on a realistic 2x-duplicated, sorted row set. The
//! two standalone functions mirror the old/new implementations exactly (the real
//! helper is private to ffs-core).

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::collections::HashSet;
use std::hint::black_box;

const FILES: usize = 3000;

/// Build the rows readdir produces: each file as a DIR_INDEX row and a DIR_ITEM
/// row (same name; DIR_ITEM gets the high-bit sort bias), then sorted by key.
fn build_rows() -> Vec<(u64, Vec<u8>)> {
    let mut rows = Vec::with_capacity(FILES * 2);
    for i in 0..FILES {
        let name = format!("file{i:06}").into_bytes();
        rows.push((i as u64, name.clone()));
        rows.push(((1_u64 << 63) | i as u64, name));
    }
    rows.sort_by_key(|(k, _)| *k);
    rows
}

/// Prior implementation: O(N^2) all-pairs keep-first-by-name scan.
fn dedup_linear(rows: Vec<(u64, Vec<u8>)>) -> Vec<(u64, Vec<u8>)> {
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    for row in rows {
        if out.iter().any(|(_, name)| *name == row.1) {
            continue;
        }
        out.push(row);
    }
    out
}

/// New implementation: O(N) seen-name HashSet.
fn dedup_hashset(rows: Vec<(u64, Vec<u8>)>) -> Vec<(u64, Vec<u8>)> {
    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(rows.len());
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if seen.insert(row.1.clone()) {
            out.push(row);
        }
    }
    out
}

fn bench_readdir_dedup(c: &mut Criterion) {
    let rows = build_rows();
    // Isomorphism: both keep the same first-by-sort-order rows.
    assert_eq!(dedup_linear(rows.clone()), dedup_hashset(rows.clone()));
    assert_eq!(dedup_hashset(rows.clone()).len(), FILES);

    let mut group = c.benchmark_group("btrfs_readdir_dedup");
    group.sample_size(10);
    group.bench_function("linear_all_pairs", |b| {
        b.iter_batched(
            || rows.clone(),
            |r| black_box(dedup_linear(r)),
            BatchSize::LargeInput,
        );
    });
    group.bench_function("hashset", |b| {
        b.iter_batched(
            || rows.clone(),
            |r| black_box(dedup_hashset(r)),
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(readdir_dedup, bench_readdir_dedup);
criterion_main!(readdir_dedup);
