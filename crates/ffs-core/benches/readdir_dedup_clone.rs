#![forbid(unsafe_code)]

//! Same-process A/B for deduping btrfs readdir rows without per-name clones
//! (bd-7pjxd).
//!
//! `btrfs_dedup_dir_rows` removes the DIR_ITEM/DIR_INDEX duplicate rows a btrfs
//! directory presents (~2 rows per file, same name). The old code cloned every
//! name into a `HashSet<Vec<u8>>` (a malloc + later free per row) purely to key
//! the dedup; the new code borrows each name (`HashSet<&[u8]>`) via a two-pass
//! keep-mask, so a large `ls` pays zero per-name allocations.
//!
//! This replicates the dedup over a row list of `(u64, Vec<u8>)` (the name is
//! all the dedup keys on). OLD clones names into the set; NEW borrows + moves
//! kept rows. Same first-occurrence result (asserted).

use criterion::{Criterion, criterion_group, criterion_main};
use std::collections::HashSet;
use std::hint::black_box;

const FILES: usize = 4096; // unique names; btrfs presents ~2 rows each

/// `2*FILES` rows: each name appears twice (DIR_ITEM + DIR_INDEX), interleaved
/// in sorted order, as btrfs readdir produces them.
fn build_rows() -> Vec<(u64, Vec<u8>)> {
    let mut rows = Vec::with_capacity(FILES * 2);
    for i in 0..FILES {
        let name = format!("file_{i:08}").into_bytes();
        rows.push((i as u64, name.clone()));
        rows.push((i as u64, name));
    }
    rows
}

/// OLD: clone each name into a HashSet<Vec<u8>>.
fn dedup_clone(rows: Vec<(u64, Vec<u8>)>) -> Vec<(u64, Vec<u8>)> {
    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(rows.len());
    let mut out: Vec<(u64, Vec<u8>)> = Vec::with_capacity(rows.len());
    for row in rows {
        if seen.insert(row.1.clone()) {
            out.push(row);
        }
    }
    out
}

/// NEW: borrow each name (HashSet<&[u8]>) via a two-pass keep-mask.
fn dedup_borrow(rows: Vec<(u64, Vec<u8>)>) -> Vec<(u64, Vec<u8>)> {
    let mut seen: HashSet<&[u8]> = HashSet::with_capacity(rows.len());
    let mut keep: Vec<bool> = Vec::with_capacity(rows.len());
    for row in &rows {
        keep.push(seen.insert(row.1.as_slice()));
    }
    drop(seen);
    rows.into_iter()
        .zip(keep)
        .filter_map(|(row, keep)| keep.then_some(row))
        .collect()
}

fn bench_dedup(c: &mut Criterion) {
    // Isomorphism: identical deduped rows (first occurrence, same order).
    assert_eq!(dedup_clone(build_rows()), dedup_borrow(build_rows()));

    let mut group = c.benchmark_group("readdir_dedup_8192rows");
    group.bench_function("clone_into_set", |b| {
        b.iter_batched(
            build_rows,
            |rows| black_box(dedup_clone(black_box(rows))),
            criterion::BatchSize::LargeInput,
        );
    });
    group.bench_function("borrow_keep_mask", |b| {
        b.iter_batched(
            build_rows,
            |rows| black_box(dedup_borrow(black_box(rows))),
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_dedup);
criterion_main!(benches);
