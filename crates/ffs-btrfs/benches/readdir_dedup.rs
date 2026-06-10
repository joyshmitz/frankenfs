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
use ffs_btrfs::{
    BTRFS_ITEM_DIR_INDEX, BTRFS_ITEM_DIR_ITEM, BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree,
};
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

const DIR_INODE: u64 = 256;
/// Representative on-disk `btrfs_dir_item` payload: ~30-byte header plus a short
/// name. readdir parses-and-discards this for every entry, so the COW collection
/// previously cloned it into an intermediate `Vec<u8>` per entry.
const DIR_ITEM_LEN: usize = 40;

/// Build a directory's DIR_ITEM + DIR_INDEX span as readdir's COW path scans it
/// (`[DIR_ITEM offset 0, DIR_INDEX offset MAX]`): one of each per file.
fn build_dir_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(1 << 22).expect("tree");
    let payload = vec![0_u8; DIR_ITEM_LEN];
    for i in 0..FILES as u64 {
        tree.insert(
            BtrfsKey {
                objectid: DIR_INODE,
                item_type: BTRFS_ITEM_DIR_ITEM,
                offset: i,
            },
            &payload,
        )
        .expect("insert dir_item");
        tree.insert(
            BtrfsKey {
                objectid: DIR_INODE,
                item_type: BTRFS_ITEM_DIR_INDEX,
                offset: i,
            },
            &payload,
        )
        .expect("insert dir_index");
    }
    tree
}

/// A/B for the readdir COW collection (bd-h9awv migration): the old path called
/// `range`, cloning every DIR entry's bytes into a throwaway `Vec<u8>` before
/// parsing; the new path uses `range_with` to parse against the borrowed node
/// bytes. The `ls` of a large directory walks 2 rows per file, so the clone is
/// paid `2 * files` times per readdir.
fn bench_readdir_collect(c: &mut Criterion) {
    let tree = build_dir_tree();
    let start = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_ITEM,
        offset: 0,
    };
    let end = BtrfsKey {
        objectid: DIR_INODE,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: u64::MAX,
    };

    // Isomorphism: range_with visits the same (key, bytes) sequence as range.
    let materialised = tree.range(&start, &end).expect("range");
    let mut collected = Vec::new();
    tree.range_with(&start, &end, |k, v| collected.push((k, v.to_vec())))
        .expect("range_with");
    assert_eq!(materialised.len(), FILES * 2);
    assert_eq!(materialised, collected);

    let mut group = c.benchmark_group("btrfs_readdir_collect");
    group.sample_size(20);
    // Old: clone each entry's bytes, then "parse" (here: sum lengths).
    group.bench_function("range_clones_each_entry", |b| {
        b.iter(|| {
            let items = tree.range(black_box(&start), black_box(&end)).unwrap();
            let mut bytes = 0_usize;
            for (_k, v) in &items {
                bytes += v.len();
            }
            black_box(bytes)
        });
    });
    // New: borrow each entry's bytes, parse in place — no per-entry allocation.
    group.bench_function("range_with_zero_copy", |b| {
        b.iter(|| {
            let mut bytes = 0_usize;
            tree.range_with(black_box(&start), black_box(&end), |_k, v| bytes += v.len())
                .unwrap();
            black_box(bytes)
        });
    });
    group.finish();
}

criterion_group!(readdir_dedup, bench_readdir_dedup, bench_readdir_collect);
criterion_main!(readdir_dedup);
