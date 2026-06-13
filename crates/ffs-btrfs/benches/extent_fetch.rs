#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B benchmark for the per-read extent fetch in `btrfs_read_file` (bd-4milp).
//!
//! The read path queries an inode's `EXTENT_DATA` items from the fs tree to
//! assemble the requested byte range. The prior query ranged every extent of the
//! inode (`offset 0 .. u64::MAX`) on every read, so a fragmented file paid an
//! O(extents) scan per read regardless of read size. Capping the upper key at the
//! read window's end (`offset + size`) bounds the scan to the extents that can
//! actually overlap the read — this benches that exact change against a tree
//! holding a deep run of single-block extents.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_ITEM_EXTENT_DATA, BtrfsBTree, BtrfsExtentData, BtrfsKey, InMemoryCowBtrfsTree,
    parse_extent_data,
};
use std::hint::black_box;

const INODE: u64 = 257;
const EXTENTS: u64 = 1024;
const BLOCK: u64 = 4096;
/// A representative on-disk `EXTENT_DATA` item payload size.
const ITEM_LEN: usize = 53;

fn build_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(1 << 21).expect("tree");
    let payload = vec![0_u8; ITEM_LEN];
    for i in 0..EXTENTS {
        let key = BtrfsKey {
            objectid: INODE,
            item_type: BTRFS_ITEM_EXTENT_DATA,
            offset: i * BLOCK,
        };
        tree.insert(key, &payload).expect("insert extent item");
    }
    tree
}

fn key(offset: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: INODE,
        item_type: BTRFS_ITEM_EXTENT_DATA,
        offset,
    }
}

fn bench_extent_fetch(c: &mut Criterion) {
    let tree = build_tree();
    // A 4 KiB read at file offset 0 overlaps exactly one extent.
    let start = key(0);
    let full_end = key(u64::MAX);
    let bounded_end = key(BLOCK); // offset(0) + size(4096)

    // Isomorphism: the bounded query returns every extent the unbounded query
    // returns that can overlap the window (key.offset <= offset + size).
    let full = tree.range(&start, &full_end).expect("full range");
    let bounded = tree.range(&start, &bounded_end).expect("bounded range");
    assert_eq!(full.len() as u64, EXTENTS);
    assert!(bounded.iter().all(|(k, _)| k.offset <= BLOCK));
    assert!(
        bounded
            .iter()
            .all(|(k, v)| full.iter().any(|(fk, fv)| fk == k && fv == v))
    );

    let mut group = c.benchmark_group("btrfs_extent_fetch_prefix_read");
    group.bench_function("unbounded_scan_all_extents", |b| {
        b.iter(|| black_box(tree.range(black_box(&start), black_box(&full_end)).unwrap()));
    });
    group.bench_function("bounded_to_read_window", |b| {
        b.iter(|| {
            black_box(
                tree.range(black_box(&start), black_box(&bounded_end))
                    .unwrap(),
            )
        });
    });
    group.finish();
}

fn bench_extent_fetch_eof(c: &mut Criterion) {
    let tree = build_tree();
    // A 4 KiB read at the LAST extent of the file. With only the upper bound
    // capped (lower bound 0), the query still scans every extent up to here; the
    // floor seek skips straight to the covering extent.
    let read_off = (EXTENTS - 1) * BLOCK;
    let read_end = read_off + BLOCK;
    let from_zero = key(0);
    let end = key(read_end);
    let seek = key(read_off);

    // Isomorphism: the floor-seeked window holds exactly the extents that can
    // overlap the read; the scan-from-zero window is a superset.
    let floor = tree
        .floor_key(&seek)
        .expect("floor")
        .expect("covering extent");
    let bounded = tree.range(&floor, &end).expect("bounded range");
    let full = tree.range(&from_zero, &end).expect("full range");
    assert_eq!(full.len() as u64, EXTENTS);
    assert!(bounded.len() <= 2);
    assert!(
        bounded
            .iter()
            .all(|(k, v)| full.iter().any(|(fk, fv)| fk == k && fv == v))
    );

    let mut group = c.benchmark_group("btrfs_extent_fetch_eof_read");
    group.bench_function("lower_bound_zero_scan_from_start", |b| {
        b.iter(|| black_box(tree.range(black_box(&from_zero), black_box(&end)).unwrap()));
    });
    group.bench_function("floor_seek_then_bounded", |b| {
        b.iter(|| {
            let f = tree.floor_key(black_box(&seek)).unwrap().unwrap();
            black_box(tree.range(black_box(&f), black_box(&end)).unwrap())
        });
    });
    group.finish();
}

fn bench_range_vs_range_with(c: &mut Criterion) {
    let tree = build_tree();
    let from_zero = key(0);
    let to_max = key(u64::MAX);

    // Isomorphism: range_with yields the same (key, bytes) sequence as range.
    let materialised = tree.range(&from_zero, &to_max).expect("range");
    let mut collected = Vec::new();
    tree.range_with(&from_zero, &to_max, |k, v| collected.push((k, v.to_vec())))
        .expect("range_with");
    assert_eq!(materialised.len() as u64, EXTENTS);
    assert_eq!(materialised, collected);

    let mut group = c.benchmark_group("btrfs_whole_file_scan");
    // `range` clones every item's bytes into an intermediate Vec<u8>.
    group.bench_function("range_clones_each_item", |b| {
        b.iter(|| {
            black_box(
                tree.range(black_box(&from_zero), black_box(&to_max))
                    .unwrap(),
            )
        });
    });
    // `range_with` borrows each item's bytes — no per-item allocation.
    group.bench_function("range_with_zero_copy", |b| {
        b.iter(|| {
            let mut bytes = 0_usize;
            tree.range_with(black_box(&from_zero), black_box(&to_max), |_k, v| {
                bytes += v.len();
            })
            .unwrap();
            black_box(bytes)
        });
    });
    group.finish();
}

/// Build a tree of valid `Regular` EXTENT_DATA items (the read path parses
/// these into `BtrfsExtentData`), one single-block extent per `BLOCK`.
fn build_regular_extent_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(1 << 21).expect("tree");
    for i in 0..EXTENTS {
        let payload = BtrfsExtentData::Regular {
            generation: 7,
            ram_bytes: BLOCK,
            extent_type: 1, // BTRFS_FILE_EXTENT_REG
            compression: 0,
            disk_bytenr: 0x10_0000 + i * BLOCK,
            disk_num_bytes: BLOCK,
            extent_offset: 0,
            num_bytes: BLOCK,
        }
        .to_bytes();
        tree.insert(key(i * BLOCK), &payload)
            .expect("insert extent");
    }
    tree
}

fn bench_read_file_extent_parse(c: &mut Criterion) {
    let tree = build_regular_extent_tree();
    let from_zero = key(0);
    let to_max = key(u64::MAX);

    // The read path materialises `Vec<(u64, BtrfsExtentData)>`. Old: `range`
    // clones each item's bytes into a throwaway Vec, then `parse_extent_data`
    // reads and discards those bytes. New: `range_with` parses straight from the
    // borrowed node bytes — no per-extent clone. Both produce the same vector.
    let old = parse_via_range(&tree, &from_zero, &to_max);
    let new = parse_via_range_with(&tree, &from_zero, &to_max);
    assert_eq!(old.len() as u64, EXTENTS);
    assert_eq!(old, new);

    let mut group = c.benchmark_group("btrfs_read_file_extent_parse");
    group.bench_function("range_clone_then_parse", |b| {
        b.iter(|| {
            black_box(parse_via_range(
                &tree,
                black_box(&from_zero),
                black_box(&to_max),
            ))
        });
    });
    group.bench_function("range_with_parse_in_place", |b| {
        b.iter(|| {
            black_box(parse_via_range_with(
                &tree,
                black_box(&from_zero),
                black_box(&to_max),
            ))
        });
    });
    group.finish();
}

fn parse_via_range(
    tree: &InMemoryCowBtrfsTree,
    start: &BtrfsKey,
    end: &BtrfsKey,
) -> Vec<(u64, BtrfsExtentData)> {
    let items = tree.range(start, end).expect("range");
    items
        .iter()
        .map(|(k, v)| (k.offset, parse_extent_data(v).expect("parse")))
        .collect()
}

fn parse_via_range_with(
    tree: &InMemoryCowBtrfsTree,
    start: &BtrfsKey,
    end: &BtrfsKey,
) -> Vec<(u64, BtrfsExtentData)> {
    let mut out = Vec::new();
    tree.range_with(start, end, |k, v| {
        out.push((k.offset, parse_extent_data(v).expect("parse")));
    })
    .expect("range_with");
    out
}

criterion_group!(
    extent_fetch,
    bench_extent_fetch,
    bench_extent_fetch_eof,
    bench_range_vs_range_with,
    bench_read_file_extent_parse
);
criterion_main!(extent_fetch);
