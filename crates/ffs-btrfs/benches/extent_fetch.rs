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
use ffs_btrfs::{BTRFS_ITEM_EXTENT_DATA, BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree};
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
        b.iter(|| black_box(tree.range(black_box(&start), black_box(&bounded_end)).unwrap()));
    });
    group.finish();
}

criterion_group!(extent_fetch, bench_extent_fetch);
criterion_main!(extent_fetch);
