#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for writable btrfs encoded-read extent lookup (bd-chbrj).
//!
//! In the writable path, `btrfs_encoded_read` queries the in-memory COW fs tree.
//! The old shape ranged every EXTENT_DATA item for the inode and then searched
//! for the one covering `file_offset`. The new shape seeks the predecessor key
//! with `floor_key`, fetches that single item, and validates that it covers the
//! requested offset.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_FILE_EXTENT_REG, BTRFS_ITEM_EXTENT_DATA, BtrfsBTree, BtrfsExtentData, BtrfsKey,
    InMemoryCowBtrfsTree, parse_extent_data,
};
use std::hint::black_box;

const INO: u64 = 257;
const EXTENT_COUNT: u64 = 4096;
const EXTENT_LEN: u64 = 4096;

fn extent_payload(offset: u64) -> Vec<u8> {
    BtrfsExtentData::Regular {
        generation: 1,
        ram_bytes: EXTENT_LEN,
        extent_type: BTRFS_FILE_EXTENT_REG,
        compression: 0,
        disk_bytenr: 1_000_000 + offset,
        disk_num_bytes: EXTENT_LEN,
        extent_offset: 0,
        num_bytes: EXTENT_LEN,
    }
    .to_bytes()
}

fn extent_key(offset: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: INO,
        item_type: BTRFS_ITEM_EXTENT_DATA,
        offset,
    }
}

fn build_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(64).expect("tree");
    for i in 0..EXTENT_COUNT {
        let offset = i * EXTENT_LEN;
        tree.insert(extent_key(offset), &extent_payload(offset))
            .expect("insert extent");
    }
    tree.validate_invariants().expect("valid tree");
    tree
}

fn covers(file_offset: u64, start: u64, extent: &BtrfsExtentData) -> bool {
    let end = match extent {
        BtrfsExtentData::Inline { data, .. } => start.saturating_add(data.len() as u64),
        BtrfsExtentData::Regular { num_bytes, .. } => start.saturating_add(*num_bytes),
    };
    file_offset >= start && file_offset < end
}

fn range_all_find(tree: &InMemoryCowBtrfsTree, file_offset: u64) -> Option<(u64, Vec<u8>)> {
    let start = extent_key(0);
    let end = extent_key(u64::MAX);
    tree.range(&start, &end)
        .expect("range")
        .into_iter()
        .find(|(key, data)| {
            parse_extent_data(data).is_ok_and(|extent| covers(file_offset, key.offset, &extent))
        })
        .map(|(key, data)| (key.offset, data))
}

fn floor_key_find(tree: &InMemoryCowBtrfsTree, file_offset: u64) -> Option<(u64, Vec<u8>)> {
    let seek = extent_key(file_offset);
    let key = tree.floor_key(&seek).expect("floor key")?;
    if key.objectid != INO || key.item_type != BTRFS_ITEM_EXTENT_DATA {
        return None;
    }
    tree.get(&key).and_then(|data| {
        parse_extent_data(&data)
            .is_ok_and(|extent| covers(file_offset, key.offset, &extent))
            .then_some((key.offset, data))
    })
}

fn probe_offsets() -> Vec<u64> {
    let max_offset = EXTENT_COUNT * EXTENT_LEN;
    let mut x = 0x243f_6a88_85a3_08d3_u64;
    (0..1024)
        .map(|_| {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let extent = (x >> 12) % EXTENT_COUNT;
            ((extent * EXTENT_LEN) + (x % EXTENT_LEN)).min(max_offset - 1)
        })
        .collect()
}

fn bench_btrfs_encoded_read_covering_extent(c: &mut Criterion) {
    let tree = build_tree();
    let probes = probe_offsets();

    for &offset in &probes {
        let old = range_all_find(&tree, offset).map(|(start, _)| start);
        let new = floor_key_find(&tree, offset).map(|(start, _)| start);
        assert_eq!(old, new, "covering extent diverged at offset {offset}");
    }

    let mut group = c.benchmark_group("btrfs_encoded_read_covering_extent_4096");
    group.bench_function("range_all_find", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &offset in &probes {
                let (start, data) =
                    range_all_find(black_box(&tree), black_box(offset)).expect("covering extent");
                acc = acc.wrapping_add(start).wrapping_add(data.len() as u64);
            }
            black_box(acc)
        });
    });
    group.bench_function("floor_key_get", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &offset in &probes {
                let (start, data) =
                    floor_key_find(black_box(&tree), black_box(offset)).expect("covering extent");
                acc = acc.wrapping_add(start).wrapping_add(data.len() as u64);
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(
    btrfs_encoded_read_covering_extent,
    bench_btrfs_encoded_read_covering_extent
);
criterion_main!(btrfs_encoded_read_covering_extent);
