#![forbid(unsafe_code)]

//! Same-machine A/B for the btrfs sequential-write COW mutation lane
//! (bd-hfkty). A 1 MiB / 4 KiB append workload performs 256 writes; each write
//! adds one `EXTENT_DATA` item for the file and updates the existing
//! `INODE_ITEM`. The legacy path applies those two same-tree mutations
//! separately, so it clones and retires the COW leaf twice per write while the
//! batched path does both mutations in one root-leaf COW.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_INODE_ITEM, BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree,
};
use std::hint::black_box;

const WRITES: u64 = 256;
const SECTOR: u64 = 4096;
const MAX_ITEMS: usize = 512;
const FILE_OBJECTID: u64 = 257;

fn inode_key() -> BtrfsKey {
    BtrfsKey {
        objectid: FILE_OBJECTID,
        item_type: BTRFS_ITEM_INODE_ITEM,
        offset: 0,
    }
}

fn extent_key(write_idx: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: FILE_OBJECTID,
        item_type: BTRFS_ITEM_EXTENT_DATA,
        offset: write_idx * SECTOR,
    }
}

fn inode_payload(write_idx: u64) -> Vec<u8> {
    let mut payload = vec![0_u8; 160];
    payload[16..24].copy_from_slice(&((write_idx + 1) * SECTOR).to_le_bytes());
    payload[24..32].copy_from_slice(&((write_idx + 1) * SECTOR).to_le_bytes());
    payload
}

fn extent_payload(write_idx: u64) -> Vec<u8> {
    let mut payload = vec![0_u8; 53];
    payload[0..8].copy_from_slice(&(write_idx + 1).to_le_bytes());
    payload[13..21].copy_from_slice(&(0x1000_0000 + write_idx * SECTOR).to_le_bytes());
    payload[21..29].copy_from_slice(&SECTOR.to_le_bytes());
    payload[37..45].copy_from_slice(&SECTOR.to_le_bytes());
    payload
}

fn fresh_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(MAX_ITEMS).expect("tree");
    tree.insert(inode_key(), &inode_payload(0))
        .expect("seed inode item");
    tree
}

fn run_sequential_insert_then_update(mut tree: InMemoryCowBtrfsTree) -> InMemoryCowBtrfsTree {
    for i in 0..WRITES {
        tree.insert(extent_key(i), &extent_payload(i))
            .expect("insert extent item");
        tree.update(&inode_key(), &inode_payload(i))
            .expect("update inode item");
    }
    tree
}

fn run_batched_insert_then_update(mut tree: InMemoryCowBtrfsTree) -> InMemoryCowBtrfsTree {
    for i in 0..WRITES {
        tree.insert_then_update(
            extent_key(i),
            &extent_payload(i),
            &inode_key(),
            &inode_payload(i),
        )
        .expect("batch insert extent and update inode item");
    }
    tree
}

fn tree_digest(tree: &InMemoryCowBtrfsTree) -> u64 {
    tree.validate_invariants().expect("tree invariants");
    let all = tree
        .range(
            &BtrfsKey {
                objectid: 0,
                item_type: 0,
                offset: 0,
            },
            &BtrfsKey {
                objectid: u64::MAX,
                item_type: u8::MAX,
                offset: u64::MAX,
            },
        )
        .expect("full range");
    assert_eq!(
        u64::try_from(all.len()).expect("entry count fits u64"),
        WRITES + 1
    );
    all.iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |acc, (key, data)| {
            let keyed = acc
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(key.objectid)
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(u64::from(key.item_type))
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(key.offset);
            data.iter().fold(keyed, |data_acc, byte| {
                data_acc
                    .wrapping_mul(0x100_0000_01b3)
                    .wrapping_add(u64::from(*byte))
            })
        })
}

fn bench_cow_write_mutation(c: &mut Criterion) {
    let sequential = run_sequential_insert_then_update(fresh_tree());
    let batched = run_batched_insert_then_update(fresh_tree());
    assert_eq!(
        tree_digest(&sequential),
        tree_digest(&batched),
        "batched COW mutation diverged from sequential insert/update"
    );

    let mut group = c.benchmark_group("btrfs_cow_write_mutation_256x4k");
    group.bench_function("sequential_insert_then_update", |b| {
        b.iter_batched(
            fresh_tree,
            |tree| black_box(tree_digest(&run_sequential_insert_then_update(tree))),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("batched_insert_then_update", |b| {
        b.iter_batched(
            fresh_tree,
            |tree| black_box(tree_digest(&run_batched_insert_then_update(tree))),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(cow_write_mutation, bench_cow_write_mutation);
criterion_main!(cow_write_mutation);
