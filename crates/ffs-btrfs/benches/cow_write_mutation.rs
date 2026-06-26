#![forbid(unsafe_code)]

//! Same-machine A/B for the btrfs sequential-write COW mutation lane
//! (bd-hfkty). A 1 MiB / 4 KiB append workload performs 256 writes; each write
//! adds one `EXTENT_DATA` item for the file and updates the existing
//! `INODE_ITEM`. The legacy path applies those two same-tree mutations
//! separately, so it clones and retires the COW leaf twice per write while the
//! batched path does both mutations in one root-leaf COW.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_ITEM_DIR_INDEX, BTRFS_ITEM_DIR_ITEM, BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_INODE_ITEM,
    BTRFS_ITEM_INODE_REF, BtrfsBTree, BtrfsKey, InMemoryCowBtrfsTree,
};
use std::hint::black_box;

const WRITES: u64 = 256;
const SECTOR: u64 = 4096;
const MAX_ITEMS: usize = 512;
const FILE_OBJECTID: u64 = 257;
const RENAME_OPS: u64 = 256;
const RENAME_PREFILL: u64 = 768;
const RENAME_MAX_ITEMS: usize = 64;
const RENAME_PARENT_OBJECTID: u64 = 1_000_000;
const RENAME_CHILD_BASE: u64 = 2_000_000;

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

fn rename_parent_key() -> BtrfsKey {
    BtrfsKey {
        objectid: RENAME_PARENT_OBJECTID,
        item_type: BTRFS_ITEM_INODE_ITEM,
        offset: 0,
    }
}

fn rename_old_dir_item_key(rename_idx: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: RENAME_PARENT_OBJECTID,
        item_type: BTRFS_ITEM_DIR_ITEM,
        offset: 10_000 + rename_idx * 2,
    }
}

fn rename_new_dir_item_key(rename_idx: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: RENAME_PARENT_OBJECTID,
        item_type: BTRFS_ITEM_DIR_ITEM,
        offset: 10_001 + rename_idx * 2,
    }
}

fn rename_old_dir_index_key(rename_idx: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: RENAME_PARENT_OBJECTID,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: 20_000 + rename_idx * 2,
    }
}

fn rename_new_dir_index_key(rename_idx: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: RENAME_PARENT_OBJECTID,
        item_type: BTRFS_ITEM_DIR_INDEX,
        offset: 20_001 + rename_idx * 2,
    }
}

fn rename_ref_key(rename_idx: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: RENAME_CHILD_BASE + rename_idx,
        item_type: BTRFS_ITEM_INODE_REF,
        offset: RENAME_PARENT_OBJECTID,
    }
}

fn fresh_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(MAX_ITEMS).expect("tree");
    tree.insert(inode_key(), &inode_payload(0))
        .expect("seed inode item");
    tree
}

fn rename_payload(rename_idx: u64, tag: u64) -> Vec<u8> {
    let mut payload = vec![0_u8; 64];
    payload[0..8].copy_from_slice(&rename_idx.to_le_bytes());
    payload[8..16].copy_from_slice(&tag.to_le_bytes());
    payload[16..24].copy_from_slice(&(RENAME_CHILD_BASE + rename_idx).to_le_bytes());
    payload[24..32].copy_from_slice(&(rename_idx.wrapping_mul(37) ^ tag).to_le_bytes());
    payload
}

fn fresh_rename_tree() -> InMemoryCowBtrfsTree {
    let mut tree = InMemoryCowBtrfsTree::new(RENAME_MAX_ITEMS).expect("rename tree");
    tree.insert(rename_parent_key(), &rename_payload(0, 1))
        .expect("seed parent inode");
    for i in 0..RENAME_OPS {
        let old_payload = rename_payload(i, 10);
        let old_ref_payload = rename_payload(i, 11);
        tree.insert(rename_old_dir_item_key(i), &old_payload)
            .expect("seed old dir item");
        tree.insert(rename_old_dir_index_key(i), &old_payload)
            .expect("seed old dir index");
        tree.insert(rename_ref_key(i), &old_ref_payload)
            .expect("seed old inode ref");
    }
    for i in 0..RENAME_PREFILL {
        let key = BtrfsKey {
            objectid: 10_000_000 + i * 11,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: 0,
        };
        tree.insert(key, &rename_payload(i, 90))
            .expect("seed prefill");
    }
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

fn run_bulk_insert_many_then_update(mut tree: InMemoryCowBtrfsTree) -> InMemoryCowBtrfsTree {
    let payloads: Vec<_> = (0..WRITES)
        .map(|i| (extent_key(i), extent_payload(i)))
        .collect();
    let refs: Vec<_> = payloads
        .iter()
        .map(|(key, payload)| (*key, payload.as_slice()))
        .collect();
    tree.insert_many_then_update(&refs, &inode_key(), &inode_payload(WRITES - 1))
        .expect("bulk insert extents and final inode update");
    tree
}

fn run_two_phase_rename_mutation(mut tree: InMemoryCowBtrfsTree) -> InMemoryCowBtrfsTree {
    for i in 0..RENAME_OPS {
        let removals = [
            rename_old_dir_item_key(i),
            rename_old_dir_index_key(i),
            rename_ref_key(i),
        ];
        tree.remove_many(&removals)
            .expect("remove old rename items");
        let new_dir_payload = rename_payload(i, 20);
        let new_ref_payload = rename_payload(i, 21);
        let inserts = [
            (rename_new_dir_item_key(i), new_dir_payload.as_slice()),
            (rename_new_dir_index_key(i), new_dir_payload.as_slice()),
            (rename_ref_key(i), new_ref_payload.as_slice()),
        ];
        let parent_payload = rename_payload(i, 30);
        tree.insert_many_then_update(&inserts, &rename_parent_key(), &parent_payload)
            .expect("insert new rename items and update parent");
    }
    tree
}

fn run_fused_rename_mutation(mut tree: InMemoryCowBtrfsTree) -> InMemoryCowBtrfsTree {
    for i in 0..RENAME_OPS {
        let removals = [
            rename_old_dir_item_key(i),
            rename_old_dir_index_key(i),
            rename_ref_key(i),
        ];
        let new_dir_payload = rename_payload(i, 20);
        let new_ref_payload = rename_payload(i, 21);
        let inserts = [
            (rename_new_dir_item_key(i), new_dir_payload.as_slice()),
            (rename_new_dir_index_key(i), new_dir_payload.as_slice()),
            (rename_ref_key(i), new_ref_payload.as_slice()),
        ];
        let parent_payload = rename_payload(i, 30);
        tree.remove_many_then_insert_many_then_update(
            &removals,
            &inserts,
            &rename_parent_key(),
            &parent_payload,
        )
        .expect("fused rename mutation");
    }
    tree
}

fn tree_digest_with_expected(tree: &InMemoryCowBtrfsTree, expected_entries: u64) -> u64 {
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
        expected_entries
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

fn tree_digest(tree: &InMemoryCowBtrfsTree) -> u64 {
    tree_digest_with_expected(tree, WRITES + 1)
}

fn rename_tree_digest(tree: &InMemoryCowBtrfsTree) -> u64 {
    tree_digest_with_expected(tree, RENAME_PREFILL + 1 + RENAME_OPS * 3)
}

fn bench_cow_write_mutation(c: &mut Criterion) {
    let sequential = run_sequential_insert_then_update(fresh_tree());
    let batched = run_batched_insert_then_update(fresh_tree());
    let bulk = run_bulk_insert_many_then_update(fresh_tree());
    assert_eq!(
        tree_digest(&sequential),
        tree_digest(&batched),
        "batched COW mutation diverged from sequential insert/update"
    );
    assert_eq!(
        tree_digest(&sequential),
        tree_digest(&bulk),
        "bulk COW mutation diverged from sequential insert/update"
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
    group.bench_function("bulk_insert_many_then_update", |b| {
        b.iter_batched(
            fresh_tree,
            |tree| black_box(tree_digest(&run_bulk_insert_many_then_update(tree))),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_cow_rename_mutation(c: &mut Criterion) {
    let two_phase = run_two_phase_rename_mutation(fresh_rename_tree());
    let fused = run_fused_rename_mutation(fresh_rename_tree());
    assert_eq!(
        rename_tree_digest(&two_phase),
        rename_tree_digest(&fused),
        "fused rename COW mutation diverged from remove_many + insert_many_then_update"
    );

    let mut group = c.benchmark_group("btrfs_cow_rename_mutation_256");
    group.bench_function("two_phase_remove_many_insert_many_update", |b| {
        b.iter_batched(
            fresh_rename_tree,
            |tree| black_box(rename_tree_digest(&run_two_phase_rename_mutation(tree))),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("fused_remove_many_insert_many_update", |b| {
        b.iter_batched(
            fresh_rename_tree,
            |tree| black_box(rename_tree_digest(&run_fused_rename_mutation(tree))),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(
    cow_write_mutation,
    bench_cow_write_mutation,
    bench_cow_rename_mutation
);
criterion_main!(cow_write_mutation);
