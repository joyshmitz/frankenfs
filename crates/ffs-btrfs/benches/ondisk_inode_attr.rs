#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B benchmark for the on-disk btrfs read-only getattr/stat lower bound
//! (bd-w6h4m).
//!
//! `btrfs_read_inode_attr` (read-only mount `getattr`/`stat`, reached via FUSE
//! `getattr`/`lookup`/`readlink` and many other ops) only needs the single
//! `INODE_ITEM` of an inode. It previously walked the ENTIRE inode object out
//! of the fs B-tree and then filtered to that one item — so a `stat()` of a
//! large fragmented file read every leaf holding an `EXTENT_DATA` item, i.e.
//! O(extents) node reads per stat. The `INODE_ITEM` (type 1) sorts before all
//! `EXTENT_DATA` (type 108), so narrowing the descent to the `INODE_ITEM` key
//! span reads only the leaf holding it — O(log N) nodes.
//!
//! This benches a two-level tree (one internal root over an `INODE_ITEM` leaf +
//! N single-extent leaves): the full-object walk reads root + all N+1 leaves;
//! the inode-item-range walk reads root + the inode-item leaf.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_HEADER_SIZE, BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_SIZE,
    BTRFS_KEY_PTR_SIZE, BtrfsChunkEntry, BtrfsKey, BtrfsStripe, walk_tree_range,
};
use std::cell::Cell;
use std::collections::HashMap;
use std::hint::black_box;

const NODESIZE: u32 = 4096;
const INODE: u64 = 257;
/// Number of `EXTENT_DATA` leaves (the inode item adds one more leaf).
const EXTENTS: u64 = 64;
const BLOCK: u64 = 4096;
/// A representative on-disk `EXTENT_DATA` item payload size.
const EXT_LEN: usize = 53;
/// A representative on-disk `INODE_ITEM` payload size.
const INODE_LEN: usize = 160;
const ROOT_LOGICAL: u64 = 0x1_0000;

fn stamp_crc32c(block: &mut [u8]) {
    let csum = ffs_types::crc32c(&block[0x20..]);
    block[0..4].copy_from_slice(&csum.to_le_bytes());
}

fn write_header(block: &mut [u8], bytenr: u64, nritems: u32, level: u8) {
    block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
    block[0x50..0x58].copy_from_slice(&10_u64.to_le_bytes()); // generation
    block[0x58..0x60].copy_from_slice(&1_u64.to_le_bytes()); // owner (FS_TREE)
    block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
    block[0x64] = level;
}

fn write_leaf_item(block: &mut [u8], idx: usize, key: &BtrfsKey, data_off: u32, payload: &[u8]) {
    let base = BTRFS_HEADER_SIZE + idx * BTRFS_ITEM_SIZE;
    let enc = data_off - u32::try_from(BTRFS_HEADER_SIZE).unwrap();
    block[base..base + 8].copy_from_slice(&key.objectid.to_le_bytes());
    block[base + 8] = key.item_type;
    block[base + 9..base + 17].copy_from_slice(&key.offset.to_le_bytes());
    block[base + 17..base + 21].copy_from_slice(&enc.to_le_bytes());
    block[base + 21..base + 25].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let start = data_off as usize;
    block[start..start + payload.len()].copy_from_slice(payload);
}

fn write_key_ptr(block: &mut [u8], idx: usize, key: &BtrfsKey, blockptr: u64) {
    let base = BTRFS_HEADER_SIZE + idx * BTRFS_KEY_PTR_SIZE;
    block[base..base + 8].copy_from_slice(&key.objectid.to_le_bytes());
    block[base + 8] = key.item_type;
    block[base + 9..base + 17].copy_from_slice(&key.offset.to_le_bytes());
    block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
    block[base + 25..base + 33].copy_from_slice(&10_u64.to_le_bytes()); // generation
}

fn inode_key() -> BtrfsKey {
    BtrfsKey {
        objectid: INODE,
        item_type: BTRFS_ITEM_INODE_ITEM,
        offset: 0,
    }
}

fn ext_key(offset: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: INODE,
        item_type: BTRFS_ITEM_EXTENT_DATA,
        offset,
    }
}

/// Build a two-level tree: one internal root over leaf 0 (the `INODE_ITEM`) and
/// `EXTENTS` further leaves, leaf `i+1` holding a single `EXTENT_DATA` item
/// keyed `(INODE, EXTENT_DATA, i*BLOCK)`.
fn build_tree() -> HashMap<u64, Vec<u8>> {
    let mut blocks = HashMap::new();
    let ns = NODESIZE as usize;
    let total = EXTENTS + 1;

    let mut root = vec![0_u8; ns];
    write_header(&mut root, ROOT_LOGICAL, total as u32, 1);

    // Leaf 0: the INODE_ITEM.
    let inode_logical = 0x2_0000;
    write_key_ptr(&mut root, 0, &inode_key(), inode_logical);
    let mut inode_leaf = vec![0_u8; ns];
    write_header(&mut inode_leaf, inode_logical, 1, 0);
    write_leaf_item(
        &mut inode_leaf,
        0,
        &inode_key(),
        NODESIZE - INODE_LEN as u32,
        &[0xcd_u8; INODE_LEN],
    );
    stamp_crc32c(&mut inode_leaf);
    blocks.insert(inode_logical, inode_leaf);

    // Leaves 1..=EXTENTS: one EXTENT_DATA each.
    let ext_payload = vec![0xab_u8; EXT_LEN];
    for i in 0..EXTENTS {
        let leaf_logical = 0x2_0000 + (i + 1) * u64::from(NODESIZE);
        let key = ext_key(i * BLOCK);
        write_key_ptr(&mut root, (i + 1) as usize, &key, leaf_logical);

        let mut leaf = vec![0_u8; ns];
        write_header(&mut leaf, leaf_logical, 1, 0);
        write_leaf_item(&mut leaf, 0, &key, NODESIZE - EXT_LEN as u32, &ext_payload);
        stamp_crc32c(&mut leaf);
        blocks.insert(leaf_logical, leaf);
    }

    stamp_crc32c(&mut root);
    blocks.insert(ROOT_LOGICAL, root);
    blocks
}

fn identity_chunks() -> Vec<BtrfsChunkEntry> {
    vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: 0,
        },
        length: 0x4000_0000,
        owner: 2,
        stripe_len: 0x1_0000,
        chunk_type: 2,
        io_align: 4096,
        io_width: 4096,
        sector_size: 4096,
        num_stripes: 1,
        sub_stripes: 0,
        stripes: vec![BtrfsStripe {
            devid: 1,
            offset: 0,
            dev_uuid: [0_u8; 16],
        }],
    }]
}

/// Whole-object bounds: `[(INODE, 0, 0), (INODE + 1, 0, 0))`.
fn object_bounds() -> (BtrfsKey, BtrfsKey) {
    (
        BtrfsKey {
            objectid: INODE,
            item_type: 0,
            offset: 0,
        },
        BtrfsKey {
            objectid: INODE + 1,
            item_type: 0,
            offset: 0,
        },
    )
}

/// `INODE_ITEM`-only bounds: `[(INODE, INODE_ITEM, 0), (INODE, INODE_ITEM, MAX)]`.
fn inode_item_bounds() -> (BtrfsKey, BtrfsKey) {
    (
        inode_key(),
        BtrfsKey {
            objectid: INODE,
            item_type: BTRFS_ITEM_INODE_ITEM,
            offset: u64::MAX,
        },
    )
}

/// Assert both walks surface the same single `INODE_ITEM` while the narrowed
/// walk reads at least 4x fewer nodes.
fn verify_equivalence(blocks: &HashMap<u64, Vec<u8>>, chunks: &[BtrfsChunkEntry]) {
    let (object_lo, object_hi) = object_bounds();
    let (inode_lo, inode_hi) = inode_item_bounds();
    let reads = Cell::new(0_u32);
    let mut read_physical = |phys: u64| {
        reads.set(reads.get() + 1);
        blocks
            .get(&phys)
            .cloned()
            .ok_or(ffs_types::ParseError::InvalidField {
                field: "physical",
                reason: "block not in bench image",
            })
    };

    reads.set(0);
    let full = walk_tree_range(
        &mut read_physical,
        chunks,
        ROOT_LOGICAL,
        NODESIZE,
        0,
        object_lo,
        object_hi,
    )
    .expect("full object walk");
    let full_reads = reads.get();

    reads.set(0);
    let narrowed = walk_tree_range(
        &mut read_physical,
        chunks,
        ROOT_LOGICAL,
        NODESIZE,
        0,
        inode_lo,
        inode_hi,
    )
    .expect("inode-item walk");
    let narrowed_reads = reads.get();

    let full_inode = full
        .iter()
        .find(|e| e.key.item_type == BTRFS_ITEM_INODE_ITEM)
        .expect("inode item in full walk");
    assert_eq!(narrowed.len(), 1);
    assert_eq!(narrowed[0].key, inode_key());
    assert_eq!(narrowed[0].key, full_inode.key);
    assert_eq!(narrowed[0].data, full_inode.data);
    assert!(
        narrowed_reads * 4 < full_reads,
        "inode-range read {narrowed_reads} nodes vs full {full_reads} (expected >=4x fewer)"
    );
}

fn bench_ondisk_inode_attr(c: &mut Criterion) {
    let blocks = build_tree();
    let chunks = identity_chunks();
    let (object_lo, object_hi) = object_bounds();
    let (inode_lo, inode_hi) = inode_item_bounds();

    verify_equivalence(&blocks, &chunks);

    let mut group = c.benchmark_group("btrfs_ondisk_getattr");
    // Whole-object walk: descend over every leaf of the inode (root + all N+1).
    group.bench_function("walk_whole_object", |b| {
        let mut rp = |phys: u64| {
            blocks
                .get(&phys)
                .cloned()
                .ok_or(ffs_types::ParseError::InvalidField {
                    field: "physical",
                    reason: "missing",
                })
        };
        b.iter(|| {
            black_box(
                walk_tree_range(
                    &mut rp,
                    black_box(&chunks),
                    ROOT_LOGICAL,
                    NODESIZE,
                    0,
                    object_lo,
                    object_hi,
                )
                .unwrap(),
            )
        });
    });
    // Narrowed walk: descend only to the INODE_ITEM leaf (root + 1 leaf).
    group.bench_function("range_to_inode_item", |b| {
        let mut rp = |phys: u64| {
            blocks
                .get(&phys)
                .cloned()
                .ok_or(ffs_types::ParseError::InvalidField {
                    field: "physical",
                    reason: "missing",
                })
        };
        b.iter(|| {
            black_box(
                walk_tree_range(
                    &mut rp,
                    black_box(&chunks),
                    ROOT_LOGICAL,
                    NODESIZE,
                    0,
                    inode_lo,
                    inode_hi,
                )
                .unwrap(),
            )
        });
    });
    group.finish();
}

criterion_group!(ondisk_inode_attr, bench_ondisk_inode_attr);
criterion_main!(ondisk_inode_attr);
