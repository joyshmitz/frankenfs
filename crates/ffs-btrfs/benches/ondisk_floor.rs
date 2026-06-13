#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B benchmark for the on-disk btrfs read lower-bound (bd-kms5z).
//!
//! The on-disk (read-only mount) read path assembles a file from its
//! `EXTENT_DATA` items walked out of the fs B-tree. bd-x52ar bounded the read
//! window's UPPER side, but the LOWER bound still descends from the inode's
//! first item, so a read near EOF of a large fragmented file walks every leaf
//! holding an earlier extent — O(extents) node reads. `walk_tree_floor`
//! (bd-kms5z) seeks straight to the leaf holding the extent covering the read
//! offset, so a windowed walk from there reads only O(log N) nodes.
//!
//! This benches a two-level tree (one internal root over N single-extent
//! leaves) and reads at the LAST extent: the lower-bound-zero scan reads root +
//! all N leaves; the floor-bounded walk reads root + the covering leaf.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_HEADER_SIZE, BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_SIZE, BTRFS_KEY_PTR_SIZE,
    BtrfsChunkEntry, BtrfsKey, BtrfsStripe, walk_tree_floor, walk_tree_range,
};
use std::cell::Cell;
use std::collections::HashMap;
use std::hint::black_box;

const NODESIZE: u32 = 4096;
const INODE: u64 = 257;
const LEAVES: u64 = 64;
const BLOCK: u64 = 4096;
/// A representative on-disk `EXTENT_DATA` item payload size.
const ITEM_LEN: usize = 53;
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

fn ext_key(offset: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: INODE,
        item_type: BTRFS_ITEM_EXTENT_DATA,
        offset,
    }
}

/// Build a two-level tree: one internal root over `LEAVES` leaves, leaf `i`
/// holding a single `EXTENT_DATA` item keyed `(INODE, EXTENT_DATA, i*BLOCK)`.
fn build_tree() -> HashMap<u64, Vec<u8>> {
    let mut blocks = HashMap::new();
    let payload = vec![0xab_u8; ITEM_LEN];
    let ns = NODESIZE as usize;

    let mut root = vec![0_u8; ns];
    write_header(&mut root, ROOT_LOGICAL, LEAVES as u32, 1);
    for i in 0..LEAVES {
        let leaf_logical = 0x2_0000 + i * u64::from(NODESIZE);
        let key = ext_key(i * BLOCK);
        write_key_ptr(&mut root, i as usize, &key, leaf_logical);

        let mut leaf = vec![0_u8; ns];
        write_header(&mut leaf, leaf_logical, 1, 0);
        let data_off = NODESIZE - ITEM_LEN as u32;
        write_leaf_item(&mut leaf, 0, &key, data_off, &payload);
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

struct OndiskFloorBenchData {
    blocks: HashMap<u64, Vec<u8>>,
    chunks: Vec<BtrfsChunkEntry>,
    read_off: u64,
    from_zero: BtrfsKey,
    window_end: BtrfsKey,
    seek: BtrfsKey,
}

impl OndiskFloorBenchData {
    fn new() -> Self {
        let read_off = (LEAVES - 1) * BLOCK;
        let read_end = read_off + BLOCK;
        Self {
            blocks: build_tree(),
            chunks: identity_chunks(),
            read_off,
            from_zero: BtrfsKey {
                objectid: INODE,
                item_type: 0,
                offset: 0,
            },
            window_end: ext_key(read_end),
            seek: ext_key(read_off),
        }
    }

    fn read_block(&self, phys: u64) -> Result<Vec<u8>, ffs_types::ParseError> {
        self.blocks
            .get(&phys)
            .cloned()
            .ok_or(ffs_types::ParseError::InvalidField {
                field: "physical",
                reason: "missing",
            })
    }

    fn counted_read(&self, reads: &Cell<u32>, phys: u64) -> Result<Vec<u8>, ffs_types::ParseError> {
        reads.set(reads.get() + 1);
        self.blocks
            .get(&phys)
            .cloned()
            .ok_or(ffs_types::ParseError::InvalidField {
                field: "physical",
                reason: "block not in bench image",
            })
    }

    fn assert_isomorphic(&self) {
        // Isomorphism + read-count check: the floor-bounded walk yields exactly
        // the extents the lower-bound-zero walk yields that can overlap the read
        // window, reading far fewer nodes.
        let reads = Cell::new(0_u32);
        let mut read_physical = |phys: u64| self.counted_read(&reads, phys);

        reads.set(0);
        let full = walk_tree_range(
            &mut read_physical,
            &self.chunks,
            ROOT_LOGICAL,
            NODESIZE,
            0,
            self.from_zero,
            self.window_end,
        )
        .expect("full walk");
        let full_reads = reads.get();

        reads.set(0);
        let floor = walk_tree_floor(
            &mut read_physical,
            &self.chunks,
            ROOT_LOGICAL,
            NODESIZE,
            0,
            self.seek,
        )
        .expect("floor")
        .expect("covering extent");
        let bounded = walk_tree_range(
            &mut read_physical,
            &self.chunks,
            ROOT_LOGICAL,
            NODESIZE,
            0,
            floor.key,
            self.window_end,
        )
        .expect("bounded walk");
        let floor_reads = reads.get();

        assert_eq!(full.last().map(|e| e.key), Some(ext_key(self.read_off)));
        assert_eq!(bounded.len(), 1);
        assert_eq!(bounded[0].key, ext_key(self.read_off));
        assert!(
            floor_reads * 4 < full_reads,
            "floor read {floor_reads} nodes vs full {full_reads} (expected >=4x fewer)"
        );
    }

    fn bench_groups(&self, c: &mut Criterion) {
        let mut group = c.benchmark_group("btrfs_ondisk_read_eof");
        group.bench_function("lower_bound_zero_scan_all_leaves", |b| {
            let mut rp = |phys: u64| self.read_block(phys);
            b.iter(|| {
                black_box(
                    walk_tree_range(
                        &mut rp,
                        black_box(&self.chunks),
                        ROOT_LOGICAL,
                        NODESIZE,
                        0,
                        self.from_zero,
                        self.window_end,
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("floor_then_windowed", |b| {
            let mut rp = |phys: u64| self.read_block(phys);
            b.iter(|| {
                let f = walk_tree_floor(
                    &mut rp,
                    black_box(&self.chunks),
                    ROOT_LOGICAL,
                    NODESIZE,
                    0,
                    self.seek,
                )
                .unwrap()
                .unwrap();
                black_box(
                    walk_tree_range(
                        &mut rp,
                        black_box(&self.chunks),
                        ROOT_LOGICAL,
                        NODESIZE,
                        0,
                        f.key,
                        self.window_end,
                    )
                    .unwrap(),
                )
            });
        });
        group.finish();
    }
}

fn bench_ondisk_read_lower_bound(c: &mut Criterion) {
    let data = OndiskFloorBenchData::new();
    data.assert_isomorphic();
    data.bench_groups(c);
}

criterion_group!(ondisk_floor, bench_ondisk_read_lower_bound);
criterion_main!(ondisk_floor);
