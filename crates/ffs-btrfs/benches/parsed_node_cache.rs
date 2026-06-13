#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B benchmark for the parsed-node walker seam (bd-u1n5f).
//!
//! On a read-only mount the on-disk metadata is immutable, so a tree node read
//! once can be reused. The byte walkers nonetheless re-do the full per-node
//! cost on EVERY traversal: read (cache clone), checksum verification, header
//! parse/validate, and item parsing. A single `read`/`getattr`/`readdir`
//! already performs several range descents that re-walk the same root +
//! internal nodes, and repeated ops re-walk the same leaves.
//!
//! `walk_tree_range_with_nodes` takes an `Arc<BtrfsParsedNode>` provider, so a
//! parsed-node cache hands the walker verified+parsed nodes and skips read +
//! verify + parse on a hit. This benches walking the same tree repeatedly:
//! `byte_reparse` re-parses every visited node each pass; `parsed_cached` parses
//! each node once and reuses it.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{
    BTRFS_HEADER_SIZE, BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_SIZE, BTRFS_KEY_PTR_SIZE,
    BtrfsChunkEntry, BtrfsKey, BtrfsLeafEntry, BtrfsLeafEntryBatch, BtrfsParsedNode, BtrfsStripe,
    parse_btrfs_tree_node, walk_tree_range, walk_tree_range_borrowed_with_nodes,
    walk_tree_range_with_nodes,
};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;

const NODESIZE: u32 = 16384;
const INODE: u64 = 257;
/// Number of leaves under the single internal root.
const LEAVES: u64 = 16;
/// Items packed into each leaf (drives per-leaf parse cost).
const ITEMS_PER_LEAF: u64 = 360;
/// Per-item payload size (small EXTENT_DATA-ish records pack densely).
const ITEM_LEN: usize = 8;
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

/// Key for global item index `g` (sorted across the whole tree).
fn item_key(g: u64) -> BtrfsKey {
    BtrfsKey {
        objectid: INODE,
        item_type: BTRFS_ITEM_EXTENT_DATA,
        offset: g * 4096,
    }
}

/// Build a two-level tree: one internal root over `LEAVES` leaves, leaf `L`
/// holding items with global indices `[L*ITEMS_PER_LEAF, (L+1)*ITEMS_PER_LEAF)`.
fn build_tree() -> HashMap<u64, Vec<u8>> {
    let mut blocks = HashMap::new();
    let ns = NODESIZE as usize;
    let payload = vec![0xab_u8; ITEM_LEN];

    let mut root = vec![0_u8; ns];
    write_header(&mut root, ROOT_LOGICAL, LEAVES as u32, 1);
    for l in 0..LEAVES {
        let leaf_logical = 0x2_0000 + l * u64::from(NODESIZE);
        let first_g = l * ITEMS_PER_LEAF;
        write_key_ptr(&mut root, l as usize, &item_key(first_g), leaf_logical);

        let mut leaf = vec![0_u8; ns];
        write_header(&mut leaf, leaf_logical, ITEMS_PER_LEAF as u32, 0);
        for i in 0..ITEMS_PER_LEAF {
            let g = first_g + i;
            // Payloads pack downward from the tail of the block.
            let data_off = NODESIZE - (i as u32 + 1) * ITEM_LEN as u32;
            write_leaf_item(&mut leaf, i as usize, &item_key(g), data_off, &payload);
        }
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

/// Pre-parse every node once, keyed by its logical address (a warm cache).
fn parsed_cache(blocks: &HashMap<u64, Vec<u8>>) -> HashMap<u64, Arc<BtrfsParsedNode>> {
    let mut cache = HashMap::new();
    // Logical == physical under the identity chunk map used here.
    for (&logical, bytes) in blocks {
        let node = parse_btrfs_tree_node(bytes, 0, logical, NODESIZE).expect("parse node");
        cache.insert(logical, Arc::new(node));
    }
    cache
}

fn owned_from_batches(batches: &[BtrfsLeafEntryBatch]) -> Vec<BtrfsLeafEntry> {
    batches
        .iter()
        .flat_map(BtrfsLeafEntryBatch::to_owned_entries)
        .collect()
}

struct ParsedNodeBenchData {
    blocks: HashMap<u64, Vec<u8>>,
    chunks: Vec<BtrfsChunkEntry>,
    cache: HashMap<u64, Arc<BtrfsParsedNode>>,
    full_lo: BtrfsKey,
    full_hi: BtrfsKey,
    narrow_lo: BtrfsKey,
    narrow_hi: BtrfsKey,
}

impl ParsedNodeBenchData {
    fn new() -> Self {
        let blocks = build_tree();
        let chunks = identity_chunks();
        let cache = parsed_cache(&blocks);
        let needle = ITEMS_PER_LEAF + 5; // an item in leaf 1
        Self {
            blocks,
            chunks,
            cache,
            full_lo: item_key(0),
            full_hi: item_key(LEAVES * ITEMS_PER_LEAF),
            narrow_lo: item_key(needle),
            narrow_hi: item_key(needle + 1),
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

    fn cached_node(&self, logical: u64) -> Result<Arc<BtrfsParsedNode>, ffs_types::ParseError> {
        self.cache
            .get(&logical)
            .cloned()
            .ok_or(ffs_types::ParseError::InvalidField {
                field: "logical",
                reason: "missing",
            })
    }

    fn assert_isomorphic(&self) {
        let mut byte_read = |phys: u64| self.read_block(phys);
        let from_bytes = walk_tree_range(
            &mut byte_read,
            &self.chunks,
            ROOT_LOGICAL,
            NODESIZE,
            0,
            self.full_lo,
            self.full_hi,
        )
        .expect("bytes");
        let mut cache_provider = |logical: u64| self.cached_node(logical);
        let from_cache = walk_tree_range_with_nodes(
            &mut cache_provider,
            ROOT_LOGICAL,
            NODESIZE,
            self.full_lo,
            self.full_hi,
        )
        .expect("cached");
        assert_eq!(from_bytes, from_cache);
        assert_eq!(from_bytes.len() as u64, LEAVES * ITEMS_PER_LEAF);
        let borrowed = walk_tree_range_borrowed_with_nodes(
            &mut cache_provider,
            ROOT_LOGICAL,
            NODESIZE,
            self.full_lo,
            self.full_hi,
        )
        .expect("borrowed");
        assert_eq!(from_bytes, owned_from_batches(&borrowed));
    }

    fn bench_full_range(&self, c: &mut Criterion) {
        let mut group = c.benchmark_group("btrfs_parsed_node_walk_full");
        group.bench_function("byte_reparse", |b| {
            let mut rp = |phys: u64| self.read_block(phys);
            b.iter(|| {
                black_box(
                    walk_tree_range(
                        &mut rp,
                        black_box(&self.chunks),
                        ROOT_LOGICAL,
                        NODESIZE,
                        0,
                        self.full_lo,
                        self.full_hi,
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("parsed_cached", |b| {
            let mut provider = |logical: u64| self.cached_node(logical);
            b.iter(|| {
                black_box(
                    walk_tree_range_with_nodes(
                        &mut provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.full_lo),
                        black_box(self.full_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("parsed_cached_borrowed", |b| {
            let mut provider = |logical: u64| self.cached_node(logical);
            b.iter(|| {
                black_box(
                    walk_tree_range_borrowed_with_nodes(
                        &mut provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.full_lo),
                        black_box(self.full_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.finish();
    }

    fn bench_narrow_range(&self, c: &mut Criterion) {
        let mut group = c.benchmark_group("btrfs_parsed_node_walk_narrow");
        group.bench_function("byte_reparse", |b| {
            let mut rp = |phys: u64| self.read_block(phys);
            b.iter(|| {
                black_box(
                    walk_tree_range(
                        &mut rp,
                        black_box(&self.chunks),
                        ROOT_LOGICAL,
                        NODESIZE,
                        0,
                        self.narrow_lo,
                        self.narrow_hi,
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("parsed_cached", |b| {
            let mut provider = |logical: u64| self.cached_node(logical);
            b.iter(|| {
                black_box(
                    walk_tree_range_with_nodes(
                        &mut provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.narrow_lo),
                        black_box(self.narrow_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.bench_function("parsed_cached_borrowed", |b| {
            let mut provider = |logical: u64| self.cached_node(logical);
            b.iter(|| {
                black_box(
                    walk_tree_range_borrowed_with_nodes(
                        &mut provider,
                        ROOT_LOGICAL,
                        NODESIZE,
                        black_box(self.narrow_lo),
                        black_box(self.narrow_hi),
                    )
                    .unwrap(),
                )
            });
        });
        group.finish();
    }
}

fn bench_parsed_node_cache(c: &mut Criterion) {
    let data = ParsedNodeBenchData::new();
    data.assert_isomorphic();
    data.bench_full_range(c);
    data.bench_narrow_range(c);
}

criterion_group!(parsed_node_cache, bench_parsed_node_cache);
criterion_main!(parsed_node_cache);
