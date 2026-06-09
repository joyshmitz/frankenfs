#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Criterion benchmark for `parse_leaf_items` (btrfs leaf-block parse).
//!
//! `parse_leaf_items` is on the hottest btrfs metadata path — it runs on every
//! leaf block read during a tree walk. Its per-item payload-overlap validation
//! is the dominant cost on a dense leaf (hundreds of items), so this benchmark
//! builds a packed leaf to establish the parse latency under load.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::parse_leaf_items;
use std::hint::black_box;

/// btrfs on-disk header size (`sizeof(struct btrfs_header)`).
const BTRFS_HEADER_SIZE: usize = 101;
/// btrfs on-disk item-table entry size (`sizeof(struct btrfs_item)`).
const BTRFS_ITEM_SIZE: usize = 25;
/// `nritems` little-endian field offset inside the header.
const NRITEMS_OFFSET: usize = 0x60;
/// `level` byte offset inside the header.
const LEVEL_OFFSET: usize = 0x64;

/// Build a valid, densely packed btrfs leaf block: `nritems` items with strictly
/// increasing keys and `payload_size`-byte non-overlapping payloads laid out
/// downward from the block end. This is the worst case for the per-item
/// payload-overlap check.
fn build_dense_leaf(block_size: usize, payload_size: usize) -> Vec<u8> {
    let header_size = u32::try_from(BTRFS_HEADER_SIZE).unwrap();
    // Largest nritems whose item table + payloads fit the block.
    let nritems = (block_size - BTRFS_HEADER_SIZE) / (BTRFS_ITEM_SIZE + payload_size);
    let mut block = vec![0_u8; block_size];
    block[NRITEMS_OFFSET..NRITEMS_OFFSET + 4]
        .copy_from_slice(&u32::try_from(nritems).unwrap().to_le_bytes());
    block[LEVEL_OFFSET] = 0; // leaf

    for idx in 0..nritems {
        let base = BTRFS_HEADER_SIZE + idx * BTRFS_ITEM_SIZE;
        // Strictly increasing key (objectid = idx).
        block[base..base + 8].copy_from_slice(&(idx as u64).to_le_bytes());
        block[base + 8] = 1; // item_type
        block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes()); // key offset
        // Payload laid out downward from the block end; non-overlapping.
        let data_offset_abs = block_size - (idx + 1) * payload_size;
        let data_offset_rel = u32::try_from(data_offset_abs).unwrap() - header_size;
        block[base + 17..base + 21].copy_from_slice(&data_offset_rel.to_le_bytes());
        block[base + 21..base + 25]
            .copy_from_slice(&u32::try_from(payload_size).unwrap().to_le_bytes());
    }
    block
}

fn bench_parse_dense_leaf(c: &mut Criterion) {
    // Default btrfs nodesize (16 KiB), 1-byte payloads → ~626 items.
    let leaf_16k = build_dense_leaf(16 * 1024, 1);
    // Smaller 4 KiB leaf → ~156 items.
    let leaf_4k = build_dense_leaf(4 * 1024, 1);

    // Sanity: both parse cleanly before benchmarking.
    assert!(parse_leaf_items(&leaf_16k).is_ok());
    assert!(parse_leaf_items(&leaf_4k).is_ok());

    let mut group = c.benchmark_group("btrfs_leaf_parse");
    group.bench_function("parse_dense_leaf_16k", |b| {
        b.iter(|| black_box(parse_leaf_items(black_box(&leaf_16k)).unwrap()));
    });
    group.bench_function("parse_dense_leaf_4k", |b| {
        b.iter(|| black_box(parse_leaf_items(black_box(&leaf_4k)).unwrap()));
    });
    group.finish();
}

criterion_group!(btrfs_leaf, bench_parse_dense_leaf);
criterion_main!(btrfs_leaf);
