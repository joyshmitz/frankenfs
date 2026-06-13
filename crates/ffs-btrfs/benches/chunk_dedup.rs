#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the btrfs chunk-tree dedup at mount (bd-o6orc).
//!
//! `walk_chunk_tree` reconstructs the chunk map by appending every CHUNK item
//! from the chunk tree to the bootstrap set, deduping by logical offset. The old
//! code scanned the whole accumulated `chunks` Vec per item
//! (`chunks.iter().any(|c| c.key.offset == ...)`) made this O(chunks^2) at mount;
//! multi-TB filesystem has thousands of chunks. The new code tracks seen offsets
//! in a HashSet (O(1) membership): O(chunks). Both keep the first occurrence of
//! each offset, producing the identical chunk list.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{BtrfsChunkEntry, BtrfsKey, BtrfsStripe};
use std::collections::HashSet;
use std::hint::black_box;

const N: u64 = 4000; // chunk items in a large filesystem's chunk tree
const CHUNK_LEN: u64 = 1 << 30; // 1 GiB chunks

fn chunk_at(logical: u64) -> BtrfsChunkEntry {
    BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228, // CHUNK_ITEM
            offset: logical,
        },
        length: CHUNK_LEN,
        owner: 2,
        stripe_len: 0x1_0000,
        chunk_type: 1,
        io_align: 4096,
        io_width: 4096,
        sector_size: 4096,
        num_stripes: 1,
        sub_stripes: 0,
        stripes: vec![BtrfsStripe {
            devid: 1,
            offset: logical,
            dev_uuid: [0_u8; 16],
        }],
    }
}

/// Parsed chunk items as they come out of the tree walk: distinct offsets, with
/// a few duplicates sprinkled in (re-seen offsets the dedup must drop).
fn build_items() -> Vec<BtrfsChunkEntry> {
    let mut v: Vec<BtrfsChunkEntry> = (0..N).map(|i| chunk_at(i * CHUNK_LEN)).collect();
    // Re-emit every 8th offset as a duplicate (exercises the skip path).
    for i in (0..N).step_by(8) {
        v.push(chunk_at(i * CHUNK_LEN));
    }
    v
}

/// Linear dedup (the pre-bd-o6orc shape): scan accumulated chunks per item.
fn linear(items: &[BtrfsChunkEntry]) -> Vec<BtrfsChunkEntry> {
    let mut chunks: Vec<BtrfsChunkEntry> = Vec::new();
    for item in items {
        if !chunks.iter().any(|c| c.key.offset == item.key.offset) {
            chunks.push(item.clone());
        }
    }
    chunks
}

/// HashSet dedup (new): O(1) membership on seen offsets.
fn hashed(items: &[BtrfsChunkEntry]) -> Vec<BtrfsChunkEntry> {
    let mut chunks: Vec<BtrfsChunkEntry> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    for item in items {
        if seen.insert(item.key.offset) {
            chunks.push(item.clone());
        }
    }
    chunks
}

fn bench_chunk_dedup(c: &mut Criterion) {
    let items = build_items();

    // Isomorphism: both dedup strategies produce the identical chunk list
    // (same offsets, first-occurrence order).
    let a: Vec<u64> = linear(&items).iter().map(|c| c.key.offset).collect();
    let b: Vec<u64> = hashed(&items).iter().map(|c| c.key.offset).collect();
    assert_eq!(a, b, "HashSet dedup diverged from linear dedup");

    let mut group = c.benchmark_group("btrfs_chunk_tree_dedup_4000");
    group.bench_function("linear_any", |bch| {
        bch.iter(|| black_box(linear(black_box(&items)).len()));
    });
    group.bench_function("hashset", |bch| {
        bch.iter(|| black_box(hashed(black_box(&items)).len()));
    });
    group.finish();
}

criterion_group!(chunk_dedup, bench_chunk_dedup);
criterion_main!(chunk_dedup);
