#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the ext4 extent-leaf cache (bd-tmyoc).
//!
//! Reading a fragmented file sequentially resolves each logical block via
//! `resolve_extent`. On a cache miss the old code walked the extent tree and
//! cached only the single matched extent — so a file with many extents in one
//! leaf re-descended and re-PARSED that ~340-entry leaf once per extent
//! boundary: O(extents^2) parsing across the read. The new code caches the
//! whole covering leaf on the first miss, so the rest of the run hits the
//! extent cache. This benches a sequential pass over a 340-extent leaf: the old
//! path re-parses the leaf per block; the new path parses once then serves the
//! rest from `ExtentCache`.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_extent::{ExtentCache, ExtentMapping};
use ffs_ondisk::{ExtentTree, parse_extent_tree};
use std::hint::black_box;

const N: usize = 340; // extents in one 4 KiB extent leaf
const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

/// Build a depth-0 extent leaf block with `N` length-1 extents at logical
/// blocks `0..N` (each its own extent, as in a maximally fragmented file).
fn build_leaf_block() -> Vec<u8> {
    let mut block = vec![0_u8; 12 + N * 12];
    block[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    block[2..4].copy_from_slice(&(N as u16).to_le_bytes()); // eh_entries
    block[4..6].copy_from_slice(&(N as u16).to_le_bytes()); // eh_max
    block[6..8].copy_from_slice(&0_u16.to_le_bytes()); // eh_depth = 0 (leaf)
    for i in 0..N {
        let base = 12 + i * 12;
        let phys = 1000 + i as u64;
        block[base..base + 4].copy_from_slice(&(i as u32).to_le_bytes()); // ee_block
        block[base + 4..base + 6].copy_from_slice(&1_u16.to_le_bytes()); // ee_len = 1
        block[base + 6..base + 8].copy_from_slice(&((phys >> 32) as u16).to_le_bytes()); // hi
        block[base + 8..base + 12].copy_from_slice(&((phys & 0xFFFF_FFFF) as u32).to_le_bytes());
    }
    block
}

/// Resolve the covering extent for `lb` within a freshly-parsed leaf (old per-
/// miss path: parse the leaf, binary-search it).
fn resolve_via_reparse(block: &[u8], lb: u32) -> Option<u64> {
    let (_h, tree) = parse_extent_tree(block).unwrap();
    let ExtentTree::Leaf(extents) = tree else {
        return None;
    };
    let pp = extents.partition_point(|e| e.logical_block <= lb);
    if pp == 0 {
        return None;
    }
    let e = &extents[pp - 1];
    if lb < e.logical_block + u32::from(e.actual_len()) {
        Some(e.physical_start + u64::from(lb - e.logical_block))
    } else {
        None
    }
}

fn bench_extent_leaf_cache(c: &mut Criterion) {
    let block = build_leaf_block();

    // Isomorphism: caching the whole leaf returns, for every block, the same
    // physical address the per-miss re-parse path does.
    {
        let (_h, tree) = parse_extent_tree(&block).unwrap();
        let ExtentTree::Leaf(extents) = tree else {
            panic!("expected leaf");
        };
        let cache = ExtentCache::new();
        for e in &extents {
            cache.insert(
                0,
                ExtentMapping {
                    logical_start: e.logical_block,
                    physical_start: e.physical_start,
                    count: u32::from(e.actual_len()),
                    unwritten: e.is_unwritten(),
                },
            );
        }
        for lb in 0..N as u32 {
            let cached = cache.lookup(0, lb).map(|m| m.physical_start);
            assert_eq!(
                cached,
                resolve_via_reparse(&block, lb),
                "block {lb} diverged"
            );
        }
    }

    let mut group = c.benchmark_group("ext4_extent_leaf_seq_read_340");
    // Old: a cache miss per extent re-parses the whole leaf.
    group.bench_function("reparse_per_extent", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for lb in 0..N as u32 {
                acc = acc.wrapping_add(resolve_via_reparse(black_box(&block), lb).unwrap_or(0));
            }
            black_box(acc)
        });
    });
    // New: parse once, cache the whole leaf, serve the rest from the cache.
    group.bench_function("cache_whole_leaf", |b| {
        b.iter(|| {
            let (_h, tree) = parse_extent_tree(black_box(&block)).unwrap();
            let ExtentTree::Leaf(extents) = tree else {
                unreachable!()
            };
            let cache = ExtentCache::new();
            for e in &extents {
                cache.insert(
                    0,
                    ExtentMapping {
                        logical_start: e.logical_block,
                        physical_start: e.physical_start,
                        count: u32::from(e.actual_len()),
                        unwritten: e.is_unwritten(),
                    },
                );
            }
            let mut acc = 0_u64;
            for lb in 0..N as u32 {
                acc = acc.wrapping_add(cache.lookup(0, lb).map_or(0, |m| m.physical_start));
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(extent_leaf_cache, bench_extent_leaf_cache);
criterion_main!(extent_leaf_cache);
