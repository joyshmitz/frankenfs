#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for caching the extent tree across the ext4_write loop
//! (bd-yqq5l).
//!
//! `ext4_write`'s per-block loop called `collect_extents_with_scope` on EVERY
//! block position — re-walking and re-materialising the inode's WHOLE extent
//! tree (parse every leaf, allocate a Vec of all E extents) each iteration. An
//! N-block write therefore parsed the tree N times (O(N*E)), even for a pure
//! overwrite that never mutates the tree. The fix collects once and reuses the
//! result, invalidating only at the two in-loop tree-mutation sites.
//!
//! This models a depth-1 extent tree (L leaves * M extents) over an in-memory
//! block map and an overwrite touching K blocks: OLD re-collects per block, NEW
//! collects once then resolves each block from the cached Vec — exactly the
//! per-iteration vs once difference the production change makes. Mirrors the
//! W115 extent_collect_window bench's tree model.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::{ExtentTree, parse_extent_tree};
use std::collections::HashMap;
use std::hint::black_box;

const L: u32 = 16; // leaf blocks (depth-1 tree)
const M: u32 = 340; // extents per 4 KiB leaf
const K: u32 = 256; // blocks touched by the write (e.g. a 1 MiB write)
const EXT4_EXTENT_MAGIC: u16 = 0xF30A;

/// One depth-0 leaf block: `M` length-1 extents at logical `start..start+M`.
fn build_leaf(start: u32) -> Vec<u8> {
    let mut block = vec![0_u8; 12 + M as usize * 12];
    block[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    block[2..4].copy_from_slice(&(M as u16).to_le_bytes());
    block[4..6].copy_from_slice(&(M as u16).to_le_bytes());
    block[6..8].copy_from_slice(&0_u16.to_le_bytes()); // depth 0
    for k in 0..M {
        let base = 12 + k as usize * 12;
        let logical = start + k;
        let phys = 100_000_u64 + u64::from(logical);
        block[base..base + 4].copy_from_slice(&logical.to_le_bytes());
        block[base + 4..base + 6].copy_from_slice(&1_u16.to_le_bytes());
        block[base + 6..base + 8].copy_from_slice(&((phys >> 32) as u16).to_le_bytes());
        block[base + 8..base + 12].copy_from_slice(&((phys & 0xFFFF_FFFF) as u32).to_le_bytes());
    }
    block
}

type Index = Vec<(u32, u32)>;
type Dev = HashMap<u32, Vec<u8>>;

fn build_tree() -> (Index, Dev) {
    let mut index = Vec::new();
    let mut dev = HashMap::new();
    for j in 0..L {
        index.push((j * M, j));
        dev.insert(j, build_leaf(j * M));
    }
    (index, dev)
}

/// Flatten the whole tree into owned extents — models collect_extents_with_scope
/// (parse every leaf, materialise a Vec of all E extents).
fn collect_all(index: &[(u32, u32)], dev: &Dev) -> Vec<(u32, u32, u64)> {
    let mut out = Vec::new();
    for &(_first, leaf) in index {
        let (_h, tree) = parse_extent_tree(&dev[&leaf]).unwrap();
        if let ExtentTree::Leaf(exts) = tree {
            out.extend(
                exts.iter()
                    .map(|e| (e.logical_block, u32::from(e.actual_len()), e.physical_start)),
            );
        }
    }
    out
}

/// The per-block resolve `ext4_write` does over the collected extents.
fn resolve(extents: &[(u32, u32, u64)], logical: u32) -> Option<u64> {
    extents.iter().find_map(|&(start, len, phys)| {
        (logical >= start && logical < start + len).then_some(phys + u64::from(logical - start))
    })
}

/// Blocks the overwrite touches, spread across the whole fragmented file.
fn targets() -> Vec<u32> {
    let e = L * M;
    (0..K).map(|i| (i * (e / K)) % e).collect()
}

fn bench_ext4_write_extent_cache(c: &mut Criterion) {
    let (index, dev) = build_tree();
    let targets = targets();

    // Isomorphism: caching changes nothing the loop observes — both resolve the
    // same physical block for every target.
    let cached = collect_all(&index, &dev);
    for &t in &targets {
        assert_eq!(
            resolve(&cached, t),
            resolve(&collect_all(&index, &dev), t),
            "cached resolve diverged at logical {t}"
        );
    }

    let mut group = c.benchmark_group("ext4_write_overwrite_256blk_16x340");
    group.bench_function("collect_per_block", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for &t in black_box(&targets) {
                let extents = collect_all(black_box(&index), black_box(&dev));
                acc ^= resolve(&extents, t).unwrap_or(0);
            }
            black_box(acc)
        });
    });
    group.bench_function("collect_once_cached", |b| {
        b.iter(|| {
            let extents = collect_all(black_box(&index), black_box(&dev));
            let mut acc = 0_u64;
            for &t in black_box(&targets) {
                acc ^= resolve(&extents, t).unwrap_or(0);
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_ext4_write_extent_cache);
criterion_main!(benches);
