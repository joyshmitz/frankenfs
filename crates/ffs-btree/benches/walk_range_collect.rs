#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for bounding extent collection to a logical range
//! (bd-k2wc7).
//!
//! `ffs_extent::mark_written` and `punch_hole` collect the extents overlapping
//! a target logical range by `walk`-ing the WHOLE extent tree and pushing the
//! ones that overlap. For a large fragmented/preallocated file that is O(E) per
//! call. Extents are sorted and non-overlapping, so `walk_range` over the
//! target range reads only the covering subtrees (O(log E + range)).
//!
//! This benches the exact collection both functions perform: gather every
//! extent overlapping a small range sitting in the MIDDLE of a large tree. OLD
//! walks all E extents; NEW reads only the range's subtree. The collected sets
//! are asserted identical.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_btree::{BlockAllocator, insert, walk, walk_range};
use ffs_error::Result;
use ffs_ondisk::Ext4Extent;
use ffs_types::BlockNumber;
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Mutex;

struct MemBlockDevice {
    block_size: u32,
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
}

impl MemBlockDevice {
    fn new(block_size: u32) -> Self {
        Self {
            block_size,
            blocks: Mutex::new(HashMap::new()),
        }
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        let blocks = self.blocks.lock().unwrap();
        blocks.get(&block.0).map_or_else(
            || Ok(BlockBuf::new(vec![0u8; self.block_size as usize])),
            |data| Ok(BlockBuf::new(data.clone())),
        )
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.blocks.lock().unwrap().insert(block.0, data.to_vec());
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        100_000_000
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

struct SeqAllocator {
    next: u64,
}

impl BlockAllocator for SeqAllocator {
    fn alloc_block(&mut self, _cx: &Cx) -> Result<BlockNumber> {
        let bn = BlockNumber(self.next);
        self.next += 1;
        Ok(bn)
    }

    fn free_block(&mut self, _cx: &Cx, _block: BlockNumber) -> Result<()> {
        Ok(())
    }
}

fn empty_root() -> [u8; 60] {
    let mut root = [0u8; 60];
    root[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // magic
    root[2..4].copy_from_slice(&0u16.to_le_bytes()); // entries
    root[4..6].copy_from_slice(&4u16.to_le_bytes()); // max_entries
    root[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth
    root[8..12].copy_from_slice(&0u32.to_le_bytes()); // generation
    root
}

/// Build an N-extent tree (disjoint single-block extents at logical 0,2,4,...).
fn build_tree(n: u32) -> (MemBlockDevice, [u8; 60]) {
    let dev = MemBlockDevice::new(4096);
    let cx = Cx::for_testing();
    let mut alloc = SeqAllocator { next: 1 };
    let mut root = empty_root();
    for i in 0..n {
        let ext = Ext4Extent {
            logical_block: i * 2,
            raw_len: 1,
            physical_start: u64::from(i) + 1_000_000,
        };
        insert(&cx, &dev, &mut root, ext, &mut alloc).expect("insert");
    }
    (dev, root)
}

fn overlaps(e: &Ext4Extent, lo: u64, hi: u64) -> bool {
    let start = u64::from(e.logical_block);
    let end = start.saturating_add(u64::from(e.raw_len));
    start < hi && end > lo
}

/// OLD collection: walk the whole tree, push overlapping extents.
fn collect_walk(cx: &Cx, dev: &dyn BlockDevice, root: &[u8; 60], lo: u32, span: u64) -> Vec<u64> {
    let hi = u64::from(lo) + span;
    let mut out = Vec::new();
    walk(cx, dev, root, &mut |e| {
        if overlaps(e, u64::from(lo), hi) {
            out.push(u64::from(e.logical_block));
        }
        Ok(())
    })
    .expect("walk");
    out
}

/// NEW collection: walk_range over the target range only.
fn collect_walk_range(
    cx: &Cx,
    dev: &dyn BlockDevice,
    root: &[u8; 60],
    lo: u32,
    span: u64,
) -> Vec<u64> {
    let hi = u64::from(lo) + span;
    let mut out = Vec::new();
    walk_range(cx, dev, root, lo, span, &mut |e| {
        if overlaps(e, u64::from(lo), hi) {
            out.push(u64::from(e.logical_block));
        }
        Ok(())
    })
    .expect("walk_range");
    out
}

/// OLD tail collection (collapse_range/insert_range shape): walk the whole
/// tree, push extents at or past `cut`.
fn collect_tail_walk(cx: &Cx, dev: &dyn BlockDevice, root: &[u8; 60], cut: u64) -> Vec<u64> {
    let mut out = Vec::new();
    walk(cx, dev, root, &mut |e| {
        if u64::from(e.logical_block) >= cut {
            out.push(u64::from(e.logical_block));
        }
        Ok(())
    })
    .expect("walk");
    out
}

/// NEW tail collection: walk_range over the [cut, 2^32) suffix.
fn collect_tail_walk_range(cx: &Cx, dev: &dyn BlockDevice, root: &[u8; 60], cut: u64) -> Vec<u64> {
    let start = u32::try_from(cut).unwrap_or(u32::MAX);
    let span = (1_u64 << 32).saturating_sub(cut);
    let mut out = Vec::new();
    walk_range(cx, dev, root, start, span, &mut |e| {
        if u64::from(e.logical_block) >= cut {
            out.push(u64::from(e.logical_block));
        }
        Ok(())
    })
    .expect("walk_range");
    out
}

#[derive(Clone, Copy)]
struct IndexProbe {
    logical_block: u32,
    leaf_block: u64,
}

fn first_index_probe_for_range(indexes: &[IndexProbe], start: u64) -> usize {
    indexes
        .partition_point(|idx| u64::from(idx.logical_block) <= start)
        .saturating_sub(1)
}

fn select_index_window_control(indexes: &[IndexProbe], start: u64, end: u64) -> Vec<u64> {
    let first = first_index_probe_for_range(indexes, start);
    let mut out = Vec::new();
    for (offset, idx) in indexes[first..].iter().enumerate() {
        let pos = first + offset;
        let child_start = u64::from(idx.logical_block);
        let child_end = indexes
            .get(pos + 1)
            .map_or(1_u64 << 32, |next| u64::from(next.logical_block));
        if child_end <= start {
            continue;
        }
        if child_start >= end {
            break;
        }
        out.push(idx.leaf_block);
    }
    out
}

fn select_index_window_candidate(indexes: &[IndexProbe], start: u64, end: u64) -> Vec<u64> {
    let first = first_index_probe_for_range(indexes, start);
    let mut out = Vec::new();
    for idx in &indexes[first..] {
        if u64::from(idx.logical_block) >= end {
            break;
        }
        out.push(idx.leaf_block);
    }
    out
}

#[inline(never)]
fn scan_index_window_control(indexes: &[IndexProbe], start: u64, end: u64) -> u64 {
    let first = first_index_probe_for_range(indexes, start);
    let mut digest = 0xCBF2_9CE4_8422_2325_u64;
    let mut visited = 0_u64;
    for (offset, idx) in indexes[first..].iter().enumerate() {
        let pos = first + offset;
        let child_start = u64::from(idx.logical_block);
        let child_end = indexes
            .get(pos + 1)
            .map_or(1_u64 << 32, |next| u64::from(next.logical_block));
        if child_end <= start {
            continue;
        }
        if child_start >= end {
            break;
        }
        digest = digest.rotate_left(7) ^ idx.leaf_block.wrapping_mul(0x9E37_79B1_85EB_CA87);
        visited += 1;
    }
    digest ^ visited
}

#[inline(never)]
fn scan_index_window_candidate(indexes: &[IndexProbe], start: u64, end: u64) -> u64 {
    let first = first_index_probe_for_range(indexes, start);
    let mut digest = 0xCBF2_9CE4_8422_2325_u64;
    let mut visited = 0_u64;
    for idx in &indexes[first..] {
        if u64::from(idx.logical_block) >= end {
            break;
        }
        digest = digest.rotate_left(7) ^ idx.leaf_block.wrapping_mul(0x9E37_79B1_85EB_CA87);
        visited += 1;
    }
    digest ^ visited
}

fn bench_index_guard(c: &mut Criterion) {
    let indexes: Vec<_> = (0_u32..340)
        .map(|i| IndexProbe {
            logical_block: i * 16,
            leaf_block: 100_000 + u64::from(i),
        })
        .collect();
    let start = u64::from(indexes[37].logical_block) + 7;
    let end = u64::from(indexes[303].logical_block);

    for &(proof_start, proof_end) in &[
        (0, 1),
        (start, end),
        (u64::from(indexes[339].logical_block), 1_u64 << 32),
    ] {
        assert_eq!(
            select_index_window_control(&indexes, proof_start, proof_end),
            select_index_window_candidate(&indexes, proof_start, proof_end),
        );
        assert_eq!(
            scan_index_window_control(&indexes, proof_start, proof_end),
            scan_index_window_candidate(&indexes, proof_start, proof_end),
        );
    }

    let mut group = c.benchmark_group("extent_walk_index_start_guard_340");
    group.bench_function("next_separator_control_a", |b| {
        b.iter(|| {
            black_box(scan_index_window_control(
                black_box(&indexes),
                black_box(start),
                black_box(end),
            ))
        });
    });
    group.bench_function("next_separator_control_b", |b| {
        b.iter(|| {
            black_box(scan_index_window_control(
                black_box(&indexes),
                black_box(start),
                black_box(end),
            ))
        });
    });
    group.bench_function("partition_proven_candidate", |b| {
        b.iter(|| {
            black_box(scan_index_window_candidate(
                black_box(&indexes),
                black_box(start),
                black_box(end),
            ))
        });
    });
    group.finish();
}

fn bench_tail(c: &mut Criterion) {
    let cx = Cx::for_testing();
    for &n in &[2000_u32, 8000] {
        let (dev, root) = build_tree(n);
        // Collapse/insert near a high logical offset: cut at ~90% of the tree,
        // so the tail is the last ~10% and walk_range prunes the long prefix.
        let cut = u64::from((n * 2) * 9 / 10);

        assert_eq!(
            collect_tail_walk(&cx, &dev, &root, cut),
            collect_tail_walk_range(&cx, &dev, &root, cut),
            "tail sets diverged at n={n}"
        );

        let mut group = c.benchmark_group(format!("extent_tail_collect_{n}"));
        group.bench_function("walk_full_tree", |b| {
            b.iter(|| black_box(collect_tail_walk(&cx, &dev, black_box(&root), cut)));
        });
        group.bench_function("walk_range", |b| {
            b.iter(|| black_box(collect_tail_walk_range(&cx, &dev, black_box(&root), cut)));
        });
        group.finish();
    }
}

fn bench_collect(c: &mut Criterion) {
    let cx = Cx::for_testing();
    // A small range (8 logical blocks) in the middle of the tree — the
    // mark_written / punch_hole scenario: a write or punch touching a few
    // extents of a large preallocated file.
    let span = 8_u64;
    for &n in &[2000_u32, 8000] {
        let (dev, root) = build_tree(n);
        let lo = n; // middle-ish: logical n maps to extent index n/2

        // Isomorphism: identical collected set.
        assert_eq!(
            collect_walk(&cx, &dev, &root, lo, span),
            collect_walk_range(&cx, &dev, &root, lo, span),
            "collected sets diverged at n={n}"
        );

        let mut group = c.benchmark_group(format!("extent_range_collect_{n}"));
        group.bench_function("walk_full_tree", |b| {
            b.iter(|| black_box(collect_walk(&cx, &dev, black_box(&root), lo, span)));
        });
        group.bench_function("walk_range", |b| {
            b.iter(|| black_box(collect_walk_range(&cx, &dev, black_box(&root), lo, span)));
        });
        group.finish();
    }
}

criterion_group!(benches, bench_collect, bench_tail, bench_index_guard);
criterion_main!(benches);
