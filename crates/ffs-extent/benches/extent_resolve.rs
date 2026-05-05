#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Criterion benchmarks for extent tree resolve (logical → physical block mapping).
//!
//! Benchmarks both "uncached" (direct tree walk) and "cached" (repeated lookups
//! of the same logical blocks) paths to establish baseline latency for the
//! `map_logical_to_physical` function.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::Result as FfsResult;
use ffs_types::BlockNumber;
use parking_lot::Mutex;
use std::hint::black_box;

// ── Constants ───────────────────────────────────────────────────────────────

const BLOCK_SIZE: u32 = 4096;
/// ext4 extent header magic.
const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
/// 12-byte header, 12-byte entries.
const HEADER_SIZE: usize = 12;
const ENTRY_SIZE: usize = 12;

/// Number of extents in the root node for the depth-0 benchmark.
const ROOT_EXTENTS: usize = 4; // max root entries for 60-byte i_block

/// Number of child blocks in the depth-1 benchmark.
const DEPTH1_CHILDREN: usize = 4;
/// Leaf entries per external node at 4K block size: (4096 - 12 - 4) / 12 = 340.
const LEAF_ENTRIES_PER_NODE: usize = 340;

// ── In-memory block device for benchmarks ──────────────────────────────────

/// A simple in-memory block device holding pre-populated blocks for tree lookups.
#[derive(Debug)]
struct MemBlockDevice {
    blocks: Mutex<Vec<Vec<u8>>>,
    block_size: u32,
}

impl MemBlockDevice {
    fn new(block_size: u32, block_count: usize) -> Self {
        let blocks = (0..block_count)
            .map(|_| vec![0u8; block_size as usize])
            .collect();
        Self {
            blocks: Mutex::new(blocks),
            block_size,
        }
    }

    fn write_block_data(&self, block: usize, data: &[u8]) {
        let mut guard = self.blocks.lock();
        guard[block][..data.len()].copy_from_slice(data);
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> FfsResult<BlockBuf> {
        let data = self.blocks.lock()[block.0 as usize].clone();
        Ok(BlockBuf::new(data))
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> FfsResult<()> {
        self.blocks.lock()[block.0 as usize][..data.len()].copy_from_slice(data);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.blocks.lock().len() as u64
    }

    fn sync(&self, _cx: &Cx) -> FfsResult<()> {
        Ok(())
    }
}

// ── Extent tree construction helpers ───────────────────────────────────────

/// Serialize an extent header into bytes.
fn write_header(buf: &mut [u8], entries: u16, max_entries: u16, depth: u16) {
    buf[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    buf[2..4].copy_from_slice(&entries.to_le_bytes());
    buf[4..6].copy_from_slice(&max_entries.to_le_bytes());
    buf[6..8].copy_from_slice(&depth.to_le_bytes());
    buf[8..12].copy_from_slice(&0u32.to_le_bytes()); // generation
}

/// Serialize a leaf extent entry.
fn write_leaf_extent(buf: &mut [u8], logical_block: u32, raw_len: u16, physical_start: u64) {
    buf[0..4].copy_from_slice(&logical_block.to_le_bytes());
    buf[4..6].copy_from_slice(&raw_len.to_le_bytes());
    // Physical start is stored as: low 32 bits at [8..12], high 16 bits at [6..8]
    let phys_hi = ((physical_start >> 32) & 0xFFFF) as u16;
    let phys_lo = (physical_start & 0xFFFF_FFFF) as u32;
    buf[6..8].copy_from_slice(&phys_hi.to_le_bytes());
    buf[8..12].copy_from_slice(&phys_lo.to_le_bytes());
}

/// Serialize an index entry.
fn write_index_entry(buf: &mut [u8], logical_block: u32, leaf_block: u64) {
    buf[0..4].copy_from_slice(&logical_block.to_le_bytes());
    let lo = (leaf_block & 0xFFFF_FFFF) as u32;
    let hi = ((leaf_block >> 32) & 0xFFFF) as u16;
    buf[4..8].copy_from_slice(&lo.to_le_bytes());
    buf[8..10].copy_from_slice(&hi.to_le_bytes());
    buf[10..12].copy_from_slice(&0u16.to_le_bytes()); // unused
}

/// Build a depth-0 root with 4 contiguous extents, each mapping 100 logical blocks.
fn build_depth0_root() -> [u8; 60] {
    let mut root = [0u8; 60];
    write_header(
        &mut root[..HEADER_SIZE],
        ROOT_EXTENTS as u16,
        ROOT_EXTENTS as u16,
        0,
    );

    for i in 0..ROOT_EXTENTS {
        let offset = HEADER_SIZE + i * ENTRY_SIZE;
        let logical = (i as u32) * 100;
        let physical = 1000 + (i as u64) * 100;
        write_leaf_extent(
            &mut root[offset..offset + ENTRY_SIZE],
            logical,
            100,
            physical,
        );
    }

    root
}

/// Build a depth-1 tree: root has 4 index entries pointing to external leaf blocks.
/// Each leaf has `LEAF_ENTRIES_PER_NODE` contiguous extents of length 1.
/// Total coverage: 4 * 340 = 1360 logical blocks.
fn build_depth1_tree() -> (MemBlockDevice, [u8; 60]) {
    // We need 4 child blocks (blocks 10..13) + some padding blocks
    let dev = MemBlockDevice::new(BLOCK_SIZE, 20);

    // Root: depth=1, 4 index entries
    let mut root = [0u8; 60];
    write_header(
        &mut root[..HEADER_SIZE],
        DEPTH1_CHILDREN as u16,
        ROOT_EXTENTS as u16,
        1,
    );

    for i in 0..DEPTH1_CHILDREN {
        let offset = HEADER_SIZE + i * ENTRY_SIZE;
        let logical = (i * LEAF_ENTRIES_PER_NODE) as u32;
        let child_block = (10 + i) as u64;
        write_index_entry(&mut root[offset..offset + ENTRY_SIZE], logical, child_block);
    }

    // Build each leaf block
    for child_idx in 0..DEPTH1_CHILDREN {
        let mut block_data = vec![0u8; BLOCK_SIZE as usize];
        let entries_in_leaf = LEAF_ENTRIES_PER_NODE.min(340); // Cap at max
        write_header(
            &mut block_data[..HEADER_SIZE],
            entries_in_leaf as u16,
            entries_in_leaf as u16,
            0,
        );

        for e in 0..entries_in_leaf {
            let off = HEADER_SIZE + e * ENTRY_SIZE;
            let logical = (child_idx * LEAF_ENTRIES_PER_NODE + e) as u32;
            let physical = 5000 + u64::from(logical);
            write_leaf_extent(&mut block_data[off..off + ENTRY_SIZE], logical, 1, physical);
        }

        dev.write_block_data(10 + child_idx, &block_data);
    }

    (dev, root)
}

// ── Benchmarks ─────────────────────────────────────────────────────────────

/// Benchmark extent resolve on a depth-0 tree (extents in root node).
/// This is the "cached" scenario: all data is in the 60-byte root, no I/O.
fn bench_extent_resolve_depth0(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let root = build_depth0_root();
    // Use a dummy device (depth-0 never reads blocks)
    let dev = MemBlockDevice::new(BLOCK_SIZE, 1);

    c.bench_function("extent_resolve_depth0_cached", |b| {
        b.iter(|| {
            // Resolve logical block 150 → should be in the 2nd extent (100..199)
            let result = ffs_extent::map_logical_to_physical(
                black_box(&cx),
                black_box(&dev),
                black_box(&root),
                black_box(150),
                black_box(1),
            )
            .expect("resolve");
            black_box(result);
        });
    });
}

/// Benchmark extent resolve on a depth-1 tree requiring external block reads.
/// This is the "uncached" scenario: must read a leaf block from the device.
fn bench_extent_resolve_depth1(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();

    c.bench_function("extent_resolve_depth1_uncached", |b| {
        b.iter(|| {
            // Resolve logical block 700 → 3rd child, entry 700-680=20
            let result = ffs_extent::map_logical_to_physical(
                black_box(&cx),
                black_box(&dev),
                black_box(&root),
                black_box(700),
                black_box(1),
            )
            .expect("resolve");
            black_box(result);
        });
    });
}

/// Benchmark resolving a range of blocks (batch mapping).
fn bench_extent_resolve_range(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let root = build_depth0_root();
    let dev = MemBlockDevice::new(BLOCK_SIZE, 1);

    c.bench_function("extent_resolve_range_50blocks", |b| {
        b.iter(|| {
            let result = ffs_extent::map_logical_to_physical(
                black_box(&cx),
                black_box(&dev),
                black_box(&root),
                black_box(50),
                black_box(50),
            )
            .expect("resolve range");
            black_box(result);
        });
    });
}

/// Benchmark repeated lookups (simulates cached access pattern).
fn bench_extent_resolve_repeated(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();

    c.bench_function("extent_resolve_depth1_repeated", |b| {
        b.iter(|| {
            // Resolve same block 10 times (simulates hot path)
            for _ in 0..10 {
                let result = ffs_extent::map_logical_to_physical(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(500),
                    black_box(1),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
}

/// Benchmark repeated lookups WITH the ExtentCache (same logical block 10 times).
fn bench_extent_resolve_cached_repeated(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();
    let cache = ffs_extent::ExtentCache::new();

    // Warm the cache with one lookup.
    ffs_extent::cached_map_logical_to_physical(&cx, &dev, &root, 500, 1, &cache, 0).expect("warm");

    c.bench_function("extent_resolve_depth1_cached_repeated", |b| {
        b.iter(|| {
            for _ in 0..10 {
                let result = ffs_extent::cached_map_logical_to_physical(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(500),
                    black_box(1),
                    black_box(&cache),
                    black_box(0),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
}

/// Benchmark sequential read pattern: blocks 0..100, uncached vs cached.
fn bench_extent_sequential_uncached(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();

    c.bench_function("extent_sequential_100blocks_uncached", |b| {
        b.iter(|| {
            for blk in 0..100_u32 {
                let result = ffs_extent::map_logical_to_physical(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(blk),
                    black_box(1),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
}

fn bench_extent_sequential_cached(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let (dev, root) = build_depth1_tree();
    let cache = ffs_extent::ExtentCache::new();

    c.bench_function("extent_sequential_100blocks_cached", |b| {
        b.iter(|| {
            for blk in 0..100_u32 {
                let result = ffs_extent::cached_map_logical_to_physical(
                    black_box(&cx),
                    black_box(&dev),
                    black_box(&root),
                    black_box(blk),
                    black_box(1),
                    black_box(&cache),
                    black_box(0),
                )
                .expect("resolve");
                black_box(result);
            }
        });
    });
}

// bd-wc9v4 — bench coverage for ExtentCache mutation paths
// (insert / invalidate_range / invalidate_all / eviction-at-capacity).
// bd-upa13 just landed 5 MR proptests pinning correctness; these
// benches pin the latency floor for the same code paths so a future
// regression that swapped the BTreeMap for a slower structure or
// removed the LRU optimisation would trip the perf gate.

fn bench_extent_cache_insert_cold(c: &mut Criterion) {
    let mapping = ffs_extent::ExtentMapping {
        logical_start: 100,
        physical_start: 5_000,
        count: 50,
        unwritten: false,
    };

    c.bench_function("extent_cache_insert_cold", |b| {
        b.iter(|| {
            // Fresh cache each iteration ensures we measure the cold-insert
            // path (no eviction, no LRU update).
            let cache = ffs_extent::ExtentCache::new();
            cache.insert(black_box(0), black_box(mapping));
            black_box(cache);
        });
    });
}

fn bench_extent_cache_invalidate_range_overlapping(c: &mut Criterion) {
    // Pre-populate a cache with 64 mappings in a single namespace.
    let cache = ffs_extent::ExtentCache::with_capacity(128);
    for i in 0..64_u32 {
        cache.insert(
            0,
            ffs_extent::ExtentMapping {
                logical_start: i * 10,
                physical_start: 1_000 + u64::from(i) * 10,
                count: 10,
                unwritten: false,
            },
        );
    }

    c.bench_function("extent_cache_invalidate_range_overlapping", |b| {
        b.iter(|| {
            // Re-insert and invalidate the same range — this measures
            // the BTreeMap range-scan + filter + remove pipeline.
            cache.insert(
                black_box(0),
                ffs_extent::ExtentMapping {
                    logical_start: 200,
                    physical_start: 9_999,
                    count: 30,
                    unwritten: false,
                },
            );
            cache.invalidate_range(black_box(0), black_box(200), black_box(30));
        });
    });
}

fn bench_extent_cache_invalidate_all(c: &mut Criterion) {
    // Pre-populate a cache with 64 mappings; each iteration re-inserts
    // and invalidates everything to measure the bulk-reset cost.
    let mapping = |i: u32| ffs_extent::ExtentMapping {
        logical_start: i * 10,
        physical_start: 1_000 + u64::from(i) * 10,
        count: 10,
        unwritten: false,
    };

    c.bench_function("extent_cache_invalidate_all_64entries", |b| {
        b.iter(|| {
            let cache = ffs_extent::ExtentCache::with_capacity(128);
            for i in 0..64_u32 {
                cache.insert(0, mapping(i));
            }
            cache.invalidate_all();
            black_box(cache);
        });
    });
}

fn bench_extent_cache_eviction_at_capacity(c: &mut Criterion) {
    // Steady-state churn: capacity 16, insert 32 mappings → 16 evictions.
    // Pins the LRU eviction tax under the workload that triggers it.
    c.bench_function("extent_cache_eviction_at_capacity_32inserts_cap16", |b| {
        b.iter(|| {
            let cache = ffs_extent::ExtentCache::with_capacity(16);
            for i in 0..32_u32 {
                cache.insert(
                    black_box(0),
                    ffs_extent::ExtentMapping {
                        logical_start: i * 10,
                        physical_start: 1_000 + u64::from(i) * 10,
                        count: 10,
                        unwritten: false,
                    },
                );
            }
            black_box(cache);
        });
    });
}

criterion_group!(
    extent_resolve,
    bench_extent_resolve_depth0,
    bench_extent_resolve_depth1,
    bench_extent_resolve_range,
    bench_extent_resolve_repeated,
    bench_extent_resolve_cached_repeated,
    bench_extent_sequential_uncached,
    bench_extent_sequential_cached,
    bench_extent_cache_insert_cold,
    bench_extent_cache_invalidate_range_overlapping,
    bench_extent_cache_invalidate_all,
    bench_extent_cache_eviction_at_capacity,
);
criterion_main!(extent_resolve);
