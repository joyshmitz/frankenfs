#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the child-block reads in the ext4 extent-tree
//! walk `collect_extents_recursive` (bd-8nrzh, I/O-overlap analogue of the btrfs
//! parallel walk bd-h6p3w).
//!
//! At each interior (Index) node the walk range-prunes its children, then read
//! each surviving child block and recurses. A fragmented file whose extent tree
//! has many children read those child blocks back-to-back, serializing one
//! device-read access latency per child. The lever plans the surviving children
//! serially (cheap, order-preserving), reads their blocks in a rayon `par_iter`
//! so the latencies overlap, then parses + recurses serially in child order
//! (extents stay in sorted logical order; first error in child order preserved).
//!
//! This bench isolates that per-node fan-out. The in-memory device is a
//! zero-latency memcpy; a `LatencyBlockDevice` parks the worker for a fixed
//! per-read latency before delegating. Both arms produce the identical extent
//! list (asserted), so this measures only the latency overlap.

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const BS: usize = 4096; // ext4 block size
/// Per-read access latency. Models a real-disk / SSD-queue round trip.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Latency-injecting in-memory device (blocks pre-built once).
struct LatencyBlockDevice {
    blocks: Vec<BlockBuf>,
    read_latency: Duration,
}

impl LatencyBlockDevice {
    fn new(block_count: u64, read_latency: Duration) -> Self {
        let blocks = (0..block_count)
            .map(|blk| BlockBuf::new((0..BS).map(|i| prng(blk << 20 ^ i as u64)).collect()))
            .collect();
        Self {
            blocks,
            read_latency,
        }
    }
}

impl BlockDevice for LatencyBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        std::thread::sleep(self.read_latency);
        let idx = usize::try_from(block.0)
            .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
        self.blocks
            .get(idx)
            .map(BlockBuf::clone_ref)
            .ok_or_else(|| FfsError::Format(format!("bench block out of range: {}", block.0)))
    }

    fn supports_contiguous_reads(&self) -> bool {
        false
    }

    fn read_contiguous_blocks(
        &self,
        cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        for (i, buf) in bufs.iter_mut().enumerate() {
            *buf = self.read_block(cx, BlockNumber(start.0 + i as u64))?;
        }
        Ok(())
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn block_size(&self) -> u32 {
        BS as u32
    }

    fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

/// Model "parse a leaf child block into its extents": derive a few u64s from the
/// block bytes (stands in for `parse_extent_tree` + `extend_from_slice`).
fn parse_child(data: &BlockBuf) -> Vec<u64> {
    let s = data.as_slice();
    (0..4).map(|k| u64::from(s[k * 8]) ^ (k as u64)).collect()
}

/// OLD: read each surviving child serially, parse + accumulate in order.
fn walk_serial(cx: &Cx, dev: &LatencyBlockDevice, children: &[u64]) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for &leaf_block in children {
        let data = dev.read_block(cx, BlockNumber(leaf_block))?;
        out.extend_from_slice(&parse_child(&data));
    }
    Ok(out)
}

/// NEW: read children in parallel, then parse + accumulate serially in order.
fn walk_parallel(cx: &Cx, dev: &LatencyBlockDevice, children: &[u64]) -> Result<Vec<u64>> {
    let reads: Vec<Result<BlockBuf>> = children
        .par_iter()
        .map(|&leaf_block| dev.read_block(cx, BlockNumber(leaf_block)))
        .collect();
    let mut out = Vec::new();
    for read in reads {
        out.extend_from_slice(&parse_child(&read?));
    }
    Ok(out)
}

fn bench_walk(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("ext4_extent_tree_walk_overlap");
    for &fanout in &[16_usize, 64, 256] {
        let dev = LatencyBlockDevice::new(fanout as u64, READ_LATENCY);
        let children: Vec<u64> = (0..fanout as u64).collect();

        assert_eq!(
            walk_serial(&cx, &dev, &children).expect("serial"),
            walk_parallel(&cx, &dev, &children).expect("parallel"),
            "parallel extent-tree walk diverged from serial (fanout={fanout})"
        );

        group.bench_with_input(BenchmarkId::new("serial", fanout), &fanout, |b, _| {
            b.iter(|| black_box(walk_serial(&cx, &dev, black_box(&children))));
        });
        group.bench_with_input(
            BenchmarkId::new("parallel_rayon", fanout),
            &fanout,
            |b, _| {
                b.iter(|| black_box(walk_parallel(&cx, &dev, black_box(&children))));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_walk);
criterion_main!(benches);
