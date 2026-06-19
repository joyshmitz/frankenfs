#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the per-cluster block reads in
//! `decompress_e2compr_cluster` (bd-giyxr), completing the ext4 read-family
//! I/O-overlap set (extent bd-yg6tk, indirect bd-r9c10, extent-tree bd-8nrzh).
//!
//! Decompressing an e2compr cluster reads each present cluster block and appends
//! it to the raw buffer before decompression. The reads serialized one device
//! access latency per block. The lever resolves the present block pointers
//! serially, reads them in a rayon `par_iter` (latencies overlap), then appends
//! in block order. This bench isolates that read fan-out on a `LatencyBlockDevice`
//! at realistic small cluster sizes; both arms assemble identical bytes.

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const BS: usize = 4096;
const READ_LATENCY: Duration = Duration::from_micros(250);

fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

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

/// OLD: read each cluster block serially, append in order.
fn cluster_serial(cx: &Cx, dev: &LatencyBlockDevice, ptrs: &[u64]) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(ptrs.len() * BS);
    for &ptr in ptrs {
        let data = dev.read_block(cx, BlockNumber(ptr))?;
        raw.extend_from_slice(data.as_slice());
    }
    Ok(raw)
}

/// NEW: read cluster blocks in parallel, append in order.
fn cluster_parallel(cx: &Cx, dev: &LatencyBlockDevice, ptrs: &[u64]) -> Result<Vec<u8>> {
    let reads: Vec<Result<BlockBuf>> = ptrs
        .par_iter()
        .map(|&ptr| dev.read_block(cx, BlockNumber(ptr)))
        .collect();
    let mut raw = Vec::with_capacity(ptrs.len() * BS);
    for read in reads {
        raw.extend_from_slice(read?.as_slice());
    }
    Ok(raw)
}

fn bench_cluster(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("e2compr_cluster_read_overlap");
    for &nblocks in &[4_usize, 16, 32] {
        let dev = LatencyBlockDevice::new(nblocks as u64, READ_LATENCY);
        let ptrs: Vec<u64> = (0..nblocks as u64).collect();

        assert_eq!(
            cluster_serial(&cx, &dev, &ptrs).expect("serial"),
            cluster_parallel(&cx, &dev, &ptrs).expect("parallel"),
            "parallel cluster read diverged from serial (nblocks={nblocks})"
        );

        group.bench_with_input(BenchmarkId::new("serial", nblocks), &nblocks, |b, _| {
            b.iter(|| black_box(cluster_serial(&cx, &dev, black_box(&ptrs))));
        });
        group.bench_with_input(BenchmarkId::new("parallel_rayon", nblocks), &nblocks, |b, _| {
            b.iter(|| black_box(cluster_parallel(&cx, &dev, black_box(&ptrs))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_cluster);
criterion_main!(benches);
