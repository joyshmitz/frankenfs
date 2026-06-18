#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the non-contiguous run reads in ext4
//! `read_ext4_indirect` (bd-r9c10, I/O-overlap sibling of the extent-path
//! bd-yg6tk).
//!
//! `read_ext4_indirect` is the legacy indirect-mapped read path. It already
//! coalesces a contiguous-physical run of full blocks into one vectored op
//! (bd-bov9c), but a fragmented legacy file with N non-contiguous runs issued
//! those N run reads back-to-back, so on real storage (each ranged read pays an
//! access latency) the N latencies serialized. The lever plans the read into
//! ordered segments serially (the indirect-block resolution stays serial — it's
//! a dependent, cached chain), then reads each segment's bytes in a rayon
//! `par_iter` and assembles them into the output buffer in byte order.
//!
//! This bench isolates that fan-out. The in-memory device is a zero-latency
//! memcpy and cannot show the win; a `LatencyBlockDevice` parks the worker for a
//! fixed per-read latency before delegating to a pre-built store. Both arms read
//! identical bytes into an identical buffer (asserted), so this measures only the
//! latency overlap.

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const RUN_BLOCKS: usize = 8; // blocks per contiguous run
const BS: usize = 4096; // ext4 block size
const RUN_BYTES: usize = RUN_BLOCKS * BS;
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
        true
    }

    fn read_contiguous_blocks(
        &self,
        _cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        std::thread::sleep(self.read_latency);
        for (i, buf) in bufs.iter_mut().enumerate() {
            let idx = usize::try_from(start.0 + i as u64)
                .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
            *buf = self
                .blocks
                .get(idx)
                .map(BlockBuf::clone_ref)
                .ok_or_else(|| FfsError::Format("bench block out of range".into()))?;
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

/// Read one contiguous run of `RUN_BLOCKS` blocks starting at `phys0`.
fn read_run(cx: &Cx, dev: &LatencyBlockDevice, phys0: u64) -> Result<Vec<u8>> {
    let mut bufs = vec![BlockBuf::new(Vec::new()); RUN_BLOCKS];
    dev.read_contiguous_blocks(cx, BlockNumber(phys0), &mut bufs)?;
    let mut out = Vec::with_capacity(RUN_BYTES);
    for b in &bufs {
        out.extend_from_slice(b.as_slice());
    }
    Ok(out)
}

/// OLD: read each run serially into the output in byte order.
fn read_serial(cx: &Cx, dev: &LatencyBlockDevice, run_starts: &[u64]) -> Result<Vec<u8>> {
    let mut buf = vec![0_u8; run_starts.len() * RUN_BYTES];
    for (i, &phys0) in run_starts.iter().enumerate() {
        let data = read_run(cx, dev, phys0)?;
        buf[i * RUN_BYTES..(i + 1) * RUN_BYTES].copy_from_slice(&data);
    }
    Ok(buf)
}

/// NEW: read runs in parallel into owned buffers, assemble in byte order.
fn read_parallel(cx: &Cx, dev: &LatencyBlockDevice, run_starts: &[u64]) -> Result<Vec<u8>> {
    let reads: Vec<Result<Vec<u8>>> = run_starts
        .par_iter()
        .map(|&phys0| read_run(cx, dev, phys0))
        .collect();
    let mut buf = vec![0_u8; run_starts.len() * RUN_BYTES];
    for (i, read) in reads.into_iter().enumerate() {
        let data = read?;
        buf[i * RUN_BYTES..(i + 1) * RUN_BYTES].copy_from_slice(&data);
    }
    Ok(buf)
}

fn bench_indirect(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("ext4_indirect_read_overlap");
    for &runs in &[16_usize, 64, 256] {
        // Non-contiguous runs: a gap between each run so they cannot coalesce.
        let total_blocks = (runs as u64) * (RUN_BLOCKS as u64) * 2 + RUN_BLOCKS as u64;
        let dev = LatencyBlockDevice::new(total_blocks, READ_LATENCY);
        let run_starts: Vec<u64> = (0..runs as u64)
            .map(|r| r * (RUN_BLOCKS as u64) * 2)
            .collect();

        assert_eq!(
            read_serial(&cx, &dev, &run_starts).expect("serial"),
            read_parallel(&cx, &dev, &run_starts).expect("parallel"),
            "parallel indirect read diverged from serial (runs={runs})"
        );

        group.bench_with_input(BenchmarkId::new("serial", runs), &runs, |b, _| {
            b.iter(|| black_box(read_serial(&cx, &dev, black_box(&run_starts))));
        });
        group.bench_with_input(BenchmarkId::new("parallel_rayon", runs), &runs, |b, _| {
            b.iter(|| black_box(read_parallel(&cx, &dev, black_box(&run_starts))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_indirect);
criterion_main!(benches);
