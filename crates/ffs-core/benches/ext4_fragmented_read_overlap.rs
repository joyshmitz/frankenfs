#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the non-contiguous extent-run device reads
//! in ext4 `read_file_data` (bd-yg6tk, I/O-overlap sibling of bd-strse).
//!
//! `read_file_data` walks a file's logical blocks in a sequential cursor,
//! coalescing each maximal run of logically+physically-consecutive written
//! blocks into one vectored `read_contiguous_into` (bd-a384r). But a fragmented
//! file with N non-contiguous runs issued those N run reads back-to-back, so on
//! real storage (where each ranged read pays an access latency — seek / queue /
//! network round trip) the N latencies serialized. bd-yg6tk plans the whole
//! read into segments serially (the metadata descent stays serial), then reads
//! the data-bearing runs in a rayon `into_par_iter` over disjoint `split_at_mut`
//! windows of the output buffer, overlapping the latencies.
//!
//! This bench isolates that I/O fan-out. The in-memory unit-test device is a
//! zero-latency memcpy and cannot show the win; a generic
//! `LatencyBlockDevice<D: BlockDevice>` decorator parks the worker for a fixed
//! per-read latency before delegating. Both arms read identical bytes into
//! identical windows and assert equality, so this measures only the latency
//! overlap:
//!   * `serial_runs_into_out` — pre-bd-yg6tk: read each run into its window one
//!     at a time.
//!   * `par_runs_into_out` — bd-yg6tk: carve disjoint windows and read each run
//!     inside an `into_par_iter` map.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const RUNS: usize = 16; // non-contiguous extent runs in the read
const RUN_BLOCKS: usize = 8; // blocks per run
const BS: usize = 4096; // ext4 block size
const RUN_BYTES: usize = RUN_BLOCKS * BS;
/// Per-read access latency. Models a real-disk/SSD-queue round trip; the
/// in-memory unit-test device is zero-latency and cannot exhibit the overlap.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Generic latency-injecting decorator for any `BlockDevice`.
struct LatencyBlockDevice<D> {
    inner: D,
    read_latency: Duration,
}

impl<D: BlockDevice> LatencyBlockDevice<D> {
    fn new(inner: D, read_latency: Duration) -> Self {
        Self {
            inner,
            read_latency,
        }
    }
}

impl<D: BlockDevice> BlockDevice for LatencyBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        std::thread::sleep(self.read_latency);
        self.inner.read_block(cx, block)
    }

    fn supports_contiguous_reads(&self) -> bool {
        self.inner.supports_contiguous_reads()
    }

    fn read_contiguous_blocks(
        &self,
        cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        std::thread::sleep(self.read_latency);
        self.inner.read_contiguous_blocks(cx, start, bufs)
    }

    fn read_contiguous_into(&self, cx: &Cx, start: BlockNumber, dst: &mut [u8]) -> Result<()> {
        // One access latency per ranged read (a full run), mirroring the
        // production `read_contiguous_into_with_scope` fast path.
        std::thread::sleep(self.read_latency);
        self.inner.read_contiguous_into(cx, start, dst)
    }

    fn write_block(&self, cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
        self.inner.write_block(cx, block, data)
    }

    fn write_contiguous_blocks(&self, cx: &Cx, start: BlockNumber, data: &[u8]) -> Result<()> {
        self.inner.write_contiguous_blocks(cx, start, data)
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.inner.sync(cx)
    }
}

/// Flat-backed bench device: `block` indexes into a contiguous byte store, so
/// `read_contiguous_into` serves a whole run in one ranged read.
struct FlatBlockDevice {
    bytes: Vec<u8>,
}

impl FlatBlockDevice {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl BlockDevice for FlatBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        let start = usize::try_from(block.0)
            .ok()
            .and_then(|b| b.checked_mul(BS))
            .ok_or_else(|| FfsError::Format("bench block index overflow".into()))?;
        let end = start
            .checked_add(BS)
            .filter(|e| *e <= self.bytes.len())
            .ok_or_else(|| FfsError::Format(format!("bench block out of range: {}", block.0)))?;
        Ok(BlockBuf::new(self.bytes[start..end].to_vec()))
    }

    fn supports_contiguous_reads(&self) -> bool {
        true
    }

    fn read_contiguous_into(&self, _cx: &Cx, start: BlockNumber, dst: &mut [u8]) -> Result<()> {
        let off = usize::try_from(start.0)
            .ok()
            .and_then(|b| b.checked_mul(BS))
            .ok_or_else(|| FfsError::Format("bench block index overflow".into()))?;
        let end = off
            .checked_add(dst.len())
            .filter(|e| *e <= self.bytes.len())
            .ok_or_else(|| FfsError::Format("bench contiguous read out of range".into()))?;
        dst.copy_from_slice(&self.bytes[off..end]);
        Ok(())
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn block_size(&self) -> u32 {
        BS as u32
    }

    fn block_count(&self) -> u64 {
        (self.bytes.len() / BS) as u64
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

/// Physical start block of run `r`, spaced so runs are non-contiguous (a gap
/// block between them — the fragmentation that defeats run-coalescing).
fn run_phys_block(r: usize) -> u64 {
    (r * (RUN_BLOCKS + 1)) as u64
}

/// Build a flat device whose blocks cover every run's physical extent.
fn build_device() -> FlatBlockDevice {
    let total_blocks = run_phys_block(RUNS - 1) as usize + RUN_BLOCKS;
    let mut bytes = vec![0_u8; total_blocks * BS];
    for r in 0..RUNS {
        let base = run_phys_block(r) as usize * BS;
        for (i, byte) in bytes[base..base + RUN_BYTES].iter_mut().enumerate() {
            *byte = prng((r as u64) << 24 ^ i as u64);
        }
    }
    FlatBlockDevice::new(bytes)
}

/// Pre-bd-yg6tk: read each run serially into its output window.
fn serial_runs_into_out(dev: &impl BlockDevice, cx: &Cx) -> Vec<u8> {
    let mut out = vec![0_u8; RUNS * RUN_BYTES];
    for (r, window) in out.chunks_mut(RUN_BYTES).enumerate() {
        dev.read_contiguous_into(cx, BlockNumber(run_phys_block(r)), window)
            .expect("bench run read");
    }
    out
}

/// bd-yg6tk: carve disjoint output windows and read each run in parallel.
fn par_runs_into_out(dev: &impl BlockDevice, cx: &Cx) -> Vec<u8> {
    let mut out = vec![0_u8; RUNS * RUN_BYTES];
    let jobs: Vec<(usize, &mut [u8])> = out.chunks_mut(RUN_BYTES).enumerate().collect();
    jobs.into_par_iter().for_each(|(r, window)| {
        dev.read_contiguous_into(cx, BlockNumber(run_phys_block(r)), window)
            .expect("bench run read");
    });
    out
}

fn bench_ext4_fragmented_read_overlap(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let dev = LatencyBlockDevice::new(build_device(), READ_LATENCY);

    // Isomorphism: both arms produce byte-identical output.
    assert_eq!(
        serial_runs_into_out(&dev, &cx),
        par_runs_into_out(&dev, &cx),
        "bd-yg6tk parallel run read diverged from serial shape"
    );

    let mut group = c.benchmark_group("ext4_fragmented_read_overlap_16runs");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("serial_runs_into_out", |b| {
        b.iter(|| {
            black_box(serial_runs_into_out(black_box(&dev), black_box(&cx)));
        });
    });
    group.bench_function("par_runs_into_out", |b| {
        b.iter(|| {
            black_box(par_runs_into_out(black_box(&dev), black_box(&cx)));
        });
    });
    group.finish();
}

criterion_group!(benches, bench_ext4_fragmented_read_overlap);
criterion_main!(benches);
