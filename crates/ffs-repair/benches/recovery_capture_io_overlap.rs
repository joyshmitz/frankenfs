#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the per-block device reads in
//! `RecoverySession::capture_expected_current_blocks` (bd-g5v1s).
//!
//! `capture_expected_current_blocks` reads each corrupt block's scrub-time
//! "expected current" bytes with a serial loop:
//!   `for index in corrupt_indices { device.read_block(cx, block)?.to_vec() }`
//! The reads are independent, so a recovery touching N corrupt blocks serializes
//! N device-read access latencies. On real storage each ranged read pays a
//! seek / queue / network round trip, so this is the rank-1 cost of capture —
//! not the cheap `to_vec` copy.
//!
//! The lever plans the block numbers serially (keeping the up-front cancellation
//! checkpoints) and then reads them across the rayon pool. A blocking read parks
//! its worker, so the per-read latencies overlap up to the pool size (the same
//! parking effect behind bd-307e4/bd-tyym4/bd-yg6tk) — bounded by the pool, not
//! the CPU core count, so it clears the ~2x ceiling that CPU-bound parallelism
//! hits on the ~2-effective-core CI remote.
//!
//! The in-memory test device is a zero-latency memcpy and cannot show the win; a
//! `LatencyBlockDevice` parks the worker for a fixed per-read latency before
//! delegating to a pre-built store (so a read is latency + cheap memcpy, the
//! production cost shape). Both arms produce the identical `(block, bytes)`
//! sequence in block order (asserted), so this measures only the read-latency
//! overlap.

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const BS: usize = 4096; // block size (bytes)
/// Per-block read access latency. Models a real-disk / SSD-queue round trip.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Latency-injecting in-memory device. Block contents are built ONCE up front,
/// so a read is a fixed latency park plus a cheap memcpy out of the pre-built
/// store — the production cost shape (the device delivers bytes cheaply; the
/// access latency is the real cost).
struct LatencyBlockDevice {
    blocks: Vec<BlockBuf>,
    read_latency: Duration,
}

impl LatencyBlockDevice {
    fn new(block_count: u64, read_latency: Duration) -> Self {
        let blocks = (0..block_count)
            .map(|blk| {
                let bytes: Vec<u8> = (0..BS).map(|i| prng(blk << 20 ^ i as u64)).collect();
                BlockBuf::new(bytes)
            })
            .collect();
        Self {
            blocks,
            read_latency,
        }
    }

    fn block(&self, block: BlockNumber) -> Result<BlockBuf> {
        let idx = usize::try_from(block.0)
            .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
        self.blocks
            .get(idx)
            .map(BlockBuf::clone_ref)
            .ok_or_else(|| FfsError::Format(format!("bench block out of range: {}", block.0)))
    }
}

impl BlockDevice for LatencyBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        std::thread::sleep(self.read_latency);
        self.block(block)
    }

    fn supports_contiguous_reads(&self) -> bool {
        false
    }

    fn read_contiguous_blocks(
        &self,
        _cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> Result<()> {
        std::thread::sleep(self.read_latency);
        for (i, buf) in bufs.iter_mut().enumerate() {
            *buf = self.block(BlockNumber(start.0 + i as u64))?;
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

/// OLD: serial per-block read loop — N read latencies back to back.
fn capture_serial(
    cx: &Cx,
    device: &dyn BlockDevice,
    blocks: &[BlockNumber],
) -> Result<Vec<(BlockNumber, Vec<u8>)>> {
    let mut out = Vec::with_capacity(blocks.len());
    for &block in blocks {
        let bytes = device.read_block(cx, block)?.as_slice().to_vec();
        out.push((block, bytes));
    }
    Ok(out)
}

/// NEW: parallel reads across the rayon pool, consumed in block order.
fn capture_parallel(
    cx: &Cx,
    device: &dyn BlockDevice,
    blocks: &[BlockNumber],
) -> Result<Vec<(BlockNumber, Vec<u8>)>> {
    let reads: Vec<Result<(BlockNumber, Vec<u8>)>> = blocks
        .to_vec()
        .into_par_iter()
        .map(|block| {
            let bytes = device.read_block(cx, block)?.as_slice().to_vec();
            Ok((block, bytes))
        })
        .collect();
    let mut out = Vec::with_capacity(reads.len());
    for read in reads {
        out.push(read?);
    }
    Ok(out)
}

fn bench_capture(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("recovery_capture_io_overlap");
    for &n in &[16_usize, 64, 256] {
        let device = LatencyBlockDevice::new(n as u64, READ_LATENCY);
        // Corrupt blocks: every block in the (sorted, unique) range.
        let blocks: Vec<BlockNumber> = (0..n as u64).map(BlockNumber).collect();

        // Isomorphism: both strategies capture the identical (block, bytes) seq.
        assert_eq!(
            capture_serial(&cx, &device, &blocks).expect("serial capture"),
            capture_parallel(&cx, &device, &blocks).expect("parallel capture"),
            "parallel capture diverged from serial (n={n})"
        );

        group.bench_with_input(BenchmarkId::new("serial", n), &n, |b, _| {
            b.iter(|| black_box(capture_serial(&cx, &device, black_box(&blocks))));
        });
        group.bench_with_input(BenchmarkId::new("parallel_rayon", n), &n, |b, _| {
            b.iter(|| black_box(capture_parallel(&cx, &device, black_box(&blocks))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_capture);
criterion_main!(benches);
