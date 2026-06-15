#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the per-batch device reads in
//! `Scrubber::scrub_range` (bd-tyym4, I/O-overlap restructure).
//!
//! `scrub_range` reads each 64-block batch contiguously (one vectored device
//! read), validates the batch, then advances to the next batch. The batches
//! were read back-to-back, so a whole-device scrub serialized one device-read
//! latency per batch. On real storage each ranged read pays an access latency
//! (seek / queue / network round trip), and a TB scrub is dominated by those
//! reads — so serializing them is the rank-1 cost, not the (pure crc32c)
//! validation.
//!
//! The lever partitions the range into chunks scanned in parallel across the
//! rayon pool. A blocking read parks its worker, so the chunk reads overlap up
//! to the pool size (the same parking effect that drives the read-path levers
//! bd-307e4/bd-strse/bd-yg6tk) — crucially this is bounded by the thread-pool
//! size, NOT the CPU core count, so it exceeds the ~2x ceiling that CPU-bound
//! validate-only parallelism hit on the ~2-effective-core CI remote.
//!
//! This bench isolates that I/O fan-out. The in-memory test device is a
//! zero-latency memcpy and cannot show the win; a `LatencyBlockDevice` parks
//! the worker for a fixed per-read latency before delegating. Both arms produce
//! an identical verdict-tag sequence (findings stay in block order), so this
//! measures only the read-latency overlap:
//!   * `serial_scan` — the pre-lever shape: read every batch serially.
//!   * `parallel_scan` — the lever: chunk the range and scan the chunks in an
//!     `into_par_iter` map, concatenating verdicts in chunk (block) order.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_repair::scrub::{BlockValidator, BlockVerdict, CorruptionKind, Severity};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const BATCH: usize = 64; // scrub read batch (matches SCRUB_READ_BATCH_BLOCKS)
const BLOCKS: u64 = 64 * BATCH as u64; // 64 batch reads over the range
const BS: usize = 4096; // block size
/// Per-ranged-read access latency. Models a real-disk/SSD-queue round trip.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Representative integrity validator: checksums every block (crc32c over the
/// whole block) and flags blocks whose checksum has its low bit set.
struct Crc32cValidator;

impl BlockValidator for Crc32cValidator {
    fn validate(&self, block: BlockNumber, data: &BlockBuf) -> BlockVerdict {
        let crc = crc32c::crc32c(data.as_slice());
        if crc & 1 == 0 {
            BlockVerdict::Clean
        } else {
            BlockVerdict::Corrupt(vec![(
                CorruptionKind::StructuralInvariant,
                Severity::Error,
                format!("synthetic odd-crc finding for block {}", block.0),
            )])
        }
    }
}

/// Latency-injecting in-memory device. Block contents are built ONCE up front
/// (not per read), so a read is a fixed latency park plus a cheap memcpy out of
/// the pre-built store — the in-production cost shape (the device delivers bytes
/// cheaply; the access latency is the real cost). This keeps the bench a clean
/// I/O-overlap + (real crc) validate measurement rather than inflating it with
/// per-read fill CPU.
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

/// Tag a verdict so the two arms can be compared without `PartialEq`.
fn tag(v: &BlockVerdict) -> u8 {
    match v {
        BlockVerdict::Clean => 0,
        BlockVerdict::Corrupt(_) => 1,
        BlockVerdict::Skip => 2,
    }
}

/// Scan `[sub_start, sub_end)` with the serial batch-read + validate loop,
/// pushing one verdict tag per block in block order.
fn scan_subrange(
    dev: &LatencyBlockDevice,
    validator: &Crc32cValidator,
    cx: &Cx,
    sub_start: u64,
    sub_end: u64,
) -> Vec<u8> {
    let mut tags = Vec::new();
    let mut bufs: Vec<BlockBuf> = Vec::new();
    let mut next = sub_start;
    while next < sub_end {
        let batch_len = ((sub_end - next) as usize).min(BATCH);
        if bufs.len() < batch_len {
            bufs.resize_with(batch_len, || BlockBuf::new(Vec::new()));
        }
        dev.read_contiguous_blocks(cx, BlockNumber(next), &mut bufs[..batch_len])
            .expect("bench batch read");
        for (i, buf) in bufs[..batch_len].iter().enumerate() {
            tags.push(tag(&validator.validate(BlockNumber(next + i as u64), buf)));
        }
        next += batch_len as u64;
    }
    tags
}

/// Pre-lever: scan the whole range serially.
fn serial_scan(dev: &LatencyBlockDevice, validator: &Crc32cValidator, cx: &Cx) -> Vec<u8> {
    scan_subrange(dev, validator, cx, 0, BLOCKS)
}

/// Lever: chunk the range (~8 chunks per pool thread) and scan chunks in
/// parallel, concatenating verdicts in chunk (block) order.
fn parallel_scan(dev: &LatencyBlockDevice, validator: &Crc32cValidator, cx: &Cx) -> Vec<u8> {
    let parallelism = rayon::current_num_threads().max(1) as u64;
    let chunk = (BLOCKS / (parallelism * 8)).max(BATCH as u64).max(1);
    let num_chunks = usize::try_from(BLOCKS.div_ceil(chunk)).unwrap_or(usize::MAX);
    let chunks: Vec<Vec<u8>> = (0..num_chunks)
        .into_par_iter()
        .map(|ci| {
            let sub_start = ci as u64 * chunk;
            let sub_end = (sub_start + chunk).min(BLOCKS);
            scan_subrange(dev, validator, cx, sub_start, sub_end)
        })
        .collect();
    chunks.into_iter().flatten().collect()
}

fn bench_scrub_scan_io_overlap(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let validator = Crc32cValidator;
    let dev = LatencyBlockDevice::new(BLOCKS, READ_LATENCY);

    // Isomorphism: identical verdict-tag sequence regardless of chunking.
    assert_eq!(
        serial_scan(&dev, &validator, &cx),
        parallel_scan(&dev, &validator, &cx),
        "parallel scrub scan diverged from serial"
    );

    let mut group = c.benchmark_group("scrub_scan_io_overlap_64batches");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("serial_scan", |b| {
        b.iter(|| {
            black_box(serial_scan(
                black_box(&dev),
                black_box(&validator),
                black_box(&cx),
            ))
        });
    });
    group.bench_function("parallel_scan", |b| {
        b.iter(|| {
            black_box(parallel_scan(
                black_box(&dev),
                black_box(&validator),
                black_box(&cx),
            ))
        });
    });
    group.finish();
}

criterion_group!(benches, bench_scrub_scan_io_overlap);
criterion_main!(benches);
