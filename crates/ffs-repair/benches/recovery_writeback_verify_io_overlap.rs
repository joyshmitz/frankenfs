#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the read-compare loops in
//! `DirectDeviceRecoveryWriteback::writeback_recovered` (bd-3q9eq).
//!
//! `writeback_recovered` runs two read-only per-block loops over the recovered
//! blocks — a pre-write compare-and-write gate and a post-write verification —
//! plus the (serial) write loop between them. Each read-compare loop reads every
//! recovered block back from the device, so a recovery touching N blocks
//! serializes 2N device-read access latencies. On real storage each read pays a
//! seek / queue / network round trip, so those reads are the rank-1 cost of the
//! writeback, not the byte compare.
//!
//! The lever parallelizes each read-compare loop: `recovered.par_iter()` reads +
//! compares across the rayon pool, then the outcomes are consumed in index order
//! so the first compare/verify failure is reported identically to the serial
//! loop. A blocking read parks its worker, so the per-read latencies overlap up
//! to the pool size (bounded by the pool, not the CPU core count) — the same
//! parking effect as bd-307e4/bd-tyym4/bd-g5v1s.
//!
//! This bench isolates one read-compare loop on a `LatencyBlockDevice` (a fixed
//! per-read latency park plus a cheap memcpy out of a pre-built store, the
//! production cost shape). Both arms produce the identical compare result, so
//! this measures only the read-latency overlap.

use asupersync::Cx;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
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

fn block_bytes(blk: u64) -> Vec<u8> {
    (0..BS).map(|i| prng(blk << 20 ^ i as u64)).collect()
}

/// Latency-injecting in-memory device. Block contents are built ONCE up front,
/// so a read is a fixed latency park plus a cheap memcpy out of the pre-built
/// store — the production cost shape.
struct LatencyBlockDevice {
    blocks: Vec<BlockBuf>,
    read_latency: Duration,
}

impl LatencyBlockDevice {
    fn new(block_count: u64, read_latency: Duration) -> Self {
        let blocks = (0..block_count)
            .map(|blk| BlockBuf::new(block_bytes(blk)))
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

/// One recovered block plus the bytes it should match on read-back.
struct VerifyItem {
    block: BlockNumber,
    expected: Vec<u8>,
}

/// OLD: serial read-compare loop — N read latencies back to back.
fn verify_serial(cx: &Cx, device: &dyn BlockDevice, items: &[VerifyItem]) -> Result<()> {
    for item in items {
        let observed = device.read_block(cx, item.block)?;
        if observed.as_slice() != item.expected.as_slice() {
            return Err(FfsError::RepairFailed(format!(
                "verify failed at block {}",
                item.block.0
            )));
        }
    }
    Ok(())
}

/// NEW: parallel read-compare across the rayon pool, consumed in index order.
fn verify_parallel(cx: &Cx, device: &dyn BlockDevice, items: &[VerifyItem]) -> Result<()> {
    let outcomes: Vec<Result<()>> = items
        .par_iter()
        .map(|item| {
            let observed = device.read_block(cx, item.block)?;
            if observed.as_slice() != item.expected.as_slice() {
                return Err(FfsError::RepairFailed(format!(
                    "verify failed at block {}",
                    item.block.0
                )));
            }
            Ok(())
        })
        .collect();
    for outcome in outcomes {
        outcome?;
    }
    Ok(())
}

fn bench_verify(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("recovery_writeback_verify_io_overlap");
    for &n in &[16_usize, 64, 256] {
        let device = LatencyBlockDevice::new(n as u64, READ_LATENCY);
        let items: Vec<VerifyItem> = (0..n as u64)
            .map(|blk| VerifyItem {
                block: BlockNumber(blk),
                expected: block_bytes(blk),
            })
            .collect();

        // Isomorphism: both strategies agree the read-back matches.
        assert!(
            verify_serial(&cx, &device, &items).is_ok()
                && verify_parallel(&cx, &device, &items).is_ok(),
            "verify arms disagreed (n={n})"
        );

        group.bench_with_input(BenchmarkId::new("serial", n), &n, |b, _| {
            b.iter(|| black_box(verify_serial(&cx, &device, black_box(&items))));
        });
        group.bench_with_input(BenchmarkId::new("parallel_rayon", n), &n, |b, _| {
            b.iter(|| black_box(verify_parallel(&cx, &device, black_box(&items))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
