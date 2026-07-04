#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the staged-block reads in the JBD2 replay
//! apply phase, `replay_jbd2_inner` (bd-pkvrj).
//!
//! The apply phase reads one staged journal block per committed-dirty target
//! block, verifies it, restores any escaped magic, then writes it to the target.
//! On a crash-recovery mount this serializes one device-read access latency per
//! committed block — thousands for a busy fs crashed mid-workload — gating mount
//! time. The reads are independent; only `resolve_block` (an FnMut closure) and
//! the verify/escape/write/count are order-sensitive.
//!
//! The lever splits apply into serial-plan (resolve block numbers) +
//! parallel-read (read staged blocks across the rayon pool) + serial-consume
//! (verify/escape/write/count in target order). A blocking read parks its
//! worker, so the access latencies overlap up to the pool size — bounded by the
//! pool, not the CPU core count (bd-g5v1s/bd-w52e5 family).
//!
//! This bench isolates the read phase on a `LatencyBlockDevice` (fixed per-read
//! latency park + cheap memcpy from a pre-built store, the production cost
//! shape). Both arms run the identical apply transform and produce the identical
//! applied bytes in target order (asserted), so this measures only the read
//! overlap.
//!
//! It also carries the bd-xmh5g.404 A/B for replay block materialization:
//! old `as_slice().to_vec()` versus `BlockBuf::into_inner()` on owned staged
//! blocks. The apply consume phase needs an owned `Vec<u8>` either way; the new
//! path moves the owned aligned buffer when the backing read produced a unique
//! block.

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
const COMMIT_CHKSUM_OFFSET: usize = 16;
const CHECKSUM_FIELD_SIZE: usize = 4;
const CHECKSUM_ZERO_FIELD: [u8; CHECKSUM_FIELD_SIZE] = [0; CHECKSUM_FIELD_SIZE];
const COMMIT_SEGMENTED_CHECKSUM_MIN: usize = 4096;

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

fn commit_block_bytes(len: usize) -> Vec<u8> {
    let mut block: Vec<u8> = (0..len).map(|i| prng(0x00C0_FFEE_u64 ^ i as u64)).collect();
    block[COMMIT_CHKSUM_OFFSET..COMMIT_CHKSUM_OFFSET + CHECKSUM_FIELD_SIZE]
        .copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    block
}

fn commit_checksum_old_clone(block: &[u8], seed: u32) -> Option<u32> {
    if block.len() < COMMIT_CHKSUM_OFFSET + CHECKSUM_FIELD_SIZE {
        return None;
    }

    let mut temp = block.to_vec();
    temp[COMMIT_CHKSUM_OFFSET..COMMIT_CHKSUM_OFFSET + CHECKSUM_FIELD_SIZE].fill(0);
    Some(!crc32c::crc32c_append(!seed, &temp))
}

fn commit_checksum_segmented(block: &[u8], seed: u32) -> Option<u32> {
    if block.len() < COMMIT_CHKSUM_OFFSET + CHECKSUM_FIELD_SIZE {
        return None;
    }

    let checksum = crc32c::crc32c_append(!seed, &block[..COMMIT_CHKSUM_OFFSET]);
    let checksum = crc32c::crc32c_append(checksum, &CHECKSUM_ZERO_FIELD);
    let checksum = crc32c::crc32c_append(
        checksum,
        &block[COMMIT_CHKSUM_OFFSET + CHECKSUM_FIELD_SIZE..],
    );
    Some(!checksum)
}

fn commit_checksum_adaptive(block: &[u8], seed: u32) -> Option<u32> {
    let after_field = COMMIT_CHKSUM_OFFSET + CHECKSUM_FIELD_SIZE;
    if block.len() < after_field {
        return None;
    }

    if block.len() < COMMIT_SEGMENTED_CHECKSUM_MIN {
        return commit_checksum_old_clone(block, seed);
    }

    let checksum = crc32c::crc32c_append(!seed, &block[..COMMIT_CHKSUM_OFFSET]);
    let checksum = crc32c::crc32c_append(checksum, &CHECKSUM_ZERO_FIELD);
    let checksum = crc32c::crc32c_append(checksum, &block[after_field..]);
    Some(!checksum)
}

/// Latency-injecting in-memory device (blocks pre-built once).
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
        Ok(())
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

/// Fast owned-read device for materialization A/B rows.
struct OwnedReadBlockDevice {
    blocks: Vec<Vec<u8>>,
}

impl OwnedReadBlockDevice {
    fn new(block_count: u64) -> Self {
        let blocks = (0..block_count).map(block_bytes).collect();
        Self { blocks }
    }

    fn block_owned(&self, block: BlockNumber) -> Result<BlockBuf> {
        let idx = usize::try_from(block.0)
            .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
        self.blocks
            .get(idx)
            .map(|bytes| BlockBuf::new(bytes.clone()))
            .ok_or_else(|| FfsError::Format(format!("bench block out of range: {}", block.0)))
    }
}

impl BlockDevice for OwnedReadBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        self.block_owned(block)
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Ok(())
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

/// The representative per-block apply transform (mirrors the escaped-magic
/// restore in `replay_jbd2_inner`): no-op here, returns the staged bytes.
fn apply_transform(data: Vec<u8>) -> Vec<u8> {
    data
}

/// OLD: serial read + apply loop — N read latencies back to back.
fn apply_serial(
    cx: &Cx,
    device: &dyn BlockDevice,
    targets: &[BlockNumber],
) -> Result<Vec<Vec<u8>>> {
    let mut applied = Vec::with_capacity(targets.len());
    for &block in targets {
        let data = device.read_block(cx, block)?.as_slice().to_vec();
        applied.push(apply_transform(data));
    }
    Ok(applied)
}

/// NEW: serial plan (here just the targets) + parallel read + serial apply.
fn apply_parallel(
    cx: &Cx,
    device: &dyn BlockDevice,
    targets: &[BlockNumber],
) -> Result<Vec<Vec<u8>>> {
    let reads: Vec<Result<Vec<u8>>> = targets
        .par_iter()
        .map(|&block| device.read_block(cx, block).map(|b| b.as_slice().to_vec()))
        .collect();
    let mut applied = Vec::with_capacity(reads.len());
    for read in reads {
        applied.push(apply_transform(read?));
    }
    Ok(applied)
}

/// OLD bd-xmh5g.404: read an owned BlockBuf, then copy it into a Vec.
fn materialize_old_to_vec(
    cx: &Cx,
    device: &dyn BlockDevice,
    targets: &[BlockNumber],
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(targets.len());
    for &block in targets {
        out.push(device.read_block(cx, block)?.as_slice().to_vec());
    }
    Ok(out)
}

/// NEW bd-xmh5g.404: consume the read BlockBuf and move its Vec when unique.
fn materialize_into_inner(
    cx: &Cx,
    device: &dyn BlockDevice,
    targets: &[BlockNumber],
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(targets.len());
    for &block in targets {
        out.push(device.read_block(cx, block)?.into_inner());
    }
    Ok(out)
}

fn bench_apply(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("journal_replay_apply_io_overlap");
    for &n in &[16_usize, 64, 256] {
        let device = LatencyBlockDevice::new(n as u64, READ_LATENCY);
        let targets: Vec<BlockNumber> = (0..n as u64).map(BlockNumber).collect();

        // Isomorphism: both apply strategies produce the identical bytes, in order.
        assert_eq!(
            apply_serial(&cx, &device, &targets).expect("serial apply"),
            apply_parallel(&cx, &device, &targets).expect("parallel apply"),
            "parallel apply diverged from serial (n={n})"
        );

        group.bench_with_input(BenchmarkId::new("serial", n), &n, |b, _| {
            b.iter(|| black_box(apply_serial(&cx, &device, black_box(&targets))));
        });
        group.bench_with_input(BenchmarkId::new("parallel_rayon", n), &n, |b, _| {
            b.iter(|| black_box(apply_parallel(&cx, &device, black_box(&targets))));
        });
    }
    group.finish();
}

fn bench_blockbuf_materialize(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let mut group = c.benchmark_group("journal_replay_blockbuf_materialize");
    for &n in &[16_usize, 64, 256] {
        let device = OwnedReadBlockDevice::new(n as u64);
        let targets: Vec<BlockNumber> = (0..n as u64).map(BlockNumber).collect();

        assert_eq!(
            materialize_old_to_vec(&cx, &device, &targets).expect("old materialize"),
            materialize_into_inner(&cx, &device, &targets).expect("new materialize"),
            "into_inner materialization changed bytes (n={n})"
        );

        group.bench_with_input(BenchmarkId::new("old_to_vec", n), &n, |b, _| {
            b.iter(|| black_box(materialize_old_to_vec(&cx, &device, black_box(&targets))));
        });
        group.bench_with_input(BenchmarkId::new("into_inner", n), &n, |b, _| {
            b.iter(|| black_box(materialize_into_inner(&cx, &device, black_box(&targets))));
        });
    }
    group.finish();
}

fn bench_commit_checksum(c: &mut Criterion) {
    let seed = 0xA55A_F00D;
    let mut group = c.benchmark_group("journal_commit_checksum_zero_field_clone_vs_segmented");
    for &len in &[1024_usize, 4096, 16_384] {
        let block = commit_block_bytes(len);

        assert_eq!(
            commit_checksum_old_clone(&block, seed),
            commit_checksum_segmented(&block, seed),
            "segmented commit checksum diverged from clone-zero model (len={len})"
        );
        assert_eq!(
            commit_checksum_old_clone(&block, seed),
            commit_checksum_adaptive(&block, seed),
            "adaptive commit checksum diverged from clone-zero model (len={len})"
        );

        group.bench_with_input(
            BenchmarkId::new("clone_zero_full_crc", len),
            &len,
            |b, _| {
                b.iter(|| black_box(commit_checksum_old_clone(black_box(&block), seed)));
            },
        );
        group.bench_with_input(BenchmarkId::new("segmented_zero_crc", len), &len, |b, _| {
            b.iter(|| black_box(commit_checksum_segmented(black_box(&block), seed)));
        });
        group.bench_with_input(BenchmarkId::new("adaptive_zero_crc", len), &len, |b, _| {
            b.iter(|| black_box(commit_checksum_adaptive(black_box(&block), seed)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_apply,
    bench_blockbuf_materialize,
    bench_commit_checksum
);
criterion_main!(benches);
