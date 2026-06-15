#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the multi-extent UNCOMPRESSED device reads
//! in `btrfs_read_file` (bd-strse, I/O-overlap sibling of the bd-307e4
//! compressed-blob gather).
//!
//! A btrfs read that spans N uncompressed regular extents must, for each
//! covering extent, read the extent bytes from the device straight into the
//! output buffer. bd-307e4 already overlapped the *compressed* extents' reads
//! by deferring them into a rayon `into_par_iter` map; the uncompressed extents
//! stayed serial in the assembly loop, so a fragmented file with N
//! non-contiguous uncompressed extents serialized N device-read latencies.
//! bd-strse defers those reads too, carving disjoint `&mut out` windows with
//! `split_at_mut` (zero-copy: each read lands in place) and overlapping them.
//!
//! This bench isolates that I/O fan-out. The in-memory test device used by the
//! unit tests is a zero-latency memcpy, so it cannot show the win; a generic
//! `LatencyBlockDevice<D: BlockDevice>` decorator parks the worker for a fixed
//! per-read latency (modeling a real-disk/SSD-queue access time) before
//! delegating. The two arms mirror the production shapes exactly and assert
//! identical output, so this measures only the read-latency overlap:
//!   * `serial_read_into_out` — the pre-bd-strse shape: read every extent
//!     serially into its `out` window, one device read at a time.
//!   * `par_read_into_out` — the bd-strse shape: carve disjoint `out` windows
//!     and read each extent into its window inside an `into_par_iter` map.

use asupersync::Cx;
use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result};
use ffs_types::BlockNumber;
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const N: usize = 16; // uncompressed extents in the read
const LEN: usize = 128 * 1024; // bytes per extent
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
///
/// Parking (not spinning) models a blocking read that frees the core, so
/// concurrent reads overlap their latencies up to the rayon pool size.
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

/// Blob-backed bench device: one uncompressed extent payload per logical block.
struct BlobBlockDevice {
    blobs: Vec<BlockBuf>,
    max_blob_len: usize,
}

impl BlobBlockDevice {
    fn new(blobs: Vec<Vec<u8>>) -> Self {
        let max_blob_len = blobs.iter().map(Vec::len).max().unwrap_or(0);
        let blobs = blobs.into_iter().map(BlockBuf::new).collect();
        Self {
            blobs,
            max_blob_len,
        }
    }
}

impl BlockDevice for BlobBlockDevice {
    fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
        let idx = usize::try_from(block.0)
            .map_err(|_| FfsError::Format("bench block index overflow".into()))?;
        self.blobs
            .get(idx)
            .map(BlockBuf::clone_ref)
            .ok_or_else(|| FfsError::Format(format!("bench block out of range: {}", block.0)))
    }

    fn write_block(&self, _cx: &Cx, _block: BlockNumber, _data: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn block_size(&self) -> u32 {
        u32::try_from(self.max_blob_len).unwrap_or(u32::MAX)
    }

    fn block_count(&self) -> u64 {
        self.blobs.len() as u64
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        Ok(())
    }
}

/// Build N uncompressed `LEN`-byte extent payloads.
fn build_extents() -> Vec<Vec<u8>> {
    (0..N)
        .map(|e| (0..LEN).map(|b| prng((e as u64) << 24 ^ b as u64)).collect())
        .collect()
}

/// Read extent `idx` straight into `dst` (one device latency), mirroring the
/// production `btrfs_read_logical_into` write-in-place.
fn read_into(dev: &impl BlockDevice, cx: &Cx, idx: usize, dst: &mut [u8]) {
    let block = BlockNumber(u64::try_from(idx).expect("bench index fits u64"));
    let blob = dev.read_block(cx, block).expect("bench read");
    dst.copy_from_slice(blob.as_slice());
}

/// Pre-bd-strse: read each extent serially into its `out` window.
fn serial_read_into_out(dev: &impl BlockDevice, cx: &Cx) -> Vec<u8> {
    let mut out = vec![0_u8; N * LEN];
    for (idx, window) in out.chunks_mut(LEN).enumerate() {
        read_into(dev, cx, idx, window);
    }
    out
}

/// bd-strse: carve disjoint `out` windows and read each extent in parallel.
fn par_read_into_out(dev: &impl BlockDevice, cx: &Cx) -> Vec<u8> {
    let mut out = vec![0_u8; N * LEN];
    let jobs: Vec<(usize, &mut [u8])> = out.chunks_mut(LEN).enumerate().collect();
    jobs.into_par_iter().for_each(|(idx, window)| {
        read_into(dev, cx, idx, window);
    });
    out
}

fn bench_btrfs_uncompressed_read_overlap(c: &mut Criterion) {
    let cx = Cx::for_testing();
    let dev = LatencyBlockDevice::new(BlobBlockDevice::new(build_extents()), READ_LATENCY);

    // Isomorphism: both arms produce byte-identical output.
    assert_eq!(
        serial_read_into_out(&dev, &cx),
        par_read_into_out(&dev, &cx),
        "bd-strse parallel uncompressed read diverged from serial shape"
    );

    let mut group = c.benchmark_group("btrfs_uncompressed_read_overlap_16extents");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("serial_read_into_out", |b| {
        b.iter(|| {
            black_box(serial_read_into_out(black_box(&dev), black_box(&cx)));
        });
    });
    group.bench_function("par_read_into_out", |b| {
        b.iter(|| {
            black_box(par_read_into_out(black_box(&dev), black_box(&cx)));
        });
    });
    group.finish();
}

criterion_group!(benches, bench_btrfs_uncompressed_read_overlap);
criterion_main!(benches);
