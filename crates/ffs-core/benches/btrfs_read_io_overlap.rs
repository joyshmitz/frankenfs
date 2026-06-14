#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for overlapping the multi-extent compressed-blob device
//! reads in `btrfs_read_file` (bd-307e4, sibling of the bd-m6g2o decompress).
//!
//! A btrfs read that spans N compressed extents must, for each covering
//! extent, read the compressed blob from the device and then decompress it.
//! bd-m6g2o already moved the *decompress* into a rayon `into_par_iter` map,
//! but the per-extent *device read* stayed serial in the gathering pass: a
//! read spanning N extents issued N device reads back-to-back. On real
//! storage each read pays an access latency (seek / queue / network round
//! trip), so N serial reads serialize N latencies. bd-307e4 defers the read
//! into the same parallel map, so the N reads (and decompresses) overlap.
//!
//! This bench isolates that I/O fan-out the way `btrfs_decompress_extents`
//! isolates the decompress fan-out. The in-memory test device used by the
//! unit tests is a zero-latency memcpy, so it cannot show the win; here a
//! `LatencyDevice` parks the worker for a fixed per-read latency (modeling a
//! real-disk/SSD-queue access time) before returning the blob. The two arms
//! mirror the production shapes exactly and assert identical decompressed
//! output, so this measures only the read-latency overlap, not any change in
//! result:
//!   * `serial_read_then_par_decompress` — the pre-bd-307e4 shape: read every
//!     blob serially, then `into_par_iter` decompress.
//!   * `par_read_and_decompress` — the bd-307e4 shape: `into_par_iter` over the
//!     read specs, reading the blob and decompressing it inside the map.

use criterion::{Criterion, criterion_group, criterion_main};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use std::hint::black_box;
use std::time::Duration;

const N: usize = 16; // compressed extents in the read (≈2 MiB read)
const RAM: usize = 128 * 1024; // uncompressed extent size (btrfs cap)
/// Per-read access latency. Models a real-disk/SSD-queue round trip; the
/// in-memory unit-test device is zero-latency and cannot exhibit the overlap.
/// Read latency dominates the µs-scale decompress (as it does on real
/// storage), so the bench measures the read serialization the lever removes.
const READ_LATENCY: Duration = Duration::from_micros(250);

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// A device whose every read pays a fixed access latency before returning the
/// stored compressed blob — a stand-in for `btrfs_read_logical_into` against
/// real storage. Parking (not spinning) models a blocking read that frees the
/// core, so concurrent reads overlap their latencies up to the rayon pool size.
struct LatencyDevice {
    blobs: Vec<Vec<u8>>,
}

impl LatencyDevice {
    fn read(&self, idx: usize) -> Vec<u8> {
        std::thread::sleep(READ_LATENCY);
        self.blobs[idx].clone()
    }
}

/// Build N zstd-compressed blobs of semi-compressible 128 KiB payloads.
fn build_compressed() -> Vec<Vec<u8>> {
    (0..N)
        .map(|e| {
            let plain: Vec<u8> = (0..RAM)
                .map(|b| {
                    if b % 8 < 4 {
                        (e as u8).wrapping_add((b / 64) as u8)
                    } else {
                        prng((e as u64) << 24 ^ b as u64)
                    }
                })
                .collect();
            zstd::encode_all(plain.as_slice(), 3).expect("zstd compress")
        })
        .collect()
}

fn decompress_one(compressed: &[u8]) -> Vec<u8> {
    zstd::decode_all(compressed).expect("zstd decompress")
}

/// Pre-bd-307e4: read every blob serially, then decompress in parallel.
fn serial_read_then_par_decompress(dev: &LatencyDevice) -> Vec<Vec<u8>> {
    let mut gathered: Vec<(usize, Vec<u8>)> = Vec::with_capacity(N);
    for idx in 0..N {
        gathered.push((idx, dev.read(idx)));
    }
    let mut out: Vec<(usize, Vec<u8>)> = gathered
        .into_par_iter()
        .map(|(idx, blob)| (idx, decompress_one(&blob)))
        .collect();
    out.sort_by_key(|(idx, _)| *idx);
    out.into_iter().map(|(_, v)| v).collect()
}

/// bd-307e4: read and decompress each blob inside the parallel map.
fn par_read_and_decompress(dev: &LatencyDevice) -> Vec<Vec<u8>> {
    let mut out: Vec<(usize, Vec<u8>)> = (0..N)
        .into_par_iter()
        .map(|idx| {
            let blob = dev.read(idx);
            (idx, decompress_one(&blob))
        })
        .collect();
    out.sort_by_key(|(idx, _)| *idx);
    out.into_iter().map(|(_, v)| v).collect()
}

fn bench_btrfs_read_io_overlap(c: &mut Criterion) {
    let dev = LatencyDevice {
        blobs: build_compressed(),
    };

    // Isomorphism: both arms produce byte-identical decompressed extents.
    assert_eq!(
        serial_read_then_par_decompress(&dev),
        par_read_and_decompress(&dev),
        "bd-307e4 parallel read+decompress diverged from serial-read shape"
    );

    let mut group = c.benchmark_group("btrfs_read_io_overlap_16extents");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(3));
    group.bench_function("serial_read_then_par_decompress", |b| {
        b.iter(|| black_box(serial_read_then_par_decompress(black_box(&dev))));
    });
    group.bench_function("par_read_and_decompress", |b| {
        b.iter(|| black_box(par_read_and_decompress(black_box(&dev))));
    });
    group.finish();
}

criterion_group!(benches, bench_btrfs_read_io_overlap);
criterion_main!(benches);
