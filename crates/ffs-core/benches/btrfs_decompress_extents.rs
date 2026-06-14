#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for parallelizing the multi-extent btrfs decompress in
//! `btrfs_read_file` (bd-m6g2o).
//!
//! A btrfs read that spans N compressed extents decompresses each covering
//! extent (zstd/zlib/lzo) before copying its bytes into the output buffer.
//! Compressed extents are capped at 128 KiB uncompressed, so a multi-megabyte
//! read fans out across many independent decompress jobs. The old assembly
//! loop ran them serially, one per extent; the new code gathers the compressed
//! blobs and decompresses them in parallel across cores (rayon) before the
//! sequential copy-into-output assembly.
//!
//! This bench isolates that decompress fan-out: build N independently
//! zstd-compressed 128 KiB blobs, then decompress all N serially vs. via
//! `into_par_iter`. Both produce the identical decompressed blobs (asserted) —
//! `zstd::decode_all` is a pure function of its input, so parallelism only
//! reorders execution.

use criterion::{Criterion, criterion_group, criterion_main};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::hint::black_box;

const N: usize = 16; // compressed extents in the read (≈2 MiB read)
const RAM: usize = 128 * 1024; // uncompressed extent size (btrfs cap)

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Build N zstd-compressed blobs of semi-compressible 128 KiB payloads
/// (mix of repeated runs + pseudo-random bytes — typical file data that
/// btrfs would choose to compress).
fn build_compressed() -> Vec<Vec<u8>> {
    (0..N)
        .map(|e| {
            let plain: Vec<u8> = (0..RAM)
                .map(|b| {
                    // ~Half the bytes are a low-entropy run, half pseudo-random,
                    // so zstd achieves a realistic (not pathological) ratio.
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

fn decompress_serial(blobs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    blobs.iter().map(|b| decompress_one(b)).collect()
}

fn decompress_parallel(blobs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    blobs.par_iter().map(|b| decompress_one(b)).collect()
}

fn bench_decompress(c: &mut Criterion) {
    let blobs = build_compressed();

    // Isomorphism: parallel produces the identical decompressed extents, same
    // order, as the serial fan-out.
    assert_eq!(
        decompress_serial(&blobs),
        decompress_parallel(&blobs),
        "parallel decompress diverged from serial"
    );

    let mut group = c.benchmark_group("btrfs_decompress_extents_n16_128k");
    group.bench_function("serial", |b| {
        b.iter(|| black_box(decompress_serial(black_box(&blobs))));
    });
    group.bench_function("parallel_rayon", |b| {
        b.iter(|| black_box(decompress_parallel(black_box(&blobs))));
    });
    group.finish();
}

criterion_group!(benches, bench_decompress);
criterion_main!(benches);
