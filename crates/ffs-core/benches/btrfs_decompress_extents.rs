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
//! reorders execution. The dedicated-pool arms model bd-defgb: large
//! compressed reads should avoid waking the full global rayon pool, while many
//! small files should not pay one dedicated-pool `install()` per file.

use criterion::{criterion_group, criterion_main, Criterion};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::hint::black_box;

const N: usize = 16; // compressed extents in the read (≈2 MiB read)
const LARGE_N: usize = 272; // ≈34 MiB compressed-read fan-out from bd-defgb
const SMALL_FILES: usize = 64;
const SMALL_EXTENTS_PER_FILE: usize = 4;
const DEDICATED_POOL_MAX_THREADS: usize = 16;
const DEDICATED_POOL_MIN_JOBS: usize = 17;
const RAM: usize = 128 * 1024; // uncompressed extent size (btrfs cap)

/// Deterministic pseudo-random byte (no `Math.random` in benches).
fn prng(seed: u64) -> u8 {
    let x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    (x >> 33) as u8
}

/// Build `n` zstd-compressed blobs of semi-compressible 128 KiB payloads
/// (mix of repeated runs + pseudo-random bytes — typical file data that
/// btrfs would choose to compress).
fn build_compressed(n: usize, seed: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|e| {
            let plain: Vec<u8> = (0..RAM)
                .map(|b| {
                    // ~Half the bytes are a low-entropy run, half pseudo-random,
                    // so zstd achieves a realistic (not pathological) ratio.
                    if b % 8 < 4 {
                        ((seed + e) as u8).wrapping_add((b / 64) as u8)
                    } else {
                        prng(((seed + e) as u64) << 24 ^ b as u64)
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

fn decompress_parallel_sum(blobs: &[Vec<u8>]) -> usize {
    blobs.par_iter().map(|b| decompress_one(b).len()).sum()
}

fn dedicated_pool() -> &'static ThreadPool {
    static POOL: std::sync::OnceLock<ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let threads = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(DEDICATED_POOL_MAX_THREADS)
            .min(DEDICATED_POOL_MAX_THREADS)
            .max(1);
        ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|idx| format!("bench-btrfs-decompress-{idx}"))
            .build()
            .expect("valid dedicated bench pool")
    })
}

fn decompress_parallel_pool(blobs: &[Vec<u8>], pool: &ThreadPool) -> Vec<Vec<u8>> {
    pool.install(|| decompress_parallel(blobs))
}

fn decompress_parallel_pool_sum(blobs: &[Vec<u8>], pool: &ThreadPool) -> usize {
    pool.install(|| decompress_parallel_sum(blobs))
}

fn build_small_files() -> Vec<Vec<Vec<u8>>> {
    (0..SMALL_FILES)
        .map(|file| build_compressed(SMALL_EXTENTS_PER_FILE, file * 1024))
        .collect()
}

fn decompress_files_always_pool(files: &[Vec<Vec<u8>>], pool: &ThreadPool) -> usize {
    files
        .iter()
        .map(|blobs| decompress_parallel_pool_sum(blobs, pool))
        .sum()
}

fn decompress_files_gated(files: &[Vec<Vec<u8>>], pool: &ThreadPool) -> usize {
    files
        .iter()
        .map(|blobs| {
            if blobs.len() >= DEDICATED_POOL_MIN_JOBS {
                decompress_parallel_pool_sum(blobs, pool)
            } else {
                decompress_parallel_sum(blobs)
            }
        })
        .sum()
}

fn bench_decompress(c: &mut Criterion) {
    let blobs = build_compressed(N, 0);

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

fn bench_decompress_pool(c: &mut Criterion) {
    let pool = dedicated_pool();
    let large_blobs = build_compressed(LARGE_N, 0);
    let small_files = build_small_files();

    assert_eq!(
        decompress_parallel(&large_blobs),
        decompress_parallel_pool(&large_blobs, pool),
        "dedicated-pool decompress diverged from global-pool decompress"
    );
    assert_eq!(
        decompress_files_always_pool(&small_files, pool),
        decompress_files_gated(&small_files, pool),
        "small-file gate changed decompressed byte count"
    );

    let mut large = c.benchmark_group("btrfs_decompress_pool_large_272x128k");
    large.bench_function("global_pool", |b| {
        b.iter(|| black_box(decompress_parallel_sum(black_box(&large_blobs))));
    });
    large.bench_function("dedicated_pool_max16", |b| {
        b.iter(|| black_box(decompress_parallel_pool_sum(black_box(&large_blobs), pool)));
    });
    large.finish();

    let mut small = c.benchmark_group("btrfs_decompress_pool_multifile_64x4x128k");
    small.bench_function("always_install_pool_max16", |b| {
        b.iter(|| black_box(decompress_files_always_pool(black_box(&small_files), pool)));
    });
    small.bench_function("gated_small_files", |b| {
        b.iter(|| black_box(decompress_files_gated(black_box(&small_files), pool)));
    });
    small.finish();
}

criterion_group!(benches, bench_decompress, bench_decompress_pool);
criterion_main!(benches);
