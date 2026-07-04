#![forbid(unsafe_code)]
//! Measures the per-alloc bitmap checksum recompute cost (full crc32c over a
//! blocks_per_group bitmap) vs the crc of just the changed region — pinpointing
//! the dominant per-alloc CPU cost AFTER the bit-loop->range wins made marking
//! O(N/8). NEGATIVE/FLAG: incremental crc via GF crc-shift is ~as expensive as
//! the full crc for an arbitrary-position delta; batching the recompute needs
//! deferring the bitmap write = owner-lane MVCC.
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench bitmap_csum_recompute
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
fn bench(c: &mut Criterion) {
    let bitmap4k = vec![0xA5u8; 4096];   // 32768-block group bitmap
    let bitmap1k = vec![0xA5u8; 1024];   // 8192-inode group bitmap
    let delta = vec![0xFFu8; 8];         // one 64-bit word changed (a small alloc)
    let mut g = c.benchmark_group("bitmap_csum");
    g.bench_function("full_recompute_4k", |b| b.iter(|| black_box(crc32c::crc32c(black_box(&bitmap4k)))));
    g.bench_function("full_recompute_1k", |b| b.iter(|| black_box(crc32c::crc32c(black_box(&bitmap1k)))));
    g.bench_function("crc_of_delta_8b", |b| b.iter(|| black_box(crc32c::crc32c(black_box(&delta)))));
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
