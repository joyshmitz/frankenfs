//! Benchmark: succinct bitmap vs plain linear scan.
//!
//! Compares O(1) rank / O(log n) select via `SuccinctBitmap` against
//! the plain `bitmap_count_free` / `bitmap_find_free` O(n) helpers.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_alloc::succinct::SuccinctBitmap;
use ffs_alloc::{
    bitmap_count_free, bitmap_find_contiguous, bitmap_find_free, bitmap_largest_free_run,
};
use std::hint::black_box;

/// Build a realistic ext4-like bitmap: 4096 bytes (32768 bits),
/// ~5% free blocks scattered in clusters.
fn make_bitmap() -> Vec<u8> {
    let mut bm = vec![0xFF_u8; 4096];
    // Free a cluster every ~650 blocks (≈5% free).
    let mut pos = 100_usize;
    while pos + 32 < 32768 {
        for i in pos..pos + 32 {
            bm[i / 8] &= !(1 << (i % 8));
        }
        pos += 650;
    }
    bm
}

/// Build a fragmented bitmap dominated by mixed bytes, where byte-level run
/// summaries should beat per-bit inspection.
fn make_fragmented_bitmap() -> Vec<u8> {
    let pattern = [0b1110_0001, 0b1000_1111, 0b1111_1000, 0b1100_0011];
    pattern.into_iter().cycle().take(4096).collect()
}

fn bench_count_free(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);

    let mut group = c.benchmark_group("count_free");

    group.bench_function("plain_O(n)", |b| {
        b.iter(|| black_box(bitmap_count_free(black_box(&bm), 32768)));
    });

    group.bench_function("succinct_O(1)", |b| {
        b.iter(|| black_box(sb.count_zeros()));
    });

    group.finish();
}

fn bench_find_free(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);

    let mut group = c.benchmark_group("find_free");

    group.bench_function("plain_O(n)", |b| {
        b.iter(|| black_box(bitmap_find_free(black_box(&bm), 32768, black_box(16000))));
    });

    group.bench_function("succinct_O(log_n)", |b| {
        b.iter(|| black_box(sb.find_free(black_box(16000))));
    });

    group.finish();
}

fn bench_find_contiguous(c: &mut Criterion) {
    let bm = make_bitmap();

    let mut group = c.benchmark_group("find_contiguous");

    group.bench_function("plain_32_O(n)", |b| {
        b.iter(|| {
            black_box(bitmap_find_contiguous(
                black_box(&bm),
                32768,
                black_box(32),
                black_box(16000),
            ))
        });
    });

    group.finish();
}

fn bench_largest_free_run(c: &mut Criterion) {
    let bm = make_fragmented_bitmap();

    let mut group = c.benchmark_group("largest_free_run");

    group.bench_function("fragmented_mixed_bytes", |b| {
        b.iter(|| black_box(bitmap_largest_free_run(black_box(&bm), 32768)));
    });

    group.finish();
}

fn bench_rank(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);

    c.bench_function("succinct_rank0", |b| {
        b.iter(|| black_box(sb.rank0(black_box(20000))));
    });
}

fn bench_select(c: &mut Criterion) {
    let bm = make_bitmap();
    let sb = SuccinctBitmap::build(&bm, 32768);
    let target = sb.count_zeros() / 2; // select the middle free block

    c.bench_function("succinct_select0", |b| {
        b.iter(|| black_box(sb.select0(black_box(target))));
    });
}

fn bench_build(c: &mut Criterion) {
    let bm = make_bitmap();

    c.bench_function("succinct_build", |b| {
        b.iter(|| black_box(SuccinctBitmap::build(black_box(&bm), 32768)));
    });
}

/// Pre-optimization byte-at-a-time find-free scan (the shape `bitmap_find_free`
/// had before the word-at-a-time fast path). Kept here only to A/B the lever in
/// one binary on one CPU (so the ratio is valid despite rch worker variance).
fn find_free_byte_scan(bitmap: &[u8], count: u32, start: u32) -> Option<u32> {
    fn range(bitmap: &[u8], mut idx: u32, end: u32) -> Option<u32> {
        while idx < end && idx % 8 != 0 {
            let &byte = bitmap.get((idx / 8) as usize)?;
            if (byte >> (idx % 8)) & 1 == 0 {
                return Some(idx);
            }
            idx += 1;
        }
        while end.saturating_sub(idx) >= 8 {
            let &byte = bitmap.get((idx / 8) as usize)?;
            if byte != 0xFF {
                return Some(idx + (!byte).trailing_zeros());
            }
            idx += 8;
        }
        while idx < end {
            let &byte = bitmap.get((idx / 8) as usize)?;
            if (byte >> (idx % 8)) & 1 == 0 {
                return Some(idx);
            }
            idx += 1;
        }
        None
    }
    let start = start.min(count);
    range(bitmap, start, count).or_else(|| range(bitmap, 0, start))
}

/// A/B the word-at-a-time lever against the old byte scan over a fully
/// allocated (all-0xFF) 4 KiB block bitmap — the worst case that forces a full
/// scan to the end (returns None). Both run in this one binary on one CPU.
fn bench_find_free_full_scan_word_vs_byte(c: &mut Criterion) {
    let bm = vec![0xFF_u8; 4096]; // 32768 bits, no free bit → full scan
    debug_assert_eq!(
        find_free_byte_scan(&bm, 32768, 0),
        bitmap_find_free(&bm, 32768, 0),
        "byte and word scans must agree"
    );

    let mut group = c.benchmark_group("find_free_full_scan");
    group.bench_function("byte_at_a_time", |b| {
        b.iter(|| black_box(find_free_byte_scan(black_box(&bm), 32768, 0)));
    });
    group.bench_function("word_at_a_time", |b| {
        b.iter(|| black_box(bitmap_find_free(black_box(&bm), 32768, 0)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_count_free,
    bench_find_free,
    bench_find_contiguous,
    bench_largest_free_run,
    bench_rank,
    bench_select,
    bench_build,
    bench_find_free_full_scan_word_vs_byte,
);
criterion_main!(benches);
