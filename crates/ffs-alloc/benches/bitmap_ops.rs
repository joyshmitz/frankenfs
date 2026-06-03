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

fn raw_get_bit(bitmap: &[u8], pos: u32) -> bool {
    let byte_idx = (pos / 8) as usize;
    let bit_idx = pos % 8;
    (bitmap[byte_idx] >> bit_idx) & 1 == 1
}

fn raw_read_word(bitmap: &[u8], word_idx: u32) -> u64 {
    let byte_start = (word_idx * 8) as usize;
    let mut word = 0_u64;
    for (i, &byte) in bitmap[byte_start..bitmap.len().min(byte_start + 8)]
        .iter()
        .enumerate()
    {
        word |= u64::from(byte) << (i * 8);
    }
    word
}

fn raw_select_nth_set_bit(mut word: u64, mut n: u32) -> u32 {
    loop {
        let bit = word.trailing_zeros();
        if n == 0 {
            return bit;
        }
        word &= word - 1;
        n -= 1;
    }
}

fn select0_in_block_bit_scan(
    bitmap: &[u8],
    block_idx: u32,
    len: u32,
    mut remaining: u32,
) -> Option<u32> {
    let bit_base = block_idx * 256;
    let bits_in_block = 256.min(len - bit_base);

    for bit in 0..bits_in_block {
        let pos = bit_base + bit;
        if !raw_get_bit(bitmap, pos) {
            if remaining == 0 {
                return Some(pos);
            }
            remaining -= 1;
        }
    }

    None
}

fn select0_in_block_broadword(
    bitmap: &[u8],
    block_idx: u32,
    len: u32,
    mut remaining: u32,
) -> Option<u32> {
    let mut word_base = block_idx * 256;
    let block_end = word_base.saturating_add(256).min(len);

    while word_base < block_end {
        let bits_in_word = (block_end - word_base).min(64);
        let mut zero_mask = !raw_read_word(bitmap, word_base / 64);
        if bits_in_word < 64 {
            zero_mask &= (1_u64 << bits_in_word) - 1;
        }

        let zeros_in_word = zero_mask.count_ones();
        if remaining < zeros_in_word {
            return Some(word_base + raw_select_nth_set_bit(zero_mask, remaining));
        }
        remaining -= zeros_in_word;
        word_base += 64;
    }

    None
}

/// A/B only the one changed lever: the final in-block select0 scan.
fn bench_select0_in_block_bit_scan_vs_broadword(c: &mut Criterion) {
    let mut bm = vec![0xFF_u8; 64]; // 512 bits, two succinct 256-bit blocks.
    for pos in [256_u32, 257, 258, 300, 301, 302, 303, 304] {
        bm[(pos / 8) as usize] &= !(1 << (pos % 8));
    }
    let len = 305;
    let block_idx = 1;
    let target_in_block = 7;
    debug_assert_eq!(
        select0_in_block_bit_scan(&bm, block_idx, len, target_in_block),
        select0_in_block_broadword(&bm, block_idx, len, target_in_block)
    );

    let mut group = c.benchmark_group("select0_in_block");
    group.bench_function("old_bit_scan", |b| {
        b.iter(|| {
            black_box(select0_in_block_bit_scan(
                black_box(&bm),
                block_idx,
                len,
                black_box(target_in_block),
            ))
        });
    });
    group.bench_function("new_broadword", |b| {
        b.iter(|| {
            black_box(select0_in_block_broadword(
                black_box(&bm),
                block_idx,
                len,
                black_box(target_in_block),
            ))
        });
    });
    group.finish();
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

/// Pre-optimization contiguous free-run scan. Kept only for same-binary A/B
/// proof of the word-at-a-time production path.
fn find_contiguous_byte_scan(bitmap: &[u8], count: u32, n: u32, start: u32) -> Option<u32> {
    fn range(bitmap: &[u8], count: u32, n: u32, start: u32) -> Option<u32> {
        let mut run_start = start;
        let mut run_len = 0_u32;
        let mut idx = start;

        while idx < count {
            if idx % 8 == 0 && (idx + 8) <= count {
                let byte_idx = (idx / 8) as usize;
                match bitmap.get(byte_idx).copied() {
                    None | Some(0xFF) => {
                        idx += 8;
                        run_start = idx;
                        run_len = 0;
                        continue;
                    }
                    Some(0x00) => {
                        if run_len == 0 {
                            run_start = idx;
                        }
                        run_len = run_len.saturating_add(8);
                        if run_len >= n {
                            return Some(run_start);
                        }
                        idx += 8;
                        continue;
                    }
                    Some(byte) => {
                        let base = idx;
                        for bit in 0..8 {
                            let pos = base + bit;
                            if (byte >> bit) & 1 == 1 {
                                run_start = pos + 1;
                                run_len = 0;
                            } else {
                                run_len += 1;
                                if run_len >= n {
                                    return Some(run_start);
                                }
                            }
                        }
                        idx += 8;
                        continue;
                    }
                }
            }

            if raw_get_bit(bitmap, idx) {
                idx += 1;
                run_start = idx;
                run_len = 0;
            } else {
                run_len += 1;
                if run_len >= n {
                    return Some(run_start);
                }
                idx += 1;
            }
        }
        None
    }

    if n == 0 {
        return Some(0);
    }
    if n > count {
        return None;
    }
    range(bitmap, count, n, start).or_else(|| {
        let pass2_end = start.saturating_add(n).saturating_sub(1).min(count);
        range(bitmap, pass2_end, n, 0)
    })
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

/// A/B contiguous free-run search on the same ext4-like bitmap used by the
/// production benchmark. This isolates the 64-bit skip path from rch worker
/// variance.
fn bench_find_contiguous_word_vs_byte(c: &mut Criterion) {
    let bm = make_bitmap();
    let count = 32768;
    let n = 32;
    let start = 16000;
    debug_assert_eq!(
        find_contiguous_byte_scan(&bm, count, n, start),
        bitmap_find_contiguous(&bm, count, n, start),
        "byte and word contiguous scans must agree"
    );

    let mut group = c.benchmark_group("find_contiguous_ab");
    group.bench_function("old_byte_scan", |b| {
        b.iter(|| {
            black_box(find_contiguous_byte_scan(
                black_box(&bm),
                count,
                black_box(n),
                black_box(start),
            ))
        });
    });
    group.bench_function("word_at_a_time", |b| {
        b.iter(|| {
            black_box(bitmap_find_contiguous(
                black_box(&bm),
                count,
                black_box(n),
                black_box(start),
            ))
        });
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
    bench_select0_in_block_bit_scan_vs_broadword,
    bench_build,
    bench_find_free_full_scan_word_vs_byte,
    bench_find_contiguous_word_vs_byte,
);
criterion_main!(benches);
