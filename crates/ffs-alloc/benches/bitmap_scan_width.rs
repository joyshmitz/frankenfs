#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Throwaway A/B: does a wider (4-u64-unrolled) inode-bitmap free-bit scan beat
//! the current one-u64-per-iteration `bitmap_find_free_range` word scan, or does
//! the compiler already auto-vectorize the simple loop (~0-gain)? The scan runs
//! from bit 0 per inode alloc (no cursor — kernel-faithful lowest-free-inode,
//! conformance-pinned), under `alloc_mutex`, so a long all-`0xFF` allocated
//! prefix in a create-heavy group is scanned every alloc — on the create serial
//! floor (bd-bhh0i per-op cost).
//!
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenfs-cc \
//!   rch exec -- cargo bench --profile release-perf -p ffs-alloc --bench bitmap_scan_width

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// One-u64-per-iteration scan (mirrors the production word fast path).
fn scan_word(bitmap: &[u8], nbits: usize) -> Option<usize> {
    let mut idx = 0usize;
    while nbits - idx >= 64 {
        let b = idx / 8;
        let word = u64::from_le_bytes(bitmap[b..b + 8].try_into().unwrap());
        if word != u64::MAX {
            return Some(idx + (!word).trailing_zeros() as usize);
        }
        idx += 64;
    }
    None
}

/// Four-u64-per-iteration scan: check 4 words against MAX with an OR-reduce,
/// only pinpoint the free bit when the block of 4 isn't fully set.
fn scan_unrolled4(bitmap: &[u8], nbits: usize) -> Option<usize> {
    let mut idx = 0usize;
    while nbits - idx >= 256 {
        let b = idx / 8;
        let w0 = u64::from_le_bytes(bitmap[b..b + 8].try_into().unwrap());
        let w1 = u64::from_le_bytes(bitmap[b + 8..b + 16].try_into().unwrap());
        let w2 = u64::from_le_bytes(bitmap[b + 16..b + 24].try_into().unwrap());
        let w3 = u64::from_le_bytes(bitmap[b + 24..b + 32].try_into().unwrap());
        if (w0 & w1 & w2 & w3) != u64::MAX {
            for (j, w) in [w0, w1, w2, w3].into_iter().enumerate() {
                if w != u64::MAX {
                    return Some(idx + j * 64 + (!w).trailing_zeros() as usize);
                }
            }
        }
        idx += 256;
    }
    scan_word(&bitmap[idx / 8..], nbits - idx).map(|r| idx + r)
}

fn bench(c: &mut Criterion) {
    // nbits = bits scanned before the free one. Realistic inode-group prefixes.
    for nbits in [8192usize, 65536] {
        let bytes = nbits / 8;
        let bitmap = vec![0xFFu8; bytes]; // fully allocated prefix (worst case)
        let mut g = c.benchmark_group(format!("bitmap_scan_{nbits}bits"));
        g.bench_function("word", |b| {
            b.iter(|| black_box(scan_word(black_box(&bitmap), nbits)));
        });
        g.bench_function("unrolled4", |b| {
            b.iter(|| black_box(scan_unrolled4(black_box(&bitmap), nbits)));
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
