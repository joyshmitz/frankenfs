#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for keeping the ext4_write extent cache across mark_written
//! (bd-e4uwb).
//!
//! Writing N consecutive blocks into one preallocated (unwritten) extent splits
//! that extent per block (mark_written), so the materialised extent list E grows
//! ~linearly as the write progresses. bd-yqq5l's cache was invalidated after each
//! mark_written, re-collecting the (growing) tree per block — O(N^2). bd-e4uwb
//! keeps the cache (a split preserves every block's physical mapping and the
//! unprocessed suffix's unwritten flag), so the loop collects once and resolves
//! N times — O(N).
//!
//! This models the per-block collect: OLD re-materialises an E=i+1 extent list at
//! block i (sum ~ N^2/2 extents); NEW materialises the original single extent once
//! then resolves each block from it. resolve() mirrors the production binary
//! covering-extent lookup (bd-uthzg).

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const K: u32 = 256; // blocks written into the preallocated unwritten extent

/// Materialise an E-extent list (length-1 extents 0..e) — models the per-block
/// collect_extents_with_scope output as the extent splits accumulate.
fn collect(e: u32) -> Vec<(u32, u32, u64)> {
    (0..e).map(|i| (i, 1, 100_000_u64 + u64::from(i))).collect()
}

/// Production binary covering-extent resolve (bd-uthzg).
fn resolve(extents: &[(u32, u32, u64)], logical: u32) -> Option<u64> {
    let pos = extents.partition_point(|&(start, _, _)| start <= logical);
    pos.checked_sub(1).and_then(|i| {
        let (start, len, phys) = extents[i];
        (logical < start + len).then_some(phys + u64::from(logical - start))
    })
}

fn bench_unwritten_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("ext4_write_unwritten_256blk");

    // OLD: re-collect per block; tree has ~i+1 extents at block i (splits).
    group.bench_function("recollect_per_block", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for i in 0..K {
                let extents = collect(i + 1);
                acc ^= resolve(&extents, i).unwrap_or(0);
            }
            black_box(acc)
        });
    });
    // NEW: collect the original single unwritten extent once, resolve each block.
    group.bench_function("cached_single_extent", |b| {
        b.iter(|| {
            // One extent covering [0, K): the pre-split unwritten extent the cache
            // holds; resolve is correct for every block despite the live splits.
            let extents = vec![(0_u32, K, 100_000_u64)];
            let mut acc = 0_u64;
            for i in 0..K {
                acc ^= resolve(&extents, i).unwrap_or(0);
            }
            black_box(acc)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_unwritten_write);
criterion_main!(benches);
