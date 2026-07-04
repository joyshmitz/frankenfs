#![forbid(unsafe_code)]
//! A/B for the ext4 extent leaf search (walk_extent_tree leaf scan): linear
//! `for ext in extents` early-exit vs binary search over the SORTED extents.
//! Re-run per resolved block (the child-cache stores the child block, not the
//! resolved extent), so for a fragmented file (many extents/leaf) it is O(E)
//! per block. Target = a late extent (worst case for linear).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench extent_leaf_search
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
// (logical_block start, len) sorted by start; each extent covers [start, start+len).
fn make(e: u32) -> Vec<(u32, u32)> { (0..e).map(|i| (i * 4, 4)).collect() }
fn linear(exts: &[(u32, u32)], target: u32) -> Option<usize> {
    for (i, &(start, len)) in exts.iter().enumerate() {
        if target >= start && target < start + len { return Some(i); }
    }
    None
}
fn binary(exts: &[(u32, u32)], target: u32) -> Option<usize> {
    // last extent with start <= target
    let p = exts.partition_point(|&(start, _)| start <= target);
    if p == 0 { return None; }
    let (start, len) = exts[p - 1];
    if target >= start && target < start + len { Some(p - 1) } else { None }
}
fn bench(c: &mut Criterion) {
    for e in [4u32, 64, 256] {
        let exts = make(e);
        let target = (e - 1) * 4 + 1; // in the LAST extent (linear worst case)
        assert_eq!(linear(&exts, target), binary(&exts, target));
        let mut g = c.benchmark_group(format!("extent_search_e{e}"));
        g.bench_function("linear", |b| b.iter(|| black_box(linear(black_box(&exts), black_box(target)))));
        g.bench_function("binary", |b| b.iter(|| black_box(binary(black_box(&exts), black_box(target)))));
        g.finish();
    }
}
criterion_group!(benches, bench);
criterion_main!(benches);
