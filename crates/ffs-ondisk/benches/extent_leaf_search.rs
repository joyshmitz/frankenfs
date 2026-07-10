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
    // COMMON case first (e=1,2,4 with a FIRST-extent hit = linear's best case, and
    // the overwhelmingly common shape for real files), then the worst case the
    // original bench covered. `extent_leaf_lookup` runs per resolved block on EVERY
    // read, so the common case is the hot case; the "negligible for 1-4 extents"
    // claim in ext4.rs::extent_leaf_lookup is verified here, not assumed.
    // Cases: (extent_count, target, label).
    let cases: &[(u32, u32, &str)] = &[
        (1, 1, "e1_hit0"),        // single contiguous extent — the 90%+ case
        (2, 1, "e2_hit0"),        // first-extent hit, linear returns immediately
        (4, 1, "e4_hit0"),        // first-extent hit
        (4, 15, "e4_hitlast"),    // last-extent hit (linear worst case, small E)
        (64, 255, "e64_hitlast"), // fragmented, last hit — binary's win case
        (256, 1023, "e256_hitlast"),
    ];
    for &(e, target, label) in cases {
        let exts = make(e);
        assert_eq!(linear(&exts, target), binary(&exts, target), "arms must agree for {label}");
        let mut g = c.benchmark_group(format!("extent_search_{label}"));
        // NULL CONTROL: identical arm registered twice — its ratio is the noise
        // floor; any linear-vs-binary gap smaller than binary-vs-binary is noise.
        g.bench_function("binary_a", |b| b.iter(|| black_box(binary(black_box(&exts), black_box(target)))));
        g.bench_function("binary_b", |b| b.iter(|| black_box(binary(black_box(&exts), black_box(target)))));
        g.bench_function("linear", |b| b.iter(|| black_box(linear(black_box(&exts), black_box(target)))));
        g.finish();
    }
}
criterion_group!(benches, bench);
criterion_main!(benches);
