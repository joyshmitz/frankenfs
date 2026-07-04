#![forbid(unsafe_code)]

//! Quantify the per-op copy eliminated by holding the cached
//! `Arc<[Ext4Extent]>` write-extent snapshot instead of `.to_vec()`-ing it on
//! every directory write op (create/unlink/rename). Measures `Arc::clone` (the
//! kept path) vs `.to_vec()` (the eliminated deep copy) at representative extent
//! counts, so the end-to-end op saving can be judged against a ~µs create.
//!
//!   CARGO_TARGET_DIR=/data/projects/frankenfs/.rch-targets/blackthrush-dig10 \
//!   rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench extent_snapshot_copy

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_ondisk::ext4::Ext4Extent;
use std::hint::black_box;
use std::sync::Arc;

fn make_snapshot(n: u32) -> Arc<[Ext4Extent]> {
    (0..n)
        .map(|i| Ext4Extent {
            logical_block: i * 8,
            raw_len: 8,
            physical_start: u64::from(i) * 8 + 1000,
        })
        .collect::<Vec<_>>()
        .into()
}

fn bench(c: &mut Criterion) {
    for n in [4u32, 16, 64] {
        let snap = make_snapshot(n);
        let mut g = c.benchmark_group(format!("ext4_write_extent_snapshot_{n}"));
        g.bench_function("arc_clone_kept", |b| {
            b.iter(|| black_box(Arc::clone(black_box(&snap))));
        });
        g.bench_function("to_vec_eliminated", |b| {
            b.iter(|| black_box(black_box(&snap).to_vec()));
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
