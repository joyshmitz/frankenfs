#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Headroom A/B for the Arc-backed uncompressed-read lever (bd-xmh5g.394).
//!
//! `read_block` on an UNCOMPRESSED version is the common read path:
//! `read_visible` returns `Cow::Borrowed(&store_data)` under the read lock, and
//! `into_owned()` (bd-xmh5g.387) must CLONE the whole block into the `BlockBuf`'s
//! `Vec` — the `.387` move only helped the compressed `Cow::Owned` case. The
//! proposed lever stores `VersionData::Full` as `Arc<[u8]>` and SHARES it
//! (`Arc::clone` = a refcount bump, no copy) via an Arc-backed `BlockBuf`.
//!
//! This isolates the per-read delta: the `clone` arm allocates + copies the
//! whole block (scales with size); the `share` arm is a flat O(1) refcount bump.
//! That delta times uncompressed-read frequency is the lever's headroom — the
//! input to the keep/reject decision once the ffs-block Arc-backed BlockBuf path
//! and a real measurement are available. Both arms expose identical bytes.

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use std::borrow::Cow;
use std::hint::black_box;
use std::sync::Arc;

fn make_block(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i & 0xff) as u8).collect()
}

fn bench_clone_vs_share(c: &mut Criterion) {
    // Behavior guard: the shared Arc exposes the same bytes the clone produces.
    let probe = make_block(4096);
    let shared: Arc<[u8]> = Arc::from(probe.clone().into_boxed_slice());
    assert_eq!(
        Cow::Borrowed(probe.as_slice()).into_owned().as_slice(),
        &shared[..],
        "shared Arc bytes diverged from the cloned block"
    );

    let mut group = c.benchmark_group("read_block_uncompressed");
    for size in [4096_usize, 16_384, 65_536] {
        let owned = make_block(size);
        let shared: Arc<[u8]> = Arc::from(owned.clone().into_boxed_slice());
        group.throughput(Throughput::Bytes(size as u64));

        // Current: read_visible's borrowed slice is cloned into an owned Vec.
        group.bench_with_input(BenchmarkId::new("clone_into_owned", size), &owned, |b, owned| {
            b.iter(|| black_box(Cow::Borrowed(black_box(owned.as_slice())).into_owned()));
        });

        // Lever: share the stored block via a refcount bump — no allocation/copy.
        group.bench_with_input(BenchmarkId::new("arc_share", size), &shared, |b, shared| {
            b.iter_batched(
                || Arc::clone(shared),
                |buf| black_box(buf),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(read_block_uncompressed, bench_clone_vs_share);
criterion_main!(read_block_uncompressed);
