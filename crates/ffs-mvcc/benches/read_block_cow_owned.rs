#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! A/B for the `Cow` handling in `MvccBlockDevice::read_block` (ffs-mvcc:4108).
//!
//! `read_visible` returns `Cow::Owned` for any compressed version —
//! `resolve_data_with` decompresses into a fresh `Vec`. The old code finished the
//! read with `Cow::to_vec()`, a SECOND full-block allocation + copy of that
//! already-owned buffer. The lever uses `Cow::into_owned()`, which MOVES the owned
//! `Vec` (O(1)); for an uncompressed `Cow::Borrowed` it clones exactly as before,
//! so the result is byte-identical.
//!
//! This isolates the eliminated copy across realistic block sizes — the saved
//! work scales with the block, so the win grows with compressed-extent size. The
//! `into_owned` arm should be flat (a move) while `to_vec` tracks the byte count.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::borrow::Cow;
use std::hint::black_box;

fn make_block(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i & 0xff) as u8).collect()
}

fn bench_read_block_cow(c: &mut Criterion) {
    let mut group = c.benchmark_group("mvcc_read_block_cow_owned");
    for size in [4096_usize, 16_384, 65_536] {
        let src = make_block(size);
        group.throughput(Throughput::Bytes(size as u64));

        // Old: the already-owned decompressed buffer is cloned again.
        group.bench_with_input(BenchmarkId::new("to_vec_clone", size), &src, |b, src| {
            b.iter_batched(
                || Cow::Owned(src.clone()),
                |cow: Cow<'_, [u8]>| black_box(cow.to_vec()),
                criterion::BatchSize::SmallInput,
            );
        });

        // Lever: the owned buffer is moved out — no second allocation or copy.
        group.bench_with_input(BenchmarkId::new("into_owned_move", size), &src, |b, src| {
            b.iter_batched(
                || Cow::Owned(src.clone()),
                |cow: Cow<'_, [u8]>| black_box(cow.into_owned()),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(read_block_cow_owned, bench_read_block_cow);
criterion_main!(read_block_cow_owned);
