#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Faithful quantification of the `BlockBuf::into_inner` move vs the old
//! `as_slice().to_vec()` copy — the dominant clean-lever family shipped in
//! bd-xmh5g.389 (3 ffs-inode RMW paths), bd-xmh5g.390 (btrfs partial-block
//! write), and bd-xmh5g.393 (8 ffs-core read/RMW paths).
//!
//! Those sites read a block (`read_block` returns an OWNED, sole-referenced
//! `BlockBuf` wrapping an `Arc`) and previously did `as_slice().to_vec()`,
//! allocating + copying the whole block. `into_inner()` does `Arc::try_unwrap`,
//! moving the inner `Vec` out in O(1) when it is the only reference (always true
//! after a single `read_block`). This isolates that eliminated copy across
//! realistic block sizes: the `into_inner` arm is flat (a move) while the copy
//! arm tracks the byte count. Both arms yield byte-identical results (asserted).

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use ffs_block::BlockBuf;
use std::hint::black_box;

fn make_block(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i & 0xff) as u8).collect()
}

fn bench_into_inner(c: &mut Criterion) {
    // Behavior-preserving guard: the move and the copy yield identical bytes.
    let probe = make_block(4096);
    assert_eq!(
        BlockBuf::new(probe.clone()).into_inner(),
        BlockBuf::new(probe.clone()).as_slice().to_vec(),
        "into_inner diverged from as_slice().to_vec()"
    );

    let mut group = c.benchmark_group("blockbuf_into_inner_vs_to_vec");
    for size in [4096_usize, 16_384, 65_536] {
        let src = make_block(size);
        group.throughput(Throughput::Bytes(size as u64));

        // Lever: move the owned Vec out (Arc::try_unwrap, O(1)).
        group.bench_with_input(BenchmarkId::new("into_inner_move", size), &src, |b, src| {
            b.iter_batched(
                || BlockBuf::new(src.clone()),
                |buf| black_box(buf.into_inner()),
                BatchSize::SmallInput,
            );
        });

        // Old: allocate + copy the whole block.
        group.bench_with_input(
            BenchmarkId::new("as_slice_to_vec_copy", size),
            &src,
            |b, src| {
                b.iter_batched(
                    || BlockBuf::new(src.clone()),
                    |buf| black_box(buf.as_slice().to_vec()),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(blockbuf_into_inner, bench_into_inner);
criterion_main!(blockbuf_into_inner);
