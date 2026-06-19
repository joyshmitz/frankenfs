#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for the per-block read-buffer construction lever (bd-kq3b4).
//!
//! The scalar device read path returns a `Vec<u8>` materialised from a
//! [`BlockBuf`]. Two ways to build that block buffer before the final
//! `as_slice().to_vec()`:
//!
//! * `via_unaligned_vec` — `vec![0; N]` (unaligned) then `BlockBuf::new`, which
//!   forces `AlignedVec::from_vec` down its realign path: an extra padded
//!   allocation + memset + memcpy on every block. This is the pre-bd-kq3b4
//!   shape of `ByteDeviceBlockAdapter::read_block`.
//! * `via_aligned_zeroed` — `BlockBuf::zeroed(N)` is block-aligned at
//!   construction, so the realign copy never happens. This is the post-bd-kq3b4
//!   shape (and matches what `read_contiguous_blocks` already did).
//!
//! Both variants do the same device-fill memcpy and the same trailing
//! `to_vec`, so the delta isolates exactly the eliminated realign work. Running
//! both in one binary keeps the comparison on a single CPU, side-stepping the
//! cross-worker timing skew that makes absolute rch numbers untrustworthy.
//! `block_vec_direct_final_buffer` measures the next owned-read lever: fill the
//! final `Vec<u8>` directly when the caller already wants owned bytes.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::BlockBuf;
use std::hint::black_box;

const BLOCK_SIZE: usize = 4096;

fn bench_block_buf_construct(c: &mut Criterion) {
    // Stand-in for the bytes a device read would deposit into the buffer.
    let src = vec![0xA5_u8; BLOCK_SIZE];
    let mut aligned = BlockBuf::zeroed(BLOCK_SIZE);
    aligned.make_mut().copy_from_slice(&src);
    let mut direct = vec![0_u8; BLOCK_SIZE];
    direct.copy_from_slice(&src);
    assert_eq!(aligned.as_slice(), direct.as_slice());

    c.bench_function("block_buf_via_unaligned_vec", |b| {
        b.iter(|| {
            let mut bytes = vec![0_u8; BLOCK_SIZE];
            bytes.copy_from_slice(black_box(&src));
            let buf = BlockBuf::new(bytes);
            black_box(buf.as_slice().to_vec())
        });
    });

    c.bench_function("block_buf_via_aligned_zeroed", |b| {
        b.iter(|| {
            let mut buf = BlockBuf::zeroed(BLOCK_SIZE);
            buf.make_mut().copy_from_slice(black_box(&src));
            black_box(buf.as_slice().to_vec())
        });
    });

    c.bench_function("block_vec_direct_final_buffer", |b| {
        b.iter(|| {
            let mut bytes = vec![0_u8; BLOCK_SIZE];
            bytes.copy_from_slice(black_box(&src));
            black_box(bytes)
        });
    });

    // ── Arc<[u8]> materialisation on the block-cache miss path ───────────────
    // The cache wrappers in ffs-core need an Arc<[u8]>. Building it through a
    // Vec (`Arc::from(buf.as_slice().to_vec())`) copies twice; building it from
    // the slice directly (`Arc::from(buf.as_slice())`) copies once.
    let mut filled = BlockBuf::zeroed(BLOCK_SIZE);
    filled.make_mut().copy_from_slice(&src);

    c.bench_function("block_arc_via_vec_two_copies", |b| {
        b.iter(|| {
            let buf = black_box(&filled);
            black_box(std::sync::Arc::<[u8]>::from(buf.as_slice().to_vec()))
        });
    });

    c.bench_function("block_arc_via_slice_one_copy", |b| {
        b.iter(|| {
            let buf = black_box(&filled);
            black_box(std::sync::Arc::<[u8]>::from(buf.as_slice()))
        });
    });
}

criterion_group!(benches, bench_block_buf_construct);
criterion_main!(benches);
