#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for ext4 indirect block-pointer resolution (bd-wxmi1).
//!
//! `resolve_indirect_block` reads one u32 pointer (4 bytes) from an indirect
//! block per logical block. Sequential reads of an ext2/3 file resolve every
//! block under the same indirect block, which the RO block cache serves as a
//! cheap `Arc`-backed `BlockBuf`. The old path then copied the WHOLE ~4 KiB
//! block into a fresh `Vec` (`read_block_with_scope`) just to read those 4
//! bytes; the new `with_block_bytes` borrows the cached block directly.
//!
//! This benches resolving every pointer in a single-indirect block (1024
//! entries at a 4 KiB block size): the old path copies the block per pointer,
//! the new path borrows it.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::BlockBuf;
use std::hint::black_box;

const BLOCK_SIZE: usize = 4096;
const N: usize = BLOCK_SIZE / 4; // u32 pointers per 4 KiB indirect block

fn build_indirect_block() -> BlockBuf {
    let mut bytes = vec![0_u8; BLOCK_SIZE];
    for i in 0..N {
        // Pointer i -> physical block 1000 + i.
        bytes[i * 4..i * 4 + 4].copy_from_slice(&((1000 + i) as u32).to_le_bytes());
    }
    BlockBuf::new(bytes)
}

#[inline]
fn read_u32_le(data: &[u8], off: usize) -> u64 {
    u64::from(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
}

fn bench_indirect_ptr_resolve(c: &mut Criterion) {
    let cached = build_indirect_block();

    // Isomorphism: both paths read the same pointer for every index.
    for idx in 0..N {
        let copied = {
            let v = cached.clone_ref().as_slice().to_vec();
            read_u32_le(&v, idx * 4)
        };
        let borrowed = read_u32_le(cached.clone_ref().as_slice(), idx * 4);
        assert_eq!(copied, borrowed, "index {idx} diverged");
    }

    let mut group = c.benchmark_group("ext4_indirect_ptr_resolve_1024");
    // Old: copy the whole cached block into a Vec per pointer read.
    group.bench_function("copy_block_per_ptr", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for idx in 0..N {
                let buf = black_box(&cached).clone_ref();
                let owned = buf.as_slice().to_vec();
                acc = acc.wrapping_add(read_u32_le(&owned, idx * 4));
            }
            black_box(acc)
        });
    });
    // New: borrow the cached block and read the pointer in place.
    group.bench_function("borrow_block_per_ptr", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for idx in 0..N {
                let buf = black_box(&cached).clone_ref();
                acc = acc.wrapping_add(read_u32_le(buf.as_slice(), idx * 4));
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(indirect_ptr_resolve, bench_indirect_ptr_resolve);
criterion_main!(indirect_ptr_resolve);
