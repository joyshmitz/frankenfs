#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-machine A/B for ext4 group-descriptor reads (bd-yuhvn).
//!
//! `read_group_desc_with_scope` parses one ~64-byte group descriptor out of the
//! group-descriptor table. The old path copied the WHOLE ~4 KiB GD-table block
//! into a fresh `Vec` (`read_block_with_scope`) to read+verify+parse those 64
//! bytes. A 4 KiB block packs ~64 descriptors, so a cold all-groups scan
//! (mount, statfs, allocation) re-touches the SAME block once per group it
//! holds — the parsed-descriptor cache is keyed per group, not per block, so it
//! doesn't dedup the per-group block copy within a cold pass. The new path uses
//! `with_block_bytes` to borrow the cached `Arc`-backed block and parse in place.
//!
//! This benches parsing every descriptor in one GD-table block (64 descriptors
//! at 64 bytes): the old path copies the block per descriptor, the new borrows.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_block::BlockBuf;
use ffs_ondisk::ext4::Ext4GroupDesc;
use std::hint::black_box;

const BLOCK_SIZE: usize = 4096;
const DESC_SIZE: u16 = 64; // 64-bit feature descriptor size
const N: usize = BLOCK_SIZE / DESC_SIZE as usize; // descriptors per GD-table block

fn build_gd_block() -> BlockBuf {
    let mut bytes = vec![0_u8; BLOCK_SIZE];
    for g in 0..N {
        let base = g * DESC_SIZE as usize;
        // bg_inode_table_lo (offset 0x08) distinct per group so divergence shows.
        bytes[base + 0x08..base + 0x0C].copy_from_slice(&((5000 + g) as u32).to_le_bytes());
    }
    BlockBuf::new(bytes)
}

fn bench_group_desc_read(c: &mut Criterion) {
    let block = build_gd_block();

    // Isomorphism: copy-then-parse and borrow-then-parse yield the same desc.
    for g in 0..N {
        let off = g * DESC_SIZE as usize;
        let copied = {
            let v = block.clone_ref().as_slice().to_vec();
            Ext4GroupDesc::parse_from_bytes(&v[off..off + DESC_SIZE as usize], DESC_SIZE).unwrap()
        };
        let borrowed = Ext4GroupDesc::parse_from_bytes(
            &block.clone_ref().as_slice()[off..off + DESC_SIZE as usize],
            DESC_SIZE,
        )
        .unwrap();
        assert_eq!(copied, borrowed, "group {g} diverged");
    }

    let mut group = c.benchmark_group("ext4_group_desc_block_64");
    // Old: copy the whole GD-table block into a Vec per descriptor.
    group.bench_function("copy_block_per_desc", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for g in 0..N {
                let off = g * DESC_SIZE as usize;
                let owned = black_box(&block).clone_ref().as_slice().to_vec();
                let d = Ext4GroupDesc::parse_from_bytes(
                    &owned[off..off + DESC_SIZE as usize],
                    DESC_SIZE,
                )
                .unwrap();
                acc = acc.wrapping_add(d.inode_table);
            }
            black_box(acc)
        });
    });
    // New: borrow the cached block and parse the descriptor in place.
    group.bench_function("borrow_block_per_desc", |b| {
        b.iter(|| {
            let mut acc = 0_u64;
            for g in 0..N {
                let off = g * DESC_SIZE as usize;
                let buf = black_box(&block).clone_ref();
                let d = Ext4GroupDesc::parse_from_bytes(
                    &buf.as_slice()[off..off + DESC_SIZE as usize],
                    DESC_SIZE,
                )
                .unwrap();
                acc = acc.wrapping_add(d.inode_table);
            }
            black_box(acc)
        });
    });
    group.finish();
}

criterion_group!(group_desc_read, bench_group_desc_read);
criterion_main!(group_desc_read);
