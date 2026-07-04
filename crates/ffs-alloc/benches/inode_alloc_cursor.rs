#![forbid(unsafe_code)]

//! Criterion A/B for the inode bitmap allocation cursor.
//!
//! The ext4 create path allocates many regular-file inodes from the parent
//! group. The old allocator restarted every bitmap search at bit 0, so each
//! create re-scanned the already allocated prefix while holding the allocator
//! lock. The cursor keeps the bitmap as authority but starts the wrapped search
//! after the last successful allocation.

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_alloc::{bitmap_find_free, bitmap_get, bitmap_set};
use std::hint::black_box;

const INODES: u32 = 131_072;
const RESERVED_INODES: u32 = 11;
const ALLOCATIONS: u32 = 16_384;

fn seed_inode_bitmap() -> Vec<u8> {
    let mut bitmap = vec![0_u8; usize::try_from(INODES.div_ceil(8)).unwrap()];
    for idx in 0..RESERVED_INODES {
        bitmap_set(&mut bitmap, idx);
    }
    bitmap
}

fn restart_at_zero_allocs() -> (u64, Vec<u8>) {
    let mut bitmap = seed_inode_bitmap();
    let mut checksum = 0_u64;
    for _ in 0..ALLOCATIONS {
        let idx = bitmap_find_free(&bitmap, INODES, 0).expect("benchmark bitmap has free inodes");
        assert!(!bitmap_get(&bitmap, idx));
        bitmap_set(&mut bitmap, idx);
        checksum = checksum
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::from(idx));
    }
    (checksum, bitmap)
}

fn cursor_allocs() -> (u64, Vec<u8>) {
    let mut bitmap = seed_inode_bitmap();
    let mut cursor = 0_u32;
    let mut checksum = 0_u64;
    for _ in 0..ALLOCATIONS {
        let idx =
            bitmap_find_free(&bitmap, INODES, cursor).expect("benchmark bitmap has free inodes");
        assert!(!bitmap_get(&bitmap, idx));
        bitmap_set(&mut bitmap, idx);
        cursor = idx
            .checked_add(1)
            .filter(|next| *next < INODES)
            .unwrap_or(0);
        checksum = checksum
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::from(idx));
    }
    (checksum, bitmap)
}

fn bench_inode_alloc_cursor(c: &mut Criterion) {
    let old = restart_at_zero_allocs();
    let new = cursor_allocs();
    assert_eq!(
        old, new,
        "cursor changed sequential inode allocation results"
    );

    let mut group = c.benchmark_group("inode_alloc_cursor");
    group.bench_function("restart_at_zero", |b| {
        b.iter(|| black_box(restart_at_zero_allocs()));
    });
    group.bench_function("monotone_cursor", |b| {
        b.iter(|| black_box(cursor_allocs()));
    });
    group.finish();
}

criterion_group!(benches, bench_inode_alloc_cursor);
criterion_main!(benches);
