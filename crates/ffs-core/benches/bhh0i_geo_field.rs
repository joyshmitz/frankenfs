#![forbid(unsafe_code)]

//! Same-machine A/B for reading a verbatim superblock field vs building the whole
//! `FsGeometry` (bd-bhh0i sharded create/write path).
//!
//! `ext4_sharded_create_inode` / `ext4_sharded_write_inode` built
//! `FsGeometry::from_superblock(sb)` — a u64 group-count division plus a ~20-field
//! struct build and a cluster-ratio feature check — only to read `.inode_size`, a
//! field `from_superblock` copies UNCHANGED from `sb.inode_size`. This benches that
//! full geometry build versus the direct `sb.inode_size` read (the landed change).
//! Byte-identical: both yield the same `inode_size` (asserted below).

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_alloc::FsGeometry;
use ffs_ondisk::ext4::Ext4Superblock;
use std::hint::black_box;

fn sample_superblock() -> Ext4Superblock {
    // Minimal superblock region covering every field `from_superblock` reads.
    let mut region = vec![0_u8; 1024];
    region[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // inodes_count
    region[0x04..0x08].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_count_lo
    region[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // log_block_size -> 4096
    region[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes()); // blocks_per_group
    region[0x28..0x2C].copy_from_slice(&2048_u32.to_le_bytes()); // inodes_per_group
    region[0x38..0x3A].copy_from_slice(&0xEF53_u16.to_le_bytes()); // magic
    region[0x4C..0x50].copy_from_slice(&1_u32.to_le_bytes()); // rev_level = dynamic
    region[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes()); // first_ino
    region[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes()); // inode_size
    region[0x60..0x64].copy_from_slice(&(0x2_u32 | 0x40_u32).to_le_bytes()); // FILETYPE|EXTENTS
    Ext4Superblock::parse_superblock_region(&region).expect("parse sample superblock")
}

fn bench_geo_field(c: &mut Criterion) {
    let sb = sample_superblock();
    // Isomorphism: the whole-geometry build and the direct field agree.
    assert_eq!(
        usize::from(FsGeometry::from_superblock(&sb).inode_size),
        usize::from(sb.inode_size),
    );

    let mut group = c.benchmark_group("bhh0i_inode_size_from_sb");
    // Old: build the entire FsGeometry, then read one u16 out of it.
    group.bench_function("build_geometry", |b| {
        b.iter(|| usize::from(FsGeometry::from_superblock(black_box(&sb)).inode_size));
    });
    // New: read the verbatim superblock field directly.
    group.bench_function("direct_field", |b| {
        b.iter(|| usize::from(black_box(&sb).inode_size));
    });
    group.finish();
}

criterion_group!(bhh0i_geo_field, bench_geo_field);
criterion_main!(bhh0i_geo_field);
