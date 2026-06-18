#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Bench target for the metadata-only ext4 inode-parse lever (bd-xmh5g.396).
//!
//! `Ext4Inode::parse_from_bytes` unconditionally allocates
//! `xattr_ibody = bytes[128 + extra_isize ..].to_vec()` (~150 B inline-xattr
//! region) on EVERY inode parse when `extra_isize > 0` — true for nearly all
//! modern ext4. The metadata hot path (getattr/lookup/readdir/access →
//! `to_file_attr`) never reads `xattr_ibody`; only listxattr/getxattr and ext4
//! inline-data reads do. So for an `ls`/`find` over a large directory it is one
//! wasted heap allocation per inode.
//!
//! This models the per-inode saving of a metadata-only parse that leaves
//! `xattr_ibody` empty, across an N-file directory scan: `eager_to_vec`
//! (current — allocate+copy the tail per inode) vs `lazy_empty` (the lever —
//! no allocation). The lever arm is flat; the eager arm pays N allocations.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const FILES: usize = 10_000; // an `ls` over a 10k-entry directory
const INODE_SIZE: usize = 256; // a 256-byte ext4 inode
const EXTRA_ISIZE: usize = 32; // typical extra_isize; xattr tail = 256-160 = 96 B

fn inode_bytes() -> Vec<u8> {
    (0..INODE_SIZE).map(|i| (i & 0xff) as u8).collect()
}

fn bench_xattr_ibody(c: &mut Criterion) {
    let inode = inode_bytes();
    let xattr_start = 128 + EXTRA_ISIZE;

    let mut group = c.benchmark_group("ext4_metadata_parse_xattr_ibody");
    group.throughput(Throughput::Elements(FILES as u64));

    // Current: every inode parse allocates + copies the inline-xattr tail, even
    // for metadata-only ops that never read it.
    group.bench_function("eager_to_vec", |b| {
        b.iter(|| {
            let mut acc = 0_usize;
            for _ in 0..FILES {
                let xattr_ibody = black_box(&inode)[xattr_start..].to_vec();
                acc = acc.wrapping_add(xattr_ibody.len());
            }
            black_box(acc)
        });
    });

    // Lever: the metadata-only parse leaves xattr_ibody empty (no allocation).
    group.bench_function("lazy_empty", |b| {
        b.iter(|| {
            let mut acc = 0_usize;
            for _ in 0..FILES {
                let xattr_ibody: Vec<u8> = black_box(Vec::new());
                acc = acc.wrapping_add(xattr_ibody.len());
            }
            black_box(acc)
        });
    });

    group.finish();
}

criterion_group!(ext4_metadata_parse_xattr_ibody, bench_xattr_ibody);
criterion_main!(ext4_metadata_parse_xattr_ibody);
