#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

//! Same-process A/B for the inode serialization buffer: the heap-allocating
//! `serialize_inode` (`vec![0; inode_size]` per call) vs the stack-buffer
//! `serialize_inode_into` used by the hot `write_inode` path
//! (bd-cc-serialize-into). Both produce identical bytes (asserted); this
//! isolates the per-call heap-alloc cost that `write_inode` runs on every
//! create/mkdir/rename/unlink inode write.

use criterion::{criterion_group, criterion_main, Criterion};
use ffs_inode::{serialize_inode, serialize_inode_into};
use ffs_ondisk::ext4::Ext4Inode;
use std::hint::black_box;

fn make_inode() -> Ext4Inode {
    // A zeroed 256-byte inode parses to a valid (empty) inode — enough to
    // exercise the full serialize field-write path.
    let mut raw = vec![0u8; 256];
    // Give it a plausible mode (S_IFREG | 0644) so no field is trivially skipped.
    raw[0..2].copy_from_slice(&0x81A4u16.to_le_bytes());
    Ext4Inode::parse_from_bytes(&raw).expect("parse zeroed inode")
}

fn bench_serialize(c: &mut Criterion) {
    let inode = make_inode();
    let inode_size = 256usize;

    // Correctness: both paths agree.
    let mut stack = [0u8; 256];
    serialize_inode_into(&inode, inode_size, &mut stack);
    assert_eq!(&stack[..], &serialize_inode(&inode, inode_size)[..]);

    let mut group = c.benchmark_group("serialize_inode_256");
    group.bench_function("heap_vec", |b| {
        b.iter(|| black_box(serialize_inode(black_box(&inode), inode_size)));
    });
    group.bench_function("stack_buf", |b| {
        let mut buf = [0u8; 256];
        b.iter(|| {
            serialize_inode_into(black_box(&inode), inode_size, &mut buf);
            black_box(&buf);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_serialize);
criterion_main!(benches);
