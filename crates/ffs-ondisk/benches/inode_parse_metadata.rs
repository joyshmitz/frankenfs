#![forbid(unsafe_code)]
//! A FULL inode parse (`parse_from_bytes`) copies the inode's ibody xattr region
//! (`bytes[128+extra_isize..].to_vec()`) into a heap `Vec` — an alloc + copy —
//! even for inodes with NO inline xattrs (the common case). A metadata-only
//! parse (`parse_metadata_from_bytes`) skips it. Callers that need only the
//! fixed fields (times/size/mode/number) — e.g. `note_dir_name_index_insert`'s
//! per-create validation-stamp read — can use the metadata parse. A/B on a
//! 256-byte inode with `extra_isize = 32` (96-byte ibody region).
//!   CARGO_TARGET_DIR=/data/projects/.rch-targets/fs-cc rch exec -- cargo bench --profile release-perf -p ffs-ondisk --bench inode_parse_metadata
use criterion::{criterion_group, criterion_main, Criterion};
use ffs_ondisk::ext4::Ext4Inode;
use std::hint::black_box;

fn make_inode() -> [u8; 256] {
    let mut b = [0u8; 256];
    b[0..2].copy_from_slice(&0x81A4u16.to_le_bytes()); // i_mode = regular 0644
    b[4..8].copy_from_slice(&4096u32.to_le_bytes()); // i_size_lo
    b[26..28].copy_from_slice(&1u16.to_le_bytes()); // i_links_count
    b[0x28] = 0x0A; // i_block[0]: extent magic lo (0xF30A) so extent_bytes look plausible
    b[0x29] = 0xF3;
    b[128..130].copy_from_slice(&32u16.to_le_bytes()); // i_extra_isize = 32
    // Fill the ibody region [160..256] with non-zero bytes (no xattr magic).
    for (i, x) in b[160..256].iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    b
}

fn bench(c: &mut Criterion) {
    let buf = make_inode();
    let full = Ext4Inode::parse_from_bytes(&buf).expect("full parse");
    let meta = Ext4Inode::parse_metadata_from_bytes(&buf).expect("metadata parse");
    // The metadata parse skips the ibody copy; both agree on the fixed fields.
    assert_eq!(full.size, meta.size);
    assert_eq!(full.mode, meta.mode);
    assert!(meta.xattr_ibody.is_empty());
    assert!(!full.xattr_ibody.is_empty());

    let mut g = c.benchmark_group("inode_parse");
    g.bench_function("full", |b| {
        b.iter(|| black_box(Ext4Inode::parse_from_bytes(black_box(&buf)).unwrap()))
    });
    g.bench_function("metadata", |b| {
        b.iter(|| black_box(Ext4Inode::parse_metadata_from_bytes(black_box(&buf)).unwrap()))
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
