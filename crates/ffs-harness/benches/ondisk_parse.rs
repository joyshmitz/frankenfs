#![forbid(unsafe_code)]

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_harness::load_sparse_fixture;
use ffs_ondisk::{
    Ext4GroupDesc, Ext4Inode, parse_dev_item, parse_dir_block, parse_dx_root, parse_extent_tree,
    parse_sys_chunk_array, parse_xattr_block,
};
use std::hint::black_box;
use std::path::Path;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance/fixtures")
        .join(name)
}

fn bench_ext4_inode_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");

    c.bench_function("ext4_inode_parse", |b| {
        b.iter(|| Ext4Inode::parse_from_bytes(black_box(&data)).expect("inode parse"));
    });
}

fn bench_ext4_group_desc_32(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_32byte.json"))
        .expect("load gd32 fixture");

    c.bench_function("ext4_group_desc_32byte", |b| {
        b.iter(|| Ext4GroupDesc::parse_from_bytes(black_box(&data), 32).expect("gd32 parse"));
    });
}

fn bench_ext4_group_desc_64(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_64byte.json"))
        .expect("load gd64 fixture");

    c.bench_function("ext4_group_desc_64byte", |b| {
        b.iter(|| Ext4GroupDesc::parse_from_bytes(black_box(&data), 64).expect("gd64 parse"));
    });
}

// bd-fjeb0 — encode-side benches for Ext4GroupDesc::write_to_bytes.
// Pair the existing parse benches above so the perf gate tracks both
// sides of the encode/decode bijection (the bd-ov7zr proptest suite +
// bd-38xrn fuzz target pin correctness; these benches pin latency).

fn bench_ext4_group_desc_write_32(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_32byte.json"))
        .expect("load gd32 fixture");
    let gd = Ext4GroupDesc::parse_from_bytes(&data, 32).expect("gd32 parse for write bench");
    let mut buf = [0_u8; 32];

    c.bench_function("ext4_group_desc_32byte_write", |b| {
        b.iter(|| {
            gd.write_to_bytes(black_box(&mut buf), 32)
                .expect("gd32 write");
        });
    });
}

fn bench_ext4_group_desc_write_64(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_64byte.json"))
        .expect("load gd64 fixture");
    let gd = Ext4GroupDesc::parse_from_bytes(&data, 64).expect("gd64 parse for write bench");
    let mut buf = [0_u8; 64];

    c.bench_function("ext4_group_desc_64byte_write", |b| {
        b.iter(|| {
            gd.write_to_bytes(black_box(&mut buf), 64)
                .expect("gd64 write");
        });
    });
}

fn bench_ext4_dir_block_parse(c: &mut Criterion) {
    let data =
        load_sparse_fixture(&fixture_path("ext4_dir_block.json")).expect("load dir block fixture");

    c.bench_function("ext4_dir_block_parse", |b| {
        b.iter(|| {
            let entries = parse_dir_block(black_box(&data), 4096).expect("dir block parse");
            black_box(entries);
        });
    });
}

fn bench_ext4_extent_tree_parse(c: &mut Criterion) {
    // The inode fixture contains a 60-byte extent tree in the i_block region.
    let inode_data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");
    let inode = Ext4Inode::parse_from_bytes(&inode_data).expect("inode parse");

    c.bench_function("ext4_extent_tree_parse", |b| {
        b.iter(|| {
            let _ = black_box(parse_extent_tree(black_box(&inode.extent_bytes)));
        });
    });
}

fn bench_btrfs_sys_chunk_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("btrfs_superblock_with_chunks.json"))
        .expect("load btrfs chunks fixture");
    let sb = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(&data)
        .expect("parse btrfs superblock");

    c.bench_function("btrfs_sys_chunk_parse", |b| {
        b.iter(|| {
            let entries =
                parse_sys_chunk_array(black_box(&sb.sys_chunk_array)).expect("chunk parse");
            black_box(entries);
        });
    });
}

// bd-6eyj5 — bench coverage for four hot ext4/btrfs metadata parsers
// that previously had no perf gate. Each is on the mounted-image
// metadata read path; a regression here would silently slow throughput
// without tripping the existing perf gate.

fn bench_ext4_xattr_block_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_xattr_block.json"))
        .expect("load ext4_xattr_block fixture");

    c.bench_function("ext4_xattr_block_parse", |b| {
        b.iter(|| {
            let xattrs = parse_xattr_block(black_box(&data)).expect("xattr block parse");
            black_box(xattrs);
        });
    });
}

fn bench_ext4_dx_root_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_htree_dx_root.json"))
        .expect("load ext4_htree_dx_root fixture");

    c.bench_function("ext4_dx_root_parse", |b| {
        b.iter(|| {
            let root = parse_dx_root(black_box(&data)).expect("dx root parse");
            black_box(root);
        });
    });
}

fn bench_btrfs_dev_item_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("btrfs_devitem.json"))
        .expect("load btrfs_devitem fixture");

    c.bench_function("btrfs_dev_item_parse", |b| {
        b.iter(|| {
            let item = parse_dev_item(black_box(&data)).expect("dev item parse");
            black_box(item);
        });
    });
}

fn bench_ext4_extent_tree_index_parse(c: &mut Criterion) {
    // The leaf path is exercised by `bench_ext4_extent_tree_parse` via the
    // inode fixture's i_block region; this bench covers the internal-node
    // (index) decoding path, which uses Ext4ExtentIndex layout instead of
    // Ext4Extent layout.
    let data = load_sparse_fixture(&fixture_path("ext4_extent_tree_index.json"))
        .expect("load ext4_extent_tree_index fixture");

    c.bench_function("ext4_extent_tree_index_parse", |b| {
        b.iter(|| {
            let _ = black_box(parse_extent_tree(black_box(&data)));
        });
    });
}

criterion_group!(
    ondisk,
    bench_ext4_inode_parse,
    bench_ext4_group_desc_32,
    bench_ext4_group_desc_64,
    bench_ext4_group_desc_write_32,
    bench_ext4_group_desc_write_64,
    bench_ext4_dir_block_parse,
    bench_ext4_extent_tree_parse,
    bench_ext4_extent_tree_index_parse,
    bench_ext4_xattr_block_parse,
    bench_ext4_dx_root_parse,
    bench_btrfs_sys_chunk_parse,
    bench_btrfs_dev_item_parse,
);
criterion_main!(ondisk);
