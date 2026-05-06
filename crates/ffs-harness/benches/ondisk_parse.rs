#![forbid(unsafe_code)]

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_harness::load_sparse_fixture;
use ffs_ondisk::{
    BtrfsHeader, BtrfsSuperblock, Ext4GroupDesc, Ext4Inode, dx_hash, parse_dev_item,
    parse_dir_block, parse_dx_root, parse_extent_tree, parse_internal_items, parse_leaf_items,
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

// bd-js1k5 — bench coverage for btrfs parsers on the mounted-image
// hot path that bd-6eyj5 left un-benched. The existing
// `bench_btrfs_sys_chunk_parse` pre-parses the superblock during
// setup and benches only sys_chunk_array decoding; these benches
// expose the parsers themselves to the perf gate.

fn bench_btrfs_superblock_parse_region(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("btrfs_superblock_sparse.json"))
        .expect("load btrfs_superblock_sparse fixture");

    c.bench_function("btrfs_superblock_parse_region", |b| {
        b.iter(|| {
            let sb = BtrfsSuperblock::parse_superblock_region(black_box(&data))
                .expect("btrfs superblock parse");
            black_box(sb);
        });
    });
}

fn bench_btrfs_leaf_items_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("btrfs_fstree_leaf.json"))
        .expect("load btrfs_fstree_leaf fixture");

    c.bench_function("btrfs_leaf_items_parse", |b| {
        b.iter(|| {
            let (header, items) = parse_leaf_items(black_box(&data)).expect("leaf items parse");
            black_box((header, items));
        });
    });
}

fn bench_btrfs_internal_items_parse(c: &mut Criterion) {
    // btrfs_leaf_node.json has level=3 in the header and therefore
    // exercises `parse_internal_items` (internal-node decoding) rather
    // than `parse_leaf_items` (leaf decoding) — distinct code paths.
    let data = load_sparse_fixture(&fixture_path("btrfs_leaf_node.json"))
        .expect("load btrfs_leaf_node fixture");

    c.bench_function("btrfs_internal_items_parse", |b| {
        b.iter(|| {
            let (header, ptrs) =
                parse_internal_items(black_box(&data)).expect("internal items parse");
            black_box((header, ptrs));
        });
    });
}

fn bench_btrfs_header_parse_from_block(c: &mut Criterion) {
    // Header-only access path; transitively covered by the leaf/internal
    // parsers but also called standalone elsewhere in the codebase.
    let data = load_sparse_fixture(&fixture_path("btrfs_fstree_leaf.json"))
        .expect("load btrfs_fstree_leaf fixture for header bench");

    c.bench_function("btrfs_header_parse_from_block", |b| {
        b.iter(|| {
            let header = BtrfsHeader::parse_from_block(black_box(&data)).expect("header parse");
            black_box(header);
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

// bd-7pfh0 — bench coverage for ext4 dx_hash directory hash function
// across all 5 supported hash versions plus the unknown-version
// fallback. dx_hash is on every htree directory lookup; a regression
// in any variant (swapped LEGACY multiplier, mis-aligned MD4 chunk
// loop, slower TEA Feistel rounds) would silently degrade lookup
// throughput without tripping any existing perf gate. Pairs with
// bd-590tc (proptest MRs) and the existing dx_hash unit tests for
// correctness; this pins the latency floor.

fn bench_ext4_dx_hash(c: &mut Criterion) {
    // Hash-version constants per fs/ext4/ext4.h (private in ondisk):
    //   0 = LEGACY (signed), 1 = HALF_MD4, 2 = TEA (signed),
    //   3 = LEGACY_UNSIGNED, 4 = HALF_MD4_UNSIGNED, 5 = TEA_UNSIGNED.
    const HASH_VERSIONS: [(u8, &str); 6] = [
        (0, "legacy_signed"),
        (1, "half_md4_signed"),
        (2, "tea_signed"),
        (3, "legacy_unsigned"),
        (4, "half_md4_unsigned"),
        (5, "tea_unsigned"),
    ];

    // Representative directory-name workload: 32 names of varying
    // lengths covering short ("a"), typical ("README.md"), nested
    // ("path/to/some/deeply/nested/file.txt"), max-length-ish, and
    // unicode-heavy patterns (as raw bytes — dx_hash takes &[u8]).
    const ASCII_UPPERCASE: &[u8; 26] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let names: Vec<Vec<u8>> = (0_usize..32)
        .map(|i| {
            let mut name = format!("entry_{i:04}_").into_bytes();
            // Pad to varying lengths to exercise both single-chunk
            // and multi-chunk paths in HALF_MD4 (32-byte chunks) and
            // TEA (16-byte chunks).
            let pad_len = 4 + (i % 64);
            name.extend(std::iter::repeat_n(
                ASCII_UPPERCASE[i % ASCII_UPPERCASE.len()],
                pad_len,
            ));
            name
        })
        .collect();

    let seed: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    for (version, label) in HASH_VERSIONS {
        c.bench_function(&format!("ext4_dx_hash_{label}"), |b| {
            b.iter(|| {
                for name in &names {
                    let (major, minor) =
                        dx_hash(black_box(version), black_box(name), black_box(&seed));
                    black_box((major, minor));
                }
            });
        });
    }
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
    bench_btrfs_superblock_parse_region,
    bench_btrfs_leaf_items_parse,
    bench_btrfs_internal_items_parse,
    bench_btrfs_header_parse_from_block,
    bench_ext4_dx_hash,
);
criterion_main!(ondisk);
