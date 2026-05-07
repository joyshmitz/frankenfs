#![forbid(unsafe_code)]

use criterion::{Criterion, criterion_group, criterion_main};
use ffs_btrfs::{BtrfsDirItem, BtrfsInodeItem, BtrfsInodeRef};
use ffs_harness::load_sparse_fixture;
use ffs_ondisk::{
    BtrfsHeader, BtrfsRaidProfile, BtrfsSuperblock, EXT_INIT_MAX_LEN, Ext4Extent, Ext4GroupDesc,
    Ext4Inode, chunk_type_flags, dx_hash, ext4_casefold_key, parse_dev_item, parse_dir_block,
    parse_dx_root, parse_extent_tree, parse_internal_items, parse_leaf_items,
    parse_sys_chunk_array, parse_xattr_block, verify_btrfs_superblock_checksum,
    verify_btrfs_tree_block_checksum,
};
use std::hint::black_box;
use std::path::Path;

const BTRFS_BENCH_BLOCK_SIZE: usize = 4096;
const BTRFS_HEADER_SIZE: usize = 101;
const BTRFS_KEY_PTR_SIZE: usize = 33;

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance/fixtures")
        .join(name)
}

fn btrfs_internal_node_block() -> Vec<u8> {
    let mut block = vec![0_u8; BTRFS_BENCH_BLOCK_SIZE];
    block
        .get_mut(0x60..0x64)
        .expect("btrfs nritems field")
        .copy_from_slice(&2_u32.to_le_bytes());
    *block.get_mut(0x64).expect("btrfs level field") = 1;
    write_btrfs_key_ptr(&mut block, 0, (256, 132, 0), 0x4000, 10);
    write_btrfs_key_ptr(&mut block, 1, (512, 132, 100), 0x8000, 10);
    block
}

fn write_btrfs_key_ptr(
    block: &mut [u8],
    index: usize,
    key: (u64, u8, u64),
    blockptr: u64,
    generation: u64,
) {
    let (objectid, item_type, offset) = key;
    let base = BTRFS_HEADER_SIZE + index * BTRFS_KEY_PTR_SIZE;
    block
        .get_mut(base..base + 8)
        .expect("btrfs key objectid field")
        .copy_from_slice(&objectid.to_le_bytes());
    *block.get_mut(base + 8).expect("btrfs key item_type field") = item_type;
    block
        .get_mut(base + 9..base + 17)
        .expect("btrfs key offset field")
        .copy_from_slice(&offset.to_le_bytes());
    block
        .get_mut(base + 17..base + 25)
        .expect("btrfs key_ptr blockptr field")
        .copy_from_slice(&blockptr.to_le_bytes());
    block
        .get_mut(base + 25..base + 33)
        .expect("btrfs key_ptr generation field")
        .copy_from_slice(&generation.to_le_bytes());
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
    let data = btrfs_internal_node_block();

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

// bd-rx88y — Criterion benches for `ext4_casefold_key` across the
// three distinct code paths in `casefold_name` (UTF-8 ASCII fast
// path, UTF-8 with multi-codepoint sharp-s expansion, invalid-UTF-8
// ASCII fallback). The function is on the hot path for every
// directory lookup on a casefold-enabled ext4 filesystem
// (lookup_in_dir_block_casefold calls it once per target plus once
// per scanned entry). Without these benches a regression in any
// branch — e.g., introducing per-char allocation, switching from
// chars() to grapheme iteration — would silently slow every
// casefold dir lookup with no signal until end users notice.
//
// Pairs with bd-6rsow proptest (32 cases of equivalence-relation
// laws), bd-c7nid fuzz target (>1M iterations / session), and
// bd-7pfh0 (dx_hash benches across 6 hash versions) — the same
// hot-path-correctness/performance pattern, applied to the casefold
// fold instead of the dx_hash function.

fn bench_ext4_casefold_key_ascii(c: &mut Criterion) {
    // Pure ASCII filename — the fast path: UTF-8 valid, every char
    // is single-codepoint and lowercases in place.
    let names: Vec<&[u8]> = vec![
        b"README.md",
        b"src",
        b"main.rs",
        b"Cargo.toml",
        b"DOCUMENTATION_AND_NOTES.txt",
        b"a",
        b"some_quite_long_filename_with_many_characters_to_exercise.dat",
    ];
    c.bench_function("ext4_casefold_key_ascii", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name)));
            }
        });
    });
}

fn bench_ext4_casefold_key_mixed_utf8(c: &mut Criterion) {
    // UTF-8 with embedded sharp-s — exercises the multi-codepoint
    // expansion branch. ß (U+00DF) and ẞ (U+1E9E) both expand to
    // "ss" via the explicit match in casefold_name.
    let names: Vec<&[u8]> = vec![
        "Straße.txt".as_bytes(),
        "GROẞBUCHSTABEN.md".as_bytes(),
        "café_passé.csv".as_bytes(),
        "MüllerStraße_Düsseldorf.log".as_bytes(),
        "naïve_façade_ßtest.dat".as_bytes(),
    ];
    c.bench_function("ext4_casefold_key_mixed_utf8", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name)));
            }
        });
    });
}

fn bench_ext4_casefold_key_long_utf8(c: &mut Criterion) {
    // Long all-non-ASCII UTF-8 input — exercises the multi-byte
    // chars() iteration path with no ASCII fast steps. Tests that
    // long Unicode lookups don't regress with grapheme/normalization
    // overhead.
    let names: Vec<Vec<u8>> = vec![
        "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ".repeat(4).into_bytes(),
        "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ".repeat(2).into_bytes(),
        "你好世界这是一个长的中文文件名".repeat(3).into_bytes(),
        "אבגדהוזחטיכלמנסעפצקרשת".repeat(4).into_bytes(),
    ];
    c.bench_function("ext4_casefold_key_long_utf8", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name.as_slice())));
            }
        });
    });
}

fn bench_ext4_casefold_key_invalid_utf8(c: &mut Criterion) {
    // Invalid UTF-8 — exercises the ASCII-fallback branch. Bytes
    // > 0x7F break UTF-8 validity, forcing the byte-by-byte ASCII
    // case fold path.
    let names: Vec<Vec<u8>> = vec![
        b"FILE\xff\xfe\xfd.bin".to_vec(),
        b"\x80\x81\x82SomeAsciiTail.dat".to_vec(),
        b"prefix\xc3middle\xc3suffix".to_vec(), // truncated UTF-8 lead
        b"\xff".repeat(64),
    ];
    c.bench_function("ext4_casefold_key_invalid_utf8", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name.as_slice())));
            }
        });
    });
}

fn bench_btrfs_raid_profile_single(c: &mut Criterion) {
    // Single is the no-RAID-bit fallback path for single-device filesystems.
    let inputs = [
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA,
        chunk_type_flags::BTRFS_BLOCK_GROUP_SYSTEM,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA,
    ];
    c.bench_function("btrfs_raid_profile_single", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(BtrfsRaidProfile::from_chunk_type(black_box(*input)));
            }
        });
    });
}

fn bench_btrfs_raid_profile_raid0(c: &mut Criterion) {
    // Raid0 is the first matching cascade arm.
    let inputs = [
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
        chunk_type_flags::BTRFS_BLOCK_GROUP_SYSTEM | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
    ];
    c.bench_function("btrfs_raid_profile_raid0", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(BtrfsRaidProfile::from_chunk_type(black_box(*input)));
            }
        });
    });
}

fn bench_btrfs_raid_profile_dup(c: &mut Criterion) {
    // Dup is the final matching cascade arm before the Single fallback.
    let inputs = [
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
    ];
    c.bench_function("btrfs_raid_profile_dup", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(BtrfsRaidProfile::from_chunk_type(black_box(*input)));
            }
        });
    });
}

fn bench_btrfs_raid_profile_mixed(c: &mut Criterion) {
    // Mixed workload covering all 9 profile outcomes.
    let inputs = [
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA, // Single
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C3,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C4,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
    ];
    c.bench_function("btrfs_raid_profile_mixed", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(BtrfsRaidProfile::from_chunk_type(black_box(*input)));
            }
        });
    });
}

// bd-ibj7e — Criterion benches for the ext4 *_extra timestamp bit-pack
// helpers. extra_nsec / extra_epoch decode the [nsec:30][epoch:2] u32
// layout once per timestamp read on every inode access on ext4 v6+
// filesystems. atime_full / mtime_full / ctime_full / crtime_full are
// the composite (i64, u32) decoders used by stat() and friends.
//
// Pairs with bd-834zk (proptest MR for the bit-pack algebra), bd-fqzsz
// (libfuzzer >1M iter), and bd-rx88y / bd-obp9f (casefold + raid_profile
// trios) — same hot-path correctness/perf trio applied to the timestamp
// bit-pack. A regression that introduced per-call allocation, switched
// from bit-shifts to a slower byte-extracting path, or added unnecessary
// bounds checks would silently slow every inode timestamp read with no
// CI signal.

fn bench_ext4_extra_nsec_epoch(c: &mut Criterion) {
    // Representative *_extra payloads: zero, all-ones, mid-range
    // nanoseconds, all four epoch values, and the explicit kernel
    // boundary (epoch=3, nsec=999_999_999).
    let inputs: Vec<u32> = vec![
        0x0000_0000,
        0xFFFF_FFFF,
        0x3B9A_C9FF, // nsec=249,999,999 epoch=3 — high-bit nsec
        0x0000_0001, // epoch=1 only
        0x0000_0002, // epoch=2 only
        0x0000_0003, // epoch=3 only
        // 999,999,999 ns << 2 | 0 epoch  = canonical max-nsec
        (999_999_999_u32) << 2,
        // 999,999,999 ns << 2 | 3 epoch  = max nsec + max epoch
        ((999_999_999_u32) << 2) | 0x3,
    ];
    c.bench_function("ext4_extra_nsec_epoch", |b| {
        b.iter(|| {
            for &extra in &inputs {
                black_box(Ext4Inode::extra_nsec(black_box(extra)));
                black_box(Ext4Inode::extra_epoch(black_box(extra)));
            }
        });
    });
}

fn bench_ext4_inode_atime_full(c: &mut Criterion) {
    // The composite atime_full path: sign-extend signed_base, shift
    // epoch into bits 32+, extract nsec, return (i64, u32). Run it
    // on a real parsed inode so the field accesses are realistic
    // rather than dummy struct.
    let data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");
    let inode = Ext4Inode::parse_from_bytes(&data).expect("inode parse");

    c.bench_function("ext4_inode_atime_full", |b| {
        b.iter(|| {
            black_box(black_box(&inode).atime_full());
        });
    });
}

fn bench_ext4_inode_all_timestamps(c: &mut Criterion) {
    // Representative stat() workload: every stat call decodes all
    // four timestamps (atime, mtime, ctime, crtime). A regression
    // in any single decoder would show up here as 4× the per-call
    // overhead.
    let data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");
    let inode = Ext4Inode::parse_from_bytes(&data).expect("inode parse");

    c.bench_function("ext4_inode_all_timestamps", |b| {
        b.iter(|| {
            let i = black_box(&inode);
            black_box(i.atime_full());
            black_box(i.mtime_full());
            black_box(i.ctime_full());
            black_box(i.crtime_full());
        });
    });
}

// bd-zc9l4 — Criterion benches for the Ext4Extent split-bit unwritten
// decoder (actual_len + is_unwritten). These run once per extent
// visited on every extent walk on every ext4 filesystem — high-
// frequency hot path for read, write, scrub, and repair. A regression
// that introduced per-call allocation, switched from a single
// subtract to a multi-step decode, or added unnecessary bounds checks
// would silently slow every extent walk with no CI signal.
//
// Pairs with bd-j0zo3 (proptest MR), bd-p0jgk (libfuzzer >1M iter)
// — same hot-path correctness/perf trio applied to the extent
// split-bit decoder.

fn bench_ext4_extent_actual_len_written(c: &mut Criterion) {
    // Workload of written extents (raw_len <= EXT_INIT_MAX_LEN).
    // Representative sizes: 1, 64, 4096, 0x7FFF, 0x8000 (boundary).
    let extents: Vec<Ext4Extent> = [1_u16, 64, 4096, 0x7FFF, EXT_INIT_MAX_LEN]
        .iter()
        .map(|&raw_len| Ext4Extent {
            logical_block: 0,
            raw_len,
            physical_start: 0,
        })
        .collect();
    c.bench_function("ext4_extent_actual_len_written", |b| {
        b.iter(|| {
            for ext in &extents {
                let e = black_box(*ext);
                black_box(e.actual_len());
                black_box(e.is_unwritten());
            }
        });
    });
}

fn bench_ext4_extent_actual_len_unwritten(c: &mut Criterion) {
    // Workload of unwritten extents (raw_len > EXT_INIT_MAX_LEN).
    // Representative sizes: MAX+1 (smallest unwritten, actual=1),
    // MAX+64, MAX+4096, MAX+0x7FFE, 0xFFFF (largest unwritten,
    // actual=0x7FFF).
    let extents: Vec<Ext4Extent> = [
        EXT_INIT_MAX_LEN + 1,
        EXT_INIT_MAX_LEN + 64,
        EXT_INIT_MAX_LEN + 4096,
        EXT_INIT_MAX_LEN + 0x7FFE,
        u16::MAX,
    ]
    .iter()
    .map(|&raw_len| Ext4Extent {
        logical_block: 0,
        raw_len,
        physical_start: 0,
    })
    .collect();
    c.bench_function("ext4_extent_actual_len_unwritten", |b| {
        b.iter(|| {
            for ext in &extents {
                let e = black_box(*ext);
                black_box(e.actual_len());
                black_box(e.is_unwritten());
            }
        });
    });
}

/// bd-tyzfe — verify_btrfs_superblock_checksum runs on every btrfs
/// mount path. The hot path computes CRC32C over [0x20..4096] and
/// compares against the bytes at [0..4]. A regression on this
/// function bloats every mount. Stamp a valid superblock once and
/// iterate verify in the bench loop.
fn bench_btrfs_verify_superblock_checksum(c: &mut Criterion) {
    const SUPERBLOCK_SIZE: usize = 4096;
    const CSUM_TYPE_OFFSET: usize = 0xC4;
    const COVERED_OFFSET: usize = 0x20;

    let mut sb = vec![0_u8; SUPERBLOCK_SIZE];
    sb[CSUM_TYPE_OFFSET..CSUM_TYPE_OFFSET + 2].copy_from_slice(&0_u16.to_le_bytes());
    let computed = crc32c::crc32c(&sb[COVERED_OFFSET..]);
    sb[0..4].copy_from_slice(&computed.to_le_bytes());

    c.bench_function("btrfs_verify_superblock_checksum", |b| {
        b.iter(|| {
            verify_btrfs_superblock_checksum(black_box(&sb)).expect("stamped superblock verifies");
        });
    });
}

/// bd-tyzfe — verify_btrfs_tree_block_checksum runs on every btrfs
/// tree block read (most frequent btrfs read-path call). Bench
/// against a stamped 4 KiB tree block with csum_type=0 (CRC32C),
/// matching production leaf-block size.
fn bench_btrfs_verify_tree_block_checksum(c: &mut Criterion) {
    const TREE_BLOCK_SIZE: usize = 4096;
    const COVERED_OFFSET: usize = 0x20;

    let mut tb = vec![0_u8; TREE_BLOCK_SIZE];
    let computed = crc32c::crc32c(&tb[COVERED_OFFSET..]);
    tb[0..4].copy_from_slice(&computed.to_le_bytes());

    c.bench_function("btrfs_verify_tree_block_checksum", |b| {
        b.iter(|| {
            verify_btrfs_tree_block_checksum(black_box(&tb), 0)
                .expect("stamped tree block verifies");
        });
    });
}

/// bd-coyy0 — parse_root_item runs on every subvolume enumeration
/// (read every entry of the root tree). Bench against the 239-byte
/// legacy minimum payload (uuid-era fields zeroed, generation_v2
/// disagrees → extension fields default to zero) which matches the
/// most common production root_item layout.
fn bench_btrfs_parse_root_item(c: &mut Criterion) {
    let mut payload = vec![0_u8; 239];
    // bytenr at offset 176 must be non-zero per parser invariant.
    payload[176..184].copy_from_slice(&0x1234_5678_9ABC_DEF0_u64.to_le_bytes());
    payload[238] = 0; // level=0

    c.bench_function("btrfs_parse_root_item", |b| {
        b.iter(|| {
            ffs_btrfs::parse_root_item(black_box(&payload)).expect("legacy root_item parses");
        });
    });
}

/// bd-coyy0 — parse_inode_refs runs on every inode_ref walk
/// (hardlink resolution, subvolume nav). Bench a single
/// 10-byte-header + 16-byte-name entry — the typical hardlink-target
/// shape.
fn bench_btrfs_parse_inode_refs(c: &mut Criterion) {
    let entry = BtrfsInodeRef {
        index: 0x1234_5678,
        name: b"hardlink-target1".to_vec(),
    };
    let payload = entry
        .try_to_bytes()
        .expect("typical inode_ref encodes within u16");

    c.bench_function("btrfs_parse_inode_refs", |b| {
        b.iter(|| {
            ffs_btrfs::parse_inode_refs(black_box(&payload)).expect("inode_ref parses");
        });
    });
}

/// bd-coyy0 — parse_dir_items runs on every directory readdir.
/// Bench a single 30-byte-header + 16-byte-name entry — the typical
/// directory entry shape.
fn bench_btrfs_parse_dir_items(c: &mut Criterion) {
    let entry = BtrfsDirItem {
        child_objectid: 0x1000,
        child_key_type: 1, // INODE_ITEM
        child_key_offset: 0,
        file_type: 1, // BTRFS_FT_REG_FILE
        name: b"regular_file_xy.".to_vec(),
    };
    let payload = entry
        .try_to_bytes()
        .expect("typical dir_item encodes within u16");

    c.bench_function("btrfs_parse_dir_items", |b| {
        b.iter(|| {
            ffs_btrfs::parse_dir_items(black_box(&payload)).expect("dir_item parses");
        });
    });
}

/// bd-maryc — parse_inode_item runs on every btrfs inode read
/// (open, stat, getattr, readdir-with-stat). Bench against a
/// kernel-stamped 160-byte payload matching the production hot path.
fn bench_btrfs_parse_inode_item(c: &mut Criterion) {
    let item = BtrfsInodeItem {
        generation: 0x1234,
        size: 0x10_0000, // 1 MiB
        nbytes: 0x10_0000,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        mode: 0o100_644,
        rdev: 0,
        atime_sec: 1_700_000_000,
        atime_nsec: 123_456_789,
        ctime_sec: 1_700_000_001,
        ctime_nsec: 234_567_890,
        mtime_sec: 1_700_000_002,
        mtime_nsec: 345_678_901,
        otime_sec: 1_700_000_003,
        otime_nsec: 456_789_012,
    };
    let payload = item.to_bytes();

    c.bench_function("btrfs_parse_inode_item", |b| {
        b.iter(|| {
            ffs_btrfs::parse_inode_item(black_box(&payload)).expect("inode_item parses");
        });
    });
}

/// bd-maryc — BtrfsInodeItem::to_bytes runs on every btrfs inode
/// write (commit, fsync, truncate path). Bench the encoder against
/// the same hot-path inputs as the parse bench so perf comparator
/// can track both sides of the encode/decode bijection.
fn bench_btrfs_inode_item_to_bytes(c: &mut Criterion) {
    let item = BtrfsInodeItem {
        generation: 0x1234,
        size: 0x10_0000,
        nbytes: 0x10_0000,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        mode: 0o100_644,
        rdev: 0,
        atime_sec: 1_700_000_000,
        atime_nsec: 123_456_789,
        ctime_sec: 1_700_000_001,
        ctime_nsec: 234_567_890,
        mtime_sec: 1_700_000_002,
        mtime_nsec: 345_678_901,
        otime_sec: 1_700_000_003,
        otime_nsec: 456_789_012,
    };

    c.bench_function("btrfs_inode_item_to_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(&item).to_bytes();
            black_box(bytes);
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
    bench_btrfs_superblock_parse_region,
    bench_btrfs_leaf_items_parse,
    bench_btrfs_internal_items_parse,
    bench_btrfs_header_parse_from_block,
    bench_ext4_dx_hash,
    bench_ext4_casefold_key_ascii,
    bench_ext4_casefold_key_mixed_utf8,
    bench_ext4_casefold_key_long_utf8,
    bench_ext4_casefold_key_invalid_utf8,
    bench_btrfs_raid_profile_single,
    bench_btrfs_raid_profile_raid0,
    bench_btrfs_raid_profile_dup,
    bench_btrfs_raid_profile_mixed,
    bench_ext4_extra_nsec_epoch,
    bench_ext4_inode_atime_full,
    bench_ext4_inode_all_timestamps,
    bench_ext4_extent_actual_len_written,
    bench_ext4_extent_actual_len_unwritten,
    bench_btrfs_verify_superblock_checksum,
    bench_btrfs_verify_tree_block_checksum,
    bench_btrfs_parse_root_item,
    bench_btrfs_parse_inode_refs,
    bench_btrfs_parse_dir_items,
    bench_btrfs_parse_inode_item,
    bench_btrfs_inode_item_to_bytes,
);
criterion_main!(ondisk);
