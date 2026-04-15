#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_btrfs::{
    BTRFS_CHUNK_TREE_OBJECTID, BTRFS_ITEM_CHUNK, BTRFS_ITEM_INODE_ITEM, BTRFS_SEND_STREAM_MAGIC,
    BtrfsDeviceSet, SendCommand, parse_send_stream, replay_tree_log, walk_chunk_tree,
};
use ffs_core::{OpenFs, OpenOptions};
use ffs_harness::{
    GoldenReference, ParityReport,
    e2e::{CrashReplaySuiteConfig, FsxStressConfig, run_crash_replay_suite, run_fsx_stress},
    load_sparse_fixture, validate_btrfs_chunk_fixture, validate_btrfs_fixture,
    validate_btrfs_leaf_fixture, validate_dir_block_fixture, validate_ext4_fixture,
    validate_extent_tree_fixture, validate_group_desc_fixture, validate_inode_fixture,
};
use ffs_ondisk::{
    BtrfsChunkEntry, BtrfsKey, BtrfsStripe, BtrfsSuperblock, Ext4IncompatFeatures, Ext4Superblock,
    ExtentTree, lookup_in_dir_block_casefold, parse_dir_block, stamp_dir_block_checksum,
    verify_dir_block_checksum,
};
use ffs_types::{EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_OFFSET, InodeNumber, ParseError};
use serde_json::Value;
use std::{
    collections::HashMap,
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    },
};

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance")
        .join("fixtures")
        .join(name)
}

#[test]
fn ext4_and_btrfs_fixtures_conform() {
    let ext4_sparse = validate_ext4_fixture(&fixture_path("ext4_superblock_sparse.json"))
        .expect("ext4 sparse fixture");
    let ext4_mkfs = validate_ext4_fixture(&fixture_path("ext4_superblock_mkfs_4096.json"))
        .expect("ext4 mkfs fixture");
    let btrfs = validate_btrfs_fixture(&fixture_path("btrfs_superblock_sparse.json"))
        .expect("btrfs fixture");

    assert_eq!(ext4_sparse.block_size, 4096);
    assert_eq!(ext4_mkfs.block_size, 4096);
    assert_eq!(ext4_mkfs.log_cluster_size, 2);
    assert_eq!(ext4_mkfs.cluster_size, 4096);
    assert_eq!(ext4_mkfs.blocks_per_group, ext4_mkfs.clusters_per_group);
    assert_eq!(ext4_mkfs.volume_name, "ffs-mkfs");
    assert_eq!(btrfs.sectorsize, 4096);
}

#[test]
fn ext4_group_desc_fixtures_conform() {
    let gd32 = validate_group_desc_fixture(&fixture_path("ext4_group_desc_32byte.json"), 32)
        .expect("32-byte group desc");
    assert_eq!(gd32.block_bitmap, 5);
    assert_eq!(gd32.inode_bitmap, 6);
    assert_eq!(gd32.inode_table, 7);
    assert_eq!(gd32.free_blocks_count, 200);

    let gd64 = validate_group_desc_fixture(&fixture_path("ext4_group_desc_64byte.json"), 64)
        .expect("64-byte group desc");
    assert!(
        gd64.block_bitmap > u64::from(u32::MAX),
        "64-bit path should set high bits"
    );
}

#[test]
fn ext4_inode_fixtures_conform() {
    let file_inode = validate_inode_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("regular file inode");
    assert_eq!(
        file_inode.mode & 0o17_0000,
        0o10_0000,
        "should be regular file"
    );
    assert_eq!(file_inode.size, 1024);

    let dir_inode = validate_inode_fixture(&fixture_path("ext4_inode_directory.json"))
        .expect("directory inode");
    assert_eq!(dir_inode.mode & 0o17_0000, 0o4_0000, "should be directory");
    assert_eq!(dir_inode.links_count, 2);
}

#[test]
fn ext4_inline_data_fixture_conforms() {
    // Simple inline data inode (data fits in i_block field)
    let inode = validate_inode_fixture(&fixture_path("ext4_inode_inline_data.json"))
        .expect("inline data inode");
    assert_eq!(inode.mode & 0o17_0000, 0o10_0000, "should be regular file");
    assert_eq!(inode.size, 23, "inline data size should be 23 bytes");
    assert_ne!(
        inode.flags & ffs_types::EXT4_INLINE_DATA_FL,
        0,
        "should have INLINE_DATA flag"
    );

    // Check that extent_bytes contains the inline data ("Hello from inline data!")
    let expected = b"Hello from inline data!";
    assert_eq!(
        &inode.extent_bytes[..expected.len()],
        expected,
        "i_block should contain inline data"
    );
}

#[test]
fn ext4_inline_data_with_continuation_fixture_conforms() {
    // Inline data inode with system.data xattr continuation
    let inode = validate_inode_fixture(&fixture_path(
        "ext4_inode_inline_data_with_continuation.json",
    ))
    .expect("inline data inode with continuation");
    assert_eq!(
        inode.size, 76,
        "inline data size should be 76 bytes (60 + 16)"
    );
    assert_ne!(
        inode.flags & ffs_types::EXT4_INLINE_DATA_FL,
        0,
        "should have INLINE_DATA flag"
    );

    // Check i_block contains 60 bytes of 'A'
    assert!(
        inode.extent_bytes.iter().all(|&b| b == b'A'),
        "i_block should contain 60 bytes of 'A'"
    );

    // Parse ibody xattrs to find system.data continuation
    let xattrs = ffs_ondisk::parse_ibody_xattrs(&inode).expect("parse ibody xattrs");
    let system_data = xattrs
        .iter()
        .find(|x| x.name_index == 7 && x.name == b"data");
    assert!(system_data.is_some(), "should have system.data xattr");

    let continuation = system_data.unwrap();
    assert_eq!(
        continuation.value.len(),
        16,
        "continuation should be 16 bytes"
    );
    assert!(
        continuation.value.iter().all(|&b| b == b'B'),
        "continuation should contain 'B' bytes"
    );
}

#[test]
fn ext4_extent_tree_leaf_fixture_conforms() {
    let (header, tree) = validate_extent_tree_fixture(&fixture_path("ext4_extent_tree_leaf.json"))
        .expect("extent tree leaf");

    assert_eq!(header.magic, 0xF30A, "should have extent magic");
    assert_eq!(header.entries, 3, "should have 3 extents");
    assert_eq!(header.max_entries, 4, "max_entries should be 4");
    assert_eq!(header.depth, 0, "should be leaf (depth=0)");

    let extents = match tree {
        ExtentTree::Leaf(extents) => extents,
        ExtentTree::Index(_) => panic!("expected leaf, got index"),
    };

    assert_eq!(extents.len(), 3, "should have 3 extents");

    // Extent 0: logical 0, len 8, physical 256
    assert_eq!(extents[0].logical_block, 0);
    assert_eq!(extents[0].actual_len(), 8);
    assert_eq!(extents[0].physical_start, 256);
    assert!(!extents[0].is_unwritten());

    // Extent 1: logical 8, len 16, physical 264
    assert_eq!(extents[1].logical_block, 8);
    assert_eq!(extents[1].actual_len(), 16);
    assert_eq!(extents[1].physical_start, 264);
    assert!(!extents[1].is_unwritten());

    // Extent 2: logical 24, len 4 (unwritten), physical 280
    assert_eq!(extents[2].logical_block, 24);
    assert_eq!(extents[2].actual_len(), 4);
    assert_eq!(extents[2].physical_start, 280);
    assert!(extents[2].is_unwritten(), "extent 2 should be unwritten");
}

#[test]
fn ext4_extent_tree_index_fixture_conforms() {
    let (header, tree) = validate_extent_tree_fixture(&fixture_path("ext4_extent_tree_index.json"))
        .expect("extent tree index");

    assert_eq!(header.magic, 0xF30A, "should have extent magic");
    assert_eq!(header.entries, 2, "should have 2 index entries");
    assert_eq!(header.max_entries, 3, "max_entries should be 3");
    assert_eq!(header.depth, 1, "should be internal node (depth=1)");
    assert_eq!(header.generation, 1, "generation should be 1");

    let indices = match tree {
        ExtentTree::Index(indices) => indices,
        ExtentTree::Leaf(_) => panic!("expected index, got leaf"),
    };

    assert_eq!(indices.len(), 2, "should have 2 index entries");

    // Index 0: logical 0, leaf block 512
    assert_eq!(indices[0].logical_block, 0);
    assert_eq!(indices[0].leaf_block, 512);

    // Index 1: logical 4096, leaf block 513
    assert_eq!(indices[1].logical_block, 4096);
    assert_eq!(indices[1].leaf_block, 513);
}

#[test]
fn ext4_htree_dx_root_fixture_conforms() {
    let dx_root =
        ffs_harness::validate_htree_dx_root_fixture(&fixture_path("ext4_htree_dx_root.json"))
            .expect("htree DX root");

    assert_eq!(dx_root.hash_version, 1, "should use half_md4 (1)");
    assert_eq!(
        dx_root.indirect_levels, 0,
        "should be single-level (indirect_levels=0)"
    );

    // Should have 3 DX entries: sentinel + 2 real entries
    assert_eq!(dx_root.entries.len(), 3, "should have 3 DX entries");

    // Entry 0: sentinel (hash implicitly 0, block 1)
    assert_eq!(dx_root.entries[0].hash, 0);
    assert_eq!(dx_root.entries[0].block, 1);

    // Entry 1: hash=0x1000, block=2
    assert_eq!(dx_root.entries[1].hash, 0x1000);
    assert_eq!(dx_root.entries[1].block, 2);

    // Entry 2: hash=0x8000, block=3
    assert_eq!(dx_root.entries[2].hash, 0x8000);
    assert_eq!(dx_root.entries[2].block, 3);
}

#[test]
fn ext4_xattr_block_fixture_conforms() {
    let xattrs = ffs_harness::validate_xattr_block_fixture(&fixture_path("ext4_xattr_block.json"))
        .expect("xattr block");

    assert_eq!(xattrs.len(), 2, "should have 2 xattrs");

    // user.mime = "text/plain"
    let mime = xattrs.iter().find(|x| x.full_name() == "user.mime");
    assert!(mime.is_some(), "should have user.mime xattr");
    assert_eq!(mime.unwrap().value, b"text/plain");

    // security.selinux = "system_u:object_r:user_home_t:s0"
    let selinux = xattrs.iter().find(|x| x.full_name() == "security.selinux");
    assert!(selinux.is_some(), "should have security.selinux xattr");
    assert_eq!(
        std::str::from_utf8(&selinux.unwrap().value).unwrap(),
        "system_u:object_r:user_home_t:s0"
    );
}

#[test]
fn ext4_dir_block_fixture_conforms() {
    let entries =
        validate_dir_block_fixture(&fixture_path("ext4_dir_block.json"), 4096).expect("dir block");
    assert!(entries.len() >= 3, "should have at least 3 entries");
    assert!(entries.iter().any(|e| e.name_str() == "hello.txt"));
}

#[test]
fn ext4_dir_block_with_tail_fixture_conforms() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_with_tail.json"))
        .expect("load tail fixture");
    let (entries, tail) = parse_dir_block(&data, 4096).expect("parse dir block with tail");
    assert_eq!(entries.len(), 3, "expected 3 directory entries");
    assert_eq!(
        entries
            .last()
            .map(ffs_ondisk::Ext4DirEntry::name_str)
            .as_deref(),
        Some("hello.txt"),
        "last entry should be hello.txt"
    );
    assert_eq!(
        entries.last().map(|e| e.rec_len),
        Some(4060),
        "last entry rec_len should leave room for tail"
    );
    let tail = tail.expect("expected checksum tail");
    assert_eq!(tail.checksum, 0x1234_5678);
}

#[test]
fn ext4_dir_block_deleted_entry_fixture_conforms() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_deleted_entry.json"))
        .expect("load deleted entry fixture");
    let (entries, tail) = parse_dir_block(&data, 4096).expect("parse dir block");
    assert!(tail.is_none(), "deleted-entry fixture should have no tail");
    assert_eq!(entries.len(), 3, "expected 3 live directory entries");
    assert!(entries.iter().all(|e| e.inode != 0));
    assert!(entries.iter().any(|e| e.name_str() == "hello.txt"));
}

#[test]
fn ext4_dir_block_truncated_tail_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_truncated_tail.json"))
        .expect("load truncated tail fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(err, ParseError::InsufficientData { .. }),
        "expected InsufficientData error, got {err:?}"
    );
}

#[test]
fn ext4_dir_block_checksum_stamp_and_verify_fixture_conforms() {
    let mut data = load_sparse_fixture(&fixture_path("ext4_dir_block_with_tail.json"))
        .expect("load checksum tail fixture");
    let csum_seed = 0xA5A5_5A5A;
    let inode = 2_u32;
    let generation = 1_u32;
    stamp_dir_block_checksum(&mut data, csum_seed, inode, generation);
    verify_dir_block_checksum(&data, csum_seed, inode, generation).expect("checksum should verify");
}

#[test]
fn ext4_dir_block_checksum_detects_corruption() {
    let mut data = load_sparse_fixture(&fixture_path("ext4_dir_block_with_tail.json"))
        .expect("load checksum tail fixture");
    let csum_seed = 0xA5A5_5A5A;
    let inode = 2_u32;
    let generation = 1_u32;
    stamp_dir_block_checksum(&mut data, csum_seed, inode, generation);
    data[0] ^= 0xFF;
    let err = verify_dir_block_checksum(&data, csum_seed, inode, generation).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "dir_checksum",
                ..
            }
        ),
        "expected InvalidField(dir_checksum), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_rec_len_too_small_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_rec_len_too_small.json"))
        .expect("load rec_len fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "de_rec_len",
                ..
            }
        ),
        "expected InvalidField(de_rec_len), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_name_len_overflow_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_name_len_overflow.json"))
        .expect("load name_len fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "de_name_len",
                ..
            }
        ),
        "expected InvalidField(de_name_len), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_rec_len_min12_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_rec_len_too_small_min12.json"))
        .expect("load rec_len min12 fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "de_rec_len",
                ..
            }
        ),
        "expected InvalidField(de_rec_len), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_rec_len_unaligned_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_rec_len_unaligned.json"))
        .expect("load rec_len unaligned fixture");
    let err = parse_dir_block(&data, 4096).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "de_rec_len",
                ..
            }
        ),
        "expected InvalidField(de_rec_len), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_tail_padding_nonzero_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_tail_padding_nonzero.json"))
        .expect("load tail padding fixture");
    let err = parse_dir_block(&data, 32).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block_tail",
                ..
            }
        ),
        "expected InvalidField(dir_block_tail), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_tail_bad_header_fixture_rejected() {
    let data = load_sparse_fixture(&fixture_path("ext4_dir_block_tail_bad_header.json"))
        .expect("load tail bad header fixture");
    let err = verify_dir_block_checksum(&data, 0, 2, 1).unwrap_err();
    assert!(
        matches!(
            err,
            ParseError::InvalidField {
                field: "dir_block_tail",
                ..
            }
        ),
        "expected InvalidField(dir_block_tail), got {err:?}"
    );
}

#[test]
fn ext4_dir_block_casefold_lookup_conforms() {
    let data =
        load_sparse_fixture(&fixture_path("ext4_dir_block.json")).expect("load dir block fixture");
    let entry = lookup_in_dir_block_casefold(&data, 4096, b"HELLO.TXT").expect("casefold lookup");
    assert!(
        entry.as_ref().is_some_and(|e| e.name_str() == "hello.txt"),
        "casefold lookup should match hello.txt"
    );
}

#[test]
fn ext4_fscrypt_nokey_readdir_and_lookup_preserve_raw_bytes() {
    let raw_name = b"\xFFenc\x80";
    let image = build_ext4_encrypt_image_with_dir(raw_name);
    let superblock = Ext4Superblock::parse_from_image(&image).expect("parse encrypted superblock");
    assert!(
        superblock.has_incompat(Ext4IncompatFeatures::ENCRYPT),
        "test image should advertise ENCRYPT incompat"
    );

    let tmp = tempfile::NamedTempFile::new().expect("create encrypted ext4 temp image");
    std::fs::write(tmp.path(), &image).expect("write encrypted ext4 image");

    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, tmp.path(), &OpenOptions::default())
        .expect("open encrypted ext4 image in nokey mode");

    let raw_entries = fs
        .readdir(&cx, InodeNumber(2), 0)
        .expect("readdir raw bytes");
    let encrypted = raw_entries
        .iter()
        .find(|entry| entry.name == raw_name)
        .expect("encrypted entry should preserve raw bytes in readdir");
    assert_eq!(encrypted.ino, InodeNumber(11));

    let attr = fs
        .lookup(&cx, InodeNumber(2), OsStr::from_bytes(raw_name))
        .expect("lookup should accept raw encrypted filename bytes");
    assert_eq!(attr.ino, InodeNumber(11));

    let root = fs.read_inode(&cx, InodeNumber(2)).expect("read root inode");
    let raw_lookup = fs
        .lookup_name(&cx, &root, raw_name)
        .expect("device lookup should parse encrypted entry")
        .expect("encrypted entry should be found");
    assert_eq!(raw_lookup.name, raw_name);
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_encrypt_image_with_dir(raw_name: &[u8]) -> Vec<u8> {
    assert!(
        raw_name.len() < 256,
        "raw encrypted ext4 name must fit in a single dirent"
    );

    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat = (Ext4IncompatFeatures::FILETYPE.0
        | Ext4IncompatFeatures::EXTENTS.0
        | Ext4IncompatFeatures::ENCRYPT.0)
        .to_le_bytes();
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat);
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let ino2 = 4 * 4096 + 256;
    image[ino2..ino2 + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[ino2 + 4..ino2 + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[ino2 + 0x1A..ino2 + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[ino2 + 0x20..ino2 + 0x24].copy_from_slice(&0x0008_0000_u32.to_le_bytes());
    image[ino2 + 0x80..ino2 + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = ino2 + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes());

    let ino11 = 4 * 4096 + 10 * 256;
    image[ino11..ino11 + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[ino11 + 4..ino11 + 8].copy_from_slice(&5_u32.to_le_bytes());
    image[ino11 + 0x1A..ino11 + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino11 + 0x80..ino11 + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let dir = 10 * 4096;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 1;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';

    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir + 6] = 2;
    image[dir + 7] = 2;
    image[dir + 8] = b'.';
    image[dir + 9] = b'.';

    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&4072_u16.to_le_bytes());
    image[dir + 6] = raw_name.len() as u8;
    image[dir + 7] = 1;
    image[dir + 8..dir + 8 + raw_name.len()].copy_from_slice(raw_name);

    image
}

#[allow(clippy::cast_possible_truncation)]
fn append_send_stream_command(stream: &mut Vec<u8>, cmd: u16, attrs: &[(u16, &[u8])]) {
    let payload_len: usize = attrs.iter().map(|(_, value)| 4 + value.len()).sum();
    stream.extend_from_slice(&(payload_len as u32).to_le_bytes());
    stream.extend_from_slice(&cmd.to_le_bytes());
    stream.extend_from_slice(&0_u32.to_le_bytes());
    for (attr, value) in attrs {
        stream.extend_from_slice(&attr.to_le_bytes());
        stream.extend_from_slice(&(value.len() as u16).to_le_bytes());
        stream.extend_from_slice(value);
    }
}

const BTRFS_TEST_NODESIZE: u32 = 4096;
const BTRFS_TEST_HEADER_SIZE: usize = 101;
const BTRFS_TEST_ITEM_SIZE: usize = 25;
const BTRFS_TEST_KEY_PTR_SIZE: usize = 33;

fn build_btrfs_tree_log_superblock(log_root: u64, log_root_level: u8) -> BtrfsSuperblock {
    BtrfsSuperblock {
        csum: [0; 32],
        fsid: [0; 16],
        bytenr: 0,
        flags: 0,
        magic: 0,
        generation: 77,
        root: 0,
        chunk_root: 0,
        log_root,
        total_bytes: 0,
        bytes_used: 0,
        root_dir_objectid: 0,
        num_devices: 1,
        sectorsize: BTRFS_TEST_NODESIZE,
        nodesize: BTRFS_TEST_NODESIZE,
        stripesize: 0,
        compat_flags: 0,
        compat_ro_flags: 0,
        incompat_flags: 0,
        csum_type: 0,
        root_level: 0,
        chunk_root_level: 0,
        log_root_level,
        label: String::new(),
        sys_chunk_array_size: 0,
        sys_chunk_array: Vec::new(),
    }
}

fn build_btrfs_chunk_tree_superblock(chunk_root: u64) -> BtrfsSuperblock {
    BtrfsSuperblock {
        csum: [0; 32],
        fsid: [0; 16],
        bytenr: chunk_root,
        flags: 0,
        magic: 0,
        generation: 77,
        root: 0,
        chunk_root,
        log_root: 0,
        total_bytes: 0,
        bytes_used: 0,
        root_dir_objectid: 0,
        num_devices: 1,
        sectorsize: BTRFS_TEST_NODESIZE,
        nodesize: BTRFS_TEST_NODESIZE,
        stripesize: 0,
        compat_flags: 0,
        compat_ro_flags: 0,
        incompat_flags: 0,
        csum_type: 0,
        root_level: 0,
        chunk_root_level: 0,
        log_root_level: 0,
        label: String::new(),
        sys_chunk_array_size: 0,
        sys_chunk_array: Vec::new(),
    }
}

fn build_single_stripe_chunk(
    logical_start: u64,
    length: u64,
    physical_start: u64,
) -> BtrfsChunkEntry {
    BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical_start,
        },
        length,
        owner: 2,
        stripe_len: u64::from(BTRFS_TEST_NODESIZE),
        chunk_type: 1,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 1,
        sub_stripes: 0,
        stripes: vec![BtrfsStripe {
            devid: 1,
            offset: physical_start,
            dev_uuid: [0; 16],
        }],
    }
}

fn write_btrfs_header(
    block: &mut [u8],
    bytenr: u64,
    nritems: u32,
    level: u8,
    owner: u64,
    generation: u64,
) {
    block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
    block[0x50..0x58].copy_from_slice(&generation.to_le_bytes());
    block[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
    block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
    block[0x64] = level;
}

fn write_btrfs_leaf_item(
    block: &mut [u8],
    idx: usize,
    objectid: u64,
    item_type: u8,
    data_off: u32,
    data_sz: u32,
) {
    let base = BTRFS_TEST_HEADER_SIZE + idx * BTRFS_TEST_ITEM_SIZE;
    let header_size =
        u32::try_from(BTRFS_TEST_HEADER_SIZE).expect("btrfs test header size should fit in u32");
    let encoded_data_off = data_off
        .checked_sub(header_size)
        .expect("btrfs test payload should follow the header");
    block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
    block[base + 8] = item_type;
    block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
    block[base + 17..base + 21].copy_from_slice(&encoded_data_off.to_le_bytes());
    block[base + 21..base + 25].copy_from_slice(&data_sz.to_le_bytes());
}

fn write_btrfs_key_ptr(
    block: &mut [u8],
    idx: usize,
    objectid: u64,
    item_type: u8,
    blockptr: u64,
    generation: u64,
) {
    let base = BTRFS_TEST_HEADER_SIZE + idx * BTRFS_TEST_KEY_PTR_SIZE;
    block[base..base + 8].copy_from_slice(&objectid.to_le_bytes());
    block[base + 8] = item_type;
    block[base + 9..base + 17].copy_from_slice(&0_u64.to_le_bytes());
    block[base + 17..base + 25].copy_from_slice(&blockptr.to_le_bytes());
    block[base + 25..base + 33].copy_from_slice(&generation.to_le_bytes());
}

fn build_chunk_item_payload(
    length: u64,
    owner: u64,
    stripe_len: u64,
    chunk_type: u64,
    io_align: u32,
    io_width: u32,
    sector_size: u32,
    devid: u64,
    physical_offset: u64,
) -> Vec<u8> {
    let mut data = vec![0_u8; 48 + 32];
    data[0..8].copy_from_slice(&length.to_le_bytes());
    data[8..16].copy_from_slice(&owner.to_le_bytes());
    data[16..24].copy_from_slice(&stripe_len.to_le_bytes());
    data[24..32].copy_from_slice(&chunk_type.to_le_bytes());
    data[32..36].copy_from_slice(&io_align.to_le_bytes());
    data[36..40].copy_from_slice(&io_width.to_le_bytes());
    data[40..44].copy_from_slice(&sector_size.to_le_bytes());
    data[44..46].copy_from_slice(&1_u16.to_le_bytes());
    data[46..48].copy_from_slice(&0_u16.to_le_bytes());
    data[48..56].copy_from_slice(&devid.to_le_bytes());
    data[56..64].copy_from_slice(&physical_offset.to_le_bytes());
    data
}

#[test]
fn btrfs_send_stream_multi_command_conforms() {
    let mut data = Vec::new();
    data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
    data.extend_from_slice(&1_u32.to_le_bytes());

    let uuid = *b"ffs-send-subvol!";
    append_send_stream_command(
        &mut data,
        SendCommand::Subvol as u16,
        &[(1, &uuid), (15, b"/sv")],
    );
    append_send_stream_command(
        &mut data,
        SendCommand::Write as u16,
        &[
            (15, b"/sv/file.txt"),
            (18, &0_u64.to_le_bytes()),
            (19, b"hello"),
        ],
    );
    append_send_stream_command(&mut data, SendCommand::End as u16, &[]);

    let result = parse_send_stream(&data).expect("parse multi-command send stream");
    assert_eq!(result.version, 1);
    assert_eq!(result.commands.len(), 3);
    assert_eq!(result.commands[0].cmd, SendCommand::Subvol);
    assert_eq!(result.commands[0].attrs[0], (1, uuid.to_vec()));
    assert_eq!(result.commands[0].attrs[1], (15, b"/sv".to_vec()));
    assert_eq!(result.commands[1].cmd, SendCommand::Write);
    assert_eq!(result.commands[1].attrs[0], (15, b"/sv/file.txt".to_vec()));
    assert_eq!(
        result.commands[1].attrs[1],
        (18, 0_u64.to_le_bytes().to_vec())
    );
    assert_eq!(result.commands[1].attrs[2], (19, b"hello".to_vec()));
    assert_eq!(result.commands[2].cmd, SendCommand::End);
    assert!(result.commands[2].attrs.is_empty());
}

#[test]
fn btrfs_send_stream_unknown_command_preserves_attrs_as_unspec() {
    let mut data = Vec::new();
    data.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
    data.extend_from_slice(&1_u32.to_le_bytes());
    append_send_stream_command(&mut data, 0xFFFE, &[(15, b"/mystery")]);
    append_send_stream_command(&mut data, SendCommand::End as u16, &[]);

    let result = parse_send_stream(&data).expect("parse send stream with unknown command");
    assert_eq!(result.commands.len(), 2);
    assert_eq!(result.commands[0].cmd, SendCommand::Unspec);
    assert_eq!(result.commands[0].attrs, vec![(15, b"/mystery".to_vec())]);
    assert_eq!(result.commands[1].cmd, SendCommand::End);
}

#[test]
fn btrfs_tree_log_replay_multilevel_conforms() {
    let root_logical = 0x10_000_u64;
    let leaf_logical = 0x20_000_u64;
    let physical_start = 0x80_000_u64;
    let root_physical = physical_start;
    let leaf_physical = physical_start + (leaf_logical - root_logical);
    let chunk_length = leaf_logical + u64::from(BTRFS_TEST_NODESIZE) - root_logical;
    let chunks = vec![build_single_stripe_chunk(
        root_logical,
        chunk_length,
        physical_start,
    )];

    let mut root = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut root, root_logical, 1, 1, 5, 77);
    write_btrfs_key_ptr(&mut root, 0, 256, BTRFS_ITEM_INODE_ITEM, leaf_logical, 77);

    let mut leaf = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut leaf, leaf_logical, 2, 0, 5, 77);
    let alpha_off = 3600_u32;
    let beta_off = 3605_u32;
    write_btrfs_leaf_item(&mut leaf, 0, 256, BTRFS_ITEM_INODE_ITEM, alpha_off, 5);
    leaf[alpha_off as usize..(alpha_off + 5) as usize].copy_from_slice(b"alpha");
    write_btrfs_leaf_item(&mut leaf, 1, 257, BTRFS_ITEM_INODE_ITEM, beta_off, 4);
    leaf[beta_off as usize..(beta_off + 4) as usize].copy_from_slice(b"beta");

    let blocks: HashMap<u64, Vec<u8>> = [(root_physical, root), (leaf_physical, leaf)]
        .into_iter()
        .collect();
    let mut reads = Vec::new();
    let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
        reads.push(phys);
        blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
            field: "physical",
            reason: "block not in test image",
        })
    };

    let sb = build_btrfs_tree_log_superblock(root_logical, 1);
    let replay = replay_tree_log(&mut read, &sb, &chunks).expect("replay tree-log");
    assert!(replay.replayed, "tree-log with log_root should replay");
    assert_eq!(reads, vec![root_physical, leaf_physical]);
    assert_eq!(replay.items_count, 2);
    assert_eq!(replay.items.len(), 2);
    assert_eq!(replay.items[0].key.objectid, 256);
    assert_eq!(replay.items[0].key.item_type, BTRFS_ITEM_INODE_ITEM);
    assert_eq!(replay.items[0].data, b"alpha");
    assert_eq!(replay.items[1].key.objectid, 257);
    assert_eq!(replay.items[1].key.item_type, BTRFS_ITEM_INODE_ITEM);
    assert_eq!(replay.items[1].data, b"beta");
}

#[test]
fn btrfs_tree_log_replay_skips_when_log_root_absent() {
    let sb = build_btrfs_tree_log_superblock(0, 0);
    let mut read_calls = 0_usize;
    let mut read = |_phys: u64| -> Result<Vec<u8>, ParseError> {
        read_calls += 1;
        Err(ParseError::InvalidField {
            field: "physical",
            reason: "tree-log replay should not read when log_root is absent",
        })
    };

    let replay = replay_tree_log(&mut read, &sb, &[]).expect("tree-log absent fast path");
    assert_eq!(read_calls, 0, "no physical reads should occur");
    assert!(!replay.replayed);
    assert_eq!(replay.items_count, 0);
    assert!(replay.items.is_empty());
}

#[test]
fn btrfs_chunk_tree_walk_adds_and_sorts_new_chunks() {
    let chunk_root_logical = 0x10_000_u64;
    let bootstrap = vec![build_single_stripe_chunk(
        chunk_root_logical,
        u64::from(BTRFS_TEST_NODESIZE),
        0x80_000,
    )];

    let mut leaf = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(
        &mut leaf,
        chunk_root_logical,
        1,
        0,
        BTRFS_CHUNK_TREE_OBJECTID,
        77,
    );
    let payload = build_chunk_item_payload(
        0x20_000,
        2,
        0x10_000,
        1,
        BTRFS_TEST_NODESIZE,
        BTRFS_TEST_NODESIZE,
        BTRFS_TEST_NODESIZE,
        2,
        0x90_000,
    );
    let data_off = 3500_u32;
    write_btrfs_leaf_item(
        &mut leaf,
        0,
        256,
        BTRFS_ITEM_CHUNK,
        data_off,
        u32::try_from(payload.len()).expect("payload length should fit in u32"),
    );
    let end = data_off as usize + payload.len();
    leaf[data_off as usize..end].copy_from_slice(&payload);
    let blocks: HashMap<u64, Vec<u8>> = [(0x80_000_u64, leaf)].into_iter().collect();
    let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
        blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
            field: "physical",
            reason: "block not in test image",
        })
    };

    let sb = build_btrfs_chunk_tree_superblock(chunk_root_logical);
    let chunks = walk_chunk_tree(&mut read, &sb, &bootstrap).expect("walk chunk tree");
    assert_eq!(
        chunks.len(),
        2,
        "bootstrap + chunk-tree entry should be returned"
    );
    assert_eq!(chunks[0].key.offset, chunk_root_logical);
    assert_eq!(chunks[0].stripes[0].offset, 0x80_000);
    assert_eq!(chunks[1].key.offset, 0x20_000);
    assert_eq!(chunks[1].length, 0x20_000);
    assert_eq!(chunks[1].stripe_len, 0x10_000);
    assert_eq!(chunks[1].stripes[0].devid, 2);
    assert_eq!(chunks[1].stripes[0].offset, 0x90_000);
}

#[test]
fn btrfs_multi_device_raid1_read_falls_back_to_second_mirror() {
    let logical = 0x40_000_u64;
    let stripe_len = 0x10_000_u64;
    let chunks = vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical,
        },
        length: stripe_len,
        owner: 2,
        stripe_len,
        chunk_type: ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 2,
        sub_stripes: 0,
        stripes: vec![
            BtrfsStripe {
                devid: 1,
                offset: 0x100_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 2,
                offset: 0x200_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let first_reads = Arc::new(AtomicUsize::new(0));
    let second_reads = Arc::new(AtomicUsize::new(0));

    let first_reads_for_closure = Arc::clone(&first_reads);
    devices.add_device(
        1,
        Box::new(move |physical, len| {
            first_reads_for_closure.fetch_add(1, AtomicOrdering::SeqCst);
            assert_eq!(physical, 0x100_000);
            assert_eq!(len, 4);
            Err(ParseError::InvalidField {
                field: "device",
                reason: "simulated mirror read failure",
            })
        }),
    );

    let second_reads_for_closure = Arc::clone(&second_reads);
    devices.add_device(
        2,
        Box::new(move |physical, len| {
            second_reads_for_closure.fetch_add(1, AtomicOrdering::SeqCst);
            assert_eq!(physical, 0x200_000);
            assert_eq!(len, 4);
            Ok(b"raid".to_vec())
        }),
    );

    let data = devices
        .read_logical(&chunks, logical, 4)
        .expect("second RAID1 mirror should satisfy read");
    assert_eq!(data, b"raid");
    assert_eq!(first_reads.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(second_reads.load(AtomicOrdering::SeqCst), 1);
}

#[test]
fn btrfs_multi_device_raid0_dispatches_to_correct_stripe() {
    let logical = 0x80_000_u64;
    let stripe_len = 0x10_000_u64;
    let chunks = vec![BtrfsChunkEntry {
        key: BtrfsKey {
            objectid: 256,
            item_type: 228,
            offset: logical,
        },
        length: stripe_len * 2,
        owner: 2,
        stripe_len,
        chunk_type: ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DATA
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 2,
        sub_stripes: 0,
        stripes: vec![
            BtrfsStripe {
                devid: 1,
                offset: 0x300_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 2,
                offset: 0x400_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let first_reads = Arc::new(AtomicUsize::new(0));
    let second_reads = Arc::new(AtomicUsize::new(0));

    let first_reads_for_closure = Arc::clone(&first_reads);
    devices.add_device(
        1,
        Box::new(move |_physical, _len| {
            first_reads_for_closure.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(b"first".to_vec())
        }),
    );

    let second_reads_for_closure = Arc::clone(&second_reads);
    devices.add_device(
        2,
        Box::new(move |physical, len| {
            second_reads_for_closure.fetch_add(1, AtomicOrdering::SeqCst);
            assert_eq!(physical, 0x400_000);
            assert_eq!(len, 5);
            Ok(b"strip".to_vec())
        }),
    );

    let data = devices
        .read_logical(&chunks, logical + stripe_len, 5)
        .expect("RAID0 second stripe should dispatch to device 2");
    assert_eq!(data, b"strip");
    assert_eq!(first_reads.load(AtomicOrdering::SeqCst), 0);
    assert_eq!(second_reads.load(AtomicOrdering::SeqCst), 1);
}

#[test]
fn btrfs_chunk_mapping_fixture_conforms() {
    let (sb, chunks) =
        validate_btrfs_chunk_fixture(&fixture_path("btrfs_superblock_with_chunks.json"))
            .expect("btrfs chunk fixture");
    assert!(!chunks.is_empty(), "should have at least one chunk entry");
    // root and chunk_root should be mappable
    let root_map = ffs_ondisk::map_logical_to_physical(&chunks, sb.root)
        .expect("mapping ok")
        .expect("root covered");
    assert_eq!(root_map.devid, 1);
    let cr_map = ffs_ondisk::map_logical_to_physical(&chunks, sb.chunk_root)
        .expect("mapping ok")
        .expect("chunk_root covered");
    assert_eq!(cr_map.devid, 1);
}

#[test]
fn btrfs_leaf_fixture_conforms() {
    let (header, items) = validate_btrfs_leaf_fixture(&fixture_path("btrfs_leaf_node.json"))
        .expect("btrfs leaf fixture");
    assert_eq!(header.level, 0, "should be a leaf");
    assert!(items.len() >= 3, "should have at least 3 items");
    // Items should be sorted by key (objectid then type)
    for pair in items.windows(2) {
        let a = &pair[0].key;
        let b = &pair[1].key;
        assert!(
            (a.objectid, a.item_type) <= (b.objectid, b.item_type),
            "items should be sorted by key"
        );
    }
}

/// btrfs item type constants for fixture validation
mod btrfs_item_types {
    pub const INODE_ITEM: u8 = 1;
    pub const DIR_ITEM: u8 = 84;
    pub const DIR_INDEX: u8 = 96;
    pub const EXTENT_DATA: u8 = 108;
    pub const ROOT_ITEM: u8 = 132;
}

/// Validate the fs-tree leaf fixture (bd-2jk.2 deliverable).
///
/// This fixture contains the minimum item types needed to support btrfs
/// read-only operations: INODE_ITEM, DIR_ITEM, DIR_INDEX, EXTENT_DATA.
#[test]
fn btrfs_fstree_leaf_fixture_conforms() {
    let (header, items) = validate_btrfs_leaf_fixture(&fixture_path("btrfs_fstree_leaf.json"))
        .expect("btrfs fs-tree leaf fixture");

    // Verify header
    assert_eq!(header.level, 0, "should be a leaf");
    assert_eq!(header.owner, 5, "owner should be FS_TREE (5)");
    assert!(items.len() >= 5, "should have at least 5 items");

    // Verify items are sorted
    for pair in items.windows(2) {
        let a = &pair[0].key;
        let b = &pair[1].key;
        assert!(
            (a.objectid, a.item_type, a.offset) <= (b.objectid, b.item_type, b.offset),
            "items should be sorted by key: {a:?} vs {b:?}"
        );
    }

    // Verify required item types are present
    let has_inode = items
        .iter()
        .any(|i| i.key.item_type == btrfs_item_types::INODE_ITEM);
    let has_dir_item = items
        .iter()
        .any(|i| i.key.item_type == btrfs_item_types::DIR_ITEM);
    let has_dir_index = items
        .iter()
        .any(|i| i.key.item_type == btrfs_item_types::DIR_INDEX);
    let has_extent_data = items
        .iter()
        .any(|i| i.key.item_type == btrfs_item_types::EXTENT_DATA);

    assert!(has_inode, "fixture should contain INODE_ITEM (type 1)");
    assert!(has_dir_item, "fixture should contain DIR_ITEM (type 84)");
    assert!(has_dir_index, "fixture should contain DIR_INDEX (type 96)");
    assert!(
        has_extent_data,
        "fixture should contain EXTENT_DATA (type 108)"
    );
}

/// Validate the root-tree leaf fixture (bd-2jk.2 deliverable).
///
/// This fixture contains ROOT_ITEM entries for the core btrfs trees,
/// needed to bootstrap tree traversal from the superblock.
#[test]
fn btrfs_roottree_leaf_fixture_conforms() {
    let (header, items) = validate_btrfs_leaf_fixture(&fixture_path("btrfs_roottree_leaf.json"))
        .expect("btrfs root-tree leaf fixture");

    // Verify header
    assert_eq!(header.level, 0, "should be a leaf");
    assert_eq!(header.owner, 1, "owner should be ROOT_TREE (1)");
    assert!(items.len() >= 3, "should have at least 3 ROOT_ITEM entries");

    // Verify items are sorted
    for pair in items.windows(2) {
        let a = &pair[0].key;
        let b = &pair[1].key;
        assert!(
            (a.objectid, a.item_type, a.offset) <= (b.objectid, b.item_type, b.offset),
            "items should be sorted by key: {a:?} vs {b:?}"
        );
    }

    // All items should be ROOT_ITEM (type 132)
    for item in &items {
        assert_eq!(
            item.key.item_type,
            btrfs_item_types::ROOT_ITEM,
            "root tree should only contain ROOT_ITEM entries"
        );
    }

    // Should have entries for standard trees: EXTENT_TREE (2), CHUNK_TREE (3), FS_TREE (5)
    let tree_ids: Vec<u64> = items.iter().map(|i| i.key.objectid).collect();
    assert!(
        tree_ids.contains(&2),
        "should have ROOT_ITEM for EXTENT_TREE (2)"
    );
    assert!(
        tree_ids.contains(&3),
        "should have ROOT_ITEM for CHUNK_TREE (3)"
    );
    assert!(
        tree_ids.contains(&5),
        "should have ROOT_ITEM for FS_TREE (5)"
    );
}

#[test]
fn btrfs_devitem_fixture_conforms() {
    let devitem = ffs_harness::validate_btrfs_devitem_fixture(&fixture_path("btrfs_devitem.json"))
        .expect("btrfs devitem fixture");

    assert_eq!(devitem.devid, 1, "devid should be 1");
    assert_eq!(
        devitem.total_bytes,
        1024 * 1024 * 1024 * 1024,
        "total_bytes should be 1TB"
    );
    assert_eq!(
        devitem.bytes_used,
        512 * 1024 * 1024 * 1024,
        "bytes_used should be 512GB"
    );
    assert_eq!(devitem.sector_size, 4096, "sector_size should be 4096");
    assert_eq!(devitem.io_align, 4096, "io_align should be 4096");
    assert_eq!(devitem.io_width, 4096, "io_width should be 4096");
    assert_eq!(devitem.generation, 100, "generation should be 100");
    assert_eq!(
        devitem.start_offset,
        1024 * 1024,
        "start_offset should be 1MiB"
    );
    assert_eq!(devitem.dev_type, 0, "dev_type should be 0 (regular)");
}

#[test]
fn ext4_mmp_block_fixture_conforms() {
    let mmp = ffs_harness::validate_mmp_block_fixture(&fixture_path("ext4_mmp_block.json"))
        .expect("MMP block");

    assert_eq!(mmp.magic, 0x004D_4D50, "should have MMP magic");
    assert_eq!(mmp.seq, 0xFF4D_4D50, "should have clean seq");
    assert_eq!(mmp.time, 1700000000, "time should be 1700000000");
    assert_eq!(mmp.nodename, "ffs-node-01", "nodename should match");
    assert_eq!(mmp.bdevname, "/dev/nvme0n1", "bdevname should match");
    assert_eq!(mmp.check_interval, 5, "check_interval should be 5");

    // Verify status decoding
    assert_eq!(
        mmp.status(),
        ffs_ondisk::Ext4MmpStatus::Clean,
        "status should be Clean"
    );
}

#[test]
fn parity_report_totals_are_consistent() {
    let report = ParityReport::current();
    let implemented_sum: u32 = report.domains.iter().map(|d| d.implemented).sum();
    let total_sum: u32 = report.domains.iter().map(|d| d.total).sum();

    assert_eq!(implemented_sum, report.overall_implemented);
    assert_eq!(total_sum, report.overall_total);
}

#[test]
fn ext4_reference_image_opens_with_journal_replay_segments() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let image_path = workspace.join("conformance/golden/ext4_8mb_reference.ext4");

    if !image_path.exists() {
        println!(
            "Skipping test: golden image {} not found.",
            image_path.display()
        );
        return;
    }

    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, &image_path, &OpenOptions::default())
        .expect("open ext4 golden image with journal replay");
    let replay = fs
        .ext4_journal_replay()
        .expect("journal-enabled reference image should expose replay outcome");

    assert!(
        replay.stats.scanned_blocks > 0,
        "journal replay should scan at least one journal block"
    );
}

/// CI gate: verify that every fixture listed in checksums.sha256 exists,
/// is non-empty, and parses successfully. The actual SHA-256 comparison
/// is done by `scripts/verify_golden.sh` (which calls `sha256sum -c`).
#[test]
fn fixture_checksum_manifest_is_complete() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let checksums_path = workspace.join("conformance/fixtures/checksums.sha256");
    let checksums_text = std::fs::read_to_string(&checksums_path)
        .expect("read conformance/fixtures/checksums.sha256");

    let listed_files: Vec<&str> = checksums_text
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once("  ").map(|(_, f)| f))
        .collect();

    assert!(
        !listed_files.is_empty(),
        "checksums.sha256 should list fixture files"
    );

    let fixtures_dir = workspace.join("conformance/fixtures");
    for filename in &listed_files {
        let path = fixtures_dir.join(filename);
        let data = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("fixture {filename} missing or unreadable: {e}"));
        assert!(!data.is_empty(), "fixture {filename} should be non-empty");
    }

    // Verify all .json fixture files are listed in the manifest
    let actual_jsons: Vec<_> = std::fs::read_dir(&fixtures_dir)
        .expect("read fixtures dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    for json_file in &actual_jsons {
        assert!(
            listed_files.contains(&json_file.as_str()),
            "fixture {json_file} exists but is not listed in checksums.sha256"
        );
    }
}

/// CI gate: verify that every golden file listed in checksums.sha256 exists,
/// is non-empty, and that every golden JSON is present in the manifest.
#[test]
fn golden_checksum_manifest_is_complete() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let checksums_path = workspace.join("conformance/golden/checksums.sha256");
    let checksums_text =
        std::fs::read_to_string(&checksums_path).expect("read conformance/golden/checksums.sha256");

    let listed_files: Vec<&str> = checksums_text
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once("  ").map(|(_, f)| f))
        .collect();

    assert!(
        !listed_files.is_empty(),
        "checksums.sha256 should list golden files"
    );

    let golden_dir = workspace.join("conformance/golden");
    for filename in &listed_files {
        assert!(
            Path::new(filename)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json")),
            "golden checksum manifest should only track .json files: {filename}"
        );
        let path = golden_dir.join(filename);
        let data = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("golden {filename} missing or unreadable: {e}"));
        assert!(!data.is_empty(), "golden {filename} should be non-empty");
    }

    let mut actual_jsons: Vec<_> = std::fs::read_dir(&golden_dir)
        .expect("read golden dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    actual_jsons.sort();

    for json_file in &actual_jsons {
        assert!(
            listed_files.contains(&json_file.as_str()),
            "golden {json_file} exists but is not listed in checksums.sha256"
        );
    }
}

/// Full conformance gate pass (bd-2jk.14).
///
/// This is the single CI gate test that exercises every conformance
/// surface in one deterministic pass: all fixture parsers, checksum
/// manifests, golden references, fuzz corpus, and parity report.
/// Must complete in < 60 seconds.
#[test]
fn full_conformance_gate_pass() {
    let start = std::time::Instant::now();

    // 1) All fixture parsers + spot checks (21 total fixture JSONs).
    ext4_and_btrfs_fixtures_conform();
    ext4_group_desc_fixtures_conform();
    ext4_inode_fixtures_conform();
    ext4_dir_block_fixture_conforms();
    ext4_dir_block_with_tail_fixture_conforms();
    ext4_dir_block_deleted_entry_fixture_conforms();
    ext4_dir_block_truncated_tail_fixture_rejected();
    ext4_dir_block_checksum_stamp_and_verify_fixture_conforms();
    ext4_dir_block_checksum_detects_corruption();
    ext4_dir_block_rec_len_too_small_fixture_rejected();
    ext4_dir_block_name_len_overflow_fixture_rejected();
    ext4_dir_block_rec_len_min12_fixture_rejected();
    ext4_dir_block_rec_len_unaligned_fixture_rejected();
    ext4_dir_block_tail_padding_nonzero_fixture_rejected();
    ext4_dir_block_tail_bad_header_fixture_rejected();
    ext4_dir_block_casefold_lookup_conforms();
    ext4_fscrypt_nokey_readdir_and_lookup_preserve_raw_bytes();
    btrfs_send_stream_multi_command_conforms();
    btrfs_send_stream_unknown_command_preserves_attrs_as_unspec();
    btrfs_tree_log_replay_multilevel_conforms();
    btrfs_tree_log_replay_skips_when_log_root_absent();
    btrfs_chunk_tree_walk_adds_and_sorts_new_chunks();
    btrfs_multi_device_raid1_read_falls_back_to_second_mirror();
    btrfs_multi_device_raid0_dispatches_to_correct_stripe();
    btrfs_chunk_mapping_fixture_conforms();
    btrfs_leaf_fixture_conforms();
    btrfs_fstree_leaf_fixture_conforms();
    btrfs_roottree_leaf_fixture_conforms();
    btrfs_devitem_fixture_conforms();
    ext4_mmp_block_fixture_conforms();

    // 2) Checksum manifests are bidirectionally complete.
    fixture_checksum_manifest_is_complete();
    golden_checksum_manifest_is_complete();

    // 3) Goldens deserialize successfully and satisfy basic invariants.
    let workspace = workspace_root();
    validate_golden_jsons(workspace);

    // 4) Fuzz corpus is populated.
    assert_fuzz_corpus_populated(workspace);

    // 5) Parity report at 100%, internally consistent, and deterministic.
    assert_parity_report_100_percent();
    parity_report_totals_are_consistent();

    // 6) Time bound.
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 60,
        "conformance gate should complete in < 60s, took {elapsed:?}"
    );
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
}

fn validate_golden_jsons(workspace: &Path) {
    let golden_dir = workspace.join("conformance/golden");

    let ext4_golden_names = [
        "ext4_64mb_sparse_super.json",
        "ext4_htree_dirindex.json",
        "ext4_64mb_reference.json",
        "ext4_dir_index_reference.json",
        "ext4_8mb_reference.json",
    ];
    for name in &ext4_golden_names {
        let text = std::fs::read_to_string(golden_dir.join(name))
            .unwrap_or_else(|e| panic!("golden {name} unreadable: {e}"));
        let golden: GoldenReference =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("golden {name} invalid: {e}"));
        assert!(golden.version >= 1, "golden {name} version should be >= 1");
        assert!(
            !golden.source.is_empty(),
            "golden {name} source should be non-empty"
        );
    }

    let btrfs_golden_names = ["btrfs_small.json", "btrfs_medium.json", "btrfs_large.json"];
    for name in &btrfs_golden_names {
        let text = std::fs::read_to_string(golden_dir.join(name))
            .unwrap_or_else(|e| panic!("golden {name} unreadable: {e}"));
        let golden: Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("golden {name} invalid: {e}"));
        assert_eq!(
            golden.get("filesystem").and_then(Value::as_str),
            Some("btrfs"),
            "golden {name} filesystem should be btrfs"
        );
        for numeric in ["sectorsize", "nodesize", "generation"] {
            assert!(
                golden.get(numeric).and_then(Value::as_u64).is_some(),
                "golden {name} missing numeric field {numeric}"
            );
        }
        assert!(
            golden
                .get("label")
                .and_then(Value::as_str)
                .is_some_and(|label| !label.is_empty()),
            "golden {name} label should be non-empty"
        );
    }
}

fn assert_fuzz_corpus_populated(workspace: &Path) {
    let corpus_dir = workspace.join("tests/fuzz_corpus");
    let corpus_count = std::fs::read_dir(&corpus_dir)
        .expect("read fuzz_corpus dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "bin"))
        .count();
    assert!(
        corpus_count >= 50,
        "expected >= 50 fuzz corpus samples, found {corpus_count}"
    );
}

fn assert_parity_report_100_percent() {
    let report = ParityReport::current();
    assert_eq!(report.overall_implemented, report.overall_total);
    assert!(
        (report.overall_coverage_percent - 100.0).abs() < f64::EPSILON,
        "overall coverage should be 100%, got {}%",
        report.overall_coverage_percent
    );
    for domain in &report.domains {
        assert_eq!(
            domain.implemented, domain.total,
            "domain '{}' not at 100%: {}/{}",
            domain.domain, domain.implemented, domain.total
        );
    }

    // Deterministic: second run yields identical report.
    let report2 = ParityReport::current();
    assert_eq!(report.overall_implemented, report2.overall_implemented);
    assert_eq!(report.overall_total, report2.overall_total);
    assert_eq!(report.domains.len(), report2.domains.len());
}

#[test]
#[ignore = "stress integration; run explicitly with --ignored"]
fn crash_replay_suite_short_integration() {
    let config = CrashReplaySuiteConfig {
        schedule_count: 20,
        min_operations: 100,
        max_operations: 1000,
        base_seed: 0xFF5E_ED00_0000_0001,
        output_dir: None,
    };
    let report = run_crash_replay_suite(&config).expect("run crash replay suite");
    assert_eq!(report.schedule_count, config.schedule_count);
    assert_eq!(report.failed_schedules, 0);
    assert_eq!(report.passed_schedules, config.schedule_count);
}

#[test]
#[ignore = "stress integration; run explicitly with --ignored"]
fn fsx_stress_short_integration() {
    let config = FsxStressConfig {
        operation_count: 500,
        seed: 0xF5A5_7E55_0000_0001,
        max_file_size_bytes: 8 * 1024 * 1024,
        corruption_every_ops: 100,
        full_verify_every_ops: 100,
        output_dir: None,
    };
    let report = run_fsx_stress(&config).expect("run fsx stress");
    assert!(report.passed, "failure: {:#?}", report.failure);
    assert_eq!(report.operations_executed, config.operation_count);
    assert!(report.failure.is_none());
}
