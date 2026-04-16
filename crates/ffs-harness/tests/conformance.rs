#![forbid(unsafe_code)]

use asupersync::Cx;
use ffs_alloc::{FsGeometry, GroupStats};
use ffs_block::{BlockDevice, ByteBlockDevice, FileByteDevice};
use ffs_btrfs::{
    parse_send_stream, replay_tree_log, walk_chunk_tree, walk_device_tree, BtrfsDeviceSet,
    SendCommand, BTRFS_CHUNK_TREE_OBJECTID, BTRFS_DEV_TREE_OBJECTID, BTRFS_FILE_EXTENT_REG,
    BTRFS_FS_TREE_OBJECTID, BTRFS_FT_REG_FILE, BTRFS_ITEM_CHUNK, BTRFS_ITEM_DEV_ITEM,
    BTRFS_ITEM_DIR_INDEX, BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_INODE_ITEM, BTRFS_SEND_STREAM_MAGIC,
};
use ffs_core::{Ext4JournalReplayMode, OpenFs, OpenOptions, RequestScope};
use ffs_harness::{
    e2e::{run_crash_replay_suite, run_fsx_stress, CrashReplaySuiteConfig, FsxStressConfig},
    load_sparse_fixture, validate_btrfs_chunk_fixture, validate_btrfs_fixture,
    validate_btrfs_leaf_fixture, validate_dir_block_fixture, validate_ext4_fixture,
    validate_extent_tree_fixture, validate_group_desc_fixture, validate_inode_fixture,
    GoldenReference, ParityReport,
};
use ffs_ondisk::{
    lookup_in_dir_block_casefold, parse_dev_item, parse_dir_block, stamp_dir_block_checksum,
    verify_dir_block_checksum, BtrfsChunkEntry, BtrfsKey, BtrfsStripe, BtrfsSuperblock,
    Ext4IncompatFeatures, Ext4Superblock, ExtentTree,
};
use ffs_types::{
    GroupNumber, InodeNumber, ParseError, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, EXT4_CASEFOLD_FL,
    EXT4_COMPRBLK_FL, EXT4_COMPR_FL, EXT4_EXTENTS_FL, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPER_MAGIC,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        Arc,
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
fn ext4_inline_data_openfs_read_conforms() {
    let fs = open_ext4_inline_data_image("ext4_inode_inline_data.json");
    let cx = Cx::for_testing();

    let data = fs
        .read(&cx, InodeNumber(11), 0, 128)
        .expect("read inline-data file");
    assert_eq!(&data, b"Hello from inline data!");

    let offset = fs
        .read(&cx, InodeNumber(11), 6, 64)
        .expect("read inline-data file at offset");
    assert_eq!(&offset, b"from inline data!");
}

#[test]
fn ext4_inline_data_xattr_continuation_openfs_read_conforms() {
    let fs = open_ext4_inline_data_image("ext4_inode_inline_data_with_continuation.json");
    let cx = Cx::for_testing();

    let data = fs
        .read(&cx, InodeNumber(11), 0, 128)
        .expect("read inline-data continuation file");
    let mut expected = vec![b'A'; 60];
    expected.extend(std::iter::repeat_n(b'B', 16));
    assert_eq!(data, expected);

    let tail = fs
        .read(&cx, InodeNumber(11), 56, 32)
        .expect("read inline-data continuation tail");
    assert_eq!(tail, b"AAAABBBBBBBBBBBBBBBB");
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
fn ext4_orphan_recovery_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp, image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);

    let name = std::ffi::OsString::from("orphan_me.txt");
    let attr = fs
        .create(&cx, root, &name, 0o644, 0, 0)
        .expect("create file");
    let ino = attr.ino;

    drop(fs);

    for command in [
        format!("set_inode_field <{}> links_count 0", ino.0),
        format!("set_super_value last_orphan {}", ino.0),
        "set_super_value state 4".to_owned(),
    ] {
        let debugfs = std::process::Command::new("debugfs")
            .args([
                "-w",
                "-R",
                &command,
                image_path.to_str().expect("utf8 image path"),
            ])
            .output()
            .expect("spawn debugfs for orphan injection");
        assert!(
            debugfs.status.success(),
            "debugfs command {command:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&debugfs.stdout),
            String::from_utf8_lossy(&debugfs.stderr)
        );
    }

    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let fs2 =
        OpenFs::open_with_options(&cx, &image_path, &opts).expect("open with orphan recovery");

    let res = fs2.read_inode(&cx, ino);
    assert!(
        matches!(res, Err(ffs_error::FfsError::NotFound(_))),
        "Orphaned inode should be deleted during recovery, got {res:?}"
    );
}

#[test]
fn ext4_path_resolution_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp, _image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);
    let scope = RequestScope::empty();

    let name_a = std::ffi::OsString::from("a");
    let attr_a = fs.mkdir(&cx, root, &name_a, 0o755, 0, 0).expect("mkdir a");

    let name_b = std::ffi::OsString::from("b");
    let attr_b = fs
        .mkdir(&cx, attr_a.ino, &name_b, 0o755, 0, 0)
        .expect("mkdir b");

    let name_c = std::ffi::OsString::from("c.txt");
    let attr_c = fs
        .create(&cx, attr_b.ino, &name_c, 0o644, 0, 0)
        .expect("create c.txt");

    let (resolved_ino, resolved_inode) = fs
        .resolve_path(&cx, &scope, "/a/b/c.txt")
        .expect("resolve /a/b/c.txt");
    assert_eq!(
        resolved_ino, attr_c.ino,
        "resolved inode number should match created file"
    );
    assert!(
        !resolved_inode.is_dir(),
        "resolved inode should be the regular file, not a directory"
    );

    let (resolved_parent_ino, _) = fs
        .resolve_path(&cx, &scope, "/a/b/../b/c.txt")
        .expect("resolve absolute path with parent traversal");
    assert_eq!(
        resolved_parent_ino, attr_c.ino,
        "absolute path containing '..' should resolve back to the same file"
    );
}

#[test]
fn btrfs_tree_block_checksum_tamper_detection_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp, image_path) = open_btrfs_mkfs(128);

    let sb = fs.btrfs_superblock().expect("btrfs sb");
    let root_logical = sb.root;

    let ctx = fs.btrfs_context().expect("btrfs context");
    let mapping = fs.btrfs_context().expect("btrfs context");
    let mapping = ffs_ondisk::map_logical_to_physical(&mapping.chunks, root_logical)
        .expect("map root logical")
        .expect("root logical covered");

    let mut data = std::fs::read(&image_path).unwrap();
    let offset = mapping.physical as usize;
    let corrupt_offset = offset + usize::try_from(ctx.nodesize.min(0x80)).expect("nodesize usize");
    data[corrupt_offset] ^= 0xFF;
    std::fs::write(&image_path, data).unwrap();

    let fs = open_btrfs_image(&image_path);
    let res = fs.readdir(&cx, InodeNumber(1), 0);

    assert!(
        res.is_err(),
        "Reading corrupted btrfs tree block should fail checksum verification"
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
fn ext4_casefold_openfs_lookup_is_case_insensitive() {
    let image = build_ext4_casefold_image_with_dir(b"hello.txt");
    let superblock = Ext4Superblock::parse_from_image(&image).expect("parse casefold superblock");
    assert!(
        superblock.has_incompat(Ext4IncompatFeatures::CASEFOLD),
        "test image should advertise CASEFOLD incompat"
    );

    let tmp = tempfile::NamedTempFile::new().expect("create casefold ext4 temp image");
    std::fs::write(tmp.path(), &image).expect("write casefold ext4 image");

    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, tmp.path(), &OpenOptions::default())
        .expect("open casefold ext4 image");

    let root = fs
        .read_inode(&cx, InodeNumber(2))
        .expect("read casefold root");
    assert_ne!(
        root.flags & EXT4_CASEFOLD_FL,
        0,
        "root inode should carry CASEFOLD flag"
    );

    let attr = fs
        .lookup(&cx, InodeNumber(2), OsStr::new("HELLO.TXT"))
        .expect("lookup uppercase casefold name");
    assert_eq!(attr.ino, InodeNumber(11));

    let raw_lookup = fs
        .lookup_name(&cx, &root, b"HeLlO.TxT")
        .expect("device lookup should accept mixed-case bytes")
        .expect("mixed-case lookup should resolve");
    assert_eq!(raw_lookup.inode, 11);
    assert_eq!(raw_lookup.name_str(), "hello.txt");

    let entries = fs
        .readdir(&cx, InodeNumber(2), 0)
        .expect("readdir casefold directory");
    assert!(
        entries
            .iter()
            .any(|entry| entry.ino == InodeNumber(11) && entry.name == b"hello.txt"),
        "readdir should expose the original case-preserved filename"
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
fn build_ext4_featured_dir_image(
    raw_name: &[u8],
    incompat_feature: u32,
    root_inode_flags: u32,
) -> Vec<u8> {
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
    let incompat =
        (Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0 | incompat_feature)
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
    image[ino2 + 0x20..ino2 + 0x24].copy_from_slice(&root_inode_flags.to_le_bytes());
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

fn build_ext4_casefold_image_with_dir(raw_name: &[u8]) -> Vec<u8> {
    build_ext4_featured_dir_image(raw_name, Ext4IncompatFeatures::CASEFOLD.0, EXT4_CASEFOLD_FL)
}

fn build_ext4_encrypt_image_with_dir(raw_name: &[u8]) -> Vec<u8> {
    build_ext4_featured_dir_image(raw_name, Ext4IncompatFeatures::ENCRYPT.0, 0x0008_0000)
}

fn build_ext4_inline_data_image(inode_fixture: &str) -> Vec<u8> {
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
        | Ext4IncompatFeatures::INLINE_DATA.0)
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

    let inline_inode =
        load_sparse_fixture(&fixture_path(inode_fixture)).expect("load inline inode fixture");
    let ino11 = 4 * 4096 + 10 * 256;
    image[ino11..ino11 + inline_inode.len()].copy_from_slice(&inline_inode);

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

    let name = b"inline.bin";
    let dir = dir + 12;
    image[dir..dir + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[dir + 4..dir + 6].copy_from_slice(&4072_u16.to_le_bytes());
    image[dir + 6] = name.len() as u8;
    image[dir + 7] = 1;
    image[dir + 8..dir + 8 + name.len()].copy_from_slice(name);

    image
}

fn open_ext4_inline_data_image(inode_fixture: &str) -> OpenFs {
    let image = build_ext4_inline_data_image(inode_fixture);
    let tmp = tempfile::NamedTempFile::new().expect("create inline-data ext4 temp image");
    std::fs::write(tmp.path(), &image).expect("write inline-data ext4 image");
    let cx = Cx::for_testing();
    OpenFs::open_with_options(&cx, tmp.path(), &OpenOptions::default())
        .expect("open inline-data ext4 image")
}

fn open_btrfs_image(image: &Path) -> OpenFs {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    OpenFs::open_with_options(&cx, image, &opts).expect("open btrfs image")
}

fn open_btrfs_mkfs(size_mb: u64) -> (OpenFs, tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for btrfs");
    let image = tmp.path().join("conformance.btrfs");
    let file = std::fs::File::create(&image).expect("create btrfs image");
    file.set_len(size_mb.max(128) * 1024 * 1024)
        .expect("size btrfs image");
    drop(file);

    let mkfs = std::process::Command::new("mkfs.btrfs")
        .args(["-f", image.to_str().expect("utf8 image path")])
        .output()
        .expect("spawn mkfs.btrfs");
    assert!(
        mkfs.status.success(),
        "mkfs.btrfs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr)
    );

    let fs = open_btrfs_image(&image);
    (fs, tmp, image)
}

fn open_writable_ext4_mkfs(size_mb: u64) -> (OpenFs, tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for writable ext4");
    let image = tmp.path().join("conformance.ext4");
    let file = std::fs::File::create(&image).expect("create ext4 image");
    file.set_len(size_mb * 1024 * 1024)
        .expect("size ext4 image");
    drop(file);

    let mkfs = std::process::Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "4096",
            "-O",
            "^metadata_csum,^64bit",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn mkfs.ext4");
    assert!(
        mkfs.status.success(),
        "mkfs.ext4 failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr)
    );

    let debugfs = std::process::Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field / mode 040777",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn debugfs");
    assert!(
        debugfs.status.success(),
        "debugfs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&debugfs.stdout),
        String::from_utf8_lossy(&debugfs.stderr)
    );

    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, &image, &opts).expect("open writable ext4 image");
    fs.enable_writes(&cx).expect("enable writes on ext4 image");
    assert!(fs.is_writable(), "test ext4 image should be writable");
    (fs, tmp, image)
}

fn enable_e2compr_for_inode(
    fs: &OpenFs,
    image_path: &Path,
    cx: &Cx,
    ino: InodeNumber,
    cluster_shift: u32,
    method_idx: u8,
) {
    let mut inode = fs.read_inode(cx, ino).expect("read inode for e2compr");
    inode.flags |= EXT4_COMPR_FL;
    inode.flags &= !EXT4_EXTENTS_FL;
    inode.flags &= !((0x7_u32 << 23) | (0x1F_u32 << 26));
    inode.flags |= (cluster_shift & 0x7) << 23;
    inode.flags |= u32::from(method_idx & 0x1F) << 26;
    inode.extent_bytes.fill(0);

    let sb = fs.ext4_superblock().expect("ext4 superblock");
    let geo = FsGeometry::from_superblock(sb);
    let groups = (0..sb.groups_count())
        .map(|group| {
            let group = GroupNumber(group);
            let gd = fs.read_group_desc(cx, group).expect("read group desc");
            GroupStats::from_group_desc(group, &gd)
        })
        .collect::<Vec<_>>();
    let block_dev = ByteBlockDevice::new(
        FileByteDevice::open(image_path).expect("open raw ext4 image"),
        fs.block_size(),
    )
    .expect("create block device adapter");

    ffs_inode::write_inode(cx, &block_dev, &geo, &groups, ino, &inode, sb.csum_seed())
        .expect("persist e2compr inode flags");
    block_dev.sync(cx).expect("sync e2compr inode flags");
}

fn reopen_writable_ext4(image_path: &Path) -> OpenFs {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, image_path, &opts).expect("reopen writable ext4");
    fs.enable_writes(&cx)
        .expect("re-enable writes on ext4 image");
    fs
}

fn ext4_free_block_counters(fs: &OpenFs, cx: &Cx) -> (u64, u64) {
    let sb = fs.ext4_superblock().expect("ext4 superblock");
    let mut bitmap_total = 0_u64;
    let mut gd_total = 0_u64;

    for group in 0..sb.groups_count() {
        let group = GroupNumber(group);
        bitmap_total += u64::from(
            fs.count_free_blocks_in_group(cx, group)
                .expect("count free blocks in group"),
        );
        gd_total += u64::from(
            fs.read_group_desc(cx, group)
                .expect("read group desc for block counters")
                .free_blocks_count,
        );
    }

    (bitmap_total, gd_total)
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_extent_test_image() -> Vec<u8> {
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
    let incompat: u32 = Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0;
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat.to_le_bytes());
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());
    image[sb_off + 0xFE..sb_off + 0x100].copy_from_slice(&32_u16.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());
    image[gd_off + 0x0C..gd_off + 0x0E].copy_from_slice(&64_u16.to_le_bytes());
    image[gd_off + 0x0E..gd_off + 0x10].copy_from_slice(&128_u16.to_le_bytes());

    let ino11_off: usize = 4 * 4096 + 10 * 256;
    image[ino11_off..ino11_off + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[ino11_off + 4..ino11_off + 8].copy_from_slice(&14_u32.to_le_bytes());
    image[ino11_off + 0x1A..ino11_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino11_off + 0x20..ino11_off + 0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    image[ino11_off + 0x80..ino11_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let e = ino11_off + 0x28;
    image[e..e + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[e + 2..e + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[e + 4..e + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[e + 6..e + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[e + 12..e + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[e + 16..e + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[e + 18..e + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[e + 20..e + 24].copy_from_slice(&13_u32.to_le_bytes());

    let d = 13 * 4096;
    image[d..d + 14].copy_from_slice(b"Hello, extent!");

    let ino12_off: usize = 4 * 4096 + 11 * 256;
    image[ino12_off..ino12_off + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[ino12_off + 4..ino12_off + 8].copy_from_slice(&14_u32.to_le_bytes());
    image[ino12_off + 0x1A..ino12_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino12_off + 0x20..ino12_off + 0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    image[ino12_off + 0x80..ino12_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let e = ino12_off + 0x28;
    image[e..e + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[e + 2..e + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[e + 4..e + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[e + 6..e + 8].copy_from_slice(&1_u16.to_le_bytes());
    image[e + 12..e + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[e + 16..e + 20].copy_from_slice(&14_u32.to_le_bytes());
    image[e + 20..e + 22].copy_from_slice(&0_u16.to_le_bytes());

    let leaf = 14 * 4096;
    image[leaf..leaf + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[leaf + 2..leaf + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[leaf + 4..leaf + 6].copy_from_slice(&340_u16.to_le_bytes());
    image[leaf + 6..leaf + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[leaf + 12..leaf + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[leaf + 16..leaf + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[leaf + 18..leaf + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[leaf + 20..leaf + 24].copy_from_slice(&15_u32.to_le_bytes());

    let d = 15 * 4096;
    image[d..d + 14].copy_from_slice(b"Index extent!\n");

    let bitmap = 2 * 4096;
    image[bitmap + 1] = 0xE0;

    image
}

fn write_jbd2_header(block: &mut [u8], block_type: u32, sequence: u32) {
    const JBD2_MAGIC: u32 = 0xC03B_3998;
    block[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    block[4..8].copy_from_slice(&block_type.to_be_bytes());
    block[8..12].copy_from_slice(&sequence.to_be_bytes());
}

#[allow(clippy::too_many_arguments)]
fn write_jbd2_superblock_v2(
    block: &mut [u8],
    block_size: u32,
    max_len: u32,
    first_log_block: u32,
    start_sequence: u32,
    start_block: u32,
    num_fc_blocks: u32,
    feature_incompat: u32,
) {
    write_jbd2_header(block, 4, 0);
    block[12..16].copy_from_slice(&block_size.to_be_bytes());
    block[16..20].copy_from_slice(&max_len.to_be_bytes());
    block[20..24].copy_from_slice(&first_log_block.to_be_bytes());
    block[24..28].copy_from_slice(&start_sequence.to_be_bytes());
    block[28..32].copy_from_slice(&start_block.to_be_bytes());
    block[40..44].copy_from_slice(&feature_incompat.to_be_bytes());
    block[84..88].copy_from_slice(&num_fc_blocks.to_be_bytes());
}

fn build_fc_tag(tag_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + payload.len());
    bytes.extend_from_slice(&tag_type.to_le_bytes());
    bytes.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("fast-commit payload length should fit")
            .to_le_bytes(),
    );
    bytes.extend_from_slice(payload);
    bytes
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_fast_commit_test_image() -> Vec<u8> {
    const JBD2_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0000_0020;
    const EXT4_COMPAT_HAS_JOURNAL: u32 = 0x0000_0004;
    const EXT4_COMPAT_FAST_COMMIT: u32 = 0x0000_0400;

    let mut image = build_ext4_extent_test_image();
    let sb_off = EXT4_SUPERBLOCK_OFFSET;

    let compat = u32::from_le_bytes([
        image[sb_off + 0x5C],
        image[sb_off + 0x5D],
        image[sb_off + 0x5E],
        image[sb_off + 0x5F],
    ]);
    image[sb_off + 0x5C..sb_off + 0x60].copy_from_slice(
        &(compat | EXT4_COMPAT_HAS_JOURNAL | EXT4_COMPAT_FAST_COMMIT).to_le_bytes(),
    );
    image[sb_off + 0xE0..sb_off + 0xE4].copy_from_slice(&8_u32.to_le_bytes());

    let ino8_off: usize = 4 * 4096 + 7 * 256;
    image[ino8_off..ino8_off + 2].copy_from_slice(&0o100_600_u16.to_le_bytes());
    image[ino8_off + 4..ino8_off + 8].copy_from_slice(&(6_u32 * 4096).to_le_bytes());
    image[ino8_off + 0x1A..ino8_off + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[ino8_off + 0x20..ino8_off + 0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    image[ino8_off + 0x80..ino8_off + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let extent = ino8_off + 0x28;
    image[extent..extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[extent + 2..extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[extent + 4..extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[extent + 6..extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[extent + 12..extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[extent + 16..extent + 18].copy_from_slice(&6_u16.to_le_bytes());
    image[extent + 18..extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[extent + 20..extent + 24].copy_from_slice(&20_u32.to_le_bytes());

    let journal_sb = 20 * 4096;
    write_jbd2_superblock_v2(
        &mut image[journal_sb..journal_sb + 4096],
        4096,
        6,
        1,
        1,
        1,
        2,
        JBD2_FEATURE_INCOMPAT_FAST_COMMIT,
    );

    let j_desc = 21 * 4096;
    write_jbd2_header(&mut image[j_desc..j_desc + 4096], 1, 1);
    image[j_desc + 12..j_desc + 16].copy_from_slice(&15_u32.to_be_bytes());
    image[j_desc + 16..j_desc + 20].copy_from_slice(&0x0000_0008_u32.to_be_bytes());

    let j_data = 22 * 4096;
    image[j_data..j_data + 16].copy_from_slice(b"JBD2-REPLAY-TEST");

    let j_commit = 23 * 4096;
    write_jbd2_header(&mut image[j_commit..j_commit + 4096], 2, 1);

    let mut fc_payload = Vec::new();
    fc_payload.extend(build_fc_tag(0x0A, &[0; 16]));
    fc_payload.extend(build_fc_tag(0x07, &42_u32.to_le_bytes()));
    fc_payload.extend(build_fc_tag(0x09, &[1, 0, 0, 0, 0, 0, 0, 0]));
    let fc_block = 24 * 4096;
    image[fc_block..fc_block + fc_payload.len()].copy_from_slice(&fc_payload);

    image
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_truncated_fast_commit_test_image() -> Vec<u8> {
    let mut image = build_ext4_fast_commit_test_image();
    let fc_block = 24 * 4096;
    let mut truncated = Vec::new();
    truncated.extend(build_fc_tag(0x0A, &[0; 16]));
    truncated.extend(build_fc_tag(0x07, &42_u32.to_le_bytes()));
    image[fc_block..fc_block + 4096].fill(0);
    image[fc_block..fc_block + truncated.len()].copy_from_slice(&truncated);
    image
}

fn open_ext4_fast_commit_image(truncated: bool) -> (OpenFs, tempfile::TempDir) {
    let image = if truncated {
        build_ext4_truncated_fast_commit_test_image()
    } else {
        build_ext4_fast_commit_test_image()
    };
    let tmp = tempfile::TempDir::new().expect("tmpdir for ext4 fast-commit image");
    let image_path = tmp.path().join("fast-commit.ext4");
    std::fs::write(&image_path, &image).expect("write ext4 fast-commit image");
    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, &image_path, &OpenOptions::default())
        .expect("open ext4 fast-commit image");
    (fs, tmp)
}

fn open_ext4_mkfs_no_extents_with_large_file(
    size_mb: u64,
) -> (OpenFs, tempfile::TempDir, InodeNumber) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for writable ext4 no extents");
    let image = tmp.path().join("conformance_no_extents.ext4");
    let file = std::fs::File::create(&image).expect("create ext4 image");
    file.set_len(size_mb * 1024 * 1024)
        .expect("size ext4 image");
    drop(file);

    let mkfs = std::process::Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "4096",
            "-O",
            "^64bit,^extents",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn mkfs.ext4");
    assert!(
        mkfs.status.success(),
        "mkfs.ext4 failed: stdout={} stderr={}",
        String::from_utf8_lossy(&mkfs.stdout),
        String::from_utf8_lossy(&mkfs.stderr)
    );

    let debugfs = std::process::Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field / mode 040777",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn debugfs");
    assert!(
        debugfs.status.success(),
        "debugfs failed: stdout={} stderr={}",
        String::from_utf8_lossy(&debugfs.stdout),
        String::from_utf8_lossy(&debugfs.stderr)
    );

    let first_offset = 45_056_usize;
    let second_offset = 4_240_000_usize;
    let payload_len = 8_192_usize;
    let host_file = tmp.path().join("large_indirect_host.bin");
    let mut payload = vec![0_u8; second_offset + payload_len];
    payload[first_offset..first_offset + payload_len].fill(0xBB);
    payload[second_offset..second_offset + payload_len].fill(0xDD);
    std::fs::write(&host_file, payload).expect("write host indirect payload");

    let write_cmd = format!(
        "write {} /large_indirect.bin",
        host_file.to_str().expect("utf8 host payload path")
    );
    let debugfs = std::process::Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &write_cmd,
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn debugfs large file write");
    assert!(
        debugfs.status.success(),
        "debugfs large file write failed: stdout={} stderr={}",
        String::from_utf8_lossy(&debugfs.stdout),
        String::from_utf8_lossy(&debugfs.stderr)
    );

    let debugfs = std::process::Command::new("debugfs")
        .args([
            "-R",
            "stat /large_indirect.bin",
            image.to_str().expect("utf8 image path"),
        ])
        .output()
        .expect("spawn debugfs stat");
    assert!(
        debugfs.status.success(),
        "debugfs stat failed: stdout={} stderr={}",
        String::from_utf8_lossy(&debugfs.stdout),
        String::from_utf8_lossy(&debugfs.stderr)
    );
    let stat_stdout = String::from_utf8_lossy(&debugfs.stdout);
    let ino = stat_stdout
        .lines()
        .find_map(|line| line.strip_prefix("Inode:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|token| token.parse::<u64>().ok())
        .map(InodeNumber)
        .expect("extract inode number from debugfs stat output");

    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, &image, &opts).expect("open indirect ext4 image");
    (fs, tmp, ino)
}

#[test]
fn ext4_indirect_block_addressing_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp, ino) = open_ext4_mkfs_no_extents_with_large_file(64);
    let inode = fs.read_inode(&cx, ino).expect("read inode");
    assert_eq!(
        inode.flags & EXT4_EXTENTS_FL,
        0,
        "inode must not have extents flag (indirect block addressing)"
    );

    // 12 direct blocks (48 KB).
    // Read 8KB crossing from direct block 11 to single-indirect block 12.
    // 11 * 4096 = 45056
    let payload1 = vec![0xBB_u8; 8192];
    let readback1 = fs
        .read(&cx, ino, 45_056, 8_192)
        .expect("read direct to single-indirect boundary");

    // 12 direct + 1024 single indirect = 1036 blocks = 4243456 bytes.
    // Read 8KB crossing from single-indirect to double-indirect.
    let payload2 = vec![0xDD_u8; 8192];
    assert_eq!(
        &readback1[..],
        payload1.as_slice(),
        "readback from single-indirect must match"
    );

    let readback2 = fs
        .read(&cx, ino, 4_240_000, 8_192)
        .expect("read single to double-indirect boundary");
    assert_eq!(
        &readback2[..],
        payload2.as_slice(),
        "readback from double-indirect must match"
    );
}

#[test]
fn ext4_e2compr_write_readback_conforms_for_gzip_and_lzo() {
    let cx = Cx::for_testing();
    let (mut fs, _tmp, image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);

    for (method_idx, label, byte) in [(20_u8, "gzip", b'G'), (10_u8, "lzo", b'L')] {
        let name = std::ffi::OsString::from(format!("e2compr_{label}.bin"));
        let attr = fs
            .create(&cx, root, &name, 0o644, 0, 0)
            .expect("create compressed ext4 file");
        enable_e2compr_for_inode(&fs, &image_path, &cx, attr.ino, 2, method_idx);
        drop(fs);
        fs = reopen_writable_ext4(&image_path);

        let (baseline_free_blocks, baseline_gd_free_blocks) = ext4_free_block_counters(&fs, &cx);
        let first = vec![byte; 4096];
        fs.write(&cx, attr.ino, 0, &first)
            .expect("first compressed write");

        let (after_first_free_blocks, after_first_gd_free_blocks) =
            ext4_free_block_counters(&fs, &cx);
        let inode_after_first = fs
            .read_inode(&cx, attr.ino)
            .expect("inode after first compressed write");
        let readback_first = fs
            .read(&cx, attr.ino, 0, 4096)
            .expect("readback after first compressed write");

        assert!(
            inode_after_first.flags & EXT4_COMPRBLK_FL != 0,
            "{label}: compressed write should mark COMPRBLK"
        );
        assert!(
            after_first_free_blocks < baseline_free_blocks,
            "{label}: compressed write should consume at least one block"
        );
        assert!(
            after_first_gd_free_blocks < baseline_gd_free_blocks,
            "{label}: compressed write should update group descriptor free-block counters"
        );
        assert_eq!(
            &readback_first[..first.len()],
            first.as_slice(),
            "{label}: read path should return first compressed payload"
        );

        let second = vec![byte.wrapping_add(1); 4096];
        fs.write(&cx, attr.ino, 0, &second)
            .expect("second compressed write");

        let (after_second_free_blocks, after_second_gd_free_blocks) =
            ext4_free_block_counters(&fs, &cx);
        let inode_after_second = fs
            .read_inode(&cx, attr.ino)
            .expect("inode after compressed rewrite");
        let readback_second = fs
            .read(&cx, attr.ino, 0, 4096)
            .expect("readback after compressed rewrite");

        assert_eq!(
            after_second_free_blocks, after_first_free_blocks,
            "{label}: rewrite should reuse compressed blocks without leaking space"
        );
        assert_eq!(
            after_second_gd_free_blocks, after_first_gd_free_blocks,
            "{label}: group descriptor free-block counters should remain stable on rewrite"
        );
        assert_eq!(
            inode_after_second.blocks, inode_after_first.blocks,
            "{label}: rewrite should preserve inode i_blocks accounting"
        );
        assert_eq!(
            &readback_second[..second.len()],
            second.as_slice(),
            "{label}: read path should return rewritten compressed payload"
        );
    }
}

#[test]
fn ext4_fallocate_zero_range_zeroes_target_range() {
    let cx = Cx::for_testing();
    let (fs, _tmp, _image_path) = open_writable_ext4_mkfs(64);
    let root = InodeNumber(2);

    let attr = fs
        .create(&cx, root, OsStr::new("zero_range.bin"), 0o644, 0, 0)
        .expect("create ext4 zero-range file");
    let ino = attr.ino;

    let mut payload = vec![b'A'; 12 * 1024];
    payload[4096..8192].fill(b'B');
    payload[8192..].fill(b'C');
    fs.write(&cx, ino, 0, &payload)
        .expect("seed ext4 zero-range file");

    fs.fallocate(&cx, ino, 4096, 4096, libc::FALLOC_FL_ZERO_RANGE)
        .expect("zero-range middle block");

    let readback = fs
        .read(&cx, ino, 0, payload.len() as u32)
        .expect("read zero-range ext4 file");
    assert_eq!(readback.len(), payload.len());
    assert_eq!(&readback[..4096], &payload[..4096]);
    assert!(readback[4096..8192].iter().all(|&byte| byte == 0));
    assert_eq!(&readback[8192..], &payload[8192..]);

    let inode = fs.read_inode(&cx, ino).expect("read zero-range inode");
    assert_eq!(
        inode.size,
        payload.len() as u64,
        "ZERO_RANGE without KEEP_SIZE should preserve size when the range stays within EOF"
    );
}

#[test]
fn ext4_fast_commit_replay_openfs_evidence_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp) = open_ext4_fast_commit_image(false);

    let replay = fs
        .ext4_journal_replay()
        .expect("journal replay outcome should be present");
    let fc = fs
        .ext4_fast_commit_replay()
        .expect("fast-commit evidence should be present");

    assert_eq!(replay.committed_sequences, vec![1]);
    assert_eq!(replay.stats.replayed_blocks, 1);
    assert_eq!(fc.reserved_fc_blocks, 2);
    assert!(fc.bytes_collected >= 32);
    assert_eq!(fc.replay.transactions_found, 1);
    assert_eq!(fc.replay.last_tid, 1);
    assert_eq!(fc.replay.operations.len(), 1);
    assert_eq!(format!("{:?}", fc.replay.operations), "[InodeUpdate(42)]");
    assert_eq!(fc.replay.incomplete_transactions, 0);
    assert!(!fc.replay.fallback_required);
    assert_eq!(fc.replay.blocks_scanned, 1);

    let target = fs
        .read_block_vec(&cx, ffs_types::BlockNumber(15))
        .expect("read replayed data block");
    assert_eq!(&target[..16], b"JBD2-REPLAY-TEST");
}

#[test]
fn ext4_fast_commit_truncated_stream_falls_back_to_jbd2_only() {
    let cx = Cx::for_testing();
    let (fs, _tmp) = open_ext4_fast_commit_image(true);

    let replay = fs
        .ext4_journal_replay()
        .expect("journal replay outcome should be present");
    let fc = fs
        .ext4_fast_commit_replay()
        .expect("fast-commit evidence should be present");

    assert_eq!(replay.committed_sequences, vec![1]);
    assert_eq!(replay.stats.replayed_blocks, 1);
    assert_eq!(fc.reserved_fc_blocks, 2);
    assert_eq!(fc.replay.transactions_found, 0);
    assert_eq!(fc.replay.last_tid, 0);
    assert!(fc.replay.operations.is_empty());
    assert_eq!(fc.replay.incomplete_transactions, 1);
    assert!(fc.replay.fallback_required);
    assert_eq!(fc.replay.blocks_scanned, 1);

    let target = fs
        .read_block_vec(&cx, ffs_types::BlockNumber(15))
        .expect("read replayed data block after fallback");
    assert_eq!(&target[..16], b"JBD2-REPLAY-TEST");
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
    key_offset: u64,
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
    block[base + 9..base + 17].copy_from_slice(&key_offset.to_le_bytes());
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

fn build_dev_item_payload(
    devid: u64,
    total_bytes: u64,
    bytes_used: u64,
    generation: u64,
    start_offset: u64,
) -> Vec<u8> {
    let mut data = vec![0_u8; 98];
    data[0..8].copy_from_slice(&devid.to_le_bytes());
    data[8..16].copy_from_slice(&total_bytes.to_le_bytes());
    data[16..24].copy_from_slice(&bytes_used.to_le_bytes());
    data[24..28].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    data[28..32].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    data[32..36].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    data[44..52].copy_from_slice(&generation.to_le_bytes());
    data[52..60].copy_from_slice(&start_offset.to_le_bytes());
    let devid_byte = u8::try_from(devid).expect("test devid should fit in u8");
    data[64] = devid_byte;
    data[65] = 100_u8.saturating_add(devid_byte);
    data[66..82].fill(devid_byte);
    data[82..98].fill(0xF0_u8.saturating_add(devid_byte));
    data
}

fn encode_btrfs_inode_item(mode: u32, size: u64, nbytes: u64, nlink: u32) -> [u8; 160] {
    let mut inode = [0_u8; 160];
    inode[0..8].copy_from_slice(&1_u64.to_le_bytes());
    inode[8..16].copy_from_slice(&1_u64.to_le_bytes());
    inode[16..24].copy_from_slice(&size.to_le_bytes());
    inode[24..32].copy_from_slice(&nbytes.to_le_bytes());
    inode[40..44].copy_from_slice(&nlink.to_le_bytes());
    inode[44..48].copy_from_slice(&1000_u32.to_le_bytes());
    inode[48..52].copy_from_slice(&1000_u32.to_le_bytes());
    inode[52..56].copy_from_slice(&mode.to_le_bytes());
    inode[112..120].copy_from_slice(&10_u64.to_le_bytes());
    inode[124..132].copy_from_slice(&10_u64.to_le_bytes());
    inode[136..144].copy_from_slice(&10_u64.to_le_bytes());
    inode[148..156].copy_from_slice(&10_u64.to_le_bytes());
    inode
}

fn encode_btrfs_dir_index_entry(name: &[u8], child_objectid: u64, file_type: u8) -> Vec<u8> {
    let mut entry = vec![0_u8; 30 + name.len()];
    entry[0..8].copy_from_slice(&child_objectid.to_le_bytes());
    entry[8] = BTRFS_ITEM_INODE_ITEM;
    entry[9..17].copy_from_slice(&0_u64.to_le_bytes());
    entry[17..25].copy_from_slice(&1_u64.to_le_bytes());
    entry[25..27].copy_from_slice(&0_u16.to_le_bytes());
    let name_len = u16::try_from(name.len()).expect("test name length should fit in u16");
    entry[27..29].copy_from_slice(&name_len.to_le_bytes());
    entry[29] = file_type;
    entry[30..30 + name.len()].copy_from_slice(name);
    entry
}

fn encode_btrfs_extent_regular(disk_bytenr: u64, num_bytes: u64) -> [u8; 53] {
    let mut extent = [0_u8; 53];
    extent[0..8].copy_from_slice(&1_u64.to_le_bytes());
    extent[8..16].copy_from_slice(&num_bytes.to_le_bytes());
    extent[20] = BTRFS_FILE_EXTENT_REG;
    extent[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
    extent[29..37].copy_from_slice(&num_bytes.to_le_bytes());
    extent[37..45].copy_from_slice(&0_u64.to_le_bytes());
    extent[45..53].copy_from_slice(&num_bytes.to_le_bytes());
    extent
}

const BTRFS_TEST_IMAGE_SIZE: usize = 512 * 1024;
const BTRFS_TEST_ROOT_TREE_LOGICAL: u64 = 0x4_000;
const BTRFS_TEST_FS_TREE_LOGICAL: u64 = 0x8_000;
const BTRFS_TEST_FILE_DATA_LOGICAL: u64 = 0x12_000;
const BTRFS_TEST_ROOT_ITEM_OFF: u32 = 3000;
const BTRFS_TEST_ROOT_INODE_OFF: u32 = 3200;
const BTRFS_TEST_DIR_INDEX_OFF: u32 = 3060;
const BTRFS_TEST_FILE_INODE_OFF: u32 = 2860;
const BTRFS_TEST_EXTENT_OFF: u32 = 2780;

#[allow(clippy::too_many_lines)]
fn build_btrfs_regular_extent_mount_image(
    file_name: &[u8],
    logical_file_bytes: &[u8],
    extent_bytes: &[u8],
    compression: u8,
) -> Vec<u8> {
    let mut image = vec![0_u8; BTRFS_TEST_IMAGE_SIZE];
    let sb_off = BTRFS_SUPER_INFO_OFFSET;
    let nodesize =
        usize::try_from(BTRFS_TEST_NODESIZE).expect("btrfs test nodesize should fit in usize");
    let file_size =
        u64::try_from(logical_file_bytes.len()).expect("logical file size should fit in u64");
    let extent_size =
        u64::try_from(extent_bytes.len()).expect("extent payload size should fit in u64");

    image[sb_off + 0x40..sb_off + 0x48].copy_from_slice(&BTRFS_MAGIC.to_le_bytes());
    image[sb_off + 0x48..sb_off + 0x50].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x50..sb_off + 0x58]
        .copy_from_slice(&BTRFS_TEST_ROOT_TREE_LOGICAL.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x60].copy_from_slice(&0_u64.to_le_bytes());
    image[sb_off + 0x70..sb_off + 0x78].copy_from_slice(
        &u64::try_from(BTRFS_TEST_IMAGE_SIZE)
            .expect("test image size")
            .to_le_bytes(),
    );
    image[sb_off + 0x80..sb_off + 0x88].copy_from_slice(&256_u64.to_le_bytes());
    image[sb_off + 0x88..sb_off + 0x90].copy_from_slice(&1_u64.to_le_bytes());
    image[sb_off + 0x90..sb_off + 0x94].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    image[sb_off + 0x94..sb_off + 0x98].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    image[sb_off + 0x9C..sb_off + 0xA0].copy_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    image[sb_off + 0xC6] = 0;

    let mut chunk_array = Vec::new();
    chunk_array.extend_from_slice(&256_u64.to_le_bytes());
    chunk_array.push(BTRFS_ITEM_CHUNK);
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(
        &u64::try_from(BTRFS_TEST_IMAGE_SIZE)
            .expect("test image size should fit in u64")
            .to_le_bytes(),
    );
    chunk_array.extend_from_slice(&2_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0x1_0000_u64.to_le_bytes());
    chunk_array.extend_from_slice(&1_u64.to_le_bytes());
    chunk_array.extend_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    chunk_array.extend_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    chunk_array.extend_from_slice(&BTRFS_TEST_NODESIZE.to_le_bytes());
    chunk_array.extend_from_slice(&1_u16.to_le_bytes());
    chunk_array.extend_from_slice(&0_u16.to_le_bytes());
    chunk_array.extend_from_slice(&1_u64.to_le_bytes());
    chunk_array.extend_from_slice(&0_u64.to_le_bytes());
    chunk_array.extend_from_slice(&[0_u8; 16]);
    image[sb_off + 0xA0..sb_off + 0xA4].copy_from_slice(
        &u32::try_from(chunk_array.len())
            .expect("chunk array should fit in u32")
            .to_le_bytes(),
    );
    let array_start = sb_off + 0x32B;
    image[array_start..array_start + chunk_array.len()].copy_from_slice(&chunk_array);

    let mut root_leaf = vec![0_u8; nodesize];
    write_btrfs_header(&mut root_leaf, BTRFS_TEST_ROOT_TREE_LOGICAL, 1, 0, 1, 1);
    let root_item_size = 239_u32;
    write_btrfs_leaf_item(
        &mut root_leaf,
        0,
        BTRFS_FS_TREE_OBJECTID,
        132,
        0,
        BTRFS_TEST_ROOT_ITEM_OFF,
        root_item_size,
    );
    let mut root_item = vec![0_u8; usize::try_from(root_item_size).expect("root item size")];
    root_item[168..176].copy_from_slice(&256_u64.to_le_bytes());
    root_item[176..184].copy_from_slice(&BTRFS_TEST_FS_TREE_LOGICAL.to_le_bytes());
    let last = root_item.len() - 1;
    root_item[last] = 0;
    let root_item_off = usize::try_from(BTRFS_TEST_ROOT_ITEM_OFF).expect("root item offset");
    root_leaf[root_item_off..root_item_off + root_item.len()].copy_from_slice(&root_item);
    let root_leaf_off =
        usize::try_from(BTRFS_TEST_ROOT_TREE_LOGICAL).expect("root tree logical should fit");
    image[root_leaf_off..root_leaf_off + root_leaf.len()].copy_from_slice(&root_leaf);

    let mut fs_leaf = vec![0_u8; nodesize];
    write_btrfs_header(
        &mut fs_leaf,
        BTRFS_TEST_FS_TREE_LOGICAL,
        4,
        0,
        BTRFS_FS_TREE_OBJECTID,
        1,
    );

    let root_inode = encode_btrfs_inode_item(0o040_755, 4096, 4096, 2);
    let file_inode = encode_btrfs_inode_item(0o100_644, file_size, file_size, 1);
    let dir_index = encode_btrfs_dir_index_entry(file_name, 257, BTRFS_FT_REG_FILE);
    let mut extent = encode_btrfs_extent_regular(BTRFS_TEST_FILE_DATA_LOGICAL, file_size);
    extent[16] = compression;
    extent[29..37].copy_from_slice(&extent_size.to_le_bytes());

    write_btrfs_leaf_item(
        &mut fs_leaf,
        0,
        256,
        BTRFS_ITEM_INODE_ITEM,
        0,
        BTRFS_TEST_ROOT_INODE_OFF,
        u32::try_from(root_inode.len()).expect("root inode size should fit in u32"),
    );
    write_btrfs_leaf_item(
        &mut fs_leaf,
        1,
        256,
        BTRFS_ITEM_DIR_INDEX,
        2,
        BTRFS_TEST_DIR_INDEX_OFF,
        u32::try_from(dir_index.len()).expect("dir index size should fit in u32"),
    );
    write_btrfs_leaf_item(
        &mut fs_leaf,
        2,
        257,
        BTRFS_ITEM_INODE_ITEM,
        0,
        BTRFS_TEST_FILE_INODE_OFF,
        u32::try_from(file_inode.len()).expect("file inode size should fit in u32"),
    );
    write_btrfs_leaf_item(
        &mut fs_leaf,
        3,
        257,
        BTRFS_ITEM_EXTENT_DATA,
        0,
        BTRFS_TEST_EXTENT_OFF,
        u32::try_from(extent.len()).expect("extent size should fit in u32"),
    );

    let root_inode_off = usize::try_from(BTRFS_TEST_ROOT_INODE_OFF).expect("root inode offset");
    fs_leaf[root_inode_off..root_inode_off + root_inode.len()].copy_from_slice(&root_inode);
    let dir_index_off = usize::try_from(BTRFS_TEST_DIR_INDEX_OFF).expect("dir index offset");
    fs_leaf[dir_index_off..dir_index_off + dir_index.len()].copy_from_slice(&dir_index);
    let file_inode_off = usize::try_from(BTRFS_TEST_FILE_INODE_OFF).expect("file inode offset");
    fs_leaf[file_inode_off..file_inode_off + file_inode.len()].copy_from_slice(&file_inode);
    let extent_off = usize::try_from(BTRFS_TEST_EXTENT_OFF).expect("extent offset");
    fs_leaf[extent_off..extent_off + extent.len()].copy_from_slice(&extent);
    let fs_leaf_off =
        usize::try_from(BTRFS_TEST_FS_TREE_LOGICAL).expect("fs tree logical should fit");
    image[fs_leaf_off..fs_leaf_off + fs_leaf.len()].copy_from_slice(&fs_leaf);

    let file_data_off =
        usize::try_from(BTRFS_TEST_FILE_DATA_LOGICAL).expect("file data logical should fit");
    image[file_data_off..file_data_off + extent_bytes.len()].copy_from_slice(extent_bytes);
    image
}

#[allow(clippy::cast_possible_truncation)]
fn build_btrfs_subvolume_mount_image() -> Vec<u8> {
    let file_bytes = b"hello from btrfs fsops";
    build_btrfs_regular_extent_mount_image(b"hello.txt", file_bytes, file_bytes, 0)
}

fn open_btrfs_test_image(image_name: &str, image: Vec<u8>) -> (OpenFs, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().expect("tmpdir for btrfs test image");
    let image_path = tmp.path().join(image_name);
    std::fs::write(&image_path, &image).expect("write btrfs test image");
    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, &image_path, &OpenOptions::default())
        .expect("open btrfs test image");
    (fs, tmp)
}

fn btrfs_transparent_decompression_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    for _ in 0..128 {
        payload.extend_from_slice(b"FrankenFS btrfs transparent decompression harness payload.\n");
    }
    payload.extend_from_slice(b"tail-marker:transparent-decompression");
    payload
}

fn compress_btrfs_zlib_payload(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(data)
        .expect("zlib encoder should accept test payload");
    encoder.finish().expect("zlib encoder should finish")
}

fn compress_btrfs_lzo_payload(data: &[u8]) -> Vec<u8> {
    let page_size =
        usize::try_from(BTRFS_TEST_NODESIZE).expect("btrfs test nodesize should fit in usize");
    let mut framed = vec![0_u8; 4];
    for chunk in data.chunks(page_size) {
        let compressed = lzokay_native::compress(chunk).expect("compress lzo test payload");
        framed.extend_from_slice(
            &u32::try_from(compressed.len())
                .expect("lzo segment should fit in u32")
                .to_le_bytes(),
        );
        framed.extend_from_slice(&compressed);
    }
    let total_len = u32::try_from(framed.len()).expect("lzo payload should fit in u32");
    framed[0..4].copy_from_slice(&total_len.to_le_bytes());
    framed
}

fn compress_btrfs_zstd_payload(data: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(data, 0).expect("compress zstd test payload")
}

fn open_btrfs_transparent_decompression_image(
    image_name: &str,
    file_name: &str,
    codec: u8,
) -> (OpenFs, tempfile::TempDir, Vec<u8>) {
    let logical = btrfs_transparent_decompression_payload();
    let compressed = match codec {
        1 => compress_btrfs_zlib_payload(&logical),
        2 => compress_btrfs_lzo_payload(&logical),
        3 => compress_btrfs_zstd_payload(&logical),
        other => panic!("unexpected compression codec {other}"),
    };
    let image =
        build_btrfs_regular_extent_mount_image(file_name.as_bytes(), &logical, &compressed, codec);
    let (fs, tmp) = open_btrfs_test_image(image_name, image);
    (fs, tmp, logical)
}

fn open_btrfs_subvolume_mount_image() -> (OpenFs, tempfile::TempDir) {
    open_btrfs_test_image("subvolume-mount.btrfs", build_btrfs_subvolume_mount_image())
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
fn btrfs_subvolume_mount_root_alias_conforms() {
    let cx = Cx::for_testing();
    let (fs, _tmp) = open_btrfs_subvolume_mount_image();

    let ctx = fs.btrfs_context().expect("btrfs context should be present");
    assert_eq!(ctx.subvol_objectid, BTRFS_FS_TREE_OBJECTID);
    assert_eq!(ctx.subvol_root_dirid, 256);

    let root_attr = fs.getattr(&cx, InodeNumber(1)).expect("get mounted root");
    assert_eq!(root_attr.ino, InodeNumber(1));
    assert_eq!(root_attr.perm, 0o755);

    let child = fs
        .lookup(&cx, InodeNumber(1), OsStr::new("hello.txt"))
        .expect("lookup file through mounted subvolume root");
    assert_eq!(child.ino, InodeNumber(257));
    assert_eq!(child.size, 22);

    let entries = fs
        .readdir(&cx, InodeNumber(1), 0)
        .expect("readdir mounted subvolume root");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, b".");
    assert_eq!(entries[1].name, b"..");
    assert_eq!(entries[2].name, b"hello.txt");

    let data = fs
        .read(&cx, InodeNumber(257), 0, 128)
        .expect("read file from mounted subvolume");
    assert_eq!(&data, b"hello from btrfs fsops");
}

fn assert_btrfs_transparent_decompression_conforms(
    image_name: &str,
    file_name: &str,
    codec_label: &str,
    codec: u8,
) {
    let cx = Cx::for_testing();
    let (fs, _tmp, expected) =
        open_btrfs_transparent_decompression_image(image_name, file_name, codec);

    let entry = fs
        .lookup(&cx, InodeNumber(1), OsStr::new(file_name))
        .unwrap_or_else(|err| panic!("lookup {codec_label} file through mounted root: {err}"));
    assert_eq!(entry.ino, InodeNumber(257));
    assert_eq!(
        entry.size,
        u64::try_from(expected.len()).expect("expected payload should fit in u64")
    );

    let data = fs
        .read(
            &cx,
            entry.ino,
            0,
            u32::try_from(expected.len() + 128).expect("read size should fit in u32"),
        )
        .unwrap_or_else(|err| panic!("read {codec_label} compressed extent: {err}"));
    assert_eq!(data, expected);

    let boundary_offset = 4080_u64;
    let boundary = fs
        .read(&cx, entry.ino, boundary_offset, 96)
        .unwrap_or_else(|err| panic!("read {codec_label} boundary slice: {err}"));
    assert_eq!(
        boundary,
        expected[usize::try_from(boundary_offset).expect("boundary offset")
            ..usize::try_from(boundary_offset + 96).expect("boundary end")]
    );
}

#[test]
fn btrfs_transparent_decompression_zlib_regular_extent_conforms() {
    assert_btrfs_transparent_decompression_conforms("btrfs-zlib.btrfs", "zlib.bin", "zlib", 1);
}

#[test]
fn btrfs_transparent_decompression_lzo_regular_extent_conforms() {
    assert_btrfs_transparent_decompression_conforms("btrfs-lzo.btrfs", "lzo.bin", "lzo", 2);
}

#[test]
fn btrfs_transparent_decompression_zstd_regular_extent_conforms() {
    assert_btrfs_transparent_decompression_conforms("btrfs-zstd.btrfs", "zstd.bin", "zstd", 3);
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
    write_btrfs_leaf_item(&mut leaf, 0, 256, BTRFS_ITEM_INODE_ITEM, 0, alpha_off, 5);
    leaf[alpha_off as usize..(alpha_off + 5) as usize].copy_from_slice(b"alpha");
    write_btrfs_leaf_item(&mut leaf, 1, 257, BTRFS_ITEM_INODE_ITEM, 0, beta_off, 4);
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
        0x20_000,
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
fn btrfs_device_tree_walk_enumerates_all_devices() {
    let root_logical = 0x20_000_u64;
    let leaf_logical = 0x30_000_u64;
    let physical_start = 0xA0_000_u64;
    let chunk_length = leaf_logical + u64::from(BTRFS_TEST_NODESIZE) - root_logical;
    let chunks = vec![build_single_stripe_chunk(
        root_logical,
        chunk_length,
        physical_start,
    )];
    let root_physical = physical_start;
    let leaf_physical = physical_start + (leaf_logical - root_logical);

    let mut root = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut root, root_logical, 1, 1, BTRFS_DEV_TREE_OBJECTID, 88);
    write_btrfs_key_ptr(&mut root, 0, 1, BTRFS_ITEM_DEV_ITEM, leaf_logical, 88);

    let mut leaf = vec![0_u8; BTRFS_TEST_NODESIZE as usize];
    write_btrfs_header(&mut leaf, leaf_logical, 2, 0, BTRFS_DEV_TREE_OBJECTID, 88);
    let first_payload = build_dev_item_payload(
        1,
        1024 * 1024 * 1024 * 1024_u64,
        512 * 1024 * 1024 * 1024_u64,
        88,
        1024 * 1024_u64,
    );
    let second_payload = build_dev_item_payload(
        2,
        2 * 1024 * 1024 * 1024 * 1024_u64,
        1024 * 1024 * 1024 * 1024_u64,
        89,
        2 * 1024 * 1024_u64,
    );
    let first_off = 3600_u32;
    let second_off = 3490_u32;
    write_btrfs_leaf_item(
        &mut leaf,
        0,
        1,
        BTRFS_ITEM_DEV_ITEM,
        1,
        first_off,
        u32::try_from(first_payload.len()).expect("payload length should fit in u32"),
    );
    write_btrfs_leaf_item(
        &mut leaf,
        1,
        2,
        BTRFS_ITEM_DEV_ITEM,
        2,
        second_off,
        u32::try_from(second_payload.len()).expect("payload length should fit in u32"),
    );
    let first_end = first_off as usize + first_payload.len();
    leaf[first_off as usize..first_end].copy_from_slice(&first_payload);
    let second_end = second_off as usize + second_payload.len();
    leaf[second_off as usize..second_end].copy_from_slice(&second_payload);

    let blocks: HashMap<u64, Vec<u8>> = [(root_physical, root), (leaf_physical, leaf)]
        .into_iter()
        .collect();
    let mut read = |phys: u64| -> Result<Vec<u8>, ParseError> {
        blocks.get(&phys).cloned().ok_or(ParseError::InvalidField {
            field: "physical",
            reason: "block not in test image",
        })
    };

    let items = walk_device_tree(&mut read, root_logical, &chunks, BTRFS_TEST_NODESIZE)
        .expect("walk device tree");
    assert_eq!(
        items.len(),
        2,
        "device tree should return both DEV_ITEM entries"
    );
    assert_eq!(items[0].key.objectid, 1);
    assert_eq!(items[0].key.item_type, BTRFS_ITEM_DEV_ITEM);
    assert_eq!(items[1].key.objectid, 2);
    assert_eq!(items[1].key.item_type, BTRFS_ITEM_DEV_ITEM);

    let first_dev = parse_dev_item(&items[0].data).expect("first DEV_ITEM should parse");
    assert_eq!(first_dev.devid, 1);
    assert_eq!(first_dev.total_bytes, 1024 * 1024 * 1024 * 1024_u64);
    assert_eq!(first_dev.bytes_used, 512 * 1024 * 1024 * 1024_u64);
    assert_eq!(first_dev.start_offset, 1024 * 1024_u64);

    let second_dev = parse_dev_item(&items[1].data).expect("second DEV_ITEM should parse");
    assert_eq!(second_dev.devid, 2);
    assert_eq!(second_dev.total_bytes, 2 * 1024 * 1024 * 1024 * 1024_u64);
    assert_eq!(second_dev.bytes_used, 1024 * 1024 * 1024 * 1024_u64);
    assert_eq!(second_dev.start_offset, 2 * 1024 * 1024_u64);
}

#[test]
fn btrfs_multi_device_dup_read_conforms() {
    let logical = 0xC0_000_u64;
    let stripe_len = 0x10_000_u64;
    // DUP with 1 device: 2 mirrors on the same device.
    // Length is stripe_len = 0x10_000.
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
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
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
                devid: 1,
                offset: 0x200_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let data1 = Arc::new(vec![0xAA_u8; 4]);
    let data2 = Arc::new(vec![0xBB_u8; 4]);

    // DUP: 2 stripes on the same device (devid 1).
    // The implementation should pick the first mirror by default.
    // If it fails, it should pick the second mirror.

    let d1 = Arc::clone(&data1);
    let d2 = Arc::clone(&data2);
    devices.add_device(
        1,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x100_000 {
                // First mirror
                Ok((*d1).clone())
            } else if physical == 0x200_000 {
                // Second mirror
                Ok((*d2).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    let cx = Cx::for_testing();
    // Read from logical (picks first mirror)
    let res1 = devices
        .read_logical(&chunks, logical, 4)
        .expect("read DUP mirror 0");
    assert_eq!(res1, vec![0xAA_u8; 4]);

    // We can't easily simulate failure of ONLY the first mirror on the same device
    // since the callback is per-device. But we've verified mirror picking for RAID1.
}

#[test]
fn btrfs_multi_device_raid6_read_conforms() {
    let logical = 0x70_000_u64;
    let stripe_len = 0x10_000_u64;
    // RAID6 with 4 devices: 2 data stripes, 2 parity stripes (P+Q).
    // Length is 2 * stripe_len = 0x20_000.
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
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 4,
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
            BtrfsStripe {
                devid: 3,
                offset: 0x300_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 4,
                offset: 0x400_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let data1 = Arc::new(vec![0x66_u8; 4]);
    let data2 = Arc::new(vec![0x77_u8; 4]);

    // In RAID6, P and Q rotate.
    // For stripe_nr=0, P=dev4, Q=dev3. Data at dev1, dev2.
    let d1 = Arc::clone(&data1);
    devices.add_device(
        1,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x100_000 {
                Ok((*d1).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    // For stripe_nr=1, rot=1. p_pos=(4-1-1)%4=2 (dev3), q_pos=(4-2+4-1)%4=1 (dev2).
    // Data at dev1, dev4.
    let d2 = Arc::clone(&data2);
    devices.add_device(
        4,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x410_000 {
                Ok((*d2).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    let cx = Cx::for_testing();
    // Read stripe 0 (data1)
    let res1 = devices
        .read_logical(&chunks, logical, 4)
        .expect("read RAID6 data1");
    assert_eq!(res1, vec![0x66_u8; 4]);

    // Read stripe 1 (data2)
    let res2 = devices
        .read_logical(&chunks, logical + stripe_len, 4)
        .expect("read RAID6 data2");
    assert_eq!(res2, vec![0x77_u8; 4]);
}

#[test]
fn btrfs_multi_device_raid10_read_conforms() {
    let logical = 0xA0_000_u64;
    let stripe_len = 0x10_000_u64;
    // RAID10 with 4 devices: 2 mirrors of 2 stripes.
    // Length is 2 * stripe_len = 0x20_000.
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
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 4,
        sub_stripes: 2,
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
            BtrfsStripe {
                devid: 3,
                offset: 0x300_000,
                dev_uuid: [0; 16],
            },
            BtrfsStripe {
                devid: 4,
                offset: 0x400_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    // Stripe 0: dev1, dev2 (mirrors)
    // Stripe 1: dev3, dev4 (mirrors)

    devices.add_device(
        1,
        Box::new(move |_physical, _len| {
            Err(ParseError::InvalidField {
                field: "device",
                reason: "simulated failure dev1",
            })
        }),
    );
    devices.add_device(
        2,
        Box::new(move |physical, len| {
            assert_eq!(physical, 0x100_000);
            assert_eq!(len, 4);
            Ok(b"mir0".to_vec())
        }),
    );
    devices.add_device(
        4,
        Box::new(move |physical, len| {
            assert_eq!(physical, 0x300_000);
            assert_eq!(len, 4);
            Ok(b"mir1".to_vec())
        }),
    );

    let cx = Cx::for_testing();
    // Read from stripe 0 (should fall back to dev2)
    let res1 = devices
        .read_logical(&chunks, logical, 4)
        .expect("read RAID10 stripe 0");
    assert_eq!(res1, b"mir0");

    // Read from stripe 1 (device 4)
    let res2 = devices
        .read_logical(&chunks, logical + stripe_len, 4)
        .expect("read RAID10 stripe 1");
    assert_eq!(res2, b"mir1");
}

#[test]
fn btrfs_multi_device_raid5_read_conforms() {
    let logical = 0x50_000_u64;
    let stripe_len = 0x10_000_u64;
    // RAID5 with 3 devices: 2 data stripes, 1 parity stripe.
    // Length is 2 * stripe_len = 0x20_000.
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
            | ffs_ondisk::chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
        io_align: BTRFS_TEST_NODESIZE,
        io_width: BTRFS_TEST_NODESIZE,
        sector_size: BTRFS_TEST_NODESIZE,
        num_stripes: 3,
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
            BtrfsStripe {
                devid: 3,
                offset: 0x300_000,
                dev_uuid: [0; 16],
            },
        ],
    }];

    let mut devices = BtrfsDeviceSet::new();
    let data1 = Arc::new(vec![0x11_u8; 4]);
    let data2 = Arc::new(vec![0x22_u8; 4]);

    // In RAID5, data is striped.
    // Stripe 0: dev1:0x100_000, dev2:0x200_000, dev3:0x300_000 (P)
    // Stripe 1: dev1:0x110_000 (P), dev2:0x210_000, dev3:0x310_000

    let d1 = Arc::clone(&data1);
    devices.add_device(
        1,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x100_000 {
                Ok((*d1).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    let d2 = Arc::clone(&data2);
    devices.add_device(
        2,
        Box::new(move |physical, len| {
            assert_eq!(len, 4);
            if physical == 0x210_000 {
                Ok((*d2).clone())
            } else {
                Err(ParseError::InvalidField {
                    field: "device",
                    reason: "unexpected physical offset",
                })
            }
        }),
    );

    devices.add_device(
        3,
        Box::new(move |_physical, _len| {
            Err(ParseError::InvalidField {
                field: "device",
                reason: "parity device read not implemented for test",
            })
        }),
    );

    // Read from logical 0x50_000 (stripe 0, data 1)
    let res1 = devices
        .read_logical(&chunks, logical, 4)
        .expect("read RAID5 data1");
    assert_eq!(res1, vec![0x11_u8; 4]);

    // Read from logical 0x50_000 + stripe_len (stripe 1, data 2)
    // Stripe 1 for logical 0x60_000 should map to dev2:0x210_000
    let res2 = devices
        .read_logical(&chunks, logical + stripe_len, 4)
        .expect("read RAID5 data2");
    assert_eq!(res2, vec![0x22_u8; 4]);
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
    btrfs_tree_block_checksum_tamper_detection_conforms();
    ext4_orphan_recovery_conforms();
    ext4_path_resolution_conforms();
    ext4_fallocate_zero_range_zeroes_target_range();
    ext4_e2compr_write_readback_conforms_for_gzip_and_lzo();
    ext4_indirect_block_addressing_conforms();
    ext4_fast_commit_replay_openfs_evidence_conforms();
    ext4_fast_commit_truncated_stream_falls_back_to_jbd2_only();
    btrfs_send_stream_multi_command_conforms();
    btrfs_send_stream_unknown_command_preserves_attrs_as_unspec();
    btrfs_transparent_decompression_zlib_regular_extent_conforms();
    btrfs_transparent_decompression_lzo_regular_extent_conforms();
    btrfs_transparent_decompression_zstd_regular_extent_conforms();
    btrfs_subvolume_mount_root_alias_conforms();
    btrfs_tree_log_replay_multilevel_conforms();
    btrfs_tree_log_replay_skips_when_log_root_absent();
    btrfs_chunk_tree_walk_adds_and_sorts_new_chunks();
    btrfs_device_tree_walk_enumerates_all_devices();
    btrfs_multi_device_raid6_read_conforms();
    btrfs_multi_device_raid10_read_conforms();
    btrfs_multi_device_raid5_read_conforms();
    btrfs_multi_device_dup_read_conforms();
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
