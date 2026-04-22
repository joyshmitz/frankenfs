#![forbid(unsafe_code)]
//! E2E tests that mount an ext4 image via FUSE and verify file operations
//! through the kernel VFS.
//!
//! These tests require:
//! - `/dev/fuse` to exist (FUSE kernel module)
//! - `mkfs.ext4` and `debugfs` on `$PATH`
//! - `fusermount3` permission to mount (may fail in containers)
//!
//! All tests run by default and return early (soft-skip) when prerequisites
//! are unavailable. This makes the suite CI-compatible: tests pass
//! everywhere, and exercise FUSE when the environment supports it.
//! Only `fuse_setattr_chown` remains `#[ignore]` as it requires root.

use asupersync::Cx;
use ffs_core::{BtrfsMountSelection, Ext4JournalReplayMode, FsOps, OpenFs, OpenOptions, RequestScope};
use ffs_fuse::{MountOptions, mount_background};
use ffs_harness::load_sparse_fixture;
use ffs_types::InodeNumber;
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

const EOPNOTSUPP_ERRNO: i64 = 95;
const BTRFS_TEST_WORKSPACE: &str = "testdir";
const FS_IOC_FIEMAP_CMD: u32 = 0xC020_660B;
const FIEMAP_REQUEST_FLAG_SYNC: u32 = 0x0001;
const FIEMAP_REQUEST_FLAG_XATTR: u32 = 0x0002;
const FIEMAP_EXTENT_LAST_FLAG: u32 = 0x0001;
const FIEMAP_EXTENT_UNWRITTEN_FLAG: u32 = 0x0800;
const FS_IOC_GET_ENCRYPTION_POLICY_CMD: u32 = 0x400C_6615;
const FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD: u32 = 0xC016_6616;
const FS_IOC_GETFSLABEL_CMD: u32 = 0x8100_9431;
const FS_IOC_SETFSLABEL_CMD: u32 = 0x4100_9432;
const EXT4_IOC_GETFLAGS_CMD: u32 = 0x8008_6601;
const EXT4_IOC_SETFLAGS_CMD: u32 = 0x4008_6602;
const EXT4_IOC_GETVERSION_CMD: u32 = 0x8008_6603;
const EXT4_IOC_SETVERSION_CMD: u32 = 0x4008_6604;
const EXT4_IOC_MOVE_EXT_CMD: u32 = 0xC028_660F;
const FSCRYPT_POLICY_V1_SIZE: usize = 12;
const FSCRYPT_CONTEXT_V1_SIZE: usize = 28;
const FSCRYPT_POLICY_V1_VERSION: u8 = 0;
const FSCRYPT_POLICY_V2_SIZE: usize = 24;
const FSCRYPT_CONTEXT_V2_SIZE: usize = 40;
const FSCRYPT_POLICY_V2_VERSION: u8 = 2;
const EXT4_ENCRYPT_INODE_FL: u32 = 0x0000_0800;
const EXT4_ENCRYPTION_XATTR_NAME: &[u8] = b"c";
const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
const ACL_USER_OBJ_TAG: u16 = 0x0001;
const ACL_GROUP_OBJ_TAG: u16 = 0x0004;
const ACL_OTHER_TAG: u16 = 0x0020;
const ACL_UNDEFINED_ID: u32 = u32::MAX;

fn patterned_bytes(len: usize, modulus: usize, offset: usize) -> Vec<u8> {
    assert!(
        modulus + offset <= usize::from(u8::MAX) + 1,
        "pattern byte range should fit u8"
    );
    (0..len)
        .map(|i| u8::try_from((i % modulus) + offset).expect("pattern byte should fit u8"))
        .collect()
}

fn command_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn emit_scenario_result(scenario_id: &str, outcome: &str, detail: Option<&str>) {
    match detail {
        Some(detail) => {
            eprintln!(
                "SCENARIO_RESULT|scenario_id={scenario_id}|outcome={outcome}|detail={detail}"
            );
        }
        None => eprintln!("SCENARIO_RESULT|scenario_id={scenario_id}|outcome={outcome}"),
    }
}

fn read_ioctl_trace(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn trace_contains_cmd(trace: &str, cmd: u32) -> bool {
    trace.contains(&format!("cmd=0x{cmd:08x}"))
}

/// Check if FUSE E2E prerequisites are met.
fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists()
        && command_available("mkfs.ext4")
        && command_available("debugfs")
}

/// Create a small ext4 image and populate it with test files using debugfs.
fn create_test_image(dir: &Path) -> std::path::PathBuf {
    create_test_image_with_size(dir, 4 * 1024 * 1024)
}

fn create_test_image_with_ext4_incompat_features(
    dir: &Path,
    image_size_bytes: u64,
    incompat_bits: u32,
) -> std::path::PathBuf {
    let image = create_test_image_with_size(dir, image_size_bytes);
    let mut data = fs::read(&image).expect("read ext4 image");
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;
    let incompat_off = sb_off + 0x60;
    let checksum_off = sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET;
    let mut feature_incompat = u32::from_le_bytes(
        data[incompat_off..incompat_off + 4]
            .try_into()
            .expect("feature_incompat bytes"),
    );
    feature_incompat |= incompat_bits;
    data[incompat_off..incompat_off + 4].copy_from_slice(&feature_incompat.to_le_bytes());
    let checksum = ffs_ondisk::ext4::ext4_chksum(
        !0u32,
        &data[sb_off..sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET],
    );
    data[checksum_off..checksum_off + 4].copy_from_slice(&checksum.to_le_bytes());
    fs::write(&image, data).expect("rewrite ext4 image with incompat bits");
    image
}

fn conformance_fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance")
        .join("fixtures")
        .join(name)
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
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
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
        (ffs_ondisk::Ext4IncompatFeatures::FILETYPE.0
            | ffs_ondisk::Ext4IncompatFeatures::EXTENTS.0
            | incompat_feature)
            .to_le_bytes();
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat);
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let root_ino = 4 * 4096 + 256;
    image[root_ino..root_ino + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[root_ino + 4..root_ino + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[root_ino + 0x1A..root_ino + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[root_ino + 0x20..root_ino + 0x24].copy_from_slice(&root_inode_flags.to_le_bytes());
    image[root_ino + 0x80..root_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = root_ino + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes());

    let file_ino = 4 * 4096 + 10 * 256;
    image[file_ino..file_ino + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[file_ino + 4..file_ino + 8].copy_from_slice(&5_u32.to_le_bytes());
    image[file_ino + 0x1A..file_ino + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[file_ino + 0x80..file_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());

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
    image[dir + 6] = u8::try_from(raw_name.len()).expect("fscrypt raw name length fits u8");
    image[dir + 7] = 1;
    image[dir + 8..dir + 8 + raw_name.len()].copy_from_slice(raw_name);

    image
}

fn build_ext4_encrypt_image_with_dir(raw_name: &[u8]) -> Vec<u8> {
    build_ext4_featured_dir_image(
        raw_name,
        ffs_ondisk::Ext4IncompatFeatures::ENCRYPT.0,
        0x0008_0000,
    )
}

fn build_ext4_inline_data_image(inode_fixture: &str) -> Vec<u8> {
    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat = (ffs_ondisk::Ext4IncompatFeatures::FILETYPE.0
        | ffs_ondisk::Ext4IncompatFeatures::EXTENTS.0
        | ffs_ondisk::Ext4IncompatFeatures::INLINE_DATA.0)
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

    let inline_inode = load_sparse_fixture(&conformance_fixture_path(inode_fixture))
        .expect("load inline inode fixture");
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
    image[dir + 6] = u8::try_from(name.len()).expect("inline fixture name length fits u8");
    image[dir + 7] = 1;
    image[dir + 8..dir + 8 + name.len()].copy_from_slice(name);

    image
}

fn create_ext4_inline_data_test_image(dir: &Path, inode_fixture: &str) -> PathBuf {
    let image = dir.join("inline-data.ext4");
    fs::write(&image, build_ext4_inline_data_image(inode_fixture))
        .expect("write ext4 inline-data fixture image");
    image
}

#[allow(clippy::too_many_lines)]
fn create_test_image_with_size(dir: &Path, image_size_bytes: u64) -> std::path::PathBuf {
    let image = dir.join("test.ext4");

    // Create a sparse image sized for the scenario under test.
    let f = fs::File::create(&image).expect("create image");
    f.set_len(image_size_bytes).expect("set image size");
    drop(f);

    // mkfs.ext4
    let out = Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "4096",
            "-L",
            "ffs-fuse-e2e",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.ext4");
    assert!(
        out.status.success(),
        "mkfs.ext4 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Make root writable so ext4 write-path tests work on unprivileged runners.
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field / mode 040777",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs chmod /");
    assert!(
        out.status.success(),
        "debugfs chmod / failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Populate with test files via debugfs.
    let hello_path = dir.join("hello_src.txt");
    let nested_path = dir.join("nested_src.txt");
    fs::write(&hello_path, b"Hello from FrankenFS E2E!\n").expect("write hello src");
    fs::write(&nested_path, b"Nested file content.\n").expect("write nested src");

    // Create directory
    let out = Command::new("debugfs")
        .args(["-w", "-R", "mkdir testdir", image.to_str().unwrap()])
        .output()
        .expect("debugfs mkdir");
    assert!(
        out.status.success(),
        "debugfs mkdir failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field testdir mode 040777",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs chmod testdir");
    assert!(
        out.status.success(),
        "debugfs chmod testdir failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Write hello.txt
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("write {} hello.txt", hello_path.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs write hello.txt");
    assert!(
        out.status.success(),
        "debugfs write hello.txt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let uid_out = Command::new("id").arg("-u").output().unwrap();
    let uid = String::from_utf8_lossy(&uid_out.stdout).trim().to_string();
    let gid_out = Command::new("id").arg("-g").output().unwrap();
    let gid = String::from_utf8_lossy(&gid_out.stdout).trim().to_string();
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field hello.txt uid {uid}"),
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field hello.txt gid {gid}"),
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field hello.txt mode 0100777",
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    // Write nested.txt
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("write {} testdir/nested.txt", nested_path.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs write nested.txt");
    assert!(
        out.status.success(),
        "debugfs write nested.txt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field testdir/nested.txt uid {uid}"),
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field testdir/nested.txt gid {gid}"),
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "set_inode_field testdir/nested.txt mode 0100777",
            image.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    image
}

fn create_test_image_with_seeded_namespace_removal_fixture(dir: &Path) -> std::path::PathBuf {
    let image = create_test_image_with_size(dir, 4 * 1024 * 1024);
    let empty_dir = "readonly_empty_dir";
    let unlink_seed_src = dir.join("readonly_unlink_seed_src.txt");
    let rename_seed_src = dir.join("readonly_rename_source_src.txt");

    fs::write(&unlink_seed_src, b"readonly ext4 unlink seed\n")
        .expect("write ext4 unlink namespace-removal seed");
    fs::write(&rename_seed_src, b"readonly ext4 rename source\n")
        .expect("write ext4 rename namespace-removal seed");

    let mkdir_out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("mkdir {empty_dir}"),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs mkdir readonly_empty_dir");
    assert!(
        mkdir_out.status.success(),
        "debugfs mkdir readonly_empty_dir failed: {}",
        String::from_utf8_lossy(&mkdir_out.stderr)
    );

    let chmod_out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("set_inode_field {empty_dir} mode 040777"),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs chmod readonly_empty_dir");
    assert!(
        chmod_out.status.success(),
        "debugfs chmod readonly_empty_dir failed: {}",
        String::from_utf8_lossy(&chmod_out.stderr)
    );

    for (src, target, desc) in [
        (
            &unlink_seed_src,
            "readonly_unlink_seed.txt",
            "readonly unlink seed",
        ),
        (
            &rename_seed_src,
            "readonly_rename_source.txt",
            "readonly rename source",
        ),
    ] {
        let out = Command::new("debugfs")
            .args([
                "-w",
                "-R",
                &format!("write {} {target}", src.display()),
                image.to_str().unwrap(),
            ])
            .output()
            .expect("debugfs write namespace-removal seed");
        assert!(
            out.status.success(),
            "debugfs write {desc} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    image
}

fn build_posix_acl_xattr(entries: &[(u16, u16)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + (entries.len() * 8));
    out.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
    for (tag, perm) in entries {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());
    }
    out
}

fn set_debugfs_xattr_from_file(
    image: &Path,
    target: &str,
    name: &str,
    value: &[u8],
    blob_path: &Path,
) {
    fs::write(blob_path, value).expect("write xattr blob");
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("ea_set -f {} {target} {name}", blob_path.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs ea_set -f");
    assert!(
        out.status.success(),
        "debugfs ea_set -f failed for {target} {name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::remove_file(blob_path).ok();
}

fn create_ext4_posix_acl_test_image(dir: &Path) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let image = create_test_image(dir);
    let access_acl = build_posix_acl_xattr(&[
        (ACL_USER_OBJ_TAG, 0o6),
        (ACL_GROUP_OBJ_TAG, 0o4),
        (ACL_OTHER_TAG, 0),
    ]);
    let default_acl = build_posix_acl_xattr(&[
        (ACL_USER_OBJ_TAG, 0o7),
        (ACL_GROUP_OBJ_TAG, 0o5),
        (ACL_OTHER_TAG, 0o1),
    ]);
    set_debugfs_xattr_from_file(
        &image,
        "/hello.txt",
        "system.posix_acl_access",
        &access_acl,
        &dir.join("acl_access.bin"),
    );
    set_debugfs_xattr_from_file(
        &image,
        "/testdir",
        "system.posix_acl_default",
        &default_acl,
        &dir.join("acl_default.bin"),
    );
    (image, access_acl, default_acl)
}

fn build_fscrypt_context_v1(
    contents_mode: u8,
    filenames_mode: u8,
    flags: u8,
    descriptor: [u8; 8],
    nonce: [u8; 16],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(FSCRYPT_CONTEXT_V1_SIZE);
    context.push(FSCRYPT_POLICY_V1_VERSION);
    context.push(contents_mode);
    context.push(filenames_mode);
    context.push(flags);
    context.extend_from_slice(&descriptor);
    context.extend_from_slice(&nonce);
    context
}

fn build_fscrypt_context_v2(
    contents_mode: u8,
    filenames_mode: u8,
    flags: u8,
    log2_data_unit_size: u8,
    identifier: [u8; 16],
    nonce: [u8; 16],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(FSCRYPT_CONTEXT_V2_SIZE);
    context.push(FSCRYPT_POLICY_V2_VERSION);
    context.push(contents_mode);
    context.push(filenames_mode);
    context.push(flags);
    context.push(log2_data_unit_size);
    context.extend_from_slice(&[0_u8; 3]);
    context.extend_from_slice(&identifier);
    context.extend_from_slice(&nonce);
    context
}

fn build_test_inline_ibody(ibody_len: usize, entries: &[ffs_ondisk::Ext4Xattr]) -> Vec<u8> {
    let mut out = vec![0_u8; ibody_len];
    if entries.is_empty() {
        return out;
    }

    out[0..4].copy_from_slice(&ffs_types::EXT4_XATTR_MAGIC.to_le_bytes());
    let region_capacity = ibody_len
        .checked_sub(4)
        .expect("inline xattr region must include 4-byte header");
    let mut region = vec![0_u8; region_capacity];
    let mut next_entry = 0_usize;
    let mut value_tail = region_capacity;

    for entry in entries {
        let entry_len = (16 + entry.name.len() + 3) & !3;
        let value_start = value_tail
            .checked_sub(entry.value.len())
            .expect("inline xattr value should fit")
            & !3;
        let entry_end_with_term = next_entry
            .checked_add(entry_len + 4)
            .expect("inline xattr entry offset should not overflow");
        assert!(
            entry_end_with_term <= value_start,
            "inline xattr entry table should not overlap values"
        );

        region[value_start..value_start + entry.value.len()].copy_from_slice(&entry.value);
        value_tail = value_start;

        region[next_entry] =
            u8::try_from(entry.name.len()).expect("inline xattr name should fit in u8");
        region[next_entry + 1] = entry.name_index;
        region[next_entry + 2..next_entry + 4].copy_from_slice(
            &u16::try_from(value_start)
                .expect("inline xattr value offset should fit in u16")
                .to_le_bytes(),
        );
        region[next_entry + 8..next_entry + 12].copy_from_slice(
            &u32::try_from(entry.value.len())
                .expect("inline xattr value length should fit in u32")
                .to_le_bytes(),
        );
        region[next_entry + 16..next_entry + 16 + entry.name.len()].copy_from_slice(&entry.name);
        next_entry += entry_len;
    }

    out[4..].copy_from_slice(&region);
    out
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_fscrypt_policy_image(encrypted_flag: bool) -> Vec<u8> {
    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes());
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off..sb_off + 0x04].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes());
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes());
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&128_u32.to_le_bytes());
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes());
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes());
    let incompat = (ffs_ondisk::Ext4IncompatFeatures::FILETYPE.0
        | ffs_ondisk::Ext4IncompatFeatures::EXTENTS.0
        | ffs_ondisk::Ext4IncompatFeatures::ENCRYPT.0)
        .to_le_bytes();
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat);
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes());
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes());

    let root_ino = 4 * 4096 + 256;
    image[root_ino..root_ino + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[root_ino + 4..root_ino + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[root_ino + 0x1A..root_ino + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[root_ino + 0x20..root_ino + 0x24]
        .copy_from_slice(&ffs_types::EXT4_EXTENTS_FL.to_le_bytes());
    image[root_ino + 0x80..root_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = root_ino + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes());
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes());
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes());
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes());
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes());

    let file_ino = 4 * 4096 + 10 * 256;
    image[file_ino..file_ino + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[file_ino + 4..file_ino + 8].copy_from_slice(&0_u32.to_le_bytes());
    image[file_ino + 0x1A..file_ino + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[file_ino + 0x80..file_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());
    if encrypted_flag {
        image[file_ino + 0x20..file_ino + 0x24]
            .copy_from_slice(&EXT4_ENCRYPT_INODE_FL.to_le_bytes());
    }

    let context = build_fscrypt_context_v1(1, 4, 0, *b"mkdesc42", *b"0123456789abcdef");
    let ibody = build_test_inline_ibody(
        256 - (128 + 32),
        &[ffs_ondisk::Ext4Xattr {
            name_index: ffs_types::EXT4_XATTR_INDEX_ENCRYPTION,
            name: EXT4_ENCRYPTION_XATTR_NAME.to_vec(),
            value: context,
        }],
    );
    let xattr_off = file_ino + 128 + 32;
    image[xattr_off..xattr_off + ibody.len()].copy_from_slice(&ibody);

    let dir_block = 10 * 4096;
    image[dir_block..dir_block + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir_block + 4..dir_block + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir_block + 6] = 1;
    image[dir_block + 7] = 2;
    image[dir_block + 8] = b'.';

    let dotdot = dir_block + 12;
    image[dotdot..dotdot + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dotdot + 4..dotdot + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dotdot + 6] = 2;
    image[dotdot + 7] = 2;
    image[dotdot + 8] = b'.';
    image[dotdot + 9] = b'.';

    let file_entry = dotdot + 12;
    let file_name = b"policy.txt";
    image[file_entry..file_entry + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[file_entry + 4..file_entry + 6].copy_from_slice(&(4096_u16 - 24).to_le_bytes());
    image[file_entry + 6] = u8::try_from(file_name.len()).expect("policy name should fit u8");
    image[file_entry + 7] = 1;
    image[file_entry + 8..file_entry + 8 + file_name.len()].copy_from_slice(file_name);

    let inode_bitmap = 3 * 4096;
    for bit in [1_usize, 10_usize] {
        image[inode_bitmap + bit / 8] |= 1 << (bit % 8);
    }

    image
}

#[allow(clippy::cast_possible_truncation)]
fn build_ext4_fscrypt_policy_v2_image() -> Vec<u8> {
    let block_size: u32 = 4096;
    let image_size: u32 = 256 * 1024;
    let mut image = vec![0_u8; image_size as usize];
    let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;

    image[sb_off + 0x38..sb_off + 0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
    image[sb_off + 0x18..sb_off + 0x1C].copy_from_slice(&2_u32.to_le_bytes()); // s_rev_level
    let blocks_count = image_size / block_size;
    image[sb_off + 0x04..sb_off + 0x08].copy_from_slice(&blocks_count.to_le_bytes());
    let inodes_count: u32 = 128;
    image[sb_off..sb_off + 4].copy_from_slice(&inodes_count.to_le_bytes());
    image[sb_off + 0x14..sb_off + 0x18].copy_from_slice(&0_u32.to_le_bytes()); // s_first_data_block
    image[sb_off + 0x20..sb_off + 0x24].copy_from_slice(&blocks_count.to_le_bytes()); // s_blocks_per_group
    image[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&inodes_count.to_le_bytes()); // s_inodes_per_group
    image[sb_off + 0x3A..sb_off + 0x3C].copy_from_slice(&1_u16.to_le_bytes()); // s_minor_rev_level
    image[sb_off + 0x58..sb_off + 0x5A].copy_from_slice(&256_u16.to_le_bytes()); // s_inode_size
    image[sb_off + 0x4C..sb_off + 0x50].copy_from_slice(&1_u32.to_le_bytes()); // s_creator_os
    image[sb_off + 0x54..sb_off + 0x58].copy_from_slice(&11_u32.to_le_bytes()); // s_first_ino
    let incompat_flags = ffs_ondisk::ext4::Ext4IncompatFeatures::FILETYPE.0
        | ffs_ondisk::ext4::Ext4IncompatFeatures::EXTENTS.0
        | ffs_ondisk::ext4::Ext4IncompatFeatures::ENCRYPT.0;
    image[sb_off + 0x60..sb_off + 0x64].copy_from_slice(&incompat_flags.to_le_bytes());
    let checksum = ffs_ondisk::ext4::ext4_chksum(
        !0_u32,
        &image[sb_off..sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET],
    );
    image[sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET..sb_off + ffs_types::EXT4_SB_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&checksum.to_le_bytes());

    let gd_off: usize = 4096;
    image[gd_off..gd_off + 4].copy_from_slice(&2_u32.to_le_bytes()); // block bitmap
    image[gd_off + 4..gd_off + 8].copy_from_slice(&3_u32.to_le_bytes()); // inode bitmap
    image[gd_off + 8..gd_off + 12].copy_from_slice(&4_u32.to_le_bytes()); // inode table

    let root_ino = 4 * 4096 + 256;
    image[root_ino..root_ino + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
    image[root_ino + 4..root_ino + 8].copy_from_slice(&4096_u32.to_le_bytes());
    image[root_ino + 0x1A..root_ino + 0x1C].copy_from_slice(&3_u16.to_le_bytes());
    image[root_ino + 0x20..root_ino + 0x24]
        .copy_from_slice(&ffs_types::EXT4_EXTENTS_FL.to_le_bytes());
    image[root_ino + 0x80..root_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());

    let root_extent = root_ino + 0x28;
    image[root_extent..root_extent + 2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // eh_magic
    image[root_extent + 2..root_extent + 4].copy_from_slice(&1_u16.to_le_bytes()); // eh_entries
    image[root_extent + 4..root_extent + 6].copy_from_slice(&4_u16.to_le_bytes()); // eh_max
    image[root_extent + 6..root_extent + 8].copy_from_slice(&0_u16.to_le_bytes()); // eh_depth
    image[root_extent + 12..root_extent + 16].copy_from_slice(&0_u32.to_le_bytes()); // ee_block
    image[root_extent + 16..root_extent + 18].copy_from_slice(&1_u16.to_le_bytes()); // ee_len
    image[root_extent + 18..root_extent + 20].copy_from_slice(&0_u16.to_le_bytes()); // ee_start_hi
    image[root_extent + 20..root_extent + 24].copy_from_slice(&10_u32.to_le_bytes()); // ee_start_lo

    let file_ino = 4 * 4096 + 10 * 256;
    image[file_ino..file_ino + 2].copy_from_slice(&0o100_644_u16.to_le_bytes());
    image[file_ino + 4..file_ino + 8].copy_from_slice(&0_u32.to_le_bytes());
    image[file_ino + 0x1A..file_ino + 0x1C].copy_from_slice(&1_u16.to_le_bytes());
    image[file_ino + 0x80..file_ino + 0x82].copy_from_slice(&32_u16.to_le_bytes());
    image[file_ino + 0x20..file_ino + 0x24].copy_from_slice(&EXT4_ENCRYPT_INODE_FL.to_le_bytes());

    let context = build_fscrypt_context_v2(1, 4, 0, 9, *b"0123456789abcdef", *b"fedcba9876543210");
    let ibody = build_test_inline_ibody(
        256 - (128 + 32),
        &[ffs_ondisk::Ext4Xattr {
            name_index: ffs_types::EXT4_XATTR_INDEX_ENCRYPTION,
            name: EXT4_ENCRYPTION_XATTR_NAME.to_vec(),
            value: context,
        }],
    );
    let xattr_off = file_ino + 128 + 32;
    image[xattr_off..xattr_off + ibody.len()].copy_from_slice(&ibody);

    let dir_block = 10 * 4096;
    image[dir_block..dir_block + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dir_block + 4..dir_block + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dir_block + 6] = 1;
    image[dir_block + 7] = 2;
    image[dir_block + 8] = b'.';

    let dotdot = dir_block + 12;
    image[dotdot..dotdot + 4].copy_from_slice(&2_u32.to_le_bytes());
    image[dotdot + 4..dotdot + 6].copy_from_slice(&12_u16.to_le_bytes());
    image[dotdot + 6] = 2;
    image[dotdot + 7] = 2;
    image[dotdot + 8] = b'.';
    image[dotdot + 9] = b'.';

    let file_entry = dotdot + 12;
    let file_name = b"policy.txt";
    image[file_entry..file_entry + 4].copy_from_slice(&11_u32.to_le_bytes());
    image[file_entry + 4..file_entry + 6].copy_from_slice(&(4096_u16 - 24).to_le_bytes());
    image[file_entry + 6] = u8::try_from(file_name.len()).expect("policy name should fit u8");
    image[file_entry + 7] = 1;
    image[file_entry + 8..file_entry + 8 + file_name.len()].copy_from_slice(file_name);

    let inode_bitmap = 3 * 4096;
    for bit in [1_usize, 10_usize] {
        image[inode_bitmap + bit / 8] |= 1 << (bit % 8);
    }

    image
}

/// Try to mount an ext4 image via FrankenFS FUSE with explicit mount options.
///
/// Returns `None` if FUSE mounting fails (e.g. permission denied in containers).
fn try_mount_ffs_with_options(
    image: &Path,
    mountpoint: &Path,
    mount_opts: &MountOptions,
) -> Option<fuser::BackgroundSession> {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, image, &opts).expect("open ext4 image");
    match mount_background(Box::new(fs), mountpoint, mount_opts) {
        Ok(session) => {
            // Give FUSE a moment to initialize.
            thread::sleep(Duration::from_millis(300));
            Some(session)
        }
        Err(e) => {
            eprintln!("FUSE mount failed (skipping test): {e}");
            None
        }
    }
}

/// Try to mount an ext4 image via FrankenFS FUSE (read-only).
///
/// Returns `None` if FUSE mounting fails (e.g. permission denied in containers).
fn try_mount_ffs(image: &Path, mountpoint: &Path) -> Option<fuser::BackgroundSession> {
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };
    try_mount_ffs_with_options(image, mountpoint, &mount_opts)
}

#[test]
fn fuse_read_hello_txt() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Read hello.txt through FUSE.
    let content = fs::read_to_string(mnt.join("hello.txt")).expect("read hello.txt via FUSE");
    assert_eq!(content, "Hello from FrankenFS E2E!\n");
}

#[test]
fn ext4_fuse_inline_data_reads_direct_inode_payload() {
    assert_mounted_ext4_inline_data_read_contract(
        "ext4_inode_inline_data.json",
        b"Hello from inline data!",
        "ext4_ro_inline_data_direct_read_contract",
        "layout=i_block_short_read_eof",
    );
}

#[test]
fn ext4_fuse_inline_data_reads_xattr_continuation_payload() {
    let mut expected = vec![b'A'; 60];
    expected.extend(std::iter::repeat_n(b'B', 16));
    assert_mounted_ext4_inline_data_read_contract(
        "ext4_inode_inline_data_with_continuation.json",
        &expected,
        "ext4_ro_inline_data_system_data_read_contract",
        "layout=system.data_short_read_eof",
    );
}

#[test]
fn ext4_inline_data_mount_open_options_preserve_xattr_continuation_reads() {
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_ext4_inline_data_test_image(
        tmp.path(),
        "ext4_inode_inline_data_with_continuation.json",
    );
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, &image, &opts)
        .expect("open inline-data image with mount options");
    let mut expected = vec![b'A'; 60];
    expected.extend(std::iter::repeat_n(b'B', 16));

    assert_eq!(
        fs.read(&cx, InodeNumber(11), 0, 4096)
            .expect("read inline-data continuation through mount options"),
        expected,
        "OpenFs mount options should preserve inline-data continuation reads before FUSE transport"
    );
}

#[test]
fn fuse_readdir_root() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Read root directory entries.
    let entries: Vec<String> = fs::read_dir(&mnt)
        .expect("readdir root via FUSE")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    assert!(
        entries.contains(&"hello.txt".to_owned()),
        "root should contain hello.txt, got: {entries:?}"
    );
    assert!(
        entries.contains(&"testdir".to_owned()),
        "root should contain testdir, got: {entries:?}"
    );
    assert!(
        entries.contains(&"lost+found".to_owned()),
        "root should contain lost+found, got: {entries:?}"
    );
}

#[test]
fn fuse_read_nested_file() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Read nested file through FUSE.
    let content =
        fs::read_to_string(mnt.join("testdir/nested.txt")).expect("read nested.txt via FUSE");
    assert_eq!(content, "Nested file content.\n");
}

#[test]
fn fuse_getattr_file_metadata() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Check file metadata.
    let meta = fs::metadata(mnt.join("hello.txt")).expect("stat hello.txt via FUSE");
    assert!(meta.is_file(), "hello.txt should be a regular file");
    assert_eq!(
        meta.len(),
        26,
        "hello.txt should be 26 bytes ('Hello from FrankenFS E2E!\\n')"
    );

    // Check directory metadata.
    let dir_meta = fs::metadata(mnt.join("testdir")).expect("stat testdir via FUSE");
    assert!(dir_meta.is_dir(), "testdir should be a directory");
}

#[test]
fn fuse_readlink_and_symlink_detection() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());

    // Add a symlink via debugfs.
    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            "symlink link.txt hello.txt",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs symlink");
    assert!(
        out.status.success(),
        "debugfs symlink failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Reading the symlink target.
    let target = fs::read_link(mnt.join("link.txt")).expect("readlink via FUSE");
    assert_eq!(
        target.to_str().unwrap(),
        "hello.txt",
        "symlink should point to hello.txt"
    );

    // Following the symlink should give the same content.
    let content = fs::read_to_string(mnt.join("link.txt")).expect("read through symlink via FUSE");
    assert_eq!(content, "Hello from FrankenFS E2E!\n");
}

// ── Write-path E2E tests ────────────────────────────────────────────────────

/// Try to mount an ext4 image via FrankenFS FUSE in **read-write** mode with
/// explicit mount options.
///
/// Returns `None` if FUSE mounting fails (e.g. permission denied in containers).
fn try_mount_ffs_rw_with_options(
    image: &Path,
    mountpoint: &Path,
    mount_opts: &MountOptions,
) -> Option<fuser::BackgroundSession> {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::Apply,
        mvcc_wal_path: Some(image.with_extension("wal")),
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, image, &opts).expect("open ext4 image");
    fs.enable_writes(&cx).expect("enable ext4 write support");
    match mount_background(Box::new(fs), mountpoint, mount_opts) {
        Ok(session) => {
            thread::sleep(Duration::from_millis(300));
            Some(session)
        }
        Err(e) => {
            eprintln!("FUSE mount (rw) failed (skipping test): {e}");
            None
        }
    }
}

/// Try to mount an ext4 image via FrankenFS FUSE in **read-write** mode.
///
/// Returns `None` if FUSE mounting fails (e.g. permission denied in containers).
fn try_mount_ffs_rw(image: &Path, mountpoint: &Path) -> Option<fuser::BackgroundSession> {
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    try_mount_ffs_rw_with_options(image, mountpoint, &mount_opts)
}

/// Helper: create image, mount rw, run a closure, then drop the session.
fn with_rw_mount(f: impl FnOnce(&Path)) {
    with_rw_mount_sized(4 * 1024 * 1024, f);
}

fn with_rw_mount_sized(image_size_bytes: u64, f: impl FnOnce(&Path)) {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), image_size_bytes);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs_rw(&image, &mnt) else {
        return;
    };
    f(&mnt);
}

fn with_ext4_inline_data_mount(inode_fixture: &str, f: impl FnOnce(&Path)) {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_ext4_inline_data_test_image(tmp.path(), inode_fixture);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };
    f(&mnt);
}

fn assert_mounted_ext4_inline_data_read_contract(
    inode_fixture: &str,
    expected: &[u8],
    scenario_id: &str,
    detail: &str,
) {
    with_ext4_inline_data_mount(inode_fixture, |mnt| {
        let path = mnt.join("inline.bin");
        assert_eq!(
            fs::metadata(&path).expect("stat inline.bin via FUSE").len(),
            u64::try_from(expected.len()).expect("expected inline size fits u64"),
            "mounted inline-data file should report the expected byte length"
        );
        assert_eq!(
            fs::read(&path).expect("read inline.bin via FUSE"),
            expected,
            "mounted inline-data file should expose the expected payload"
        );

        let mut file = fs::File::open(&path).expect("open inline.bin for boundary reads");
        let short_offset =
            u64::try_from(expected.len().saturating_sub(4)).expect("offset fits u64");
        file.seek(SeekFrom::Start(short_offset))
            .expect("seek near inline-data EOF");
        let mut buf = [0_u8; 8];
        let read = file
            .read(&mut buf)
            .expect("short read near inline-data EOF");
        assert_eq!(
            &buf[..read],
            &expected[expected.len() - read..],
            "near-EOF mounted inline-data read should truncate to the remaining tail bytes"
        );
        let eof_read = file
            .read(&mut buf)
            .expect("read exactly at inline-data EOF");
        assert_eq!(eof_read, 0, "mounted inline-data EOF read should be empty");

        emit_scenario_result(scenario_id, "PASS", Some(detail));
    });
}

fn query_fiemap(path: &Path, extent_count: u32) -> Value {
    query_fiemap_with_options(path, extent_count, 0, None)
}

fn query_fiemap_with_options(
    path: &Path,
    extent_count: u32,
    request_flags: u32,
    response_size: Option<usize>,
) -> Value {
    let script = r"
import fcntl, json, struct, sys

FS_IOC_FIEMAP = 0xC020660B
FIEMAP_HEADER_SIZE = 32
FIEMAP_EXTENT_SIZE = 56
FIEMAP_EXTENT_LAST = 0x0001

path = sys.argv[1]
extent_count = int(sys.argv[2])
request_flags = int(sys.argv[3], 0)
response_size = int(sys.argv[4])
buffer = bytearray(response_size)
if response_size < FIEMAP_HEADER_SIZE:
    raise ValueError('fiemap response buffer too small: {}'.format(response_size))
struct.pack_into('@Q', buffer, 0, 0)
struct.pack_into('@Q', buffer, 8, (1 << 64) - 1)
struct.pack_into('@I', buffer, 16, request_flags)
struct.pack_into('@I', buffer, 24, extent_count)

with open(path, 'rb', buffering=0) as fh:
    try:
        fcntl.ioctl(fh.fileno(), FS_IOC_FIEMAP, buffer, True)
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)

mapped_extents = struct.unpack_from('@I', buffer, 20)[0]
requested_extents = struct.unpack_from('@I', buffer, 24)[0]
extents = []
for index in range(mapped_extents):
    off = FIEMAP_HEADER_SIZE + index * FIEMAP_EXTENT_SIZE
    logical = struct.unpack_from('@Q', buffer, off)[0]
    physical = struct.unpack_from('@Q', buffer, off + 8)[0]
    length = struct.unpack_from('@Q', buffer, off + 16)[0]
    flags = struct.unpack_from('@I', buffer, off + 40)[0]
    extents.append({
        'logical': logical,
        'physical': physical,
        'length': length,
        'flags': flags,
        'last': bool(flags & FIEMAP_EXTENT_LAST),
    })

print(json.dumps({
    'mapped_extents': mapped_extents,
    'requested_extents': requested_extents,
    'extents': extents,
}))
    ";

    let response_size = response_size
        .unwrap_or_else(|| 32 + usize::try_from(extent_count).expect("extent_count fits") * 56);

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &extent_count.to_string(),
            &request_flags.to_string(),
            &response_size.to_string(),
        ])
        .output()
        .expect("python3 fiemap ioctl");
    assert!(
        output.status.success(),
        "python3 fiemap ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode fiemap JSON")
}

fn query_directory_fiemap_with_options(
    path: &Path,
    extent_count: u32,
    request_flags: u32,
    response_size: Option<usize>,
) -> Value {
    let script = r"
import errno, fcntl, json, os, struct, sys

FS_IOC_FIEMAP = 0xC020660B
FIEMAP_HEADER_SIZE = 32

path = sys.argv[1]
extent_count = int(sys.argv[2])
request_flags = int(sys.argv[3], 0)
response_size = int(sys.argv[4])
buffer = bytearray(response_size)
if response_size < FIEMAP_HEADER_SIZE:
    raise ValueError('fiemap response buffer too small: {}'.format(response_size))
struct.pack_into('@Q', buffer, 0, 0)
struct.pack_into('@Q', buffer, 8, (1 << 64) - 1)
struct.pack_into('@I', buffer, 16, request_flags)
struct.pack_into('@I', buffer, 24, extent_count)

fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
try:
    try:
        fcntl.ioctl(fd, FS_IOC_FIEMAP, buffer, True)
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'name': errno.errorcode.get(exc.errno, 'UNKNOWN'),
            'message': str(exc),
        }))
        sys.exit(0)
finally:
    os.close(fd)

print(json.dumps({'ok': True}))
";

    let response_size = response_size
        .unwrap_or_else(|| 32 + usize::try_from(extent_count).expect("extent_count fits") * 56);

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &extent_count.to_string(),
            &request_flags.to_string(),
            &response_size.to_string(),
        ])
        .output()
        .expect("python3 directory fiemap ioctl");
    assert!(
        output.status.success(),
        "python3 directory fiemap ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode directory fiemap JSON")
}

fn fiemap_extent_flags(extent: &Value) -> u32 {
    u32::try_from(extent["flags"].as_u64().unwrap_or(0)).expect("fiemap flags should fit u32")
}

fn ext4_inode_flags_ioctl(path: &Path, command: &str, flags: Option<u32>) -> Value {
    let script = r"
import fcntl, json, struct, sys

EXT4_IOC_GETFLAGS = 0x80086601
EXT4_IOC_SETFLAGS = 0x40086602

command = sys.argv[1]
path = sys.argv[2]
word_size = struct.calcsize('@L')

def setflags_buffer(flags: int) -> bytes:
    if word_size >= 8:
        return struct.pack('@Q', flags)
    return struct.pack('@I', flags)

with open(path, 'r+b', buffering=0) as fh:
    try:
        if command == 'get':
            buffer = bytearray(word_size)
            fcntl.ioctl(fh.fileno(), EXT4_IOC_GETFLAGS, buffer, True)
            print(json.dumps({
                'flags': struct.unpack_from('@I', buffer, 0)[0],
            }))
        elif command == 'set':
            flags = int(sys.argv[3], 0)
            buffer = setflags_buffer(flags)
            fcntl.ioctl(fh.fileno(), EXT4_IOC_SETFLAGS, buffer)
            print(json.dumps({'ok': True}))
        else:
            raise ValueError(f'unsupported ioctl command: {command}')
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let mut args = vec![
        "-c".to_owned(),
        script.to_owned(),
        command.to_owned(),
        path.to_str().expect("path utf8").to_owned(),
    ];
    if let Some(flags) = flags {
        args.push(flags.to_string());
    }

    let output = Command::new("python3")
        .args(args)
        .output()
        .expect("python3 ext4 ioctl");
    assert!(
        output.status.success(),
        "python3 ext4 ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode ext4 ioctl JSON")
}

fn ext4_inode_generation_ioctl(path: &Path, command: &str, generation: Option<u32>) -> Value {
    let script = r"
import fcntl, json, struct, sys

EXT4_IOC_GETVERSION = 0x80086603
EXT4_IOC_SETVERSION = 0x40086604

command = sys.argv[1]
path = sys.argv[2]
word_size = struct.calcsize('@L')

def setversion_buffer(generation: int) -> bytes:
    if word_size >= 8:
        return struct.pack('@Q', generation)
    return struct.pack('@I', generation)

mode = 'r+b' if command == 'set' else 'rb'
with open(path, mode, buffering=0) as fh:
    try:
        if command == 'get':
            buffer = bytearray(word_size)
            fcntl.ioctl(fh.fileno(), EXT4_IOC_GETVERSION, buffer, True)
            print(json.dumps({
                'generation': struct.unpack_from('@I', buffer, 0)[0],
            }))
        elif command == 'set':
            generation = int(sys.argv[3], 0)
            buffer = setversion_buffer(generation)
            fcntl.ioctl(fh.fileno(), EXT4_IOC_SETVERSION, buffer)
            print(json.dumps({'ok': True}))
        else:
            raise ValueError(f'unsupported ioctl command: {command}')
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let mut args = vec![
        "-c".to_owned(),
        script.to_owned(),
        command.to_owned(),
        path.to_str().expect("path utf8").to_owned(),
    ];
    if let Some(generation) = generation {
        args.push(generation.to_string());
    }

    let output = Command::new("python3")
        .args(args)
        .output()
        .expect("python3 ext4 setversion ioctl");
    assert!(
        output.status.success(),
        "python3 ext4 setversion ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode ext4 setversion ioctl JSON")
}

fn ext4_get_encryption_policy_ioctl(path: &Path) -> Value {
    let script = r"
import fcntl, json, sys

FS_IOC_GET_ENCRYPTION_POLICY = 0x400C6615
POLICY_SIZE = 12

with open(sys.argv[1], 'rb', buffering=0) as fh:
    buffer = bytearray(POLICY_SIZE)
    try:
        fcntl.ioctl(fh.fileno(), FS_IOC_GET_ENCRYPTION_POLICY, buffer, True)
        print(json.dumps({
            'policy_version': buffer[0],
            'contents_mode': buffer[1],
            'filenames_mode': buffer[2],
            'flags': buffer[3],
            'master_key_descriptor_hex': buffer[4:12].hex(),
            'policy_hex': buffer.hex(),
        }))
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let output = Command::new("python3")
        .args(["-c", script, path.to_str().expect("path utf8")])
        .output()
        .expect("python3 get encryption policy ioctl");
    assert!(
        output.status.success(),
        "python3 get encryption policy ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode encryption policy ioctl JSON")
}

fn ext4_get_encryption_policy_ex_ioctl(path: &Path) -> Value {
    let script = r"
import fcntl, json, struct, sys

FS_IOC_GET_ENCRYPTION_POLICY_EX = 0xC0166616
FSCRYPT_POLICY_V1_SIZE = 12
FSCRYPT_POLICY_V2_SIZE = 24
HEADER_SIZE = 8

with open(sys.argv[1], 'rb', buffering=0) as fh:
    buffer = bytearray(HEADER_SIZE + FSCRYPT_POLICY_V2_SIZE)
    struct.pack_into('<Q', buffer, 0, FSCRYPT_POLICY_V2_SIZE)
    try:
        fcntl.ioctl(fh.fileno(), FS_IOC_GET_ENCRYPTION_POLICY_EX, buffer, True)
        actual_size = struct.unpack_from('<Q', buffer, 0)[0]
        policy = buffer[HEADER_SIZE:HEADER_SIZE + actual_size]
        version = policy[0] if len(policy) > 0 else 255
        result = {
            'policy_size': actual_size,
            'policy_version': version,
            'policy_hex': policy.hex(),
        }
        if version == 0 and actual_size >= FSCRYPT_POLICY_V1_SIZE:
            result['contents_mode'] = policy[1]
            result['filenames_mode'] = policy[2]
            result['flags'] = policy[3]
            result['master_key_descriptor_hex'] = policy[4:12].hex()
        elif version == 2 and actual_size >= FSCRYPT_POLICY_V2_SIZE:
            result['contents_mode'] = policy[1]
            result['filenames_mode'] = policy[2]
            result['flags'] = policy[3]
            result['master_key_identifier_hex'] = policy[8:24].hex()
        print(json.dumps(result))
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let output = Command::new("python3")
        .args(["-c", script, path.to_str().expect("path utf8")])
        .output()
        .expect("python3 get encryption policy ex ioctl");
    assert!(
        output.status.success(),
        "python3 get encryption policy ex ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode encryption policy ex ioctl JSON")
}

fn fs_label_ioctl(path: &Path, command: &str, label: Option<&str>) -> Value {
    let script = r"
import fcntl, json, sys

FS_IOC_GETFSLABEL = 0x81009431
FS_IOC_SETFSLABEL = 0x41009432
FSLABEL_MAX = 256

with open(sys.argv[1], 'rb', buffering=0) as fh:
    command = sys.argv[2]
    try:
        if command == 'get':
            buffer = bytearray(FSLABEL_MAX)
            fcntl.ioctl(fh.fileno(), FS_IOC_GETFSLABEL, buffer, True)
            end = buffer.find(0)
            if end < 0:
                end = len(buffer)
            label_bytes = bytes(buffer[:end])
            print(json.dumps({
                'label': label_bytes.decode('utf-8', 'surrogateescape'),
                'label_hex': label_bytes.hex(),
            }))
        elif command == 'set':
            label = sys.argv[3].encode('utf-8', 'surrogateescape')
            if len(label) >= FSLABEL_MAX:
                raise ValueError('label too long for ioctl buffer')
            buffer = bytearray(FSLABEL_MAX)
            buffer[:len(label)] = label
            buffer[len(label)] = 0
            fcntl.ioctl(fh.fileno(), FS_IOC_SETFSLABEL, buffer)
            print(json.dumps({'ok': True}))
        else:
            raise ValueError(f'unsupported ioctl command: {command}')
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    ";

    let mut args = vec!["-c", script, path.to_str().expect("path utf8"), command];
    if let Some(label) = label {
        args.push(label);
    }

    let output = Command::new("python3")
        .args(args)
        .output()
        .expect("python3 fs label ioctl");
    assert!(
        output.status.success(),
        "python3 fs label ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode fs label ioctl JSON")
}

fn ext4_move_ext_ioctl(
    path: &Path,
    donor_path: &Path,
    orig_start: u64,
    donor_start: u64,
    len: u64,
) -> Value {
    let script = r"
import fcntl, json, struct, sys
import signal

EXT4_IOC_MOVE_EXT = 0xC028660F
MOVE_EXT_SIZE = 40

path = sys.argv[1]
donor_path = sys.argv[2]
orig_start = int(sys.argv[3])
donor_start = int(sys.argv[4])
length = int(sys.argv[5])

buffer = bytearray(MOVE_EXT_SIZE)
struct.pack_into('@Q', buffer, 8, orig_start)
struct.pack_into('@Q', buffer, 16, donor_start)
struct.pack_into('@Q', buffer, 24, length)

def _timeout(_signum, _frame):
    raise TimeoutError('move_ext ioctl timed out')

with open(path, 'r+b', buffering=0) as orig, open(donor_path, 'r+b', buffering=0) as donor:
    struct.pack_into('@i', buffer, 4, donor.fileno())
    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(15)
    try:
        fcntl.ioctl(orig.fileno(), EXT4_IOC_MOVE_EXT, buffer, True)
    except (TimeoutError, InterruptedError) as exc:
        print(json.dumps({
            'timeout': True,
            'message': str(exc),
        }))
        sys.exit(0)
    except OSError as exc:
        print(json.dumps({
            'errno': exc.errno,
            'message': str(exc),
        }))
        sys.exit(0)
    finally:
        signal.alarm(0)

    print(json.dumps({
        'donor_fd': donor.fileno(),
        'orig_start': struct.unpack_from('@Q', buffer, 8)[0],
        'donor_start': struct.unpack_from('@Q', buffer, 16)[0],
        'len': struct.unpack_from('@Q', buffer, 24)[0],
        'moved_len': struct.unpack_from('@Q', buffer, 32)[0],
    }))
    ";

    let mut command = if command_available("timeout") {
        let mut command = Command::new("timeout");
        command.arg("20s").arg("python3");
        command
    } else {
        Command::new("python3")
    };
    let output = command
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            donor_path.to_str().expect("donor path utf8"),
            &orig_start.to_string(),
            &donor_start.to_string(),
            &len.to_string(),
        ])
        .output()
        .expect("python3 ext4 move_ext ioctl");
    if output.status.code() == Some(124) {
        return serde_json::json!({
            "timeout": true,
            "message": "move_ext ioctl timed out",
        });
    }
    assert!(
        output.status.success(),
        "python3 ext4 move_ext ioctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode ext4 move_ext ioctl JSON")
}

fn physical_blocks_by_logical_block(report: &Value, block_size: u64) -> Vec<u64> {
    let extents = report["extents"].as_array().expect("fiemap extents array");
    let mut blocks = Vec::new();
    for extent in extents {
        let logical = extent["logical"].as_u64().expect("logical") / block_size;
        let physical = extent["physical"].as_u64().expect("physical") / block_size;
        let block_count = extent["length"].as_u64().expect("length") / block_size;
        for idx in 0..block_count {
            let logical_block =
                usize::try_from(logical + idx).expect("logical block index should fit usize");
            if blocks.len() <= logical_block {
                blocks.resize(logical_block + 1, 0);
            }
            blocks[logical_block] = physical + idx;
        }
    }
    blocks
}

fn query_seek(path: &Path, offset: u64, whence: &str) -> Value {
    let script = r"
import json, os, sys

path = sys.argv[1]
offset = int(sys.argv[2])
whence = getattr(os, sys.argv[3])
fd = os.open(path, os.O_RDONLY)
try:
    print(json.dumps({'offset': os.lseek(fd, offset, whence)}))
except OSError as exc:
    print(json.dumps({
        'errno': exc.errno,
        'message': str(exc),
    }))
finally:
    os.close(fd)
    ";

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &offset.to_string(),
            whence,
        ])
        .output()
        .expect("python3 seek probe");
    assert!(
        output.status.success(),
        "python3 seek probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode seek probe JSON")
}

fn query_fallocate(path: &Path, mode: i32, offset: u64, length: u64) -> Value {
    let script = r#"
import ctypes, errno, json, os, sys

path = sys.argv[1]
mode = int(sys.argv[2], 0)
offset = int(sys.argv[3])
length = int(sys.argv[4])
fd = os.open(path, os.O_RDWR)
libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int
try:
    res = libc.fallocate(fd, mode, offset, length)
    err = ctypes.get_errno()
    payload = {"res": res, "errno": err}
    if err:
        payload["name"] = errno.errorcode.get(err, "UNKNOWN")
    print(json.dumps(payload))
finally:
    os.close(fd)
"#;

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &format!("{mode:#x}"),
            &offset.to_string(),
            &length.to_string(),
        ])
        .output()
        .expect("python3 fallocate probe");
    assert!(
        output.status.success(),
        "python3 fallocate probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode fallocate probe JSON")
}

fn query_directory_fallocate(path: &Path, mode: i32, offset: u64, length: u64) -> Value {
    let script = r#"
import ctypes, errno, json, os, sys

path = sys.argv[1]
mode = int(sys.argv[2], 0)
offset = int(sys.argv[3])
length = int(sys.argv[4])

try:
    fd = os.open(path, os.O_RDWR | os.O_DIRECTORY)
except OSError as exc:
    print(json.dumps({
        "errno": exc.errno,
        "name": errno.errorcode.get(exc.errno, "UNKNOWN"),
        "message": str(exc),
        "phase": "open",
    }))
    sys.exit(0)

libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int
try:
    res = libc.fallocate(fd, mode, offset, length)
    err = ctypes.get_errno()
    payload = {"res": res, "errno": err, "phase": "fallocate"}
    if err:
        payload["name"] = errno.errorcode.get(err, "UNKNOWN")
    print(json.dumps(payload))
finally:
    os.close(fd)
"#;

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &format!("{mode:#x}"),
            &offset.to_string(),
            &length.to_string(),
        ])
        .output()
        .expect("python3 directory fallocate probe");
    assert!(
        output.status.success(),
        "python3 directory fallocate probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode directory fallocate probe JSON")
}

fn py_fallocate_report(path: &Path, mode: i32, offset: u64, length: u64) -> Value {
    let script = r#"
import ctypes, errno, json, os, sys

path = sys.argv[1]
mode = int(sys.argv[2], 0)
offset = int(sys.argv[3])
length = int(sys.argv[4])
libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int

try:
    fd = os.open(path, os.O_RDWR)
except OSError as e:
    print(json.dumps({
        "stage": "open",
        "errno": e.errno,
        "name": errno.errorcode.get(e.errno, "UNKNOWN"),
        "message": str(e),
    }))
    raise SystemExit(0)

try:
    res = libc.fallocate(fd, mode, offset, length)
    err = ctypes.get_errno()
    payload = {"stage": "fallocate", "res": res, "errno": err}
    if err:
        payload["name"] = errno.errorcode.get(err, "UNKNOWN")
    print(json.dumps(payload))
finally:
    os.close(fd)
"#;

    let output = Command::new("python3")
        .args([
            "-c",
            script,
            path.to_str().expect("path utf8"),
            &format!("{mode:#x}"),
            &offset.to_string(),
            &length.to_string(),
        ])
        .output()
        .expect("python3 read-only fallocate probe");
    assert!(
        output.status.success(),
        "python3 read-only fallocate probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("decode read-only fallocate probe JSON")
}

fn assert_seek_data_hole_contract(path: &Path, scenario_id: &str) {
    let data = patterned_bytes(12_288, 251, 1);
    fs::write(path, &data).expect("seed seek test file");

    let out = Command::new("fallocate")
        .args([
            "--keep-size",
            "--punch-hole",
            "-o",
            "4096",
            "-l",
            "4096",
            path.to_str().unwrap(),
        ])
        .output()
        .expect("run fallocate --punch-hole --keep-size for seek test");
    assert!(
        out.status.success(),
        "seek-layout punch-hole failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let readback = fs::read(path).expect("read punched-hole seek test file");
    assert_eq!(
        &readback[..4096],
        &data[..4096],
        "seek test prefix must be preserved"
    );
    assert!(
        readback[4096..8192].iter().all(|&byte| byte == 0),
        "seek test middle hole must read back as zeros"
    );
    assert_eq!(
        &readback[8192..],
        &data[8192..],
        "seek test suffix must be preserved"
    );

    let data0 = query_seek(path, 0, "SEEK_DATA");
    if let Some(errno) = data0["errno"].as_i64() {
        if errno == i64::from(libc::EINVAL)
            || errno == i64::from(libc::ENOSYS)
            || errno == EOPNOTSUPP_ERRNO
        {
            eprintln!(
                "SEEK_DATA/SEEK_HOLE skipped: current kernel/FUSE stack reports errno {errno} \
                 before FrankenFS can prove mounted seek semantics"
            );
            return;
        }
    }

    assert_eq!(
        data0["offset"].as_u64(),
        Some(0),
        "SEEK_DATA at file start should return the first data byte: {data0}"
    );

    let hole0 = query_seek(path, 0, "SEEK_HOLE");
    assert_eq!(
        hole0["offset"].as_u64(),
        Some(4096),
        "SEEK_HOLE from file start should stop at the punched range: {hole0}"
    );

    let data_middle = query_seek(path, 4096, "SEEK_DATA");
    assert_eq!(
        data_middle["offset"].as_u64(),
        Some(8192),
        "SEEK_DATA from inside the punched range should advance to the next extent: {data_middle}"
    );

    let hole_middle = query_seek(path, 4096, "SEEK_HOLE");
    assert_eq!(
        hole_middle["offset"].as_u64(),
        Some(4096),
        "SEEK_HOLE from the punched range should return the hole start: {hole_middle}"
    );

    let hole_tail = query_seek(path, 8192, "SEEK_HOLE");
    assert_eq!(
        hole_tail["offset"].as_u64(),
        Some(data.len() as u64),
        "SEEK_HOLE from the tail extent should report the virtual EOF hole: {hole_tail}"
    );

    let eof_data = query_seek(path, data.len() as u64, "SEEK_DATA");
    assert_eq!(
        eof_data["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA at EOF should surface ENXIO: {eof_data}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("punch_hole_seek_offsets_verified"),
    );
}

fn seek_transport_skipped(report: &Value) -> bool {
    report["errno"].as_i64().is_some_and(|errno| {
        errno == i64::from(libc::EINVAL)
            || errno == i64::from(libc::ENOSYS)
            || errno == EOPNOTSUPP_ERRNO
    })
}

fn assert_seek_fully_allocated_contract(path: &Path, scenario_id: &str) {
    let data = patterned_bytes(8192, 251, 1);
    fs::write(path, &data).expect("seed fully allocated seek test file");

    let data0 = query_seek(path, 0, "SEEK_DATA");
    if seek_transport_skipped(&data0) {
        eprintln!(
            "SEEK_DATA/SEEK_HOLE skipped: current kernel/FUSE stack reports transport-layer \
             rejection before FrankenFS can prove fully allocated seek semantics: {data0}"
        );
        return;
    }

    assert_eq!(
        data0["offset"].as_u64(),
        Some(0),
        "SEEK_DATA at file start should return the first byte of a fully allocated file: {data0}"
    );

    let data_middle = query_seek(path, 4096, "SEEK_DATA");
    assert_eq!(
        data_middle["offset"].as_u64(),
        Some(4096),
        "SEEK_DATA inside a fully allocated extent should return the queried offset: {data_middle}"
    );

    let hole0 = query_seek(path, 0, "SEEK_HOLE");
    assert_eq!(
        hole0["offset"].as_u64(),
        Some(data.len() as u64),
        "SEEK_HOLE from file start should report the virtual EOF hole on a fully allocated file: {hole0}"
    );

    let hole_middle = query_seek(path, 4096, "SEEK_HOLE");
    assert_eq!(
        hole_middle["offset"].as_u64(),
        Some(data.len() as u64),
        "SEEK_HOLE inside a fully allocated extent should report the virtual EOF hole: {hole_middle}"
    );

    let eof_data = query_seek(path, data.len() as u64, "SEEK_DATA");
    assert_eq!(
        eof_data["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA at EOF should surface ENXIO on a fully allocated file: {eof_data}"
    );

    let eof_hole = query_seek(path, data.len() as u64, "SEEK_HOLE");
    assert_eq!(
        eof_hole["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_HOLE at EOF should surface ENXIO on a fully allocated file: {eof_hole}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("fully_allocated_seek_offsets_verified"),
    );
}

fn assert_seek_leading_hole_contract(path: &Path, scenario_id: &str) {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    let data = patterned_bytes(8192, 253, 1);
    fs::write(path, &data).expect("seed leading-hole seek test file");

    let out = Command::new("fallocate")
        .args([
            "--keep-size",
            "--punch-hole",
            "-o",
            "0",
            "-l",
            "4096",
            path.to_str().expect("path utf8"),
        ])
        .output()
        .expect("run fallocate --punch-hole for leading-hole seek test");
    assert!(
        out.status.success(),
        "leading-hole punch-hole failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let readback = fs::read(path).expect("read leading-hole seek test file");
    assert_eq!(
        readback.len(),
        8192,
        "leading-hole seek test file should be sparse with a 4KiB hole prefix"
    );
    assert!(
        readback[..4096].iter().all(|&byte| byte == 0),
        "leading-hole seek test prefix must read back as zeros"
    );
    assert_eq!(
        &readback[4096..],
        &data[4096..],
        "leading-hole seek test suffix must preserve written payload"
    );

    let data0 = query_seek(path, 0, "SEEK_DATA");
    if seek_transport_skipped(&data0) {
        eprintln!(
            "SEEK_DATA/SEEK_HOLE skipped: current kernel/FUSE stack reports transport-layer \
             rejection before FrankenFS can prove leading-hole seek semantics: {data0}"
        );
        return;
    }

    assert_eq!(
        data0["offset"].as_u64(),
        Some(4096),
        "SEEK_DATA from file start should advance to the first real extent after a leading hole: {data0}"
    );

    let hole0 = query_seek(path, 0, "SEEK_HOLE");
    assert_eq!(
        hole0["offset"].as_u64(),
        Some(0),
        "SEEK_HOLE from file start should report the leading sparse hole immediately: {hole0}"
    );

    let data_middle = query_seek(path, 1024, "SEEK_DATA");
    assert_eq!(
        data_middle["offset"].as_u64(),
        Some(4096),
        "SEEK_DATA from inside the leading hole should advance to the first data extent: {data_middle}"
    );

    let hole_middle = query_seek(path, 1024, "SEEK_HOLE");
    assert_eq!(
        hole_middle["offset"].as_u64(),
        Some(1024),
        "SEEK_HOLE from inside the leading hole should return the queried hole offset: {hole_middle}"
    );

    let hole_data_region = query_seek(path, 4096, "SEEK_HOLE");
    assert_eq!(
        hole_data_region["offset"].as_u64(),
        Some(readback.len() as u64),
        "SEEK_HOLE from the data extent should report the virtual EOF hole: {hole_data_region}"
    );

    let eof_data = query_seek(path, readback.len() as u64, "SEEK_DATA");
    assert_eq!(
        eof_data["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA at EOF should surface ENXIO on a leading-hole file: {eof_data}"
    );

    let eof_hole = query_seek(path, readback.len() as u64, "SEEK_HOLE");
    assert_eq!(
        eof_hole["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_HOLE at EOF should surface ENXIO on a leading-hole file: {eof_hole}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("leading_hole_seek_offsets_verified"),
    );
}

fn assert_seek_all_hole_contract(path: &Path, scenario_id: &str) {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .expect("create all-hole seek test file");
    file.set_len(8192)
        .expect("set logical size for all-hole seek test file");
    drop(file);

    let readback = fs::read(path).expect("read all-hole seek test file");
    assert_eq!(
        readback.len(),
        8192,
        "all-hole seek test file should preserve its logical size"
    );
    assert!(
        readback.iter().all(|&byte| byte == 0),
        "all-hole seek test file must read back as zeros"
    );

    let data0 = query_seek(path, 0, "SEEK_DATA");
    if seek_transport_skipped(&data0) {
        eprintln!(
            "SEEK_DATA/SEEK_HOLE skipped: current kernel/FUSE stack reports transport-layer \
             rejection before FrankenFS can prove all-hole seek semantics: {data0}"
        );
        return;
    }

    assert_eq!(
        data0["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA from file start should surface ENXIO on an all-hole file: {data0}"
    );

    let hole0 = query_seek(path, 0, "SEEK_HOLE");
    assert_eq!(
        hole0["offset"].as_u64(),
        Some(0),
        "SEEK_HOLE from file start should report the all-hole sparse range immediately: {hole0}"
    );

    let data_middle = query_seek(path, 4096, "SEEK_DATA");
    assert_eq!(
        data_middle["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA from inside an all-hole file should still surface ENXIO: {data_middle}"
    );

    let hole_middle = query_seek(path, 4096, "SEEK_HOLE");
    assert_eq!(
        hole_middle["offset"].as_u64(),
        Some(4096),
        "SEEK_HOLE from inside an all-hole file should return the queried hole offset: {hole_middle}"
    );

    let eof_data = query_seek(path, readback.len() as u64, "SEEK_DATA");
    assert_eq!(
        eof_data["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_DATA at EOF should surface ENXIO on an all-hole file: {eof_data}"
    );

    let eof_hole = query_seek(path, readback.len() as u64, "SEEK_HOLE");
    assert_eq!(
        eof_hole["errno"].as_i64(),
        Some(i64::from(libc::ENXIO)),
        "SEEK_HOLE at EOF should surface ENXIO on an all-hole file: {eof_hole}"
    );

    emit_scenario_result(scenario_id, "PASS", Some("all_hole_seek_offsets_verified"));
}

#[test]
fn fuse_create_and_read_file() {
    with_rw_mount(|mnt| {
        let path = mnt.join("newfile.txt");
        fs::write(&path, b"Created via FUSE write path!\n").expect("create file via FUSE");

        let content = fs::read_to_string(&path).expect("read back created file");
        assert_eq!(content, "Created via FUSE write path!\n");

        let meta = fs::metadata(&path).expect("stat created file");
        assert!(meta.is_file());
        assert_eq!(meta.len(), 29);
    });
}

#[test]
fn fuse_write_overwrite_and_append() {
    with_rw_mount(|mnt| {
        let path = mnt.join("overwrite.txt");

        // Write initial content.
        fs::write(&path, b"initial").expect("write initial");
        assert_eq!(fs::read_to_string(&path).expect("read initial"), "initial");

        // Overwrite with longer content.
        fs::write(&path, b"overwritten content").expect("overwrite");
        assert_eq!(
            fs::read_to_string(&path).expect("read overwritten"),
            "overwritten content"
        );

        // Append additional content.
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        file.write_all(b" + appended").expect("append write");
        drop(file);
        assert_eq!(
            fs::read_to_string(&path).expect("read appended"),
            "overwritten content + appended"
        );
    });
}

#[test]
fn fuse_write_with_offset_extends_file_and_zero_fills_gap() {
    with_rw_mount(|mnt| {
        let path = mnt.join("offset_write.bin");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .expect("create offset_write.bin");

        file.seek(SeekFrom::Start(8))
            .expect("seek to sparse offset");
        file.write_all(b"abc").expect("write payload at offset");
        drop(file);

        let bytes = fs::read(&path).expect("read sparse write result");
        assert_eq!(bytes.len(), 11);
        assert_eq!(&bytes[..8], vec![0_u8; 8].as_slice());
        assert_eq!(&bytes[8..], b"abc");
    });
}

#[test]
fn fuse_write_to_directory_reports_eisdir() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_write_to_directory_errno_eisdir";
        let dir = mnt.join("ext4_write_dir");
        fs::create_dir(&dir).expect("mkdir ext4 write directory target");
        let child = dir.join("child.txt");
        fs::write(&child, b"directory child stays intact\n")
            .expect("seed ext4 write directory child");

        let entries_before = snapshot_directory_entries(&dir);
        let child_before = snapshot_file_state(&child);

        let err = fs::OpenOptions::new()
            .write(true)
            .open(&dir)
            .expect_err("opening a directory for write should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EISDIR),
            "opening a directory for write should surface exact EISDIR: {err}"
        );
        assert!(
            dir.is_dir(),
            "directory-write rejection must leave the directory in place"
        );
        assert_eq!(
            snapshot_directory_entries(&dir),
            entries_before,
            "directory-write rejection must not change directory entries"
        );
        assert_file_state_unchanged(&child, &child_before, "directory write rejection");
        emit_scenario_result(scenario_id, "PASS", Some("open=EISDIR_no_drift"));
    });
}

#[test]
fn fuse_mkdir_and_nested_create() {
    with_rw_mount(|mnt| {
        let dir = mnt.join("newdir");
        fs::create_dir(&dir).expect("mkdir via FUSE");

        let meta = fs::metadata(&dir).expect("stat newdir");
        assert!(meta.is_dir());

        // Create a file inside the new directory.
        let nested = dir.join("inner.txt");
        fs::write(&nested, b"nested content\n").expect("write nested file");

        let content = fs::read_to_string(&nested).expect("read nested file");
        assert_eq!(content, "nested content\n");
    });
}

#[test]
fn fuse_mkdir_existing_directory_fails() {
    with_rw_mount(|mnt| {
        let dir = mnt.join("already_there");
        fs::create_dir(&dir).expect("initial mkdir should succeed");

        let err = fs::create_dir(&dir).expect_err("mkdir existing should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    });
}

#[test]
fn fuse_create_and_mkdir_under_non_directory_parent_report_enotdir() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_create_and_mkdir_under_non_directory_parent";
        let regular_parent = mnt.join("hello.txt");
        let root_entries_before = snapshot_directory_entries(mnt);
        let parent_before = snapshot_file_state(&regular_parent);

        let create_target = regular_parent.join("child.txt");
        let create_err = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&create_target)
            .expect_err("create beneath regular-file parent should fail");
        assert_eq!(
            create_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "create beneath a regular-file parent should surface exact ENOTDIR: {create_err}"
        );
        assert!(
            fs::symlink_metadata(&create_target).is_err(),
            "rejected create must not leave a nested child entry behind"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected create must not change visible root entries"
        );
        assert_file_state_unchanged(
            &regular_parent,
            &parent_before,
            "non-directory parent after rejected create",
        );

        let mkdir_target = regular_parent.join("child_dir");
        let mkdir_err = fs::create_dir(&mkdir_target)
            .expect_err("mkdir beneath regular-file parent should fail");
        assert_eq!(
            mkdir_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "mkdir beneath a regular-file parent should surface exact ENOTDIR: {mkdir_err}"
        );
        assert!(
            fs::symlink_metadata(&mkdir_target).is_err(),
            "rejected mkdir must not leave a nested directory entry behind"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected mkdir must not change visible root entries"
        );
        assert_file_state_unchanged(
            &regular_parent,
            &parent_before,
            "non-directory parent after rejected mkdir",
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("create=ENOTDIR_mkdir=ENOTDIR_no_drift"),
        );
    });
}

#[test]
fn fuse_unlink_removes_file() {
    with_rw_mount(|mnt| {
        // hello.txt exists from create_test_image.
        let path = mnt.join("hello.txt");
        assert!(path.exists(), "hello.txt should exist before unlink");

        fs::remove_file(&path).expect("unlink hello.txt via FUSE");
        assert!(!path.exists(), "hello.txt should be gone after unlink");
    });
}

#[test]
fn fuse_rmdir_missing_directory_fails() {
    with_rw_mount(|mnt| {
        let missing = mnt.join("no_such_dir");
        let err = fs::remove_dir(&missing).expect_err("rmdir missing should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    });
}

#[test]
fn fuse_rmdir_removes_empty_directory() {
    with_rw_mount(|mnt| {
        let dir = mnt.join("empty_dir");
        fs::create_dir(&dir).expect("mkdir empty_dir");
        assert!(dir.exists());

        fs::remove_dir(&dir).expect("rmdir empty_dir via FUSE");
        assert!(!dir.exists(), "empty_dir should be gone after rmdir");
    });
}

#[test]
fn fuse_rmdir_on_file_reports_enotdir() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_rmdir_on_file_reports_enotdir";
        let path = mnt.join("hello.txt");
        let original_bytes = fs::read(&path).expect("read hello.txt before rmdir-on-file");

        let err = fs::remove_dir(&path).expect_err("rmdir on regular file should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOTDIR),
            "rmdir on a regular file should surface exact ENOTDIR: {err}"
        );
        assert!(
            path.is_file(),
            "failed rmdir on regular file must leave the file in place"
        );
        assert_eq!(
            fs::read(&path).expect("read hello.txt after failed rmdir-on-file"),
            original_bytes,
            "failed rmdir on regular file must not mutate file contents"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=ENOTDIR_no_drift"));
    });
}

#[test]
fn fuse_unlink_directory_reports_eisdir() {
    with_rw_mount(|mnt| {
        assert_unlink_directory_via_remove_file_reports_eisdir(
            mnt,
            "ext4_rw_unlink_directory_reports_eisdir",
        );
    });
}

#[test]
fn fuse_mkdir_rmdir_parent_nlink_accounting() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_mkdir_rmdir_parent_nlink_accounting";
        let parent = mnt;
        let child_name = "nlink-accounting-dir";
        let child = parent.join(child_name);
        let parent_entries_before = snapshot_directory_entries(parent);
        let parent_nlink_before = fs::metadata(parent)
            .expect("stat parent before mkdir")
            .nlink();

        assert!(
            !parent_entries_before.contains(child_name),
            "test directory name should be absent before mkdir"
        );

        fs::create_dir(&child).expect("mkdir child directory");

        let parent_nlink_after_mkdir = fs::metadata(parent)
            .expect("stat parent after mkdir")
            .nlink();
        let child_nlink_after_mkdir = fs::metadata(&child)
            .expect("stat child after mkdir")
            .nlink();
        let mut parent_entries_expected_after_mkdir = parent_entries_before.clone();
        parent_entries_expected_after_mkdir.insert(child_name.to_string());
        assert_eq!(
            parent_nlink_after_mkdir,
            parent_nlink_before + 1,
            "mkdir must increment parent st_nlink by one for the new child directory"
        );
        assert_eq!(
            child_nlink_after_mkdir, 2,
            "new directory must expose the canonical '.'/'..' link count"
        );
        assert_eq!(
            snapshot_directory_entries(parent),
            parent_entries_expected_after_mkdir,
            "mkdir must add exactly one visible root entry"
        );

        fs::remove_dir(&child).expect("rmdir child directory");

        let parent_nlink_after_rmdir = fs::metadata(parent)
            .expect("stat parent after rmdir")
            .nlink();
        assert_eq!(
            parent_nlink_after_rmdir, parent_nlink_before,
            "rmdir must restore the parent st_nlink once the child directory is gone"
        );
        assert_eq!(
            snapshot_directory_entries(parent),
            parent_entries_before,
            "rmdir must restore the visible parent entries to baseline"
        );
        assert!(
            fs::symlink_metadata(&child).is_err(),
            "removed child directory must no longer be visible"
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("mkdir_parent_nlink_plus_one_rmdir_restored"),
        );
    });
}

#[test]
fn fuse_rmdir_non_empty_fails() {
    with_rw_mount(|mnt| {
        let dir = mnt.join("non_empty_dir");
        fs::create_dir(&dir).expect("mkdir non_empty_dir");
        fs::write(dir.join("child.txt"), b"child").expect("create child in non_empty_dir");

        let err = fs::remove_dir(&dir).expect_err("rmdir non-empty should fail");
        assert_eq!(err.kind(), std::io::ErrorKind::DirectoryNotEmpty);
        assert!(
            dir.exists(),
            "directory should still exist after failed rmdir"
        );
    });
}

#[test]
fn fuse_rename_over_existing_destination_replaces_target() {
    with_rw_mount(|mnt| {
        let src = mnt.join("src.txt");
        let dst = mnt.join("dst.txt");
        fs::write(&src, b"from-src").expect("write src");
        fs::write(&dst, b"stale-dst").expect("write existing dst");

        fs::rename(&src, &dst).expect("rename over existing destination");
        assert!(!src.exists(), "source path should be removed");
        assert_eq!(
            fs::read_to_string(&dst).expect("read replaced dst"),
            "from-src"
        );
    });
}

#[test]
fn fuse_rename_file() {
    with_rw_mount(|mnt| {
        let old = mnt.join("hello.txt");
        let new = mnt.join("renamed.txt");
        assert!(old.exists());

        fs::rename(&old, &new).expect("rename via FUSE");
        assert!(!old.exists(), "old name should be gone");
        assert!(new.exists(), "new name should exist");

        let content = fs::read_to_string(&new).expect("read renamed file");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");
    });
}

#[test]
fn fuse_rename_across_directories() {
    with_rw_mount(|mnt| {
        let src = mnt.join("hello.txt");
        let dst = mnt.join("testdir/moved.txt");
        assert!(src.exists());

        fs::rename(&src, &dst).expect("rename across dirs via FUSE");
        assert!(!src.exists());

        let content = fs::read_to_string(&dst).expect("read moved file");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");
    });
}

#[test]
fn fuse_rename_over_same_inode_hardlink_is_noop() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_rename_over_same_inode_hardlink_noop";
        let original = mnt.join("original.txt");
        let alias = mnt.join("alias.txt");
        fs::write(&original, b"same inode rename\n").expect("write original");
        fs::hard_link(&original, &alias).expect("create alias hard link");

        let entries_before = snapshot_directory_entries(mnt);
        let alias_before = snapshot_file_state(&alias);
        let original_ino_before = fs::metadata(&original).expect("stat original").ino();
        let alias_meta_before = fs::metadata(&alias).expect("stat alias");
        assert_eq!(
            alias_meta_before.ino(),
            original_ino_before,
            "hard link should point at the same inode before rename"
        );
        assert_eq!(
            alias_meta_before.nlink(),
            2,
            "same-inode rename precondition should have two names"
        );

        fs::rename(&original, &alias).expect("rename over same-inode hard link");

        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "same-inode rename should be a visible no-op"
        );
        assert!(
            fs::symlink_metadata(&original).is_ok(),
            "source name should still resolve after same-inode rename"
        );
        assert_file_state_unchanged(&alias, &alias_before, "same-inode rename alias");
        assert_file_state_unchanged(&original, &alias_before, "same-inode rename source");

        let alias_meta_after = fs::metadata(&alias).expect("stat alias after rename");
        assert_eq!(
            alias_meta_after.ino(),
            original_ino_before,
            "destination should keep the original inode"
        );
        assert_eq!(
            alias_meta_after.nlink(),
            2,
            "same-inode rename should preserve the shared link count"
        );
        let original_meta_after = fs::metadata(&original).expect("stat source after rename");
        assert_eq!(
            original_meta_after.ino(),
            original_ino_before,
            "source should still resolve to the original inode"
        );
        assert_eq!(
            original_meta_after.nlink(),
            2,
            "source should keep the shared link count after same-inode rename"
        );
        emit_scenario_result(scenario_id, "PASS", Some("visible_noop_nlink=2"));
    });
}

#[test]
fn fuse_rename_same_name_is_noop() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_rename_same_name_noop";
        let path = mnt.join("same-name.txt");
        fs::write(&path, b"same name rename\n").expect("write rename same-name seed");

        let entries_before = snapshot_directory_entries(mnt);
        let before = snapshot_file_state(&path);
        let ino_before = fs::metadata(&path)
            .expect("stat before same-name rename")
            .ino();

        fs::rename(&path, &path).expect("rename same name should succeed");

        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "same-name rename should not change directory entries"
        );
        assert_file_state_unchanged(&path, &before, "same-name rename");

        let ino_after = fs::metadata(&path)
            .expect("stat after same-name rename")
            .ino();
        assert_eq!(
            ino_after, ino_before,
            "same-name rename should preserve the inode binding"
        );

        emit_scenario_result(scenario_id, "PASS", Some("visible_noop"));
    });
}

#[test]
fn fuse_rename_file_directory_type_mismatch_reports_eisdir_and_enotdir() {
    with_rw_mount(|mnt| {
        assert_rename_file_directory_type_mismatch_contract(
            mnt,
            "ext4_rw_rename_file_directory_type_mismatch",
        );
    });
}

#[test]
fn fuse_renameat2_flag_rejection_reports_einval() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_renameat2_flag_rejection";
        if !command_available("python3") {
            eprintln!("python3 not available, skipping");
            return;
        }

        let noreplace_src = mnt.join("renameat2-noreplace-src.txt");
        let noreplace_dst = mnt.join("renameat2-noreplace-dst.txt");
        let exchange_src = mnt.join("renameat2-exchange-src.txt");
        let exchange_dst = mnt.join("renameat2-exchange-dst.txt");

        fs::write(&noreplace_src, b"noreplace src\n").expect("write renameat2 noreplace src");
        fs::write(&exchange_src, b"exchange src\n").expect("write renameat2 exchange src");
        fs::write(&exchange_dst, b"exchange dst\n").expect("write renameat2 exchange dst");

        let root_entries_before = snapshot_directory_entries(mnt);
        let noreplace_src_before = snapshot_file_state(&noreplace_src);
        let exchange_src_before = snapshot_file_state(&exchange_src);
        let exchange_dst_before = snapshot_file_state(&exchange_dst);

        let noreplace_report =
            py_renameat2_report(&noreplace_src, &noreplace_dst, libc::RENAME_NOREPLACE);
        assert_eq!(
            noreplace_report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "renameat2(RENAME_NOREPLACE) should surface exact EINVAL: {noreplace_report:?}"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected RENAME_NOREPLACE must not change visible root entries"
        );
        assert_file_state_unchanged(
            &noreplace_src,
            &noreplace_src_before,
            "renameat2 RENAME_NOREPLACE source",
        );
        assert!(
            fs::symlink_metadata(&noreplace_dst).is_err(),
            "rejected RENAME_NOREPLACE must not create a new destination entry"
        );

        let exchange_report =
            py_renameat2_report(&exchange_src, &exchange_dst, libc::RENAME_EXCHANGE);
        assert_eq!(
            exchange_report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "renameat2(RENAME_EXCHANGE) should surface exact EINVAL: {exchange_report:?}"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected RENAME_EXCHANGE must not change visible root entries"
        );
        assert_file_state_unchanged(
            &exchange_src,
            &exchange_src_before,
            "renameat2 RENAME_EXCHANGE source",
        );
        assert_file_state_unchanged(
            &exchange_dst,
            &exchange_dst_before,
            "renameat2 RENAME_EXCHANGE destination",
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("noreplace=EINVAL_exchange=EINVAL_no_drift"),
        );
    });
}

#[test]
fn fuse_hard_link() {
    with_rw_mount(|mnt| {
        let original = mnt.join("hello.txt");
        let link = mnt.join("hello_link.txt");

        fs::hard_link(&original, &link).expect("hard link via FUSE");

        let content = fs::read_to_string(&link).expect("read through hard link");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");

        // Both should share the same inode.
        let orig_ino = fs::metadata(&original).expect("stat original").ino();
        let link_ino = fs::metadata(&link).expect("stat link").ino();
        assert_eq!(orig_ino, link_ino, "hard link should share inode");
        let orig_nlink = fs::metadata(&original).expect("stat original").nlink();
        let link_nlink = fs::metadata(&link).expect("stat link").nlink();
        assert_eq!(orig_nlink, 2, "original should report two hard links");
        assert_eq!(link_nlink, 2, "link should report two hard links");
    });
}

#[test]
fn fuse_symlink_create_and_follow() {
    with_rw_mount(|mnt| {
        let target = mnt.join("hello.txt");
        let link = mnt.join("sym.txt");

        std::os::unix::fs::symlink("hello.txt", &link).expect("symlink via FUSE");

        // Verify readlink returns the target.
        let read_target = fs::read_link(&link).expect("readlink via FUSE");
        assert_eq!(read_target.to_str().unwrap(), "hello.txt");

        // Following the symlink should work.
        let content = fs::read_to_string(&link).expect("read through new symlink");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");

        // Symlink metadata should differ from target.
        let link_meta = fs::symlink_metadata(&link).expect("lstat symlink");
        assert!(link_meta.file_type().is_symlink());
        let _ = target; // used implicitly via symlink follow
    });
}

#[test]
fn fuse_readlink_on_non_symlink_reports_einval() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_readlink_on_non_symlink_reports_einval";
        let file_path = mnt.join("hello.txt");
        let dir_path = mnt.join("testdir");
        let root_entries_before = snapshot_directory_entries(mnt);
        let file_before = snapshot_file_state(&file_path);
        let dir_entries_before = snapshot_directory_entries(&dir_path);

        let file_err = fs::read_link(&file_path).expect_err("readlink on regular file should fail");
        assert_eq!(
            file_err.raw_os_error(),
            Some(libc::EINVAL),
            "readlink on regular file should surface exact EINVAL: {file_err}"
        );
        assert_file_state_unchanged(
            &file_path,
            &file_before,
            "readlink rejection on regular file",
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected readlink on regular file must not change root entries"
        );

        let dir_err = fs::read_link(&dir_path).expect_err("readlink on directory should fail");
        assert_eq!(
            dir_err.raw_os_error(),
            Some(libc::EINVAL),
            "readlink on directory should surface exact EINVAL: {dir_err}"
        );
        assert_eq!(
            snapshot_directory_entries(&dir_path),
            dir_entries_before,
            "rejected readlink on directory must not change directory entries"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected readlink on directory must not change root entries"
        );
        emit_scenario_result(scenario_id, "PASS", Some("file+dir_errno=EINVAL_no_drift"));
    });
}

#[test]
fn fuse_setattr_truncate() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_len = fs::metadata(&path).expect("stat").len();
        assert!(original_len > 0);

        // Truncate to 5 bytes.
        let f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate");
        f.set_len(5).expect("truncate via FUSE");
        drop(f);

        let new_len = fs::metadata(&path).expect("stat after truncate").len();
        assert_eq!(new_len, 5, "file should be truncated to 5 bytes");

        let content = fs::read_to_string(&path).expect("read truncated file");
        assert_eq!(content, "Hello");
    });
}

#[test]
fn fuse_setattr_chmod() {
    with_rw_mount(|mnt| {
        // hello.txt exists from create_test_image.
        let path = mnt.join("hello.txt");
        let orig_meta = fs::metadata(&path).expect("stat hello.txt");
        let orig_mode = orig_meta.permissions().mode() & 0o7777;

        // Change to 0o755.
        let new_perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&path, new_perms).expect("chmod 755 via FUSE");

        let meta = fs::metadata(&path).expect("stat after chmod");
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o755,
            "permissions should be 0o755 after chmod (were 0o{orig_mode:o})"
        );

        // Change to 0o600.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod 600 via FUSE");

        let meta = fs::metadata(&path).expect("stat after second chmod");
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o600,
            "permissions should be 0o600 after second chmod"
        );

        // File should still be readable/writable by us since we own it.
        let content = fs::read_to_string(&path).expect("read after chmod");
        assert_eq!(content, "Hello from FrankenFS E2E!\n");
    });
}

#[test]
#[ignore = "requires /dev/fuse and root for chown"]
#[allow(clippy::similar_names)] // uid/gid are naturally similar
fn fuse_setattr_chown() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let meta = fs::metadata(&path).expect("stat hello.txt");
        let owner_uid = meta.uid();
        let owner_gid = meta.gid();

        // Try to chown to the same uid/gid (should always succeed even without CAP_CHOWN).
        let script = format!(
            "import os; os.chown({path:?}, {uid}, {gid})",
            path = path.to_str().unwrap(),
            uid = owner_uid,
            gid = owner_gid,
        );
        let out = Command::new("python3")
            .args(["-c", &script])
            .output()
            .expect("python3 chown");
        assert!(
            out.status.success(),
            "chown to same uid/gid failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Verify uid/gid are unchanged.
        let meta2 = fs::metadata(&path).expect("stat after no-op chown");
        assert_eq!(meta2.uid(), owner_uid);
        assert_eq!(meta2.gid(), owner_gid);

        // Attempt chown to uid 65534 (nobody). This requires CAP_CHOWN;
        // skip the assertion if we get EPERM (non-root environment).
        let script2 = format!(
            "import os\ntry:\n    os.chown({path:?}, 65534, 65534)\n    print('OK')\nexcept PermissionError:\n    print('EPERM')",
            path = path.to_str().unwrap(),
        );
        let out2 = Command::new("python3")
            .args(["-c", &script2])
            .output()
            .expect("python3 chown to nobody");
        assert!(out2.status.success());
        let result = String::from_utf8_lossy(&out2.stdout);
        if result.trim() == "OK" {
            let meta3 = fs::metadata(&path).expect("stat after chown to nobody");
            assert_eq!(meta3.uid(), 65534, "uid should be 65534 after chown");
            assert_eq!(meta3.gid(), 65534, "gid should be 65534 after chown");
        }
        // If EPERM, the test passes silently — chown path was exercised.
    });
}

#[test]
fn fuse_setattr_utimes() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Use Python os.utime to set atime and mtime to a known epoch.
        let script = format!(
            "import os; os.utime({path:?}, (1_700_000_000, 1_700_000_000))",
            path = path.to_str().unwrap(),
        );
        let out = Command::new("python3")
            .args(["-c", &script])
            .output()
            .expect("python3 utime");
        assert!(
            out.status.success(),
            "os.utime failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after utime");
        // atime and mtime should both be 1_700_000_000.
        assert_eq!(
            meta.atime(),
            1_700_000_000,
            "atime should be 1700000000 after os.utime"
        );
        assert_eq!(
            meta.mtime(),
            1_700_000_000,
            "mtime should be 1700000000 after os.utime"
        );

        // Set different atime and mtime values.
        let script2 = format!(
            "import os; os.utime({path:?}, (1_600_000_000, 1_650_000_000))",
            path = path.to_str().unwrap(),
        );
        let out2 = Command::new("python3")
            .args(["-c", &script2])
            .output()
            .expect("python3 utime second");
        assert!(
            out2.status.success(),
            "os.utime (second) failed: {}",
            String::from_utf8_lossy(&out2.stderr)
        );

        let meta2 = fs::metadata(&path).expect("stat after second utime");
        assert_eq!(meta2.atime(), 1_600_000_000, "atime should be 1600000000");
        assert_eq!(meta2.mtime(), 1_650_000_000, "mtime should be 1650000000");
    });
}

#[test]
fn fuse_setattr_read_only_rejects_chmod_truncate_and_utimes_with_erofs() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    assert_read_only_setattr_contract(
        &mnt.join("hello.txt"),
        "ext4_ro_setattr_rejects_erofs_no_drift",
    );
}

#[test]
fn fuse_read_only_unlink_rmdir_and_rename_report_erofs_without_dirent_drift() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_seeded_namespace_removal_fixture(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    let keep_file = mnt.join("readonly_unlink_seed.txt");
    let empty_dir = mnt.join("readonly_empty_dir");
    let rename_source = mnt.join("readonly_rename_source.txt");
    assert_eq!(
        fs::read(&keep_file).expect("read seeded ext4 unlink file"),
        b"readonly ext4 unlink seed\n",
        "read-only remount must preserve the seeded unlink target bytes"
    );
    assert_eq!(
        fs::read(&rename_source).expect("read seeded ext4 rename source file"),
        b"readonly ext4 rename source\n",
        "read-only remount must preserve the seeded rename source bytes"
    );
    assert!(
        empty_dir.is_dir(),
        "read-only remount must preserve the seeded empty directory"
    );

    assert_read_only_unlink_rmdir_and_rename_contract(
        &mnt,
        &keep_file,
        &empty_dir,
        &rename_source,
        "ext4_ro_unlink_rmdir_rename_reject_erofs_no_drift",
    );
}

#[test]
fn fuse_read_only_fallocate_mutation_attempts_report_erofs_without_file_drift() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    let scenario_id = "ext4_ro_fallocate_mutation_attempts_reject_erofs_no_drift";
    let path = mnt.join("hello.txt");
    let before = snapshot_file_state(&path);

    let preallocate_report = py_fallocate_report(&path, 0, 0, before.len + 4096);
    assert_eq!(
        preallocate_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only preallocate should surface exact EROFS: {preallocate_report}"
    );
    assert_file_state_unchanged(&path, &before, "rejected read-only preallocate");

    let punch_hole_report = py_fallocate_report(
        &path,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
        0,
        before.len.min(8),
    );
    assert_eq!(
        punch_hole_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only punch-hole should surface exact EROFS: {punch_hole_report}"
    );
    assert_file_state_unchanged(&path, &before, "rejected read-only punch-hole");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("preallocate+punch_hole=EROFS_no_file_drift"),
    );
}

#[test]
fn ext4_fuse_fallocate_preallocate_extends_size() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_preallocate_extends_size";
        let path = mnt.join("preallocated.bin");
        fs::write(&path, b"").expect("create empty file");

        let out = Command::new("fallocate")
            .args(["-l", "8192", path.to_str().unwrap()])
            .output()
            .expect("fallocate command");
        assert!(
            out.status.success(),
            "fallocate failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after fallocate");
        assert_eq!(
            meta.len(),
            8192,
            "file apparent size should be 8192 after fallocate"
        );
        assert!(
            meta.blocks() * 512 >= 8192,
            "allocated disk space ({}*512={}) should be >= 8192",
            meta.blocks(),
            meta.blocks() * 512
        );

        fs::write(&path, b"data in preallocated space").expect("write to preallocated");
        let content = fs::read_to_string(&path).expect("read preallocated");
        assert_eq!(content, "data in preallocated space");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn ext4_fuse_fallocate_keep_size_preserves_size() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_keep_size_preserves_size";
        let path = mnt.join("keepsize.bin");
        fs::write(&path, b"short").expect("create file with content");

        let out = Command::new("fallocate")
            .args(["-l", "16384", "--keep-size", path.to_str().unwrap()])
            .output()
            .expect("fallocate keep-size");
        assert!(
            out.status.success(),
            "fallocate --keep-size failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after keep-size fallocate");
        assert_eq!(
            meta.len(),
            5,
            "file size should remain 5 with KEEP_SIZE flag"
        );
        assert!(
            meta.blocks() * 512 >= 16384,
            "allocated disk space ({}*512={}) should be >= 16384 after keep-size fallocate",
            meta.blocks(),
            meta.blocks() * 512
        );

        let content = fs::read_to_string(&path).expect("read after keep-size");
        assert_eq!(content, "short");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn ext4_fuse_fallocate_zero_range_zeroes_range() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_zero_range_zeroes_range";
        let path = mnt.join("ext4_zero_range.bin");
        let data = patterned_bytes(12_288, 253, 1);
        fs::write(&path, &data).expect("seed zero-range file on ext4");

        let out = Command::new("fallocate")
            .args([
                "--zero-range",
                "-o",
                "4096",
                "-l",
                "4096",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("run fallocate --zero-range on ext4");
        assert!(
            out.status.success(),
            "ext4 zero-range failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after ext4 zero-range");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "zero-range must preserve file size"
        );

        let readback = fs::read(&path).expect("read after ext4 zero-range");
        assert_eq!(&readback[..4096], &data[..4096], "prefix must be preserved");
        assert!(
            readback[4096..8192].iter().all(|&byte| byte == 0),
            "zero-range span must read back as zeros"
        );
        assert_eq!(&readback[8192..], &data[8192..], "suffix must be preserved");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn ext4_fuse_fallocate_punch_hole_keep_size_zeroes_range() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_punch_hole_keep_size_zeroes_range";
        let path = mnt.join("ext4_punch_hole.bin");
        let data = patterned_bytes(12_288, 251, 1);
        fs::write(&path, &data).expect("seed punch-hole file on ext4");

        let out = Command::new("fallocate")
            .args([
                "--keep-size",
                "--punch-hole",
                "-o",
                "4096",
                "-l",
                "4096",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("run fallocate --punch-hole --keep-size on ext4");
        assert!(
            out.status.success(),
            "ext4 keep-size punch-hole failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after ext4 keep-size punch-hole");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "punch hole must preserve file size"
        );

        let readback = fs::read(&path).expect("read after ext4 keep-size punch-hole");
        assert_eq!(&readback[..4096], &data[..4096], "prefix must be preserved");
        assert!(
            readback[4096..8192].iter().all(|&byte| byte == 0),
            "punched range must read back as zeros"
        );
        assert_eq!(&readback[8192..], &data[8192..], "suffix must be preserved");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn ext4_fuse_invalid_punch_hole_without_keep_size_reports_einval() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_invalid_punch_hole_without_keep_size_errno_einval";
        let path = mnt.join("ext4_invalid_punch_hole_mode.bin");
        let data = patterned_bytes(12_288, 251, 1);
        fs::write(&path, &data).expect("seed invalid-punch-hole file on ext4");

        let report = query_fallocate(&path, libc::FALLOC_FL_PUNCH_HOLE, 4096, 4096);
        let meta = fs::metadata(&path).expect("stat after invalid ext4 punch-hole rejection");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "invalid ext4 punch-hole rejection must preserve file size"
        );
        let readback = fs::read(&path).expect("read after invalid ext4 punch-hole rejection");
        assert_eq!(
            readback, data,
            "invalid ext4 punch-hole rejection must preserve file data"
        );

        if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
            eprintln!(
                "invalid ext4 punch-hole mode collapsed to transport-layer errno 95 before \
                 FrankenFS could prove mounted-path EINVAL semantics: {report}"
            );
            return;
        }

        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "ext4 invalid punch-hole mode should surface EINVAL when dispatched to FrankenFS: {report}"
        );
        assert_eq!(
            report["name"].as_str(),
            Some("EINVAL"),
            "ext4 invalid punch-hole mode should surface the EINVAL alias: {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=22"));
    });
}

#[test]
fn ext4_fuse_fallocate_on_directory_reports_eisdir() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fallocate_on_directory_errno_eisdir";
        let dir = mnt.join("ext4_fallocate_dir");
        fs::create_dir(&dir).expect("mkdir ext4 fallocate directory target");
        let child = dir.join("child.txt");
        fs::write(&child, b"directory child stays intact\n").expect("seed ext4 directory child");

        let entries_before = snapshot_directory_entries(&dir);
        let child_before = snapshot_file_state(&child);
        let report = query_directory_fallocate(&dir, 0, 0, 4096);

        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EISDIR)),
            "ext4 directory fallocate should surface exact EISDIR: {report}"
        );
        assert_eq!(
            report["name"].as_str(),
            Some("EISDIR"),
            "ext4 directory fallocate should surface the EISDIR alias: {report}"
        );
        let phase = report["phase"]
            .as_str()
            .expect("directory fallocate rejection phase");
        assert!(
            matches!(phase, "open" | "fallocate"),
            "unexpected directory fallocate rejection phase: {report}"
        );

        let entries_after = snapshot_directory_entries(&dir);
        assert_eq!(
            entries_after, entries_before,
            "directory fallocate rejection must not change directory entries"
        );
        assert_file_state_unchanged(&child, &child_before, "directory fallocate rejection");
        emit_scenario_result(scenario_id, "PASS", Some(phase));
    });
}

#[test]
fn ext4_fuse_unsupported_fallocate_mode_bits_errno_eopnotsupp() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_unsupported_fallocate_mode_bits_errno_eopnotsupp";
        let path = mnt.join("ext4_unsupported_mode_bits.bin");
        let data = b"keep-intact-on-ext4-unsupported-mode".to_vec();
        fs::write(&path, &data).expect("seed unsupported-mode file on ext4");

        let script = r#"
import ctypes
import errno
import os
import sys

path = sys.argv[1]
fd = os.open(path, os.O_RDWR)
libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int
res = libc.fallocate(fd, 0x08, 0, 4096)
err = ctypes.get_errno()
os.close(fd)
if res == 0:
    print("res=0")
    sys.exit(0)
print(f"errno={err}")
print(errno.errorcode.get(err, "UNKNOWN"))
sys.exit(1)
"#;
        let out = Command::new("python3")
            .args(["-c", script, path.to_str().unwrap()])
            .output()
            .expect("run unsupported-mode fallocate probe on ext4");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !out.status.success(),
            "unsupported mode bits should fail, got stdout={stdout} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains(&format!("errno={EOPNOTSUPP_ERRNO}")),
            "unsupported mode bits should surface errno {EOPNOTSUPP_ERRNO}, got: {stdout}"
        );
        assert!(
            stdout.contains("EOPNOTSUPP") || stdout.contains("ENOTSUP"),
            "unsupported mode bits should surface the errno-95 not-supported alias, got: {stdout}"
        );

        let meta = fs::metadata(&path).expect("stat after unsupported-mode rejection");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "unsupported mode rejection must preserve file size"
        );
        let readback = fs::read(&path).expect("read after unsupported-mode rejection");
        assert_eq!(
            readback, data,
            "unsupported mode rejection must preserve file data"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=95"));
    });
}

#[test]
fn fuse_ioctl_fiemap_reports_valid_extents() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let seed_src = tmp.path().join("fiemap_seed_src.bin");
    fs::write(&seed_src, vec![0x5A_u8; 12 * 1024]).expect("write fiemap seed src");

    let out = Command::new("debugfs")
        .args([
            "-w",
            "-R",
            &format!("write {} fiemap_seed.bin", seed_src.display()),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("debugfs write fiemap_seed.bin");
    assert!(
        out.status.success(),
        "debugfs write fiemap_seed.bin failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fiemap.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let path = mnt.join("fiemap_seed.bin");
    let meta = fs::metadata(&path).expect("stat fiemap seed file");
    let report = query_fiemap(&path, 16);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "FIEMAP ioctl skipped: kernel/VFS returned EOPNOTSUPP before ffs-fuse::ioctl \
             (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful FIEMAP should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    let extents = report["extents"].as_array().expect("fiemap extents array");

    assert!(
        report["mapped_extents"].as_u64().unwrap_or(0) >= 1,
        "expected at least one mapped extent: {report}"
    );
    assert_eq!(
        report["requested_extents"].as_u64().unwrap_or(0),
        16,
        "kernel should preserve requested extent count in response header"
    );

    let mut covered = 0_u64;
    let mut expected_logical = 0_u64;
    let mut saw_last = false;
    for extent in extents {
        let logical = extent["logical"].as_u64().expect("logical");
        let physical = extent["physical"].as_u64().expect("physical");
        let length = extent["length"].as_u64().expect("length");
        let last = extent["last"].as_bool().expect("last flag");

        assert_eq!(
            logical, expected_logical,
            "expected extents to begin at logical offset 0 and remain contiguous: {report}"
        );
        assert!(physical > 0, "physical offset should be non-zero: {report}");
        assert!(length > 0, "extent length should be non-zero: {report}");

        covered = covered.saturating_add(length);
        expected_logical = expected_logical.saturating_add(length);
        saw_last |= last;
    }

    assert!(
        covered >= meta.len(),
        "fiemap extents should cover file length (covered={covered}, len={}): {report}",
        meta.len()
    );
    assert!(
        saw_last,
        "expected FIEMAP_EXTENT_LAST in returned extents: {report}"
    );
}

#[test]
fn fuse_ioctl_fiemap_sync_flag_reports_valid_extents_on_rw_mount() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fiemap-sync.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_fiemap_sync_flag";
    let path = mnt.join("fiemap_sync_seed.bin");
    let payload = patterned_bytes(12 * 1024, 241, 7);
    fs::write(&path, &payload).expect("write fiemap sync seed file");

    let meta = fs::metadata(&path).expect("stat fiemap sync seed file");
    let report = query_fiemap_with_options(&path, 16, FIEMAP_REQUEST_FLAG_SYNC, None);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "FIEMAP SYNC returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "FIEMAP SYNC ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful FIEMAP SYNC should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert!(
        report["errno"].is_null(),
        "FIEMAP SYNC should succeed on the mounted ext4 path once userspace sees the ioctl: \
         {report}"
    );

    let extents = report["extents"].as_array().expect("fiemap extents array");
    assert!(
        report["mapped_extents"].as_u64().unwrap_or(0) >= 1,
        "expected at least one mapped extent from FIEMAP SYNC: {report}"
    );
    assert_eq!(
        report["requested_extents"].as_u64().unwrap_or(0),
        16,
        "kernel should preserve requested extent count in the FIEMAP SYNC response header"
    );

    let mut covered = 0_u64;
    let mut saw_last = false;
    for extent in extents {
        let physical = extent["physical"].as_u64().expect("physical");
        let length = extent["length"].as_u64().expect("length");
        let last = extent["last"].as_bool().expect("last flag");
        assert!(
            physical > 0,
            "FIEMAP SYNC should return non-zero physical offsets for regular extents: {report}"
        );
        assert!(
            length > 0,
            "FIEMAP SYNC extent length should be non-zero: {report}"
        );
        covered = covered.saturating_add(length);
        saw_last |= last;
    }

    assert!(
        covered >= meta.len(),
        "FIEMAP SYNC extents should cover file length (covered={covered}, len={}): {report}",
        meta.len()
    );
    assert!(
        saw_last,
        "FIEMAP SYNC should surface FIEMAP_EXTENT_LAST: {report}"
    );
    emit_scenario_result(scenario_id, "PASS", Some("request_flags=sync"));
}

#[test]
fn fuse_ioctl_fiemap_rejects_unsupported_request_flags_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fiemap-invalid-flag.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_fiemap_invalid_request_flags";
    let path = mnt.join("fiemap_invalid_flag_seed.bin");
    let payload = patterned_bytes(8 * 1024, 239, 11);
    fs::write(&path, &payload).expect("write fiemap invalid-flag seed file");

    let report = query_fiemap_with_options(&path, 16, FIEMAP_REQUEST_FLAG_XATTR, None);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "invalid-flag FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "FIEMAP invalid-flag ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "unsupported FIEMAP request flags should still hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::EBADR)),
        "unsupported FIEMAP request flags should reject with EBADR: {report}"
    );
    assert_eq!(
        fs::read(&path).expect("read after invalid FIEMAP flag rejection"),
        payload,
        "FIEMAP invalid-flag rejection must not mutate file data"
    );
    emit_scenario_result(scenario_id, "PASS", Some("errno=53_ebadr"));
}

#[test]
fn fuse_ioctl_fiemap_directory_fd_reports_eisdir() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fiemap-directory.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let dir = mnt.join("fiemap_dir_target");
    fs::create_dir(&dir).expect("mkdir ext4 fiemap directory target");
    let child = dir.join("child.txt");
    fs::write(&child, b"fiemap directory child\n").expect("seed ext4 fiemap directory child");

    let entries_before = snapshot_directory_entries(&dir);
    let child_before = snapshot_file_state(&child);
    let report = query_directory_fiemap_with_options(&dir, 16, 0, None);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "directory-fd ext4 FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        emit_scenario_result(
            "ext4_ioctl_fiemap_directory_fd_errno_eisdir",
            "SKIP",
            Some("kernel_or_vfs_rejected_before_userspace"),
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "directory-fd ext4 FIEMAP should hit ffs-fuse::ioctl when not transport-rejected: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::EISDIR)),
        "directory-fd ext4 FIEMAP should surface exact EISDIR: {report}"
    );
    assert_eq!(
        report["name"].as_str(),
        Some("EISDIR"),
        "directory-fd ext4 FIEMAP should surface the EISDIR alias: {report}"
    );

    let entries_after = snapshot_directory_entries(&dir);
    assert_eq!(
        entries_after, entries_before,
        "directory-fd FIEMAP rejection must not change directory entries"
    );
    assert_file_state_unchanged(&child, &child_before, "directory-fd FIEMAP rejection");
    emit_scenario_result(
        "ext4_ioctl_fiemap_directory_fd_errno_eisdir",
        "PASS",
        Some("errno=21_eisdir"),
    );
}

#[test]
fn btrfs_fuse_ioctl_fiemap_reports_valid_extents() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-btrfs-fiemap.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    assert!(
        workspace.is_dir(),
        "seeded btrfs workspace missing at {}",
        workspace.display()
    );

    let path = workspace.join("fiemap_seed.bin");
    let payload = vec![0xA5_u8; 24 * 1024];
    fs::write(&path, &payload).expect("write btrfs fiemap seed file");

    let meta = fs::metadata(&path).expect("stat btrfs fiemap seed file");
    let report = query_fiemap(&path, 16);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "btrfs FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "btrfs FIEMAP ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful btrfs FIEMAP should hit ffs-fuse::ioctl: {ioctl_trace}"
    );

    let extents = report["extents"]
        .as_array()
        .expect("btrfs fiemap extents array");

    assert!(
        report["mapped_extents"].as_u64().unwrap_or(0) >= 1,
        "expected at least one mapped btrfs extent: {report}"
    );
    assert_eq!(
        report["requested_extents"].as_u64().unwrap_or(0),
        16,
        "kernel should preserve requested btrfs extent count in response header"
    );

    let mut covered = 0_u64;
    let mut expected_logical = 0_u64;
    let mut saw_last = false;
    for extent in extents {
        let logical = extent["logical"].as_u64().expect("logical");
        let physical = extent["physical"].as_u64().expect("physical");
        let length = extent["length"].as_u64().expect("length");
        let last = extent["last"].as_bool().expect("last flag");

        assert_eq!(
            logical, expected_logical,
            "expected btrfs extents to begin at logical offset 0 and remain contiguous: {report}"
        );
        assert!(physical > 0, "physical offset should be non-zero: {report}");
        assert!(length > 0, "extent length should be non-zero: {report}");

        covered = covered.saturating_add(length);
        expected_logical = expected_logical.saturating_add(length);
        saw_last |= last;
    }

    assert!(
        covered >= meta.len(),
        "btrfs fiemap extents should cover file length (covered={covered}, len={}): {report}",
        meta.len()
    );
    assert!(
        saw_last,
        "expected FIEMAP_EXTENT_LAST in returned btrfs extents: {report}"
    );
}

#[test]
fn btrfs_fuse_ioctl_fiemap_directory_fd_reports_eisdir() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-btrfs-fiemap-directory.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let dir = workspace.join("fiemap_dir_target");
    fs::create_dir(&dir).expect("mkdir btrfs fiemap directory target");
    let child = dir.join("child.txt");
    fs::write(&child, b"fiemap directory child\n").expect("seed btrfs fiemap directory child");

    let entries_before = snapshot_directory_entries(&dir);
    let child_before = snapshot_file_state(&child);
    let report = query_directory_fiemap_with_options(&dir, 16, 0, None);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "directory-fd btrfs FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        emit_scenario_result(
            "btrfs_ioctl_fiemap_directory_fd_errno_eisdir",
            "SKIP",
            Some("kernel_or_vfs_rejected_before_userspace"),
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "directory-fd btrfs FIEMAP should hit ffs-fuse::ioctl when not transport-rejected: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::EISDIR)),
        "directory-fd btrfs FIEMAP should surface exact EISDIR: {report}"
    );
    assert_eq!(
        report["name"].as_str(),
        Some("EISDIR"),
        "directory-fd btrfs FIEMAP should surface the EISDIR alias: {report}"
    );

    let entries_after = snapshot_directory_entries(&dir);
    assert_eq!(
        entries_after, entries_before,
        "directory-fd FIEMAP rejection must not change directory entries"
    );
    assert_file_state_unchanged(&child, &child_before, "directory-fd FIEMAP rejection");
    emit_scenario_result(
        "btrfs_ioctl_fiemap_directory_fd_errno_eisdir",
        "PASS",
        Some("errno=21_eisdir"),
    );
}

#[test]
fn btrfs_fuse_ioctl_fiemap_reports_inline_extent_with_zero_physical() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-btrfs-fiemap-inline.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let path = workspace.join("fiemap_inline_seed.bin");
    let payload = b"inline-fiemap";
    fs::write(&path, payload).expect("write inline btrfs fiemap seed file");

    let report = query_fiemap(&path, 16);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "inline btrfs FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "btrfs inline FIEMAP ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful inline btrfs FIEMAP should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert!(
        report["errno"].is_null(),
        "inline btrfs FIEMAP should succeed once userspace sees the ioctl: {report}"
    );

    let extents = report["extents"]
        .as_array()
        .expect("inline btrfs fiemap extents array");
    assert_eq!(
        extents.len(),
        1,
        "inline btrfs FIEMAP should report a single inline extent: {report}"
    );
    assert_eq!(
        report["mapped_extents"].as_u64().unwrap_or(0),
        1,
        "inline btrfs FIEMAP should map exactly one extent: {report}"
    );

    let extent = &extents[0];
    assert_eq!(extent["logical"].as_u64().unwrap_or(u64::MAX), 0);
    assert_eq!(extent["physical"].as_u64().unwrap_or(u64::MAX), 0);
    assert_eq!(extent["length"].as_u64().unwrap_or(0), payload.len() as u64);
    assert_eq!(
        fiemap_extent_flags(extent),
        FIEMAP_EXTENT_LAST_FLAG,
        "inline btrfs FIEMAP extent should only carry LAST: {report}"
    );
    assert!(
        extent["last"].as_bool().unwrap_or(false),
        "inline btrfs FIEMAP extent should surface LAST: {report}"
    );
}

#[test]
fn btrfs_fuse_ioctl_fiemap_marks_keep_size_prealloc_extent_unwritten() {
    if !btrfs_fuse_available() || !command_available("fallocate") {
        eprintln!("btrfs FIEMAP keep-size prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-btrfs-fiemap-prealloc.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let path = workspace.join("fiemap_prealloc_seed.bin");
    fs::write(&path, b"existing").expect("write keep-size seed file");

    let out = Command::new("fallocate")
        .args([
            "--keep-size",
            "-o",
            "4096",
            "-l",
            "4096",
            path.to_str().unwrap(),
        ])
        .output()
        .expect("run keep-size fallocate on btrfs");
    assert!(
        out.status.success(),
        "btrfs keep-size fallocate for FIEMAP failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read(&path).expect("read after keep-size fallocate"),
        b"existing",
        "keep-size preallocation should preserve visible file data"
    );

    let report = query_fiemap(&path, 16);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
            "keep-size btrfs FIEMAP returned EOPNOTSUPP after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "btrfs keep-size FIEMAP ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_FIEMAP_CMD),
        "successful keep-size btrfs FIEMAP should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert!(
        report["errno"].is_null(),
        "keep-size btrfs FIEMAP should succeed once userspace sees the ioctl: {report}"
    );

    let extents = report["extents"]
        .as_array()
        .expect("keep-size btrfs fiemap extents array");
    assert!(
        report["mapped_extents"].as_u64().unwrap_or(0) >= 2,
        "keep-size btrfs FIEMAP should report data plus unwritten prealloc extents: {report}"
    );

    let has_materialized_prefix = extents.iter().any(|extent| {
        extent["logical"].as_u64() == Some(0)
            && extent["physical"].as_u64().unwrap_or(0) > 0
            && fiemap_extent_flags(extent) & FIEMAP_EXTENT_UNWRITTEN_FLAG == 0
    });
    assert!(
        has_materialized_prefix,
        "keep-size btrfs FIEMAP should expose the materialized prefix extent: {report}"
    );

    let has_unwritten_prealloc = extents.iter().any(|extent| {
        extent["logical"].as_u64() == Some(4096)
            && extent["length"].as_u64() == Some(4096)
            && extent["physical"].as_u64().unwrap_or(0) > 0
            && fiemap_extent_flags(extent) & FIEMAP_EXTENT_UNWRITTEN_FLAG != 0
            && fiemap_extent_flags(extent) & FIEMAP_EXTENT_LAST_FLAG != 0
    });
    assert!(
        has_unwritten_prealloc,
        "keep-size btrfs FIEMAP should expose a trailing unwritten prealloc extent: {report}"
    );
}

#[test]
fn fuse_ioctl_ext4_getflags_setflags_roundtrip_preserves_system_bits() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-flags.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_getflags_setflags_roundtrip";
    let path = mnt.join("inode_flags.bin");
    fs::write(&path, b"ext4 ioctl flags payload\n").expect("write ext4 ioctl seed file");

    let original_report = ext4_inode_flags_ioctl(&path, "get", None);
    let get_trace = read_ioctl_trace(&ioctl_trace_path);
    if original_report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
            "GETFLAGS returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {get_trace}"
        );
        eprintln!(
            "EXT4 GETFLAGS ioctl skipped: kernel/VFS returned EOPNOTSUPP before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
        "successful GETFLAGS should hit ffs-fuse::ioctl: {get_trace}"
    );
    let original = u32::try_from(
        original_report["flags"]
            .as_u64()
            .expect("original flags u64"),
    )
    .expect("original flags should fit u32");
    assert_ne!(
        original & ffs_types::EXT4_EXTENTS_FL,
        0,
        "default rw ext4 file should start extent-based: {original_report}"
    );

    let requested = (original
        | ffs_types::EXT4_NOATIME_FL
        | ffs_types::EXT4_NODUMP_FL
        | ffs_types::EXT4_HUGE_FILE_FL)
        & !ffs_types::EXT4_EXTENTS_FL;
    let set_report = ext4_inode_flags_ioctl(&path, "set", Some(requested));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if set_report["errno"].as_i64() == Some(i64::from(libc::ENOTTY)) {
        assert!(
            !trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
            "SETFLAGS returned ENOTTY after reaching ffs-fuse::ioctl: {set_trace}"
        );
        eprintln!(
            "EXT4 SETFLAGS ioctl skipped: kernel/VFS returned ENOTTY before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
        "successful SETFLAGS should hit ffs-fuse::ioctl: {set_trace}"
    );
    assert!(
        set_report["errno"].is_null(),
        "EXT4 SETFLAGS ioctl should succeed on rw mount: {set_report}"
    );

    let updated_report = ext4_inode_flags_ioctl(&path, "get", None);
    let updated = u32::try_from(updated_report["flags"].as_u64().expect("updated flags u64"))
        .expect("updated flags should fit u32");
    assert_eq!(
        updated & (ffs_types::EXT4_NOATIME_FL | ffs_types::EXT4_NODUMP_FL),
        ffs_types::EXT4_NOATIME_FL | ffs_types::EXT4_NODUMP_FL,
        "SETFLAGS should apply user-settable NOATIME/NODUMP bits: {updated_report}"
    );
    assert_eq!(
        updated & ffs_types::EXT4_EXTENTS_FL,
        original & ffs_types::EXT4_EXTENTS_FL,
        "SETFLAGS must not clear system-managed EXTENTS bit: {updated_report}"
    );
    assert_eq!(
        updated & ffs_types::EXT4_HUGE_FILE_FL,
        original & ffs_types::EXT4_HUGE_FILE_FL,
        "SETFLAGS must not introduce system-managed HUGE_FILE bit: {updated_report}"
    );
    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("user_bits_applied_system_bits_preserved"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_setfslabel_updates_label_and_survives_remount() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-fslabel.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_setfslabel_roundtrip";
    let path = mnt.join("fslabel-target.txt");
    fs::write(&path, b"fs label ioctl target\n").expect("create fslabel ioctl target");
    let requested = "ffs-renamed";

    let set_report = fs_label_ioctl(&path, "set", Some(requested));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if let Some(errno) = set_report["errno"].as_i64() {
        if errno == i64::from(libc::EPERM)
            || errno == i64::from(libc::ENOTTY)
            || errno == EOPNOTSUPP_ERRNO
        {
            assert!(
                !trace_contains_cmd(&set_trace, FS_IOC_SETFSLABEL_CMD),
                "SETFSLABEL should not return {errno} after reaching ffs-fuse::ioctl: {set_trace}"
            );
            emit_scenario_result(
                scenario_id,
                "SKIP",
                Some("kernel_or_vfs_rejected_setfslabel_before_userspace"),
            );
            return;
        }
    }
    assert!(
        trace_contains_cmd(&set_trace, FS_IOC_SETFSLABEL_CMD),
        "successful SETFSLABEL should hit ffs-fuse::ioctl: {set_trace}"
    );
    assert!(
        set_report["errno"].is_null(),
        "SETFSLABEL should succeed on rw ext4 mount: {set_report}"
    );

    drop(session);

    let Some(_remount) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };
    let remount_report = fs_label_ioctl(&path, "get", None);
    let remount_trace = read_ioctl_trace(&ioctl_trace_path);
    if let Some(errno) = remount_report["errno"].as_i64() {
        assert!(
            errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO,
            "unexpected errno for remount GETFSLABEL fallback: {remount_report}"
        );
        assert!(
            !trace_contains_cmd(&remount_trace, FS_IOC_GETFSLABEL_CMD),
            "GETFSLABEL should not return {errno} after reaching ffs-fuse::ioctl: {remount_trace}"
        );

        let cx = Cx::for_testing();
        let opts = OpenOptions {
            ext4_journal_replay_mode: Ext4JournalReplayMode::Skip,
            ..OpenOptions::default()
        };
        let fs = OpenFs::open_with_options(&cx, &image, &opts)
            .expect("open image to verify persisted fs label");
        let label = fs
            .get_fs_label(&cx, &mut RequestScope::empty())
            .expect("read persisted fs label directly");
        let end = label
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(label.len());
        assert_eq!(
            &label[..end],
            requested.as_bytes(),
            "SETFSLABEL should persist even when remount GETFSLABEL is transport-blocked"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("setfslabel_persisted_direct_verify_after_remount"),
        );
        return;
    }

    assert!(
        trace_contains_cmd(&remount_trace, FS_IOC_GETFSLABEL_CMD),
        "successful GETFSLABEL after remount should hit ffs-fuse::ioctl: {remount_trace}"
    );
    assert_eq!(
        remount_report["label"].as_str(),
        Some(requested),
        "SETFSLABEL should persist across remount: {remount_report}"
    );
    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("setfslabel_persisted_after_remount"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_setflags_enables_compr_and_roundtrips_data_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_ext4_incompat_features(
        tmp.path(),
        4 * 1024 * 1024,
        ffs_ondisk::Ext4IncompatFeatures::COMPRESSION.0,
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-compr-setflags.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_setflags_compr_enable";
    let path = mnt.join("compr-enable.bin");
    fs::write(&path, b"").expect("create empty file for COMPR enable");

    let original_report = ext4_inode_flags_ioctl(&path, "get", None);
    let get_trace = read_ioctl_trace(&ioctl_trace_path);
    if original_report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
            "GETFLAGS returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {get_trace}"
        );
        eprintln!(
            "EXT4 GETFLAGS ioctl skipped for COMPR enable: kernel/VFS returned EOPNOTSUPP \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
        "successful GETFLAGS should hit ffs-fuse::ioctl: {get_trace}"
    );
    let original = u32::try_from(
        original_report["flags"]
            .as_u64()
            .expect("original COMPR flags u64"),
    )
    .expect("original COMPR flags should fit u32");
    assert_ne!(
        original & ffs_types::EXT4_EXTENTS_FL,
        0,
        "fresh ext4 file should start extent-based before COMPR enable: {original_report}"
    );

    let set_report =
        ext4_inode_flags_ioctl(&path, "set", Some(original | ffs_types::EXT4_COMPR_FL));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if set_report["errno"].as_i64() == Some(i64::from(libc::ENOTTY)) {
        assert!(
            !trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
            "COMPR SETFLAGS returned ENOTTY after reaching ffs-fuse::ioctl: {set_trace}"
        );
        eprintln!(
            "EXT4 COMPR SETFLAGS ioctl skipped: kernel/VFS returned ENOTTY before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
        "successful COMPR SETFLAGS should hit ffs-fuse::ioctl: {set_trace}"
    );
    assert!(
        set_report["errno"].is_null(),
        "ext4 COMPR enable via SETFLAGS should succeed on rw mount: {set_report}"
    );

    let updated_report = ext4_inode_flags_ioctl(&path, "get", None);
    let updated = u32::try_from(
        updated_report["flags"]
            .as_u64()
            .expect("updated COMPR flags u64"),
    )
    .expect("updated COMPR flags should fit u32");
    assert_ne!(
        updated & ffs_types::EXT4_COMPR_FL,
        0,
        "SETFLAGS should publish EXT4_COMPR_FL after COMPR enable: {updated_report}"
    );
    assert_eq!(
        updated & ffs_types::EXT4_EXTENTS_FL,
        0,
        "COMPR enable should clear EXTENTS on the mounted path: {updated_report}"
    );

    let payload = vec![b'C'; 4096];
    fs::write(&path, &payload).expect("write compressible payload after COMPR enable");
    let readback = fs::read(&path).expect("readback after COMPR enable");
    assert_eq!(
        readback, payload,
        "COMPR-enabled mounted path should preserve file bytes across write/read"
    );

    let post_write_report = ext4_inode_flags_ioctl(&path, "get", None);
    let post_write = u32::try_from(
        post_write_report["flags"]
            .as_u64()
            .expect("post-write COMPR flags u64"),
    )
    .expect("post-write COMPR flags should fit u32");
    assert_ne!(
        post_write & ffs_types::EXT4_COMPRBLK_FL,
        0,
        "compressed mounted-path write should set COMPRBLK after COMPR enable: {post_write_report}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("compr_flag_enabled_and_compressed_write_roundtrips"),
    );
}

#[test]
fn fuse_ioctl_ext4_setflags_rejects_compr_without_compression_feature() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-compr-reject.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_setflags_compr_requires_feature";
    let path = mnt.join("compr-reject.bin");
    fs::write(&path, b"").expect("create empty file for COMPR rejection");

    let original_report = ext4_inode_flags_ioctl(&path, "get", None);
    let get_trace = read_ioctl_trace(&ioctl_trace_path);
    if original_report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
        assert!(
            !trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
            "GETFLAGS returned EOPNOTSUPP after reaching ffs-fuse::ioctl: {get_trace}"
        );
        eprintln!(
            "EXT4 GETFLAGS ioctl skipped for COMPR rejection: kernel/VFS returned EOPNOTSUPP \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&get_trace, EXT4_IOC_GETFLAGS_CMD),
        "successful GETFLAGS should hit ffs-fuse::ioctl: {get_trace}"
    );
    let original = u32::try_from(
        original_report["flags"]
            .as_u64()
            .expect("original rejection flags u64"),
    )
    .expect("original rejection flags should fit u32");

    let set_report =
        ext4_inode_flags_ioctl(&path, "set", Some(original | ffs_types::EXT4_COMPR_FL));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if set_report["errno"].as_i64() == Some(i64::from(libc::ENOTTY)) {
        assert!(
            !trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
            "COMPR rejection SETFLAGS returned ENOTTY after reaching ffs-fuse::ioctl: {set_trace}"
        );
        eprintln!(
            "EXT4 COMPR rejection SETFLAGS ioctl skipped: kernel/VFS returned ENOTTY before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&set_trace, EXT4_IOC_SETFLAGS_CMD),
        "rejected COMPR SETFLAGS should still hit ffs-fuse::ioctl: {set_trace}"
    );
    assert_eq!(
        set_report["errno"].as_i64(),
        Some(EOPNOTSUPP_ERRNO),
        "COMPR enable without the COMPRESSION feature should surface EOPNOTSUPP: {set_report}"
    );
    assert_eq!(
        set_report["message"].as_str(),
        Some("[Errno 95] Operation not supported"),
        "COMPR rejection should keep the stable mounted-path errno string: {set_report}"
    );

    let updated_report = ext4_inode_flags_ioctl(&path, "get", None);
    let updated = u32::try_from(
        updated_report["flags"]
            .as_u64()
            .expect("updated rejection flags u64"),
    )
    .expect("updated rejection flags should fit u32");
    assert_eq!(
        updated & ffs_types::EXT4_COMPR_FL,
        0,
        "failed COMPR enable must not set EXT4_COMPR_FL: {updated_report}"
    );
    assert_eq!(
        updated, original,
        "failed COMPR enable must leave mounted-path inode flags unchanged: {updated_report}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("compr_enable_without_feature_rejected"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ext4_fscrypt_nokey_readdir_and_lookup_preserve_raw_bytes_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let raw_name = b"\xFFenc\x80";
    let image_path = tmp.path().join("fscrypt-nokey-raw-name.ext4");
    fs::write(&image_path, build_ext4_encrypt_image_with_dir(raw_name))
        .expect("write fscrypt raw-name image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image_path, &mnt) else {
        return;
    };

    let scenario_id = "ext4_fscrypt_nokey_raw_name_lookup_and_readdir";
    let entries = fs::read_dir(&mnt)
        .expect("readdir mounted root")
        .map(|entry| entry.expect("mounted root dirent").file_name())
        .collect::<Vec<_>>();
    assert!(
        entries.iter().any(|name| name.as_bytes() == raw_name),
        "mounted-path readdir should preserve encrypted raw bytes, got: {entries:?}"
    );

    let encrypted_path = mnt.join(Path::new(std::ffi::OsStr::from_bytes(raw_name)));
    let metadata = fs::metadata(&encrypted_path).expect("lookup encrypted entry via raw bytes");
    assert!(metadata.is_file(), "raw-byte lookup should resolve the encrypted file");
    assert_eq!(
        metadata.ino(),
        11,
        "raw-byte lookup should resolve inode 11 for the encrypted entry"
    );
    assert_eq!(
        fs::read(&encrypted_path).expect("read encrypted file via raw-byte path"),
        vec![0_u8; 5],
        "encrypted fixture file should remain readable through the raw-byte name"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("readdir_and_lookup_preserve_raw_bytes"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_get_encryption_policy_v1_reports_legacy_policy_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = build_ext4_fscrypt_policy_image(true);
    let image_path = tmp.path().join("fscrypt-policy-v1.ext4");
    fs::write(&image_path, image).expect("write fscrypt policy image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-encryption-policy.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image_path, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_get_encryption_policy_v1";
    let path = mnt.join("policy.txt");
    let report = ext4_get_encryption_policy_ioctl(&path);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_CMD),
            "GET_ENCRYPTION_POLICY returned unsupported errno after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "EXT4 GET_ENCRYPTION_POLICY ioctl skipped: kernel/VFS returned unsupported errno \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_CMD),
        "successful GET_ENCRYPTION_POLICY should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    // The legacy getter is encoded as `_IOW`, so restricted FUSE sends the
    // caller buffer as `in_data` with `out_size == 0`. Real kernels then reject
    // any successful data reply with `EIO` even though the request reached
    // FrankenFS; treat that as an auditable surfaced transport gap rather than
    // as a backend regression.
    if report["errno"].as_i64() == Some(i64::from(libc::EIO)) {
        assert!(
            ioctl_trace.contains("in_len=12 out_size=0"),
            "legacy fscrypt v1 ioctl should surface the restricted-FUSE `_IOW` \
             request shape before returning EIO: {ioctl_trace}"
        );
        assert_eq!(
            report["message"].as_str(),
            Some("[Errno 5] Input/output error"),
            "legacy fscrypt v1 mounted-path failure should remain the expected \
             kernel/FUSE transport EIO: {report}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("restricted_fuse_iow_transport_surfaces_eio"),
        );
        return;
    }

    assert!(
        report["errno"].is_null(),
        "GET_ENCRYPTION_POLICY should either succeed or surface the known \
         restricted-FUSE `_IOW` EIO: {report}"
    );
    assert_eq!(
        report["policy_version"].as_u64(),
        Some(u64::from(FSCRYPT_POLICY_V1_VERSION)),
        "expected legacy fscrypt policy v1 payload: {report}"
    );
    assert_eq!(
        report["contents_mode"].as_u64(),
        Some(1),
        "unexpected fscrypt contents mode: {report}"
    );
    assert_eq!(
        report["filenames_mode"].as_u64(),
        Some(4),
        "unexpected fscrypt filenames mode: {report}"
    );
    assert_eq!(
        report["flags"].as_u64(),
        Some(0),
        "unexpected fscrypt policy flags: {report}"
    );
    assert_eq!(
        report["master_key_descriptor_hex"].as_str(),
        Some("6d6b646573633432"),
        "unexpected fscrypt v1 master key descriptor: {report}"
    );
    assert_eq!(
        report["policy_hex"].as_str(),
        Some("000104006d6b646573633432"),
        "expected raw fscrypt policy v1 bytes to remain stable: {report}"
    );
    assert_eq!(
        report["policy_hex"].as_str().map(str::len),
        Some(FSCRYPT_POLICY_V1_SIZE * 2),
        "expected the legacy policy ioctl to return exactly 12 bytes: {report}"
    );
    emit_scenario_result(scenario_id, "PASS", Some("policy_version=0_v1"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_get_encryption_policy_ex_returns_v1_policy_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = build_ext4_fscrypt_policy_image(true);
    let image_path = tmp.path().join("fscrypt-policy-ex-v1.ext4");
    fs::write(&image_path, image).expect("write fscrypt policy-ex image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-encryption-policy-ex.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image_path, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_get_encryption_policy_ex_v1";
    let path = mnt.join("policy.txt");
    let report = ext4_get_encryption_policy_ex_ioctl(&path);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);

    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD),
            "GET_ENCRYPTION_POLICY_EX returned unsupported errno after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "EXT4 GET_ENCRYPTION_POLICY_EX ioctl skipped: kernel/VFS returned unsupported errno \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }

    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD),
        "successful GET_ENCRYPTION_POLICY_EX should hit ffs-fuse::ioctl: {ioctl_trace}"
    );

    assert!(
        report["errno"].is_null(),
        "GET_ENCRYPTION_POLICY_EX should succeed: {report}"
    );
    assert_eq!(
        report["policy_version"].as_u64(),
        Some(u64::from(FSCRYPT_POLICY_V1_VERSION)),
        "expected fscrypt policy v1 via policy-ex: {report}"
    );
    assert_eq!(
        report["policy_size"].as_u64(),
        Some(FSCRYPT_POLICY_V1_SIZE as u64),
        "expected policy size 12 for v1: {report}"
    );
    assert_eq!(
        report["contents_mode"].as_u64(),
        Some(1),
        "unexpected fscrypt contents mode: {report}"
    );
    assert_eq!(
        report["filenames_mode"].as_u64(),
        Some(4),
        "unexpected fscrypt filenames mode: {report}"
    );
    assert_eq!(
        report["flags"].as_u64(),
        Some(0),
        "unexpected fscrypt policy flags: {report}"
    );
    assert_eq!(
        report["master_key_descriptor_hex"].as_str(),
        Some("6d6b646573633432"),
        "unexpected fscrypt v1 master key descriptor: {report}"
    );
    emit_scenario_result(scenario_id, "PASS", Some("policy_ex_returns_v1"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_get_encryption_policy_ex_returns_v2_policy_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = build_ext4_fscrypt_policy_v2_image();
    let image_path = tmp.path().join("fscrypt-policy-ex-v2.ext4");
    fs::write(&image_path, image).expect("write fscrypt policy-ex v2 image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-encryption-policy-ex-v2.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image_path, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_get_encryption_policy_ex_v2";
    let path = mnt.join("policy.txt");
    let report = ext4_get_encryption_policy_ex_ioctl(&path);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);

    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD),
            "GET_ENCRYPTION_POLICY_EX returned unsupported errno after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "EXT4 GET_ENCRYPTION_POLICY_EX v2 ioctl skipped: kernel/VFS returned unsupported errno \
             before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }

    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_EX_CMD),
        "successful GET_ENCRYPTION_POLICY_EX v2 should hit ffs-fuse::ioctl: {ioctl_trace}"
    );

    assert!(
        report["errno"].is_null(),
        "GET_ENCRYPTION_POLICY_EX v2 should succeed: {report}"
    );
    assert_eq!(
        report["policy_version"].as_u64(),
        Some(u64::from(FSCRYPT_POLICY_V2_VERSION)),
        "expected fscrypt policy v2 via policy-ex: {report}"
    );
    assert_eq!(
        report["policy_size"].as_u64(),
        Some(FSCRYPT_POLICY_V2_SIZE as u64),
        "expected policy size 24 for v2: {report}"
    );
    assert_eq!(
        report["contents_mode"].as_u64(),
        Some(1),
        "unexpected fscrypt v2 contents mode: {report}"
    );
    assert_eq!(
        report["filenames_mode"].as_u64(),
        Some(4),
        "unexpected fscrypt v2 filenames mode: {report}"
    );
    assert_eq!(
        report["flags"].as_u64(),
        Some(0),
        "unexpected fscrypt v2 policy flags: {report}"
    );
    assert_eq!(
        report["master_key_identifier_hex"].as_str(),
        Some("30313233343536373839616263646566"),
        "unexpected fscrypt v2 master key identifier: {report}"
    );
    emit_scenario_result(scenario_id, "PASS", Some("policy_ex_returns_v2"));
}

#[test]
fn fuse_ioctl_ext4_get_encryption_policy_returns_enodata_for_unencrypted_inode() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = build_ext4_fscrypt_policy_image(false);
    let image_path = tmp.path().join("fscrypt-policy-enodata.ext4");
    fs::write(&image_path, image).expect("write fscrypt ENODATA image");
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-encryption-policy-enodata.log");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_with_options(&image_path, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_get_encryption_policy_enodata";
    let path = mnt.join("policy.txt");
    let report = ext4_get_encryption_policy_ioctl(&path);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_CMD),
            "GET_ENCRYPTION_POLICY ENODATA path returned unsupported errno after reaching \
             ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "EXT4 GET_ENCRYPTION_POLICY ENODATA path skipped: kernel/VFS returned unsupported \
             errno before ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, FS_IOC_GET_ENCRYPTION_POLICY_CMD),
        "ENODATA GET_ENCRYPTION_POLICY should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::ENODATA)),
        "unencrypted inode should surface ENODATA: {report}"
    );
    let detail = format!("errno={}", libc::ENODATA);
    emit_scenario_result(scenario_id, "PASS", Some(detail.as_str()));
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_move_ext_swaps_middle_extent_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 8 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-move-ext.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_move_ext_swaps_middle_extent";
    let source = mnt.join("move_ext_source.bin");
    let donor = mnt.join("move_ext_donor.bin");
    let block_size = 4096_usize;

    let mut source_payload = Vec::with_capacity(block_size * 3);
    source_payload.extend(std::iter::repeat_n(0x11_u8, block_size));
    source_payload.extend(std::iter::repeat_n(0x22_u8, block_size));
    source_payload.extend(std::iter::repeat_n(0x33_u8, block_size));
    let mut donor_payload = Vec::with_capacity(block_size * 3);
    donor_payload.extend(std::iter::repeat_n(0xAA_u8, block_size));
    donor_payload.extend(std::iter::repeat_n(0xBB_u8, block_size));
    donor_payload.extend(std::iter::repeat_n(0xCC_u8, block_size));

    fs::write(&source, &source_payload).expect("write source payload");
    fs::write(&donor, &donor_payload).expect("write donor payload");

    let source_before = query_fiemap(&source, 16);
    let donor_before = query_fiemap(&donor, 16);
    if matches!(
        source_before["errno"].as_i64(),
        Some(errno) if errno == EOPNOTSUPP_ERRNO || errno == i64::from(libc::ENOTTY)
    ) || matches!(
        donor_before["errno"].as_i64(),
        Some(errno) if errno == EOPNOTSUPP_ERRNO || errno == i64::from(libc::ENOTTY)
    ) {
        eprintln!(
            "EXT4 MOVE_EXT swap proof skipped: FIEMAP unavailable on current kernel/FUSE stack"
        );
        return;
    }
    let report = ext4_move_ext_ioctl(&source, &donor, 1, 1, 1);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["timeout"].as_bool() == Some(true) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
            "MOVE_EXT timed out after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "EXT4 MOVE_EXT ioctl skipped: kernel/FUSE stack timed out before ffs-fuse::ioctl"
        );
        return;
    }
    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
            "MOVE_EXT returned kernel/VFS-level unsupported errno after reaching ffs-fuse::ioctl: \
             {ioctl_trace}"
        );
        eprintln!(
            "EXT4 MOVE_EXT ioctl skipped: kernel/VFS returned unsupported errno before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
        "successful MOVE_EXT should hit ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert!(
        report["errno"].is_null(),
        "EXT4 MOVE_EXT ioctl should succeed on fully mapped extents: {report}"
    );
    assert_eq!(
        report["moved_len"].as_u64(),
        Some(1),
        "MOVE_EXT should report the swapped block count: {report}"
    );

    let source_after = fs::read(&source).expect("read source after move_ext");
    let donor_after = fs::read(&donor).expect("read donor after move_ext");
    assert_eq!(
        &source_after[..block_size],
        &source_payload[..block_size],
        "source prefix block should stay in place"
    );
    assert_eq!(
        &source_after[block_size..2 * block_size],
        &donor_payload[block_size..2 * block_size],
        "source middle block should come from donor"
    );
    assert_eq!(
        &source_after[2 * block_size..],
        &source_payload[2 * block_size..],
        "source suffix block should stay in place"
    );
    assert_eq!(
        &donor_after[..block_size],
        &donor_payload[..block_size],
        "donor prefix block should stay in place"
    );
    assert_eq!(
        &donor_after[block_size..2 * block_size],
        &source_payload[block_size..2 * block_size],
        "donor middle block should come from source"
    );
    assert_eq!(
        &donor_after[2 * block_size..],
        &donor_payload[2 * block_size..],
        "donor suffix block should stay in place"
    );

    let source_after_report = query_fiemap(&source, 16);
    let donor_after_report = query_fiemap(&donor, 16);
    assert!(
        source_after_report["errno"].is_null() && donor_after_report["errno"].is_null(),
        "post-move FIEMAP must succeed to prove extent exchange: source={source_after_report} \
         donor={donor_after_report}"
    );
    let source_before_blocks = physical_blocks_by_logical_block(&source_before, block_size as u64);
    let donor_before_blocks = physical_blocks_by_logical_block(&donor_before, block_size as u64);
    let source_after_blocks =
        physical_blocks_by_logical_block(&source_after_report, block_size as u64);
    let donor_after_blocks =
        physical_blocks_by_logical_block(&donor_after_report, block_size as u64);
    assert!(
        source_before_blocks.len() >= 3
            && donor_before_blocks.len() >= 3
            && source_after_blocks.len() >= 3
            && donor_after_blocks.len() >= 3,
        "expected block-level FIEMAP coverage for three-block move_ext scenario"
    );
    assert_eq!(
        source_after_blocks[0], source_before_blocks[0],
        "source logical block 0 should keep its original physical block"
    );
    assert_eq!(
        source_after_blocks[1], donor_before_blocks[1],
        "source logical block 1 should adopt donor's original physical block"
    );
    assert_eq!(
        source_after_blocks[2], source_before_blocks[2],
        "source logical block 2 should keep its original physical block"
    );
    assert_eq!(
        donor_after_blocks[0], donor_before_blocks[0],
        "donor logical block 0 should keep its original physical block"
    );
    assert_eq!(
        donor_after_blocks[1], source_before_blocks[1],
        "donor logical block 1 should adopt source's original physical block"
    );
    assert_eq!(
        donor_after_blocks[2], donor_before_blocks[2],
        "donor logical block 2 should keep its original physical block"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("moved_len=1_middle_block_swapped"),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_move_ext_rejects_hole_backed_range_on_mounted_path() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 8 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-move-ext-hole.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_move_ext_rejects_hole_backed_range";
    let source = mnt.join("move_ext_hole_source.bin");
    let donor = mnt.join("move_ext_hole_donor.bin");
    let block_size = 4096_usize;

    let mut source_payload = Vec::with_capacity(block_size * 3);
    source_payload.extend(std::iter::repeat_n(0x31_u8, block_size));
    source_payload.extend(std::iter::repeat_n(0x32_u8, block_size));
    source_payload.extend(std::iter::repeat_n(0x33_u8, block_size));
    let mut donor_payload = Vec::with_capacity(block_size * 3);
    donor_payload.extend(std::iter::repeat_n(0x61_u8, block_size));
    donor_payload.extend(std::iter::repeat_n(0x62_u8, block_size));
    donor_payload.extend(std::iter::repeat_n(0x63_u8, block_size));

    fs::write(&source, &source_payload).expect("write source payload");
    fs::write(&donor, &donor_payload).expect("write donor payload");

    let fiemap_preflight = query_fiemap(&donor, 4);
    if matches!(
        fiemap_preflight["errno"].as_i64(),
        Some(errno) if errno == EOPNOTSUPP_ERRNO || errno == i64::from(libc::ENOTTY)
    ) {
        eprintln!(
            "EXT4 MOVE_EXT hole rejection skipped: current kernel/FUSE stack does not \
             route prerequisite ioctl coverage to userspace"
        );
        return;
    }

    let out = Command::new("fallocate")
        .args([
            "--keep-size",
            "--punch-hole",
            "-o",
            "4096",
            "-l",
            "4096",
            source.to_str().expect("source path utf8"),
        ])
        .output()
        .expect("run fallocate --punch-hole for move_ext source");
    assert!(
        out.status.success(),
        "move_ext hole setup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let expected_source = fs::read(&source).expect("read source after punching hole");
    assert!(
        expected_source[block_size..2 * block_size]
            .iter()
            .all(|&byte| byte == 0),
        "punched move_ext source block should read back as zeros"
    );
    let donor_before = fs::read(&donor).expect("read donor before move_ext");

    let report = ext4_move_ext_ioctl(&source, &donor, 1, 1, 1);
    let ioctl_trace = read_ioctl_trace(&ioctl_trace_path);
    if report["timeout"].as_bool() == Some(true) {
        assert!(
            !trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
            "MOVE_EXT hole rejection timed out after reaching ffs-fuse::ioctl: {ioctl_trace}"
        );
        eprintln!(
            "EXT4 MOVE_EXT hole rejection skipped: kernel/FUSE stack timed out before \
             ffs-fuse::ioctl"
        );
        return;
    }
    if matches!(
        report["errno"].as_i64(),
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO
    ) && !trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD)
    {
        eprintln!(
            "EXT4 MOVE_EXT hole rejection skipped: kernel/VFS returned unsupported errno before \
             ffs-fuse::ioctl (trace empty)"
        );
        return;
    }
    assert!(
        trace_contains_cmd(&ioctl_trace, EXT4_IOC_MOVE_EXT_CMD),
        "MOVE_EXT hole rejection should still reach ffs-fuse::ioctl: {ioctl_trace}"
    );
    assert_eq!(
        report["errno"].as_i64(),
        Some(EOPNOTSUPP_ERRNO),
        "hole-backed MOVE_EXT range should reject with EOPNOTSUPP: {report}"
    );
    assert_eq!(
        fs::read(&source).expect("read source after rejected move_ext"),
        expected_source,
        "rejected MOVE_EXT must leave the source file unchanged"
    );
    assert_eq!(
        fs::read(&donor).expect("read donor after rejected move_ext"),
        donor_before,
        "rejected MOVE_EXT must leave the donor file unchanged"
    );

    emit_scenario_result(scenario_id, "PASS", Some("errno=95_hole_backed_range"));
}

/// Mounted-path proof that ext4 mutation ioctls (SETFLAGS and MOVE_EXT) surface
/// a deterministic read-only rejection when the mount is `read_only: true`.
///
/// The backend already rejects these ioctls with `EROFS` at dispatch time for
/// read-only sessions (see `ffs-fuse` unit tests), but until now the
/// harness-level, real-kernel path only proved the writable happy-path and the
/// writable hole-backed rejection.  This scenario stitches the two phases
/// together: seed source + donor files via a brief rw mount, drop the session,
/// remount the same image read-only, and then prove — against the real FUSE
/// transport — that both mutation ioctls fail and the seeded file contents
/// remain byte-identical afterwards.
///
/// Per bd-l1sr3 the rejection path is a documented disjunction: either the
/// kernel/VFS short-circuits before dispatch (trace does **not** contain the
/// command) or the request reaches `ffs-fuse::ioctl` which then returns
/// `EROFS` (trace **does** contain it).  Both are acceptable; the
/// non-acceptable outcome is "ffs-fuse dispatched and mutated the image
/// anyway", which the post-state byte compare pins down.
#[test]
#[allow(clippy::too_many_lines)]
fn fuse_ioctl_ext4_mutation_ioctls_fast_fail_erofs_on_read_only_mount() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 8 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    // ── Phase 1: rw mount, seed source + donor, then tear down. ────────────
    // `auto_unmount: true` so the kernel FUSE mount is released when the
    // `BackgroundSession` is dropped, leaving the backing image ready for a
    // fresh ro remount.  The seed payloads are 4 blocks of distinct fill each
    // so any accidental MOVE_EXT swap through the ro-rejection path is
    // instantly visible in the post-state compare.
    let setup_trace_path: PathBuf = tmp.path().join("ioctl-ext4-erofs-setup.log");
    let setup_mount_opts = MountOptions {
        read_only: false,
        auto_unmount: true,
        ioctl_trace_path: Some(setup_trace_path),
        ..MountOptions::default()
    };
    let block_size = 4096_usize;
    let source_rel = "erofs_source.bin";
    let donor_rel = "erofs_donor.bin";
    let source_payload: Vec<u8> = std::iter::repeat_n(0x5A_u8, block_size * 4).collect();
    let donor_payload: Vec<u8> = std::iter::repeat_n(0xA5_u8, block_size * 4).collect();
    {
        let Some(setup_session) = try_mount_ffs_rw_with_options(&image, &mnt, &setup_mount_opts)
        else {
            return;
        };
        fs::write(mnt.join(source_rel), &source_payload).expect("write ro source seed");
        fs::write(mnt.join(donor_rel), &donor_payload).expect("write ro donor seed");
        drop(setup_session);
    }
    // Give the kernel a beat to release the mount before Phase 2 rebinds it.
    thread::sleep(Duration::from_millis(500));

    // ── Phase 2: ro mount, attempt mutation ioctls, assert EROFS + no drift.
    let ro_trace_path: PathBuf = tmp.path().join("ioctl-ext4-erofs.log");
    let ro_mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ioctl_trace_path: Some(ro_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_ro_session) = try_mount_ffs_with_options(&image, &mnt, &ro_mount_opts) else {
        return;
    };

    let source_path = mnt.join(source_rel);
    let donor_path = mnt.join(donor_rel);

    let source_before = fs::read(&source_path).expect("read source on ro mount");
    let donor_before = fs::read(&donor_path).expect("read donor on ro mount");
    assert_eq!(
        source_before, source_payload,
        "ro remount must expose seeded source bytes identically"
    );
    assert_eq!(
        donor_before, donor_payload,
        "ro remount must expose seeded donor bytes identically"
    );

    let scenario_id = "ext4_ioctl_mutation_rejects_erofs_on_ro_mount";

    // SETFLAGS: adding NOATIME to a file on an ro mount must not succeed.
    let setflags_report =
        ext4_inode_flags_ioctl(&source_path, "set", Some(ffs_types::EXT4_NOATIME_FL));
    let setflags_trace = read_ioctl_trace(&ro_trace_path);
    match setflags_report["errno"].as_i64() {
        Some(errno) if errno == i64::from(libc::EROFS) => {
            // Accepted: either the kernel/VFS short-circuited, or ffs-fuse
            // rejected after dispatch — both land EROFS on the caller.
        }
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO => {
            assert!(
                !trace_contains_cmd(&setflags_trace, EXT4_IOC_SETFLAGS_CMD),
                "SETFLAGS surfaced transport-unsupported errno after reaching \
                 ffs-fuse::ioctl on ro mount: {setflags_trace}"
            );
            eprintln!(
                "SETFLAGS ro rejection: kernel/VFS returned transport-unsupported errno \
                 before ffs-fuse::ioctl — acceptable per documented transport behaviour"
            );
        }
        other => panic!(
            "unexpected SETFLAGS errno on ro mount: {other:?} report={setflags_report} \
             trace={setflags_trace}"
        ),
    }

    // MOVE_EXT: swap 1 block between source and donor.  On ro, must reject.
    let move_ext_report = ext4_move_ext_ioctl(&source_path, &donor_path, 0, 0, 1);
    let move_ext_trace = read_ioctl_trace(&ro_trace_path);
    if move_ext_report["timeout"].as_bool() == Some(true) {
        assert!(
            !trace_contains_cmd(&move_ext_trace, EXT4_IOC_MOVE_EXT_CMD),
            "MOVE_EXT timed out after reaching ffs-fuse::ioctl on ro mount: {move_ext_trace}"
        );
        eprintln!(
            "MOVE_EXT ro rejection skipped: kernel/FUSE stack timed out before ffs-fuse::ioctl"
        );
        return;
    }
    match move_ext_report["errno"].as_i64() {
        Some(errno) if errno == i64::from(libc::EROFS) => {}
        Some(errno) if errno == i64::from(libc::ENOTTY) || errno == EOPNOTSUPP_ERRNO => {
            assert!(
                !trace_contains_cmd(&move_ext_trace, EXT4_IOC_MOVE_EXT_CMD),
                "MOVE_EXT surfaced transport-unsupported errno after reaching \
                 ffs-fuse::ioctl on ro mount: {move_ext_trace}"
            );
            eprintln!(
                "MOVE_EXT ro rejection: kernel/VFS returned transport-unsupported errno \
                 before ffs-fuse::ioctl — acceptable per documented transport behaviour"
            );
        }
        other => panic!(
            "unexpected MOVE_EXT errno on ro mount: {other:?} report={move_ext_report} \
             trace={move_ext_trace}"
        ),
    }

    // Post-state byte compare: neither rejected mutation may have perturbed
    // the seeded file contents — this is the real "no accidental mutation"
    // invariant the bead is protecting.
    let source_after = fs::read(&source_path).expect("read source after ro ioctls");
    let donor_after = fs::read(&donor_path).expect("read donor after ro ioctls");
    assert_eq!(
        source_after, source_payload,
        "rejected SETFLAGS/MOVE_EXT must not mutate source bytes on ro mount"
    );
    assert_eq!(
        donor_after, donor_payload,
        "rejected MOVE_EXT must not mutate donor bytes on ro mount"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("setflags+move_ext=EROFS_no_drift"),
    );
}

#[test]
fn ext4_fuse_seek_data_hole_reports_punched_range_offsets() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_seek_data_hole";
        let path = mnt.join("ext4_seek_layout.bin");
        assert_seek_data_hole_contract(&path, scenario_id);
    });
}

#[test]
fn ext4_fuse_seek_hole_reports_virtual_eof_for_fully_allocated_file() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_seek_hole_fully_allocated";
        let path = mnt.join("ext4_seek_fully_allocated.bin");
        assert_seek_fully_allocated_contract(&path, scenario_id);
    });
}

#[test]
fn ext4_fuse_seek_data_hole_reports_leading_sparse_hole_offsets() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_seek_leading_hole";
        let path = mnt.join("ext4_seek_leading_hole.bin");
        assert_seek_leading_hole_contract(&path, scenario_id);
    });
}

#[test]
fn ext4_fuse_seek_data_hole_reports_all_hole_sparse_file_offsets() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_seek_all_hole";
        let path = mnt.join("ext4_seek_all_hole.bin");
        assert_seek_all_hole_contract(&path, scenario_id);
    });
}

#[test]
fn fuse_statfs_returns_valid_stats() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    // Use `stat -f` to exercise the FUSE statfs handler and parse the output.
    let out = Command::new("stat")
        .args(["-f", "-c", "%s %b %f %a %c %d %l", mnt.to_str().unwrap()])
        .output()
        .expect("stat -f on mountpoint");
    assert!(
        out.status.success(),
        "stat -f failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let fields: Vec<&str> = stdout.split_whitespace().collect();
    assert_eq!(
        fields.len(),
        7,
        "expected 7 stat -f fields, got: {stdout:?}"
    );

    // Parse statfs fields: block_size blocks blocks_free blocks_avail files files_free namelen
    let block_size: u64 = fields[0].parse().expect("parse block_size");
    let blocks: u64 = fields[1].parse().expect("parse blocks");
    let blocks_free: u64 = fields[2].parse().expect("parse blocks_free");
    let blocks_avail: u64 = fields[3].parse().expect("parse blocks_avail");
    let files: u64 = fields[4].parse().expect("parse files");
    let files_free: u64 = fields[5].parse().expect("parse files_free");
    let namelen: u64 = fields[6].parse().expect("parse namelen");

    // Validate: block size should be a power of two in [1024, 65536].
    assert!(
        block_size.is_power_of_two() && (1024..=65536).contains(&block_size),
        "block_size {block_size} should be a power-of-two in [1024, 65536]"
    );

    // Total blocks should be non-zero (we made a 4 MiB image).
    assert!(blocks > 0, "total blocks should be > 0");

    // Free blocks should not exceed total blocks.
    assert!(
        blocks_free <= blocks,
        "free blocks ({blocks_free}) should be <= total ({blocks})"
    );
    assert!(
        blocks_avail <= blocks,
        "available blocks ({blocks_avail}) should be <= total ({blocks})"
    );

    // Total inodes should be non-zero.
    assert!(files > 0, "total inodes should be > 0");
    assert!(
        files_free <= files,
        "free inodes ({files_free}) should be <= total ({files})"
    );

    // Max filename length: ext4 is 255.
    assert_eq!(namelen, 255, "ext4 max filename length should be 255");
}

#[derive(Debug, Clone, Copy)]
struct StatFsSnapshot {
    blocks_free: u64,
    files_free: u64,
}

fn statfs_snapshot(path: &Path) -> StatFsSnapshot {
    let out = Command::new("stat")
        .args(["-f", "-c", "%s %b %f %a %c %d", path.to_str().unwrap()])
        .output()
        .expect("stat -f snapshot");
    assert!(
        out.status.success(),
        "stat -f snapshot failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let fields: Vec<&str> = stdout.split_whitespace().collect();
    assert_eq!(
        fields.len(),
        6,
        "expected 6 stat -f fields, got: {stdout:?}"
    );

    let _block_size: u64 = fields[0].parse().expect("parse block_size");
    let _blocks: u64 = fields[1].parse().expect("parse blocks");
    let blocks_free: u64 = fields[2].parse().expect("parse blocks_free");
    let _blocks_avail: u64 = fields[3].parse().expect("parse blocks_avail");
    let _files: u64 = fields[4].parse().expect("parse files");
    let files_free: u64 = fields[5].parse().expect("parse files_free");

    StatFsSnapshot {
        blocks_free,
        files_free,
    }
}

#[test]
fn fuse_write_large_file() {
    with_rw_mount(|mnt| {
        let path = mnt.join("large.bin");
        // Write 64 KiB of patterned data (crosses multiple blocks).
        let data = patterned_bytes(65_536, 251, 0);
        fs::write(&path, &data).expect("write large file via FUSE");

        let readback = fs::read(&path).expect("read large file");
        assert_eq!(readback.len(), 65536);
        assert_eq!(readback, data, "large file content should match");
    });
}

#[test]
fn fuse_spec_i3_write_and_persist_after_remount() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mount_a = tmp.path().join("mnt_a");
    fs::create_dir_all(&mount_a).expect("create first mountpoint");

    {
        let Some(_session) = try_mount_ffs_rw(&image, &mount_a) else {
            return;
        };
        let path = mount_a.join("persist_i3.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create persist_i3.txt");
        file.write_all(b"persisted across remount\n")
            .expect("write persistence payload");
        file.sync_all().expect("sync persistence payload");
        let out = Command::new("sync").output().expect("sync command");
        assert!(
            out.status.success(),
            "sync command failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    } // drop first mount session before remounting the same image

    thread::sleep(Duration::from_millis(150));

    let mount_b = tmp.path().join("mnt_b");
    fs::create_dir_all(&mount_b).expect("create second mountpoint");
    let Some(_session) = try_mount_ffs_rw(&image, &mount_b) else {
        return;
    };
    let persisted = fs::read_to_string(mount_b.join("persist_i3.txt"))
        .expect("read persisted file after remount");
    assert_eq!(persisted, "persisted across remount\n");
}

#[test]
fn fuse_spec_i5_delete_reclaims_free_counts() {
    with_rw_mount_sized(64 * 1024 * 1024, |mnt| {
        let before = statfs_snapshot(mnt);
        let batch_dir = mnt.join("reclaim_batch");
        fs::create_dir(&batch_dir).expect("mkdir reclaim_batch");

        for idx in 0..1_000_u32 {
            let path = batch_dir.join(format!("file_{idx:04}.txt"));
            fs::write(path, format!("payload {idx}\n").as_bytes())
                .unwrap_or_else(|e| panic!("write reclaim file {idx}: {e}"));
        }

        let after_create = statfs_snapshot(mnt);
        assert!(
            after_create.blocks_free <= before.blocks_free,
            "free block count should not increase after creating files (before={}, after={})",
            before.blocks_free,
            after_create.blocks_free
        );
        assert!(
            after_create.files_free <= before.files_free,
            "free inode count should not increase after creating files (before={}, after={})",
            before.files_free,
            after_create.files_free
        );

        for idx in 0..1_000_u32 {
            let path = batch_dir.join(format!("file_{idx:04}.txt"));
            fs::remove_file(path).unwrap_or_else(|e| panic!("remove reclaim file {idx}: {e}"));
        }
        fs::remove_dir(&batch_dir).expect("remove reclaim_batch");

        let after_delete = statfs_snapshot(mnt);
        assert!(
            after_delete.blocks_free >= after_create.blocks_free,
            "free blocks should increase after delete (after_create={}, after_delete={})",
            after_create.blocks_free,
            after_delete.blocks_free
        );
        assert!(
            after_delete.files_free >= after_create.files_free,
            "free inodes should increase after delete (after_create={}, after_delete={})",
            after_create.files_free,
            after_delete.files_free
        );

        // ext4/FUSE metadata bookkeeping may leave a small delta in free counts.
        let block_slack = 8_u64;
        let inode_slack = 4_u64;
        assert!(
            after_delete.blocks_free + block_slack >= before.blocks_free,
            "free blocks should be restored within slack after delete (before={}, after_delete={}, slack={})",
            before.blocks_free,
            after_delete.blocks_free,
            block_slack
        );
        assert!(
            after_delete.files_free + inode_slack >= before.files_free,
            "free inodes should be restored within slack after delete (before={}, after_delete={}, slack={})",
            before.files_free,
            after_delete.files_free,
            inode_slack
        );
    });
}

#[test]
fn fuse_spec_i6_concurrent_writes_no_corruption() {
    with_rw_mount(|mnt| {
        const THREADS: usize = 4;
        const WRITES_PER_THREAD: usize = 256;

        let mut handles = Vec::with_capacity(THREADS);
        for thread_id in 0..THREADS {
            let mount_root = mnt.to_path_buf();
            handles.push(thread::spawn(move || {
                let path = mount_root.join(format!("i6_thread_{thread_id}.txt"));
                let mut expected = String::new();
                for write_id in 0..WRITES_PER_THREAD {
                    use std::fmt::Write;
                    let _ = writeln!(expected, "thread={thread_id} write={write_id}");
                }
                fs::write(&path, expected.as_bytes()).expect("write concurrent thread file");
                let readback = fs::read_to_string(&path).expect("read concurrent thread file");
                assert_eq!(readback, expected, "thread file content should match");
            }));
        }

        for handle in handles {
            handle
                .join()
                .expect("concurrent writer thread should succeed");
        }

        for thread_id in 0..THREADS {
            let path = mnt.join(format!("i6_thread_{thread_id}.txt"));
            let content = fs::read_to_string(&path).expect("final verify concurrent thread file");
            let lines: HashSet<&str> = content.lines().collect();
            assert_eq!(
                lines.len(),
                WRITES_PER_THREAD,
                "thread file should have exactly {WRITES_PER_THREAD} lines"
            );
            for write_id in 0..WRITES_PER_THREAD {
                let needle = format!("thread={thread_id} write={write_id}");
                assert!(
                    lines.contains(needle.as_str()),
                    "missing expected line: {needle}"
                );
            }
        }
    });
}

#[test]
fn fuse_spec_i7_reader_sees_pre_modification_version_during_write() {
    with_rw_mount(|mnt| {
        let path = mnt.join("i7_snapshot.txt");
        fs::write(&path, b"old-version\n").expect("write old snapshot version");
        let writer_path = path.clone();

        let writer = thread::spawn(move || {
            let replacement = writer_path.with_extension("tmp");
            let payload = "new-version\n".repeat(8_192);
            fs::write(&replacement, payload.as_bytes()).expect("write replacement payload");
            thread::sleep(Duration::from_millis(100));
            fs::rename(&replacement, &writer_path).expect("atomic replace for snapshot check");
        });

        // While writer prepares replacement data, readers should still see the old version.
        thread::sleep(Duration::from_millis(20));
        let observed = fs::read_to_string(&path).expect("read pre-commit path view");

        writer.join().expect("writer thread should succeed");

        assert_eq!(
            observed, "old-version\n",
            "reader should observe the pre-modification version while replacement is in-flight"
        );
        let latest = fs::read_to_string(&path).expect("read latest path version");
        assert!(
            latest.starts_with("new-version\n"),
            "path should expose the post-modification version"
        );
    });
}

// ── Large directory and ENOSPC E2E tests ─────────────────────────────────────

#[test]
fn fuse_readdir_large_directory() {
    with_rw_mount(|mnt| {
        let dir = mnt.join("bigdir");
        fs::create_dir(&dir).expect("mkdir bigdir");

        // Create 100 files in the directory.
        let count = 100_usize;
        for i in 0..count {
            let name = format!("file_{i:04}.txt");
            fs::write(dir.join(&name), format!("content {i}").as_bytes())
                .unwrap_or_else(|e| panic!("write {name}: {e}"));
        }

        // Read directory and collect all entries.
        let entries: Vec<String> = fs::read_dir(&dir)
            .expect("readdir bigdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        // Verify no duplicates.
        let mut sorted = entries.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            entries.len(),
            sorted.len(),
            "readdir should return no duplicate entries"
        );

        // Verify we got all files.
        assert_eq!(
            entries.len(),
            count,
            "readdir should return all {count} files, got {}",
            entries.len()
        );

        // Spot-check a few entries.
        assert!(entries.contains(&"file_0000.txt".to_owned()));
        assert!(entries.contains(&"file_0050.txt".to_owned()));
        assert!(entries.contains(&"file_0099.txt".to_owned()));
    });
}

/// Regression test: creating files that span multiple directory blocks
/// then removing them must succeed.  Exercises the transition from
/// a single-block to a multi-block directory.
#[test]
fn fuse_create_and_remove_across_dir_block_boundary() {
    with_rw_mount_sized(64 * 1024 * 1024, |mnt| {
        let dir = mnt.join("boundary_dir");
        fs::create_dir(&dir).expect("mkdir boundary_dir");

        // 200 files crosses the ~170-entry first-block boundary.
        let count = 200_u32;
        for i in 0..count {
            let name = format!("file_{i:04}.txt");
            let path = dir.join(&name);
            fs::write(&path, format!("payload {i}\n").as_bytes())
                .unwrap_or_else(|e| panic!("write {name}: {e}"));
        }

        // Verify all files are accessible.
        for i in 0..count {
            let name = format!("file_{i:04}.txt");
            let path = dir.join(&name);
            assert!(path.exists(), "file_{i:04}.txt should exist after creation");
        }

        // Remove all files.
        for i in 0..count {
            let name = format!("file_{i:04}.txt");
            let path = dir.join(&name);
            fs::remove_file(&path).unwrap_or_else(|e| panic!("remove file_{i:04}.txt: {e}"));
        }

        fs::remove_dir(&dir).expect("remove boundary_dir");
    });
}

#[test]
fn fuse_write_enospc_on_full_filesystem() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = tmp.path().join("tiny.ext4");

    // Create a very small 1 MiB ext4 image to exhaust space quickly.
    let f = fs::File::create(&image).expect("create tiny image");
    f.set_len(1024 * 1024).expect("set tiny image size");
    drop(f);

    let out = Command::new("mkfs.ext4")
        .args([
            "-F",
            "-b",
            "1024",
            "-N",
            "32",
            "-L",
            "ffs-enospc",
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.ext4 tiny");
    assert!(
        out.status.success(),
        "mkfs.ext4 tiny failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs_rw(&image, &mnt) else {
        return;
    };

    // Write data to fill the filesystem.
    let mut hit_enospc = false;
    for i in 0..100 {
        let path = mnt.join(format!("fill_{i:03}.dat"));
        // Write ~10KB per file to gradually fill 1MB image.
        match fs::write(&path, [0xAA_u8; 10240]) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(28 /* ENOSPC */) => {
                hit_enospc = true;
                break;
            }
            Err(e) => {
                // Other errors might occur depending on allocator behavior.
                eprintln!("write fill_{i}: {e}");
                hit_enospc = true;
                break;
            }
        }
    }

    assert!(
        hit_enospc,
        "should eventually hit ENOSPC on 1 MiB filesystem"
    );
}

// ── fsync/flush E2E tests ────────────────────────────────────────────────────

#[test]
fn fuse_fsync_persists_written_data() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fsync";
        let path = mnt.join("synced.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create synced.txt");

        file.write_all(b"data before fsync\n")
            .expect("write before fsync");

        // sync_all triggers FUSE fsync.
        file.sync_all().expect("fsync via sync_all");

        drop(file);

        // Read back and verify.
        let content = fs::read_to_string(&path).expect("read after fsync");
        assert_eq!(content, "data before fsync\n");
        emit_scenario_result(scenario_id, "PASS", Some("sync_all"));
    });
}

#[test]
fn fuse_fsyncdir_emits_scenario_result_and_preserves_dirent() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fsyncdir";
        let dir = mnt.join("synced_dir");
        fs::create_dir(&dir).expect("mkdir for ext4 fsyncdir");

        let child = dir.join("child.txt");
        fs::write(&child, b"directory sync payload\n").expect("write child before ext4 fsyncdir");

        let dirfd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(&dir)
            .expect("open directory fd for ext4 fsyncdir");
        dirfd.sync_all().expect("fsyncdir via sync_all on ext4");
        drop(dirfd);

        let entries: HashSet<String> = fs::read_dir(&dir)
            .expect("readdir after ext4 fsyncdir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.contains("child.txt"),
            "directory entry should remain visible after ext4 fsyncdir, got: {entries:?}"
        );
        assert_eq!(
            fs::read_to_string(&child).expect("read child after ext4 fsyncdir"),
            "directory sync payload\n"
        );
        emit_scenario_result(scenario_id, "PASS", Some("dirfd_sync_all"));
    });
}

#[test]
fn fuse_sync_data_without_metadata() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_fdatasync";
        let path = mnt.join("datasync.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create datasync.txt");

        file.write_all(b"datasync content\n")
            .expect("write before sync_data");

        // sync_data triggers FUSE fsync with datasync=true.
        file.sync_data().expect("sync_data");

        drop(file);

        let content = fs::read_to_string(&path).expect("read after sync_data");
        assert_eq!(content, "datasync content\n");
        emit_scenario_result(scenario_id, "PASS", Some("sync_data"));
    });
}

#[test]
fn ext4_fuse_flush_emits_scenario_result_and_preserves_data() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_flush";
        let path = mnt.join("flushed.txt");

        // Write and explicitly flush (triggers FUSE flush).
        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .expect("create flushed.txt");

            file.write_all(b"flushed content\n").expect("write");
            // std::io::Write::flush triggers the FUSE flush handler.
            file.flush().expect("explicit flush");
        } // drop/close triggers another FUSE flush+release

        let content = fs::read_to_string(&path).expect("read after flush+close");
        assert_eq!(content, "flushed content\n");
        emit_scenario_result(scenario_id, "PASS", Some("explicit_flush_and_close"));
    });
}

#[test]
fn ext4_fuse_read_only_flush_succeeds_without_data_drift() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    assert_read_only_flush_contract(&mnt.join("hello.txt"), "ext4_ro_flush_succeeds_no_drift");
}

#[test]
fn fuse_fsync_after_multiple_writes() {
    with_rw_mount(|mnt| {
        let path = mnt.join("multi_write_sync.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create multi_write_sync.txt");

        // Multiple writes followed by a single fsync.
        file.write_all(b"chunk1 ").expect("write chunk1");
        file.write_all(b"chunk2 ").expect("write chunk2");
        file.write_all(b"chunk3").expect("write chunk3");
        file.sync_all().expect("fsync after multiple writes");

        drop(file);

        let content = fs::read_to_string(&path).expect("read multi_write");
        assert_eq!(content, "chunk1 chunk2 chunk3");
    });
}

// ── Extended attribute (xattr) E2E tests ─────────────────────────────────────

/// Helper: set an extended attribute on a file using Python's `os.setxattr`.
fn py_setxattr(path: &Path, name: &str, value: &[u8]) {
    let hex_val = value.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    let script = format!(
        "import os; os.setxattr({path:?}, {name:?}, bytes.fromhex({hex_val:?}))",
        path = path.to_str().unwrap(),
        name = name,
        hex_val = hex_val,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 setxattr");
    assert!(
        out.status.success(),
        "setxattr failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn py_setxattr_report(path: &Path, name: &str, value: &[u8], flags: i32) -> Value {
    let hex_val = value.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    let script = format!(
        "import json, os\ntry:\n os.setxattr({path:?}, {name:?}, bytes.fromhex({hex_val:?}), {flags})\n print(json.dumps({{'ok': True}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        name = name,
        hex_val = hex_val,
        flags = flags,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 setxattr JSON");
    assert!(
        out.status.success(),
        "python3 setxattr JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse setxattr JSON")
}

/// Helper: get an extended attribute value from a file using Python's `os.getxattr`.
/// Returns `None` if the attribute does not exist.
fn py_getxattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let script = format!(
        "import os,sys\ntry:\n v=os.getxattr({path:?},{name:?})\n sys.stdout.buffer.write(v)\nexcept OSError:\n sys.exit(1)",
        path = path.to_str().unwrap(),
        name = name,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 getxattr");
    if out.status.success() {
        Some(out.stdout)
    } else {
        None
    }
}

fn py_getxattr_report(path: &Path, name: &str) -> Value {
    let script = format!(
        "import json, os\ntry:\n v=os.getxattr({path:?},{name:?})\n print(json.dumps({{'value_hex': v.hex(), 'len': len(v)}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        name = name,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 getxattr JSON");
    assert!(
        out.status.success(),
        "python3 getxattr JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse getxattr JSON")
}

fn py_getxattr_probe_report(path: &Path, name: &str, size: usize) -> Value {
    let script = format!(
        "import ctypes, json, os\nlibc = ctypes.CDLL(None, use_errno=True)\nlibc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]\nlibc.getxattr.restype = ctypes.c_ssize_t\nbuf = None if {size} == 0 else ctypes.create_string_buffer({size})\nret = libc.getxattr({path:?}.encode(), {name:?}.encode(), None if buf is None else ctypes.byref(buf), {size})\nif ret >= 0:\n out = {{'len': ret}}\n if buf is not None:\n  out['value_hex'] = ctypes.string_at(buf, ret).hex()\n print(json.dumps(out))\nelse:\n errno = ctypes.get_errno()\n print(json.dumps({{'errno': errno, 'message': os.strerror(errno)}}))",
        path = path.to_str().unwrap(),
        name = name,
        size = size,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 getxattr probe JSON");
    assert!(
        out.status.success(),
        "python3 getxattr probe JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse getxattr probe JSON")
}

/// Helper: list extended attribute names on a file using Python's `os.listxattr`.
fn py_listxattr(path: &Path) -> Vec<String> {
    let script = format!(
        "import os\nfor n in os.listxattr({path:?}):\n print(n)",
        path = path.to_str().unwrap(),
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 listxattr");
    assert!(
        out.status.success(),
        "listxattr failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

fn py_listxattr_probe_report(path: &Path, size: usize) -> Value {
    let script = format!(
        "import ctypes, json, os\nlibc = ctypes.CDLL(None, use_errno=True)\nlibc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]\nlibc.listxattr.restype = ctypes.c_ssize_t\nbuf = None if {size} == 0 else ctypes.create_string_buffer({size})\nret = libc.listxattr({path:?}.encode(), None if buf is None else ctypes.byref(buf), {size})\nif ret >= 0:\n out = {{'len': ret}}\n if buf is not None:\n  raw = ctypes.string_at(buf, ret)\n  out['names'] = [chunk.decode() for chunk in raw.split(b'\\0') if chunk]\n print(json.dumps(out))\nelse:\n errno = ctypes.get_errno()\n print(json.dumps({{'errno': errno, 'message': os.strerror(errno)}}))",
        path = path.to_str().unwrap(),
        size = size,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 listxattr probe JSON");
    assert!(
        out.status.success(),
        "python3 listxattr probe JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse listxattr probe JSON")
}

/// Helper: remove an extended attribute. Returns true if removal succeeded.
fn py_removexattr(path: &Path, name: &str) -> bool {
    let script = format!(
        "import os; os.removexattr({path:?}, {name:?})",
        path = path.to_str().unwrap(),
        name = name,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 removexattr");
    out.status.success()
}

fn py_removexattr_report(path: &Path, name: &str) -> Value {
    let script = format!(
        "import json, os\ntry:\n os.removexattr({path:?}, {name:?})\n print(json.dumps({{'ok': True}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        name = name,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 removexattr JSON");
    assert!(
        out.status.success(),
        "python3 removexattr JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse removexattr JSON")
}

fn py_chmod_report(path: &Path, mode: u32) -> Value {
    let script = format!(
        "import json, os\ntry:\n os.chmod({path:?}, {mode})\n print(json.dumps({{'ok': True}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        mode = mode,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 chmod JSON");
    assert!(
        out.status.success(),
        "python3 chmod JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse chmod JSON")
}

fn py_truncate_report(path: &Path, size: u64) -> Value {
    let script = format!(
        "import json, os\ntry:\n os.truncate({path:?}, {size})\n print(json.dumps({{'ok': True}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        size = size,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 truncate JSON");
    assert!(
        out.status.success(),
        "python3 truncate JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse truncate JSON")
}

fn py_utime_report(path: &Path, atime: i64, mtime: i64) -> Value {
    let script = format!(
        "import json, os\ntry:\n os.utime({path:?}, ({atime}, {mtime}))\n print(json.dumps({{'ok': True}}))\nexcept OSError as e:\n print(json.dumps({{'errno': e.errno, 'message': str(e)}}))",
        path = path.to_str().unwrap(),
        atime = atime,
        mtime = mtime,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 utime JSON");
    assert!(
        out.status.success(),
        "python3 utime JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse utime JSON")
}

fn py_renameat2_report(old_path: &Path, new_path: &Path, flags: u32) -> Value {
    let script = format!(
        "import ctypes, json, os\nAT_FDCWD = -100\nlibc = ctypes.CDLL(None, use_errno=True)\nrenameat2 = libc.renameat2\nrenameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]\nrenameat2.restype = ctypes.c_int\nret = renameat2(AT_FDCWD, {old_path:?}.encode(), AT_FDCWD, {new_path:?}.encode(), {flags})\nif ret == 0:\n print(json.dumps({{'ok': True}}))\nelse:\n errno = ctypes.get_errno()\n print(json.dumps({{'errno': errno, 'message': os.strerror(errno)}}))",
        old_path = old_path.to_str().unwrap(),
        new_path = new_path.to_str().unwrap(),
        flags = flags,
    );
    let out = Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("python3 renameat2 JSON");
    assert!(
        out.status.success(),
        "python3 renameat2 JSON helper failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse renameat2 JSON")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStateSnapshot {
    bytes: Vec<u8>,
    mode: u32,
    len: u64,
    atime: i64,
    atime_nsec: i64,
    mtime: i64,
    mtime_nsec: i64,
}

fn snapshot_file_state(path: &Path) -> FileStateSnapshot {
    let meta = fs::metadata(path).expect("stat file state");
    FileStateSnapshot {
        bytes: fs::read(path).expect("read file state"),
        mode: meta.permissions().mode() & 0o7777,
        len: meta.len(),
        atime: meta.atime(),
        atime_nsec: meta.atime_nsec(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
    }
}

fn assert_file_state_unchanged(path: &Path, before: &FileStateSnapshot, context: &str) {
    let after = snapshot_file_state(path);
    assert_eq!(
        after, *before,
        "{context} must not change file contents or metadata on a read-only mount"
    );
}

fn snapshot_directory_entries(path: &Path) -> HashSet<String> {
    fs::read_dir(path)
        .expect("readdir directory state")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

fn assert_unlink_directory_via_remove_file_reports_eisdir(mnt: &Path, scenario_id: &str) {
    let dir = mnt.join("unlink_directory_target");
    fs::create_dir(&dir).expect("create directory unlink target");
    let child = dir.join("child.txt");
    fs::write(&child, b"child").expect("seed child beneath unlink target");

    let root_entries_before = snapshot_directory_entries(mnt);
    let dir_entries_before = snapshot_directory_entries(&dir);
    let child_before = snapshot_file_state(&child);

    let err = fs::remove_file(&dir).expect_err("unlink on directory should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EISDIR),
        "unlink on a directory should surface exact EISDIR: {err}"
    );
    assert!(
        dir.is_dir(),
        "failed unlink on directory must leave the directory in place"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "failed unlink on directory must not change visible root entries"
    );
    assert_eq!(
        snapshot_directory_entries(&dir),
        dir_entries_before,
        "failed unlink on directory must not change child entries"
    );
    assert_file_state_unchanged(&child, &child_before, "directory unlink rejection");

    emit_scenario_result(scenario_id, "PASS", Some("errno=EISDIR_no_drift"));
}

fn assert_unlink_missing_reports_enoent(mnt: &Path, scenario_id: &str) {
    let missing = mnt.join("missing_unlink_target.txt");
    let witness = mnt.join("unlink_missing_witness.txt");
    fs::write(&witness, b"unlink missing witness\n").expect("write unlink missing witness");
    let root_entries_before = snapshot_directory_entries(mnt);
    let witness_before = snapshot_file_state(&witness);

    let err = fs::remove_file(&missing).expect_err("unlink on missing path should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOENT),
        "unlink on a missing path should surface exact ENOENT: {err}"
    );
    assert!(
        fs::symlink_metadata(&missing).is_err(),
        "failed unlink on a missing path must not materialize the missing entry"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "failed unlink on a missing path must not change visible root entries"
    );
    assert_file_state_unchanged(&witness, &witness_before, "missing unlink rejection");

    emit_scenario_result(scenario_id, "PASS", Some("errno=ENOENT_no_drift"));
}

fn assert_rename_missing_source_reports_enoent(mnt: &Path, scenario_id: &str) {
    let missing_source = mnt.join("missing_rename_source.txt");
    let target = mnt.join("missing_rename_target.txt");
    let witness = mnt.join("rename_missing_witness.txt");
    fs::write(&witness, b"rename missing witness\n").expect("write rename missing witness");
    let root_entries_before = snapshot_directory_entries(mnt);
    let witness_before = snapshot_file_state(&witness);

    let err =
        fs::rename(&missing_source, &target).expect_err("rename with missing source should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOENT),
        "rename with a missing source should surface exact ENOENT: {err}"
    );
    assert!(
        fs::symlink_metadata(&missing_source).is_err(),
        "rejected rename must leave the missing source absent"
    );
    assert!(
        fs::symlink_metadata(&target).is_err(),
        "rejected rename must not create the target entry"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "rejected rename with missing source must not change visible root entries"
    );
    assert_file_state_unchanged(&witness, &witness_before, "rename missing-source rejection");

    emit_scenario_result(scenario_id, "PASS", Some("errno=ENOENT_no_drift"));
}

#[allow(clippy::too_many_lines)]
fn assert_rename_file_directory_type_mismatch_contract(mnt: &Path, scenario_id: &str) {
    let file_source = mnt.join("rename_file_over_dir_src.txt");
    let directory_target = mnt.join("rename_file_over_dir_dst");
    fs::write(&file_source, b"rename file source\n").expect("write rename file source");
    fs::create_dir(&directory_target).expect("create rename directory target");
    let directory_child = directory_target.join("child.txt");
    fs::write(&directory_child, b"rename dir child\n").expect("write rename directory child");

    let file_over_dir_entries_before = snapshot_directory_entries(mnt);
    let file_source_before = snapshot_file_state(&file_source);
    let directory_child_before = snapshot_file_state(&directory_child);
    let directory_entries_before = snapshot_directory_entries(&directory_target);

    let file_over_dir_err = fs::rename(&file_source, &directory_target)
        .expect_err("rename file over directory should fail");
    assert_eq!(
        file_over_dir_err.raw_os_error(),
        Some(libc::EISDIR),
        "rename file over directory should surface exact EISDIR: {file_over_dir_err}"
    );
    assert!(
        fs::symlink_metadata(&file_source).is_ok(),
        "rejected rename must leave the file source entry in place"
    );
    assert!(
        fs::metadata(&directory_target)
            .expect("stat directory target after rejected rename")
            .is_dir(),
        "rejected rename must leave the destination as a directory"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        file_over_dir_entries_before,
        "rename file over directory must not change visible root entries"
    );
    assert_eq!(
        snapshot_directory_entries(&directory_target),
        directory_entries_before,
        "rename file over directory must not change directory child entries"
    );
    assert_file_state_unchanged(
        &file_source,
        &file_source_before,
        "rename file over directory source",
    );
    assert_file_state_unchanged(
        &directory_child,
        &directory_child_before,
        "rename file over directory child",
    );

    let directory_source = mnt.join("rename_dir_over_file_src");
    let file_target = mnt.join("rename_dir_over_file_dst.txt");
    fs::create_dir(&directory_source).expect("create rename directory source");
    let source_child = directory_source.join("nested.txt");
    fs::write(&source_child, b"rename dir source child\n")
        .expect("write rename directory source child");
    fs::write(&file_target, b"rename file target\n").expect("write rename file target");

    let dir_over_file_entries_before = snapshot_directory_entries(mnt);
    let source_entries_before = snapshot_directory_entries(&directory_source);
    let source_child_before = snapshot_file_state(&source_child);
    let file_target_before = snapshot_file_state(&file_target);

    let dir_over_file_err = fs::rename(&directory_source, &file_target)
        .expect_err("rename directory over file should fail");
    assert_eq!(
        dir_over_file_err.raw_os_error(),
        Some(libc::ENOTDIR),
        "rename directory over file should surface exact ENOTDIR: {dir_over_file_err}"
    );
    assert!(
        fs::metadata(&directory_source)
            .expect("stat directory source after rejected rename")
            .is_dir(),
        "rejected rename must leave the source as a directory"
    );
    assert!(
        fs::symlink_metadata(&source_child).is_ok(),
        "rejected rename must preserve the source directory child entry"
    );
    assert!(
        fs::metadata(&file_target)
            .expect("stat file target after rejected rename")
            .is_file(),
        "rejected rename must leave the destination as a file"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        dir_over_file_entries_before,
        "rename directory over file must not change visible root entries"
    );
    assert_eq!(
        snapshot_directory_entries(&directory_source),
        source_entries_before,
        "rename directory over file must not change source directory entries"
    );
    assert_file_state_unchanged(
        &source_child,
        &source_child_before,
        "rename directory over file child",
    );
    assert_file_state_unchanged(
        &file_target,
        &file_target_before,
        "rename directory over file target",
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("file_over_dir=EISDIR_dir_over_file=ENOTDIR_no_drift"),
    );
}

fn assert_read_only_flush_contract(path: &Path, scenario_id: &str) {
    let before = snapshot_file_state(path);
    let mut file = fs::File::open(path).expect("open file for read-only flush contract");
    file.flush().expect("read-only flush should succeed");
    drop(file);

    assert_file_state_unchanged(path, &before, "read-only flush");
    emit_scenario_result(scenario_id, "PASS", Some("flush_ok_no_drift"));
}

fn assert_read_only_file_sync_contract(
    path: &Path,
    scenario_id: &str,
    sync_name: &str,
    sync_fn: impl FnOnce(&fs::File) -> std::io::Result<()>,
) {
    let before = snapshot_file_state(path);
    let file = fs::File::open(path).expect("open file for read-only sync contract");
    let err = sync_fn(&file).expect_err("read-only sync should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EROFS),
        "read-only {sync_name} should surface exact EROFS: {err}"
    );
    drop(file);

    let context = format!("rejected {sync_name}");
    assert_file_state_unchanged(path, &before, &context);
    emit_scenario_result(scenario_id, "PASS", Some("sync=EROFS_no_drift"));
}

fn assert_read_only_dir_sync_contract(dir: &Path, child: &Path, scenario_id: &str) {
    let entries_before = snapshot_directory_entries(dir);
    let child_before = snapshot_file_state(child);

    let dirfd = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(dir)
        .expect("open directory fd for read-only sync contract");
    let err = dirfd
        .sync_all()
        .expect_err("read-only directory sync should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EROFS),
        "read-only fsyncdir should surface exact EROFS: {err}"
    );
    drop(dirfd);

    let entries_after = snapshot_directory_entries(dir);
    assert_eq!(
        entries_after, entries_before,
        "rejected fsyncdir must not change directory entries on a read-only mount"
    );
    assert_file_state_unchanged(child, &child_before, "rejected fsyncdir");
    emit_scenario_result(scenario_id, "PASS", Some("fsyncdir=EROFS_no_drift"));
}

fn assert_read_only_setattr_contract(path: &Path, scenario_id: &str) {
    let before = snapshot_file_state(path);
    let requested_mode = if before.mode == 0o755 { 0o600 } else { 0o755 };
    let truncate_len = if before.len == 5 { 6 } else { 5 };
    let requested_time = if before.mtime == 1_700_000_000 {
        1_700_000_123
    } else {
        1_700_000_000
    };

    let chmod_report = py_chmod_report(path, requested_mode);
    assert_eq!(
        chmod_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only chmod should surface exact EROFS: {chmod_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected chmod");

    let truncate_report = py_truncate_report(path, truncate_len);
    assert_eq!(
        truncate_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only truncate should surface exact EROFS: {truncate_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected truncate");

    let utime_report = py_utime_report(path, requested_time, requested_time);
    assert_eq!(
        utime_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only utime should surface exact EROFS: {utime_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected utime");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("chmod+truncate+utimes=EROFS_no_drift"),
    );
}

fn assert_read_only_xattr_mutation_contract(path: &Path, scenario_id: &str) {
    let before = snapshot_file_state(path);

    let set_report = py_setxattr_report(path, "user.created", b"blocked", 0);
    assert_eq!(
        set_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only setxattr should surface exact EROFS: {set_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected setxattr");
    assert!(
        py_getxattr(path, "user.created").is_none(),
        "read-only setxattr must not create a new xattr"
    );
    assert_eq!(
        py_getxattr(path, "user.locked").expect("locked xattr should remain readable"),
        b"original",
        "read-only setxattr must not disturb the targeted existing xattr state"
    );
    assert_eq!(
        py_getxattr(path, "user.keep").expect("keep xattr should remain readable"),
        b"preserve",
        "read-only setxattr must not disturb unrelated xattrs"
    );

    let remove_report = py_removexattr_report(path, "user.locked");
    assert_eq!(
        remove_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only removexattr should surface exact EROFS: {remove_report}"
    );
    assert_file_state_unchanged(path, &before, "rejected removexattr");
    assert_eq!(
        py_getxattr(path, "user.locked").expect("locked xattr should remain readable"),
        b"original",
        "read-only removexattr must not delete the targeted xattr"
    );
    assert_eq!(
        py_getxattr(path, "user.keep").expect("keep xattr should remain readable"),
        b"preserve",
        "read-only removexattr must not disturb unrelated xattrs"
    );

    let names = py_listxattr(path);
    assert!(
        !names.iter().any(|name| name == "user.created"),
        "read-only setxattr must not leave a newly created xattr behind: {names:?}"
    );
    assert!(
        names.iter().any(|name| name == "user.locked"),
        "read-only removexattr must leave the targeted xattr intact: {names:?}"
    );
    assert!(
        names.iter().any(|name| name == "user.keep"),
        "read-only xattr mutations must leave unrelated xattrs intact: {names:?}"
    );

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("setxattr+removexattr=EROFS_no_side_effects"),
    );
}

fn assert_read_only_namespace_mutation_contract(dir: &Path, seed: &Path, scenario_id: &str) {
    let entries_before = snapshot_directory_entries(dir);
    let seed_before = snapshot_file_state(seed);
    let seed_name = seed
        .file_name()
        .expect("seed file name")
        .to_string_lossy()
        .into_owned();

    let create_path = dir.join("blocked_create.txt");
    let create_err = fs::write(&create_path, b"blocked create")
        .expect_err("read-only create should fail with EROFS");
    assert_eq!(
        create_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only create should surface exact EROFS: {create_err}"
    );
    assert!(
        fs::symlink_metadata(&create_path).is_err(),
        "read-only create must not leave a new file behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected create must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected create");

    let mkdir_path = dir.join("blocked_dir");
    let mkdir_err = fs::create_dir(&mkdir_path).expect_err("read-only mkdir should fail");
    assert_eq!(
        mkdir_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only mkdir should surface exact EROFS: {mkdir_err}"
    );
    assert!(
        fs::symlink_metadata(&mkdir_path).is_err(),
        "read-only mkdir must not leave a new directory behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected mkdir must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected mkdir");

    let link_path = dir.join("blocked_link.txt");
    let link_err = fs::hard_link(seed, &link_path).expect_err("read-only link should fail");
    assert_eq!(
        link_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only hard link should surface exact EROFS: {link_err}"
    );
    assert!(
        fs::symlink_metadata(&link_path).is_err(),
        "read-only hard link must not leave a new directory entry behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected hard link must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected hard link");

    let symlink_path = dir.join("blocked_symlink.txt");
    let symlink_err = std::os::unix::fs::symlink(&seed_name, &symlink_path)
        .expect_err("read-only symlink should fail");
    assert_eq!(
        symlink_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only symlink should surface exact EROFS: {symlink_err}"
    );
    assert!(
        fs::symlink_metadata(&symlink_path).is_err(),
        "read-only symlink must not leave a new directory entry behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected symlink must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected symlink");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("create+mkdir+link+symlink=EROFS_no_drift"),
    );
}

fn assert_read_only_regular_write_contract(dir: &Path, seed: &Path, scenario_id: &str) {
    let entries_before = snapshot_directory_entries(dir);
    let seed_before = snapshot_file_state(seed);

    let create_path = dir.join("blocked_write_create.txt");
    let create_err = fs::write(&create_path, b"blocked create via write")
        .expect_err("read-only create-via-write should fail");
    assert_eq!(
        create_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only create-via-write should surface exact EROFS: {create_err}"
    );
    assert!(
        fs::symlink_metadata(&create_path).is_err(),
        "read-only create-via-write must not leave a new file behind"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected create-via-write must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected create-via-write");

    let overwrite_err = fs::OpenOptions::new()
        .write(true)
        .open(seed)
        .and_then(|mut file| {
            file.write_all(b"blocked overwrite write")?;
            file.flush()
        })
        .expect_err("read-only overwrite should fail with EROFS");
    assert_eq!(
        overwrite_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only overwrite should surface exact EROFS: {overwrite_err}"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected overwrite must not change visible directory entries"
    );
    assert_file_state_unchanged(seed, &seed_before, "rejected overwrite");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("create_via_write+overwrite=EROFS_no_drift"),
    );
}

fn assert_read_only_unlink_rmdir_and_rename_contract(
    dir: &Path,
    keep_file: &Path,
    empty_dir: &Path,
    rename_source: &Path,
    scenario_id: &str,
) {
    let entries_before = snapshot_directory_entries(dir);
    let keep_before = snapshot_file_state(keep_file);
    let rename_before = snapshot_file_state(rename_source);

    let unlink_err = fs::remove_file(keep_file).expect_err("read-only unlink should fail");
    assert_eq!(
        unlink_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only unlink should surface exact EROFS: {unlink_err}"
    );
    assert!(
        fs::symlink_metadata(keep_file).is_ok(),
        "read-only unlink must leave the source file in place"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected unlink must not change visible directory entries"
    );
    assert_file_state_unchanged(keep_file, &keep_before, "rejected unlink");
    assert_file_state_unchanged(rename_source, &rename_before, "rejected unlink");

    let rmdir_err = fs::remove_dir(empty_dir).expect_err("read-only rmdir should fail");
    assert_eq!(
        rmdir_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only rmdir should surface exact EROFS: {rmdir_err}"
    );
    assert!(
        fs::symlink_metadata(empty_dir).is_ok(),
        "read-only rmdir must leave the empty directory in place"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected rmdir must not change visible directory entries"
    );
    assert_file_state_unchanged(keep_file, &keep_before, "rejected rmdir");
    assert_file_state_unchanged(rename_source, &rename_before, "rejected rmdir");

    let rename_target = dir.join("readonly_rename_target.txt");
    let rename_err =
        fs::rename(rename_source, &rename_target).expect_err("read-only rename should fail");
    assert_eq!(
        rename_err.raw_os_error(),
        Some(libc::EROFS),
        "read-only rename should surface exact EROFS: {rename_err}"
    );
    assert!(
        fs::symlink_metadata(rename_source).is_ok(),
        "read-only rename must leave the source entry in place"
    );
    assert!(
        fs::symlink_metadata(&rename_target).is_err(),
        "read-only rename must not create the destination entry"
    );
    assert_eq!(
        snapshot_directory_entries(dir),
        entries_before,
        "rejected rename must not change visible directory entries"
    );
    assert_file_state_unchanged(keep_file, &keep_before, "rejected rename");
    assert_file_state_unchanged(rename_source, &rename_before, "rejected rename");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("unlink+rmdir+rename=EROFS_no_drift"),
    );
}

#[test]
fn fuse_xattr_set_get_list_remove() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Set a user xattr.
        py_setxattr(&path, "user.test_key", b"test_value_123");

        // Get it back.
        let val = py_getxattr(&path, "user.test_key").expect("xattr should exist after set");
        assert_eq!(val, b"test_value_123");

        // List should include it.
        let names = py_listxattr(&path);
        assert!(
            names.iter().any(|n| n == "user.test_key"),
            "listxattr should contain user.test_key, got: {names:?}"
        );

        // Remove it.
        assert!(
            py_removexattr(&path, "user.test_key"),
            "removexattr should succeed"
        );

        // Should be gone.
        assert!(
            py_getxattr(&path, "user.test_key").is_none(),
            "xattr should be absent after removexattr"
        );

        // listxattr should no longer include it.
        let names_after = py_listxattr(&path);
        assert!(
            !names_after.iter().any(|n| n == "user.test_key"),
            "listxattr should not contain user.test_key after removal"
        );
    });
}

#[test]
fn fuse_xattr_multiple_attributes() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Set multiple xattrs.
        py_setxattr(&path, "user.alpha", b"aaa");
        py_setxattr(&path, "user.beta", b"bbb");
        py_setxattr(&path, "user.gamma", b"ccc");

        // Verify each value.
        assert_eq!(py_getxattr(&path, "user.alpha").unwrap(), b"aaa");
        assert_eq!(py_getxattr(&path, "user.beta").unwrap(), b"bbb");
        assert_eq!(py_getxattr(&path, "user.gamma").unwrap(), b"ccc");

        // List should contain all three.
        let names = py_listxattr(&path);
        for expected in ["user.alpha", "user.beta", "user.gamma"] {
            assert!(
                names.iter().any(|n| n == expected),
                "listxattr should contain {expected}, got: {names:?}"
            );
        }
    });
}

#[test]
fn fuse_xattr_overwrite_value() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Set initial value.
        py_setxattr(&path, "user.mutable", b"original");
        assert_eq!(py_getxattr(&path, "user.mutable").unwrap(), b"original");

        // Overwrite with different value.
        py_setxattr(&path, "user.mutable", b"updated_value");
        assert_eq!(
            py_getxattr(&path, "user.mutable").unwrap(),
            b"updated_value"
        );
    });
}

#[test]
fn fuse_xattr_on_directory() {
    with_rw_mount(|mnt| {
        let dir = mnt.join("testdir");

        // Set xattr on directory.
        py_setxattr(&dir, "user.dir_attr", b"dir_value");

        let val = py_getxattr(&dir, "user.dir_attr").expect("xattr on dir should exist");
        assert_eq!(val, b"dir_value");

        let names = py_listxattr(&dir);
        assert!(
            names.iter().any(|n| n == "user.dir_attr"),
            "listxattr on dir should contain user.dir_attr, got: {names:?}"
        );
    });
}

#[test]
fn fuse_xattr_ext4_get_missing_reports_enodata_without_side_effects() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_xattr_get_missing_reports_enodata";
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_getxattr_report(&path, "user.does_not_exist");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "missing ext4 getxattr should surface ENODATA: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "missing getxattr must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read file bytes after missing getxattr"),
            original_file,
            "missing getxattr must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.does_not_exist"),
            "missing xattr should remain absent after ENODATA getxattr: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should remain listed after ENODATA getxattr: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn fuse_xattr_ext4_empty_listxattr_size_probe_and_zero_length_payload() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_empty_listxattr_size_probe";
        let path = mnt.join("empty_listxattr_probe.txt");
        let original_file = b"ext4 empty listxattr probe coverage\n";
        fs::write(&path, original_file).expect("write ext4 empty listxattr probe file");

        let initial_names = py_listxattr(&path);
        assert!(
            initial_names.is_empty(),
            "fresh ext4 file should expose no visible xattrs: {initial_names:?}"
        );

        let probe_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            probe_report["len"].as_u64(),
            Some(0),
            "empty listxattr size probe should report length 0: {probe_report}"
        );

        let zero_len_payload_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            zero_len_payload_report["len"].as_u64(),
            Some(0),
            "empty listxattr zero-length payload should succeed with length 0: {zero_len_payload_report}"
        );

        let names_after = py_listxattr(&path);
        assert!(
            names_after.is_empty(),
            "empty listxattr probe paths must not create visible xattrs: {names_after:?}"
        );
        assert_eq!(
            fs::read(&path).expect("read ext4 file bytes after empty listxattr probe"),
            original_file,
            "empty listxattr probe paths must not mutate file contents"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("empty_len_zero_and_zero_length_success"),
        );
    });
}

#[test]
fn fuse_xattr_ext4_remove_missing_reports_enodata_without_side_effects() {
    with_rw_mount(|mnt| {
        let scenario_id = "ext4_rw_xattr_remove_missing_reports_enodata";
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_removexattr_report(&path, "user.no_such_attr");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "missing ext4 removexattr should surface ENODATA: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "missing removexattr must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read file bytes after missing removexattr"),
            original_file,
            "missing removexattr must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.no_such_attr"),
            "missing xattr should remain absent after ENODATA removexattr: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should remain listed after ENODATA removexattr: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn fuse_xattr_ext4_create_existing_reports_eexist_without_side_effects() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");

        py_setxattr(&path, "user.locked", b"original");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_setxattr_report(&path, "user.locked", b"replacement", libc::XATTR_CREATE);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EEXIST)),
            "XATTR_CREATE should reject an existing xattr with EEXIST: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.locked").expect("existing xattr should remain readable"),
            b"original",
            "XATTR_CREATE failure must preserve the original xattr value"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "XATTR_CREATE failure must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read file bytes after create failure"),
            original_file,
            "XATTR_CREATE failure must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            names.iter().any(|name| name == "user.locked"),
            "existing xattr should still be listed after XATTR_CREATE failure: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should still be listed after XATTR_CREATE failure: {names:?}"
        );
    });
}

#[test]
fn fuse_xattr_ext4_replace_missing_reports_enodata_without_side_effects() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");

        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_setxattr_report(&path, "user.missing", b"replacement", libc::XATTR_REPLACE);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "XATTR_REPLACE should reject a missing xattr with ENODATA: {report}"
        );
        assert!(
            py_getxattr(&path, "user.missing").is_none(),
            "XATTR_REPLACE failure must not create the missing xattr"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "XATTR_REPLACE failure must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read file bytes after replace failure"),
            original_file,
            "XATTR_REPLACE failure must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.missing"),
            "missing xattr should remain absent after XATTR_REPLACE failure: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should still be listed after XATTR_REPLACE failure: {names:?}"
        );
    });
}

#[test]
fn fuse_xattr_ext4_posix_acl_list_and_get() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let (image, access_acl, default_acl) = create_ext4_posix_acl_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    let file_path = mnt.join("hello.txt");
    let dir_path = mnt.join("testdir");
    let expected_access_hex = hex::encode(&access_acl);
    let expected_default_hex = hex::encode(&default_acl);

    let file_names = py_listxattr(&file_path);
    assert!(
        file_names
            .iter()
            .any(|name| name == "system.posix_acl_access"),
        "listxattr on hello.txt should expose system.posix_acl_access, got: {file_names:?}"
    );
    let access_report = py_getxattr_report(&file_path, "system.posix_acl_access");
    assert!(
        access_report["errno"].is_null(),
        "mounted-path getxattr for system.posix_acl_access should succeed: {access_report}"
    );
    assert_eq!(
        access_report["value_hex"].as_str(),
        Some(expected_access_hex.as_str()),
        "mounted-path access ACL bytes should remain stable: {access_report}"
    );

    let dir_names = py_listxattr(&dir_path);
    assert!(
        dir_names
            .iter()
            .any(|name| name == "system.posix_acl_default"),
        "listxattr on testdir should expose system.posix_acl_default, got: {dir_names:?}"
    );
    let default_report = py_getxattr_report(&dir_path, "system.posix_acl_default");
    assert!(
        default_report["errno"].is_null(),
        "mounted-path getxattr for system.posix_acl_default should succeed: {default_report}"
    );
    assert_eq!(
        default_report["value_hex"].as_str(),
        Some(expected_default_hex.as_str()),
        "mounted-path default ACL bytes should remain stable: {default_report}"
    );
}

#[test]
fn fuse_xattr_ext4_posix_acl_default_missing_on_regular_file_reports_enodata() {
    if !fuse_available() {
        eprintln!("FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let (image, _access_acl, _default_acl) = create_ext4_posix_acl_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_ffs(&image, &mnt) else {
        return;
    };

    let file_path = mnt.join("hello.txt");
    let names = py_listxattr(&file_path);
    assert!(
        !names.iter().any(|name| name == "system.posix_acl_default"),
        "regular file should not list a default ACL xattr, got: {names:?}"
    );

    let report = py_getxattr_report(&file_path, "system.posix_acl_default");
    assert_eq!(
        report["errno"].as_i64(),
        Some(i64::from(libc::ENODATA)),
        "missing default ACL on a regular file should surface ENODATA: {report}"
    );
}

#[test]
fn fuse_xattr_ext4_name_too_long_reports_enametoolong() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");

        // ext4 xattr name suffix is limited to 255 bytes (u8::MAX)
        // The full name includes the "user." prefix (5 bytes), so a suffix of 256 bytes exceeds.
        let long_suffix = "a".repeat(256);
        let long_name = format!("user.{long_suffix}");

        let report = py_setxattr_report(&path, &long_name, b"value", 0);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENAMETOOLONG)),
            "xattr name > 255-byte suffix should return ENAMETOOLONG: {report}"
        );

        // Verify no side effects
        assert_eq!(
            fs::read(&path).expect("read file bytes after name-too-long rejection"),
            original_file,
            "name-too-long rejection must not mutate file contents"
        );
    });
}

#[test]
fn fuse_xattr_ext4_value_too_large_reports_einval() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        let original_file = fs::read(&path).expect("read original file bytes");

        // ext4 xattr value limit is 64KB (65536 bytes)
        let oversized_value = vec![0x42_u8; 65537];

        let report = py_setxattr_report(&path, "user.toobig", &oversized_value, 0);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "xattr value > 64KB should return EINVAL: {report}"
        );

        // Verify the xattr was not created
        assert!(
            py_getxattr(&path, "user.toobig").is_none(),
            "oversized xattr value should not be stored"
        );

        // Verify no side effects
        assert_eq!(
            fs::read(&path).expect("read file bytes after value-too-large rejection"),
            original_file,
            "value-too-large rejection must not mutate file contents"
        );
    });
}

#[test]
fn fuse_xattr_ext4_boundary_name_length_accepted() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // The maximum suffix length is 255 bytes (u8::MAX)
        let max_suffix = "z".repeat(255);
        let max_name = format!("user.{max_suffix}");

        py_setxattr(&path, &max_name, b"boundary");
        let readback = py_getxattr(&path, &max_name).expect("255-byte suffix xattr should exist");
        assert_eq!(readback, b"boundary", "boundary-length xattr should round-trip");
    });
}

#[test]
fn fuse_xattr_ext4_boundary_value_size_accepted() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // The maximum value size is 64KB (65536 bytes)
        let max_value = vec![0xAB_u8; 65536];

        py_setxattr(&path, "user.maxval", &max_value);
        let readback = py_getxattr(&path, "user.maxval").expect("64KB xattr value should exist");
        assert_eq!(readback, max_value, "boundary-size xattr value should round-trip");
    });
}

// ── btrfs FUSE E2E tests ────────────────────────────────────────────────────

/// Check if btrfs FUSE prerequisites are met.
fn btrfs_fuse_available() -> bool {
    Path::new("/dev/fuse").exists() && command_available("mkfs.btrfs")
}

/// Create a small btrfs image and populate it with test files.
fn create_btrfs_test_image(dir: &Path) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");
    let seed_root = dir.join("seed_root");
    let seed_workspace = seed_root.join(BTRFS_TEST_WORKSPACE);

    // Create a 128 MiB sparse image (btrfs minimum is ~109 MiB).
    let f = fs::File::create(&image).expect("create btrfs image");
    f.set_len(128 * 1024 * 1024).expect("set btrfs image size");
    drop(f);

    // Seed a writable workspace so unprivileged `default_permissions` mounts
    // can exercise the btrfs write path without weakening mount semantics.
    fs::create_dir_all(&seed_workspace).expect("create btrfs seed workspace");
    fs::set_permissions(&seed_root, fs::Permissions::from_mode(0o777))
        .expect("chmod btrfs seed root");
    fs::set_permissions(&seed_workspace, fs::Permissions::from_mode(0o777))
        .expect("chmod btrfs seed workspace");

    // mkfs.btrfs
    let out = Command::new("mkfs.btrfs")
        .args([
            "-f",
            "-L",
            "ffs-btrfs-e2e",
            "--rootdir",
            seed_root.to_str().unwrap(),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.btrfs");
    assert!(
        out.status.success(),
        "mkfs.btrfs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

/// Try to mount a btrfs image via FrankenFS FUSE (read-write) with explicit
/// mount options.
fn try_mount_btrfs_rw_with_options(
    image: &Path,
    mountpoint: &Path,
    mount_opts: &MountOptions,
) -> Option<fuser::BackgroundSession> {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let mut fs = OpenFs::open_with_options(&cx, image, &opts).expect("open btrfs image");
    if let Err(e) = fs.enable_writes(&cx) {
        eprintln!("btrfs enable_writes failed (skipping test): {e}");
        return None;
    }
    match mount_background(Box::new(fs), mountpoint, mount_opts) {
        Ok(session) => {
            thread::sleep(Duration::from_millis(300));
            Some(session)
        }
        Err(e) => {
            eprintln!("btrfs FUSE mount failed (skipping test): {e}");
            None
        }
    }
}

/// Try to mount a btrfs image via FrankenFS FUSE (read-write).
fn try_mount_btrfs_rw(image: &Path, mountpoint: &Path) -> Option<fuser::BackgroundSession> {
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ..MountOptions::default()
    };
    try_mount_btrfs_rw_with_options(image, mountpoint, &mount_opts)
}

/// Create a btrfs image with one deterministic seeded file for read-only
/// mounted-path setattr coverage.
fn create_btrfs_test_image_with_seeded_file(
    dir: &Path,
    file_name: &str,
    contents: &[u8],
) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");
    let seed_root = dir.join("seed_root");
    let seed_workspace = seed_root.join(BTRFS_TEST_WORKSPACE);

    let f = fs::File::create(&image).expect("create seeded btrfs image");
    f.set_len(128 * 1024 * 1024)
        .expect("set seeded btrfs image size");
    drop(f);

    fs::create_dir_all(&seed_workspace).expect("create seeded btrfs workspace");
    fs::set_permissions(&seed_root, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs root");
    fs::set_permissions(&seed_workspace, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs workspace");
    fs::write(seed_workspace.join(file_name), contents).expect("write seeded btrfs file");

    let out = Command::new("mkfs.btrfs")
        .args([
            "-f",
            "-L",
            "ffs-btrfs-e2e",
            "--rootdir",
            seed_root.to_str().unwrap(),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.btrfs seeded image");
    assert!(
        out.status.success(),
        "mkfs.btrfs seeded image failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

fn create_btrfs_test_image_with_seeded_sync_fixture(dir: &Path) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");
    let seed_root = dir.join("seed_root");
    let seed_workspace = seed_root.join(BTRFS_TEST_WORKSPACE);
    let seed_dir = seed_workspace.join("readonly_sync_dir");

    let f = fs::File::create(&image).expect("create seeded btrfs sync image");
    f.set_len(128 * 1024 * 1024)
        .expect("set seeded btrfs sync image size");
    drop(f);

    fs::create_dir_all(&seed_dir).expect("create seeded btrfs sync dir");
    fs::set_permissions(&seed_root, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs sync root");
    fs::set_permissions(&seed_workspace, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs sync workspace");
    fs::set_permissions(&seed_dir, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs sync dir");
    fs::write(
        seed_workspace.join("readonly_sync_seed.txt"),
        b"readonly btrfs sync seed content\n",
    )
    .expect("write seeded btrfs sync file");
    fs::write(seed_dir.join("child.txt"), b"readonly btrfs sync child\n")
        .expect("write seeded btrfs sync child");

    let out = Command::new("mkfs.btrfs")
        .args([
            "-f",
            "-L",
            "ffs-btrfs-e2e",
            "--rootdir",
            seed_root.to_str().unwrap(),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.btrfs seeded sync image");
    assert!(
        out.status.success(),
        "mkfs.btrfs seeded sync image failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

fn create_btrfs_test_image_with_seeded_namespace_removal_fixture(dir: &Path) -> std::path::PathBuf {
    let image = dir.join("test.btrfs");
    let seed_root = dir.join("seed_root");
    let seed_workspace = seed_root.join(BTRFS_TEST_WORKSPACE);
    let empty_dir = seed_workspace.join("readonly_empty_dir");

    let f = fs::File::create(&image).expect("create seeded btrfs namespace removal image");
    f.set_len(128 * 1024 * 1024)
        .expect("set seeded btrfs namespace removal image size");
    drop(f);

    fs::create_dir_all(&empty_dir).expect("create seeded btrfs namespace removal dir");
    fs::set_permissions(&seed_root, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs namespace removal root");
    fs::set_permissions(&seed_workspace, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs namespace removal workspace");
    fs::set_permissions(&empty_dir, fs::Permissions::from_mode(0o777))
        .expect("chmod seeded btrfs namespace removal dir");
    fs::write(
        seed_workspace.join("readonly_unlink_seed.txt"),
        b"readonly btrfs unlink seed\n",
    )
    .expect("write seeded btrfs unlink file");
    fs::write(
        seed_workspace.join("readonly_rename_source.txt"),
        b"readonly btrfs rename source\n",
    )
    .expect("write seeded btrfs rename source file");

    let out = Command::new("mkfs.btrfs")
        .args([
            "-f",
            "-L",
            "ffs-btrfs-e2e",
            "--rootdir",
            seed_root.to_str().unwrap(),
            image.to_str().unwrap(),
        ])
        .output()
        .expect("mkfs.btrfs seeded namespace removal image");
    assert!(
        out.status.success(),
        "mkfs.btrfs seeded namespace removal image failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    image
}

fn try_mount_btrfs_ro(image: &Path, mountpoint: &Path) -> Option<fuser::BackgroundSession> {
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        skip_validation: false,
        ext4_journal_replay_mode: Ext4JournalReplayMode::SimulateOverlay,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, image, &opts).expect("open btrfs image");
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };
    match mount_background(Box::new(fs), mountpoint, &mount_opts) {
        Ok(session) => {
            thread::sleep(Duration::from_millis(300));
            Some(session)
        }
        Err(e) => {
            eprintln!("btrfs read-only FUSE mount failed (skipping test): {e}");
            None
        }
    }
}

/// Try to mount a btrfs image with explicit OpenOptions (for BtrfsMountSelection tests).
fn try_mount_btrfs_with_open_options(
    image: &Path,
    mountpoint: &Path,
    open_opts: &OpenOptions,
    mount_opts: &MountOptions,
) -> Option<fuser::BackgroundSession> {
    let cx = Cx::for_testing();
    let fs = match OpenFs::open_with_options(&cx, image, open_opts) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("btrfs open with options failed (may be expected): {e}");
            return None;
        }
    };
    match mount_background(Box::new(fs), mountpoint, mount_opts) {
        Ok(session) => {
            thread::sleep(Duration::from_millis(300));
            Some(session)
        }
        Err(e) => {
            eprintln!("btrfs FUSE mount failed: {e}");
            None
        }
    }
}

/// Check if we can run sudo commands (for tests that create btrfs subvolumes).
fn can_run_sudo() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Create a btrfs image with subvolumes and snapshots using kernel btrfs tools.
/// Requires sudo access. Returns (image_path, subvol_names, snapshot_names).
fn create_btrfs_image_with_subvolumes(
    dir: &Path,
) -> Option<(PathBuf, Vec<String>, Vec<String>)> {
    if !can_run_sudo() {
        eprintln!("sudo not available, skipping subvolume test");
        return None;
    }
    if !command_available("btrfs") {
        eprintln!("btrfs command not available, skipping subvolume test");
        return None;
    }

    let image = dir.join("subvol_test.btrfs");
    let kernel_mnt = dir.join("kernel_mnt");

    // Create 256MiB image
    let f = fs::File::create(&image).expect("create btrfs image");
    f.set_len(256 * 1024 * 1024).expect("set image size");
    drop(f);

    // mkfs.btrfs
    let out = Command::new("mkfs.btrfs")
        .args(["-f", "-L", "ffs-subvol-e2e", image.to_str().unwrap()])
        .output()
        .expect("mkfs.btrfs");
    if !out.status.success() {
        eprintln!("mkfs.btrfs failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }

    // Mount with kernel driver to create subvolumes
    fs::create_dir_all(&kernel_mnt).expect("create kernel mount dir");
    let out = Command::new("sudo")
        .args(["mount", "-t", "btrfs", image.to_str().unwrap(), kernel_mnt.to_str().unwrap()])
        .output()
        .expect("sudo mount");
    if !out.status.success() {
        eprintln!("sudo mount failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }

    // Create subvolume "data"
    let subvol_path = kernel_mnt.join("data");
    let out = Command::new("sudo")
        .args(["btrfs", "subvolume", "create", subvol_path.to_str().unwrap()])
        .output()
        .expect("btrfs subvolume create");
    if !out.status.success() {
        let _ = Command::new("sudo").args(["umount", kernel_mnt.to_str().unwrap()]).output();
        eprintln!("btrfs subvolume create failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }

    // Write a marker file in the subvolume
    let marker = subvol_path.join("subvol_marker.txt");
    let out = Command::new("sudo")
        .args(["sh", "-c", &format!("echo 'in-data-subvol' > '{}'", marker.display())])
        .output()
        .expect("write marker");
    if !out.status.success() {
        eprintln!("write marker failed");
    }

    // Write a marker file in the root (not visible when mounting subvolume)
    let root_marker = kernel_mnt.join("root_marker.txt");
    let out = Command::new("sudo")
        .args(["sh", "-c", &format!("echo 'in-root' > '{}'", root_marker.display())])
        .output()
        .expect("write root marker");
    if !out.status.success() {
        eprintln!("write root marker failed");
    }

    // Create snapshot "snap-data" of "data"
    let snap_path = kernel_mnt.join("snap-data");
    let out = Command::new("sudo")
        .args(["btrfs", "subvolume", "snapshot", subvol_path.to_str().unwrap(), snap_path.to_str().unwrap()])
        .output()
        .expect("btrfs snapshot");
    let has_snapshot = out.status.success();
    if has_snapshot {
        // Write different content in snapshot
        let snap_marker = snap_path.join("snapshot_marker.txt");
        let _ = Command::new("sudo")
            .args(["sh", "-c", &format!("echo 'in-snapshot' > '{}'", snap_marker.display())])
            .output();
    }

    // Unmount
    let out = Command::new("sudo")
        .args(["umount", kernel_mnt.to_str().unwrap()])
        .output()
        .expect("sudo umount");
    if !out.status.success() {
        eprintln!("sudo umount failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    let subvols = vec!["data".to_string()];
    let snaps = if has_snapshot { vec!["snap-data".to_string()] } else { vec![] };
    Some((image, subvols, snaps))
}

/// Helper: create btrfs image, mount rw, run a closure against the mount root.
fn with_btrfs_rw_root_mount(f: impl FnOnce(&Path)) {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_rw(&image, &mnt) else {
        return;
    };
    f(&mnt);
}

/// Helper: create btrfs image, mount rw, run a closure in the seeded workspace.
fn with_btrfs_rw_mount(f: impl FnOnce(&Path)) {
    with_btrfs_rw_root_mount(|mnt| {
        let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
        assert!(
            workspace.is_dir(),
            "seeded btrfs workspace missing at {}",
            workspace.display()
        );
        f(&workspace);
    });
}

fn with_btrfs_ro_sync_fixture(f: impl FnOnce(&Path, &Path, &Path)) {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_sync_fixture(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    f(
        &workspace.join("readonly_sync_seed.txt"),
        &workspace.join("readonly_sync_dir"),
        &workspace.join("readonly_sync_dir").join("child.txt"),
    );
}

#[test]
fn btrfs_fuse_readdir_root() {
    with_btrfs_rw_root_mount(|mnt| {
        let entries: Vec<String> = fs::read_dir(mnt)
            .expect("readdir btrfs root via FUSE")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.iter().any(|entry| entry == BTRFS_TEST_WORKSPACE),
            "seeded btrfs workspace should appear at root, got: {entries:?}"
        );
    });
}

#[test]
fn btrfs_fuse_create_and_read_file() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");
        fs::write(&path, b"Hello from btrfs FUSE!\n").expect("write file on btrfs");

        let content = fs::read_to_string(&path).expect("read file on btrfs");
        assert_eq!(content, "Hello from btrfs FUSE!\n");
    });
}

#[test]
fn btrfs_fuse_write_to_directory_reports_eisdir() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_write_to_directory_errno_eisdir";
        let dir = mnt.join("btrfs_write_dir");
        fs::create_dir(&dir).expect("mkdir btrfs write directory target");
        let child = dir.join("child.txt");
        fs::write(&child, b"directory child stays intact\n")
            .expect("seed btrfs write directory child");

        let entries_before = snapshot_directory_entries(&dir);
        let child_before = snapshot_file_state(&child);

        let err = fs::OpenOptions::new()
            .write(true)
            .open(&dir)
            .expect_err("opening a directory for write should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EISDIR),
            "opening a directory for write should surface exact EISDIR: {err}"
        );
        assert!(
            dir.is_dir(),
            "directory-write rejection must leave the directory in place"
        );
        assert_eq!(
            snapshot_directory_entries(&dir),
            entries_before,
            "directory-write rejection must not change directory entries"
        );
        assert_file_state_unchanged(&child, &child_before, "directory write rejection");
        emit_scenario_result(scenario_id, "PASS", Some("open=EISDIR_no_drift"));
    });
}

#[test]
fn btrfs_fuse_mkdir_and_nested_file() {
    with_btrfs_rw_mount(|mnt| {
        let dir = mnt.join("subdir");
        fs::create_dir(&dir).expect("mkdir on btrfs");

        let nested = dir.join("nested.txt");
        fs::write(&nested, b"nested btrfs content\n").expect("write nested on btrfs");

        let content = fs::read_to_string(&nested).expect("read nested on btrfs");
        assert_eq!(content, "nested btrfs content\n");
    });
}

#[test]
fn btrfs_fuse_create_and_mkdir_under_non_directory_parent_report_enotdir() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_create_and_mkdir_under_non_directory_parent";
        let regular_parent = mnt.join("nondir_parent.txt");
        fs::write(&regular_parent, b"not a directory\n").expect("write btrfs non-directory parent");

        let root_entries_before = snapshot_directory_entries(mnt);
        let parent_before = snapshot_file_state(&regular_parent);

        let create_target = regular_parent.join("child.txt");
        let create_err = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&create_target)
            .expect_err("create beneath regular-file parent should fail");
        assert_eq!(
            create_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "create beneath a regular-file parent should surface exact ENOTDIR: {create_err}"
        );
        assert!(
            fs::symlink_metadata(&create_target).is_err(),
            "rejected create must not leave a nested child entry behind"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected create must not change visible root entries"
        );
        assert_file_state_unchanged(
            &regular_parent,
            &parent_before,
            "btrfs non-directory parent after rejected create",
        );

        let mkdir_target = regular_parent.join("child_dir");
        let mkdir_err = fs::create_dir(&mkdir_target)
            .expect_err("mkdir beneath regular-file parent should fail");
        assert_eq!(
            mkdir_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "mkdir beneath a regular-file parent should surface exact ENOTDIR: {mkdir_err}"
        );
        assert!(
            fs::symlink_metadata(&mkdir_target).is_err(),
            "rejected mkdir must not leave a nested directory entry behind"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "rejected mkdir must not change visible root entries"
        );
        assert_file_state_unchanged(
            &regular_parent,
            &parent_before,
            "btrfs non-directory parent after rejected mkdir",
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("create=ENOTDIR_mkdir=ENOTDIR_no_drift"),
        );
    });
}

#[test]
fn btrfs_fuse_unlink_and_rmdir() {
    with_btrfs_rw_mount(|mnt| {
        // Create and remove a file.
        let path = mnt.join("temp.txt");
        fs::write(&path, b"temporary").expect("write temp");
        assert!(path.exists());
        fs::remove_file(&path).expect("unlink on btrfs");
        assert!(!path.exists());

        // Create and remove a directory.
        let dir = mnt.join("tempdir");
        fs::create_dir(&dir).expect("mkdir tempdir");
        assert!(dir.exists());
        fs::remove_dir(&dir).expect("rmdir on btrfs");
        assert!(!dir.exists());
    });
}

#[test]
fn btrfs_fuse_rmdir_on_file_reports_enotdir() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_rmdir_on_file_reports_enotdir";
        let path = mnt.join("rmdir-on-file.txt");
        fs::write(&path, b"btrfs rmdir-on-file witness\n").expect("write rmdir-on-file witness");
        let original_bytes = fs::read(&path).expect("read witness before rmdir-on-file");

        let err = fs::remove_dir(&path).expect_err("rmdir on regular file should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOTDIR),
            "rmdir on a regular file should surface exact ENOTDIR: {err}"
        );
        assert!(
            path.is_file(),
            "failed rmdir on regular file must leave the file in place"
        );
        assert_eq!(
            fs::read(&path).expect("read witness after failed rmdir-on-file"),
            original_bytes,
            "failed rmdir on regular file must not mutate file contents"
        );

        emit_scenario_result(scenario_id, "PASS", Some("errno=ENOTDIR_no_drift"));
    });
}

#[test]
fn btrfs_fuse_unlink_directory_reports_eisdir() {
    with_btrfs_rw_mount(|mnt| {
        assert_unlink_directory_via_remove_file_reports_eisdir(
            mnt,
            "btrfs_rw_unlink_directory_reports_eisdir",
        );
    });
}

#[test]
fn btrfs_fuse_unlink_missing_reports_enoent() {
    with_btrfs_rw_mount(|mnt| {
        assert_unlink_missing_reports_enoent(mnt, "btrfs_rw_unlink_missing_reports_enoent");
    });
}

#[test]
fn btrfs_fuse_rename() {
    with_btrfs_rw_mount(|mnt| {
        let old = mnt.join("original.txt");
        let new = mnt.join("renamed.txt");
        fs::write(&old, b"rename test").expect("write for rename");
        assert!(old.exists());

        fs::rename(&old, &new).expect("rename on btrfs");
        assert!(!old.exists());
        assert!(new.exists());
        assert_eq!(
            fs::read_to_string(&new).expect("read renamed"),
            "rename test"
        );
    });
}

#[test]
fn btrfs_fuse_rename_same_name_is_noop() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_rename_same_name_noop";
        let path = mnt.join("same-name.txt");
        fs::write(&path, b"same name rename\n").expect("write rename same-name seed");

        let entries_before = snapshot_directory_entries(mnt);
        let before = snapshot_file_state(&path);
        let ino_before = fs::metadata(&path)
            .expect("stat before same-name rename")
            .ino();

        fs::rename(&path, &path).expect("rename same name should succeed");

        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "same-name rename should not change directory entries"
        );
        assert_file_state_unchanged(&path, &before, "same-name rename");

        let ino_after = fs::metadata(&path)
            .expect("stat after same-name rename")
            .ino();
        assert_eq!(
            ino_after, ino_before,
            "same-name rename should preserve the inode binding"
        );

        emit_scenario_result(scenario_id, "PASS", Some("visible_noop"));
    });
}

#[test]
fn btrfs_fuse_hard_link() {
    with_btrfs_rw_mount(|mnt| {
        let original = mnt.join("linkme.txt");
        fs::write(&original, b"hard link content\n").expect("write original for hard link");

        let link = mnt.join("linkme_link.txt");
        fs::hard_link(&original, &link).expect("hard link on btrfs");

        let content = fs::read_to_string(&link).expect("read through hard link");
        assert_eq!(content, "hard link content\n");

        // Both should share the same inode.
        let orig_ino = fs::metadata(&original).expect("stat original").ino();
        let link_ino = fs::metadata(&link).expect("stat link").ino();
        assert_eq!(orig_ino, link_ino, "hard link should share inode");

        let orig_nlink = fs::metadata(&original).expect("stat original").nlink();
        let link_nlink = fs::metadata(&link).expect("stat link").nlink();
        assert_eq!(orig_nlink, 2, "original should report two hard links");
        assert_eq!(link_nlink, 2, "link should report two hard links");
    });
}

fn assert_btrfs_hard_link_directory_source_refusal(mnt: &Path) {
    let dir_source = mnt.join("dir_source");
    fs::create_dir(&dir_source).expect("create directory hard-link source");
    let root_entries_before = snapshot_directory_entries(mnt);

    let dir_err = fs::hard_link(&dir_source, mnt.join("dir_hardlink"))
        .expect_err("hard-linking a directory should fail");
    assert_eq!(
        dir_err.raw_os_error(),
        Some(libc::EPERM),
        "hard-linking a directory should surface exact EPERM: {dir_err}"
    );
    assert!(
        fs::symlink_metadata(mnt.join("dir_hardlink")).is_err(),
        "directory-source refusal must not leave a new entry behind"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "directory-source refusal must not change visible root entries"
    );
}

fn assert_btrfs_hard_link_non_directory_parent_refusal(mnt: &Path) {
    let source = mnt.join("link_src.txt");
    let non_directory_parent = mnt.join("not_a_dir.txt");
    fs::write(&source, b"link source payload\n").expect("write hard-link source");
    fs::write(&non_directory_parent, b"not a directory\n").expect("write non-directory parent");
    let root_entries_before = snapshot_directory_entries(mnt);
    let source_before = snapshot_file_state(&source);
    let parent_before = snapshot_file_state(&non_directory_parent);
    let source_nlink_before = fs::metadata(&source).expect("stat source before").nlink();
    let nested_target = non_directory_parent.join("child.txt");

    let parent_err = fs::hard_link(&source, &nested_target)
        .expect_err("hard link into non-directory parent should fail");
    assert_eq!(
        parent_err.raw_os_error(),
        Some(libc::ENOTDIR),
        "hard link into non-directory parent should surface exact ENOTDIR: {parent_err}"
    );
    assert!(
        fs::symlink_metadata(&nested_target).is_err(),
        "non-directory-parent refusal must not create the nested destination"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "non-directory-parent refusal must not change visible root entries"
    );
    assert_file_state_unchanged(&source, &source_before, "rejected hard-link source");
    assert_file_state_unchanged(
        &non_directory_parent,
        &parent_before,
        "rejected hard-link non-directory parent",
    );
    assert_eq!(
        fs::metadata(&source).expect("stat source after").nlink(),
        source_nlink_before,
        "non-directory-parent refusal must not change source link count"
    );
}

fn assert_btrfs_hard_link_occupied_destination_refusal(mnt: &Path) {
    let occupied_target = mnt.join("occupied_target.txt");
    let occupied_destination = mnt.join("occupied_destination.txt");
    fs::write(&occupied_target, b"occupied target payload\n").expect("write occupied target");
    fs::write(&occupied_destination, b"occupied destination payload\n")
        .expect("write occupied destination");
    let root_entries_before = snapshot_directory_entries(mnt);
    let target_before = snapshot_file_state(&occupied_target);
    let destination_before = snapshot_file_state(&occupied_destination);
    let target_nlink_before = fs::metadata(&occupied_target)
        .expect("stat occupied target before")
        .nlink();

    let exists_err = fs::hard_link(&occupied_target, &occupied_destination)
        .expect_err("hard link onto existing destination should fail");
    assert_eq!(
        exists_err.raw_os_error(),
        Some(libc::EEXIST),
        "hard link onto existing destination should surface exact EEXIST: {exists_err}"
    );
    assert_eq!(
        snapshot_directory_entries(mnt),
        root_entries_before,
        "occupied-destination refusal must not change visible root entries"
    );
    assert_file_state_unchanged(
        &occupied_target,
        &target_before,
        "rejected occupied-destination source",
    );
    assert_file_state_unchanged(
        &occupied_destination,
        &destination_before,
        "rejected occupied destination",
    );
    assert_eq!(
        fs::metadata(&occupied_target)
            .expect("stat occupied target after")
            .nlink(),
        target_nlink_before,
        "occupied-destination refusal must not change source link count"
    );
}

#[test]
fn btrfs_fuse_hard_link_refusal_contracts() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_hard_link_refusal_contracts";
        assert_btrfs_hard_link_directory_source_refusal(mnt);
        assert_btrfs_hard_link_non_directory_parent_refusal(mnt);
        assert_btrfs_hard_link_occupied_destination_refusal(mnt);

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("dir=EPERM_parent=ENOTDIR_exists=EEXIST_no_drift"),
        );
    });
}

#[test]
fn btrfs_fuse_symlink_create_and_follow() {
    with_btrfs_rw_mount(|mnt| {
        let target = mnt.join("sym_target.txt");
        fs::write(&target, b"symlink target content\n").expect("write symlink target");

        let link = mnt.join("sym.txt");
        std::os::unix::fs::symlink("sym_target.txt", &link).expect("symlink on btrfs");

        // Verify readlink returns the target.
        let read_target = fs::read_link(&link).expect("readlink on btrfs");
        assert_eq!(read_target.to_str().unwrap(), "sym_target.txt");

        // Following the symlink should work.
        let content = fs::read_to_string(&link).expect("read through symlink on btrfs");
        assert_eq!(content, "symlink target content\n");

        // Symlink metadata should differ from target.
        let link_meta = fs::symlink_metadata(&link).expect("lstat symlink on btrfs");
        assert!(link_meta.file_type().is_symlink());
    });
}

#[test]
fn btrfs_fuse_symlink_refusal_contracts() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_symlink_refusal_contracts";
        let target = mnt.join("sym_target.txt");
        fs::write(&target, b"symlink target content\n").expect("write btrfs symlink target");

        let occupied_destination = mnt.join("occupied_symlink_destination.txt");
        fs::write(&occupied_destination, b"occupied destination payload\n")
            .expect("write occupied btrfs symlink destination");
        let root_entries_before = snapshot_directory_entries(mnt);
        let occupied_before = snapshot_file_state(&occupied_destination);

        let exists_err = std::os::unix::fs::symlink("sym_target.txt", &occupied_destination)
            .expect_err("symlink onto existing destination should fail");
        assert_eq!(
            exists_err.raw_os_error(),
            Some(libc::EEXIST),
            "symlink onto existing destination should surface exact EEXIST: {exists_err}"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "occupied-destination symlink refusal must not change visible root entries"
        );
        assert_file_state_unchanged(
            &occupied_destination,
            &occupied_before,
            "rejected occupied btrfs symlink destination",
        );

        let non_directory_parent = mnt.join("symlink_parent_file.txt");
        fs::write(&non_directory_parent, b"not a directory\n")
            .expect("write btrfs symlink non-directory parent");
        let root_entries_before = snapshot_directory_entries(mnt);
        let parent_before = snapshot_file_state(&non_directory_parent);
        let nested_target = non_directory_parent.join("child_link.txt");

        let parent_err = std::os::unix::fs::symlink("sym_target.txt", &nested_target)
            .expect_err("symlink into non-directory parent should fail");
        assert_eq!(
            parent_err.raw_os_error(),
            Some(libc::ENOTDIR),
            "symlink into non-directory parent should surface exact ENOTDIR: {parent_err}"
        );
        assert!(
            fs::symlink_metadata(&nested_target).is_err(),
            "non-directory-parent symlink refusal must not create the nested destination"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            root_entries_before,
            "non-directory-parent symlink refusal must not change visible root entries"
        );
        assert_file_state_unchanged(
            &non_directory_parent,
            &parent_before,
            "rejected btrfs symlink non-directory parent",
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("exists=EEXIST_parent=ENOTDIR_no_drift"),
        );
    });
}

#[test]
fn btrfs_fuse_setattr_truncate() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("trunc.txt");
        fs::write(&path, b"Hello from btrfs truncate test!\n").expect("write for truncate");

        let original_len = fs::metadata(&path).expect("stat").len();
        assert!(original_len > 0);

        // Truncate to 5 bytes.
        let f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate");
        f.set_len(5).expect("truncate on btrfs");
        drop(f);

        let new_len = fs::metadata(&path).expect("stat after truncate").len();
        assert_eq!(new_len, 5, "file should be truncated to 5 bytes");

        let content = fs::read_to_string(&path).expect("read truncated file on btrfs");
        assert_eq!(content, "Hello");
    });
}

#[test]
fn btrfs_fuse_setattr_chmod() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("chmod_test.txt");
        fs::write(&path, b"chmod test content\n").expect("write for chmod");

        // Change to 0o755.
        let new_perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&path, new_perms).expect("chmod 755 on btrfs");

        let meta = fs::metadata(&path).expect("stat after chmod");
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o755,
            "permissions should be 0o755 after chmod on btrfs"
        );

        // Change to 0o600.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod 600 on btrfs");

        let meta = fs::metadata(&path).expect("stat after second chmod");
        assert_eq!(
            meta.permissions().mode() & 0o7777,
            0o600,
            "permissions should be 0o600 after second chmod on btrfs"
        );

        // File should still be readable/writable by us since we own it.
        let content = fs::read_to_string(&path).expect("read after chmod on btrfs");
        assert_eq!(content, "chmod test content\n");
    });
}

#[test]
fn btrfs_fuse_setattr_utimes() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("utimes_test.txt");
        fs::write(&path, b"utimes test content\n").expect("write for utimes");

        // Use Python os.utime to set atime and mtime to a known epoch.
        let script = format!(
            "import os; os.utime({path:?}, (1_700_000_000, 1_700_000_000))",
            path = path.to_str().unwrap(),
        );
        let out = Command::new("python3")
            .args(["-c", &script])
            .output()
            .expect("python3 utime");
        assert!(
            out.status.success(),
            "os.utime on btrfs failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after utime on btrfs");
        assert_eq!(
            meta.atime(),
            1_700_000_000,
            "atime should be 1700000000 after os.utime on btrfs"
        );
        assert_eq!(
            meta.mtime(),
            1_700_000_000,
            "mtime should be 1700000000 after os.utime on btrfs"
        );
    });
}

#[test]
fn btrfs_fuse_setattr_read_only_rejects_chmod_truncate_and_utimes_with_erofs() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_file(
        tmp.path(),
        "readonly_seed.txt",
        b"readonly btrfs seed content\n",
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    assert_read_only_setattr_contract(
        &mnt.join(BTRFS_TEST_WORKSPACE).join("readonly_seed.txt"),
        "btrfs_ro_setattr_rejects_erofs_no_drift",
    );
}

#[test]
fn btrfs_fuse_read_only_fallocate_mutation_attempts_report_erofs_without_file_drift() {
    if !btrfs_fuse_available() || !command_available("python3") {
        eprintln!("btrfs FUSE or python3 prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_file(
        tmp.path(),
        "readonly_fallocate_seed.txt",
        b"readonly btrfs fallocate seed\n",
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let scenario_id = "btrfs_ro_fallocate_mutation_attempts_reject_erofs_no_drift";
    let path = mnt
        .join(BTRFS_TEST_WORKSPACE)
        .join("readonly_fallocate_seed.txt");
    let before = snapshot_file_state(&path);

    let preallocate_report = py_fallocate_report(&path, 0, 0, before.len + 4096);
    assert_eq!(
        preallocate_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only btrfs preallocate should surface exact EROFS: {preallocate_report}"
    );
    assert_file_state_unchanged(&path, &before, "rejected read-only btrfs preallocate");

    let punch_hole_report = py_fallocate_report(
        &path,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
        0,
        before.len.min(8),
    );
    assert_eq!(
        punch_hole_report["errno"].as_i64(),
        Some(i64::from(libc::EROFS)),
        "read-only btrfs punch-hole should surface exact EROFS: {punch_hole_report}"
    );
    assert_file_state_unchanged(&path, &before, "rejected read-only btrfs punch-hole");

    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("preallocate+punch_hole=EROFS_no_file_drift"),
    );
}

#[test]
fn btrfs_fuse_read_only_create_mkdir_link_and_symlink_report_erofs_without_dirent_drift() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_file(
        tmp.path(),
        "readonly_namespace_seed.txt",
        b"readonly btrfs namespace seed\n",
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let seed = workspace.join("readonly_namespace_seed.txt");
    assert_eq!(
        fs::read(&seed).expect("read seeded btrfs namespace file"),
        b"readonly btrfs namespace seed\n",
        "read-only remount must preserve the seeded namespace file bytes"
    );

    assert_read_only_namespace_mutation_contract(
        &workspace,
        &seed,
        "btrfs_ro_create_mkdir_link_symlink_reject_erofs_no_drift",
    );
}

#[test]
fn btrfs_fuse_read_only_regular_writes_report_erofs_without_file_or_dirent_drift() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_file(
        tmp.path(),
        "readonly_write_seed.txt",
        b"readonly btrfs write seed\n",
    );
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let seed = workspace.join("readonly_write_seed.txt");
    assert_eq!(
        fs::read(&seed).expect("read seeded btrfs write file"),
        b"readonly btrfs write seed\n",
        "read-only remount must preserve the seeded write target bytes"
    );

    assert_read_only_regular_write_contract(
        &workspace,
        &seed,
        "btrfs_ro_regular_writes_reject_erofs_no_drift",
    );
}

#[test]
fn btrfs_fuse_read_only_unlink_rmdir_and_rename_report_erofs_without_dirent_drift() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image_with_seeded_namespace_removal_fixture(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let workspace = mnt.join(BTRFS_TEST_WORKSPACE);
    let keep_file = workspace.join("readonly_unlink_seed.txt");
    let empty_dir = workspace.join("readonly_empty_dir");
    let rename_source = workspace.join("readonly_rename_source.txt");
    assert_eq!(
        fs::read(&keep_file).expect("read seeded btrfs unlink file"),
        b"readonly btrfs unlink seed\n",
        "read-only remount must preserve the seeded unlink target bytes"
    );
    assert_eq!(
        fs::read(&rename_source).expect("read seeded btrfs rename source file"),
        b"readonly btrfs rename source\n",
        "read-only remount must preserve the seeded rename source bytes"
    );
    assert!(
        empty_dir.is_dir(),
        "read-only remount must preserve the seeded empty directory"
    );

    assert_read_only_unlink_rmdir_and_rename_contract(
        &workspace,
        &keep_file,
        &empty_dir,
        &rename_source,
        "btrfs_ro_unlink_rmdir_rename_reject_erofs_no_drift",
    );
}

#[test]
fn btrfs_fuse_statfs() {
    with_btrfs_rw_root_mount(|mnt| {
        // Use `stat -f` to exercise the FUSE statfs handler and parse the output.
        let out = Command::new("stat")
            .args(["-f", "-c", "%s %b %f %a %c %d %l", mnt.to_str().unwrap()])
            .output()
            .expect("stat -f on btrfs mountpoint");
        assert!(
            out.status.success(),
            "stat -f on btrfs failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let stdout = String::from_utf8_lossy(&out.stdout);
        let fields: Vec<&str> = stdout.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            7,
            "expected 7 stat -f fields, got: {stdout:?}"
        );

        // Parse statfs fields: block_size blocks blocks_free blocks_avail files files_free namelen
        let block_size: u64 = fields[0].parse().expect("parse block_size");
        let blocks: u64 = fields[1].parse().expect("parse blocks");
        let blocks_free: u64 = fields[2].parse().expect("parse blocks_free");
        let blocks_avail: u64 = fields[3].parse().expect("parse blocks_avail");
        let files: u64 = fields[4].parse().expect("parse files");
        let _files_free: u64 = fields[5].parse().expect("parse files_free");
        let namelen: u64 = fields[6].parse().expect("parse namelen");

        // Validate: block size should be a power of two in [4096, 65536].
        assert!(
            block_size.is_power_of_two() && (4096..=65536).contains(&block_size),
            "btrfs block_size {block_size} should be a power-of-two in [4096, 65536]"
        );

        // Total blocks should be non-zero (we made a 128 MiB image).
        assert!(blocks > 0, "total blocks should be > 0");

        // Free blocks should not exceed total blocks.
        assert!(
            blocks_free <= blocks,
            "free blocks ({blocks_free}) should be <= total ({blocks})"
        );
        assert!(
            blocks_avail <= blocks,
            "available blocks ({blocks_avail}) should be <= total ({blocks})"
        );

        // Total inodes should be non-zero.
        assert!(files > 0, "total inodes should be > 0");

        // Max filename length: btrfs is 255.
        assert_eq!(namelen, 255, "btrfs max filename length should be 255");
    });
}

#[test]
fn btrfs_fuse_seek_data_hole_reports_punched_range_offsets() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_seek_data_hole";
        let path = mnt.join("btrfs_seek_layout.bin");
        assert_seek_data_hole_contract(&path, scenario_id);
    });
}

#[test]
fn btrfs_fuse_seek_hole_reports_virtual_eof_for_fully_allocated_file() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_seek_hole_fully_allocated";
        let path = mnt.join("btrfs_seek_fully_allocated.bin");
        assert_seek_fully_allocated_contract(&path, scenario_id);
    });
}

#[test]
fn btrfs_fuse_seek_data_hole_reports_leading_sparse_hole_offsets() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_seek_leading_hole";
        let path = mnt.join("btrfs_seek_leading_hole.bin");
        assert_seek_leading_hole_contract(&path, scenario_id);
    });
}

#[test]
fn btrfs_fuse_seek_data_hole_reports_all_hole_sparse_file_offsets() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_seek_all_hole";
        let path = mnt.join("btrfs_seek_all_hole.bin");
        assert_seek_all_hole_contract(&path, scenario_id);
    });
}

#[test]
fn btrfs_fuse_xattr_set_get_list_remove() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_set_get_list_remove";
        let path = mnt.join("xattr_test.txt");
        fs::write(&path, b"xattr test content\n").expect("write for xattr");

        // Set a user xattr.
        py_setxattr(&path, "user.test_key", b"test_value_123");

        // Get it back.
        let val = py_getxattr(&path, "user.test_key").expect("xattr should exist after set");
        assert_eq!(val, b"test_value_123");

        // List should include it.
        let names = py_listxattr(&path);
        assert!(
            names.iter().any(|n| n == "user.test_key"),
            "listxattr should contain user.test_key on btrfs, got: {names:?}"
        );

        // Remove it.
        assert!(
            py_removexattr(&path, "user.test_key"),
            "removexattr should succeed on btrfs"
        );

        // Should be gone.
        assert!(
            py_getxattr(&path, "user.test_key").is_none(),
            "xattr should be absent after removexattr on btrfs"
        );
        emit_scenario_result(scenario_id, "PASS", Some("user_namespace_full_cycle"));
    });
}

#[test]
fn btrfs_fuse_xattr_multiple_attributes() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_multiple_attributes";
        let path = mnt.join("multi_xattr.txt");
        fs::write(&path, b"multi xattr content\n").expect("write for multi xattr");

        // Set multiple xattrs.
        py_setxattr(&path, "user.alpha", b"aaa");
        py_setxattr(&path, "user.beta", b"bbb");
        py_setxattr(&path, "user.gamma", b"ccc");

        // Verify each value.
        assert_eq!(py_getxattr(&path, "user.alpha").unwrap(), b"aaa");
        assert_eq!(py_getxattr(&path, "user.beta").unwrap(), b"bbb");
        assert_eq!(py_getxattr(&path, "user.gamma").unwrap(), b"ccc");

        // List should contain all three.
        let names = py_listxattr(&path);
        for expected in ["user.alpha", "user.beta", "user.gamma"] {
            assert!(
                names.iter().any(|n| n == expected),
                "listxattr on btrfs should contain {expected}, got: {names:?}"
            );
        }
        emit_scenario_result(scenario_id, "PASS", Some("three_distinct_user_xattrs"));
    });
}

#[test]
fn btrfs_fuse_xattr_on_directory() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_on_directory";
        let dir = mnt.join("xattr_dir");
        fs::create_dir(&dir).expect("mkdir for xattr");

        // Set xattr on directory.
        py_setxattr(&dir, "user.dir_attr", b"dir_value");

        let val = py_getxattr(&dir, "user.dir_attr").expect("xattr on btrfs dir should exist");
        assert_eq!(val, b"dir_value");

        let names = py_listxattr(&dir);
        assert!(
            names.iter().any(|n| n == "user.dir_attr"),
            "listxattr on btrfs dir should contain user.dir_attr, got: {names:?}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("user_xattr_on_directory_inode"));
    });
}

#[test]
fn btrfs_fuse_xattr_create_existing_reports_eexist_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_create_existing_reports_eexist";
        let path = mnt.join("btrfs_xattr_modes.txt");
        fs::write(&path, b"btrfs xattr mode coverage\n").expect("write btrfs xattr mode file");
        let original_file = fs::read(&path).expect("read original btrfs file bytes");

        py_setxattr(&path, "user.locked", b"original");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_setxattr_report(&path, "user.locked", b"replacement", libc::XATTR_CREATE);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EEXIST)),
            "btrfs XATTR_CREATE should reject an existing xattr with EEXIST: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.locked").expect("existing xattr should remain readable"),
            b"original",
            "btrfs XATTR_CREATE failure must preserve the original xattr value"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "btrfs XATTR_CREATE failure must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after create failure"),
            original_file,
            "btrfs XATTR_CREATE failure must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            names.iter().any(|name| name == "user.locked"),
            "existing xattr should still be listed after btrfs XATTR_CREATE failure: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should still be listed after btrfs XATTR_CREATE failure: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=EEXIST_with_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_xattr_replace_missing_reports_enodata_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_replace_missing_reports_enodata";
        let path = mnt.join("btrfs_xattr_modes.txt");
        fs::write(&path, b"btrfs xattr mode coverage\n").expect("write btrfs xattr mode file");
        let original_file = fs::read(&path).expect("read original btrfs file bytes");

        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_setxattr_report(&path, "user.missing", b"replacement", libc::XATTR_REPLACE);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "btrfs XATTR_REPLACE should reject a missing xattr with ENODATA on Linux FUSE: {report}"
        );
        assert!(
            py_getxattr(&path, "user.missing").is_none(),
            "btrfs XATTR_REPLACE failure must not create the missing xattr"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "btrfs XATTR_REPLACE failure must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after replace failure"),
            original_file,
            "btrfs XATTR_REPLACE failure must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.missing"),
            "missing xattr should remain absent after btrfs XATTR_REPLACE failure: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should still be listed after btrfs XATTR_REPLACE failure: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_xattr_read_only_set_and_remove_report_erofs_without_side_effects() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_btrfs_test_image(tmp.path());
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let setup_mount_opts = MountOptions {
        read_only: false,
        auto_unmount: true,
        ..MountOptions::default()
    };

    {
        let Some(setup_session) = try_mount_btrfs_rw_with_options(&image, &mnt, &setup_mount_opts)
        else {
            return;
        };

        let path = mnt
            .join(BTRFS_TEST_WORKSPACE)
            .join("readonly_xattr_seed.txt");
        fs::write(&path, b"readonly btrfs xattr seed\n").expect("write ro btrfs xattr seed file");
        py_setxattr(&path, "user.locked", b"original");
        py_setxattr(&path, "user.keep", b"preserve");
        drop(setup_session);
    }

    thread::sleep(Duration::from_millis(500));

    let Some(_session) = try_mount_btrfs_ro(&image, &mnt) else {
        return;
    };

    let path = mnt
        .join(BTRFS_TEST_WORKSPACE)
        .join("readonly_xattr_seed.txt");
    assert_eq!(
        fs::read(&path).expect("read seeded ro btrfs xattr file"),
        b"readonly btrfs xattr seed\n",
        "ro remount must preserve the seeded file bytes"
    );

    assert_read_only_xattr_mutation_contract(
        &path,
        "btrfs_ro_xattr_mutation_rejects_erofs_no_side_effects",
    );
}

#[test]
fn btrfs_fuse_xattr_overwrite_value() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_overwrite_value";
        let path = mnt.join("overwrite_xattr.txt");
        fs::write(&path, b"overwrite xattr test\n").expect("write for overwrite xattr");

        // Set initial value.
        py_setxattr(&path, "user.mutable", b"original");
        assert_eq!(py_getxattr(&path, "user.mutable").unwrap(), b"original");

        // Overwrite with different value.
        py_setxattr(&path, "user.mutable", b"updated_value");
        assert_eq!(
            py_getxattr(&path, "user.mutable").unwrap(),
            b"updated_value"
        );
        emit_scenario_result(scenario_id, "PASS", Some("second_setxattr_updates_value"));
    });
}

#[test]
fn btrfs_fuse_xattr_get_missing_reports_enodata_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_get_missing_reports_enodata";
        let path = mnt.join("nonexistent_xattr.txt");
        fs::write(&path, b"nonexistent xattr test\n").expect("write for nonexistent xattr");
        let original_file = fs::read(&path).expect("read original btrfs file bytes");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_getxattr_report(&path, "user.does_not_exist");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "missing btrfs getxattr should surface ENODATA on Linux FUSE: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "missing btrfs getxattr must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after missing getxattr"),
            original_file,
            "missing btrfs getxattr must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.does_not_exist"),
            "missing xattr should remain absent after btrfs ENODATA getxattr: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should remain listed after btrfs ENODATA getxattr: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_xattr_remove_missing_reports_enodata_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_xattr_remove_missing_reports_enodata";
        let path = mnt.join("remove_nonexistent_xattr.txt");
        fs::write(&path, b"remove nonexistent xattr test\n")
            .expect("write for remove nonexistent xattr");
        let original_file = fs::read(&path).expect("read original btrfs file bytes");
        py_setxattr(&path, "user.keep", b"preserve");

        let report = py_removexattr_report(&path, "user.no_such_attr");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "missing btrfs removexattr should surface ENODATA on Linux FUSE: {report}"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("unrelated xattr should remain readable"),
            b"preserve",
            "missing btrfs removexattr must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after missing removexattr"),
            original_file,
            "missing btrfs removexattr must not mutate file contents"
        );

        let names = py_listxattr(&path);
        assert!(
            !names.iter().any(|name| name == "user.no_such_attr"),
            "missing xattr should remain absent after btrfs ENODATA removexattr: {names:?}"
        );
        assert!(
            names.iter().any(|name| name == "user.keep"),
            "unrelated xattr should remain listed after btrfs ENODATA removexattr: {names:?}"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("errno=ENODATA_with_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_getxattr_size_probe_and_erange_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_getxattr_size_probe_and_erange";
        let path = mnt.join("getxattr_probe.txt");
        let original_file = b"btrfs getxattr probe coverage\n";
        let expected_value = b"probe-value";
        fs::write(&path, original_file).expect("write btrfs getxattr probe file");
        py_setxattr(&path, "user.probed", expected_value);
        py_setxattr(&path, "user.keep", b"preserve");

        let probe_report = py_getxattr_probe_report(&path, "user.probed", 0);
        assert_eq!(
            probe_report["len"].as_u64(),
            Some(expected_value.len() as u64),
            "zero-sized getxattr probe should report exact required length: {probe_report}"
        );

        let exact_report = py_getxattr_probe_report(&path, "user.probed", expected_value.len());
        let expected_value_hex = hex::encode(expected_value);
        assert_eq!(
            exact_report["len"].as_u64(),
            Some(expected_value.len() as u64),
            "exact-sized getxattr should report the payload length: {exact_report}"
        );
        assert_eq!(
            exact_report["value_hex"].as_str(),
            Some(expected_value_hex.as_str()),
            "exact-sized getxattr should return the full payload: {exact_report}"
        );

        let erange_report =
            py_getxattr_probe_report(&path, "user.probed", expected_value.len() - 1);
        assert_eq!(
            erange_report["errno"].as_i64(),
            Some(i64::from(libc::ERANGE)),
            "undersized getxattr buffer should fail with ERANGE: {erange_report}"
        );

        assert_eq!(
            py_getxattr(&path, "user.probed").expect("probed xattr should remain readable"),
            expected_value,
            "getxattr probe/ERANGE paths must not disturb the target xattr"
        );
        assert_eq!(
            py_getxattr(&path, "user.keep").expect("keep xattr should remain readable"),
            b"preserve",
            "getxattr probe/ERANGE paths must not disturb unrelated xattrs"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after getxattr probe"),
            original_file,
            "getxattr probe/ERANGE paths must not mutate file contents"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("probe_len_exact_and_erange_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_listxattr_size_probe_and_erange_without_side_effects() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_listxattr_size_probe_and_erange";
        let path = mnt.join("listxattr_probe.txt");
        let original_file = b"btrfs listxattr probe coverage\n";
        fs::write(&path, original_file).expect("write btrfs listxattr probe file");
        py_setxattr(&path, "user.alpha", b"one");
        py_setxattr(&path, "user.beta", b"two");

        let expected_names = py_listxattr(&path);
        let expected_len: usize = expected_names.iter().map(|name| name.len() + 1).sum();

        let probe_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            probe_report["len"].as_u64(),
            Some(expected_len as u64),
            "zero-sized listxattr probe should report exact required length: {probe_report}"
        );

        let exact_report = py_listxattr_probe_report(&path, expected_len);
        assert_eq!(
            exact_report["len"].as_u64(),
            Some(expected_len as u64),
            "exact-sized listxattr should report the serialized name length: {exact_report}"
        );
        let mut actual_names: Vec<String> = exact_report["names"]
            .as_array()
            .expect("listxattr exact-sized names")
            .iter()
            .map(|value| value.as_str().expect("listxattr name string").to_string())
            .collect();
        let mut expected_sorted = expected_names;
        actual_names.sort();
        expected_sorted.sort();
        assert_eq!(
            actual_names, expected_sorted,
            "exact-sized listxattr should return the full mounted-path name set"
        );

        let erange_report = py_listxattr_probe_report(&path, expected_len - 1);
        assert_eq!(
            erange_report["errno"].as_i64(),
            Some(i64::from(libc::ERANGE)),
            "undersized listxattr buffer should fail with ERANGE: {erange_report}"
        );

        let mut names_after = py_listxattr(&path);
        names_after.sort();
        assert_eq!(
            names_after, expected_sorted,
            "listxattr probe/ERANGE paths must not disturb the visible xattr set"
        );
        assert_eq!(
            py_getxattr(&path, "user.alpha").expect("alpha xattr should remain readable"),
            b"one",
            "listxattr probe/ERANGE paths must not disturb alpha"
        );
        assert_eq!(
            py_getxattr(&path, "user.beta").expect("beta xattr should remain readable"),
            b"two",
            "listxattr probe/ERANGE paths must not disturb beta"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after listxattr probe"),
            original_file,
            "listxattr probe/ERANGE paths must not mutate file contents"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("probe_len_exact_and_erange_no_side_effects"),
        );
    });
}

#[test]
fn btrfs_fuse_empty_listxattr_size_probe_and_zero_length_payload() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_empty_listxattr_size_probe";
        let path = mnt.join("empty_listxattr_probe.txt");
        let original_file = b"btrfs empty listxattr probe coverage\n";
        fs::write(&path, original_file).expect("write btrfs empty listxattr probe file");

        let initial_names = py_listxattr(&path);
        assert!(
            initial_names.is_empty(),
            "fresh btrfs file should expose no visible xattrs: {initial_names:?}"
        );

        let probe_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            probe_report["len"].as_u64(),
            Some(0),
            "empty listxattr size probe should report length 0: {probe_report}"
        );

        // For an empty xattr set, the exact-fit payload size is also zero.
        let zero_len_payload_report = py_listxattr_probe_report(&path, 0);
        assert_eq!(
            zero_len_payload_report["len"].as_u64(),
            Some(0),
            "empty listxattr zero-length payload should succeed with length 0: {zero_len_payload_report}"
        );

        let names_after = py_listxattr(&path);
        assert!(
            names_after.is_empty(),
            "empty listxattr probe paths must not create visible xattrs: {names_after:?}"
        );
        assert_eq!(
            fs::read(&path).expect("read btrfs file bytes after empty listxattr probe"),
            original_file,
            "empty listxattr probe paths must not mutate file contents"
        );
        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("empty_len_zero_and_zero_length_success"),
        );
    });
}

#[test]
fn btrfs_fuse_ioctl_fs_info_via_mounted_path() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        // Use direct ioctl via Python to exercise BTRFS_IOC_FS_INFO (0x8400941F).
        // The ioctl returns a 1024-byte btrfs_ioctl_fs_info_args struct.
        let script = format!(
            r#"
import os, fcntl, struct
fd = os.open({mnt:?}, os.O_RDONLY | os.O_DIRECTORY)
try:
    buf = bytearray(1024)
    # BTRFS_IOC_FS_INFO = _IOR(0x94, 0x1f, 1024) = 0x8400941f
    fcntl.ioctl(fd, 0x8400941f, buf)
    # Parse first fields: max_id(u64), num_devices(u64), fsid(16 bytes), nodesize(u32)
    max_id, num_devices = struct.unpack_from('<QQ', buf, 0)
    fsid = buf[0x10:0x20]
    nodesize, sectorsize = struct.unpack_from('<II', buf, 0x20)
    print("max_id=%d num_devices=%d nodesize=%d sectorsize=%d" % (max_id, num_devices, nodesize, sectorsize))
    print("fsid=%s" % fsid.hex())
    assert num_devices >= 1, "num_devices should be at least 1"
    assert nodesize in (4096, 8192, 16384, 32768, 65536), "unexpected nodesize %d" % nodesize
    assert sectorsize in (512, 1024, 2048, 4096), "unexpected sectorsize %d" % sectorsize
    print("PASS")
finally:
    os.close(fd)
"#,
            mnt = mnt.to_str().unwrap()
        );

        let out = Command::new("python3")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run python3 ioctl script");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("PASS"),
            "BTRFS_IOC_FS_INFO via mounted path failed: stdout={stdout}, stderr={stderr}"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_posix_acl_list_and_get() {
    with_btrfs_rw_mount(|mnt| {
        let file_path = mnt.join("acl_test_file.txt");
        let dir_path = mnt.join("acl_test_dir");
        fs::write(&file_path, b"POSIX ACL test content\n").expect("create test file for ACL");
        fs::create_dir(&dir_path).expect("create test dir for ACL");

        let access_acl = build_posix_acl_xattr(&[
            (ACL_USER_OBJ_TAG, 0o6),
            (ACL_GROUP_OBJ_TAG, 0o4),
            (ACL_OTHER_TAG, 0),
        ]);
        let default_acl = build_posix_acl_xattr(&[
            (ACL_USER_OBJ_TAG, 0o7),
            (ACL_GROUP_OBJ_TAG, 0o5),
            (ACL_OTHER_TAG, 0o1),
        ]);

        py_setxattr(&file_path, "system.posix_acl_access", &access_acl);
        py_setxattr(&dir_path, "system.posix_acl_default", &default_acl);

        let file_names = py_listxattr(&file_path);
        assert!(
            file_names
                .iter()
                .any(|name| name == "system.posix_acl_access"),
            "listxattr on btrfs file should expose system.posix_acl_access, got: {file_names:?}"
        );

        let access_report = py_getxattr_report(&file_path, "system.posix_acl_access");
        assert!(
            access_report["value_hex"].is_string(),
            "btrfs getxattr for system.posix_acl_access should succeed: {access_report}"
        );

        let dir_names = py_listxattr(&dir_path);
        assert!(
            dir_names
                .iter()
                .any(|name| name == "system.posix_acl_default"),
            "listxattr on btrfs dir should expose system.posix_acl_default, got: {dir_names:?}"
        );

        let default_report = py_getxattr_report(&dir_path, "system.posix_acl_default");
        assert!(
            default_report["value_hex"].is_string(),
            "btrfs getxattr for system.posix_acl_default should succeed: {default_report}"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_posix_acl_default_missing_on_regular_file_reports_enodata() {
    with_btrfs_rw_mount(|mnt| {
        let file_path = mnt.join("no_acl_file.txt");
        fs::write(&file_path, b"file without default ACL\n").expect("create test file");

        let names = py_listxattr(&file_path);
        assert!(
            !names.iter().any(|name| name == "system.posix_acl_default"),
            "btrfs regular file should not list a default ACL xattr, got: {names:?}"
        );

        let report = py_getxattr_report(&file_path, "system.posix_acl_default");
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENODATA)),
            "btrfs getxattr for missing system.posix_acl_default should return ENODATA: {report}"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_name_too_long_reports_enametoolong() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("xattr_name_test.txt");
        fs::write(&path, b"xattr name length test\n").expect("create test file");
        let original_file = fs::read(&path).expect("read original file bytes");

        // xattr name suffix is limited to 255 bytes (u8::MAX)
        let long_suffix = "a".repeat(256);
        let long_name = format!("user.{long_suffix}");

        let report = py_setxattr_report(&path, &long_name, b"value", 0);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::ENAMETOOLONG)),
            "btrfs xattr name > 255-byte suffix should return ENAMETOOLONG: {report}"
        );

        // Verify no side effects
        assert_eq!(
            fs::read(&path).expect("read file bytes after name-too-long rejection"),
            original_file,
            "btrfs name-too-long rejection must not mutate file contents"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_value_too_large_reports_einval() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("xattr_value_test.txt");
        fs::write(&path, b"xattr value size test\n").expect("create test file");
        let original_file = fs::read(&path).expect("read original file bytes");

        // xattr value limit is 64KB (65536 bytes)
        let oversized_value = vec![0x42_u8; 65537];

        let report = py_setxattr_report(&path, "user.toobig", &oversized_value, 0);
        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "btrfs xattr value > 64KB should return EINVAL: {report}"
        );

        // Verify the xattr was not created
        assert!(
            py_getxattr(&path, "user.toobig").is_none(),
            "btrfs oversized xattr value should not be stored"
        );

        // Verify no side effects
        assert_eq!(
            fs::read(&path).expect("read file bytes after value-too-large rejection"),
            original_file,
            "btrfs value-too-large rejection must not mutate file contents"
        );
    });
}

#[test]
fn btrfs_fuse_xattr_boundary_name_length_accepted() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("xattr_boundary_name.txt");
        fs::write(&path, b"boundary name test\n").expect("create test file");

        // The maximum suffix length is 255 bytes (u8::MAX)
        let max_suffix = "z".repeat(255);
        let max_name = format!("user.{max_suffix}");

        py_setxattr(&path, &max_name, b"boundary");
        let readback = py_getxattr(&path, &max_name).expect("btrfs 255-byte suffix xattr should exist");
        assert_eq!(readback, b"boundary", "btrfs boundary-length xattr should round-trip");
    });
}

#[test]
fn btrfs_fuse_xattr_boundary_value_size_accepted() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("xattr_boundary_value.txt");
        fs::write(&path, b"boundary value test\n").expect("create test file");

        // The maximum value size is 64KB (65536 bytes)
        let max_value = vec![0xAB_u8; 65536];

        py_setxattr(&path, "user.maxval", &max_value);
        let readback = py_getxattr(&path, "user.maxval").expect("btrfs 64KB xattr value should exist");
        assert_eq!(readback, max_value, "btrfs boundary-size xattr value should round-trip");
    });
}

#[test]
fn ext4_fuse_security_xattr_requires_privilege() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Attempting to set security.* xattr without CAP_SYS_ADMIN should fail.
        // This tests the security namespace enforcement path.
        let report = py_setxattr_report(&path, "security.test", b"test_value", 0);

        // Expect EPERM (operation not permitted) for unprivileged security xattr write.
        // Some kernels may return EOPNOTSUPP if security xattrs are disabled.
        let errno = report["errno"].as_i64();
        assert!(
            errno == Some(i64::from(libc::EPERM)) || errno == Some(i64::from(libc::EOPNOTSUPP)),
            "security.* xattr write should fail with EPERM or EOPNOTSUPP, got: {report}"
        );
    });
}

#[test]
fn btrfs_fuse_security_xattr_requires_privilege() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("security_test.txt");
        fs::write(&path, b"security xattr test\n").expect("create test file");

        // Attempting to set security.* xattr without CAP_SYS_ADMIN should fail.
        let report = py_setxattr_report(&path, "security.test", b"test_value", 0);

        // Expect EPERM (operation not permitted) for unprivileged security xattr write.
        let errno = report["errno"].as_i64();
        assert!(
            errno == Some(i64::from(libc::EPERM)) || errno == Some(i64::from(libc::EOPNOTSUPP)),
            "btrfs security.* xattr write should fail with EPERM or EOPNOTSUPP, got: {report}"
        );
    });
}

#[test]
fn ext4_fuse_security_xattr_not_listed_without_privilege() {
    with_rw_mount(|mnt| {
        let path = mnt.join("hello.txt");

        // Verify security.* xattrs are not visible to unprivileged listxattr.
        // The file shouldn't have any security.* xattrs by default.
        let names = py_listxattr(&path);
        let has_security = names.iter().any(|n| n.starts_with("security."));
        assert!(
            !has_security,
            "unprivileged listxattr should not expose security.* xattrs, got: {names:?}"
        );
    });
}

#[test]
fn btrfs_fuse_security_xattr_not_listed_without_privilege() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("security_list_test.txt");
        fs::write(&path, b"security list test\n").expect("create test file");

        // Verify security.* xattrs are not visible to unprivileged listxattr.
        let names = py_listxattr(&path);
        let has_security = names.iter().any(|n| n.starts_with("security."));
        assert!(
            !has_security,
            "btrfs unprivileged listxattr should not expose security.* xattrs, got: {names:?}"
        );
    });
}

#[test]
fn ext4_fuse_ioctl_getversion_via_mounted_path() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_rw_mount(|mnt| {
        let file_path = mnt.join("hello.txt");

        // Use Python fcntl to issue EXT4_IOC_GETVERSION (0x80086603).
        // Returns a 4-byte u32 (inode generation number).
        let script = format!(
            r#"
import os, fcntl, struct
fd = os.open({path:?}, os.O_RDONLY)
try:
    buf = bytearray(4)
    # EXT4_IOC_GETVERSION = _IOR('f', 3, long) = 0x80086603
    fcntl.ioctl(fd, 0x80086603, buf)
    version = struct.unpack('<I', buf)[0]
    print("version=%d" % version)
    # Version should be a reasonable number (not garbage).
    assert version < 0xFFFFFFFF, "version looks like uninitialized garbage"
    print("PASS")
except OSError as e:
    print("errno=%d message=%s" % (e.errno, str(e)))
finally:
    os.close(fd)
"#,
            path = file_path.to_str().unwrap()
        );

        let out = Command::new("python3")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run python3 ioctl script");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        // The ioctl may fail if the kernel doesn't forward it to FUSE.
        // We accept either PASS or a known transport-layer failure.
        if stdout.contains("PASS") {
            // Success - FUSE forwarded the ioctl and we got a valid version.
            return;
        }

        // Check for known transport-layer rejections (ENOTTY, EINVAL from kernel).
        if stdout.contains("errno=25") || stdout.contains("errno=22") {
            eprintln!(
                "EXT4_IOC_GETVERSION not forwarded by kernel (transport-layer skip): {stdout}"
            );
            return;
        }

        panic!(
            "EXT4_IOC_GETVERSION via mounted path failed unexpectedly: stdout={stdout}, stderr={stderr}"
        );
    });
}

#[test]
fn ext4_fuse_ioctl_setversion_roundtrips_via_mounted_path() {
    if !fuse_available() || !command_available("python3") {
        eprintln!("FUSE or python3 prerequisites not met, skipping");
        return;
    }

    let tmp = TempDir::new().expect("tmpdir");
    let image = create_test_image_with_size(tmp.path(), 4 * 1024 * 1024);
    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");
    let ioctl_trace_path: PathBuf = tmp.path().join("ioctl-ext4-setversion.log");
    let mount_opts = MountOptions {
        read_only: false,
        auto_unmount: false,
        ioctl_trace_path: Some(ioctl_trace_path.clone()),
        ..MountOptions::default()
    };
    let Some(_session) = try_mount_ffs_rw_with_options(&image, &mnt, &mount_opts) else {
        return;
    };

    let scenario_id = "ext4_ioctl_setversion_roundtrip";
    let path = mnt.join("version-target.txt");
    fs::write(&path, b"setversion mounted path target\n").expect("create setversion target");

    let original_report = ext4_inode_generation_ioctl(&path, "get", None);
    let get_trace = read_ioctl_trace(&ioctl_trace_path);
    if let Some(errno) = original_report["errno"].as_i64() {
        let transport_errno = errno == i64::from(libc::ENOTTY)
            || errno == i64::from(libc::EINVAL)
            || errno == EOPNOTSUPP_ERRNO;
        assert!(
            transport_errno,
            "unexpected errno for mounted-path GETVERSION preflight: {original_report}"
        );
        assert!(
            !trace_contains_cmd(&get_trace, EXT4_IOC_GETVERSION_CMD),
            "GETVERSION returned transport errno after reaching ffs-fuse::ioctl: {get_trace}"
        );
        emit_scenario_result(
            scenario_id,
            "SKIP",
            Some("kernel_or_vfs_rejected_getversion_before_userspace"),
        );
        return;
    }
    assert!(
        trace_contains_cmd(&get_trace, EXT4_IOC_GETVERSION_CMD),
        "successful GETVERSION should hit ffs-fuse::ioctl: {get_trace}"
    );

    let original = u32::try_from(
        original_report["generation"]
            .as_u64()
            .expect("original generation u64"),
    )
    .expect("original generation should fit u32");
    let requested = original ^ 0x1357_9BDF_u32;

    let set_report = ext4_inode_generation_ioctl(&path, "set", Some(requested));
    let set_trace = read_ioctl_trace(&ioctl_trace_path);
    if let Some(errno) = set_report["errno"].as_i64() {
        let transport_errno = errno == i64::from(libc::ENOTTY) || errno == i64::from(libc::EINVAL);
        assert!(
            transport_errno,
            "unexpected errno for mounted-path SETVERSION: {set_report}"
        );
        assert!(
            !trace_contains_cmd(&set_trace, EXT4_IOC_SETVERSION_CMD),
            "SETVERSION returned transport errno after reaching ffs-fuse::ioctl: {set_trace}"
        );
        emit_scenario_result(
            scenario_id,
            "SKIP",
            Some("kernel_or_vfs_rejected_setversion_before_userspace"),
        );
        return;
    }
    assert!(
        trace_contains_cmd(&set_trace, EXT4_IOC_SETVERSION_CMD),
        "successful SETVERSION should hit ffs-fuse::ioctl: {set_trace}"
    );
    assert!(
        set_report["errno"].is_null(),
        "mounted-path SETVERSION should succeed on rw ext4 mount: {set_report}"
    );

    let updated_report = ext4_inode_generation_ioctl(&path, "get", None);
    let updated_trace = read_ioctl_trace(&ioctl_trace_path);
    assert!(
        trace_contains_cmd(&updated_trace, EXT4_IOC_GETVERSION_CMD),
        "post-set GETVERSION should hit ffs-fuse::ioctl: {updated_trace}"
    );
    assert!(
        updated_report["errno"].is_null(),
        "post-set GETVERSION should succeed after mounted-path SETVERSION: {updated_report}"
    );
    assert_eq!(
        updated_report["generation"].as_u64(),
        Some(u64::from(requested)),
        "mounted-path GETVERSION should roundtrip the SETVERSION payload: {updated_report}"
    );
    emit_scenario_result(
        scenario_id,
        "PASS",
        Some("setversion_roundtrip_via_getversion"),
    );
}

#[test]
fn btrfs_fuse_write_large_file() {
    with_btrfs_rw_mount(|mnt| {
        let path = mnt.join("large.bin");
        // Write 64 KiB of patterned data (crosses multiple blocks).
        let data = patterned_bytes(65_536, 251, 0);
        fs::write(&path, &data).expect("write large file on btrfs");

        let readback = fs::read(&path).expect("read large file on btrfs");
        assert_eq!(readback.len(), 65536);
        assert_eq!(readback, data, "large file content should match on btrfs");
    });
}

#[test]
fn btrfs_fuse_fallocate_preallocate_extends_size() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_preallocate_extends_size";
        let path = mnt.join("btrfs_preallocated.bin");
        fs::write(&path, b"").expect("create empty btrfs file");

        let out = Command::new("fallocate")
            .args(["-l", "8192", path.to_str().unwrap()])
            .output()
            .expect("run fallocate preallocate on btrfs");
        assert!(
            out.status.success(),
            "btrfs preallocate fallocate failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after btrfs preallocate fallocate");
        assert_eq!(
            meta.len(),
            8192,
            "btrfs preallocate should extend apparent file size to 8192"
        );
        assert!(
            meta.blocks() * 512 >= 8192,
            "allocated disk space ({}*512={}) should be >= 8192 after btrfs preallocation",
            meta.blocks(),
            meta.blocks() * 512
        );

        fs::write(&path, b"data in btrfs preallocated space").expect("write to btrfs preallocated");
        let content = fs::read_to_string(&path).expect("read btrfs preallocated");
        assert_eq!(content, "data in btrfs preallocated space");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_keep_size_preserves_size() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_keep_size_preserves_size";
        let path = mnt.join("btrfs_keep_size.bin");
        fs::write(&path, b"short").expect("create btrfs file with content");

        let out = Command::new("fallocate")
            .args(["-l", "16384", "--keep-size", path.to_str().unwrap()])
            .output()
            .expect("run keep-size fallocate on btrfs");
        assert!(
            out.status.success(),
            "btrfs keep-size fallocate failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after btrfs keep-size fallocate");
        assert_eq!(
            meta.len(),
            5,
            "btrfs keep-size fallocate should preserve apparent file size"
        );

        let content = fs::read_to_string(&path).expect("read after btrfs keep-size fallocate");
        assert_eq!(content, "short");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_punch_hole_keep_size_zeroes_range() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_punch_hole_keep_size_zeroes_range";
        let path = mnt.join("punch_hole.bin");
        let data = patterned_bytes(12_288, 251, 1);
        fs::write(&path, &data).expect("seed punch-hole file on btrfs");

        let out = Command::new("fallocate")
            .args([
                "--keep-size",
                "--punch-hole",
                "-o",
                "4096",
                "-l",
                "4096",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("run fallocate --punch-hole --keep-size on btrfs");
        assert!(
            out.status.success(),
            "btrfs keep-size punch-hole failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after btrfs keep-size punch-hole");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "punch hole must preserve file size"
        );

        let readback = fs::read(&path).expect("read after btrfs keep-size punch-hole");
        assert_eq!(&readback[..4096], &data[..4096], "prefix must be preserved");
        assert!(
            readback[4096..8192].iter().all(|&byte| byte == 0),
            "punched range must read back as zeros"
        );
        assert_eq!(&readback[8192..], &data[8192..], "suffix must be preserved");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_zero_range_zeroes_range() {
    if !command_available("fallocate") {
        eprintln!("fallocate not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_zero_range_zeroes_range";
        let path = mnt.join("zero_range.bin");
        let data = patterned_bytes(12_288, 253, 1);
        fs::write(&path, &data).expect("seed zero-range file on btrfs");

        let out = Command::new("fallocate")
            .args([
                "--zero-range",
                "-o",
                "4096",
                "-l",
                "4096",
                path.to_str().unwrap(),
            ])
            .output()
            .expect("run fallocate --zero-range on btrfs");
        assert!(
            out.status.success(),
            "btrfs zero-range failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let meta = fs::metadata(&path).expect("stat after btrfs zero-range");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "zero-range must preserve file size"
        );

        let readback = fs::read(&path).expect("read after btrfs zero-range");
        assert_eq!(&readback[..4096], &data[..4096], "prefix must be preserved");
        assert!(
            readback[4096..8192].iter().all(|&byte| byte == 0),
            "zero-range span must read back as zeros"
        );
        assert_eq!(&readback[8192..], &data[8192..], "suffix must be preserved");
        emit_scenario_result(scenario_id, "PASS", None);
    });
}

#[test]
fn btrfs_fuse_fallocate_on_directory_reports_eisdir() {
    if !command_available("python3") {
        eprintln!("python3 not available, skipping");
        return;
    }

    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fallocate_on_directory_errno_eisdir";
        let dir = mnt.join("fallocate_dir");
        fs::create_dir(&dir).expect("mkdir btrfs fallocate directory target");
        let child = dir.join("child.txt");
        fs::write(&child, b"directory child stays intact\n").expect("seed btrfs directory child");

        let entries_before = snapshot_directory_entries(&dir);
        let child_before = snapshot_file_state(&child);
        let report = query_directory_fallocate(&dir, 0, 0, 4096);

        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EISDIR)),
            "btrfs directory fallocate should surface exact EISDIR: {report}"
        );
        assert_eq!(
            report["name"].as_str(),
            Some("EISDIR"),
            "btrfs directory fallocate should surface the EISDIR alias: {report}"
        );
        let phase = report["phase"]
            .as_str()
            .expect("directory fallocate rejection phase");
        assert!(
            matches!(phase, "open" | "fallocate"),
            "unexpected directory fallocate rejection phase: {report}"
        );

        let entries_after = snapshot_directory_entries(&dir);
        assert_eq!(
            entries_after, entries_before,
            "directory fallocate rejection must not change directory entries"
        );
        assert_file_state_unchanged(&child, &child_before, "directory fallocate rejection");
        emit_scenario_result(scenario_id, "PASS", Some(phase));
    });
}

#[test]
fn btrfs_fuse_invalid_punch_hole_without_keep_size_reports_einval() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_invalid_punch_hole_without_keep_size_errno_einval";
        let path = mnt.join("invalid_punch_hole_mode.bin");
        let data = patterned_bytes(12_288, 253, 1);
        fs::write(&path, &data).expect("seed invalid-punch-hole file on btrfs");

        let report = query_fallocate(&path, libc::FALLOC_FL_PUNCH_HOLE, 4096, 4096);
        let meta = fs::metadata(&path).expect("stat after invalid btrfs punch-hole rejection");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "invalid btrfs punch-hole rejection must preserve file size"
        );
        let readback = fs::read(&path).expect("read after invalid btrfs punch-hole rejection");
        assert_eq!(
            readback, data,
            "invalid btrfs punch-hole rejection must preserve file data"
        );

        if report["errno"].as_i64() == Some(EOPNOTSUPP_ERRNO) {
            eprintln!(
                "invalid btrfs punch-hole mode collapsed to transport-layer errno 95 before \
                 FrankenFS could prove mounted-path EINVAL semantics: {report}"
            );
            return;
        }

        assert_eq!(
            report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "btrfs invalid punch-hole mode should surface EINVAL when dispatched to FrankenFS: {report}"
        );
        assert_eq!(
            report["name"].as_str(),
            Some("EINVAL"),
            "btrfs invalid punch-hole mode should surface the EINVAL alias: {report}"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=22"));
    });
}

#[test]
fn btrfs_fuse_unsupported_fallocate_mode_bits_errno_eopnotsupp() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_unsupported_fallocate_mode_bits_errno_eopnotsupp";
        let path = mnt.join("unsupported_mode_bits.bin");
        let data = b"keep-intact-on-unsupported-mode".to_vec();
        fs::write(&path, &data).expect("seed unsupported-mode file on btrfs");

        let script = r#"
import ctypes
import errno
import os
import sys

path = sys.argv[1]
fd = os.open(path, os.O_RDWR)
libc = ctypes.CDLL(None, use_errno=True)
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
libc.fallocate.restype = ctypes.c_int
res = libc.fallocate(fd, 0x20, 0, 4096)
err = ctypes.get_errno()
os.close(fd)
if res == 0:
    print("res=0")
    sys.exit(0)
print(f"errno={err}")
print(errno.errorcode.get(err, "UNKNOWN"))
sys.exit(1)
"#;
        let out = Command::new("python3")
            .args(["-c", script, path.to_str().unwrap()])
            .output()
            .expect("run unsupported-mode fallocate probe on btrfs");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !out.status.success(),
            "unsupported mode bits should fail, got stdout={stdout} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains(&format!("errno={EOPNOTSUPP_ERRNO}")),
            "unsupported mode bits should surface errno {EOPNOTSUPP_ERRNO}, got: {stdout}"
        );
        assert!(
            stdout.contains("EOPNOTSUPP") || stdout.contains("ENOTSUP"),
            "unsupported mode bits should surface the errno-95 not-supported alias, got: {stdout}"
        );

        let meta = fs::metadata(&path).expect("stat after unsupported-mode rejection");
        assert_eq!(
            meta.len(),
            data.len() as u64,
            "unsupported mode rejection must preserve file size"
        );
        let readback = fs::read(&path).expect("read after unsupported-mode rejection");
        assert_eq!(
            readback, data,
            "unsupported mode rejection must preserve file data"
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=95"));
    });
}

#[test]
fn btrfs_fuse_fsync_emits_scenario_result_and_persists_written_data() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fsync";
        let path = mnt.join("synced.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create synced.txt on btrfs");

        file.write_all(b"data before fsync\n")
            .expect("write before fsync on btrfs");

        // sync_all triggers FUSE fsync.
        file.sync_all().expect("fsync via sync_all on btrfs");

        drop(file);

        // Read back and verify.
        let content = fs::read_to_string(&path).expect("read after fsync on btrfs");
        assert_eq!(content, "data before fsync\n");
        emit_scenario_result(scenario_id, "PASS", Some("sync_all"));
    });
}

#[test]
fn btrfs_fuse_sync_data_emits_scenario_result_and_persists_written_data() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fdatasync";
        let path = mnt.join("datasync.txt");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .expect("create datasync.txt on btrfs");

        file.write_all(b"datasync content\n")
            .expect("write before sync_data on btrfs");

        // sync_data triggers FUSE fsync with datasync=true.
        file.sync_data().expect("sync_data on btrfs");

        drop(file);

        let content = fs::read_to_string(&path).expect("read after sync_data on btrfs");
        assert_eq!(content, "datasync content\n");
        emit_scenario_result(scenario_id, "PASS", Some("sync_data"));
    });
}

#[test]
fn btrfs_fuse_fsyncdir_emits_scenario_result_and_preserves_dirent() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_fsyncdir";
        let dir = mnt.join("synced_dir");
        fs::create_dir(&dir).expect("mkdir for btrfs fsyncdir");

        let child = dir.join("child.txt");
        fs::write(&child, b"directory sync payload\n").expect("write child before btrfs fsyncdir");

        let dirfd = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(&dir)
            .expect("open directory fd for btrfs fsyncdir");
        dirfd.sync_all().expect("fsyncdir via sync_all on btrfs");
        drop(dirfd);

        let entries: HashSet<String> = fs::read_dir(&dir)
            .expect("readdir after btrfs fsyncdir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            entries.contains("child.txt"),
            "directory entry should remain visible after fsyncdir, got: {entries:?}"
        );
        assert_eq!(
            fs::read_to_string(&child).expect("read child after btrfs fsyncdir"),
            "directory sync payload\n"
        );
        emit_scenario_result(scenario_id, "PASS", Some("dirfd_sync_all"));
    });
}

#[test]
fn btrfs_fuse_read_only_fsync_reports_erofs_without_data_drift() {
    with_btrfs_ro_sync_fixture(|file_path, _, _| {
        assert_read_only_file_sync_contract(
            file_path,
            "btrfs_ro_fsync_rejects_erofs_no_drift",
            "fsync",
            fs::File::sync_all,
        );
    });
}

#[test]
fn btrfs_fuse_read_only_sync_data_reports_erofs_without_data_drift() {
    with_btrfs_ro_sync_fixture(|file_path, _, _| {
        assert_read_only_file_sync_contract(
            file_path,
            "btrfs_ro_fdatasync_rejects_erofs_no_drift",
            "fdatasync",
            fs::File::sync_data,
        );
    });
}

#[test]
fn btrfs_fuse_read_only_fsyncdir_reports_erofs_without_dirent_drift() {
    with_btrfs_ro_sync_fixture(|_, dir_path, child_path| {
        assert_read_only_dir_sync_contract(
            dir_path,
            child_path,
            "btrfs_ro_fsyncdir_rejects_erofs_no_drift",
        );
    });
}

#[test]
fn btrfs_fuse_flush_emits_scenario_result_and_preserves_data() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_flush";
        let path = mnt.join("flushed.txt");

        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&path)
                .expect("create flushed.txt on btrfs");

            file.write_all(b"flushed content\n")
                .expect("write flushed content on btrfs");
            // std::io::Write::flush triggers the FUSE flush handler.
            file.flush().expect("explicit flush on btrfs");
        } // drop/close triggers another FUSE flush+release

        let content = fs::read_to_string(&path).expect("read after btrfs flush+close");
        assert_eq!(content, "flushed content\n");
        emit_scenario_result(scenario_id, "PASS", Some("explicit_flush_and_close"));
    });
}

#[test]
fn btrfs_fuse_read_only_flush_succeeds_without_data_drift() {
    with_btrfs_ro_sync_fixture(|file_path, _, _| {
        assert_read_only_flush_contract(file_path, "btrfs_ro_flush_succeeds_no_drift");
    });
}

#[test]
fn btrfs_fuse_rename_across_directories() {
    with_btrfs_rw_mount(|mnt| {
        let dir_a = mnt.join("dir_a");
        let dir_b = mnt.join("dir_b");
        fs::create_dir(&dir_a).expect("mkdir dir_a");
        fs::create_dir(&dir_b).expect("mkdir dir_b");

        let src = dir_a.join("moveme.txt");
        let dst = dir_b.join("moved.txt");
        fs::write(&src, b"cross-dir rename").expect("write for cross-dir rename");

        fs::rename(&src, &dst).expect("rename across directories on btrfs");
        assert!(!src.exists());
        assert!(dst.exists());
        assert_eq!(
            fs::read_to_string(&dst).expect("read cross-dir renamed"),
            "cross-dir rename"
        );
    });
}

#[test]
fn btrfs_fuse_cross_parent_directory_rename_updates_parent_nlink_accounting() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_cross_parent_directory_rename_nlink_accounting";
        let source_parent = mnt.join("rename_src_parent");
        let destination_parent = mnt.join("rename_dst_parent");
        fs::create_dir(&source_parent).expect("mkdir btrfs source parent");
        fs::create_dir(&destination_parent).expect("mkdir btrfs destination parent");

        let source_child = source_parent.join("moved_dir");
        let destination_child = destination_parent.join("moved_dir");
        fs::create_dir(&source_child).expect("mkdir btrfs child directory");

        let source_entries_before = snapshot_directory_entries(&source_parent);
        let destination_entries_before = snapshot_directory_entries(&destination_parent);
        let source_parent_nlink_before = fs::metadata(&source_parent)
            .expect("stat btrfs source parent before rename")
            .nlink();
        let destination_parent_nlink_before = fs::metadata(&destination_parent)
            .expect("stat btrfs destination parent before rename")
            .nlink();
        let source_child_meta_before =
            fs::metadata(&source_child).expect("stat btrfs child before rename");
        let source_child_ino_before = source_child_meta_before.ino();
        let source_child_nlink_before = source_child_meta_before.nlink();

        fs::rename(&source_child, &destination_child)
            .expect("cross-parent directory rename on btrfs");

        let mut source_entries_expected_after = source_entries_before;
        source_entries_expected_after.remove("moved_dir");
        let mut destination_entries_expected_after = destination_entries_before;
        destination_entries_expected_after.insert("moved_dir".to_string());

        assert!(
            fs::symlink_metadata(&source_child).is_err(),
            "cross-parent rename must remove the source directory entry"
        );
        assert!(
            fs::symlink_metadata(&destination_child).is_ok(),
            "cross-parent rename must create the destination directory entry"
        );
        assert_eq!(
            snapshot_directory_entries(&source_parent),
            source_entries_expected_after,
            "source parent entries must drop the moved directory"
        );
        assert_eq!(
            snapshot_directory_entries(&destination_parent),
            destination_entries_expected_after,
            "destination parent entries must gain the moved directory"
        );
        assert_eq!(
            fs::metadata(&source_parent)
                .expect("stat btrfs source parent after rename")
                .nlink(),
            source_parent_nlink_before - 1,
            "moving a child directory out must decrement the source parent st_nlink"
        );
        assert_eq!(
            fs::metadata(&destination_parent)
                .expect("stat btrfs destination parent after rename")
                .nlink(),
            destination_parent_nlink_before + 1,
            "moving a child directory in must increment the destination parent st_nlink"
        );

        let destination_child_meta =
            fs::metadata(&destination_child).expect("stat btrfs child after rename");
        assert_eq!(
            destination_child_meta.ino(),
            source_child_ino_before,
            "cross-parent rename must preserve the moved directory inode"
        );
        assert_eq!(
            destination_child_meta.nlink(),
            source_child_nlink_before,
            "cross-parent rename must preserve the moved directory link count"
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("src_parent_minus_one_dst_parent_plus_one_child_preserved"),
        );
    });
}

#[test]
fn btrfs_fuse_rename_into_non_directory_parent_reports_enotdir() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_rename_into_non_directory_parent_errno_enotdir";
        let source = mnt.join("rename_source.txt");
        let non_directory_parent = mnt.join("rename_parent_file.txt");
        fs::write(&source, b"rename source payload\n").expect("write btrfs rename source");
        fs::write(&non_directory_parent, b"not a directory\n")
            .expect("write btrfs non-directory parent");

        let entries_before = snapshot_directory_entries(mnt);
        let source_before = snapshot_file_state(&source);
        let parent_before = snapshot_file_state(&non_directory_parent);
        let target = non_directory_parent.join("child.txt");

        let err =
            fs::rename(&source, &target).expect_err("rename into non-directory parent should fail");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ENOTDIR),
            "rename into a non-directory parent should surface exact ENOTDIR: {err}"
        );
        assert!(
            fs::symlink_metadata(&source).is_ok(),
            "rejected rename must leave the source entry in place"
        );
        assert!(
            fs::symlink_metadata(&target).is_err(),
            "rejected rename must not create the target entry"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "rejected rename must not change visible root entries"
        );
        assert_file_state_unchanged(&source, &source_before, "rejected rename source");
        assert_file_state_unchanged(
            &non_directory_parent,
            &parent_before,
            "rejected rename non-directory parent",
        );
        emit_scenario_result(scenario_id, "PASS", Some("errno=ENOTDIR_no_drift"));
    });
}

#[test]
fn btrfs_fuse_rename_file_directory_type_mismatch_reports_eisdir_and_enotdir() {
    with_btrfs_rw_mount(|mnt| {
        assert_rename_file_directory_type_mismatch_contract(
            mnt,
            "btrfs_rw_rename_file_directory_type_mismatch",
        );
    });
}

#[test]
fn btrfs_fuse_rename_missing_source_reports_enoent() {
    with_btrfs_rw_mount(|mnt| {
        assert_rename_missing_source_reports_enoent(
            mnt,
            "btrfs_rw_rename_missing_source_errno_enoent",
        );
    });
}

#[test]
fn btrfs_fuse_rename_overwrite() {
    with_btrfs_rw_mount(|mnt| {
        let src = mnt.join("src.txt");
        let dst = mnt.join("dst.txt");
        fs::write(&src, b"new content").expect("write src");
        fs::write(&dst, b"old content").expect("write dst");

        fs::rename(&src, &dst).expect("rename overwrite on btrfs");
        assert!(!src.exists());
        assert_eq!(
            fs::read_to_string(&dst).expect("read overwritten"),
            "new content"
        );
    });
}

#[test]
fn btrfs_fuse_renameat2_flag_rejection_reports_einval() {
    with_btrfs_rw_mount(|mnt| {
        let scenario_id = "btrfs_rw_renameat2_flag_rejection";
        if !command_available("python3") {
            emit_scenario_result(scenario_id, "SKIP", Some("python3_unavailable"));
            return;
        }

        let noreplace_src = mnt.join("renameat2-btrfs-noreplace-src.txt");
        let noreplace_dst = mnt.join("renameat2-btrfs-noreplace-dst.txt");
        let exchange_src = mnt.join("renameat2-btrfs-exchange-src.txt");
        let exchange_dst = mnt.join("renameat2-btrfs-exchange-dst.txt");

        fs::write(&noreplace_src, b"btrfs noreplace src\n")
            .expect("write btrfs renameat2 noreplace source");
        fs::write(&exchange_src, b"btrfs exchange src\n")
            .expect("write btrfs renameat2 exchange source");
        fs::write(&exchange_dst, b"btrfs exchange dst\n")
            .expect("write btrfs renameat2 exchange destination");

        let entries_before = snapshot_directory_entries(mnt);
        let noreplace_src_before = snapshot_file_state(&noreplace_src);
        let exchange_src_before = snapshot_file_state(&exchange_src);
        let exchange_dst_before = snapshot_file_state(&exchange_dst);

        let noreplace_report =
            py_renameat2_report(&noreplace_src, &noreplace_dst, libc::RENAME_NOREPLACE);
        assert_eq!(
            noreplace_report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "renameat2(RENAME_NOREPLACE) should surface exact EINVAL on btrfs: {noreplace_report:?}"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "rejected btrfs RENAME_NOREPLACE must not change visible workspace entries"
        );
        assert_file_state_unchanged(
            &noreplace_src,
            &noreplace_src_before,
            "btrfs renameat2 RENAME_NOREPLACE source",
        );
        assert!(
            fs::symlink_metadata(&noreplace_dst).is_err(),
            "rejected btrfs RENAME_NOREPLACE must not create a new destination entry"
        );

        let exchange_report =
            py_renameat2_report(&exchange_src, &exchange_dst, libc::RENAME_EXCHANGE);
        assert_eq!(
            exchange_report["errno"].as_i64(),
            Some(i64::from(libc::EINVAL)),
            "renameat2(RENAME_EXCHANGE) should surface exact EINVAL on btrfs: {exchange_report:?}"
        );
        assert_eq!(
            snapshot_directory_entries(mnt),
            entries_before,
            "rejected btrfs RENAME_EXCHANGE must not change visible workspace entries"
        );
        assert_file_state_unchanged(
            &exchange_src,
            &exchange_src_before,
            "btrfs renameat2 RENAME_EXCHANGE source",
        );
        assert_file_state_unchanged(
            &exchange_dst,
            &exchange_dst_before,
            "btrfs renameat2 RENAME_EXCHANGE destination",
        );

        emit_scenario_result(
            scenario_id,
            "PASS",
            Some("noreplace=EINVAL_exchange=EINVAL_no_drift"),
        );
    });
}

// ── New CI-compatible E2E scenarios ────────────────────────────────

#[test]
fn fuse_deep_directory_tree() {
    with_rw_mount(|mnt| {
        // Create a 5-level deep directory tree and verify traversal.
        let mut path = mnt.to_path_buf();
        for i in 0..5 {
            path = path.join(format!("level_{i}"));
            fs::create_dir(&path).unwrap_or_else(|e| panic!("mkdir level_{i}: {e}"));
        }

        // Write a file at the deepest level.
        let deep_file = path.join("deep.txt");
        fs::write(&deep_file, b"deep content").expect("write deep file");
        assert_eq!(
            fs::read_to_string(&deep_file).expect("read deep file"),
            "deep content"
        );

        // Verify the full path exists via metadata.
        let meta = fs::metadata(&deep_file).expect("stat deep file");
        assert!(meta.is_file());
        assert_eq!(meta.len(), 12);
    });
}

#[test]
fn fuse_many_files_in_directory() {
    with_rw_mount(|mnt| {
        // Create 100 files in a single directory and verify readdir returns all.
        let dir = mnt.join("many_files");
        fs::create_dir(&dir).expect("mkdir many_files");

        for i in 0..100 {
            let path = dir.join(format!("file_{i:03}.txt"));
            fs::write(&path, format!("content_{i}")).expect("write file");
        }

        let entries: Vec<String> = fs::read_dir(&dir)
            .expect("readdir many_files")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        assert_eq!(entries.len(), 100, "expected 100 entries in readdir");

        // Verify a random file.
        let content = fs::read_to_string(dir.join("file_042.txt")).expect("read file_042");
        assert_eq!(content, "content_42");
    });
}

#[test]
fn fuse_empty_file_operations() {
    with_rw_mount(|mnt| {
        // Create an empty file and verify it reads back as empty.
        let path = mnt.join("empty.txt");
        fs::write(&path, b"").expect("create empty file");

        let content = fs::read(&path).expect("read empty file");
        assert!(content.is_empty());

        let meta = fs::metadata(&path).expect("stat empty file");
        assert_eq!(meta.len(), 0);
    });
}

#[test]
fn fuse_rename_chain() {
    with_rw_mount(|mnt| {
        // Rename a file through a chain of names and verify content persists.
        let file_a = mnt.join("chain_a.txt");
        fs::write(&file_a, b"chain content").expect("write chain_a");

        let file_b = mnt.join("chain_b.txt");
        fs::rename(&file_a, &file_b).expect("rename a -> b");
        assert!(!file_a.exists());

        let file_c = mnt.join("chain_c.txt");
        fs::rename(&file_b, &file_c).expect("rename b -> c");
        assert!(!file_b.exists());

        assert_eq!(
            fs::read_to_string(&file_c).expect("read chain_c"),
            "chain content"
        );
    });
}

#[test]
fn fuse_concurrent_file_creation() {
    with_rw_mount(|mnt| {
        // Create files concurrently from multiple threads.
        let mnt_path = mnt.to_path_buf();
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let mp = mnt_path.clone();
                thread::spawn(move || {
                    let path = mp.join(format!("concurrent_{i}.txt"));
                    fs::write(&path, format!("thread_{i}")).expect("concurrent write");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread join");
        }

        // Verify all files exist with correct content.
        for i in 0..10 {
            let path = mnt_path.join(format!("concurrent_{i}.txt"));
            let content = fs::read_to_string(&path).expect("read concurrent file");
            assert_eq!(content, format!("thread_{i}"));
        }
    });
}

#[test]
fn fuse_unlink_nonexistent_returns_error() {
    with_rw_mount(|mnt| {
        let path = mnt.join("nonexistent.txt");
        let result = fs::remove_file(&path);
        assert!(
            result.is_err(),
            "removing nonexistent file should return error"
        );
    });
}

#[test]
fn fuse_overwrite_preserves_inode() {
    with_rw_mount(|mnt| {
        let path = mnt.join("inode_test.txt");
        fs::write(&path, b"first").expect("write first");
        let ino_before = fs::metadata(&path).expect("stat before").ino();

        // Overwrite with new content — inode should be preserved (same file, truncate+write).
        fs::write(&path, b"second").expect("write second");
        let ino_after = fs::metadata(&path).expect("stat after").ino();

        assert_eq!(
            ino_before, ino_after,
            "inode should be preserved on overwrite"
        );
        assert_eq!(
            fs::read_to_string(&path).expect("read after overwrite"),
            "second"
        );
    });
}

// =============================================================================
// btrfs subvolume/snapshot mount selection E2E tests
// =============================================================================

#[test]
#[ignore = "requires sudo for btrfs subvolume creation"]
fn btrfs_fuse_mount_subvolume_scopes_root_to_subvol() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let Some((image, subvols, _)) = create_btrfs_image_with_subvolumes(tmp.path()) else {
        return;
    };
    assert!(subvols.contains(&"data".to_string()), "test setup should create 'data' subvolume");

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let open_opts = OpenOptions {
        btrfs_mount_selection: BtrfsMountSelection::Subvolume("data".to_string()),
        ..OpenOptions::default()
    };
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };

    let Some(_session) = try_mount_btrfs_with_open_options(&image, &mnt, &open_opts, &mount_opts) else {
        panic!("mounting subvolume 'data' should succeed");
    };

    // The mounted root should be the subvolume, so subvol_marker.txt should be at root
    let subvol_marker = mnt.join("subvol_marker.txt");
    assert!(
        subvol_marker.exists(),
        "subvol_marker.txt should exist at mount root when mounting 'data' subvolume"
    );
    let content = fs::read_to_string(&subvol_marker).expect("read subvol marker");
    assert!(
        content.contains("in-data-subvol"),
        "marker content should confirm we're in the subvolume"
    );

    // root_marker.txt should NOT be visible (it's in the fs root, not the subvolume)
    let root_marker = mnt.join("root_marker.txt");
    assert!(
        !root_marker.exists(),
        "root_marker.txt should NOT exist when mounting subvolume (scoped to subvol tree)"
    );

    // The 'data' directory itself should NOT exist (we're inside it)
    let data_dir = mnt.join("data");
    assert!(
        !data_dir.exists(),
        "'data' directory should not exist inside itself"
    );

    emit_scenario_result(
        "btrfs_mount_subvolume_scopes_root",
        "PASS",
        Some("subvolume mounted as root, parent tree not visible"),
    );
}

#[test]
#[ignore = "requires sudo for btrfs subvolume creation"]
fn btrfs_fuse_mount_snapshot_scopes_root_to_snapshot() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let Some((image, _, snaps)) = create_btrfs_image_with_subvolumes(tmp.path()) else {
        return;
    };
    if !snaps.contains(&"snap-data".to_string()) {
        eprintln!("snapshot creation was not successful, skipping snapshot test");
        return;
    }

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let open_opts = OpenOptions {
        btrfs_mount_selection: BtrfsMountSelection::Snapshot("snap-data".to_string()),
        ..OpenOptions::default()
    };
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };

    let Some(_session) = try_mount_btrfs_with_open_options(&image, &mnt, &open_opts, &mount_opts) else {
        panic!("mounting snapshot 'snap-data' should succeed");
    };

    // The snapshot should have both markers (snapshot of subvolume + its own marker)
    let subvol_marker = mnt.join("subvol_marker.txt");
    assert!(
        subvol_marker.exists(),
        "subvol_marker.txt should exist in snapshot (inherited from source)"
    );

    let snap_marker = mnt.join("snapshot_marker.txt");
    assert!(
        snap_marker.exists(),
        "snapshot_marker.txt should exist (written after snapshot)"
    );

    emit_scenario_result(
        "btrfs_mount_snapshot_scopes_root",
        "PASS",
        Some("snapshot mounted as root with inherited + snapshot-specific content"),
    );
}

#[test]
#[ignore = "requires sudo for btrfs subvolume creation"]
fn btrfs_fuse_mount_missing_subvolume_returns_not_found() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let Some((image, _, _)) = create_btrfs_image_with_subvolumes(tmp.path()) else {
        return;
    };

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let open_opts = OpenOptions {
        btrfs_mount_selection: BtrfsMountSelection::Subvolume("nonexistent".to_string()),
        ..OpenOptions::default()
    };
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };

    // This should fail to mount because the subvolume doesn't exist
    let session = try_mount_btrfs_with_open_options(&image, &mnt, &open_opts, &mount_opts);
    assert!(
        session.is_none(),
        "mounting nonexistent subvolume should fail"
    );

    emit_scenario_result(
        "btrfs_mount_missing_subvolume_not_found",
        "PASS",
        Some("nonexistent subvolume correctly rejected"),
    );
}

#[test]
#[ignore = "requires sudo for btrfs subvolume creation"]
fn btrfs_fuse_mount_default_root_shows_subvolumes_as_directories() {
    if !btrfs_fuse_available() {
        eprintln!("btrfs FUSE prerequisites not met, skipping");
        return;
    }
    let tmp = TempDir::new().expect("tmpdir");
    let Some((image, subvols, _)) = create_btrfs_image_with_subvolumes(tmp.path()) else {
        return;
    };
    assert!(subvols.contains(&"data".to_string()));

    let mnt = tmp.path().join("mnt");
    fs::create_dir_all(&mnt).expect("create mountpoint");

    let open_opts = OpenOptions {
        btrfs_mount_selection: BtrfsMountSelection::DefaultRoot,
        ..OpenOptions::default()
    };
    let mount_opts = MountOptions {
        read_only: true,
        auto_unmount: false,
        ..MountOptions::default()
    };

    let Some(_session) = try_mount_btrfs_with_open_options(&image, &mnt, &open_opts, &mount_opts) else {
        panic!("mounting default root should succeed");
    };

    // Default root should show subvolumes as directories
    let data_dir = mnt.join("data");
    assert!(
        data_dir.exists(),
        "'data' subvolume should appear as directory when mounting default root"
    );
    assert!(
        data_dir.is_dir(),
        "'data' subvolume should be a directory"
    );

    // root_marker.txt should be visible at root
    let root_marker = mnt.join("root_marker.txt");
    assert!(
        root_marker.exists(),
        "root_marker.txt should exist when mounting default root"
    );

    // The subvolume's marker should be accessible via the directory
    let nested_marker = data_dir.join("subvol_marker.txt");
    assert!(
        nested_marker.exists(),
        "subvol_marker.txt should be accessible via data/ directory"
    );

    emit_scenario_result(
        "btrfs_mount_default_root_shows_subvols",
        "PASS",
        Some("default root shows subvolumes as directories"),
    );
}
