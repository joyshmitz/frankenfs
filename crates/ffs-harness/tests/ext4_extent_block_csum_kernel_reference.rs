//! Conformance harness: ext4 extent-tree external-block CRC32C tails
//! computed by `ffs_ondisk::verify_extent_block_checksum` must match what
//! the kernel/`mkfs.ext4`/`debugfs` actually wrote on disk.
//!
//! Inline extent trees (≤ 4 extents) live in the inode's 60-byte `i_block`
//! and have no tail checksum. Once a file fragments past four extents, ext4
//! spills the tree into one or more external blocks; each of those blocks
//! ends in a 4-byte CRC32C of `[..tail_off]` where `tail_off = 12 + 12 *
//! eh_max`. That tail is what `e2fsck -f` checks and what
//! `verify_extent_block_checksum` is responsible for. The existing kernel
//! reference covers logical→physical *mappings* (`collect_extents` vs
//! `debugfs blocks`) but never confirms the tail checksums against the
//! kernel's view, so a regression in the seed/tail-offset logic would slip
//! through every other test.
//!
//! Strategy:
//!   1. Build an image, write many small "padding" files, delete every
//!      other one to scatter the free-block list, then write one large
//!      target file. With this geometry `mkfs.ext4 1.47.x` reliably emits
//!      a depth-1 extent tree (one external leaf block).
//!   2. Walk the target inode's extent tree: for every external (non-root)
//!      block we read the raw bytes, recompute the tail using
//!      `verify_extent_block_checksum`, and assert success.
//!   3. Run `e2fsck -fn` on the image afterwards as an independent witness
//!      that the kernel agrees the tails are valid.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ffs_ondisk::{
    Ext4ImageReader, Ext4Inode, ExtentTree, parse_extent_tree, verify_extent_block_checksum,
};
use ffs_types::InodeNumber;

const TARGET_BIN_LEN: usize = 192 * 1024; // 48 blocks @ 4 KiB
const PAD_FILE_LEN: usize = 16 * 1024; // 4 blocks @ 4 KiB
const PAD_FILE_COUNT: usize = 24;

fn has_command(name: &str) -> bool {
    Command::new(name)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn ext4_tools_available() -> bool {
    has_command("mkfs.ext4")
        && has_command("debugfs")
        && has_command("dumpe2fs")
        && has_command("e2fsck")
}

fn unique_temp_path(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("ffs_extcsum_{tag}_{pid}_{nanos}.ext4"))
}

fn run_debugfs_w(image: &Path, cmd: &str) {
    let st = Command::new("debugfs")
        .args(["-w", "-R", cmd])
        .arg(image)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn debugfs");
    assert!(st.success(), "debugfs -w -R {cmd:?} failed");
}

fn create_fragmented_extent_image() -> PathBuf {
    let path = unique_temp_path("frag");
    let f = std::fs::File::create(&path).expect("create image file");
    f.set_len(64 * 1024 * 1024).expect("set image length");
    drop(f);
    let st = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-O", "^has_journal", "-b", "4096"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 failed");

    // Create the padding files.
    let pad_dir = std::env::temp_dir().join(format!(
        "ffs_extcsum_pads_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&pad_dir).expect("create pad scratch dir");

    for i in 1..=PAD_FILE_COUNT {
        let local = pad_dir.join(format!("pad_{i:02}.bin"));
        std::fs::write(&local, vec![b'P'; PAD_FILE_LEN]).expect("write pad payload");
        run_debugfs_w(
            &path,
            &format!("write {} /pad_{i:02}.bin", local.display()),
        );
    }
    // Delete every other padding file so the free list is shredded into
    // 16-KiB holes alternating with 16-KiB live regions.
    for i in (1..=PAD_FILE_COUNT).step_by(2) {
        run_debugfs_w(&path, &format!("rm /pad_{i:02}.bin"));
    }
    // Write the target file. With the above hole layout, mkfs.ext4 1.47.x
    // emits a depth-1 extent tree for this file (one external leaf block).
    let target_local = pad_dir.join("target.bin");
    std::fs::write(&target_local, vec![b'T'; TARGET_BIN_LEN]).expect("write target payload");
    run_debugfs_w(
        &path,
        &format!("write {} /target.bin", target_local.display()),
    );

    std::fs::remove_dir_all(&pad_dir).ok();
    path
}

#[derive(Debug, Default)]
struct ExtentTreeWalk {
    /// Total external (non-root) blocks visited.
    external_blocks: usize,
    /// Maximum depth reached, where depth=0 is the root inside the inode.
    max_depth: u16,
    /// Number of leaf-data extents found across the whole tree.
    leaf_extents: usize,
}

/// Walk the extent tree rooted in `inode`. For every external index/leaf
/// block, verifies its CRC32C tail against the kernel-written value.
fn walk_and_verify(
    image: &[u8],
    reader: &Ext4ImageReader,
    inode: &Ext4Inode,
    ino: InodeNumber,
) -> ExtentTreeWalk {
    let csum_seed = reader.sb.csum_seed();
    let block_size = reader.sb.block_size;
    let inode_no_u32 = u32::try_from(ino.0).expect("ino fits u32");
    let generation = inode.generation;

    let mut stats = ExtentTreeWalk::default();

    // Parse the inline root from the inode's extent_bytes.
    let (root_header, root_tree) =
        parse_extent_tree(&inode.extent_bytes).expect("parse inline extent root");
    stats.max_depth = root_header.depth;

    let mut frontier: Vec<(u64, u16)> = match root_tree {
        ExtentTree::Leaf(leaves) => {
            stats.leaf_extents += leaves.len();
            Vec::new()
        }
        ExtentTree::Index(idxs) => idxs.iter().map(|i| (i.leaf_block, root_header.depth)).collect(),
    };

    while let Some((phys, parent_depth)) = frontier.pop() {
        let block = reader
            .read_block(image, ffs_types::BlockNumber(phys))
            .expect("read external extent block");

        verify_extent_block_checksum(block, csum_seed, inode_no_u32, generation)
            .unwrap_or_else(|err| {
                panic!(
                    "extent block at physical {phys} (inode {inode_no_u32}, gen {generation}): \
                     verify_extent_block_checksum failed: {err:?}"
                );
            });

        stats.external_blocks += 1;
        let (child_header, child_tree) =
            parse_extent_tree(block).expect("parse external extent block");

        // Depth invariant: each level down decrements depth by 1.
        let expected_child_depth = parent_depth.saturating_sub(1);
        assert_eq!(
            child_header.depth, expected_child_depth,
            "extent block at phys {phys}: depth {child} != expected {expected_child_depth}",
            child = child_header.depth,
        );

        match child_tree {
            ExtentTree::Leaf(leaves) => {
                stats.leaf_extents += leaves.len();
            }
            ExtentTree::Index(idxs) => {
                for idx in idxs {
                    frontier.push((idx.leaf_block, child_header.depth));
                }
            }
        }

        // Lightweight sanity: read_block returned a slice of exactly
        // block_size bytes (so verify_extent_block_checksum walked the
        // full kernel-written block).
        assert_eq!(
            block.len(),
            usize::try_from(block_size).expect("block_size fits usize"),
            "read_block did not return a full block"
        );
    }

    stats
}

#[test]
fn ext4_extent_block_csum_kernel_reference() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let path = create_fragmented_extent_image();
    let image = std::fs::read(&path).expect("read fragmented image");
    let reader = Ext4ImageReader::new(&image).expect("parse fragmented image");

    let (ino, inode) = reader
        .resolve_path(&image, "/target.bin")
        .expect("resolve /target.bin");

    let stats = walk_and_verify(&image, &reader, &inode, ino);

    // The fragmentation strategy is calibrated so that mkfs.ext4 1.47.x
    // emits a depth-1 tree with at least one external block. If a future
    // e2fsprogs allocates more contiguously and the tree stays inline,
    // the test would silently degrade — so we assert that we actually
    // exercised the external-block path.
    assert!(
        stats.max_depth >= 1,
        "expected a non-inline extent tree (depth >= 1), got depth={} (the fragmentation \
         strategy may need revisiting for this e2fsprogs version)",
        stats.max_depth
    );
    assert!(
        stats.external_blocks >= 1,
        "expected at least one external extent block, got {}",
        stats.external_blocks
    );
    // The target file is 192 KiB across 48 blocks; even with maximal
    // contiguity the tree must cover all of those blocks via leaf extents.
    assert!(
        stats.leaf_extents >= 2,
        "expected ≥2 leaf extents in the fragmented target, got {}",
        stats.leaf_extents
    );

    // Independent witness: run e2fsck -fn (force, read-only, answer no).
    // It exits 0 when the on-disk metadata — including extent tail
    // checksums — is consistent.
    let st = Command::new("e2fsck")
        .args(["-fn"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn e2fsck");
    let code = st.code().unwrap_or(-1);
    assert_eq!(
        code, 0,
        "e2fsck disagreed with the FFS view: exit code {code}"
    );

    std::fs::remove_file(&path).ok();
}
