//! Conformance harness: ext4 block-bitmap and inode-bitmap CRC32C tails
//! computed by `ffs_ondisk::verify_block_bitmap_checksum` /
//! `verify_inode_bitmap_checksum` must match what `mkfs.ext4` actually
//! wrote into each group descriptor.
//!
//! These are distinct from the *group-descriptor* checksum (covered by
//! `ext4_group_desc_kernel_reference`): the kernel stores a separate CRC32C
//! of each bitmap block in `bg_block_bitmap_csum` / `bg_inode_bitmap_csum`,
//! seeded with `s_csum_seed` (no group-number XOR). Until now, ffs had no
//! end-to-end pin proving that its CRC computation here matches the kernel's
//! formula across multiple groups.
//!
//! Strategy:
//!   * Generate image variants that cover 4 KiB / 1 KiB block sizes and both
//!     32-byte and 64-byte descriptor widths. The bitmap csum is split into a
//!     16-bit lo half (always present) and a 16-bit hi half (only when the
//!     descriptor is 64 bytes).
//!   * For every group, read the on-disk block-bitmap and inode-bitmap
//!     blocks, recompute their CRC32C tails, and assert they validate
//!     against the stored value. Confirm the wider 64-bit csum form
//!     ignores the high half on 32-byte descriptor images.
//!   * Run `e2fsck -fn` as an independent witness that the kernel's view
//!     of the same bitmaps agrees with both ffs and mkfs.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use ffs_ondisk::ext4::{
    block_bitmap_checksum_value, inode_bitmap_checksum_value, verify_block_bitmap_checksum,
    verify_inode_bitmap_checksum,
};
use ffs_ondisk::Ext4ImageReader;
use ffs_types::{BlockNumber, GroupNumber};

/// `EXT4_BG_INODE_UNINIT` — the inode bitmap is uninitialised; the kernel
/// neither writes nor validates its CRC32C tail, so the stored value is 0.
const BG_INODE_UNINIT: u16 = 0x0001;
/// `EXT4_BG_BLOCK_UNINIT` — the block bitmap is uninitialised; same
/// "csum stays 0, do not validate" semantics.
const BG_BLOCK_UNINIT: u16 = 0x0002;

fn has_command(name: &str) -> bool {
    Command::new(name)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn ext4_tools_available() -> bool {
    has_command("mkfs.ext4") && has_command("e2fsck")
}

fn unique_temp_path(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("ffs_bitmap_csum_{tag}_{pid}_{nanos}.ext4"))
}

#[derive(Debug, Clone, Copy)]
struct Variant {
    tag: &'static str,
    size_bytes: u64,
    block_size: u32,
    /// Comma-separated `mkfs.ext4 -O` features (or empty for defaults).
    features: &'static str,
}

const VARIANTS: &[Variant] = &[
    // 4 KiB blocks: default features → 64-byte descriptor (so bitmap csums
    // span both lo/hi halves of `bg_*_bitmap_csum`).
    Variant {
        tag: "4k_default",
        size_bytes: 64 * 1024 * 1024,
        block_size: 4096,
        features: "",
    },
    // 1 KiB blocks: small group geometry exercises many groups in a small
    // image. Defaults still emit a 64-byte descriptor on modern e2fsprogs.
    Variant {
        tag: "1k_default",
        size_bytes: 64 * 1024 * 1024,
        block_size: 1024,
        features: "",
    },
    // No journal — the bitmap csum logic is journal-agnostic but exercising
    // `^has_journal` keeps the test honest about flag-independent behavior.
    Variant {
        tag: "4k_nojournal",
        size_bytes: 64 * 1024 * 1024,
        block_size: 4096,
        features: "^has_journal",
    },
    // Force legacy 32-byte descriptors so the csum value APIs prove their
    // low-16-bit truncation path against a kernel-written image.
    Variant {
        tag: "4k_no64bit",
        size_bytes: 64 * 1024 * 1024,
        block_size: 4096,
        features: "^has_journal,^64bit",
    },
];

fn create_image(variant: &Variant) -> PathBuf {
    let path = unique_temp_path(variant.tag);
    let f = std::fs::File::create(&path).expect("create image file");
    f.set_len(variant.size_bytes).expect("set image length");
    drop(f);
    let block_size = variant.block_size.to_string();
    let mut cmd = Command::new("mkfs.ext4");
    cmd.args(["-q", "-F", "-b", &block_size]);
    if !variant.features.is_empty() {
        cmd.args(["-O", variant.features]);
    }
    cmd.arg(&path);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let st = cmd.status().expect("spawn mkfs.ext4");
    assert!(
        st.success(),
        "mkfs.ext4 failed for variant {} (size={}, block_size={}, features='{}')",
        variant.tag,
        variant.size_bytes,
        variant.block_size,
        variant.features
    );
    path
}

#[derive(Debug, Default)]
struct VerifyStats {
    groups_checked: usize,
    block_csums_verified: usize,
    inode_csums_verified: usize,
    #[allow(dead_code)] // visible in panic-time Debug formatting only
    block_csums_skipped_uninit: usize,
    #[allow(dead_code)] // visible in panic-time Debug formatting only
    inode_csums_skipped_uninit: usize,
    desc_size_observed: u16,
    block_size_observed: u32,
}

fn verify_all_groups(image: &[u8]) -> VerifyStats {
    let reader = Ext4ImageReader::new(image).expect("parse ext4 image");
    let sb = &reader.sb;
    let csum_seed = sb.csum_seed();
    let desc_size = sb.group_desc_size();
    let groups_count = sb.groups_count();

    let mut stats = VerifyStats {
        desc_size_observed: desc_size,
        block_size_observed: sb.block_size,
        ..VerifyStats::default()
    };

    for raw in 0..groups_count {
        let group = GroupNumber(raw);
        let gd = reader
            .read_group_desc(image, group)
            .unwrap_or_else(|err| panic!("read group desc {raw}: {err:?}"));

        // Block bitmap. The kernel does not stamp a CRC into uninitialised
        // bitmaps (BG_BLOCK_UNINIT), so checking those would compare the
        // CRC of arbitrary-content disk space against a literal 0.
        if gd.flags & BG_BLOCK_UNINIT == 0 {
            let block_bitmap = reader
                .read_block(image, BlockNumber(gd.block_bitmap))
                .unwrap_or_else(|err| panic!("read block bitmap for group {raw}: {err:?}"));
            verify_block_bitmap_checksum(
                block_bitmap,
                csum_seed,
                sb.clusters_per_group,
                &gd,
                desc_size,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "verify_block_bitmap_checksum failed for group {raw} (csum_seed={:#x}, \
                     clusters_per_group={}, stored={:#010x}): {err:?}",
                    csum_seed, sb.clusters_per_group, gd.block_bitmap_csum
                );
            });
            // Recompute with the value-only API and confirm it matches the
            // truncated form of the stored csum on 32-byte descriptors and
            // the full form on 64-byte descriptors.
            let recomputed = block_bitmap_checksum_value(
                block_bitmap,
                csum_seed,
                sb.clusters_per_group,
                desc_size,
            );
            let stored_truncated = if desc_size >= 64 {
                gd.block_bitmap_csum
            } else {
                gd.block_bitmap_csum & 0xFFFF
            };
            assert_eq!(
                recomputed, stored_truncated,
                "block_bitmap_csum: recomputed value diverged from stored for group {raw} \
                 (desc_size={desc_size})"
            );
            stats.block_csums_verified += 1;
        } else {
            stats.block_csums_skipped_uninit += 1;
        }

        // Inode bitmap — same UNINIT semantics.
        if gd.flags & BG_INODE_UNINIT == 0 {
            let inode_bitmap = reader
                .read_block(image, BlockNumber(gd.inode_bitmap))
                .unwrap_or_else(|err| panic!("read inode bitmap for group {raw}: {err:?}"));
            verify_inode_bitmap_checksum(
                inode_bitmap,
                csum_seed,
                sb.inodes_per_group,
                &gd,
                desc_size,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "verify_inode_bitmap_checksum failed for group {raw} (csum_seed={:#x}, \
                     inodes_per_group={}, stored={:#010x}): {err:?}",
                    csum_seed, sb.inodes_per_group, gd.inode_bitmap_csum
                );
            });
            let recomputed = inode_bitmap_checksum_value(
                inode_bitmap,
                csum_seed,
                sb.inodes_per_group,
                desc_size,
            );
            let stored_truncated = if desc_size >= 64 {
                gd.inode_bitmap_csum
            } else {
                gd.inode_bitmap_csum & 0xFFFF
            };
            assert_eq!(
                recomputed, stored_truncated,
                "inode_bitmap_csum: recomputed value diverged from stored for group {raw} \
                 (desc_size={desc_size})"
            );
            stats.inode_csums_verified += 1;
        } else {
            stats.inode_csums_skipped_uninit += 1;
        }

        stats.groups_checked += 1;
    }

    stats
}

#[test]
fn ext4_bitmap_csum_kernel_reference() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let mut total_groups = 0_usize;
    let mut total_block_csums = 0_usize;
    let mut total_inode_csums = 0_usize;
    let mut saw_4k = false;
    let mut saw_1k = false;
    let mut saw_desc32 = false;
    let mut saw_desc64 = false;

    for variant in VARIANTS {
        let path = create_image(variant);
        let image = std::fs::read(&path).expect("read image");
        let stats = verify_all_groups(&image);

        // Independent witness — e2fsck's bitmap-csum check exits non-zero
        // if any csum is bad. This catches the case where ffs's CRC and the
        // kernel's CRC happen to share the same bug.
        let st = Command::new("e2fsck")
            .args(["-fn"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn e2fsck");
        assert_eq!(
            st.code().unwrap_or(-1),
            0,
            "e2fsck disagreed with the on-disk bitmap csums for variant {}",
            variant.tag,
        );

        total_groups += stats.groups_checked;
        total_block_csums += stats.block_csums_verified;
        total_inode_csums += stats.inode_csums_verified;
        if stats.block_size_observed == 4096 {
            saw_4k = true;
        }
        if stats.block_size_observed == 1024 {
            saw_1k = true;
        }
        if stats.desc_size_observed == 32 {
            saw_desc32 = true;
        }
        if stats.desc_size_observed >= 64 {
            saw_desc64 = true;
        }

        std::fs::remove_file(&path).ok();
    }

    assert!(
        total_groups >= 2,
        "expected at least two groups across the corpus, got {total_groups}"
    );
    assert!(
        total_block_csums >= 1,
        "at least one group must have an initialised block bitmap that we verified"
    );
    assert!(
        total_inode_csums >= 1,
        "at least one group must have an initialised inode bitmap that we verified"
    );
    assert!(
        saw_4k && saw_1k,
        "expected both 4 KiB and 1 KiB block geometries"
    );
    assert!(
        saw_desc32 && saw_desc64,
        "expected both 32-byte and 64-byte group descriptor widths"
    );
}
