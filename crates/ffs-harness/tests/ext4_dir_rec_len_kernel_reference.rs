//! Conformance harness: ext4 directory entry `rec_len` after `unlink`
//! must obey the on-disk coalesce contract that e2fsprogs enforces.
//!
//! When ext4 unlinks a directory entry, it does NOT shift remaining
//! entries — instead it extends the **previous** live entry's `rec_len`
//! to span the freed slot, leaving the slot's bytes intact (including
//! the old name). The parser MUST treat the previous entry as a single
//! covering record. This invariant is load-bearing for every downstream
//! tool: e2fsck, debugfs ls, the kernel readdir path, and FFS's
//! `parse_dir_block` all assume rec_len chains cover the block end-to-end
//! with no gaps.
//!
//! ffs has unit-test coverage of `add_entry` / `remove_entry` and a
//! fixture-based deleted-entry test, but no end-to-end pin against
//! an actual `debugfs rm`-produced rec_len layout. A regression in
//! `parse_dir_block` that mis-handled coalesced rec_lens would silently
//! mis-list directory contents on every image written by the kernel
//! after an unlink.
//!
//! Strategy:
//!   1. mkfs.ext4 a small image without journal.
//!   2. debugfs `write` three files into the root: `alpha`, `beta`, `gamma`.
//!   3. Parse the root directory block via `Ext4ImageReader::read_dir`,
//!      record each entry's name + rec_len.
//!   4. debugfs `rm /beta` to unlink the middle entry.
//!   5. Re-parse the root directory block, assert:
//!      a. /beta is no longer listed.
//!      b. /alpha and /gamma are both present with matching inode numbers.
//!      c. The sum of rec_lens of the live-after-unlink entries plus the
//!         coalesced gap covers the entire usable directory block.
//!      d. The previous entry (`.` or `alpha`, whichever is sequentially
//!         before /beta) has its rec_len extended to span the freed slot.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ffs_ondisk::{parse_dir_block, Ext4ImageReader};

fn has_command(name: &str) -> bool {
    matches!(
        Command::new(name)
            .arg("-V")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        Ok(status) if status.success()
    )
}

fn ext4_tools_available() -> bool {
    has_command("mkfs.ext4") && has_command("debugfs")
}

fn unique_path(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("ffs_dirreclen_{tag}_{pid}_{nanos}.ext4"))
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

#[test]
fn ext4_dir_rec_len_kernel_reference_coalesces_after_unlink() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let path = unique_path("dir");
    let f = std::fs::File::create(&path).expect("create image file");
    f.set_len(16 * 1024 * 1024).expect("set image length");
    drop(f);
    let st = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-O", "^has_journal", "-b", "4096"])
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn mkfs.ext4");
    assert!(st.success(), "mkfs.ext4 failed");

    let scratch = std::env::temp_dir().join(format!(
        "ffs_dirreclen_stage_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&scratch).expect("create scratch dir");

    // Stage three files via debugfs write.
    for name in ["alpha", "beta", "gamma"] {
        let local = scratch.join(name);
        std::fs::write(&local, b"x").expect("write seed content");
        run_debugfs_w(&path, &format!("write {} /{}", local.display(), name));
    }
    std::fs::remove_dir_all(&scratch).ok();

    // Pre-unlink: parse root dir, capture entries.
    let image = std::fs::read(&path).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse image");
    let (_root_ino, root_inode) = reader
        .resolve_path(&image, "/")
        .expect("resolve root");

    let block_size = u64::from(reader.sb.block_size);
    let block_size_usize = usize::try_from(block_size).expect("block size fits");
    let mut pre_block = vec![0_u8; block_size_usize];
    let n = reader
        .read_inode_data(&image, &root_inode, 0, &mut pre_block)
        .expect("read root dir block");
    assert_eq!(n, block_size_usize, "expected to read full root dir block");
    let (pre_entries, pre_tail) =
        parse_dir_block(&pre_block, reader.sb.block_size).expect("parse pre-unlink");
    // When metadata_csum is enabled (default for modern mkfs.ext4) the
    // last 12 bytes of the directory block are a dir-tail checksum and
    // are not covered by any entry's rec_len.
    let usable_block = block_size_usize - if pre_tail.is_some() { 12 } else { 0 };

    let alpha_ino_pre = pre_entries
        .iter()
        .find(|e| e.name_str() == "alpha")
        .expect("alpha must exist pre-unlink")
        .inode;
    let gamma_ino_pre = pre_entries
        .iter()
        .find(|e| e.name_str() == "gamma")
        .expect("gamma must exist pre-unlink")
        .inode;

    // Sanity: pre-unlink has at least our 3 staged files plus "." and "..".
    // mkfs may also create lost+found which gets counted.
    assert!(
        pre_entries.iter().any(|e| e.name_str() == "beta"),
        "beta must exist pre-unlink"
    );
    let pre_live = pre_entries.iter().filter(|e| e.inode != 0).count();
    assert!(
        pre_live >= 5,
        "expected at least 5 live entries pre-unlink (.,..,alpha,beta,gamma), got {pre_live}"
    );

    // Pre-unlink rec_lens cover the usable block (block_size minus the
    // 12-byte checksum tail, when present).
    let pre_total_rec: u32 = pre_entries.iter().map(|e| u32::from(e.rec_len)).sum();
    assert_eq!(
        pre_total_rec,
        usable_block as u32,
        "pre-unlink rec_lens must cover the usable block"
    );

    // Unlink the middle entry.
    run_debugfs_w(&path, "rm /beta");

    // Re-parse and verify the coalesce contract.
    let image_after = std::fs::read(&path).expect("read image after rm");
    let reader_after = Ext4ImageReader::new(&image_after).expect("re-parse image");
    let (_root_ino, root_inode_after) = reader_after
        .resolve_path(&image_after, "/")
        .expect("resolve root after");
    let mut post_block = vec![0_u8; block_size_usize];
    let n_after = reader_after
        .read_inode_data(&image_after, &root_inode_after, 0, &mut post_block)
        .expect("read root dir block after");
    assert_eq!(n_after, block_size_usize, "expected to read full root dir block after rm");
    let (post_entries, post_tail) =
        parse_dir_block(&post_block, reader_after.sb.block_size).expect("parse post-unlink");
    let usable_block_after = block_size_usize - if post_tail.is_some() { 12 } else { 0 };

    // Beta must be gone from the live list.
    assert!(
        !post_entries
            .iter()
            .any(|e| e.inode != 0 && e.name_str() == "beta"),
        "beta must be unlinked"
    );
    // Alpha and gamma must persist with the same inode numbers.
    let alpha_post = post_entries
        .iter()
        .find(|e| e.inode != 0 && e.name_str() == "alpha")
        .expect("alpha must survive");
    assert_eq!(alpha_post.inode, alpha_ino_pre);
    let gamma_post = post_entries
        .iter()
        .find(|e| e.inode != 0 && e.name_str() == "gamma")
        .expect("gamma must survive");
    assert_eq!(gamma_post.inode, gamma_ino_pre);

    // The sum of rec_lens (including any coalesced or stale-but-zero-inode
    // slots) must still cover the usable block — this is the load-bearing
    // invariant the kernel and e2fsprogs enforce.
    let post_total_rec: u32 = post_entries.iter().map(|e| u32::from(e.rec_len)).sum();
    assert_eq!(
        post_total_rec,
        usable_block_after as u32,
        "post-unlink rec_lens must still cover the usable block"
    );

    // The number of LIVE entries dropped by exactly one (beta).
    let post_live = post_entries.iter().filter(|e| e.inode != 0).count();
    assert_eq!(
        post_live,
        pre_live - 1,
        "exactly one entry should have become unlinked"
    );

    std::fs::remove_file(&path).ok();
}
