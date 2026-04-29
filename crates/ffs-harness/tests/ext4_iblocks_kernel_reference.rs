//! Conformance harness: ext4 `i_blocks` (the "Blockcount" field that
//! `debugfs stat` prints) read by ffs-ondisk must match the value
//! e2fsprogs and the kernel record for the same inode.
//!
//! `i_blocks` counts how many 512-byte sectors are charged to an inode —
//! a quantity that includes data blocks and any external extent /
//! indirect-block overhead, while excluding the inode block itself. Fast
//! symlinks (target stored in `i_block`) report 0; ordinary files report
//! `(allocated_data_blocks + extent_overhead) * (block_size / 512)`. The
//! field is the source of truth for `stat(2).st_blocks` — a regression
//! that misreads it would silently corrupt every "du -k" / "ls -s" call
//! a downstream caller makes.
//!
//! ffs has unit-test coverage of the inode parser but no end-to-end pin
//! against the kernel/e2fsprogs view of `i_blocks`. The existing
//! `kernel_reference` harness compares mode, size, links, mtime/ctime
//! and timestamps but never reads back this accounting field.
//!
//! Strategy: stage a corpus that covers the meaningful shapes —
//! a 0-byte file, a 1-byte file (forces one block of allocation),
//! a multi-block file (8 contiguous blocks via one inline extent),
//! a directory (a single 4 KiB block), a fast symlink (no blocks),
//! and an extent-mapped symlink (one data block) — then assert
//! `Ext4Inode.blocks == debugfs's Blockcount` byte-for-byte.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ffs_ondisk::Ext4ImageReader;

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
    std::env::temp_dir().join(format!("ffs_iblocks_{tag}_{pid}_{nanos}.ext4"))
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

/// Capture `Blockcount: N` from `debugfs stat <path>`.
///
/// e2fsprogs prints the field on the same line as `Links: N` in a stable
/// `Links: <n>   Blockcount: <m>` format, with the value in 512-byte
/// sector units.
fn capture_blockcount(image: &Path, file: &str) -> u64 {
    let out = Command::new("debugfs")
        .args(["-R", &format!("stat {file}")])
        .arg(image)
        .stderr(Stdio::null())
        .output()
        .expect("spawn debugfs");
    assert!(out.status.success(), "debugfs stat {file} failed");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    for line in text.lines() {
        if let Some(rest) = line.split("Blockcount:").nth(1) {
            let token = rest
                .split_whitespace()
                .next()
                .unwrap_or_else(|| panic!("malformed Blockcount line: {line}"));
            return token
                .parse()
                .unwrap_or_else(|e| panic!("non-numeric Blockcount '{token}': {e}"));
        }
    }
    panic!("debugfs stat {file}: no Blockcount line in:\n{text}")
}

#[derive(Debug, Clone, Copy)]
enum CaseKind {
    /// Empty regular file: zero size and zero charged sectors.
    EmptyFile,
    /// Regular file with content — staged via `debugfs write`.
    File { content_bytes: usize },
    /// Sparse file: write `prefix_bytes` of content, then `sif size` to extend.
    SparseFile {
        prefix_bytes: usize,
        final_size: u64,
    },
    /// Symlink staged via `debugfs symlink`.
    Symlink { target_len: usize },
    /// Empty directory created via `debugfs mkdir`.
    Directory,
}

#[derive(Debug, Clone)]
struct Case {
    name: &'static str,
    kind: CaseKind,
}

fn corpus() -> Vec<Case> {
    vec![
        // Zero-byte regular file: no data or metadata extent blocks should be
        // charged to i_blocks, distinct from the zero-block fast symlink case.
        Case {
            name: "empty_regular_file",
            kind: CaseKind::EmptyFile,
        },
        // 1-byte file: smallest allocation that still costs one data block
        // (Blockcount = 8 sectors on 4 KiB FS).
        Case {
            name: "tiny_file",
            kind: CaseKind::File { content_bytes: 1 },
        },
        // 4 KiB file: exactly one block, no extent-tree overhead.
        Case {
            name: "one_block_file",
            kind: CaseKind::File {
                content_bytes: 4096,
            },
        },
        // 32 KiB file: 8 contiguous blocks via one inline extent header,
        // no external extent block (Blockcount = 64 sectors).
        Case {
            name: "eight_block_contiguous_file",
            kind: CaseKind::File {
                content_bytes: 32 * 1024,
            },
        },
        // Sparse file: 4 KiB content extended to 16 KiB via `sif size`.
        // Only the first block is allocated, so Blockcount = 8 sectors
        // even though i_size == 16 KiB.
        Case {
            name: "sparse_one_block_three_block_hole",
            kind: CaseKind::SparseFile {
                prefix_bytes: 4096,
                final_size: 16 * 1024,
            },
        },
        // Fast symlink (≤ 60 bytes) — target lives in `i_block`, no data
        // block allocated, Blockcount = 0.
        Case {
            name: "fast_symlink",
            kind: CaseKind::Symlink { target_len: 16 },
        },
        // Extent-mapped symlink (> 60 bytes) — one allocated data block,
        // Blockcount = 8 sectors.
        Case {
            name: "extent_symlink",
            kind: CaseKind::Symlink { target_len: 200 },
        },
        // Directory: 4 KiB single-block dir, Blockcount = 8.
        Case {
            name: "small_directory",
            kind: CaseKind::Directory,
        },
    ]
}

fn stage_case(image: &Path, scratch: &Path, case: &Case) {
    match case.kind {
        CaseKind::EmptyFile => {
            // `debugfs write` creates regular files, but it refuses an empty
            // native source file. Seed one byte, deallocate from logical
            // block 0, then force i_size back to zero so the final inode is a
            // true empty regular file.
            let local = scratch.join(format!("{}.bin", case.name));
            std::fs::write(&local, [0_u8]).expect("write empty-file seed");
            run_debugfs_w(image, &format!("write {} /{}", local.display(), case.name));
            run_debugfs_w(image, &format!("punch /{} 0", case.name));
            run_debugfs_w(image, &format!("sif /{} size 0", case.name));
        }
        CaseKind::File { content_bytes } => {
            let content = vec![b'F'; content_bytes];
            let local = scratch.join(format!("{}.bin", case.name));
            std::fs::write(&local, &content).expect("write content");
            run_debugfs_w(image, &format!("write {} /{}", local.display(), case.name));
        }
        CaseKind::SparseFile {
            prefix_bytes,
            final_size,
        } => {
            let local = scratch.join(format!("{}.bin", case.name));
            std::fs::write(&local, vec![b'S'; prefix_bytes]).expect("write prefix");
            run_debugfs_w(image, &format!("write {} /{}", local.display(), case.name));
            run_debugfs_w(image, &format!("sif /{} size {}", case.name, final_size));
        }
        CaseKind::Symlink { target_len } => {
            // ASCII-only target so `debugfs symlink` (which space-splits its
            // argv) accepts it as a single token.
            let target = "x".repeat(target_len);
            run_debugfs_w(image, &format!("symlink /{} {target}", case.name));
        }
        CaseKind::Directory => {
            run_debugfs_w(image, &format!("mkdir /{}", case.name));
        }
    }
}

#[test]
fn ext4_iblocks_kernel_reference_matches_debugfs_blockcount() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let path = unique_path("corpus");
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

    let scratch = std::env::temp_dir().join(format!(
        "ffs_iblocks_stage_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&scratch).expect("create scratch dir");

    let cases = corpus();
    for case in &cases {
        stage_case(&path, &scratch, case);
    }
    std::fs::remove_dir_all(&scratch).ok();

    let image = std::fs::read(&path).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse image");

    let mut saw_zero_blockcount = false;
    let mut saw_nonzero_blockcount = false;
    for case in &cases {
        let path_str = format!("/{}", case.name);
        let kernel_blockcount = capture_blockcount(&path, case.name);
        let (_ino, inode) = reader
            .resolve_path(&image, &path_str)
            .unwrap_or_else(|err| panic!("resolve {path_str}: {err:?}"));
        if matches!(case.kind, CaseKind::EmptyFile) {
            assert!(
                inode.is_regular(),
                "/{}: empty corpus case should remain a regular file, mode={:o}",
                case.name,
                inode.mode,
            );
            assert_eq!(
                inode.size, 0,
                "/{}: empty file should have i_size 0",
                case.name
            );
        }
        assert_eq!(
            inode.blocks, kernel_blockcount,
            "/{}: ffs Ext4Inode.blocks ({}) != debugfs Blockcount ({})",
            case.name, inode.blocks, kernel_blockcount
        );
        if kernel_blockcount == 0 {
            saw_zero_blockcount = true;
        } else {
            saw_nonzero_blockcount = true;
        }
    }

    // Cross-corpus invariants: at least one case where Blockcount is 0
    // (fast symlink) and at least one where it's non-zero (any allocated
    // file/dir/extent symlink). A future cleanup that drops one or the
    // other shape silently weakens coverage.
    assert!(
        saw_zero_blockcount,
        "expected at least one case with Blockcount = 0 (fast symlink)"
    );
    assert!(
        saw_nonzero_blockcount,
        "expected at least one case with Blockcount > 0"
    );

    std::fs::remove_file(&path).ok();
}
