//! Conformance harness: sparse-file reads via
//! `Ext4ImageReader::read_inode_data` must zero-fill holes the same way
//! e2fsprogs (`debugfs dump`) does — which is what the kernel's read path
//! produces on `ext4(5)` for the same inode.
//!
//! ext4 represents trailing or interior holes as gaps in the extent map:
//! `i_size` advertises the logical EOF, but no extent covers the hole's
//! logical-block range. The kernel returns zeros for those bytes; ffs must
//! match that contract or callers will see undefined data when they read
//! past the last allocated extent. The reader's hole-handling code path
//! has unit-test coverage but no end-to-end pin against an image written
//! by something other than ffs itself.
//!
//! Strategy:
//!   1. Stage a corpus of sparse files via `debugfs write` followed by
//!      `debugfs sif <path> size <N>` to extend i_size past the allocated
//!      data without writing additional blocks. This is the standard way
//!      e2fsprogs creates a trailing hole.
//!   2. For every staged file, capture the kernel's view via
//!      `debugfs dump` (which zero-fills holes during read), and the FFS
//!      view via `Ext4ImageReader::read_inode_data` over the full
//!      `i_size`. Assert byte-for-byte equality.
//!   3. Also sample a partial read straddling the content/hole boundary
//!      so a regression where the reader returns stale buffer content
//!      past the last allocated extent is caught.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ffs_ondisk::Ext4ImageReader;

fn has_command(name: &str) -> bool {
    Command::new(name)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn ext4_tools_available() -> bool {
    has_command("mkfs.ext4") && has_command("debugfs")
}

fn unique_path(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("ffs_sparse_{tag}_{pid}_{nanos}.ext4"))
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

fn dump_via_debugfs(image: &Path, file: &str) -> Vec<u8> {
    let scratch = std::env::temp_dir().join(format!(
        "ffs_sparse_dump_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
        file.replace('/', "_"),
    ));
    let st = Command::new("debugfs")
        .args(["-R", &format!("dump {file} {}", scratch.display())])
        .arg(image)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn debugfs");
    assert!(st.success(), "debugfs dump {file} failed");
    let bytes = std::fs::read(&scratch).expect("read dumped file");
    std::fs::remove_file(&scratch).ok();
    bytes
}

#[derive(Debug, Clone)]
struct SparseCase {
    /// File name (no leading `/`).
    name: &'static str,
    /// Bytes the staged file contains before the trailing hole.
    content: Vec<u8>,
    /// Final i_size to set via `debugfs sif`.
    final_size: u64,
}

fn corpus() -> Vec<SparseCase> {
    vec![
        // Tiny content, large trailing hole (one block of hole).
        SparseCase {
            name: "tiny_then_one_block_hole",
            content: b"HELLO".to_vec(),
            final_size: 4096,
        },
        // Tiny content extended past block boundary — hole spans the
        // remainder of the first block plus a full second block.
        SparseCase {
            name: "tiny_across_block_boundary",
            content: b"first-block-fragment\n".to_vec(),
            final_size: 8192,
        },
        // One full block of content followed by two blocks of hole.
        SparseCase {
            name: "one_block_then_two_block_hole",
            content: vec![b'A'; 4096],
            final_size: 12288,
        },
        // Heterogeneous content fill so a byte-substitution regression
        // (e.g., XOR with stale buffer state) cannot hide.
        SparseCase {
            name: "heterogeneous_then_hole",
            content: (0..200u32)
                .map(|i| u8::try_from(33 + (i % 90)).expect("printable"))
                .collect(),
            final_size: 4096 + 1024,
        },
        // Boundary just past the end of the first block (1 byte of hole).
        SparseCase {
            name: "one_byte_hole_after_block",
            content: vec![b'B'; 4096],
            final_size: 4097,
        },
        // 4 blocks of content + 12 blocks of hole = 64 KiB total.
        SparseCase {
            name: "large_trailing_hole",
            content: vec![b'C'; 4 * 4096],
            final_size: 16 * 4096,
        },
    ]
}

// One long test body intentionally: the sequence of mkfs / debugfs
// staging / per-case dump+read+compare reads top-to-bottom as the spec
// of "FFS reads sparse files exactly like the kernel does." Splitting
// the per-case loop into a helper would just shuffle the same control
// flow through an accessor.
#[allow(clippy::too_many_lines)]
#[test]
fn ext4_sparse_read_kernel_reference_zero_fills_holes() {
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

    // Stage every sparse case: write content via debugfs, then sif size up.
    let scratch_dir = std::env::temp_dir().join(format!(
        "ffs_sparse_stage_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&scratch_dir).expect("create scratch dir");

    let cases = corpus();
    for case in &cases {
        let local = scratch_dir.join(format!("{}.bin", case.name));
        std::fs::write(&local, &case.content).expect("write staged content");
        run_debugfs_w(&path, &format!("write {} /{}", local.display(), case.name));
        run_debugfs_w(
            &path,
            &format!("sif /{} size {}", case.name, case.final_size),
        );
    }
    std::fs::remove_dir_all(&scratch_dir).ok();

    let image = std::fs::read(&path).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse image");

    let mut total_bytes_compared = 0_u64;
    for case in &cases {
        let kernel_bytes = dump_via_debugfs(&path, case.name);
        assert_eq!(
            u64::try_from(kernel_bytes.len()).expect("dump len fits u64"),
            case.final_size,
            "/{}: debugfs dump length {} != final_size {}",
            case.name,
            kernel_bytes.len(),
            case.final_size,
        );

        // Sanity: the leading content matches what we wrote, and the tail
        // is all zero. A failure here means the staging itself didn't
        // produce the expected geometry, so the rest of the test would be
        // meaningless.
        let leading = &kernel_bytes[..case.content.len().min(kernel_bytes.len())];
        assert_eq!(
            leading,
            case.content.as_slice(),
            "/{}: staged leading content mismatch",
            case.name
        );
        for (offset, byte) in kernel_bytes.iter().enumerate().skip(case.content.len()) {
            assert_eq!(
                *byte, 0,
                "/{}: kernel-dumped byte at offset {} should be 0",
                case.name, offset
            );
        }

        let path_str = format!("/{}", case.name);
        let (_ino, inode) = reader
            .resolve_path(&image, &path_str)
            .unwrap_or_else(|err| panic!("resolve {path_str}: {err:?}"));
        assert_eq!(
            inode.size, case.final_size,
            "/{}: ffs i_size {} != case final_size {}",
            case.name, inode.size, case.final_size
        );

        // Full-file read through the FFS reader. Pre-fill the buffer with a
        // recognisable poison byte so a partial-write regression (reader
        // returns N < buf.len()) is visible against the ground truth.
        let final_size_usize = usize::try_from(case.final_size).expect("size fits");
        let mut full = vec![0xCC_u8; final_size_usize];
        let n = reader
            .read_inode_data(&image, &inode, 0, &mut full)
            .unwrap_or_else(|err| panic!("read_inode_data /{}: {err:?}", case.name));
        assert_eq!(
            n,
            full.len(),
            "/{}: read_inode_data returned {} bytes, expected {}",
            case.name,
            n,
            full.len()
        );
        assert_eq!(
            full, kernel_bytes,
            "/{}: read_inode_data full read diverged from debugfs dump",
            case.name
        );

        // Boundary-straddling read: 16 bytes spanning the last 8 bytes of
        // content through the first 8 bytes of hole. Catches regressions
        // where the reader returns stale buffer content past the allocated
        // extent or zero-fills too eagerly.
        if case.content.len() >= 8 && case.content.len() + 8 <= final_size_usize {
            let start = u64::try_from(case.content.len() - 8).expect("offset");
            let mut window = [0xCC_u8; 16];
            let m = reader
                .read_inode_data(&image, &inode, start, &mut window)
                .unwrap_or_else(|err| panic!("boundary read /{}: {err:?}", case.name));
            assert_eq!(m, 16, "/{}: boundary read returned {m} bytes", case.name);
            let expected = &kernel_bytes[case.content.len() - 8..case.content.len() + 8];
            assert_eq!(
                window.as_slice(),
                expected,
                "/{}: boundary read diverged from debugfs dump at content/hole transition",
                case.name
            );
        }

        total_bytes_compared += case.final_size;
    }

    // The corpus ranges from 4 KiB to 64 KiB. Make the floor explicit so
    // a future cleanup that accidentally shrinks the corpus to one tiny
    // case doesn't silently weaken coverage.
    assert!(
        total_bytes_compared >= 64 * 1024,
        "total bytes compared {total_bytes_compared} below corpus floor 64 KiB"
    );

    std::fs::remove_file(&path).ok();
}
