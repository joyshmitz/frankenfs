//! Conformance harness: ext4 `i_flags`, `i_uid`, `i_gid`, and the
//! permission bits of `i_mode` parsed by ffs-ondisk must match what
//! `debugfs stat` reports for the same inode.
//!
//! These four fields control behaviors that surface directly through
//! `stat(2)` and POSIX semantics:
//!
//!   * `i_flags` (32 bits, `EXT4_*_FL`): IMMUTABLE, APPEND_ONLY,
//!     NOATIME, EXTENTS, INDEX, … — a regression here would silently
//!     drop chattr-style protections on disk.
//!   * `i_uid` / `i_gid` (split lo/hi halves under `EXT4_FEATURE_RO_COMPAT_LARGE_FILE`,
//!     plus uid_hi / gid_hi at ext4 inode bytes 0x74 / 0x72): a
//!     regression would mis-report file ownership to every consumer of
//!     `stat`.
//!   * `i_mode` permission bits (the low 12 bits — rwxrwxrwx plus
//!     setuid / setgid / sticky): the existing kernel_reference checks
//!     only the file-type portion of mode (top 4 bits) via
//!     `ext4_file_type_str`; the permission half had no end-to-end pin.
//!
//! `debugfs stat` prints all four on stable lines:
//!     `Inode: N   Type: ...   Mode:  0NNNN   Flags: 0xNNNNNNNN`
//!     `User:  N   Group:  N   Project:  N   Size: N`
//!
//! ffs has unit-test coverage of the inode parser and a
//! `set_inode_field`-driven test in `ffs-ext4/tests/ioctl_setflags.rs`,
//! but no end-to-end pin against e2fsprogs's view across non-default
//! flag/uid/gid combinations or the high half of the 32-bit uid/gid
//! split. Cover that surface here.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ffs_ondisk::Ext4ImageReader;

const MODE_PERMISSION_MASK: u16 = 0o7777;

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
    std::env::temp_dir().join(format!("ffs_inode_meta_{tag}_{pid}_{nanos}.ext4"))
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

#[derive(Debug, Default)]
struct StatFields {
    mode: u16,
    flags: u32,
    uid: u32,
    gid: u32,
}

/// Parse the four fields we care about out of `debugfs stat <path>`.
///
/// e2fsprogs prints them on two header lines in a stable layout:
///   Inode: N   Type: T   Mode:  0NNNN   Flags: 0xNNNNNNNN
///   User:  N   Group:  N   Project:  N   Size: N
fn capture_stat(image: &Path, file: &str) -> StatFields {
    let out = Command::new("debugfs")
        .args(["-R", &format!("stat {file}")])
        .arg(image)
        .stderr(Stdio::null())
        .output()
        .expect("spawn debugfs");
    assert!(out.status.success(), "debugfs stat {file} failed");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();

    let mut fields = StatFields::default();
    let mut saw_mode = false;
    let mut saw_flags = false;
    let mut saw_user = false;
    let mut saw_group = false;
    for line in text.lines() {
        if let Some(token) = field_after(line, "Mode:") {
            // "0NNNN" — parse as octal, mask to permission bits + type.
            let no_prefix = token.strip_prefix('0').unwrap_or(token);
            let parsed = u32::from_str_radix(no_prefix, 8)
                .unwrap_or_else(|e| panic!("non-octal Mode '{token}': {e}"));
            fields.mode = u16::try_from(parsed).expect("mode fits u16");
            saw_mode = true;
        }
        if let Some(token) = field_after(line, "Flags:") {
            let no_prefix = token.trim_start_matches("0x").trim_start_matches("0X");
            fields.flags = u32::from_str_radix(no_prefix, 16)
                .unwrap_or_else(|e| panic!("non-hex Flags '{token}': {e}"));
            saw_flags = true;
        }
        if let Some(token) = field_after(line, "User:") {
            fields.uid = parse_signed_or_unsigned_u32(token, "User");
            saw_user = true;
        }
        if let Some(token) = field_after(line, "Group:") {
            fields.gid = parse_signed_or_unsigned_u32(token, "Group");
            saw_group = true;
        }
    }
    assert!(
        saw_mode && saw_flags && saw_user && saw_group,
        "debugfs stat {file} missing one of Mode/Flags/User/Group lines:\n{text}"
    );
    fields
}

/// Return the first whitespace-delimited token following `needle:` on `line`.
fn field_after<'a>(line: &'a str, needle: &str) -> Option<&'a str> {
    let after = line.split(needle).nth(1)?;
    after.split_whitespace().next()
}

/// Parse a uid/gid token from `debugfs stat`, accepting both unsigned
/// decimal and the signed form e2fsprogs emits when the value exceeds
/// `i32::MAX` (e.g., `Group: -65535` for gid `0xFFFF_0001`).
fn parse_signed_or_unsigned_u32(token: &str, label: &str) -> u32 {
    if let Ok(unsigned) = token.parse::<u32>() {
        return unsigned;
    }
    let signed: i64 = token
        .parse()
        .unwrap_or_else(|e| panic!("non-numeric {label} '{token}': {e}"));
    if signed >= 0 {
        u32::try_from(signed).unwrap_or_else(|_| panic!("{label} '{token}' out of u32 range"))
    } else {
        // debugfs cast a `u32 > i32::MAX` to signed. Reinterpret the bit
        // pattern by going through u32::from_le_bytes(i32::to_le_bytes(_)).
        let truncated = i32::try_from(signed)
            .unwrap_or_else(|_| panic!("{label} '{token}' outside i32 range too"));
        u32::from_le_bytes(truncated.to_le_bytes())
    }
}

#[derive(Debug, Clone, Copy)]
struct Mutation {
    /// Override `i_flags` to this exact value (None = leave debugfs default).
    flags: Option<u32>,
    /// Override `i_uid` (the full 32 bits — debugfs splits into hi/lo).
    uid: Option<u32>,
    /// Override `i_gid` (full 32 bits).
    gid: Option<u32>,
    /// Override mode (full 16 bits including type bits).
    mode: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
struct Case {
    name: &'static str,
    mutation: Mutation,
}

fn corpus() -> Vec<Case> {
    let none = Mutation {
        flags: None,
        uid: None,
        gid: None,
        mode: None,
    };
    vec![
        // Default: only the EXTENTS_FL bit that mkfs.ext4 sets on a file
        // staged via debugfs.
        Case {
            name: "defaults",
            mutation: none,
        },
        // chattr +ai: APPEND_ONLY (0x20) | IMMUTABLE (0x10) — the most
        // commonly-set policy bits — alongside the EXTENTS bit.
        Case {
            name: "append_immutable",
            mutation: Mutation {
                flags: Some(0x80000 | 0x20 | 0x10),
                ..none
            },
        },
        // High-bit + low-bit flags simultaneously: HUGE_FILE (0x40000)
        // exercises the upper byte alongside the EXTENTS bit, which a
        // u32 truncated to u16 would silently drop.
        Case {
            name: "huge_extents",
            mutation: Mutation {
                flags: Some(0x80000 | 0x40000),
                ..none
            },
        },
        // 16-bit uid/gid (fits in i_uid_lo / i_gid_lo on its own).
        Case {
            name: "uid_gid_lo",
            mutation: Mutation {
                uid: Some(1234),
                gid: Some(5678),
                ..none
            },
        },
        // 32-bit uid that requires i_uid_hi: a regression that ignores
        // the high half (split at offset 0x74 in the inode) would round
        // this to 1234 only.
        Case {
            name: "uid_uses_hi_half",
            mutation: Mutation {
                uid: Some(0x0001_2345),
                gid: Some(0xFFFF_0001),
                ..none
            },
        },
        // u32::MAX uid/gid — the largest value the field can hold,
        // boundary case for the lo/hi reassembly.
        Case {
            name: "uid_gid_u32_max",
            mutation: Mutation {
                uid: Some(u32::MAX),
                gid: Some(u32::MAX),
                ..none
            },
        },
        // Permission bits 0o755 (the existing kernel_reference only
        // verified the type half of mode via ext4_file_type_str).
        Case {
            name: "mode_0755",
            // ext4 stores type|perms in i_mode; 0o100000 = S_IFREG.
            mutation: Mutation {
                mode: Some(0o100_755),
                ..none
            },
        },
        // setuid + setgid + sticky on a regular file — checks that the
        // top three permission bits round-trip too (they live above
        // 0o777 and a u9-truncated parser would lose them).
        Case {
            name: "setuid_setgid_sticky",
            mutation: Mutation {
                mode: Some(0o100_000 | 0o7_755),
                ..none
            },
        },
    ]
}

#[test]
#[allow(clippy::too_many_lines)]
fn ext4_inode_flags_uidgid_kernel_reference_matches_debugfs() {
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
        "ffs_inode_meta_stage_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&scratch).expect("create scratch dir");

    let cases = corpus();
    for case in &cases {
        // Stage as a 1-byte regular file, then optionally mutate fields.
        let local = scratch.join(format!("{}.bin", case.name));
        std::fs::write(&local, *b"F").expect("write seed");
        run_debugfs_w(&path, &format!("write {} /{}", local.display(), case.name));
        if let Some(flags) = case.mutation.flags {
            run_debugfs_w(
                &path,
                &format!("set_inode_field /{} flags {:#010x}", case.name, flags),
            );
        }
        if let Some(uid) = case.mutation.uid {
            run_debugfs_w(&path, &format!("set_inode_field /{} uid {uid}", case.name));
        }
        if let Some(gid) = case.mutation.gid {
            run_debugfs_w(&path, &format!("set_inode_field /{} gid {gid}", case.name));
        }
        if let Some(mode) = case.mutation.mode {
            // debugfs's set_inode_field parses C-style octal (leading `0`).
            // The Rust `{:#o}` prefix is `0o…`, which debugfs misreads as
            // hex-or-malformed and silently leaves the mode untouched.
            run_debugfs_w(
                &path,
                &format!("set_inode_field /{} mode 0{mode:o}", case.name),
            );
        }
    }
    std::fs::remove_dir_all(&scratch).ok();

    let image = std::fs::read(&path).expect("read image");
    let reader = Ext4ImageReader::new(&image).expect("parse image");

    let mut saw_uid_hi_half = false;
    let mut saw_high_flag_bit = false;
    let mut saw_setuid_setgid_sticky = false;
    for case in &cases {
        let path_str = format!("/{}", case.name);
        let kernel = capture_stat(&path, case.name);
        let (_ino, inode) = reader
            .resolve_path(&image, &path_str)
            .unwrap_or_else(|err| panic!("resolve {path_str}: {err:?}"));

        // i_flags must match the entire 32-bit field.
        assert_eq!(
            inode.flags, kernel.flags,
            "/{}: ffs i_flags {:#010x} != debugfs {:#010x}",
            case.name, inode.flags, kernel.flags
        );

        // uid / gid must match across both lo and hi halves.
        assert_eq!(
            inode.uid, kernel.uid,
            "/{}: ffs uid {} != debugfs {}",
            case.name, inode.uid, kernel.uid
        );
        assert_eq!(
            inode.gid, kernel.gid,
            "/{}: ffs gid {} != debugfs {}",
            case.name, inode.gid, kernel.gid
        );

        // i_mode permission bits — the bottom 12 bits, separate from the
        // type half kernel_reference already pins.
        let ffs_perm = inode.mode & MODE_PERMISSION_MASK;
        let kernel_perm = kernel.mode & MODE_PERMISSION_MASK;
        assert_eq!(
            ffs_perm, kernel_perm,
            "/{}: ffs mode permission bits {:o} != debugfs {:o}",
            case.name, ffs_perm, kernel_perm
        );

        if kernel.uid > u32::from(u16::MAX) || kernel.gid > u32::from(u16::MAX) {
            saw_uid_hi_half = true;
        }
        if kernel.flags & 0xFFFF_0000 != 0 {
            saw_high_flag_bit = true;
        }
        if kernel_perm & 0o7000 != 0 {
            saw_setuid_setgid_sticky = true;
        }
    }

    // Cross-corpus invariants: a future cleanup that drops the high-half
    // uid case, the upper-byte flag case, or the setuid/setgid/sticky
    // case silently weakens this test, so make the floors explicit.
    assert!(
        saw_uid_hi_half,
        "expected at least one case with uid or gid > u16::MAX (covers i_uid_hi/i_gid_hi)"
    );
    assert!(
        saw_high_flag_bit,
        "expected at least one case with i_flags upper-half bits set (covers full u32 width)"
    );
    assert!(
        saw_setuid_setgid_sticky,
        "expected at least one case with setuid/setgid/sticky bits set"
    );

    std::fs::remove_file(&path).ok();
}
