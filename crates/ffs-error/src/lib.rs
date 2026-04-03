#![forbid(unsafe_code)]
//! Error types for FrankenFS.
//!
//! # Error Taxonomy
//!
//! FrankenFS uses a two-layer error model:
//!
//! | Layer | Type | Crate | Purpose |
//! |-------|------|-------|---------|
//! | Parsing | `ParseError` | `ffs-types` | On-disk format violations detected during byte parsing |
//! | Runtime | `FfsError` | `ffs-error` (this crate) | User-facing errors for FUSE, CLI, and API consumers |
//!
//! ## Mapping Policy: ParseError → FfsError
//!
//! `ffs-error` is intentionally independent of `ffs-types` and `ffs-ondisk` to
//! avoid cyclic dependencies. The conversion from `ParseError` to `FfsError` is
//! implemented in `ffs-core`, which depends on both crates.
//!
//! The mapping rules are:
//!
//! | ParseError Variant | FfsError Variant | Rationale |
//! |--------------------|------------------|-----------|
//! | `InsufficientData` | `Corruption { block, detail }` | Truncated metadata indicates corruption or a truncated image |
//! | `InvalidMagic` | `Format(detail)` | Wrong magic means wrong filesystem type, not corruption |
//! | `InvalidField` | `Format` / `UnsupportedFeature` / `IncompatibleFeature` / `UnsupportedBlockSize` / `InvalidGeometry` | `ffs-core` adds mount-validation context from field+reason |
//! | `IntegerConversion` | `Corruption { block, detail }` | Arithmetic overflow in parsed values suggests corruption |
//!
//! When a `ParseError` occurs during mount-time validation (before the
//! filesystem is live), prefer `FfsError::Format` with a descriptive message.
//! When it occurs while reading live metadata (e.g., reading an inode from a
//! mounted image), prefer `FfsError::Corruption` with the block number for
//! repair triage.
//!
//! ## Mount-Validation Errors
//!
//! Mount-time validation (`validate_v1()` in ffs-ondisk) can fail for five
//! distinct reasons, each with its own FfsError variant:
//!
//! | Failure | FfsError Variant | errno | Example |
//! |---------|------------------|-------|---------|
//! | Feature not supported by this build | `UnsupportedFeature` | `EOPNOTSUPP` | ENCRYPT, INLINE_DATA |
//! | Incompatible feature contract not met | `IncompatibleFeature` | `EOPNOTSUPP` | missing FILETYPE+EXTENTS, unknown incompat bits |
//! | Block size valid in ext4 but unsupported by FrankenFS v1 | `UnsupportedBlockSize` | `EOPNOTSUPP` | 8K ext4 image |
//! | Block size or geometry out of range | `InvalidGeometry` | `EINVAL` | 64K blocks, zero blocks_per_group |
//! | Structurally invalid format | `Format` | `EINVAL` | Bad magic, unknown revision |
//!
//! The `ffs-core` mount path converts `ParseError::InvalidField` from
//! `validate_v1()` into the appropriate variant by inspecting the field
//! name and reason. The parsing layer (`ffs-ondisk`) does not need to know
//! about `FfsError` — it returns `ParseError` and the boundary conversion
//! adds the mount-validation context.
//!
//! ## FUSE errno Mapping
//!
//! Every `FfsError` variant maps to exactly one POSIX errno via [`FfsError::to_errno`].
//! The mapping is exhaustive (no wildcard arms) so adding a new variant is a
//! compile error until its errno is assigned.
//!
//! | Variant | errno | Constant |
//! |---------|-------|----------|
//! | `Io` | `raw_os_error` → passthrough, else `ErrorKind` map, else `EIO` | varies |
//! | `Corruption` | `EIO` | 5 |
//! | `Format` | `EINVAL` | 22 |
//! | `Parse` | `EINVAL` | 22 |
//! | `UnsupportedFeature` | `EOPNOTSUPP` | 95 |
//! | `IncompatibleFeature` | `EOPNOTSUPP` | 95 |
//! | `UnsupportedBlockSize` | `EOPNOTSUPP` | 95 |
//! | `InvalidGeometry` | `EINVAL` | 22 |
//! | `MvccConflict` | `EAGAIN` | 11 |
//! | `Cancelled` | `EINTR` | 4 |
//! | `NoSpace` | `ENOSPC` | 28 |
//! | `NotFound` | `ENOENT` | 2 |
//! | `PermissionDenied` | `EACCES` | 13 |
//! | `ReadOnly` | `EROFS` | 30 |
//! | `NotDirectory` | `ENOTDIR` | 20 |
//! | `IsDirectory` | `EISDIR` | 21 |
//! | `NotEmpty` | `ENOTEMPTY` | 39 |
//! | `NameTooLong` | `ENAMETOOLONG` | 36 |
//! | `Exists` | `EEXIST` | 17 |
//! | `RepairFailed` | `EIO` | 5 |
//! | `ModeViolation` | `EPERM` | 1 |
//!
//! ## Design Constraints
//!
//! - `ffs-error` MUST NOT depend on `ffs-types` or `ffs-ondisk` (no cyclic deps).
//! - `FfsError` is the single user-facing error type; crate-internal errors
//!   (like `ParseError`, `CommitError`) convert into `FfsError` at their
//!   respective crate boundaries.
//! - All string payloads in `FfsError` are owned (`String`) to avoid lifetime
//!   entanglement across async boundaries.

use thiserror::Error;

/// Unified error type for all FrankenFS operations.
///
/// This is the canonical error type returned by FUSE handlers, CLI commands,
/// and public API surfaces. Internal crate-specific errors (e.g., `ParseError`
/// from `ffs-types`) are converted into `FfsError` at crate boundaries.
#[derive(Debug, Error)]
pub enum FfsError {
    /// Operating system I/O error (wraps `std::io::Error`).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// On-disk metadata corruption detected at a known block.
    ///
    /// Used when live metadata reads produce invalid data (checksum mismatch,
    /// truncated structures, out-of-range field values). The `block` field
    /// enables repair triage.
    #[error("corrupt metadata at block {block}: {detail}")]
    Corruption { block: u64, detail: String },

    /// Invalid on-disk format (wrong filesystem type, unsupported features).
    ///
    /// Used during mount-time validation when the image structure is
    /// fundamentally wrong (bad magic, unsupported format version).
    #[error("invalid on-disk format: {0}")]
    Format(String),

    /// Parse-layer error surfaced to the user.
    ///
    /// This variant carries the string representation of a `ParseError` from
    /// `ffs-types`. It exists so that higher-level code can convert parse
    /// failures without losing diagnostic detail. Prefer `Corruption` or
    /// `Format` when the block number or mount-validation context is known.
    #[error("parse error: {0}")]
    Parse(String),

    /// The filesystem image uses a feature that this build does not support.
    ///
    /// Used during mount-time validation when incompatible feature flags are
    /// set (e.g., ENCRYPT, INLINE_DATA). Maps to `EOPNOTSUPP` to distinguish
    /// "we don't support this yet" from "this image is broken."
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),

    /// The filesystem image's compatibility contract cannot be satisfied.
    ///
    /// Used when required compatibility bits are missing or unknown
    /// incompatible feature bits are present.
    #[error("incompatible feature set: {0}")]
    IncompatibleFeature(String),

    /// The image's block size is valid for the format but unsupported by this build.
    ///
    /// For v1 ext4 compatibility, FrankenFS currently supports 1K/2K/4K only.
    #[error("unsupported block size: {0}")]
    UnsupportedBlockSize(String),

    /// On-disk geometry is invalid or out of the supported range.
    ///
    /// Used during mount-time validation for block sizes, blocks_per_group,
    /// inodes_per_group, or other structural parameters that are numerically
    /// invalid or outside what FrankenFS supports.
    #[error("invalid geometry: {0}")]
    InvalidGeometry(String),

    /// MVCC serialization conflict.
    #[error("MVCC conflict: transaction {tx} conflicts on block {block}")]
    MvccConflict { tx: u64, block: u64 },

    /// Operation cancelled via `Cx` budget exhaustion or explicit cancel.
    #[error("operation cancelled")]
    Cancelled,

    /// No free blocks or inodes available.
    #[error("no space left on device")]
    NoSpace,

    /// File, directory, or other named object not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Insufficient permissions for the requested operation.
    #[error("permission denied")]
    PermissionDenied,

    /// Filesystem is mounted read-only and a write was attempted.
    #[error("read-only filesystem")]
    ReadOnly,

    /// A path component is not a directory.
    #[error("not a directory")]
    NotDirectory,

    /// Attempted a file operation on a directory.
    #[error("is a directory")]
    IsDirectory,

    /// rmdir on a non-empty directory.
    #[error("directory not empty")]
    NotEmpty,

    /// Filename exceeds the filesystem's name length limit.
    #[error("name too long")]
    NameTooLong,

    /// Target already exists (create, mkdir, exclusive open).
    #[error("file exists")]
    Exists,

    /// RaptorQ repair or self-healing workflow could not recover data.
    #[error("repair failed: {0}")]
    RepairFailed(String),

    /// A native-mode-only operation was attempted in compatibility mode.
    ///
    /// Returned when code tries to write repair symbols, version-store
    /// entries, or BLAKE3 checksums while mounted in compat mode. Maps to
    /// `EPERM` because the operation is valid but not authorized by the
    /// current mount configuration.
    #[error("mount-mode violation: {0}")]
    ModeViolation(String),
}

impl FfsError {
    /// Convert this error into a POSIX errno suitable for FUSE replies.
    ///
    /// The mapping is exhaustive — every variant has an explicit arm. Adding a
    /// new variant without updating this function is a compile error.
    ///
    /// Policy notes:
    /// - `Cancelled` → `EINTR`: aligns with POSIX "interrupted system call"
    ///   semantics. FUSE callers may retry at a higher layer.
    /// - `Parse` → `EINVAL`: parse failures during mount are format errors;
    ///   during live operation they should be wrapped as `Corruption` instead.
    /// - `UnsupportedFeature` → `EOPNOTSUPP`: distinguishes "not implemented"
    ///   from "structurally invalid."
    /// - `IncompatibleFeature` → `EOPNOTSUPP`: required/known compatibility
    ///   contracts are not satisfiable for this image.
    /// - `UnsupportedBlockSize` → `EOPNOTSUPP`: block size is valid on-disk
    ///   but outside this build's declared support envelope.
    /// - `InvalidGeometry` → `EINVAL`: bad on-disk parameters.
    /// - `ReadOnly` → `EROFS`: standard read-only filesystem errno.
    #[must_use]
    pub fn to_errno(&self) -> libc::c_int {
        match self {
            Self::Io(err) => err.raw_os_error().unwrap_or_else(|| match err.kind() {
                std::io::ErrorKind::NotFound => libc::ENOENT,
                std::io::ErrorKind::PermissionDenied => libc::EACCES,
                std::io::ErrorKind::AlreadyExists => libc::EEXIST,
                std::io::ErrorKind::WouldBlock => libc::EAGAIN,
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => libc::EINVAL,
                std::io::ErrorKind::TimedOut => libc::ETIMEDOUT,
                std::io::ErrorKind::Interrupted => libc::EINTR,
                std::io::ErrorKind::WriteZero
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::AddrInUse
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::Unsupported
                | _ => libc::EIO,
            }),
            Self::Corruption { .. } | Self::RepairFailed(_) => libc::EIO,
            Self::Format(_) | Self::Parse(_) | Self::InvalidGeometry(_) => libc::EINVAL,
            Self::UnsupportedFeature(_)
            | Self::IncompatibleFeature(_)
            | Self::UnsupportedBlockSize(_) => libc::EOPNOTSUPP,
            Self::MvccConflict { .. } => libc::EAGAIN,
            Self::Cancelled => libc::EINTR,
            Self::NoSpace => libc::ENOSPC,
            Self::NotFound(_) => libc::ENOENT,
            Self::PermissionDenied => libc::EACCES,
            Self::ReadOnly => libc::EROFS,
            Self::NotDirectory => libc::ENOTDIR,
            Self::IsDirectory => libc::EISDIR,
            Self::NotEmpty => libc::ENOTEMPTY,
            Self::NameTooLong => libc::ENAMETOOLONG,
            Self::Exists => libc::EEXIST,
            Self::ModeViolation(_) => libc::EPERM,
        }
    }
}

/// Result alias using `FfsError`.
pub type Result<T> = std::result::Result<T, FfsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_mapping_covers_all_variants() {
        // Verify each variant produces the expected errno.
        let cases: Vec<(FfsError, libc::c_int)> = vec![
            (FfsError::Io(std::io::Error::other("test")), libc::EIO),
            (
                FfsError::Corruption {
                    block: 0,
                    detail: "test".into(),
                },
                libc::EIO,
            ),
            (FfsError::Format("test".into()), libc::EINVAL),
            (FfsError::Parse("test".into()), libc::EINVAL),
            (
                FfsError::UnsupportedFeature("ENCRYPT".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::IncompatibleFeature("feature_incompat: missing FILETYPE".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::UnsupportedBlockSize("block_size: 8192".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::InvalidGeometry("block_size=0".into()),
                libc::EINVAL,
            ),
            (FfsError::MvccConflict { tx: 1, block: 2 }, libc::EAGAIN),
            (FfsError::Cancelled, libc::EINTR),
            (FfsError::NoSpace, libc::ENOSPC),
            (FfsError::NotFound("test".into()), libc::ENOENT),
            (FfsError::PermissionDenied, libc::EACCES),
            (FfsError::ReadOnly, libc::EROFS),
            (FfsError::NotDirectory, libc::ENOTDIR),
            (FfsError::IsDirectory, libc::EISDIR),
            (FfsError::NotEmpty, libc::ENOTEMPTY),
            (FfsError::NameTooLong, libc::ENAMETOOLONG),
            (FfsError::Exists, libc::EEXIST),
            (FfsError::RepairFailed("test".into()), libc::EIO),
            (
                FfsError::ModeViolation("test operation".into()),
                libc::EPERM,
            ),
        ];

        for (error, expected_errno) in &cases {
            assert_eq!(
                error.to_errno(),
                *expected_errno,
                "wrong errno for {error:?}",
            );
        }
    }

    #[test]
    fn io_error_preserves_raw_os_error() {
        let raw = std::io::Error::from_raw_os_error(libc::EPERM);
        let ffs = FfsError::Io(raw);
        assert_eq!(ffs.to_errno(), libc::EPERM);
    }

    #[test]
    fn display_formatting() {
        let err = FfsError::Corruption {
            block: 42,
            detail: "bad checksum".into(),
        };
        assert_eq!(
            err.to_string(),
            "corrupt metadata at block 42: bad checksum"
        );

        let parse = FfsError::Parse("insufficient data: need 4 bytes at offset 0, got 2".into());
        assert!(parse.to_string().contains("parse error:"));

        let ro = FfsError::ReadOnly;
        assert_eq!(ro.to_string(), "read-only filesystem");

        let unsup = FfsError::UnsupportedFeature("ENCRYPT".into());
        assert_eq!(unsup.to_string(), "unsupported feature: ENCRYPT");

        let incompat = FfsError::IncompatibleFeature("missing FILETYPE+EXTENTS".into());
        assert_eq!(
            incompat.to_string(),
            "incompatible feature set: missing FILETYPE+EXTENTS"
        );

        let blk = FfsError::UnsupportedBlockSize("8192".into());
        assert_eq!(blk.to_string(), "unsupported block size: 8192");

        let geom = FfsError::InvalidGeometry("blocks_per_group=0".into());
        assert_eq!(geom.to_string(), "invalid geometry: blocks_per_group=0");
    }

    #[test]
    fn mount_validation_errnos_are_distinct() {
        // UnsupportedFeature should be EOPNOTSUPP, not EINVAL
        let unsup = FfsError::UnsupportedFeature("ENCRYPT".into());
        let incompat = FfsError::IncompatibleFeature("unknown incompat bits".into());
        let blk = FfsError::UnsupportedBlockSize("8192".into());
        let geom = FfsError::InvalidGeometry("bad block size".into());
        let fmt = FfsError::Format("bad magic".into());

        assert_eq!(unsup.to_errno(), libc::EOPNOTSUPP);
        assert_eq!(incompat.to_errno(), libc::EOPNOTSUPP);
        assert_eq!(blk.to_errno(), libc::EOPNOTSUPP);
        assert_eq!(geom.to_errno(), libc::EINVAL);
        assert_eq!(fmt.to_errno(), libc::EINVAL);

        // EOPNOTSUPP != EINVAL (verifying the distinction matters)
        assert_ne!(unsup.to_errno(), geom.to_errno());
    }

    // ── Exhaustive Display formatting tests ─────────────────────────────

    #[test]
    fn display_all_string_carrying_variants() {
        // Every variant that carries a String payload should include it in Display.
        let cases: Vec<(FfsError, &str)> = vec![
            (
                FfsError::Format("bad magic 0xDEAD".into()),
                "invalid on-disk format: bad magic 0xDEAD",
            ),
            (
                FfsError::Parse("need 4 bytes".into()),
                "parse error: need 4 bytes",
            ),
            (
                FfsError::UnsupportedFeature("INLINE_DATA".into()),
                "unsupported feature: INLINE_DATA",
            ),
            (
                FfsError::IncompatibleFeature("missing EXTENTS".into()),
                "incompatible feature set: missing EXTENTS",
            ),
            (
                FfsError::UnsupportedBlockSize("16384".into()),
                "unsupported block size: 16384",
            ),
            (
                FfsError::InvalidGeometry("zero inodes_per_group".into()),
                "invalid geometry: zero inodes_per_group",
            ),
            (
                FfsError::NotFound("/lost+found".into()),
                "not found: /lost+found",
            ),
            (
                FfsError::RepairFailed("symbol decode failed".into()),
                "repair failed: symbol decode failed",
            ),
        ];

        for (err, expected) in &cases {
            assert_eq!(err.to_string(), *expected, "Display mismatch for {err:?}");
        }
    }

    #[test]
    fn display_unit_variants() {
        // Variants with no payload should produce fixed strings.
        assert_eq!(FfsError::Cancelled.to_string(), "operation cancelled");
        assert_eq!(FfsError::NoSpace.to_string(), "no space left on device");
        assert_eq!(FfsError::PermissionDenied.to_string(), "permission denied");
        assert_eq!(FfsError::ReadOnly.to_string(), "read-only filesystem");
        assert_eq!(FfsError::NotDirectory.to_string(), "not a directory");
        assert_eq!(FfsError::IsDirectory.to_string(), "is a directory");
        assert_eq!(FfsError::NotEmpty.to_string(), "directory not empty");
        assert_eq!(FfsError::NameTooLong.to_string(), "name too long");
        assert_eq!(FfsError::Exists.to_string(), "file exists");
    }

    #[test]
    fn display_structured_variants() {
        let corruption = FfsError::Corruption {
            block: 12345,
            detail: "checksum mismatch: expected 0xABCD, got 0x1234".into(),
        };
        assert_eq!(
            corruption.to_string(),
            "corrupt metadata at block 12345: checksum mismatch: expected 0xABCD, got 0x1234"
        );

        let conflict = FfsError::MvccConflict { tx: 99, block: 256 };
        assert_eq!(
            conflict.to_string(),
            "MVCC conflict: transaction 99 conflicts on block 256"
        );
    }

    #[test]
    fn display_corruption_with_block_zero() {
        // Block 0 is the superblock — valid corruption target.
        let err = FfsError::Corruption {
            block: 0,
            detail: "superblock magic invalid".into(),
        };
        assert_eq!(
            err.to_string(),
            "corrupt metadata at block 0: superblock magic invalid"
        );
    }

    #[test]
    fn display_corruption_with_max_block() {
        let err = FfsError::Corruption {
            block: u64::MAX,
            detail: "out of range".into(),
        };
        let s = err.to_string();
        assert!(
            s.contains(&u64::MAX.to_string()),
            "max block number should appear in Display: {s}"
        );
    }

    #[test]
    fn display_mvcc_conflict_with_large_ids() {
        let err = FfsError::MvccConflict {
            tx: u64::MAX,
            block: u64::MAX - 1,
        };
        let s = err.to_string();
        assert!(s.contains(&u64::MAX.to_string()));
        assert!(s.contains(&(u64::MAX - 1).to_string()));
    }

    // ── From<std::io::Error> conversion tests ───────────────────────────

    #[test]
    fn from_io_error_conversion() {
        // Error::new() does NOT set raw_os_error — only from_raw_os_error() does.
        // With ErrorKind mapping, NotFound now yields ENOENT even without raw errno.
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let ffs_err: FfsError = io_err.into();
        assert_eq!(ffs_err.to_errno(), libc::ENOENT);
        assert!(ffs_err.to_string().contains("file gone"));

        // With from_raw_os_error, the errno passes through.
        let io_err2 = std::io::Error::from_raw_os_error(libc::ENOENT);
        let ffs_err2: FfsError = io_err2.into();
        assert_eq!(ffs_err2.to_errno(), libc::ENOENT);
    }

    #[test]
    fn io_error_without_raw_os_error_falls_back_to_eio() {
        // Error::other() uses ErrorKind::Other, which has no specific mapping → EIO.
        let io_err = std::io::Error::other("custom error with no errno");
        let ffs_err = FfsError::Io(io_err);
        assert_eq!(ffs_err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_kind_mapping_without_raw_errno() {
        // Verify ErrorKind → errno mapping when raw_os_error() is None.
        let cases: Vec<(std::io::ErrorKind, libc::c_int)> = vec![
            (std::io::ErrorKind::NotFound, libc::ENOENT),
            (std::io::ErrorKind::PermissionDenied, libc::EACCES),
            (std::io::ErrorKind::AlreadyExists, libc::EEXIST),
            (std::io::ErrorKind::WouldBlock, libc::EAGAIN),
            (std::io::ErrorKind::InvalidInput, libc::EINVAL),
            (std::io::ErrorKind::InvalidData, libc::EINVAL),
            (std::io::ErrorKind::TimedOut, libc::ETIMEDOUT),
            (std::io::ErrorKind::Interrupted, libc::EINTR),
            (std::io::ErrorKind::Unsupported, libc::EIO),
            (std::io::ErrorKind::Other, libc::EIO),
        ];
        for (kind, expected_errno) in &cases {
            let io_err = std::io::Error::new(*kind, "test");
            let ffs_err = FfsError::Io(io_err);
            assert_eq!(
                ffs_err.to_errno(),
                *expected_errno,
                "ErrorKind::{kind:?} should map to errno {expected_errno}"
            );
        }
    }

    #[test]
    fn io_error_preserves_various_raw_errnos() {
        let errnos = [
            libc::EPERM,
            libc::ENOENT,
            libc::EIO,
            libc::ENOMEM,
            libc::EACCES,
            libc::EBUSY,
            libc::ENOSPC,
        ];
        for errno in errnos {
            let raw = std::io::Error::from_raw_os_error(errno);
            let ffs = FfsError::Io(raw);
            assert_eq!(
                ffs.to_errno(),
                errno,
                "raw errno {errno} should pass through unchanged"
            );
        }
    }

    // ── Error trait implementation tests ─────────────────────────────────

    #[test]
    fn error_trait_source_for_io_variant() {
        use std::error::Error;
        let io_err = std::io::Error::other("underlying cause");
        let ffs_err = FfsError::Io(io_err);
        // Io variant should have a source (the wrapped std::io::Error).
        assert!(ffs_err.source().is_some());
    }

    #[test]
    fn error_trait_source_for_non_io_variants() {
        use std::error::Error;
        // Non-Io variants should have no source chain.
        let cases: Vec<FfsError> = vec![
            FfsError::Corruption {
                block: 1,
                detail: "x".into(),
            },
            FfsError::Format("x".into()),
            FfsError::MvccConflict { tx: 1, block: 2 },
            FfsError::Cancelled,
            FfsError::NoSpace,
            FfsError::NotFound("x".into()),
            FfsError::RepairFailed("x".into()),
        ];
        for err in &cases {
            assert!(
                err.source().is_none(),
                "expected no source for {err:?}, got {:?}",
                err.source()
            );
        }
    }

    #[test]
    fn debug_formatting_includes_variant_name() {
        let err = FfsError::NoSpace;
        let debug = format!("{err:?}");
        assert!(
            debug.contains("NoSpace"),
            "Debug should include variant name: {debug}"
        );

        let err2 = FfsError::Corruption {
            block: 7,
            detail: "bad".into(),
        };
        let debug2 = format!("{err2:?}");
        assert!(debug2.contains("Corruption"));
        assert!(debug2.contains('7'));
        assert!(debug2.contains("bad"));
    }

    // ── Errno value correctness (verify against libc constants) ─────────

    #[test]
    fn errno_values_match_expected_posix_constants() {
        // Verify the actual integer values match POSIX expectations.
        assert_eq!(libc::EIO, 5);
        assert_eq!(libc::EINVAL, 22);
        assert_eq!(libc::EOPNOTSUPP, 95);
        assert_eq!(libc::EAGAIN, 11);
        assert_eq!(libc::EINTR, 4);
        assert_eq!(libc::ENOSPC, 28);
        assert_eq!(libc::ENOENT, 2);
        assert_eq!(libc::EACCES, 13);
        assert_eq!(libc::EROFS, 30);
        assert_eq!(libc::ENOTDIR, 20);
        assert_eq!(libc::EISDIR, 21);
        assert_eq!(libc::ENOTEMPTY, 39);
        assert_eq!(libc::ENAMETOOLONG, 36);
        assert_eq!(libc::EEXIST, 17);
        assert_eq!(libc::EPERM, 1);
    }

    // ── Empty string payload tests ──────────────────────────────────────

    #[test]
    fn empty_string_payloads_produce_valid_display() {
        // All string-carrying variants should handle empty strings gracefully.
        let cases: Vec<FfsError> = vec![
            FfsError::Format(String::new()),
            FfsError::Parse(String::new()),
            FfsError::UnsupportedFeature(String::new()),
            FfsError::IncompatibleFeature(String::new()),
            FfsError::UnsupportedBlockSize(String::new()),
            FfsError::InvalidGeometry(String::new()),
            FfsError::NotFound(String::new()),
            FfsError::RepairFailed(String::new()),
            FfsError::Corruption {
                block: 0,
                detail: String::new(),
            },
        ];

        for err in &cases {
            // Should not panic and should produce non-empty output.
            let display = err.to_string();
            assert!(
                !display.is_empty(),
                "Display should not be empty for {err:?}"
            );
            // Errno should still work.
            let _ = err.to_errno();
        }
    }

    // ── Result type alias test ──────────────────────────────────────────

    // ── Send + Sync compile-time check ──────────────────────────────

    #[test]
    fn ffs_error_is_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<FfsError>();
        assert_sync::<FfsError>();
    }

    // ── IoError ErrorKind fallthrough to EIO ─────────────────────────

    #[test]
    fn io_error_write_zero_maps_to_eio() {
        let err = FfsError::Io(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "short write",
        ));
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_broken_pipe_maps_to_eio() {
        let err = FfsError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ));
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_connection_reset_maps_to_eio() {
        let err = FfsError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ));
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_unexpected_eof_maps_to_eio() {
        let err = FfsError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        ));
        assert_eq!(err.to_errno(), libc::EIO);
    }

    // ── MvccConflict zero values ─────────────────────────────────────

    #[test]
    fn mvcc_conflict_zero_tx_and_block() {
        let err = FfsError::MvccConflict { tx: 0, block: 0 };
        assert_eq!(err.to_errno(), libc::EAGAIN);
        assert_eq!(
            err.to_string(),
            "MVCC conflict: transaction 0 conflicts on block 0"
        );
    }

    // ── Unicode in string payloads ───────────────────────────────────

    #[test]
    fn unicode_in_string_payloads() {
        let err = FfsError::NotFound("日本語ファイル.txt".into());
        assert!(err.to_string().contains("日本語ファイル.txt"));
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    // ── Raw errno passthrough negative test ──────────────────────────

    #[test]
    fn io_error_raw_errno_takes_precedence_over_kind_mapping() {
        // from_raw_os_error sets both raw_os_error and a kind, but
        // raw_os_error() should take precedence in our mapping.
        let err = FfsError::Io(std::io::Error::from_raw_os_error(libc::ENOSYS));
        assert_eq!(err.to_errno(), libc::ENOSYS);
    }

    // ── Debug formatting for all string variants ─────────────────────

    #[test]
    fn debug_includes_payload_for_string_variants() {
        let err = FfsError::RepairFailed("reed-solomon decode fail".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("RepairFailed"));
        assert!(dbg.contains("reed-solomon decode fail"));
    }

    // ── Chained ? operator across error types ────────────────────────

    #[test]
    fn question_mark_chains_io_into_ffs_error() {
        fn inner() -> Result<()> {
            let io_res: std::result::Result<(), std::io::Error> =
                Err(std::io::Error::from_raw_os_error(libc::EPERM));
            io_res?;
            Ok(())
        }
        let err = inner().unwrap_err();
        assert_eq!(err.to_errno(), libc::EPERM);
    }

    #[test]
    fn result_alias_works_with_question_mark() {
        fn inner() -> Result<u64> {
            let val: Result<u64> = Ok(42);
            let v = val?;
            Ok(v + 1)
        }
        assert_eq!(inner().unwrap(), 43);

        let failing: Result<u64> = Err(FfsError::NoSpace);
        assert!(failing.is_err());
    }

    // ── Untested ErrorKind → EIO fallthrough variants ───────────────────

    #[test]
    fn io_error_connection_aborted_maps_to_eio() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "aborted");
        let err = FfsError::Io(io_err);
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_not_connected_maps_to_eio() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotConnected, "not connected");
        let err = FfsError::Io(io_err);
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_addr_in_use_maps_to_eio() {
        let io_err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use");
        let err = FfsError::Io(io_err);
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_addr_not_available_maps_to_eio() {
        let io_err = std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "unavailable");
        let err = FfsError::Io(io_err);
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_connection_refused_maps_to_eio() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err = FfsError::Io(io_err);
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_unsupported_maps_to_eio() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Unsupported, "unsupported");
        let err = FfsError::Io(io_err);
        assert_eq!(err.to_errno(), libc::EIO);
    }

    #[test]
    fn io_error_other_maps_to_eio() {
        let io_err = std::io::Error::other("other");
        let err = FfsError::Io(io_err);
        assert_eq!(err.to_errno(), libc::EIO);
    }

    // ── Additional edge case coverage ───────────────────────────────────

    #[test]
    fn display_mode_violation_includes_detail() {
        let err = FfsError::ModeViolation("native-only op in compat mode".to_owned());
        let msg = format!("{err}");
        assert!(msg.contains("native-only op in compat mode"));
    }

    #[test]
    fn display_repair_failed_includes_detail() {
        let err = FfsError::RepairFailed("codec exhausted".to_owned());
        let msg = format!("{err}");
        assert!(msg.contains("codec exhausted"));
    }

    #[test]
    fn from_io_error_via_question_mark() {
        fn fallible() -> Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"))?;
            Ok(())
        }
        let err = fallible().unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
    }

    #[test]
    fn error_source_chain_for_io() {
        let io_err = std::io::Error::other("inner cause");
        let err = FfsError::Io(io_err);
        let source = std::error::Error::source(&err);
        assert!(source.is_some());
        assert!(format!("{}", source.unwrap()).contains("inner cause"));
    }

    #[test]
    fn all_unit_variants_have_stable_errno() {
        let cases: Vec<(FfsError, libc::c_int)> = vec![
            (FfsError::Cancelled, libc::EINTR),
            (FfsError::NoSpace, libc::ENOSPC),
            (FfsError::PermissionDenied, libc::EACCES),
            (FfsError::ReadOnly, libc::EROFS),
            (FfsError::NotDirectory, libc::ENOTDIR),
            (FfsError::IsDirectory, libc::EISDIR),
            (FfsError::NotEmpty, libc::ENOTEMPTY),
            (FfsError::NameTooLong, libc::ENAMETOOLONG),
            (FfsError::Exists, libc::EEXIST),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_errno(), expected, "wrong errno for {err:?}");
        }
    }
}
