//! VFS semantics layer: filesystem-agnostic types and operations trait.
//!
//! This module defines the core VFS abstractions that higher layers (FUSE,
//! test harness) consume. Format-specific implementations (ext4, btrfs) live
//! behind the [`FsOps`] trait so that callers are filesystem-agnostic.

use asupersync::Cx;
use ffs_error::FfsError;
use ffs_types::{CommitSeq, InodeNumber, Snapshot};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::Path;
use std::time::SystemTime;

// ── VFS semantics layer ─────────────────────────────────────────────────────

const COPY_FILE_RANGE_CHUNK_BYTES: u32 = 1024 * 1024;

fn ranges_overlap(a_start: u64, a_len: u64, b_start: u64, b_len: u64) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let Some(a_end) = a_start.checked_add(a_len) else {
        return true;
    };
    let Some(b_end) = b_start.checked_add(b_len) else {
        return true;
    };
    a_start < b_end && b_start < a_end
}

/// Filesystem-agnostic file type for VFS operations.
///
/// This is the semantics-level file type used by [`FsOps`] methods. It unifies
/// ext4's `Ext4FileType` and btrfs's inode type into a single enum that
/// higher layers (FUSE, harness) consume without filesystem-specific knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    RegularFile,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
}

/// Inode attributes returned by [`FsOps::getattr`] and [`FsOps::lookup`].
///
/// This is the semantics-level stat structure, analogous to POSIX `struct stat`.
/// Format-specific crates (ffs-ext4, ffs-btrfs) convert their on-disk inode
/// representations into `InodeAttr` at the crate boundary.
///
/// # Generation Number Lifecycle
///
/// The `generation` field implements NFS-style stale-handle detection:
///
/// - **ext4:** Per-inode counter stored at on-disk offset `0x64`. Bumped by
///   `wrapping_add(1)` each time an inode number is reused after deletion.
///   This lets FUSE/NFS clients detect that a previously-held file handle now
///   refers to a different file occupying the same inode slot.
///
/// - **btrfs:** Uses the inode-item's `generation` field (transaction generation
///   at inode creation time). Since btrfs inode numbers (objectids) are never
///   reused within a filesystem, the creation-time transaction generation
///   suffices as a unique discriminator. For in-memory-only mutations (COW
///   write path), `BtrfsAllocState.generation` is used.
///
/// The FUSE layer passes this value as the `generation` parameter in
/// `reply.entry()` and `reply.created()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeAttr {
    /// Inode number.
    pub ino: InodeNumber,
    /// File size in bytes.
    pub size: u64,
    /// Number of 512-byte blocks allocated.
    pub blocks: u64,
    /// Last access time.
    pub atime: SystemTime,
    /// Last modification time.
    pub mtime: SystemTime,
    /// Last status change time.
    pub ctime: SystemTime,
    /// Creation time (if available).
    pub crtime: SystemTime,
    /// File type.
    pub kind: FileType,
    /// POSIX permission bits (lower 12 bits of mode).
    pub perm: u16,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Device ID (for block/char devices).
    pub rdev: u32,
    /// Preferred I/O block size.
    pub blksize: u32,
    /// NFS-style generation number for stale-handle detection.
    ///
    /// See struct-level docs for the per-filesystem lifecycle contract.
    pub generation: u64,
}

/// A directory entry returned by [`FsOps::readdir`].
///
/// Each entry represents one name in a directory listing. The `offset` field
/// is an opaque cookie for resuming iteration — FUSE passes it back on
/// subsequent `readdir` calls so the implementation can skip already-returned
/// entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// Inode number of the target.
    pub ino: InodeNumber,
    /// Opaque offset cookie for readdir continuation.
    pub offset: u64,
    /// File type of the target.
    pub kind: FileType,
    /// Entry name (filename component, not a full path).
    pub name: Vec<u8>,
}

impl DirEntry {
    /// Return the name as a UTF-8 string (lossy).
    #[must_use]
    pub fn name_str(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }
}

/// A single extent returned by [`FsOps::fiemap`].
///
/// Mirrors `struct fiemap_extent` from `<linux/fiemap.h>`. All offsets and
/// lengths are in **bytes** (not blocks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiemapExtent {
    /// Logical offset in the file (bytes).
    pub logical: u64,
    /// Physical offset on the device (bytes).
    pub physical: u64,
    /// Length in bytes.
    pub length: u64,
    /// Flags bitmap (FIEMAP_EXTENT_* constants).
    pub flags: u32,
}

/// FIEMAP extent flag: this extent is the last in the file.
pub const FIEMAP_EXTENT_LAST: u32 = 0x0001;
/// FIEMAP extent flag: this extent is unwritten / preallocated.
pub const FIEMAP_EXTENT_UNWRITTEN: u32 = 0x0800;

/// Seek whence for [`FsOps::lseek`].
///
/// Standard POSIX whence values plus `SEEK_DATA`/`SEEK_HOLE` for sparse file
/// support (FUSE 7.24+). Required for efficient sparse file handling in
/// `cp --sparse`, `rsync`, and `tar`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeekWhence {
    /// Seek relative to start of file.
    Set,
    /// Seek relative to current position (not used by FUSE lseek, but included
    /// for completeness).
    Cur,
    /// Seek relative to end of file.
    End,
    /// Find the next data (non-hole) region at or after the offset.
    Data,
    /// Find the next hole (unallocated) region at or after the offset.
    Hole,
}

impl SeekWhence {
    // POSIX whence constants (from <unistd.h> / libc)
    const SEEK_SET: i32 = 0;
    const SEEK_CUR: i32 = 1;
    const SEEK_END: i32 = 2;
    const SEEK_DATA: i32 = 3;
    const SEEK_HOLE: i32 = 4;

    /// Convert from raw POSIX whence value.
    ///
    /// Returns `None` for unrecognized values.
    #[must_use]
    pub fn from_raw(whence: i32) -> Option<Self> {
        match whence {
            Self::SEEK_SET => Some(Self::Set),
            Self::SEEK_CUR => Some(Self::Cur),
            Self::SEEK_END => Some(Self::End),
            Self::SEEK_DATA => Some(Self::Data),
            Self::SEEK_HOLE => Some(Self::Hole),
            _ => None,
        }
    }
}

/// FUSE/VFS operation kind used for MVCC request-scope hooks.
///
/// These operation tags let `FsOps` implementations choose an MVCC policy per
/// request (for example: read-snapshot only vs. begin write transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RequestOp {
    Getattr,
    Statfs,
    Getxattr,
    Lookup,
    Listxattr,
    Flush,
    Fsync,
    Fsyncdir,
    Open,
    Release,
    Opendir,
    Read,
    Readdir,
    Readlink,
    Lseek,
    // Write operations
    Create,
    Mkdir,
    Unlink,
    Rmdir,
    Rename,
    Link,
    Symlink,
    Fallocate,
    Setattr,
    Setxattr,
    Removexattr,
    Write,
    IoctlRead,
    IoctlWrite,
}

impl RequestOp {
    /// Whether this operation mutates the filesystem.
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Self::Create
                | Self::Mkdir
                | Self::Unlink
                | Self::Rmdir
                | Self::Rename
                | Self::Link
                | Self::Symlink
                | Self::Fallocate
                | Self::Setattr
                | Self::Setxattr
                | Self::Removexattr
                | Self::Write
                | Self::IoctlWrite
                | Self::Fsync
                | Self::Fsyncdir
        )
    }

    /// Whether this operation is a metadata-only write.
    #[must_use]
    pub const fn is_metadata_write(self) -> bool {
        matches!(
            self,
            Self::Create
                | Self::Mkdir
                | Self::Unlink
                | Self::Rmdir
                | Self::Rename
                | Self::Link
                | Self::Symlink
                | Self::Setattr
                | Self::Setxattr
                | Self::Removexattr
                | Self::IoctlWrite
        )
    }
}

/// MVCC scope acquired for a single VFS request.
///
/// Current read-only implementations can return an empty scope. Future write
/// implementations may attach a transaction captured at request
/// start so that begin/end hooks can manage commit/abort semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestScope {
    pub snapshot: Option<Snapshot>,
    pub tx: Option<ffs_mvcc::Transaction>,
}

impl RequestScope {
    /// Create a scope with no snapshot or transaction attached.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            snapshot: None,
            tx: None,
        }
    }

    /// Create a scope tied to a specific MVCC snapshot.
    #[must_use]
    pub fn with_snapshot(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Some(snapshot),
            tx: None,
        }
    }

    /// Commit the transaction if one is present.
    ///
    /// Returns the commit sequence on success, or an error if the commit failed.
    /// Returns `Ok(CommitSeq(0))` if no transaction was attached.
    pub fn commit_if_write(
        &mut self,
        mvcc_store: &parking_lot::RwLock<ffs_mvcc::MvccStore>,
    ) -> ffs_error::Result<CommitSeq> {
        self.tx.take().map_or(Ok(CommitSeq(0)), |tx| {
            let tx_id = tx.id().0;
            mvcc_store.write().commit(tx).map_err(|error| match error {
                ffs_mvcc::CommitError::Conflict { block, .. }
                | ffs_mvcc::CommitError::ChainBackpressure { block, .. } => {
                    ffs_error::FfsError::MvccConflict {
                        tx: tx_id,
                        block: block.0,
                    }
                }
                ffs_mvcc::CommitError::SsiConflict { pivot_block, .. } => {
                    ffs_error::FfsError::MvccConflict {
                        tx: tx_id,
                        block: pivot_block.0,
                    }
                }
                ffs_mvcc::CommitError::DurabilityFailure { detail } => {
                    ffs_error::FfsError::Io(std::io::Error::other(format!(
                        "MVCC durability failure during request-scope commit: {detail}"
                    )))
                }
            })
        })
    }
}

/// Inode state surfaced by the `FS_IOC_FSGETXATTR` / `FS_IOC_FSSETXATTR`
/// ioctls — a Rust mirror of `struct fsxattr` from `<linux/fs.h>`.
///
/// The on-the-wire encoding is 28 bytes little-endian:
/// `xflags | extsize | nextents | projid | cowextsize | 8 bytes pad`.
/// xflags bits are documented in `uapi/linux/fs.h::FS_XFLAG_*` and are
/// the chattr/lsattr-visible projection of the underlying filesystem
/// inode flags. Backends populate the fields they support and zero
/// the rest; ext4 sets `xflags`, `nextents`, and `projid` and leaves
/// `extsize` + `cowextsize` at zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsxattrInfo {
    /// chattr-style flags mapped from filesystem-specific `i_flags`.
    pub xflags: u32,
    /// XFS-specific extent size hint (0 for ext4).
    pub extsize: u32,
    /// Live count of extents allocated to the inode (0 for inline-data
    /// or non-extent-tree inodes).
    pub nextents: u32,
    /// Project ID for project-based quota accounting.
    pub projid: u32,
    /// XFS-specific CoW extent size hint (0 for ext4).
    pub cowextsize: u32,
}

/// xflags bits per `<uapi/linux/fs.h>`. Only the subset that ext4
/// `i_flags` can map onto is used by the FrankenFS backend; the rest
/// are XFS- or DAX-specific and stay zero on a getxattr return.
pub mod xflags {
    pub const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
    pub const FS_XFLAG_APPEND: u32 = 0x0000_0010;
    pub const FS_XFLAG_SYNC: u32 = 0x0000_0020;
    pub const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
    pub const FS_XFLAG_NODUMP: u32 = 0x0000_0080;
    pub const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;
    pub const FS_XFLAG_NODEFRAG: u32 = 0x0000_2000;
    pub const FS_XFLAG_DAX: u32 = 0x0000_8000;
    /// Set when at least one inode-level xflag is in effect; ext4
    /// surfaces this whenever the mapped flag set is non-empty so
    /// userspace can tell "no chattrs" from "queried successfully".
    pub const FS_XFLAG_HASATTR: u32 = 0x8000_0000;
}

/// Request to modify inode attributes via `setattr`.
///
/// Each field is `Option` — only present fields are applied. Missing fields
/// leave the corresponding attribute unchanged.
#[derive(Debug, Clone, Default)]
pub struct SetAttrRequest {
    /// New permission mode bits (lower 12 bits of st_mode).
    pub mode: Option<u16>,
    /// New owner UID.
    pub uid: Option<u32>,
    /// New owner GID.
    pub gid: Option<u32>,
    /// New file size (truncate/extend).
    pub size: Option<u64>,
    /// New access time.
    pub atime: Option<SystemTime>,
    /// New modification time.
    pub mtime: Option<SystemTime>,
}

/// Request to release a backend-managed open file handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseRequest {
    /// Inode whose open file handle is being released.
    pub ino: InodeNumber,
    /// Backend file handle returned from `open`.
    pub fh: u64,
    /// Open flags supplied by the kernel.
    pub flags: i32,
    /// Optional lock owner supplied by the kernel.
    pub lock_owner: Option<u64>,
    /// Whether release should flush pending state.
    pub flush: bool,
}

/// How `setxattr` should treat pre-existing attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrSetMode {
    /// Create if missing, replace if existing.
    Set,
    /// Fail with `EEXIST` if the attribute already exists.
    Create,
    /// Fail with `ENODATA`/`ENOATTR` if the attribute does not exist.
    Replace,
}

/// Filesystem statistics returned by `statfs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsStat {
    /// Total data blocks in filesystem units.
    pub blocks: u64,
    /// Free data blocks.
    pub blocks_free: u64,
    /// Free blocks available to unprivileged callers.
    pub blocks_available: u64,
    /// Total inode count (or object count when available).
    pub files: u64,
    /// Free inode/object count.
    pub files_free: u64,
    /// Preferred block size in bytes.
    pub block_size: u32,
    /// Maximum filename length.
    pub name_max: u32,
    /// Fundamental fragment size in bytes.
    pub fragment_size: u32,
}

/// Quota type (user, group, or project).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuotaType {
    /// User quota (per-UID limits).
    User,
    /// Group quota (per-GID limits).
    Group,
    /// Project quota (per-project-ID limits).
    Project,
}

/// Quota usage and limits for a single ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaEntry {
    /// The ID (UID, GID, or project ID depending on quota type).
    pub id: u32,
    /// Current space usage in bytes.
    pub space_used: u64,
    /// Soft limit for space in bytes (0 = no limit).
    pub space_soft_limit: u64,
    /// Hard limit for space in bytes (0 = no limit).
    pub space_hard_limit: u64,
    /// Current inode usage count.
    pub inodes_used: u64,
    /// Soft limit for inode count (0 = no limit).
    pub inodes_soft_limit: u64,
    /// Hard limit for inode count (0 = no limit).
    pub inodes_hard_limit: u64,
}

/// Summary of filesystem quota configuration and status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaInfo {
    /// Whether user quotas are enabled.
    pub user_quota_enabled: bool,
    /// User quota inode number (if enabled).
    pub user_quota_inum: Option<u32>,
    /// Whether group quotas are enabled.
    pub group_quota_enabled: bool,
    /// Group quota inode number (if enabled).
    pub group_quota_inum: Option<u32>,
    /// Whether project quotas are enabled.
    pub project_quota_enabled: bool,
    /// Project quota inode number (if enabled).
    pub project_quota_inum: Option<u32>,
}

/// VFS operations trait for filesystem access.
///
/// This is the internal interface that FUSE and the test harness call.
/// Format-specific implementations (ext4, btrfs) live behind this trait so
/// that higher layers are filesystem-agnostic.
///
/// # Design Notes
///
/// - All methods take `&Cx` for cooperative cancellation and deadline
///   propagation via the asupersync runtime.
/// - Errors are returned as `ffs_error::FfsError`, which maps to POSIX
///   errnos via [`FfsError::to_errno()`].
/// - The trait is `Send + Sync` so that FUSE can call it from multiple
///   threads concurrently.
/// - Write operations have default implementations returning `FfsError::ReadOnly`.
/// - `begin_request_scope`/`end_request_scope` provide a policy hook for
///   per-request MVCC snapshot/transaction management.
pub trait FsOps: Send + Sync {
    /// Get file attributes by inode number.
    ///
    /// Returns the attributes for the given inode. Returns
    /// `FfsError::NotFound` if the inode does not exist.
    fn getattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr>;

    /// Look up a directory entry by name.
    ///
    /// Returns the attributes of the child inode named `name` within the
    /// directory `parent`. Returns `FfsError::NotFound` if the name does
    /// not exist, or `FfsError::NotDirectory` if `parent` is not a directory.
    fn lookup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<InodeAttr>;

    /// List directory entries starting from `offset`.
    ///
    /// Returns a batch of entries from the directory identified by `ino`.
    /// The `offset` parameter is an opaque cookie from a previous call's
    /// `DirEntry::offset` field (use 0 for the first call). An empty
    /// result indicates the end of the directory.
    ///
    /// Returns `FfsError::NotDirectory` if `ino` is not a directory.
    fn readdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> ffs_error::Result<Vec<DirEntry>>;

    /// Read file data.
    ///
    /// Returns up to `size` bytes starting at byte `offset` within the
    /// file identified by `ino`. Returns fewer bytes at EOF. Returns
    /// `FfsError::IsDirectory` if `ino` is a directory.
    fn read(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>>;

    /// Open a file and optionally return backend-managed handle state.
    ///
    /// Stateless implementations should return `(0, 0)`, matching the FUSE
    /// open reply's default file handle and open flags.
    fn open(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _flags: i32,
    ) -> ffs_error::Result<(u64, u32)> {
        Ok((0, 0))
    }

    /// Read the target of a symbolic link.
    ///
    /// Returns the raw bytes of the symlink target. Returns
    /// `FfsError::Format` if `ino` is not a symlink.
    fn readlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>>;

    /// Return filesystem-level capacity and free-space statistics.
    fn statfs(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<FsStat> {
        Err(FfsError::UnsupportedFeature(
            "statfs is not implemented by this backend".to_owned(),
        ))
    }

    /// List extended attribute names for an inode.
    ///
    /// Returns the full attribute names (including namespace prefix, e.g.
    /// `"user.myattr"`, `"security.selinux"`). Returns an empty list if the
    /// inode has no xattrs or the filesystem does not support them.
    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<String>> {
        let _ = (cx, ino);
        Ok(Vec::new())
    }

    /// Get the value of an extended attribute by full name.
    ///
    /// The `name` parameter is the full attribute name including namespace
    /// prefix (e.g. `"user.myattr"`). Returns `None` if the attribute does
    /// not exist.
    fn getxattr(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<Option<Vec<u8>>> {
        let _ = (cx, ino, name);
        Ok(None)
    }

    // ── Write operations (default: return ReadOnly) ─────────────────────

    /// Create, replace, or upsert one extended attribute.
    fn setxattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _name: &str,
        _value: &[u8],
        _mode: XattrSetMode,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Remove one extended attribute.
    ///
    /// Returns `true` if the attribute existed and was removed.
    fn removexattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _name: &str,
    ) -> ffs_error::Result<bool> {
        Err(FfsError::ReadOnly)
    }

    /// Create a regular file in directory `parent` with name `name`.
    ///
    /// Returns attributes of the newly created inode.
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _mode: u16,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Create a directory in `parent` with name `name`.
    #[allow(clippy::too_many_arguments)]
    fn mkdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _mode: u16,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Remove a non-directory entry from `parent`.
    fn unlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Remove an empty directory entry from `parent`.
    fn rmdir(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Rename an entry from `parent`/`name` to `new_parent`/`new_name`.
    fn rename(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _new_parent: InodeNumber,
        _new_name: &OsStr,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// `mknod(2)` for non-regular file types.
    ///
    /// `mode` carries the full S_IF* + permission bits. `rdev` is the
    /// `makedev(2)`-encoded device number, ignored for FIFO and socket.
    /// Regular-file creation goes through [`Self::create`] and dirs
    /// through [`Self::mkdir`]; this method handles char/block devices,
    /// FIFOs, and sockets — the file types that overlayfs whiteouts,
    /// POSIX named pipes, and Unix-domain socket files depend on.
    ///
    /// The default implementation returns `ENOTSUP` so backends that
    /// only support regular files (e.g. tests, read-only mounts) are
    /// not silently broken when callers expect device-creation
    /// semantics.
    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _mode: u16,
        _rdev: u32,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::Io(std::io::Error::from_raw_os_error(
            libc::ENOTSUP,
        )))
    }

    /// Rename with `renameat2(2)` flags (FUSE_RENAME2 opcode).
    ///
    /// `flags` is the bitset defined by `<linux/fs.h>`:
    /// - `0`  — classic rename (overwrite target if it exists).
    /// - `RENAME_NOREPLACE` (1) — fail with `EEXIST` if the destination
    ///   exists. The check + rename must be atomic under the parent
    ///   directory locks held by the caller.
    /// - `RENAME_EXCHANGE` (2) — atomically swap two existing entries.
    /// - `RENAME_WHITEOUT` (4) — used by overlayfs; not currently supported.
    ///
    /// The default implementation delegates to [`Self::rename`] when
    /// `flags == 0` and returns `EINVAL` for any non-zero flags so that
    /// callers cannot silently get classic-rename semantics on an
    /// implementation that does not honour the requested mode.
    #[allow(clippy::too_many_arguments)]
    fn rename2(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
        flags: u32,
    ) -> ffs_error::Result<()> {
        if flags == 0 {
            return self.rename(cx, scope, parent, name, new_parent, new_name);
        }
        Err(FfsError::Io(std::io::Error::from_raw_os_error(
            libc::EINVAL,
        )))
    }

    /// Write data to file `ino` at byte `offset`. Returns bytes written.
    fn write(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        _data: &[u8],
    ) -> ffs_error::Result<u32> {
        Err(FfsError::ReadOnly)
    }

    /// Copy bytes between two regular files.
    ///
    /// The default implementation preserves Linux `copy_file_range(2)` safety
    /// semantics and streams through the existing read/write contract in large
    /// chunks. Format-specific implementations can override this with an
    /// extent-aware clone path.
    #[allow(clippy::too_many_arguments)]
    fn copy_file_range(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino_in: InodeNumber,
        offset_in: u64,
        ino_out: InodeNumber,
        offset_out: u64,
        len: u64,
    ) -> ffs_error::Result<u64> {
        if len == 0 {
            return Ok(0);
        }
        if offset_in.checked_add(len).is_none() || offset_out.checked_add(len).is_none() {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }
        if ino_in == ino_out && ranges_overlap(offset_in, len, offset_out, len) {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }

        let mut copied = 0_u64;
        while copied < len {
            let remaining = len - copied;
            let request_len =
                COPY_FILE_RANGE_CHUNK_BYTES.min(u32::try_from(remaining).unwrap_or(u32::MAX));
            let src_offset = offset_in + copied;
            let dst_offset = offset_out + copied;
            let mut data = self.read(cx, scope, ino_in, src_offset, request_len)?;
            let request_len = usize::try_from(request_len).unwrap_or(usize::MAX);
            if data.len() > request_len {
                data.truncate(request_len);
            }
            if data.is_empty() {
                break;
            }

            let written = self.write(cx, scope, ino_out, dst_offset, &data)?;
            let written = usize::try_from(written)
                .unwrap_or(usize::MAX)
                .min(data.len());
            if written == 0 {
                break;
            }
            copied = copied.saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
            if written < data.len() {
                break;
            }
        }

        Ok(copied)
    }

    /// Create a hard link to `ino` in `new_parent` under `new_name`.
    fn link(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _new_parent: InodeNumber,
        _new_name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Create a symlink in `parent` named `name` targeting `target`.
    #[allow(clippy::too_many_arguments)]
    fn symlink(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _parent: InodeNumber,
        _name: &OsStr,
        _target: &Path,
        _uid: u32,
        _gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Preallocate or punch file space (POSIX `fallocate`-style).
    fn fallocate(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        _length: u64,
        _mode: i32,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Query extent mappings for a file (FIEMAP semantics).
    ///
    /// Returns extent entries covering the byte range `[start, start+length)`.
    /// If `length` is `u64::MAX`, returns all extents from `start` to EOF.
    /// Directories and symlinks return `FfsError::InvalidArgument`.
    fn fiemap(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _start: u64,
        _length: u64,
    ) -> ffs_error::Result<Vec<FiemapExtent>> {
        Err(FfsError::UnsupportedFeature(
            "fiemap is not supported by this backend".to_owned(),
        ))
    }

    /// Reposition read offset for SEEK_HOLE/SEEK_DATA support.
    ///
    /// Implements the `lseek(2)` system call semantics for sparse file queries:
    ///
    /// - `SeekWhence::Data`: Returns the offset of the next data (non-hole) region
    ///   at or after `offset`. If `offset` points to data, returns `offset`.
    /// - `SeekWhence::Hole`: Returns the offset of the next hole (unallocated) region
    ///   at or after `offset`. If `offset` points to a hole, returns `offset`.
    ///   The virtual hole at EOF counts as a hole.
    ///
    /// Returns `FfsError::InvalidArgument` (maps to `ENXIO`) if:
    /// - `offset` is at or beyond the file size
    /// - No data/hole exists after `offset` (for `SEEK_DATA`/`SEEK_HOLE` respectively)
    ///
    /// Standard `SEEK_SET`/`SEEK_CUR`/`SEEK_END` are handled by the FUSE layer
    /// and do not call this method.
    fn lseek(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _offset: u64,
        _whence: SeekWhence,
    ) -> ffs_error::Result<u64> {
        Err(FfsError::UnsupportedFeature(
            "lseek SEEK_HOLE/SEEK_DATA is not supported by this backend".to_owned(),
        ))
    }

    /// Read the inode-level state surfaced by `FS_IOC_FSGETXATTR`
    /// (28-byte `struct fsxattr` from `<linux/fs.h>`).
    ///
    /// The default implementation returns
    /// [`FfsError::UnsupportedFeature`]; backends that expose chattr-style
    /// flags + project IDs override this. ext4 maps `i_flags` ->
    /// `fsx_xflags` per uapi/linux/fs.h; `fsx_projid` from `i_projid`;
    /// `fsx_nextents` from the live extent count; `fsx_extsize` and
    /// `fsx_cowextsize` are 0 (ext4 does not implement them).
    fn get_inode_fsxattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<FsxattrInfo> {
        Err(FfsError::UnsupportedFeature(
            "get_inode_fsxattr is not supported by this backend".to_owned(),
        ))
    }

    /// Service `FITRIM` (`_IOWR('X', 121, struct fstrim_range)`).
    ///
    /// `start` + `len` describe the byte range that fstrim(8) wants
    /// the FS to release back to the underlying device; `min_len` is
    /// a hint at the smallest contiguous run worth discarding. The
    /// return value is the number of bytes actually discarded — the
    /// kernel writes it back into `fstrim_range.len` so userspace
    /// can report it.
    ///
    /// FrankenFS runs in userspace over a `BlockDevice` that does not
    /// expose a discard syscall, so the default implementation
    /// validates the range against the underlying device size and
    /// returns 0 (zero bytes discarded, call succeeded) — matches
    /// Linux's behaviour on filesystems mounted on non-discard-capable
    /// devices.
    fn trim_range(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _start: u64,
        _len: u64,
        _min_len: u64,
    ) -> ffs_error::Result<u64> {
        Err(FfsError::UnsupportedFeature(
            "trim_range is not supported by this backend".to_owned(),
        ))
    }

    /// Return the 16-byte filesystem UUID.
    ///
    /// Surfaces what `FS_IOC_GETFSUUID` (Linux 6.5+) returns. ext4
    /// reads `s_uuid`; btrfs reads `s_fsid`. The default returns
    /// [`FfsError::UnsupportedFeature`] for backends that do not
    /// model an FS-level UUID.
    fn fs_uuid(&self) -> ffs_error::Result<[u8; 16]> {
        Err(FfsError::UnsupportedFeature(
            "fs_uuid is not supported by this backend".to_owned(),
        ))
    }

    /// Return the kernel-side sysfs path of the underlying block device,
    /// or an empty `Vec` for backends with no sysfs visibility.
    ///
    /// Surfaces what `FS_IOC_GETFSSYSFSPATH` (Linux 6.7+) returns. The
    /// kernel struct is `u8 len + u8 name[128]` (129 bytes total).
    /// Userspace probes (systemd-mount, blkid, util-linux) treat
    /// `len == 0` as "no sysfs path available" and silently skip rather
    /// than erroring, so a userspace FUSE backend whose `ByteDevice` has
    /// no /sys entry should return an empty `Vec` here. The dispatcher
    /// pads to 128 bytes and writes `len` as the first byte.
    ///
    /// Backends that DO surface a sysfs path (e.g., a future loop-device
    /// adapter that knows its `/sys/block/loopN` path) must return at
    /// most 128 bytes; longer paths are rejected as `EINVAL` by the
    /// dispatcher to keep the wire-format contract.
    fn fs_sysfs_path(&self) -> ffs_error::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    /// Apply userspace-supplied [`FsxattrInfo`] (the `FS_IOC_FSSETXATTR`
    /// payload) to the inode.
    ///
    /// Backends translate `xflags` back into their native flag set,
    /// stash `projid`, and reject unsupported fields with `EINVAL` /
    /// `EOPNOTSUPP`. The default implementation returns
    /// [`FfsError::UnsupportedFeature`] so backends that opt in must
    /// override it explicitly.
    fn set_inode_fsxattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _info: FsxattrInfo,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "set_inode_fsxattr is not supported by this backend".to_owned(),
        ))
    }

    /// Get filesystem-specific inode flags (ext4 `EXT4_IOC_GETFLAGS`).
    ///
    /// Returns the raw `i_flags` field for the given inode.
    fn get_inode_flags(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        Err(FfsError::UnsupportedFeature(
            "get_inode_flags is not supported by this backend".to_owned(),
        ))
    }

    /// Return the kernel-side runtime state bitmap for an inode.
    ///
    /// Surfaces what `EXT4_IOC_GETSTATE` reports — the
    /// `EXT4_STATE_FLAG_*` bits used by `e2fsprogs` and `debugfs` for
    /// diagnostic dumps (`EXT_PRECACHED`, `NEW`, `NEWENTRY`,
    /// `DA_ALLOC_CLOSE`). These are kernel-side transient flags with
    /// no persistent on-disk representation, so a userspace FUSE
    /// backend has nothing meaningful to expose; the default returns
    /// `0`. Backends with inode identity should override this to
    /// validate that `ino` exists.
    fn get_inode_state(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        Ok(0)
    }

    /// Hint that the caller is about to walk the inode and would like
    /// the extent metadata read into the page cache up-front.
    ///
    /// Surfaces what `EXT4_IOC_PRECACHE_EXTENTS` triggers in the kernel:
    /// `fs/ext4/ioctl.c::ext4_ext_precache` walks the on-disk extent
    /// tree for the inode and pulls every internal/leaf block into the
    /// page cache so subsequent reads don't stall on metadata I/O. The
    /// kernel returns 0 even when the inode has no extents — the
    /// contract is "best effort, never an error for a valid inode."
    /// Backends without an out-of-band cache are free to no-op (the
    /// default), but they should still validate that the inode exists.
    fn precache_extents(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Drop the in-memory extent status cache for an inode.
    ///
    /// Surfaces what `EXT4_IOC_CLEAR_ES_CACHE` triggers in the kernel:
    /// `fs/ext4/ioctl.c::ext4_clear_inode_es` removes every cached
    /// `ext4_es_status` entry so the next read repopulates state from
    /// the on-disk extent tree. e2fsprogs uses this to defeat caching
    /// after offline metadata edits via `debugfs`. FrankenFS keeps
    /// extent state per-`RequestScope` rather than in a long-lived
    /// inode-level cache, so the default implementation is a successful
    /// no-op — backends only need to override if they expose a
    /// process-lifetime cache that needs explicit invalidation.
    fn clear_extent_status_cache(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Get ext4 inode generation (`EXT4_IOC_GETVERSION`).
    ///
    /// Returns the raw `i_generation` field for the given inode.
    fn get_inode_generation(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        Err(FfsError::UnsupportedFeature(
            "get_inode_generation is not supported by this backend".to_owned(),
        ))
    }

    /// Set ext4 inode generation (`EXT4_IOC_SETVERSION`).
    fn set_inode_generation(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _generation: u32,
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "set_inode_generation is not supported by this backend".to_owned(),
        ))
    }

    /// Get the legacy fscrypt v1 encryption policy (`FS_IOC_GET_ENCRYPTION_POLICY`).
    ///
    /// Returns the raw 12-byte `struct fscrypt_policy_v1` payload for the given
    /// inode. Backends should return `ENODATA` if the inode is not encrypted,
    /// and `EINVAL` if the inode uses a newer policy version.
    fn get_encryption_policy_v1(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<[u8; 12]> {
        Err(FfsError::UnsupportedFeature(
            "get_encryption_policy_v1 is not supported by this backend".to_owned(),
        ))
    }

    /// Get the fscrypt encryption policy (`FS_IOC_GET_ENCRYPTION_POLICY_EX`).
    ///
    /// Returns the policy version (0 for v1, 2 for v2) and the raw policy bytes.
    /// For v1: 12 bytes; for v2: 24 bytes.
    /// Returns `ENODATA` if the inode is not encrypted.
    fn get_encryption_policy_ex(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<(u8, Vec<u8>)> {
        Err(FfsError::UnsupportedFeature(
            "get_encryption_policy_ex is not supported by this backend".to_owned(),
        ))
    }

    /// Get the filesystem label (`FS_IOC_GETFSLABEL`).
    ///
    /// Returns the filesystem label as a null-terminated byte vector.
    /// ext4: up to 16 bytes from `s_volume_name`.
    /// btrfs: up to 256 bytes from superblock `label`.
    fn get_fs_label(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_fs_label is not supported by this backend".to_owned(),
        ))
    }

    /// Set the filesystem label (`FS_IOC_SETFSLABEL`).
    ///
    /// `label` is the userspace payload without the terminating NUL byte.
    /// Backends should reject labels that exceed their filesystem-specific
    /// maximum length with `EINVAL`.
    fn set_fs_label(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _label: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::UnsupportedFeature(
            "set_fs_label is not supported by this backend".to_owned(),
        ))
    }

    /// Return the btrfs filesystem-info payload for `BTRFS_IOC_FS_INFO`.
    ///
    /// Implementations should encode a `struct btrfs_ioctl_fs_info_args`
    /// (1024 bytes on x86_64) populated with the live `fs_info` fields:
    /// `max_id`, `num_devices`, `fsid`, `nodesize`, `sectorsize`,
    /// `clone_alignment`, `csum_type`, `csum_size`, `flags`, `generation`,
    /// and `metadata_uuid`.  The returned `Vec<u8>` must be exactly
    /// 1024 bytes so `ffs-fuse` can forward it verbatim to the kernel ioctl
    /// reply buffer.
    ///
    /// Non-btrfs backends must return
    /// `FfsError::UnsupportedFeature`, which `ffs-fuse` maps to
    /// `EOPNOTSUPP` so callers on ext4 see a deterministic rejection
    /// rather than a bogus success.
    fn get_btrfs_fs_info(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_fs_info is not supported by this backend".to_owned(),
        ))
    }

    /// Look up an inode path for `BTRFS_IOC_INO_LOOKUP`.
    ///
    /// Given a `treeid` (subvolume tree objectid, or 0 for the mounted tree)
    /// and an `objectid` (inode number), returns the path from that
    /// subvolume root to the inode. For the subvolume root itself
    /// (objectid == 256), returns an empty path and fills in the actual
    /// mounted treeid when callers pass 0.
    ///
    /// Returns `(treeid, path)` where `treeid` is the resolved tree objectid
    /// and `path` is the NUL-terminated path bytes (empty for root).
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`.
    fn btrfs_ino_lookup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _treeid: u64,
        _objectid: u64,
    ) -> ffs_error::Result<(u64, Vec<u8>)> {
        Err(FfsError::UnsupportedFeature(
            "btrfs_ino_lookup is not supported by this backend".to_owned(),
        ))
    }

    /// Return the btrfs per-device-info payload for `BTRFS_IOC_DEV_INFO`.
    ///
    /// `devid_in` and `uuid_in` are the lookup keys supplied in the ioctl
    /// input struct: the kernel resolves whichever of them is non-zero (or
    /// both) to a device and writes back the full `btrfs_ioctl_dev_info_args`
    /// struct (4096 bytes).  Implementations return the encoded payload on
    /// match, or `FfsError::Io(ENODEV)` when the caller's lookup keys do not
    /// identify a device this filesystem tracks.
    ///
    /// Non-btrfs backends must return `FfsError::UnsupportedFeature`, which
    /// `ffs-fuse` maps to `EOPNOTSUPP`.
    fn get_btrfs_dev_info(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _devid_in: u64,
        _uuid_in: [u8; 16],
    ) -> ffs_error::Result<Vec<u8>> {
        Err(FfsError::UnsupportedFeature(
            "get_btrfs_dev_info is not supported by this backend".to_owned(),
        ))
    }

    /// Get quota configuration and status.
    ///
    /// Returns a summary of which quota types are enabled and their
    /// corresponding inode numbers. This allows inspection of quota
    /// configuration without parsing quota file contents.
    ///
    /// ext4: Reads `s_usr_quota_inum`, `s_grp_quota_inum`, `s_prj_quota_inum`
    /// from the superblock, conditioned on QUOTA/PROJECT feature bits.
    ///
    /// btrfs: Returns `UnsupportedFeature` (btrfs uses qgroups, not inodes).
    fn get_quota_info(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<QuotaInfo> {
        Err(FfsError::UnsupportedFeature(
            "get_quota_info is not supported by this backend".to_owned(),
        ))
    }

    /// Set filesystem-specific inode flags (ext4 `EXT4_IOC_SETFLAGS`).
    ///
    /// Updates the raw `i_flags` field. The implementation should validate
    /// which flags are user-settable and reject immutable/system-only flags.
    fn set_inode_flags(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _flags: u32,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Move extents between files (ext4 `EXT4_IOC_MOVE_EXT`).
    ///
    /// `donor_fd` is the userspace donor file descriptor carried by the ioctl
    /// request. `orig_start`, `donor_start`, and `len` are block-based ranges
    /// matching Linux's `struct move_extent`. Implementations that do not
    /// support online defragmentation may return `UnsupportedFeature`.
    #[allow(clippy::too_many_arguments)]
    fn move_ext(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _donor_fd: u32,
        _orig_start: u64,
        _donor_start: u64,
        _len: u64,
    ) -> ffs_error::Result<u64> {
        Err(FfsError::UnsupportedFeature(
            "move_ext is not supported by this backend".to_owned(),
        ))
    }

    /// Register a userspace donor fd mapping for `EXT4_IOC_MOVE_EXT`.
    ///
    /// FUSE dispatch can resolve the caller's donor fd to a mounted-path inode
    /// before invoking [`FsOps::move_ext`]. Backends that key move-ext donor
    /// lookup by userspace fd can override this hook; other backends may keep
    /// the default no-op implementation.
    fn register_move_ext_donor_fd(
        &self,
        _donor_fd: u32,
        _donor_ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Release a temporary donor-fd registration for `EXT4_IOC_MOVE_EXT`.
    ///
    /// Called after `move_ext` returns, regardless of success.
    fn unregister_move_ext_donor_fd(&self, _donor_fd: u32) {}

    /// Set inode attributes. Returns updated attributes.
    fn setattr(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _attrs: &SetAttrRequest,
    ) -> ffs_error::Result<InodeAttr> {
        Err(FfsError::ReadOnly)
    }

    /// Flush per-handle state on `close(2)`; no durability guarantee required.
    ///
    /// This hook exists for backends that keep per-handle locks or delayed
    /// write errors. Stateless implementations may return `Ok(())`.
    fn flush(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _fh: u64,
        _lock_owner: u64,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Release the last reference to an open file handle.
    ///
    /// Stateless implementations may return `Ok(())`.
    fn release(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _request: ReleaseRequest,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Synchronize file data to stable storage.
    ///
    /// `datasync=true` allows skipping non-essential metadata where supported.
    fn fsync(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        _fh: u64,
        _datasync: bool,
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }

    /// Synchronize directory contents to stable storage.
    fn fsyncdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        datasync: bool,
    ) -> ffs_error::Result<()> {
        self.fsync(cx, scope, ino, fh, datasync)
    }

    // ── Request scope hooks ───────────────────────────────────────────

    /// Acquire request scope before executing a VFS operation.
    ///
    /// Default behavior is a no-op for read-only backends.
    fn begin_request_scope(&self, _cx: &Cx, _op: RequestOp) -> ffs_error::Result<RequestScope> {
        Ok(RequestScope::empty())
    }

    /// Release request scope after executing a VFS operation.
    ///
    /// Called even when the operation body fails. Default behavior is a no-op.
    fn end_request_scope(
        &self,
        _cx: &Cx,
        _op: RequestOp,
        _scope: RequestScope,
    ) -> ffs_error::Result<()> {
        Ok(())
    }

    /// Commit any write transaction attached to the request scope.
    fn commit_request_scope(&self, _scope: &mut RequestScope) -> ffs_error::Result<CommitSeq> {
        Ok(CommitSeq(0))
    }

    /// Flush all pending writes to durable storage before unmount.
    ///
    /// Called by the FUSE `destroy` callback to ensure in-memory MVCC
    /// data is materialised to the underlying image.  The default
    /// implementation is a no-op.
    fn flush_on_destroy(&self, _cx: &Cx) -> ffs_error::Result<()> {
        Ok(())
    }
}
